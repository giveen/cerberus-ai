"""Asynchronous/batched ingestion manager for RAG vector DB adapters.

Features:
- Batching by collection with configurable batch size and interval
- Background worker that performs adapter writes asynchronously
- Retries with exponential backoff on transient failures
- Optional TTL/retention purge (best-effort depending on adapter)
- Emits basic metrics via `cai.rag.metrics`

This implementation favors simplicity and safe defaults so it can be
used in CI/development without extra dependencies.
"""
from __future__ import annotations

import threading
import time
import traceback
from typing import Any, Dict, List, Optional, Tuple
import os

from cai.rag.metrics import collector


def _now_ts() -> float:
    return time.time()


class IngestionManager:
    def __init__(self, adapter: Any, *, batch_size: int = 50, batch_interval: float = 1.0, max_retries: int = 3, backoff_base: float = 0.2, backoff_factor: float = 2.0, ttl_seconds: Optional[int] = None, retention_interval: int = 3600):
        self.adapter = adapter
        self.batch_size = int(batch_size)
        self.batch_interval = float(batch_interval)
        self.max_retries = int(max_retries)
        self.backoff_base = float(backoff_base)
        self.backoff_factor = float(backoff_factor)
        self.ttl_seconds = int(ttl_seconds) if ttl_seconds is not None else None
        self.retention_interval = int(retention_interval)

        # queue: list of tuples (collection_name, ids, texts, metadata)
        self._queue: List[Tuple[str, Any, List[str], List[dict]]] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._wakeup = threading.Event()

        # metrics
        self._indexed_docs = 0

        # background worker thread
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()

        # retention thread
        if self.ttl_seconds is not None and self.ttl_seconds > 0:
            self._retention_thread = threading.Thread(target=self._retention_worker, daemon=True)
            self._retention_thread.start()
        else:
            self._retention_thread = None

    def enqueue(self, collection: str, id_point: Any, texts: List[str], metadata: List[dict]) -> None:
        with self._lock:
            self._queue.append((collection, id_point, texts, metadata))
            if len(self._queue) >= self.batch_size:
                # signal immediate flush
                self._wakeup.set()
        # update counter
        collector().incr("ingest_queued", len(texts))

    def flush_sync(self, timeout: float = 2.0) -> None:
        """Force a synchronous flush and wait up to `timeout` seconds."""
        self._wakeup.set()
        # wait for queue to drain or timeout
        start = _now_ts()
        while _now_ts() - start < float(timeout):
            with self._lock:
                if not self._queue:
                    return
            time.sleep(0.05)

    def stop(self) -> None:
        self._stop.set()
        self._wakeup.set()
        self._thread.join(timeout=2.0)
        if self._retention_thread:
            # best-effort join
            self._retention_thread.join(timeout=1.0)

    def _worker(self) -> None:
        while not self._stop.is_set():
            # wait for wakeup or timeout
            self._wakeup.wait(self.batch_interval)
            self._wakeup.clear()
            # drain up to batch_size items
            to_process: List[Tuple[str, Any, List[str], List[dict]]] = []
            with self._lock:
                if not self._queue:
                    continue
                # take up to batch_size events
                take = min(len(self._queue), self.batch_size)
                for _ in range(take):
                    to_process.append(self._queue.pop(0))

            # group by collection
            grouped: Dict[str, List[Tuple[Any, List[str], List[dict]]]] = {}
            for collection, id_point, texts, metadata in to_process:
                grouped.setdefault(collection, []).append((id_point, texts, metadata))

            for collection, items in grouped.items():
                # flatten items: combine ids, texts, metadata
                combined_ids: List[Any] = []
                combined_texts: List[str] = []
                combined_meta: List[dict] = []
                for id_point, texts, metadata in items:
                    # id_point can be a single id or list
                    if isinstance(id_point, (list, tuple)):
                        combined_ids.extend(list(id_point))
                    else:
                        # if there are multiple texts, we generate per-item ids later in adapter
                        combined_ids.append(id_point)
                    combined_texts.extend(texts or [])
                    combined_meta.extend(metadata or [{} for _ in (texts or [])])

                # perform write with retries/backoff
                start_ts = _now_ts()
                success = False
                attempt = 0
                delay = self.backoff_base
                while attempt < self.max_retries and not success:
                    try:
                        # best-effort: call adapter.add_points synchronously in background
                        self.adapter.add_points(
                            id_point=combined_ids if len(combined_ids) > 1 else (combined_ids[0] if combined_ids else None),
                            collection_name=collection,
                            texts=combined_texts,
                            metadata=combined_meta,
                        )
                        success = True
                    except Exception:
                        attempt += 1
                        if attempt < self.max_retries:
                            time.sleep(delay)
                            delay *= self.backoff_factor
                        else:
                            # log and continue
                            try:
                                traceback.print_exc()
                            except Exception:
                                pass

                elapsed_ms = ( _now_ts() - start_ts ) * 1000.0
                collector().incr("ingest_indexed_docs", len(combined_texts))
                collector().observe("ingest_index_time_ms", elapsed_ms)
                # best-effort update collection size if adapter supports export_collection
                try:
                    if hasattr(self.adapter, "export_collection"):
                        exported = self.adapter.export_collection(collection)
                        collector().set_gauge(f"collection_size_{collection}", float(len(exported)))
                except Exception:
                    pass

    def _retention_worker(self) -> None:
        # Periodically purge older items based on ttl_seconds
        while not self._stop.is_set():
            try:
                cutoff = _now_ts() - float(self.ttl_seconds)
                # Try adapter-specific purge
                if hasattr(self.adapter, "purge_older_than"):
                    try:
                        self.adapter.purge_older_than(cutoff)
                    except Exception:
                        pass
                else:
                    # Best-effort: export collection and delete by id if adapter supports delete_points
                    if hasattr(self.adapter, "export_collection") and hasattr(self.adapter, "delete_points"):
                        try:
                            # iterate collections
                            if hasattr(self.adapter, "list_collections"):
                                cols = self.adapter.list_collections()
                            else:
                                # best-effort: try a default list
                                cols = ["_all_"]
                            for c in cols:
                                exported = self.adapter.export_collection(c)
                                to_delete = []
                                for d in (exported or []):
                                    meta = d.get("metadata") or {}
                                    prov = meta.get("provenance") if isinstance(meta, dict) else d.get("provenance")
                                    if isinstance(prov, dict):
                                        ts = prov.get("timestamp")
                                        try:
                                            # assume ISO ending with Z
                                            tsec = time.mktime(time.strptime(ts.replace("Z", ""), "%Y-%m-%dT%H:%M:%S.%f")) if ts and "." in ts else time.mktime(time.strptime(ts.replace("Z", ""), "%Y-%m-%dT%H:%M:%S"))
                                        except Exception:
                                            tsec = None
                                        if tsec is not None and tsec < cutoff:
                                            to_delete.append(d.get("id"))
                                if to_delete:
                                    try:
                                        self.adapter.delete_points(c, to_delete)
                                    except Exception:
                                        pass
                        except Exception:
                            pass
                # sleep until next retention check
            except Exception:
                pass
            # Sleep for retention interval or shorter if stopping
            for _ in range(int(max(1, self.retention_interval))):
                if self._stop.is_set():
                    break
                time.sleep(1)


# Simple registry to reuse ingestion manager per adapter instance
_INGESTORS: Dict[int, IngestionManager] = {}


def get_ingestor(adapter: Any, **kwargs) -> IngestionManager:
    key = id(adapter)
    if key not in _INGESTORS:
        # Read defaults from environment if not provided
        env_batch_size = int(os.getenv("CEREBRO_RAG_BATCH_SIZE", "50"))
        env_batch_interval = float(os.getenv("CEREBRO_RAG_BATCH_INTERVAL", "1.0"))
        env_max_retries = int(os.getenv("CEREBRO_RAG_MAX_RETRIES", "3"))
        env_backoff_base = float(os.getenv("CEREBRO_RAG_BACKOFF_BASE", "0.2"))
        env_backoff_factor = float(os.getenv("CEREBRO_RAG_BACKOFF_FACTOR", "2.0"))
        env_ttl = os.getenv("CEREBRO_RAG_TTL_SECONDS")
        env_retention = int(os.getenv("CEREBRO_RAG_RETENTION_INTERVAL", "3600"))

        params = {
            "batch_size": kwargs.get("batch_size", env_batch_size),
            "batch_interval": kwargs.get("batch_interval", env_batch_interval),
            "max_retries": kwargs.get("max_retries", env_max_retries),
            "backoff_base": kwargs.get("backoff_base", env_backoff_base),
            "backoff_factor": kwargs.get("backoff_factor", env_backoff_factor),
            "ttl_seconds": int(env_ttl) if env_ttl is not None else kwargs.get("ttl_seconds", None),
            "retention_interval": kwargs.get("retention_interval", env_retention),
        }
        _INGESTORS[key] = IngestionManager(adapter, **params)
    return _INGESTORS[key]


def shutdown_all() -> None:
    for ing in list(_INGESTORS.values()):
        try:
            ing.stop()
        except Exception:
            pass


__all__ = ["get_ingestor", "shutdown_all", "IngestionManager"]


# ---------------------------------------------------------------------------
# PathGuardIngestionManager — PathGuard-gated file reads + hot-loading
# ---------------------------------------------------------------------------


def _naive_chunk(text: str, size: int = 2000, overlap: int = 200) -> List[str]:
    step = max(1, size - overlap)
    return [text[i : i + size] for i in range(0, len(text), step)]


class PathGuardIngestionManager:
    """IngestionManager wrapper that gates all file reads through PathGuard.

    Provides hot-loading: a background thread polls ``loot_dir`` and
    automatically ingests any new files that appear without requiring a
    restart.
    """

    def __init__(
        self,
        ingestor: IngestionManager,
        workspace: Optional[str] = None,
        loot_dir: Optional[str] = None,
        poll_interval: float = 2.0,
        collection: str = "loot",
        chunk_size: int = 2000,
        chunk_overlap: int = 200,
    ) -> None:
        self.ingestor = ingestor
        self.workspace = workspace or os.getenv("CIR_WORKSPACE", "/workspace")
        self.loot_dir = loot_dir or os.path.join(self.workspace, "loot")
        self.poll_interval = float(poll_interval)
        self.collection = collection
        self.chunk_size = int(chunk_size)
        self.chunk_overlap = int(chunk_overlap)
        self._seen_files: set = set()
        self._stop = threading.Event()
        self._poll_thread: Optional[threading.Thread] = None
        self._pg = None  # PathGuard; deferred import to avoid circular imports

    def _get_pathguard(self):
        if self._pg is None:
            try:
                from cai.tools.reconnaissance.filesystem import PathGuard  # type: ignore
                self._pg = PathGuard(root=self.workspace)
            except Exception:
                self._pg = None
        return self._pg

    def _safe_read(self, filepath: str) -> Optional[str]:
        """Read file through PathGuard; returns None on access denial."""
        pg = self._get_pathguard()
        if pg is not None:
            try:
                resolved = str(pg.resolve(filepath))
            except Exception:
                return None
        else:
            import os.path as _osp
            resolved_raw = _osp.realpath(filepath)
            workspace_real = _osp.realpath(self.workspace)
            if not (resolved_raw == workspace_real or
                    resolved_raw.startswith(workspace_real + os.sep)):
                return None
            resolved = resolved_raw
        try:
            with open(resolved, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except Exception:
            return None

    def ingest_file(self, filepath: str, collection: Optional[str] = None) -> int:
        """Ingest a single file through PathGuard. Returns chunk count enqueued."""
        text = self._safe_read(filepath)
        if not text:
            return 0
        col = collection or self.collection
        chunks = _naive_chunk(text, self.chunk_size, self.chunk_overlap)
        for i, chunk in enumerate(chunks):
            self.ingestor.enqueue(
                col,
                id_point=f"{filepath}::{i}",
                texts=[chunk],
                metadata=[{"source": filepath, "chunk_index": i}],
            )
        return len(chunks)

    def start_hot_loader(self) -> None:
        """Start the background hot-loader thread."""
        if self._poll_thread is not None and self._poll_thread.is_alive():
            return
        self._stop.clear()
        self._poll_thread = threading.Thread(
            target=self._poll_loop, daemon=True, name="pg-hot-loader"
        )
        self._poll_thread.start()

    def stop_hot_loader(self) -> None:
        self._stop.set()
        if self._poll_thread:
            self._poll_thread.join(timeout=self.poll_interval + 1.0)

    def _poll_loop(self) -> None:
        while not self._stop.is_set():
            try:
                if os.path.isdir(self.loot_dir):
                    for fname in os.listdir(self.loot_dir):
                        fpath = os.path.join(self.loot_dir, fname)
                        if fpath not in self._seen_files and os.path.isfile(fpath):
                            self._seen_files.add(fpath)
                            try:
                                self.ingest_file(fpath)
                            except Exception:
                                pass
            except Exception:
                pass
            self._stop.wait(self.poll_interval)


__all__ = [
    "get_ingestor",
    "shutdown_all",
    "IngestionManager",
    "PathGuardIngestionManager",
]
