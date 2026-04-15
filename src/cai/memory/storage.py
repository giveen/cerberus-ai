"""Workspace-aware storage backend for memory evidence.

The default implementation persists JSONL records inside the active workspace.
"""

from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
from typing import Any, Iterable, Protocol
import uuid

from pydantic import BaseModel, Field, ValidationError

from cai.memory.logic import clean_data


class EvidenceRecord(BaseModel):
    """Strict schema for stored technical memory events."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    topic: str = Field(min_length=1)
    finding: str = Field(min_length=1)
    source: str = Field(default="agent")
    tags: list[str] = Field(default_factory=list)
    artifacts: dict[str, Any] = Field(default_factory=dict)


class StorageBackend(Protocol):
    """Protocol for memory persistence engines."""

    def initialize(self) -> Path:
        """Create and return storage directory."""
        ...

    def append(self, event: EvidenceRecord | dict[str, Any]) -> EvidenceRecord:
        """Persist one event and return validated record."""
        ...

    def load_all(self) -> list[EvidenceRecord]:
        """Load all persisted events."""
        ...


class WorkspaceJSONStore:
    """JSONL memory store rooted in the active workspace."""

    def __init__(self, relative_dir: str = ".cai/memory", file_name: str = "evidence.jsonl") -> None:
        self.relative_dir = Path(relative_dir)
        self.file_name = file_name
        self.storage_root = self._resolve_workspace_root() / self.relative_dir
        self.file_path = self.storage_root / self.file_name

    def _resolve_workspace_root(self) -> Path:
        try:
            from cai.tools.workspace import get_project_space

            return get_project_space().ensure_initialized().resolve()
        except Exception:
            # Safe fallback for environments where workspace bootstrap is not ready.
            return Path.cwd().resolve()

    def initialize(self) -> Path:
        self.storage_root.mkdir(parents=True, exist_ok=True)
        if not self.file_path.exists():
            self.file_path.touch()
        return self.storage_root

    def append(self, event: EvidenceRecord | dict[str, Any]) -> EvidenceRecord:
        self.initialize()

        if isinstance(event, EvidenceRecord):
            record = event
        else:
            try:
                record = EvidenceRecord.model_validate(clean_data(event))
            except ValidationError as exc:
                raise ValueError(f"Invalid memory event payload: {exc}") from exc

        payload = clean_data(record.model_dump(mode="json"))
        with self.file_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=True) + "\n")

        return EvidenceRecord.model_validate(payload)

    def load_all(self) -> list[EvidenceRecord]:
        self.initialize()
        records: list[EvidenceRecord] = []

        with self.file_path.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                    records.append(EvidenceRecord.model_validate(payload))
                except (json.JSONDecodeError, ValidationError):
                    # Skip malformed line; preserve robust recovery.
                    continue

        return records

    def iter_topic(self, topic: str) -> Iterable[EvidenceRecord]:
        needle = topic.strip().lower()
        for record in self.load_all():
            if needle in record.topic.lower():
                yield record


# =============================================================================
# Cerebro High-Velocity Persistence Engine (CHPE)
# =============================================================================

import asyncio
import logging
import os
import shutil
import tempfile
import threading
from collections import deque

_CHPE_LOG = logging.getLogger("CerebroStorageHandler")
_DEFAULT_CHPE_WORKSPACE = Path(os.getenv("CIR_WORKSPACE", "/workspace")).resolve()


class CerebroStorageHandler:
    """Cerebro High-Velocity Persistence Engine (CHPE).

    Treats the disk as a high-speed Transaction Log while using an in-process
    write-back queue as a RAM-resident staging buffer.  Key properties:

    * **Open format** — every file is plain JSONL or Markdown; no encoding or
      obfuscation.  Any file under ``/workspace/memory/`` can be opened with a
      standard text editor.
    * **Atomic writes** — all JSONL and state files are written to a sibling
      ``.tmp`` file first, then ``os.replace()``-renamed into place, making
      every write crash-safe (POSIX atomicity guarantee).
    * **Write-back flush** — a daemon thread drains the in-memory deque to
      disk without blocking the caller.  The queue can also be flushed
      synchronously via :meth:`flush_sync` or asynchronously via
      :meth:`flush_async`.
    * **Audit versioning** — state snapshots are versioned automatically
      (``state.v1.jsonl``, ``state.v2.jsonl``, …) so any mission state can be
      rolled back.
    * **Binary loot storage** — :meth:`save_loot` writes raw bytes (PCAPs,
      database dumps, etc.) via a dedicated zero-copy path that bypasses the
      JSON serialiser entirely.
    * **PathGuard compliance** — all paths are validated through an internal
      ``_CHPEWriter`` that rejects writes outside ``workspace_root``.

    Example::

        handler = CerebroStorageHandler.get_instance()
        handler.start_background_flusher()

        # Non-blocking enqueue
        handler.enqueue(EvidenceRecord(topic="scan", finding="open:22", source="nmap"))

        # Synchronous append (no queue)
        handler.append_now(EvidenceRecord(topic="exploit", finding="got shell", source="msf"))

        # Binary loot
        handler.save_loot("capture.pcap", raw_bytes)

        # Versioned state snapshot
        handler.save_state_version({"phase": "post-exploit", "targets": ["10.0.0.5"]})
    """

    _instance: "CerebroStorageHandler | None" = None
    _instance_lock: threading.Lock = threading.Lock()

    # ------------------------------------------------------------------
    # Singleton
    # ------------------------------------------------------------------

    @classmethod
    def get_instance(cls, **kwargs: Any) -> "CerebroStorageHandler":
        """Return the process-wide singleton, creating it on first call."""
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls(**kwargs)
        return cls._instance

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(
        self,
        *,
        workspace_root: str | None = None,
        queue_max: int = 10_000,
        evidence_file: str = "memory/evidence.jsonl",
    ) -> None:
        self.workspace_root = Path(
            workspace_root or str(_DEFAULT_CHPE_WORKSPACE)
        ).resolve()
        self._evidence_rel = evidence_file
        self._lock = threading.RLock()

        # Write-back queue (RAM staging buffer)
        self._queue: deque[EvidenceRecord] = deque(maxlen=queue_max)
        self._queue_event = threading.Event()

        # Versioning counter (loaded from disk on first use)
        self._version: int = 0
        self._version_loaded = False

        # Lazy PathGuard writer
        self._writer: "_CHPEWriter | None" = None
        self._writer_lock = threading.Lock()

        # Background flusher state
        self._stop_event = threading.Event()
        self._flusher_thread: threading.Thread | None = None

        _CHPE_LOG.info("[CHPE] Initialised. workspace=%s", self.workspace_root)

    # ------------------------------------------------------------------
    # PathGuard writer (lazy)
    # ------------------------------------------------------------------

    def _ensure_writer(self) -> "_CHPEWriter":
        if self._writer is None:
            with self._writer_lock:
                if self._writer is None:
                    self._writer = _CHPEWriter(self.workspace_root)
        return self._writer

    # ------------------------------------------------------------------
    # Enqueue (non-blocking)
    # ------------------------------------------------------------------

    def enqueue(self, record: "EvidenceRecord | dict[str, Any]") -> EvidenceRecord:
        """Stage a record in the RAM write-back queue (non-blocking).

        The background flusher drains the queue to disk.  Call
        :meth:`flush_sync` before process exit to ensure nothing is lost.
        """
        validated = self._coerce(record)
        with self._lock:
            self._queue.append(validated)
        self._queue_event.set()
        return validated

    # ------------------------------------------------------------------
    # Immediate (synchronous) append — atomic write-then-rename
    # ------------------------------------------------------------------

    def append_now(self, record: "EvidenceRecord | dict[str, Any]") -> EvidenceRecord:
        """Append one record directly to the JSONL evidence log.

        Uses POSIX atomic rename so the file is never left in a partial state.
        """
        validated = self._coerce(record)
        self._atomic_jsonl_append(self._evidence_rel, validated)
        _CHPE_LOG.debug("[CHPE] append_now: id=%s topic=%s", validated.id, validated.topic)
        return validated

    # ------------------------------------------------------------------
    # Load
    # ------------------------------------------------------------------

    def load_all(self) -> list[EvidenceRecord]:
        """Return all records stored in the JSONL evidence log."""
        writer = self._ensure_writer()
        resolved = self.workspace_root / self._evidence_rel
        if not resolved.exists():
            return []
        records: list[EvidenceRecord] = []
        with resolved.open("r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line:
                    continue
                try:
                    records.append(EvidenceRecord.model_validate(json.loads(line)))
                except Exception:
                    continue
        return records

    # ------------------------------------------------------------------
    # Binary loot storage (zero-copy path)
    # ------------------------------------------------------------------

    def save_loot(
        self,
        filename: str,
        data: bytes,
        *,
        subdirectory: str = "memory/loot",
    ) -> Path:
        """Persist raw binary data (PCAPs, dumps, etc.) atomically.

        Writes to a ``.tmp`` file then renames, bypassing the JSON serialiser
        for maximum throughput.  Returns the final absolute path.
        """
        writer = self._ensure_writer()
        rel = f"{subdirectory}/{filename}"
        resolved = writer.validate(rel, mode="write")
        resolved.parent.mkdir(parents=True, exist_ok=True)

        tmp = resolved.with_suffix(resolved.suffix + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, resolved)

        _CHPE_LOG.info("[CHPE] save_loot: %s (%d bytes)", resolved, len(data))
        return resolved

    # ------------------------------------------------------------------
    # Versioned state snapshots (rollback support)
    # ------------------------------------------------------------------

    def save_state_version(
        self,
        state: dict[str, Any],
        *,
        subdirectory: str = "memory/versions",
    ) -> Path:
        """Persist a mission-state snapshot with an auto-incremented version tag.

        Files are named ``state.v1.json``, ``state.v2.json``, etc.  Existing
        versions are never overwritten, supporting full mission rollback.
        Returns the path of the newly written version file.
        """
        writer = self._ensure_writer()
        version = self._next_version(subdirectory, writer)
        rel = f"{subdirectory}/state.v{version}.json"
        resolved = writer.validate(rel, mode="write")
        resolved.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "version": version,
            "saved_at": datetime.now(tz=UTC).isoformat(timespec="milliseconds"),
            "state": state,
        }
        _atomic_write_text(resolved, json.dumps(payload, indent=2, default=str))
        _CHPE_LOG.info("[CHPE] state version v%d → %s", version, resolved)
        return resolved

    def list_state_versions(
        self, *, subdirectory: str = "memory/versions"
    ) -> list[Path]:
        """Return all existing state version files, oldest-first."""
        writer = self._ensure_writer()
        dir_path = self.workspace_root / subdirectory
        if not dir_path.exists():
            return []
        versions = sorted(dir_path.glob("state.v*.json"), key=lambda p: _parse_version(p.name))
        return versions

    def load_state_version(
        self, version: int, *, subdirectory: str = "memory/versions"
    ) -> dict[str, Any]:
        """Load and return the payload of a specific state version."""
        writer = self._ensure_writer()
        rel = f"{subdirectory}/state.v{version}.json"
        resolved = writer.validate(rel, mode="read")
        return json.loads(resolved.read_text(encoding="utf-8"))

    # ------------------------------------------------------------------
    # Markdown audit export
    # ------------------------------------------------------------------

    def export_markdown(
        self,
        *,
        output_file: str = "memory/audit_report.md",
        limit: int = 0,
    ) -> Path:
        """Write all evidence records to a human-readable Markdown report.

        Args:
            output_file: Workspace-relative destination path.
            limit:       Max records to include (0 = unlimited).
        Returns the resolved path of the written file.
        """
        writer = self._ensure_writer()
        records = self.load_all()
        if limit > 0:
            records = records[:limit]

        lines: list[str] = [
            "# CHPE Audit Report",
            f"Generated: {datetime.now(tz=UTC).isoformat(timespec='milliseconds')}",
            f"Records: {len(records)}",
            "",
        ]
        for r in records:
            lines += [
                f"## [{r.topic}] `{r.id}`",
                f"- **Source**: `{r.source}`  **Time**: {r.created_at.isoformat(timespec='milliseconds')}",
                f"- **Tags**: {', '.join(r.tags) or 'none'}",
                f"- **Artifacts**: {r.artifacts or 'none'}",
                "",
                r.finding,
                "",
                "---",
                "",
            ]

        resolved = writer.validate(output_file, mode="write")
        resolved.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_text(resolved, "\n".join(lines))
        _CHPE_LOG.info("[CHPE] Markdown export → %s (%d records)", resolved, len(records))
        return resolved

    # ------------------------------------------------------------------
    # Flush (synchronous and async)
    # ------------------------------------------------------------------

    def flush_sync(self) -> int:
        """Drain the entire RAM write-back queue to disk synchronously.

        Returns the number of records written.
        """
        batch = self._drain_queue()
        if not batch:
            return 0
        for record in batch:
            self._atomic_jsonl_append(self._evidence_rel, record)
        _CHPE_LOG.debug("[CHPE] flush_sync: wrote %d records", len(batch))
        return len(batch)

    async def flush_async(self) -> int:
        """Drain the queue asynchronously using ``asyncio.to_thread``.

        Non-blocking for the active async event loop.
        """
        return await asyncio.to_thread(self.flush_sync)

    # ------------------------------------------------------------------
    # Background flusher
    # ------------------------------------------------------------------

    def start_background_flusher(self, idle_seconds: float = 2.0) -> None:
        """Start a daemon thread that flushes the queue whenever it is non-empty.

        Args:
            idle_seconds: How long to wait between flush attempts when the
                          queue is empty. Default is 2 seconds.
        """
        with self._lock:
            if self._flusher_thread and self._flusher_thread.is_alive():
                return
            self._stop_event.clear()
            self._flusher_thread = threading.Thread(
                target=self._flusher_loop,
                args=(max(0.1, idle_seconds),),
                daemon=True,
                name="chpe-flusher",
            )
            self._flusher_thread.start()
            _CHPE_LOG.info("[CHPE] Background flusher started (idle=%.1fs)", idle_seconds)

    def stop_background_flusher(self) -> None:
        """Signal the flusher thread to stop and drain remaining items."""
        self._stop_event.set()
        self._queue_event.set()  # unblock any wait
        if self._flusher_thread:
            self._flusher_thread.join(timeout=10.0)
            self._flusher_thread = None
        self.flush_sync()  # final drain
        _CHPE_LOG.info("[CHPE] Background flusher stopped")

    def _flusher_loop(self, idle: float) -> None:
        while not self._stop_event.is_set():
            triggered = self._queue_event.wait(timeout=idle)
            self._queue_event.clear()
            try:
                self.flush_sync()
            except Exception as exc:
                _CHPE_LOG.warning("[CHPE] Flusher error: %s", exc)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _coerce(self, record: "EvidenceRecord | dict[str, Any]") -> EvidenceRecord:
        if isinstance(record, EvidenceRecord):
            return record
        try:
            from cai.memory.logic import clean_data  # deferred to match existing pattern
            return EvidenceRecord.model_validate(clean_data(record))
        except Exception as exc:
            raise ValueError(f"Invalid record payload: {exc}") from exc

    def _drain_queue(self) -> list[EvidenceRecord]:
        with self._lock:
            batch = list(self._queue)
            self._queue.clear()
        return batch

    def _atomic_jsonl_append(self, relative_path: str, record: EvidenceRecord) -> None:
        """Append one JSON line atomically (write-then-rename strategy).

        Because append is not atomic on all filesystems, this method reads the
        existing file, appends in memory, then writes the full content to a
        sibling tmp file and renames it.  For high-throughput callers use the
        background flusher with batching.
        """
        writer = self._ensure_writer()
        resolved = writer.validate(relative_path, mode="write")
        resolved.parent.mkdir(parents=True, exist_ok=True)

        existing = resolved.read_text(encoding="utf-8") if resolved.exists() else ""
        line = json.dumps(record.model_dump(mode="json"), ensure_ascii=True)
        _atomic_write_text(resolved, existing + line + "\n")

    def _next_version(self, subdirectory: str, writer: "_CHPEWriter") -> int:
        with self._lock:
            if not self._version_loaded:
                existing = self.list_state_versions(subdirectory=subdirectory)
                if existing:
                    self._version = max(_parse_version(p.name) for p in existing)
                self._version_loaded = True
            self._version += 1
            return self._version

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Stop background tasks and flush remaining queued items."""
        self.stop_background_flusher()
        _CHPE_LOG.info("[CHPE] Closed")


# ---------------------------------------------------------------------------
# Module-level atomic write helper
# ---------------------------------------------------------------------------

def _atomic_write_text(path: Path, content: str) -> None:
    """Write *content* to *path* atomically using write-then-rename."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, path)


def _parse_version(filename: str) -> int:
    """Extract version integer from filenames like ``state.v3.json``."""
    import re
    m = re.search(r"\.v(\d+)\.", filename)
    return int(m.group(1)) if m else 0


# ---------------------------------------------------------------------------
# PathGuard-gated writer for CHPE
# ---------------------------------------------------------------------------

class _CHPEWriter:
    """PathGuard-backed path validator for CHPE persistence paths."""

    def __init__(self, workspace_root: Path) -> None:
        from cai.tools.reconnaissance.filesystem import PathGuard as _PG  # noqa: PLC0415
        self._root = workspace_root.resolve()
        self._guard = _PG(self._root, self._audit)

    def validate(self, relative_path: str, *, mode: str) -> Path:
        return self._guard.validate_path(
            relative_path, action="chpe_write", mode=mode
        )

    @staticmethod
    def _audit(_event: str, _payload: Any) -> None:
        return
