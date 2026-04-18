"""Vector DB adapter interface and concrete adapters.

Provides a small adapter abstraction so callers can switch between
Qdrant (existing) and MemPalace for A/B testing retrieval quality.

The intention is non-destructive: QdrantAdapter delegates to the
project's existing `QdrantConnector` when available; MemPalaceAdapter
implements best-effort read/search via the `mempalace` Python API or
CLI. Add/ingest operations for MemPalace are intentionally not implemented
here to avoid accidental data migration.
"""
from __future__ import annotations

import os
import shlex
import subprocess
import time
import hashlib
import json
import datetime as _dt
from pathlib import Path
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Type
from cerberus.rag.metrics import collector
import concurrent.futures
import threading
import fcntl
import tempfile
import shutil
import errno
import re
import atexit


@dataclass
class VectorDBConfig:
    """Lightweight configuration holder for vector DB adapters.

    Backends may read provider-specific options from `options`.
    """

    name: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    options: Dict[str, Any] = field(default_factory=dict)


def with_retries(retries: int = 3, base_delay: float = 0.2, backoff: float = 2.0):
    """Simple retry decorator with exponential backoff.

    Keep this intentionally dependency-free to avoid adding runtime
    requirements for the core adapter layer.
    """

    def decorator(fn):
        def wrapper(*args, **kwargs):
            last_exc: Optional[BaseException] = None
            delay = base_delay
            for attempt in range(retries):
                try:
                    return fn(*args, **kwargs)
                except Exception as exc:  # pragma: no cover - network/runtime dependent
                    last_exc = exc
                    if attempt < retries - 1:
                        time.sleep(delay)
                        delay *= backoff
            # If we get here, raise the last exception (guard against None)
            if last_exc is not None:
                raise last_exc
            raise RuntimeError("with_retries exhausted without capturing an exception")

        return wrapper

    return decorator


def _canonicalize_search_results(results: Any, limit: int = 3) -> List[Dict[str, Any]]:
    """Normalize heterogeneous backend search outputs into a canonical
    list of dicts with keys: `id`, `text`, `metadata`, `score`.

    This function is intentionally permissive: it accepts strings (CLI
    output), single dicts, lists/tuples of various shapes, and best-effort
    converts them into the canonical shape expected by the RAG callers.
    """
    out: List[Dict[str, Any]] = []
    if results is None:
        return out

    # Strings: try JSON parse first, then line-splitting
    if isinstance(results, str):
        s = results.strip()
        if not s:
            return out
        if (s.startswith("[") or s.startswith("{")):
            try:
                parsed = json.loads(s)
                results = parsed
            except Exception:
                lines = [l.strip() for l in s.splitlines() if l.strip()]
                for i, line in enumerate(lines[:limit]):
                    out.append({"id": hashlib.sha256(line.encode()).hexdigest()[:12], "text": line, "metadata": {}, "score": 1.0})
                return out
        else:
            lines = [l.strip() for l in s.splitlines() if l.strip()]
            for i, line in enumerate(lines[:limit]):
                out.append({"id": hashlib.sha256(line.encode()).hexdigest()[:12], "text": line, "metadata": {}, "score": 1.0})
            return out

    # Single dict -> list
    if isinstance(results, dict):
        results = [results]

    if isinstance(results, (list, tuple)):
        for item in list(results)[:limit]:
            if isinstance(item, dict):
                # id extraction heuristics
                id_keys = ("id", "uuid", "_id", "name", "document_id", "doc_id")
                id_val = next((item.get(k) for k in id_keys if item.get(k) is not None), None)

                # text extraction heuristics
                text = None
                for k in ("text", "payload", "document", "content", "body", "description"):
                    v = item.get(k)
                    if isinstance(v, str):
                        text = v
                        break
                    if isinstance(v, dict):
                        # nested payloads may contain text fields
                        text = v.get("text") or v.get("content") or v.get("document")
                        if isinstance(text, str):
                            break

                # metadata heuristics
                metadata = item.get("metadata") or item.get("meta") or {}
                # if payload is dict and metadata empty, use payload as metadata
                if not metadata and isinstance(item.get("payload"), dict):
                    metadata = item.get("payload")

                # score heuristics
                score = item.get("score") if isinstance(item.get("score"), (int, float)) else None
                if score is None:
                    for k in ("similarity", "sim", "distance", "_score"):
                        if k in item:
                            try:
                                val = item.get(k)
                                if val is None:
                                    continue
                                score = float(val)
                                break
                            except Exception:
                                score = None
                if score is None:
                    score = 1.0

                if text is None:
                    # fallback: stringify item for text
                    try:
                        text = json.dumps(item)
                    except Exception:
                        text = str(item)

                if id_val is None:
                    id_val = hashlib.sha256(str(text).encode()).hexdigest()[:12]

                if not isinstance(metadata, dict):
                    metadata = {"value": metadata}

                out.append({"id": str(id_val), "text": text, "metadata": metadata, "score": float(score)})
            else:
                # tuples/lists or primitive values
                if isinstance(item, (list, tuple)) and len(item) >= 1:
                    text = item[0]
                    id_val = item[1] if len(item) > 1 else hashlib.sha256(str(text).encode()).hexdigest()[:12]
                    score = float(item[2]) if len(item) > 2 else 1.0
                    out.append({"id": str(id_val), "text": str(text), "metadata": {}, "score": float(score)})
                else:
                    text = str(item)
                    id_val = hashlib.sha256(text.encode()).hexdigest()[:12]
                    out.append({"id": id_val, "text": text, "metadata": {}, "score": 1.0})
        return out

    # Fallback: stringify
    s = str(results)
    if not s:
        return []
    return [{"id": hashlib.sha256(s.encode()).hexdigest()[:12], "text": s, "metadata": {}, "score": 1.0}]


def _active_workspace_scope() -> Dict[str, Optional[str]]:
    """Resolve active workspace/session scope from environment."""
    workspace_root = (
        os.getenv("CERBERUS_WORKSPACE_ACTIVE_ROOT")
        or os.getenv("WORKSPACE_ROOT")
        or os.getenv("CIR_WORKSPACE")
        or "/workspace"
    )
    workspace_root = str(Path(str(workspace_root or "/workspace")).expanduser().resolve(strict=False))
    workspace_id = os.getenv("CERBERUS_WORKSPACE") or Path(workspace_root).name
    session_id = os.getenv("CERBERUS_SESSION_ID") or os.getenv("SESSION_ID")
    return {
        "workspace_root": workspace_root,
        "workspace_id": str(workspace_id) if workspace_id else None,
        "session_id": str(session_id) if session_id else None,
    }


def _normalize_workspace_marker(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.startswith("/") or text.startswith("~"):
        return str(Path(text).expanduser().resolve(strict=False))
    return text


def _extract_scope_markers(metadata: Dict[str, Any]) -> Dict[str, set[str]]:
    roots: set[str] = set()
    workspace_ids: set[str] = set()
    sessions: set[str] = set()

    for key in ("workspace_root", "workspace", "workspace_path", "workspace_dir"):
        marker = _normalize_workspace_marker(metadata.get(key))
        if marker:
            roots.add(marker)

    for key in ("workspace_id", "workspace_name"):
        marker = _normalize_workspace_marker(metadata.get(key))
        if marker:
            workspace_ids.add(marker)

    for key in ("session_id",):
        marker = _normalize_workspace_marker(metadata.get(key))
        if marker:
            sessions.add(marker)

    provenance = metadata.get("provenance")
    if isinstance(provenance, dict):
        for key in ("workspace_root", "workspace", "workspace_path", "workspace_dir"):
            marker = _normalize_workspace_marker(provenance.get(key))
            if marker:
                roots.add(marker)
        for key in ("workspace_id", "workspace_name"):
            marker = _normalize_workspace_marker(provenance.get(key))
            if marker:
                workspace_ids.add(marker)
        marker = _normalize_workspace_marker(provenance.get("session_id"))
        if marker:
            sessions.add(marker)

    return {"roots": roots, "workspace_ids": workspace_ids, "sessions": sessions}


def _result_matches_active_workspace(result: Dict[str, Any], scope: Dict[str, Optional[str]]) -> bool:
    metadata = result.get("metadata")
    if not isinstance(metadata, dict):
        return False

    markers = _extract_scope_markers(metadata)
    if not markers["roots"] and not markers["workspace_ids"]:
        # Strict mode: results without workspace attribution are dropped.
        return False

    scope_root = _normalize_workspace_marker(scope.get("workspace_root"))
    scope_workspace_id = _normalize_workspace_marker(scope.get("workspace_id"))
    scope_session_id = _normalize_workspace_marker(scope.get("session_id"))

    workspace_match = False
    if scope_root and scope_root in markers["roots"]:
        workspace_match = True
    if scope_workspace_id and scope_workspace_id in markers["workspace_ids"]:
        workspace_match = True
    if not workspace_match:
        return False

    if scope_session_id and markers["sessions"] and scope_session_id not in markers["sessions"]:
        return False

    return True


def _enrich_metadata_with_scope(metadata: Any, texts: List[str]) -> List[Dict[str, Any]]:
    """Ensure each metadata item carries workspace/session provenance."""
    size = len(texts)
    if isinstance(metadata, list):
        normalized = [m if isinstance(m, dict) else {} for m in metadata]
        if len(normalized) < size:
            normalized.extend({} for _ in range(size - len(normalized)))
        metadata_list = normalized[:size]
    elif isinstance(metadata, dict):
        metadata_list = [dict(metadata) for _ in range(size)]
    else:
        metadata_list = [{} for _ in range(size)]

    scope = _active_workspace_scope()
    for i in range(size):
        md = metadata_list[i] if i < len(metadata_list) else {}
        if not isinstance(md, dict):
            md = {}

        if scope.get("workspace_root") and not md.get("workspace_root"):
            md["workspace_root"] = scope["workspace_root"]
        if scope.get("workspace_id") and not md.get("workspace_id"):
            md["workspace_id"] = scope["workspace_id"]
        if scope.get("session_id") and not md.get("session_id"):
            md["session_id"] = scope["session_id"]

        provenance = md.get("provenance")
        if not isinstance(provenance, dict):
            provenance = {}
        if scope.get("workspace_root") and not provenance.get("workspace_root"):
            provenance["workspace_root"] = scope["workspace_root"]
        if scope.get("workspace_id") and not provenance.get("workspace_id"):
            provenance["workspace_id"] = scope["workspace_id"]
        if scope.get("session_id") and not provenance.get("session_id"):
            provenance["session_id"] = scope["session_id"]
        md["provenance"] = provenance

        metadata_list[i] = md

    return metadata_list


class VectorDBAdapter(ABC):
    """Abstract Vector DB adapter.

    Implementations should be lightweight shims around concrete
    vector-database SDKs. Methods should return stable, serializable
    structures where practical (e.g. list-of-dicts for `search`).
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None, embeddings_provider: Optional[Any] = None):
        self.config = VectorDBConfig(**(config or {})) if config is not None else VectorDBConfig()
        # Optional embeddings provider instance. If not provided, a
        # provider will be lazily created by `embed_texts()` using the
        # `get_embeddings_provider` factory from `cerberus.rag.embeddings`.
        self.embeddings_provider = embeddings_provider

    @abstractmethod
    def search(self, collection_name: str, query_text: str, limit: int = 3) -> Any:
        raise NotImplementedError()

    @abstractmethod
    def create_collection(self, collection_name: str) -> bool:
        raise NotImplementedError()

    @abstractmethod
    def add_points(self, id_point: Any, collection_name: str, texts: List[str], metadata: List[dict]) -> bool:
        raise NotImplementedError()

    @abstractmethod
    def health_check(self) -> Dict[str, Any]:
        """Return a health dictionary like {'ok': bool, 'details': str|dict}.

        Implementations should try to be non-destructive and fast.
        """
        raise NotImplementedError()

    def embed_texts(self, texts: List[str]) -> List[List[float]]:
        """Return embeddings for the provided texts using the configured
        embeddings provider. If no provider was supplied at construction
        time, a default provider is created lazily.
        """
        if self.embeddings_provider is None:
            try:
                # Lazy import to avoid import-time cycles
                from cerberus.rag.embeddings import get_embeddings_provider  # type: ignore

                self.embeddings_provider = get_embeddings_provider()
            except Exception:
                # Fall back to a trivial deterministic provider if factory fails
                from cerberus.rag.embeddings import LocalDeterministicEmbeddingsProvider  # type: ignore

                self.embeddings_provider = LocalDeterministicEmbeddingsProvider()

        return self.embeddings_provider.embed_texts(texts)


def get_vector_db_adapter(name: Optional[str] = None, **kwargs) -> VectorDBAdapter:
    """Factory to get an adapter by name or environment `CERBERUS_VECTOR_DB`.

    Behavior:
    - If the caller provides `name` or `CERBERUS_VECTOR_DB` env is set, that value
      is used.
    - If no backend is configured, the factory will prefer an in-process
      local fallback (FAISS-accelerated when available) when running in CI
      or when no Qdrant URL is configured. This avoids requiring an external
      Qdrant instance for developer/CI runs.

    Supported names: "qdrant" (remote), "mempalace", "local", "faiss",
    "inmemory", "chroma" (alias to local fallback).
    """
    env_value = os.getenv("CERBERUS_VECTOR_DB")
    source = (name or env_value or "").lower().strip()

    # If the caller didn't explicitly choose a backend, pick a sensible
    # default: prefer remote Qdrant only when a QDRANT_URL is configured and
    # prefer the local in-process fallback for CI/dev environments.
    if not source:
        # Common CI indicators -> prefer local fallback to avoid external deps
        if os.getenv("CI") or os.getenv("GITHUB_ACTIONS") or os.getenv("GITLAB_CI"):
            source = "local"
        # If a Qdrant HTTP URL is configured, prefer qdrant
        elif os.getenv("QDRANT_URL") or os.getenv("CERBERUS_QDRANT_URL"):
            source = "qdrant"
        else:
            # Default to local in-process adapter to make developer/CI runs
            # convenient without a running Qdrant instance.
            source = "local"
    # If the caller didn't provide an embeddings provider instance, create
    # one via the centralized factory so all adapters share the same
    # embeddings configuration by default.
    if "embeddings_provider" not in kwargs:
        try:
            from cerberus.rag.embeddings import get_embeddings_provider  # type: ignore

            kwargs["embeddings_provider"] = get_embeddings_provider()
        except Exception:
            # Non-fatal: fall back to adapters creating providers lazily.
            pass
    # Prefer registry if backends have been registered
    try:
        if source in _BACKEND_REGISTRY:  # type: ignore[name-defined]
            return _BACKEND_REGISTRY[source](**kwargs)  # type: ignore[name-defined]
    except NameError:
        # Registry not yet defined (older modules importing early) — fall back
        pass

    if source in ("qdrant", "q"):
        return QdrantAdapter(**kwargs)
    if source in ("mempalace", "palace", "mp"):
        return MemPalaceAdapter(**kwargs)
    raise ValueError(f"Unknown vector DB adapter: {source}")


class QdrantAdapter(VectorDBAdapter):
    """Adapter that delegates to the project's existing Qdrant connector.

    This tries to import `QdrantConnector` from `cerberus.rag.vector_db` lazily so
    that environments without the connector won't fail import-time.
    """

    def __init__(self, client: Optional[Any] = None, config: Optional[Dict[str, Any]] = None, embeddings_provider: Optional[Any] = None):
        super().__init__(config=config, embeddings_provider=embeddings_provider)
        self._client = client

    def _ensure_client(self):
        if self._client is None:
            try:
                # The project historically referenced `cerberus.rag.vector_db.QdrantConnector`.
                from cerberus.rag.vector_db import QdrantConnector  # type: ignore

                self._client = QdrantConnector()
            except Exception as exc:  # pragma: no cover - runtime environment dependent
                raise RuntimeError(
                    "QdrantConnector is not available; ensure the project's vector_db "
                    "module or qdrant client is installed and importable"
                ) from exc

    @with_retries(retries=3)
    def search(self, collection_name: str, query_text: str, limit: int = 3):
        self._ensure_client()
        client = self._client
        if client is None:
            raise RuntimeError("Qdrant client not initialized")
        res = client.search(collection_name=collection_name, query_text=query_text, limit=limit)
        try:
            collector().incr("search_queries")
        except Exception:
            pass

        # Normalize heterogeneous backend outputs to canonical form
        try:
            canonical = _canonicalize_search_results(res, limit=limit)
            scope = _active_workspace_scope()
            canonical = [item for item in canonical if _result_matches_active_workspace(item, scope)]
            canonical = canonical[:limit]
            try:
                collector().incr("search_hits", len(canonical))
            except Exception:
                pass
            return canonical
        except Exception:
            # On failure to canonicalize, fall back to raw result
            return res

    @with_retries(retries=2)
    def create_collection(self, collection_name: str) -> bool:
        self._ensure_client()
        client = self._client
        if client is None:
            raise RuntimeError("Qdrant client not initialized")
        return client.create_collection(collection_name)

    @with_retries(retries=2)
    def add_points(self, id_point: Any, collection_name: str, texts: List[str], metadata: List[dict]) -> bool:
        self._ensure_client()
        metadata = _enrich_metadata_with_scope(metadata, texts)
        # Attempt to compute embeddings and pass them to the client if the
        # client's `add_points` supports an explicit `vectors` argument.
        vectors = None
        try:
            vectors = self.embed_texts(texts)
        except Exception:
            vectors = None
        client = self._client
        if client is None:
            raise RuntimeError("Qdrant client not initialized")

        if vectors is not None:
            try:
                return client.add_points(
                    id_point=id_point, collection_name=collection_name, texts=texts, metadata=metadata, vectors=vectors
                )
            except TypeError:
                # Client does not accept `vectors`; fall back to original call
                pass

        return client.add_points(id_point=id_point, collection_name=collection_name, texts=texts, metadata=metadata)

    def health_check(self) -> Dict[str, Any]:
        """Lightweight health check for Qdrant connector.

        Attempts to ensure the client can be instantiated, then looks for
        common health/ping methods. Falls back to an HTTP collection list
        check if `QDRANT_URL` or `CERBERUS_QDRANT_URL` is provided.
        """
        try:
            self._ensure_client()
        except Exception as exc:  # pragma: no cover - environment dependent
            return {"ok": False, "error": str(exc)}

        client = self._client
        if client is None:
            return {"ok": False, "error": "Qdrant client not initialized"}
        # Prefer explicit health_check
        if hasattr(client, "health_check") and callable(getattr(client, "health_check")):
            try:
                res = client.health_check()
                return {"ok": True, "details": res}
            except Exception as exc:  # pragma: no cover - environment dependent
                return {"ok": False, "error": str(exc)}

        # Try ping
        if hasattr(client, "ping") and callable(getattr(client, "ping")):
            try:
                res = client.ping()
                return {"ok": True, "details": getattr(res, "__dict__", str(res))}
            except Exception as exc:  # pragma: no cover - environment dependent
                return {"ok": False, "error": str(exc)}

        # Last resort: check HTTP endpoint if provided
        qdrant_url = os.getenv("QDRANT_URL") or os.getenv("CERBERUS_QDRANT_URL")
        if qdrant_url:
            try:
                import urllib.request

                url = qdrant_url.rstrip("/") + "/collections"
                with urllib.request.urlopen(url, timeout=3) as resp:
                    data = resp.read().decode("utf-8")
                    return {"ok": True, "details": data[:1024]}
            except Exception as exc:  # pragma: no cover - environment dependent
                return {"ok": False, "error": f"HTTP check failed: {exc}"}

        return {"ok": True, "details": "client instantiated (no explicit health endpoint available)"}


class MemPalaceAdapter(VectorDBAdapter):
    """Adapter to query MemPalace.

    Notes:
    - This adapter focuses on *search* (read) so it is safe for A/B testing.
    - `add_points` is intentionally a no-op / not-implemented to avoid
    accidental migration of Cerberus Qdrant data into MemPalace.
    - Two invocation methods are attempted in order: Python API import,
      then CLI via the `mempalace` command.
    """

    def __init__(self, palace_path: Optional[str] = None, config: Optional[Dict[str, Any]] = None, embeddings_provider: Optional[Any] = None):
        super().__init__(config=config, embeddings_provider=embeddings_provider)
        # Allow palace_path to be provided via explicit arg, config options, or env
        self.palace_path = (
            palace_path
            or self.config.options.get("palace_path")
            or os.getenv("CERBERUS_MEMPALACE_PATH", "~/.mempalace/palace")
        )

    def search(self, collection_name: str, query_text: str, limit: int = 3):
        # Try Python API first (if mempalace package is installed)
        try:
            from mempalace.searcher import search_memories  # type: ignore

            # Many mempalace APIs accept palace_path/palace args; adapt if needed.
            try:
                res = search_memories(query_text, palace_path=self.palace_path, top_k=limit)  # type: ignore
            except TypeError:
                # fallback if different signature
                res = search_memories(query_text, palace_path=self.palace_path)  # type: ignore
            # Normalize to canonical shape
            return _canonicalize_search_results(res, limit=limit)
        except Exception:  # pragma: no cover - external dependency
            # Fallback to calling the `mempalace` CLI. Return raw CLI output.
            cmd = ["mempalace", "search", query_text, "--palace", self.palace_path]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
                return _canonicalize_search_results(proc.stdout.strip(), limit=limit)
            except Exception as exc:  # pragma: no cover - runtime dependent
                raise RuntimeError("Failed to query MemPalace: ensure mempalace is installed") from exc

    def create_collection(self, collection_name: str) -> bool:
        # Not applicable for MemPalace (file/closet based) — treat as no-op
        return True
    # MemPalaceAdapter intentionally focuses on search; FAISS helpers
    # belong to the LocalFallbackAdapter implementation and are not
    # provided here.


    def add_points(self, id_point: Any, collection_name: str, texts: List[str], metadata: List[dict]) -> bool:
        # Intentionally not implemented to avoid accidental writes; use mempalace CLI or API
        raise NotImplementedError("MemPalaceAdapter.add_points is not implemented. Use mempalace CLI/API for ingestion.")

    def health_check(self) -> Dict[str, Any]:
        # Check palace path existence first
        try:
            path = Path(self.palace_path).expanduser()
            if path.exists():
                return {"ok": True, "details": f"palace_path exists: {path}"}
        except Exception:
            pass

        # Try CLI
        try:
            proc = subprocess.run(["mempalace", "--version"], capture_output=True, text=True, timeout=3)
            if proc.returncode == 0:
                return {"ok": True, "details": proc.stdout.strip()}
        except Exception:
            pass

        # Try python import
        try:
            import mempalace  # type: ignore

            version = getattr(mempalace, "__version__", "unknown")
            return {"ok": True, "details": f"mempalace python package {version}"}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}


# Backend registry so new adapters can be registered at runtime
_BACKEND_REGISTRY: Dict[str, Type[VectorDBAdapter]] = {}


def register_vector_db_backend(name: str, cls: Type[VectorDBAdapter]) -> None:
    """Register a backend adapter class under a short name."""
    _BACKEND_REGISTRY[name.lower()] = cls


# Register built-in adapters
register_vector_db_backend("qdrant", QdrantAdapter)
register_vector_db_backend("q", QdrantAdapter)
register_vector_db_backend("mempalace", MemPalaceAdapter)
register_vector_db_backend("palace", MemPalaceAdapter)
register_vector_db_backend("mp", MemPalaceAdapter)


def list_registered_backends() -> List[str]:
    """Return names of currently registered vector DB backends."""
    return list(_BACKEND_REGISTRY.keys())


def get_rag_status() -> Dict[str, Any]:
    """Return a lightweight snapshot of RAG-related metrics and adapter state.

    This function is intentionally conservative: it returns the global
    metrics snapshot and an adapters-summary placeholder to avoid
    import-time failures for tools that expose RAG status.
    """
    try:
        metrics_snapshot = collector().snapshot()
    except Exception:
        metrics_snapshot = {}

    # Provide a best-effort summary of adapter cache state; avoid
    # importing adapters or relying on runtime instances here to keep
    # this function side-effect free at import time.
    adapters_summary: Dict[str, Any] = {k: {"registered": True} for k in _BACKEND_REGISTRY.keys()}

    return {"metrics": metrics_snapshot, "adapters": adapters_summary}


class LocalFallbackAdapter(VectorDBAdapter):
    """Lightweight in-memory vector store with optional FAISS acceleration.

    This adapter is intended for local development and testing. It stores
    vectors, texts, and metadata in-process and performs a linear scan
    search when FAISS is not available. If `use_faiss` is set in the
    adapter config options and `faiss` + `numpy` are installed, searches
    will use FAISS for speed.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None, embeddings_provider: Optional[Any] = None):
        super().__init__(config=config, embeddings_provider=embeddings_provider)
        opts = self.config.options or {}
        env_use = os.getenv("CERBERUS_USE_FAISS", "").strip()
        self.use_faiss = bool(opts.get("use_faiss") or env_use in ("1", "true", "True"))
        self._faiss_available = False
        self._faiss = None
        self._np = None
        if self.use_faiss:
            try:
                import faiss  # type: ignore
                import numpy as np  # type: ignore

                self._faiss = faiss
                self._np = np
                self._faiss_available = True
            except Exception:
                self._faiss_available = False
        # collections: name -> {'ids':[], 'texts':[], 'metadata':[], 'vectors':[]}
        self._collections: Dict[str, Dict[str, List[Any]]] = {}
        # Cached FAISS indexes per collection (when faiss is available).
        # _faiss_indexes[collection_name] -> faiss.Index or None
        # _faiss_maps[collection_name] -> list mapping faiss index position -> original collection index
        self._faiss_indexes: Dict[str, Any] = {}
        self._faiss_maps: Dict[str, List[int]] = {}

        # Persistence / background IO
        self._persist_dir = Path(os.getenv("CERBERUS_LOCAL_PERSIST_DIR", "~/.cerberus/memory/local/")).expanduser()
        try:
            self._persist_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        # Executor and synchronization for background saves
        self._io_executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        self._io_lock = threading.Lock()
        self._pending_persist_collections = set()
        # per-collection held lock fds (if we claimed exclusive ownership)
        self._locks: Dict[str, int] = {}

        # Ensure graceful shutdown to flush pending writes and release locks
        try:
            atexit.register(self._shutdown_persistence)
        except Exception:
            pass

    # FAISS helpers (moved here from MemPalaceAdapter) ------------------
    def _build_faiss_index(self, collection_name: str, dim: Optional[int] = None) -> None:
        """Build or rebuild a FAISS Index for the given collection.

        If `dim` is provided, only vectors with matching dimensionality
        will be included. The resulting index is cached in
        `self._faiss_indexes` and a mapping from faiss-pos -> collection
        index is stored in `self._faiss_maps`.
        """
        if not getattr(self, "_faiss_available", False):
            self._faiss_indexes[collection_name] = None
            self._faiss_maps[collection_name] = []
            return
        if collection_name not in self._collections:
            self._faiss_indexes[collection_name] = None
            self._faiss_maps[collection_name] = []
            return
        col = self._collections[collection_name]
        vectors = col.get("vectors", [])

        # Select valid vectors matching requested dim (if provided)
        if dim is not None:
            valid = [i for i, v in enumerate(vectors) if v is not None and len(v) == dim]
        else:
            # pick first valid vector to establish dimension
            first = next((i for i, v in enumerate(vectors) if v is not None), None)
            if first is None:
                self._faiss_indexes[collection_name] = None
                self._faiss_maps[collection_name] = []
                return
            chosen_dim = len(vectors[first])
            valid = [i for i, v in enumerate(vectors) if v is not None and len(v) == chosen_dim]

        if not valid:
            self._faiss_indexes[collection_name] = None
            self._faiss_maps[collection_name] = []
            return

        try:
            if self._np is None or self._faiss is None:
                # FAISS or numpy not available at runtime
                self._faiss_indexes[collection_name] = None
                self._faiss_maps[collection_name] = []
                return
            vecs = [vectors[i] for i in valid if vectors[i] is not None]
            if not vecs:
                self._faiss_indexes[collection_name] = None
                self._faiss_maps[collection_name] = []
                return
            arr = self._np.array(vecs, dtype="float32")
            index = self._faiss.IndexFlatIP(arr.shape[1])
            index.add(arr)
            self._faiss_indexes[collection_name] = index
            self._faiss_maps[collection_name] = valid.copy()
        except Exception:
            # On any failure, ensure cache is cleared so caller falls back
            self._faiss_indexes[collection_name] = None
            self._faiss_maps[collection_name] = []

    def _invalidate_faiss_index(self, collection_name: str) -> None:
        try:
            self._faiss_indexes[collection_name] = None
            self._faiss_maps[collection_name] = []
        except Exception:
            pass

    # Persistence helpers (LocalFallbackAdapter) -------------------------
    def _safe_collection_filename(self, collection_name: str) -> str:
        # sanitize collection name for filesystem usage
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", collection_name)
        return safe

    def _asset_paths(self, collection_name: str):
        safe = self._safe_collection_filename(collection_name)
        persist_dir = Path(self._persist_dir)
        idx_path = str(persist_dir / f"{safe}.index")
        json_path = str(persist_dir / f"{safe}.json")
        lock_path = str(persist_dir / f"{safe}.lock")
        return idx_path, json_path, lock_path

    def _claim_collection_lock(self, collection_name: str, timeout: float = 0.0) -> bool:
        """Try to claim an exclusive lock for a collection. If claimed,
        the file descriptor is stored in self._locks and held until
        _release_collection_lock is called.
        """
        _, _, lock_path = self._asset_paths(collection_name)
        try:
            fd = os.open(lock_path, os.O_RDWR | os.O_CREAT)
        except Exception:
            return False

        start = time.time()
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                # success; keep fd open to hold lock
                self._locks[collection_name] = fd
                return True
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN):
                    try:
                        os.close(fd)
                    except Exception:
                        pass
                    return False
                # retry until timeout
                if timeout and (time.time() - start) >= timeout:
                    try:
                        os.close(fd)
                    except Exception:
                        pass
                    return False
                if not timeout:
                    # if no timeout provided, do a single non-blocking try
                    try:
                        os.close(fd)
                    except Exception:
                        pass
                    return False
                time.sleep(0.1)

    def _release_collection_lock(self, collection_name: str) -> None:
        fd = self._locks.pop(collection_name, None)
        if not fd:
            return
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except Exception:
                pass
        finally:
            try:
                os.close(fd)
            except Exception:
                pass

    def _load_persisted_collection(self, collection_name: str) -> bool:
        """Attempt to load a persisted collection (json + faiss index).
        If loading succeeds, populate self._collections, _faiss_indexes,
        and _faiss_maps. Returns True on successful load.
        """
        idx_path, json_path, lock_path = self._asset_paths(collection_name)
        if not Path(json_path).exists() or not Path(idx_path).exists():
            return False

        # Try to claim lock for exclusive ownership; if we fail, still try
        # to load read-only but avoid persisting later.
        claimed = self._claim_collection_lock(collection_name, timeout=0.1)

        try:
            with open(json_path, "r") as fh:
                data = json.load(fh)
            # restore collection structure
            ids = data.get("ids", [])
            texts = data.get("texts", [])
            metadata = data.get("metadata", [])
            vectors = data.get("vectors", [])
            faiss_map = data.get("faiss_map", None)

            # ensure lists
            vectors = [v if v is None else list(v) for v in vectors]

            self._collections[collection_name] = {"ids": ids, "texts": texts, "metadata": metadata, "vectors": vectors}

            if self._faiss_available and self._faiss is not None:
                try:
                    idx = self._faiss.read_index(idx_path)
                    self._faiss_indexes[collection_name] = idx
                    if faiss_map is None:
                        # default mapping: sequential
                        self._faiss_maps[collection_name] = list(range(len(vectors)))
                    else:
                        self._faiss_maps[collection_name] = list(faiss_map)
                except Exception:
                    # If index cannot be read, mark as not cached
                    self._faiss_indexes[collection_name] = None
                    self._faiss_maps[collection_name] = []
            else:
                self._faiss_indexes[collection_name] = None
                self._faiss_maps[collection_name] = []
            return True
        except Exception:
            # On any failure, release a temporary claim
            if claimed:
                try:
                    self._release_collection_lock(collection_name)
                except Exception:
                    pass
            return False

    def _save_persisted_collection(self, collection_name: str) -> None:
        """Persist collection metadata and faiss index to disk atomically.
        This will only write if a faiss index exists and we can acquire
        the lock (either we previously claimed it, or we can obtain it
        non-blocking)."""
        if not self._faiss_available:
            return
        if collection_name not in self._collections:
            return

        idx_path, json_path, lock_path = self._asset_paths(collection_name)

        # Determine if we hold the claim
        own_fd = self._locks.get(collection_name)
        acquired_temp = None
        if not own_fd:
            # try to acquire non-blocking for a short time
            try:
                fd = os.open(lock_path, os.O_RDWR | os.O_CREAT)
            except Exception:
                return
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired_temp = fd
            except OSError:
                try:
                    os.close(fd)
                except Exception:
                    pass
                return

        try:
            # Prepare JSON payload
            col = self._collections[collection_name]
            payload = {
                "collection_name": collection_name,
                "ids": col.get("ids", []),
                "texts": col.get("texts", []),
                "metadata": col.get("metadata", []),
                "vectors": [None if v is None else [float(x) for x in v] for v in col.get("vectors", [])],
                "faiss_map": self._faiss_maps.get(collection_name, []),
            }

            # Write JSON atomically
            tmp_json = json_path + ".tmp"
            try:
                with open(tmp_json, "w") as fh:
                    json.dump(payload, fh, ensure_ascii=False)
                os.replace(tmp_json, json_path)
            finally:
                try:
                    if Path(tmp_json).exists():
                        os.remove(tmp_json)
                except Exception:
                    pass

            # Write faiss index atomically
            idx = self._faiss_indexes.get(collection_name)
            if idx is not None and self._faiss is not None:
                tmp_idx = idx_path + ".tmp"
                try:
                    self._faiss.write_index(idx, tmp_idx)
                    os.replace(tmp_idx, idx_path)
                except Exception:
                    try:
                        if Path(tmp_idx).exists():
                            os.remove(tmp_idx)
                    except Exception:
                        pass
        finally:
            if acquired_temp:
                try:
                    fcntl.flock(acquired_temp, fcntl.LOCK_UN)
                except Exception:
                    pass
                try:
                    os.close(acquired_temp)
                except Exception:
                    pass

    def _schedule_persist(self, collection_name: str) -> None:
        with self._io_lock:
            if collection_name in self._pending_persist_collections:
                return
            self._pending_persist_collections.add(collection_name)
        def _worker(name: str):
            try:
                self._save_persisted_collection(name)
            finally:
                with self._io_lock:
                    self._pending_persist_collections.discard(name)
        try:
            self._io_executor.submit(_worker, collection_name)
        except Exception:
            # best-effort: ignore scheduling failures
            with self._io_lock:
                self._pending_persist_collections.discard(collection_name)

    def _shutdown_persistence(self) -> None:
        try:
            # wait for background tasks to finish
            try:
                self._io_executor.shutdown(wait=True)
            except Exception:
                pass
            # release any held locks
            for cname in list(self._locks.keys()):
                try:
                    self._release_collection_lock(cname)
                except Exception:
                    pass
        except Exception:
            pass

    def create_collection(self, collection_name: str) -> bool:
        if collection_name in self._collections:
            return True
        # Attempt to auto-load a persisted collection if present
        try:
            loaded = self._load_persisted_collection(collection_name)
            if loaded:
                return True
        except Exception:
            pass

        self._collections[collection_name] = {"ids": [], "texts": [], "metadata": [], "vectors": []}
        # initialize cache placeholders
        self._faiss_indexes[collection_name] = None
        self._faiss_maps[collection_name] = []
        return True

    def add_points(self, id_point: Any, collection_name: str, texts: List[str], metadata: List[dict]) -> bool:
        # Ensure collection
        self.create_collection(collection_name)
        col = self._collections[collection_name]

        # helper imports and defaults
        import uuid
        metadata_list: List[Dict[str, Any]] = []

        # Normalize ids and metadata lists to match texts length
        if isinstance(id_point, (list, tuple)) and len(id_point) == len(texts):
            ids = list(id_point)
        else:
            if len(texts) == 1:
                ids = [id_point]
            else:
                # generate per-item ids when a single id is provided for multiple texts
                import uuid

                base = id_point or ""
                ids = [f"{base}-{i}" if base else str(uuid.uuid4()) for i in range(len(texts))]

        if metadata is None:
            metadata = [{} for _ in texts]
        elif isinstance(metadata, (list, tuple)) and len(metadata) == len(texts):
            metadata_list = list(metadata)
        elif isinstance(metadata, dict):
            metadata_list = [metadata for _ in texts]
        else:
            # Fallback: try to coerce
            metadata_list = [m if isinstance(m, dict) else {} for m in (metadata if isinstance(metadata, list) else [metadata])]
            if len(metadata_list) < len(texts):
                metadata_list = metadata_list * (len(texts) // len(metadata_list) + 1)
            metadata_list = metadata_list[: len(texts)]

        # Ensure metadata_list variable exists
        if 'metadata_list' not in locals():
            metadata_list = [{} for _ in texts]

        # Ensure provenance metadata exists for each text (best-effort)
        try:
            session = os.getenv("CERBERUS_SESSION_ID") or os.getenv("SESSION_ID")
        except Exception:
            session = None

        for i, t in enumerate(texts):
            try:
                md = metadata_list[i] if i < len(metadata_list) else {}
            except Exception:
                md = {}
            if not isinstance(md, dict):
                md = {}
            if "provenance" not in md:
                try:
                    ch = hashlib.sha256((t or "").encode("utf-8")).hexdigest()
                except Exception:
                    ch = None
                prov = {
                    "source": __name__,
                    "timestamp": _dt.datetime.utcnow().isoformat() + "Z",
                    "session_id": session,
                    "tool_name": "local_add_points",
                    "original_text": t,
                    "chunk_id": ids[i] if i < len(ids) else str(uuid.uuid4()),
                    "content_hash": ch,
                }
                md["provenance"] = prov
            # ensure metadata_list updated
            if i < len(metadata_list):
                metadata_list[i] = md
            else:
                metadata_list.append(md)

        # Compute embeddings (best-effort)
        try:
            vectors = self.embed_texts(texts)
        except Exception:
            vectors = [None for _ in texts]

        # Track starting index so we can update cached FAISS index incrementally
        start_index = len(col["vectors"])
        for i, t in enumerate(texts):
            col["ids"].append(ids[i])
            col["texts"].append(t)
            col["metadata"].append(metadata_list[i])
            col["vectors"].append(vectors[i] if vectors and i < len(vectors) else None)

        # Update FAISS cache incrementally when possible
        if self._faiss_available:
            try:
                # Collect newly appended valid vectors and their absolute indices
                new_items = []  # tuples of (abs_index, vector)
                for rel_i in range(len(texts)):
                    abs_i = start_index + rel_i
                    v = col["vectors"][abs_i]
                    if v is not None:
                        new_items.append((abs_i, v))

                if new_items:
                    # If there is an existing index for this collection, try to append
                    idx = self._faiss_indexes.get(collection_name)
                    if idx is not None:
                        # Ensure dimensionality matches existing index
                        idx_dim = getattr(idx, "d", None)
                        if idx_dim is None:
                            # Unknown dimension, rebuild index from scratch
                            self._build_faiss_index(collection_name)
                        else:
                            compatible = all(len(v) == idx_dim for (_i, v) in new_items)
                            if compatible:
                                np_mod = self._np
                                faiss_mod = self._faiss
                                if np_mod is None or faiss_mod is None:
                                    # missing dependencies -> rebuild index instead
                                    self._build_faiss_index(collection_name)
                                else:
                                    arr = np_mod.array([v for (_i, v) in new_items], dtype="float32")
                                    idx.add(arr)
                                # extend mapping
                                self._faiss_maps.setdefault(collection_name, [])
                                self._faiss_maps[collection_name].extend([_i for (_i, _v) in new_items])
                            else:
                                # Incompatible dimensions; rebuild index using a consistent dim
                                self._build_faiss_index(collection_name)
                    else:
                        # No index yet; build one using the dim of the first new vector
                        first_dim = len(new_items[0][1])
                        self._build_faiss_index(collection_name, dim=first_dim)
            except Exception:
                # Don't let indexing failures block writes
                pass
        # Schedule background persistence when faiss is enabled
        if self._faiss_available:
            try:
                self._schedule_persist(collection_name)
            except Exception:
                pass

        return True

    def export_collection(self, collection_name: str) -> List[Dict[str, Any]]:
        """Return a list of documents for the collection with optional vectors.

        Each document is a dict: {id, text, metadata, vector}
        """
        if collection_name not in self._collections:
            return []
        col = self._collections[collection_name]
        out: List[Dict[str, Any]] = []
        for i in range(len(col["ids"])):
            out.append({
                "id": col["ids"][i],
                "text": col["texts"][i],
                "metadata": col["metadata"][i],
                "vector": col["vectors"][i],
            })
        return out

    def delete_points(self, collection_name: str, ids: List[str]) -> bool:
        """Delete points by id from the local collection. Returns True if any removed."""
        if collection_name not in self._collections:
            return False
        col = self._collections[collection_name]
        removed = False
        # build new lists excluding ids to remove
        new_ids, new_texts, new_meta, new_vectors = [], [], [], []
        for i, existing_id in enumerate(col["ids"]):
            if existing_id in ids:
                removed = True
                continue
            new_ids.append(existing_id)
            new_texts.append(col["texts"][i])
            new_meta.append(col["metadata"][i])
            new_vectors.append(col["vectors"][i])
        if removed:
            col["ids"] = new_ids
            col["texts"] = new_texts
            col["metadata"] = new_meta
            col["vectors"] = new_vectors
            # Invalidate FAISS cache for this collection; mapping changed
            try:
                self._faiss_indexes[collection_name] = None
                self._faiss_maps[collection_name] = []
            except Exception:
                pass
            # persist updated collection state in background
            if self._faiss_available:
                try:
                    self._schedule_persist(collection_name)
                except Exception:
                    pass
        return removed

    def list_collections(self) -> List[str]:
        return list(self._collections.keys())

    def purge_older_than(self, cutoff_ts: float) -> int:
        """Purge documents whose provenance timestamp is older than cutoff_ts.

        Returns the number of deleted items.
        """
        deleted = 0
        for cname, col in self._collections.items():
            # record original size so we can detect removals and invalidate FAISS cache
            orig_count = len(col.get("ids", []))
            keep_ids = []
            keep_texts = []
            keep_meta = []
            keep_vectors = []
            for i, md in enumerate(col.get("metadata", [])):
                prov = md.get("provenance") if isinstance(md, dict) else None
                ts_ok = True
                if isinstance(prov, dict):
                    ts = prov.get("timestamp")
                    if ts:
                        try:
                            # support both with and without fractional seconds
                            if "." in ts:
                                fmt = "%Y-%m-%dT%H:%M:%S.%fZ"
                            else:
                                fmt = "%Y-%m-%dT%H:%M:%SZ"
                            import datetime as _dt

                            t = _dt.datetime.strptime(ts, fmt)
                            tsec = t.replace(tzinfo=_dt.timezone.utc).timestamp()
                        except Exception:
                            tsec = None
                        if tsec is not None and tsec < cutoff_ts:
                            ts_ok = False
                if ts_ok:
                    keep_ids.append(col["ids"][i])
                    keep_texts.append(col["texts"][i])
                    keep_meta.append(col["metadata"][i])
                    keep_vectors.append(col["vectors"][i])
                else:
                    deleted += 1
            col["ids"] = keep_ids
            col["texts"] = keep_texts
            col["metadata"] = keep_meta
            col["vectors"] = keep_vectors
            # If any items were removed for this collection, invalidate FAISS cache
            if len(keep_ids) != orig_count:
                try:
                    self._faiss_indexes[cname] = None
                    self._faiss_maps[cname] = []
                except Exception:
                    pass
                # persist updated collection state in background
                if self._faiss_available:
                    try:
                        self._schedule_persist(cname)
                    except Exception:
                        pass
        return deleted

    def search(self, collection_name: str, query_text: str, limit: int = 3):
        try:
            collector().incr("search_queries")
        except Exception:
            pass
        if collection_name not in self._collections:
            try:
                collector().incr("search_hits", 0)
            except Exception:
                pass
            return []
        col = self._collections[collection_name]
        if not col["texts"]:
            try:
                collector().incr("search_hits", 0)
            except Exception:
                pass
            return []

        try:
            qvec = self.embed_texts([query_text])[0]
        except Exception:
            try:
                collector().incr("search_hits", 0)
            except Exception:
                pass
            return []

        # Filter out vectors that are None or the wrong dimension
        vectors = col["vectors"]
        valid = [i for i, v in enumerate(vectors) if v is not None and len(v) == len(qvec)]
        if not valid:
            return []

        # FAISS path
        if self._faiss_available:
            try:
                # Ensure a cached FAISS index exists for this collection and
                # matches the query dimensionality. This avoids rebuilding a
                # fresh index on every search.
                self._build_faiss_index(collection_name, dim=len(qvec))
                idx = self._faiss_indexes.get(collection_name)
                if idx is not None and getattr(idx, "ntotal", 0) > 0:
                    np_mod = self._np
                    faiss_mod = self._faiss
                    if np_mod is None or faiss_mod is None:
                        # Missing numpy/faiss at runtime -> fall back to linear scan
                        raise RuntimeError("numpy/faiss unavailable")
                    qarr = np_mod.array([qvec], dtype="float32")
                    k = min(limit, int(getattr(idx, "ntotal", 0)))
                    D, I = idx.search(qarr, k)
                    results = []
                    fmap = self._faiss_maps.get(collection_name, [])
                    for score, pos in zip(D[0], I[0]):
                        if int(pos) < 0:
                            continue
                        orig_i = fmap[int(pos)] if int(pos) < len(fmap) else None
                        if orig_i is None:
                            continue
                        results.append({
                            "id": col["ids"][orig_i],
                            "text": col["texts"][orig_i],
                            "metadata": col["metadata"][orig_i],
                            "score": float(score),
                        })
                    try:
                        collector().incr("search_hits", len(results))
                    except Exception:
                        pass
                    return results
            except Exception:
                # Fall back to naive linear scan when FAISS fails
                pass

        # Naive linear scan (dot product)
        scores = []
        for i in valid:
            v = vectors[i]
            score = 0.0
            try:
                score = sum(float(a) * float(b) for a, b in zip(qvec, v))
            except Exception:
                score = 0.0
            scores.append((score, i))

        scores.sort(key=lambda x: x[0], reverse=True)
        results = []
        for score, i in scores[:limit]:
            results.append({
                "id": col["ids"][i],
                "text": col["texts"][i],
                "metadata": col["metadata"][i],
                "score": float(score),
            })
        try:
            collector().incr("search_hits", len(results))
        except Exception:
            pass
        return results

    def health_check(self) -> Dict[str, Any]:
        return {
            "ok": True,
            "details": {
                "type": "local-fallback",
                "faiss_available": bool(self._faiss_available),
                "collections": list(self._collections.keys()),
            },
        }


# Register local fallback adapter aliases
register_vector_db_backend("local", LocalFallbackAdapter)
register_vector_db_backend("faiss", LocalFallbackAdapter)
register_vector_db_backend("inmemory", LocalFallbackAdapter)
register_vector_db_backend("chroma", LocalFallbackAdapter)
