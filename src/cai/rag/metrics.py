"""Simple in-memory metrics collector for RAG ingestion and retrieval.

This lightweight collector is intentionally dependency-free so it can
be used in CI and development. It provides counters, gauges, and
simple histograms (as lists) that can be exported for monitoring.
"""
from __future__ import annotations

import threading
from typing import Dict, List, Any


class MetricsCollector:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.counters: Dict[str, int] = {}
        self.gauges: Dict[str, float] = {}
        self.histograms: Dict[str, List[float]] = {}

    def incr(self, name: str, amount: int = 1) -> None:
        with self._lock:
            self.counters[name] = int(self.counters.get(name, 0)) + int(amount)

    def set_gauge(self, name: str, value: float) -> None:
        with self._lock:
            self.gauges[name] = float(value)

    def observe(self, name: str, value: float) -> None:
        with self._lock:
            self.histograms.setdefault(name, []).append(float(value))

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "counters": dict(self.counters),
                "gauges": dict(self.gauges),
                "histograms": {k: list(v) for k, v in self.histograms.items()},
            }


# Global collector instance
_COLLECTOR = MetricsCollector()


def collector() -> MetricsCollector:
    return _COLLECTOR


def export_metrics() -> Dict[str, Any]:
    """Return a snapshot of current metrics."""
    return _COLLECTOR.snapshot()


# ---------------------------------------------------------------------------
# RetrievalFidelityTracker — Precision@k + query/result audit log
# ---------------------------------------------------------------------------


class _RAGAuditWriter:
    """Singleton JSONL writer for RAG query/response audit events.

    Writes one JSON object per line to
    ``$CIR_WORKSPACE/logs/rag_audit.jsonl``.  A background daemon thread
    drains the in-process queue so callers never block on disk I/O.
    """

    _instance: "Optional[_RAGAuditWriter]" = None
    _cls_lock: threading.Lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> "_RAGAuditWriter":
        if cls._instance is None:
            with cls._cls_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def __init__(self) -> None:
        import queue as _queue
        import os as _os
        self._queue: "_queue.Queue[Dict[str, Any]]" = _queue.Queue()
        workspace = _os.getenv("CIR_WORKSPACE", "/workspace")
        log_dir = _os.path.join(workspace, "logs")
        try:
            _os.makedirs(log_dir, exist_ok=True)
        except Exception:
            log_dir = "/tmp"
        self._path = _os.path.join(log_dir, "rag_audit.jsonl")
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._writer_loop, daemon=True, name="rag-audit-writer"
        )
        self._thread.start()

    def append(self, event: Dict[str, Any]) -> None:
        import time as _time
        event.setdefault("ts", _time.time())
        try:
            self._queue.put_nowait(event)
        except Exception:
            pass

    def _writer_loop(self) -> None:
        import json as _json
        while not self._stop.is_set():
            try:
                event = self._queue.get(timeout=0.5)
                try:
                    line = _json.dumps(event, default=str) + "\n"
                    with open(self._path, "a", encoding="utf-8") as fh:
                        fh.write(line)
                except Exception:
                    pass
            except Exception:
                pass


class RetrievalFidelityTracker:
    """Tracks Precision@k per query and writes every event to the audit log.

    If ``relevant_ids`` is provided to :meth:`record`, Precision@k is computed
    as the fraction of returned results whose ``id`` appears in the relevant
    set.  When no ground-truth is available, the fidelity score is 0.0 but the
    event is still written to the audit log for traceability.
    """

    def __init__(self, audit_writer: "Optional[_RAGAuditWriter]" = None) -> None:
        self._audit = audit_writer or _RAGAuditWriter.get_instance()
        self._lock = threading.Lock()
        self._total_queries: int = 0
        self._precision_sum: float = 0.0

    def record(
        self,
        query: str,
        results: List[Dict[str, Any]],
        relevant_ids: "Optional[List[Any]]" = None,
    ) -> float:
        """Record a retrieval event; returns Precision@k (0.0 if no ground-truth)."""
        k = len(results)
        precision = 0.0
        if relevant_ids and k > 0:
            hit_set = {str(r) for r in relevant_ids}
            hits = sum(
                1 for r in results
                if str(r.get("id") or r.get("text") or "") in hit_set
            )
            precision = hits / k
        with self._lock:
            self._total_queries += 1
            self._precision_sum += precision
        self._audit.append({
            "event": "retrieval",
            "query": query,
            "precision_at_k": precision,
            "k": k,
            "result_ids": [r.get("id") or (r.get("text") or "")[:80] for r in results],
        })
        collector().incr("retrieval_queries")
        collector().observe("retrieval_precision_at_k", precision)
        return precision

    def mean_precision(self) -> float:
        with self._lock:
            if self._total_queries == 0:
                return 0.0
            return self._precision_sum / self._total_queries


class HardwareSaturationMonitor:
    """Samples RAM and VRAM utilisation and pushes readings to the metrics collector.

    Requires ``psutil`` for system RAM and ``nvidia-smi`` in PATH for
    VRAM.  Both are best-effort; missing dependencies produce partial
    readings without raising.
    """

    def sample(self) -> Dict[str, float]:
        """Return a dict of hardware readings and push gauges to the collector."""
        readings: Dict[str, float] = {}
        # RAM via psutil
        try:
            import psutil  # type: ignore
            vm = psutil.virtual_memory()
            readings["ram_used_gb"] = round(vm.used / (1024 ** 3), 2)
            readings["ram_total_gb"] = round(vm.total / (1024 ** 3), 2)
            readings["ram_pct"] = round(float(vm.percent), 1)
        except Exception:
            pass
        # VRAM via nvidia-smi (no pynvml required)
        try:
            import subprocess
            out = subprocess.check_output(
                [
                    "nvidia-smi",
                    "--query-gpu=memory.used,memory.total",
                    "--format=csv,noheader,nounits",
                ],
                timeout=3,
                stderr=subprocess.DEVNULL,
            ).decode().strip()
            for line in out.splitlines():
                parts = line.split(",")
                if len(parts) >= 2:
                    readings["vram_used_mb"] = float(parts[0].strip())
                    readings["vram_total_mb"] = float(parts[1].strip())
                    break
        except Exception:
            pass
        for k, v in readings.items():
            collector().set_gauge(f"hw_{k}", v)
        return readings


__all__ = [
    "collector",
    "export_metrics",
    "MetricsCollector",
    "RetrievalFidelityTracker",
    "HardwareSaturationMonitor",
    "_RAGAuditWriter",
]
