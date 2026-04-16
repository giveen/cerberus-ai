"""Local-only debug logger for Cerberus runtime internals.

This logger is intentionally offline-first: it writes structured records to a
workspace-local log file and never attempts remote export.
"""

from __future__ import annotations

from datetime import UTC, datetime
import json
import os
from pathlib import Path
import threading
from typing import Any, Dict


class DebugLogger:
    """Thread-safe line logger that writes JSONL records to a local .log file."""

    def __init__(self, log_path: Path) -> None:
        self._log_path = log_path
        self._lock = threading.Lock()
        self._log_path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._log_path

    def write(self, *, channel: str, message: str, payload: Dict[str, Any] | None = None) -> None:
        record = {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "channel": channel,
            "message": message,
            "payload": payload or {},
        }
        line = json.dumps(record, ensure_ascii=True)
        with self._lock:
            with self._log_path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        # Deliberately avoid stdout/stderr mirroring so debug records never leak
        # back into conversation context.
        return None


_LOGGER: DebugLogger | None = None
_LOGGER_LOCK = threading.Lock()


def _workspace_root() -> Path:
    explicit = os.getenv("CERBERUS_WORKSPACE_ACTIVE_ROOT") or os.getenv("WORKSPACE_ROOT")
    if explicit:
        return Path(explicit).expanduser().resolve()
    return Path.cwd().resolve()


def get_debug_logger() -> DebugLogger:
    """Return the process-wide DebugLogger instance."""
    global _LOGGER
    if _LOGGER is None:
        with _LOGGER_LOCK:
            if _LOGGER is None:
                log_path = _workspace_root() / "logs" / "runtime_debug.jsonl"
                _LOGGER = DebugLogger(log_path=log_path)
    return _LOGGER
