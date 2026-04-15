"""Cerberus AI forensic audit logging utilities for REPL and UI telemetry.

This module provides:
- ForensicHandler: asynchronous, batched JSONL persistence + in-memory audit buffer
- CerebroLogger: semantic, security-first logger with terminal + disk + buffer sinks
- setup_session_logging: backward-compatible history file bootstrap used by CLI
"""

from __future__ import annotations

import atexit
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
import json
import logging
from logging import Logger
import os
from pathlib import Path
import queue
try:
    import readline
except ImportError:  # pragma: no cover
    readline = None  # type: ignore[assignment]
import secrets
import threading
from typing import Any, Callable, Deque, Dict, List, Optional, Sequence

from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from cai.memory.logic import clean_data
from cai.tools.workspace import get_project_space

LOG_AUDIT = "LOG_AUDIT"
LOG_THOUGHT = "LOG_THOUGHT"
LOG_ACTION = "LOG_ACTION"
LOG_FINDING = "LOG_FINDING"

__all__ = [
    "LOG_AUDIT",
    "LOG_THOUGHT",
    "LOG_ACTION",
    "LOG_FINDING",
    "ForensicHandler",
    "CerebroLogger",
    "get_cerebro_logger",
    "append_history_entry",
    "load_history_entries",
    "prepare_prompt_history_file",
    "setup_session_logging",
]


_LEVEL_TO_NUM: Dict[str, int] = {
    LOG_AUDIT: 25,
    LOG_THOUGHT: 15,
    LOG_ACTION: 24,
    LOG_FINDING: 35,
}

_LEVEL_TO_STYLE: Dict[str, Dict[str, str]] = {
    LOG_AUDIT: {"icon": "[cyan]A[/cyan]", "label": "[bold cyan]AUDIT[/bold cyan]"},
    LOG_THOUGHT: {"icon": "[magenta]T[/magenta]", "label": "[bold magenta]THOUGHT[/bold magenta]"},
    LOG_ACTION: {"icon": "[yellow]X[/yellow]", "label": "[bold yellow]ACTION[/bold yellow]"},
    LOG_FINDING: {"icon": "[red]F[/red]", "label": "[bold red]FINDING[/bold red]"},
}

_HISTORY_FILE = Path.home() / ".cai_history"
_LEGACY_HISTORY_FILE = Path.home() / ".cai" / "history.txt"
_HISTORY_LENGTH = 1000
_READLINE_BOOTSTRAPPED = False


@dataclass(frozen=True)
class ForensicEvent:
    timestamp: str
    session_id: str
    level: str
    actor: str
    message: str
    command: Optional[str]
    data: Dict[str, Any]
    tags: List[str]
    workspace: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "level": self.level,
            "actor": self.actor,
            "message": self.message,
            "command": self.command,
            "data": self.data,
            "tags": self.tags,
            "workspace": self.workspace,
        }


class ForensicHandler:
    """Async JSONL writer with in-memory secure audit buffer and workspace rotation."""

    def __init__(
        self,
        *,
        session_id: Optional[str] = None,
        max_buffer: int = 4096,
        max_queue: int = 8192,
        batch_size: int = 64,
        flush_interval_sec: float = 0.20,
        redactor: Callable[[Any], Any] = clean_data,
    ) -> None:
        self._session_id = session_id or self._new_session_id()
        self._max_buffer = max(128, max_buffer)
        self._batch_size = max(1, batch_size)
        self._flush_interval = max(0.05, flush_interval_sec)
        self._redactor = redactor

        self._queue: queue.Queue[Dict[str, Any]] = queue.Queue(maxsize=max_queue)
        self._audit_buffer: Deque[Dict[str, Any]] = deque(maxlen=self._max_buffer)
        self._buffer_lock = threading.Lock()

        self._active_workspace: Optional[Path] = None
        self._active_log_path: Optional[Path] = None
        self._dropped_events = 0

        self._stop_event = threading.Event()
        self._worker = threading.Thread(target=self._writer_loop, name="cerebro-forensic-writer", daemon=True)
        self._worker.start()

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def active_log_path(self) -> Optional[Path]:
        return self._active_log_path

    def emit(self, payload: Dict[str, Any]) -> None:
        sanitized = self._sanitize(payload)

        with self._buffer_lock:
            self._audit_buffer.append(sanitized)

        try:
            self._queue.put_nowait(sanitized)
        except queue.Full:
            self._dropped_events += 1

    def recent(self, *, limit: int = 200, levels: Optional[Sequence[str]] = None) -> List[Dict[str, Any]]:
        selected = set(levels or [])
        with self._buffer_lock:
            data = list(self._audit_buffer)
        if selected:
            data = [item for item in data if str(item.get("level")) in selected]
        if limit <= 0:
            return []
        return data[-limit:]

    def close(self, *, timeout: float = 2.0) -> None:
        self._stop_event.set()
        self._worker.join(timeout=timeout)

    def _writer_loop(self) -> None:
        while not self._stop_event.is_set() or not self._queue.empty():
            batch: List[Dict[str, Any]] = []
            try:
                first = self._queue.get(timeout=self._flush_interval)
                batch.append(first)
            except queue.Empty:
                first = None

            if first is not None:
                for _ in range(self._batch_size - 1):
                    try:
                        batch.append(self._queue.get_nowait())
                    except queue.Empty:
                        break

            if not batch:
                continue

            self._flush_batch(batch)

    def _flush_batch(self, batch: List[Dict[str, Any]]) -> None:
        partitions: Dict[Path, List[Dict[str, Any]]] = {}
        for event in batch:
            workspace_path = Path(str(event.get("workspace", self._workspace_root()))).resolve()
            log_path = self._log_path_for_workspace(workspace_path)
            partitions.setdefault(log_path, []).append(event)

        for log_path, events in partitions.items():
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as handle:
                for event in events:
                    handle.write(json.dumps(event, ensure_ascii=True, separators=(",", ":")) + "\n")
            self._active_workspace = Path(str(events[-1].get("workspace", ""))) if events else self._active_workspace
            self._active_log_path = log_path

    def _log_path_for_workspace(self, workspace: Path) -> Path:
        return workspace / ".cai" / "audit" / f"forensic_{self._session_id}.jsonl"

    def _workspace_root(self) -> Path:
        try:
            return get_project_space().ensure_initialized().resolve()
        except Exception:
            return Path.cwd().resolve()

    def _sanitize(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return self._redactor(payload)

    @staticmethod
    def _new_session_id() -> str:
        return datetime.now(tz=UTC).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(4)


class CerebroLogger:
    """Semantic, redacted multi-sink logger for UI and system telemetry."""

    def __init__(
        self,
        *,
        console: Optional[Console] = None,
        forensic: Optional[ForensicHandler] = None,
        show_thought: Optional[bool] = None,
    ) -> None:
        self._console = console or Console()
        self._forensic = forensic or ForensicHandler()
        self._show_thought = bool(show_thought) if show_thought is not None else self._env_show_thought()
        self._terminal_logger = self._build_terminal_logger(self._console, self._forensic.session_id)

    @property
    def forensic_handler(self) -> ForensicHandler:
        return self._forensic

    @property
    def session_id(self) -> str:
        return self._forensic.session_id

    def set_thought_visibility(self, enabled: bool) -> None:
        self._show_thought = bool(enabled)

    def log(
        self,
        level: str,
        message: str,
        *,
        actor: str = "system",
        command: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        terminal: bool = True,
    ) -> Dict[str, Any]:
        normalized_level = level if level in _LEVEL_TO_NUM else LOG_AUDIT
        cleaned_message = str(clean_data(message))
        cleaned_data = clean_data(data or {})
        workspace = str(self._workspace_root())

        event = ForensicEvent(
            timestamp=datetime.now(tz=UTC).isoformat(),
            session_id=self._forensic.session_id,
            level=normalized_level,
            actor=str(clean_data(actor)),
            message=cleaned_message,
            command=str(clean_data(command)) if command else None,
            data=cleaned_data,
            tags=[str(clean_data(t)) for t in (tags or [])],
            workspace=workspace,
        ).as_dict()

        self._forensic.emit(event)

        if terminal and self._should_render_terminal(normalized_level):
            self._emit_terminal(event)

        return event

    def audit(self, message: str, **kwargs: Any) -> Dict[str, Any]:
        return self.log(LOG_AUDIT, message, **kwargs)

    def thought(self, message: str, **kwargs: Any) -> Dict[str, Any]:
        return self.log(LOG_THOUGHT, message, **kwargs)

    def action(self, message: str, **kwargs: Any) -> Dict[str, Any]:
        return self.log(LOG_ACTION, message, **kwargs)

    def finding(self, message: str, **kwargs: Any) -> Dict[str, Any]:
        return self.log(LOG_FINDING, message, **kwargs)

    def recent_events(self, *, limit: int = 200, levels: Optional[Sequence[str]] = None) -> List[Dict[str, Any]]:
        return self._forensic.recent(limit=limit, levels=levels)

    def render_structured(self, title: str, data: Dict[str, Any], *, level: str = LOG_ACTION) -> None:
        safe = clean_data(data)
        table = Table(title=title)
        table.add_column("Field", style="bold cyan", no_wrap=True)
        table.add_column("Value", style="white")
        for key, value in safe.items():
            if isinstance(value, (dict, list)):
                rendered = json.dumps(value, ensure_ascii=True)
            else:
                rendered = str(value)
            table.add_row(str(key), rendered)
        self._console.print(table)
        self.log(level, title, data=safe, terminal=False)

    def close(self) -> None:
        self._forensic.close()

    def _emit_terminal(self, event: Dict[str, Any]) -> None:
        level = str(event.get("level", LOG_AUDIT))
        style = _LEVEL_TO_STYLE.get(level, _LEVEL_TO_STYLE[LOG_AUDIT])
        actor = str(event.get("actor", "system"))
        msg = str(event.get("message", ""))
        line = f"{style['icon']} {style['label']} [white]{actor}[/white] {msg}"
        self._terminal_logger.log(_LEVEL_TO_NUM.get(level, 25), line)

        payload = event.get("data")
        if isinstance(payload, dict) and payload:
            preview = Table(box=None, show_header=False, pad_edge=False)
            preview.add_column("k", style="dim cyan", no_wrap=True)
            preview.add_column("v", style="dim white")
            for idx, (k, v) in enumerate(payload.items()):
                if idx >= 6:
                    preview.add_row("...", "(truncated)")
                    break
                if isinstance(v, (dict, list)):
                    preview.add_row(str(k), json.dumps(v, ensure_ascii=True))
                else:
                    preview.add_row(str(k), str(v))
            self._console.print(preview)

    def _should_render_terminal(self, level: str) -> bool:
        if level == LOG_THOUGHT and not self._show_thought:
            return False
        return True

    @staticmethod
    def _build_terminal_logger(console: Console, session_id: str) -> Logger:
        logger_name = f"cerebro.ui.{session_id}"
        log = logging.getLogger(logger_name)
        if not log.handlers:
            rich = RichHandler(console=console, show_path=False, show_time=True, markup=True)
            rich.setLevel(logging.INFO)
            rich.setFormatter(logging.Formatter("%(message)s"))
            log.addHandler(rich)
            log.propagate = False
            log.setLevel(logging.INFO)
        return log

    @staticmethod
    def _env_show_thought() -> bool:
        value = str(os.environ.get("CEREBRO_THINK", os.environ.get("CEREBRO_LOG_THOUGHTS", "false"))).strip().lower()
        return value in {"1", "true", "yes", "on"}

    @staticmethod
    def _is_web_mode() -> bool:
        return False

    @staticmethod
    def _workspace_root() -> Path:
        try:
            return get_project_space().ensure_initialized().resolve()
        except Exception:
            return Path.cwd().resolve()


_GLOBAL_LOGGER: Optional[CerebroLogger] = None


def _normalize_history_path(history_file: Path | str | None = None) -> Path:
    candidate = Path(history_file).expanduser() if history_file is not None else _HISTORY_FILE
    return candidate.resolve()


def load_history_entries(history_file: Path | str | None = None) -> List[str]:
    """Load plain-text history entries from disk."""
    resolved = _normalize_history_path(history_file)
    if not resolved.exists():
        return []

    try:
        raw_lines = resolved.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []

    entries: List[str] = []
    current_entry: List[str] = []
    saw_prompt_toolkit_format = False

    for line in raw_lines:
        if line.startswith("#"):
            saw_prompt_toolkit_format = True
            if current_entry:
                entries.append("\n".join(current_entry).strip())
                current_entry = []
            continue
        if line.startswith("+"):
            saw_prompt_toolkit_format = True
            current_entry.append(line[1:])
            continue
        if line.strip():
            entries.append(line.strip())

    if current_entry:
        entries.append("\n".join(current_entry).strip())

    if saw_prompt_toolkit_format:
        entries = [entry for entry in entries if entry]

    return entries[-_HISTORY_LENGTH:]


def _write_history_entries(history_file: Path | str | None, entries: Sequence[str]) -> None:
    resolved = _normalize_history_path(history_file)
    trimmed = [entry.strip() for entry in entries if isinstance(entry, str) and entry.strip()][-_HISTORY_LENGTH:]
    resolved.parent.mkdir(parents=True, exist_ok=True)
    payload_lines: List[str] = []
    for entry in trimmed:
        payload_lines.append(f"# {datetime.now(tz=UTC).isoformat()}")
        for line in entry.splitlines() or [""]:
            payload_lines.append(f"+{line}")
    payload = "" if not payload_lines else "\n".join(payload_lines) + "\n"
    resolved.write_text(payload, encoding="utf-8")


def _persist_readline_history(history_file: Path) -> None:
    if readline is None:
        return

    try:
        readline.set_history_length(_HISTORY_LENGTH)
        entries = load_history_entries(history_file)
        current_length = readline.get_current_history_length()
        start_index = max(1, current_length - _HISTORY_LENGTH + 1)
        for index in range(start_index, current_length + 1):
            item = readline.get_history_item(index)
            normalized = " ".join((item or "").splitlines()).strip()
            if not normalized:
                continue
            if not entries or entries[-1] != normalized:
                entries.append(normalized)
        _write_history_entries(history_file, entries)
    except OSError:
        _write_history_entries(history_file, load_history_entries(history_file))


def _bootstrap_readline_history(history_file: Path) -> None:
    global _READLINE_BOOTSTRAPPED

    if _READLINE_BOOTSTRAPPED or readline is None:
        return

    history_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        clear_history = getattr(readline, "clear_history", None)
        if callable(clear_history):
            clear_history()
        for entry in load_history_entries(history_file):
            readline.add_history(entry)
    except OSError:
        pass

    readline.set_history_length(_HISTORY_LENGTH)
    atexit.register(_persist_readline_history, history_file)
    _READLINE_BOOTSTRAPPED = True


def prepare_prompt_history_file(history_file: Path | str | None = None) -> Path:
    """Normalize and migrate the shared history file to prompt_toolkit FileHistory format."""
    resolved = _normalize_history_path(history_file)
    resolved.parent.mkdir(parents=True, exist_ok=True)

    if not resolved.exists() and _LEGACY_HISTORY_FILE.exists():
        legacy_entries = load_history_entries(_LEGACY_HISTORY_FILE)
        if legacy_entries:
            _write_history_entries(resolved, legacy_entries)

    if resolved.exists():
        _write_history_entries(resolved, load_history_entries(resolved))

    return resolved


def append_history_entry(history_file: Path | str | None, entry: str) -> None:
    """Append a single REPL entry to the shared history file and readline buffer."""
    normalized = " ".join((entry or "").splitlines()).strip()
    if not normalized:
        return

    entries = load_history_entries(history_file)
    if not entries or entries[-1] != normalized:
        entries.append(normalized)
        _write_history_entries(history_file, entries)

    if readline is None:
        return

    try:
        current_length = readline.get_current_history_length()
        last_entry = readline.get_history_item(current_length) if current_length > 0 else None
        if last_entry != normalized:
            readline.add_history(normalized)
        readline.set_history_length(_HISTORY_LENGTH)
    except OSError:
        pass


def get_cerebro_logger() -> CerebroLogger:
    global _GLOBAL_LOGGER
    if _GLOBAL_LOGGER is None:
        _GLOBAL_LOGGER = CerebroLogger()
    return _GLOBAL_LOGGER


def setup_session_logging() -> Path:
    """Set up REPL history file and bootstrap forensic logger singleton.

    Returns:
        Path to prompt_toolkit history file (backward compatible API).
    """
    history_file = prepare_prompt_history_file()

    _bootstrap_readline_history(history_file)

    logger = get_cerebro_logger()
    logger.audit(
        "Session logging initialized",
        data={
            "history_file": str(history_file),
            "history_length": _HISTORY_LENGTH,
            "workspace": str(CerebroLogger._workspace_root()),
            "forensic_log": str(logger.forensic_handler.active_log_path) if logger.forensic_handler.active_log_path else "pending-first-event",
        },
        terminal=False,
    )
    return history_file
