"""Session and checkpoint management for Cerberus AI engagements.

This module provides two complementary capabilities:

1) Legacy interactive shell session lifecycle APIs used by existing tooling
   (`create_shell_session`, `list_shell_sessions`, `send_to_session`, etc.).
2) A new enterprise-grade `CerebroSessionTool` for explicit checkpointing,
   resume, listing, and cross-agent handoff export.

Design goals for Cerebro session checkpoints:
- Strict versioned schema with Pydantic.
- Semantic context compression instead of raw transcript dumps.
- Concurrency-safe file operations with lock + atomic writes.
- Artifact and tool linkage for forensic continuity.
- Optional encryption at rest when security mode is enabled.
- Forensic audit trail on save/resume/export operations.
"""

from __future__ import annotations

import base64
import contextvars
import hashlib
import json
import os
import pty
import re
import select
import signal
import subprocess  # nosec B404
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional

import fcntl
from pydantic import BaseModel, Field, ValidationError, field_validator
from wasabi.util import color  # pylint: disable=import-error

from cerberus.tools.workspace import _get_container_workspace_path, _get_workspace_dir, get_project_space

try:
    from cerberus.memory import MemoryManager
except Exception:
    MemoryManager = None

try:
    from cerberus.memory.logic import clean_data
except Exception:
    clean_data = lambda value: value

try:
    from cerberus.repl.ui.logging import get_cerberus_logger
except Exception:
    get_cerberus_logger = None

def _function_tool(*args: Any, **kwargs: Any) -> Any:
    """Resolve function_tool lazily with a safe no-op fallback."""
    try:
        from cerberus.sdk.agents.tool import function_tool as _impl
        return _impl(*args, **kwargs)
    except Exception:
        try:
            from cerberus.sdk.agents import function_tool as _impl  # type: ignore
            return _impl(*args, **kwargs)
        except Exception:
            def _decorator(fn: Any) -> Any:
                return fn

            return _decorator


# =============================================================================
# Legacy shell session registry (compatibility)
# =============================================================================

SESSIONS_LOCK = threading.Lock()
ACTIVE_SESSIONS: Dict[str, "ShellSession"] = {}
FRIENDLY_SESSION_MAP: Dict[str, str] = {}
REVERSE_SESSION_MAP: Dict[str, str] = {}
SESSION_COUNTER = 0
SESSION_OUTPUT_COUNTER: Dict[str, int] = {}

TOOLBOX_SESSION_LOCK = threading.Lock()
_CURRENT_TOOLBOX_SESSION_ID: contextvars.ContextVar[str] = contextvars.ContextVar(
    "cerberus_toolbox_session_id",
    default="default",
)
_CURRENT_TOOLBOX_SESSION_ID_FALLBACK = "default"

if TYPE_CHECKING:
    from cerberus.tools.all_tools import ExecutionPlan, ToolResolutionState


def _get_tool_runtime_models() -> tuple[type["ExecutionPlan"], type["ToolResolutionState"]]:
    from cerberus.tools.all_tools import ExecutionPlan, ToolResolutionState

    return ExecutionPlan, ToolResolutionState


def _default_tool_resolution_state() -> "ToolResolutionState":
    _, tool_resolution_state = _get_tool_runtime_models()
    return tool_resolution_state.FAILED


def _default_execution_plan() -> "ExecutionPlan":
    execution_plan_cls, tool_resolution_state = _get_tool_runtime_models()
    return execution_plan_cls(
        resolved_category="",
        tool_nodes=[],
        resolution_state=tool_resolution_state.FAILED,
        reasoning_trace=["tool_state_initialized"],
    )


_UNSET = object()


class ToolboxToolState(BaseModel):
    """Structured tool runtime state for a single logical session."""

    active_category: Optional[str] = None
    resolution_state: "ToolResolutionState" = Field(default_factory=_default_tool_resolution_state)
    last_execution_plan: "ExecutionPlan" = Field(default_factory=_default_execution_plan)


class ToolSnapshot(BaseModel):
    """Deterministic snapshot of tool-selection state for one request."""

    timestamp: str = Field(min_length=1)
    prompt: str = ""
    resolved_category: str = ""
    tool_list: List[str] = Field(default_factory=list)
    execution_plan_hash: str = Field(min_length=1)
    execution_plan_payload: Dict[str, Any] = Field(default_factory=dict)


class ToolboxSessionState(BaseModel):
    """Per-session toolbox routing preferences used by request pipeline."""

    session_id: str = Field(min_length=1)
    tool_state: ToolboxToolState = Field(default_factory=ToolboxToolState)
    tool_history: List[ToolSnapshot] = Field(default_factory=list)


def _rebuild_tool_state_models() -> None:
    """Resolve forward references for typed toolbox tool-state models."""
    try:
        execution_plan_cls, tool_resolution_state = _get_tool_runtime_models()
        ToolboxToolState.model_rebuild(
            _types_namespace={
                "ExecutionPlan": execution_plan_cls,
                "ToolResolutionState": tool_resolution_state,
            }
        )
        ToolboxSessionState.model_rebuild(
            _types_namespace={
                "ToolboxToolState": ToolboxToolState,
                "ToolSnapshot": ToolSnapshot,
                "ExecutionPlan": execution_plan_cls,
                "ToolResolutionState": tool_resolution_state,
            }
        )
    except Exception:
        pass


_rebuild_tool_state_models()


TOOLBOX_SESSIONS: Dict[str, ToolboxSessionState] = {}


def _normalize_toolbox_session_id(session_id: Optional[str]) -> str:
    raw = str(session_id or "").strip()
    return raw if raw else "default"


def _extract_toolbox_session_id_from_context(run_context: Any = None) -> str:
    if run_context is None:
        return "default"

    existing = str(getattr(run_context, "toolbox_session_id", "") or "").strip()
    if existing:
        return _normalize_toolbox_session_id(existing)

    context_obj = getattr(run_context, "context", None)
    candidate: Optional[str] = None
    if isinstance(context_obj, dict):
        candidate = str(context_obj.get("session_id") or context_obj.get("id") or "").strip() or None
    elif context_obj is not None:
        candidate = str(getattr(context_obj, "session_id", "") or "").strip() or None

    resolved = _normalize_toolbox_session_id(candidate)
    try:
        setattr(run_context, "toolbox_session_id", resolved)
    except Exception:
        pass
    return resolved


def get_or_create_toolbox_session(session_id: Optional[str] = None) -> ToolboxSessionState:
    resolved = _normalize_toolbox_session_id(session_id)
    with TOOLBOX_SESSION_LOCK:
        existing = TOOLBOX_SESSIONS.get(resolved)
        if existing is not None:
            return existing
        created = ToolboxSessionState(session_id=resolved)
        TOOLBOX_SESSIONS[resolved] = created
        return created


def set_toolbox_active_category(
    session_id: str,
    active_category: Optional[str],
) -> ToolboxSessionState:
    resolved = _normalize_toolbox_session_id(session_id)
    with TOOLBOX_SESSION_LOCK:
        current = TOOLBOX_SESSIONS.get(resolved) or ToolboxSessionState(session_id=resolved)
        updated_tool_state = current.tool_state.model_copy(update={"active_category": active_category})
        updated = current.model_copy(update={"tool_state": updated_tool_state})
        TOOLBOX_SESSIONS[resolved] = updated
        return updated


def set_toolbox_tool_state(
    session_id: str,
    *,
    active_category: Any = _UNSET,
    resolution_state: Optional["ToolResolutionState"] = None,
    last_execution_plan: Optional["ExecutionPlan"] = None,
) -> ToolboxSessionState:
    """Apply explicit, typed tool-state transitions for a session."""
    resolved = _normalize_toolbox_session_id(session_id)
    with TOOLBOX_SESSION_LOCK:
        current = TOOLBOX_SESSIONS.get(resolved) or ToolboxSessionState(session_id=resolved)
        updates: Dict[str, Any] = {}
        if active_category is not _UNSET:
            updates["active_category"] = active_category
        if resolution_state is not None:
            updates["resolution_state"] = resolution_state
        if last_execution_plan is not None:
            updates["last_execution_plan"] = last_execution_plan

        updated_tool_state = (
            current.tool_state.model_copy(update=updates)
            if updates
            else current.tool_state
        )
        updated = current.model_copy(update={"tool_state": updated_tool_state})
        TOOLBOX_SESSIONS[resolved] = updated
        return updated


def get_toolbox_tool_state(session_id: Optional[str]) -> ToolboxToolState:
    state = get_or_create_toolbox_session(session_id)
    return state.tool_state


def append_toolbox_tool_snapshot(
    session_id: str,
    *,
    prompt: str,
    resolved_category: str,
    tool_list: List[str],
    execution_plan: "ExecutionPlan",
) -> ToolSnapshot:
    """Append one structured tool-selection snapshot to session history."""
    resolved = _normalize_toolbox_session_id(session_id)

    plan_payload = execution_plan.model_dump(mode="json")
    plan_hash = hashlib.sha256(
        json.dumps(plan_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    snapshot = ToolSnapshot(
        timestamp=datetime.now(UTC).isoformat(),
        prompt=str(prompt or ""),
        resolved_category=str(resolved_category or ""),
        tool_list=list(tool_list),
        execution_plan_hash=plan_hash,
        execution_plan_payload=plan_payload,
    )

    with TOOLBOX_SESSION_LOCK:
        current = TOOLBOX_SESSIONS.get(resolved) or ToolboxSessionState(session_id=resolved)
        updated_history = [*current.tool_history, snapshot]
        updated = current.model_copy(update={"tool_history": updated_history})
        TOOLBOX_SESSIONS[resolved] = updated

    return snapshot


def get_toolbox_tool_history(session_id: Optional[str]) -> List[ToolSnapshot]:
    state = get_or_create_toolbox_session(session_id)
    return list(state.tool_history)


def get_toolbox_active_category(session_id: Optional[str]) -> Optional[str]:
    state = get_or_create_toolbox_session(session_id)
    return state.tool_state.active_category


def set_run_context_toolbox_session_id(run_context: Any, session_id: Optional[str] = None) -> str:
    resolved = _normalize_toolbox_session_id(session_id)
    if resolved == "default":
        resolved = _extract_toolbox_session_id_from_context(run_context)
    try:
        setattr(run_context, "toolbox_session_id", resolved)
    except Exception:
        pass
    get_or_create_toolbox_session(resolved)
    return resolved


def set_current_toolbox_session_id(session_id: Optional[str]) -> str:
    global _CURRENT_TOOLBOX_SESSION_ID_FALLBACK
    resolved = _normalize_toolbox_session_id(session_id)
    _CURRENT_TOOLBOX_SESSION_ID_FALLBACK = resolved
    _CURRENT_TOOLBOX_SESSION_ID.set(resolved)
    get_or_create_toolbox_session(resolved)
    return resolved


def get_current_toolbox_session_id() -> str:
    from_context = _normalize_toolbox_session_id(_CURRENT_TOOLBOX_SESSION_ID.get())
    if from_context != "default":
        return from_context
    return _normalize_toolbox_session_id(_CURRENT_TOOLBOX_SESSION_ID_FALLBACK)


class ShellSession:  # pylint: disable=too-many-instance-attributes
    """Manage one interactive shell session (local/CTF/container)."""

    def __init__(
        self,
        command: str,
        session_id: Optional[str] = None,
        ctf: Any = None,
        workspace_dir: Optional[str] = None,
        container_id: Optional[str] = None,
    ):
        self.session_id = session_id or str(uuid.uuid4())[:8]
        self.command = command
        self.ctf = ctf
        self.container_id = container_id

        if self.container_id:
            self.workspace_dir = _get_container_workspace_path()
        elif self.ctf:
            self.workspace_dir = workspace_dir or _get_workspace_dir()
        else:
            self.workspace_dir = workspace_dir or _get_workspace_dir()

        self.friendly_id: Optional[str] = None
        self.created_at = time.time()
        self.process: Optional[subprocess.Popen[str]] = None
        self.master: Optional[int] = None
        self.slave: Optional[int] = None
        self.output_buffer: List[str] = []
        self.is_running = False
        self.last_activity = time.time()

    def start(self) -> Optional[str]:
        """Start the session process and output reader."""
        start_message_cmd = self.command

        if self.container_id:
            try:
                self.master, self.slave = pty.openpty()
                docker_cmd = [
                    "docker",
                    "exec",
                    "-i",
                    "-t",
                    "-w",
                    self.workspace_dir,
                    self.container_id,
                    "sh",
                    "-c",
                    self.command,
                ]
                self.process = subprocess.Popen(  # nosec B603
                    docker_cmd,
                    stdin=self.slave,
                    stdout=self.slave,
                    stderr=self.slave,
                    preexec_fn=os.setsid,
                    universal_newlines=True,
                )
                self.is_running = True
                self.output_buffer.append(
                    f"[Session {self.session_id}] Started in container "
                    f"{self.container_id[:12]}: {start_message_cmd} in {self.workspace_dir}"
                )
                threading.Thread(target=self._read_output, daemon=True).start()
                return None
            except Exception as exc:  # pylint: disable=broad-except
                self.output_buffer.append(f"Error starting container session: {exc}")
                self.is_running = False
                return str(exc)

        if self.ctf:
            try:
                self.is_running = True
                self.output_buffer.append(f"[Session {self.session_id}] Started CTF command: {self.command}")
                output = self.ctf.get_shell(self.command)
                if output:
                    self.output_buffer.append(str(output))
                self.is_running = False
                return None
            except Exception as exc:  # pylint: disable=broad-except
                self.output_buffer.append(f"Error executing CTF command: {exc}")
                self.is_running = False
                return str(exc)

        try:
            self.master, self.slave = pty.openpty()
            self.process = subprocess.Popen(
                self.command,
                shell=True,  # nosec B602
                stdin=self.slave,
                stdout=self.slave,
                stderr=self.slave,
                cwd=self.workspace_dir,
                preexec_fn=os.setsid,
                universal_newlines=True,
            )
            self.is_running = True
            self.output_buffer.append(f"[Session {self.session_id}] Started: {self.command}")
            threading.Thread(target=self._read_output, daemon=True).start()
            return None
        except Exception as exc:  # pylint: disable=broad-except
            self.output_buffer.append(f"Error starting local session: {exc}")
            self.is_running = False
            return str(exc)

    def _read_output(self) -> Optional[str]:
        try:
            while self.is_running and self.master is not None:
                try:
                    if self.process and self.process.poll() is not None:
                        self.is_running = False
                        break

                    ready, _, _ = select.select([self.master], [], [], 0.5)
                    if not ready:
                        if self.process and self.process.poll() is not None:
                            self.is_running = False
                            break
                        continue

                    output = os.read(self.master, 4096).decode("utf-8", errors="replace")
                    if output:
                        self.output_buffer.append(output)
                        self.last_activity = time.time()
                    else:
                        if self.process and self.process.poll() is None:
                            continue
                        self.is_running = False
                        break

                except UnicodeDecodeError:
                    self.output_buffer.append(f"[Session {self.session_id}] Unicode decode error in output\n")
                except Exception as read_err:  # pylint: disable=broad-except
                    self.output_buffer.append(f"Error reading output buffer: {read_err}\n")
                    self.is_running = False
                    break

                if self.is_process_running():
                    time.sleep(0.05)

            return None
        except Exception as exc:  # pylint: disable=broad-except
            self.output_buffer.append(f"Error in read_output loop: {exc}")
            self.is_running = False
            return str(exc)

    def is_process_running(self) -> bool:
        if self.container_id or self.ctf:
            return self.is_running
        if not self.process:
            return False
        return self.process.poll() is None

    def send_input(self, input_data: str) -> str:
        if not self.is_running:
            if self.process and self.process.poll() is None:
                self.is_running = True
            else:
                return "Session is not running"

        try:
            if self.ctf:
                output = self.ctf.get_shell(input_data)
                self.output_buffer.append(str(output))
                return "Input sent to CTF session"

            if self.master is None:
                return "Session PTY not available for input"

            payload = (input_data.rstrip() + "\n").encode()
            bytes_written = os.write(self.master, payload)
            if bytes_written != len(payload):
                self.output_buffer.append(f"[Session {self.session_id}] Warning: Partial input write.")
            self.last_activity = time.time()
            return "Input sent to session"
        except Exception as exc:  # pylint: disable=broad-except
            self.output_buffer.append(f"Error sending input: {exc}")
            return f"Error sending input: {exc}"

    def get_output(self, clear: bool = True) -> str:
        output = "\n".join(self.output_buffer)
        if clear:
            self.output_buffer = []
        return output

    def get_new_output(self, mark_position: bool = True) -> str:
        if not hasattr(self, "_last_output_position"):
            self._last_output_position = 0
        new_output_lines = self.output_buffer[self._last_output_position :]
        new_output = "\n".join(new_output_lines)
        if mark_position:
            self._last_output_position = len(self.output_buffer)
        return new_output

    def terminate(self) -> str:
        session_id_short = self.session_id[:8]
        termination_message = f"Session {session_id_short} terminated"

        if not self.is_running:
            if not (self.process and self.process.poll() is None):
                return f"Session {session_id_short} already terminated or finished."

        try:
            self.is_running = False

            if self.process:
                try:
                    pgid = os.getpgid(self.process.pid)
                    os.killpg(pgid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                except Exception as term_err:  # pylint: disable=broad-except
                    termination_message = f" (Error during SIGTERM: {term_err})"
                    try:
                        self.process.kill()
                    except Exception:
                        pass

                if self.process.poll() is None:
                    print(
                        color(
                            f"Session {session_id_short} process {self.process.pid} may still be running after termination attempts.",
                            fg="red",
                        )
                    )
                    termination_message += " (Warning: Process may still be running)"

            if self.master is not None:
                try:
                    os.close(self.master)
                except OSError:
                    pass
                self.master = None

            if self.slave is not None:
                try:
                    os.close(self.slave)
                except OSError:
                    pass
                self.slave = None

            return termination_message
        except Exception as exc:  # pylint: disable=broad-except
            return f"Error terminating session {session_id_short}: {exc}"


# =============================================================================
# Session checkpoint schemas
# =============================================================================

SCHEMA_VERSION = "cerebro.session.v1"
ENVELOPE_VERSION = "cerebro.session.envelope.v1"
INDEX_VERSION = "cerebro.session.index.v1"
HANDOFF_VERSION = "cerebro.handoff.v1"


class ToolUsageRef(BaseModel):
    """Tool invocation footprint for checkpoint traceability."""

    name: str = Field(min_length=1)
    count: int = Field(default=1, ge=1)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


class ArtifactRef(BaseModel):
    """Link to a file artifact generated during the checkpoint window."""

    path: str = Field(min_length=1)
    category: str = Field(default="artifact")
    size_bytes: int = Field(default=0, ge=0)
    modified_at: str
    sha256: Optional[str] = None
    linked_tool: Optional[str] = None


class SemanticState(BaseModel):
    """Compressed engagement context for fast agent ramp-up."""

    summary: str = Field(min_length=1)
    key_findings: List[str] = Field(default_factory=list)
    pending_tasks: List[str] = Field(default_factory=list)
    next_actions: List[str] = Field(default_factory=list)
    key_decisions: List[str] = Field(default_factory=list)
    risks: List[str] = Field(default_factory=list)
    history_digest: str = Field(default="")


class CheckpointWindow(BaseModel):
    """Time window represented by a checkpoint."""

    started_at: str
    ended_at: str


class SessionCheckpoint(BaseModel):
    """Versioned snapshot payload for session checkpointing."""

    schema_version: str = Field(default=SCHEMA_VERSION)
    checkpoint_id: str = Field(min_length=8)
    created_at: str
    workspace_root: str
    case_id: Optional[str] = None
    agent_id: str = Field(default="unknown")
    agent_role: str = Field(default="unknown")
    checkpoint_window: CheckpointWindow
    semantic_state: SemanticState
    reasoning_state: Dict[str, Any] = Field(default_factory=dict)
    findings: List[str] = Field(default_factory=list)
    pending_tasks: List[str] = Field(default_factory=list)
    tools: List[ToolUsageRef] = Field(default_factory=list)
    artifacts: List[ArtifactRef] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)

    @field_validator("schema_version")
    @classmethod
    def _validate_schema(cls, value: str) -> str:
        if value != SCHEMA_VERSION:
            raise ValueError(f"Unsupported checkpoint schema version: {value}")
        return value


class SessionEnvelope(BaseModel):
    """On-disk envelope supporting optional encrypted payloads."""

    envelope_version: str = Field(default=ENVELOPE_VERSION)
    checkpoint_id: str
    created_at: str
    encrypted: bool = False
    cipher: Optional[str] = None
    payload: str


class CheckpointIndexEntry(BaseModel):
    """Compact index metadata for listing and lookup."""

    checkpoint_id: str
    created_at: str
    file_name: str
    encrypted: bool = False
    agent_id: str = "unknown"
    agent_role: str = "unknown"
    summary: str = ""
    artifact_count: int = 0
    tool_count: int = 0
    window_started_at: str = ""
    window_ended_at: str = ""


class CheckpointIndex(BaseModel):
    """Checkpoint index rooted in workspace .cerberus/sessions directory."""

    schema_version: str = Field(default=INDEX_VERSION)
    last_checkpoint_at: Optional[str] = None
    entries: List[CheckpointIndexEntry] = Field(default_factory=list)


class HandoffMemo(BaseModel):
    """Cross-agent handoff summary generated from a checkpoint."""

    schema_version: str = Field(default=HANDOFF_VERSION)
    generated_at: str
    checkpoint_id: str
    from_agent_id: str
    from_agent_role: str
    target_agent_role: str
    memo_title: str
    executive_summary: str
    priority_actions: List[str] = Field(default_factory=list)
    open_risks: List[str] = Field(default_factory=list)
    recommended_tools: List[str] = Field(default_factory=list)
    linked_artifacts: List[str] = Field(default_factory=list)


# =============================================================================
# Cerebro session orchestration tool
# =============================================================================


class CerebroSessionTool:
    """Checkpoint/resume/list/export tool for long-running engagements."""

    def __init__(self) -> None:
        self._workspace_root = self._resolve_workspace_root()
        self._root = self._workspace_root / ".cerberus" / "sessions"
        self._checkpoints_dir = self._root / "checkpoints"
        self._exports_dir = self._root / "handoffs"
        self._index_path = self._root / "index.json"
        self._lock_path = self._root / ".lock"
        self._memory = MemoryManager() if MemoryManager else None
        self._logger = get_cerberus_logger() if get_cerberus_logger else None
        self._ensure_layout()

    @staticmethod
    def _resolve_workspace_root() -> Path:
        active_root = os.getenv("CERBERUS_WORKSPACE_ACTIVE_ROOT")
        if active_root:
            try:
                return Path(active_root).expanduser().resolve()
            except Exception:
                pass

        try:
            return get_project_space().ensure_initialized().resolve()
        except Exception:
            return Path(_get_workspace_dir()).resolve()

    def _ensure_layout(self) -> None:
        self._checkpoints_dir.mkdir(parents=True, exist_ok=True)
        self._exports_dir.mkdir(parents=True, exist_ok=True)
        self._root.mkdir(parents=True, exist_ok=True)
        if not self._index_path.exists():
            self._atomic_write_json(self._index_path, CheckpointIndex().model_dump(mode="json"))

    @contextmanager
    def _locked(self) -> Any:
        self._root.mkdir(parents=True, exist_ok=True)
        with self._lock_path.open("a+", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def _atomic_write_bytes(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as tmp:
            tmp.write(data)
            tmp_path = Path(tmp.name)
        tmp_path.replace(path)

    @staticmethod
    def _atomic_write_json(path: Path, payload: Dict[str, Any]) -> None:
        encoded = json.dumps(payload, ensure_ascii=True, indent=2).encode("utf-8")
        CerebroSessionTool._atomic_write_bytes(path, encoded)

    def _load_index(self) -> CheckpointIndex:
        if not self._index_path.exists():
            return CheckpointIndex()
        try:
            payload = json.loads(self._index_path.read_text(encoding="utf-8"))
            return CheckpointIndex.model_validate(payload)
        except Exception:
            return CheckpointIndex()

    def _write_index(self, index: CheckpointIndex) -> None:
        self._atomic_write_json(self._index_path, index.model_dump(mode="json"))

    @staticmethod
    def _bool_env(name: str) -> bool:
        value = str(os.getenv(name, "")).strip().lower()
        return value in {"1", "true", "yes", "on", "enabled", "strict", "secure"}

    def _security_mode_enabled(self) -> bool:
        return self._bool_env("CERBERUS_SECURITY_MODE") or self._bool_env("CERBERUS_SESSION_ENCRYPTION")

    def _resolve_primary_key(self) -> Optional[bytes]:
        for key_name in ("CERBERUS_WORKSPACE_PRIMARY_KEY", "CERBERUS_PRIMARY_KEY", "CERBERUS_SESSION_PRIMARY_KEY"):
            value = os.getenv(key_name)
            if value:
                return value.encode("utf-8")

        keyring = Path.home() / ".cerberus" / ".keyring"
        if keyring.exists():
            try:
                return keyring.read_bytes().strip()
            except Exception:
                return None

        return None

    def _encrypt_payload(self, payload: bytes) -> str:
        try:
            from cryptography.fernet import Fernet
        except Exception as exc:
            raise RuntimeError("Security mode requires cryptography. Install cryptography to enable encryption.") from exc

        key = self._resolve_primary_key()
        if not key:
            raise RuntimeError("Security mode enabled but no workspace primary key is available")

        try:
            token = Fernet(key).encrypt(payload)
            return token.decode("utf-8")
        except Exception as exc:
            raise RuntimeError("Unable to encrypt checkpoint payload with workspace primary key") from exc

    def _decrypt_payload(self, token: str) -> bytes:
        try:
            from cryptography.fernet import Fernet
        except Exception as exc:
            raise RuntimeError("Encrypted checkpoint requires cryptography package") from exc

        key = self._resolve_primary_key()
        if not key:
            raise RuntimeError("Encrypted checkpoint cannot be resumed: missing workspace primary key")

        try:
            return Fernet(key).decrypt(token.encode("utf-8"))
        except Exception as exc:
            raise RuntimeError("Checkpoint decryption failed with current workspace key") from exc

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(tz=UTC).isoformat()

    @staticmethod
    def _normalize_lines(value: Any, *, max_items: int = 32) -> List[str]:
        if value is None:
            return []
        if isinstance(value, str):
            items = [line.strip() for line in value.splitlines() if line.strip()]
            return items[:max_items]
        if isinstance(value, (list, tuple)):
            out: List[str] = []
            for item in value:
                text = str(item).strip()
                if text:
                    out.append(text)
                if len(out) >= max_items:
                    break
            return out
        return [str(value).strip()][:max_items]

    @staticmethod
    def _history_digest(history: Iterable[str], max_lines: int = 120) -> str:
        lines = [line.strip() for line in history if isinstance(line, str) and line.strip()]
        if not lines:
            return ""
        trimmed = lines[-max_lines:]
        joined = "\n".join(trimmed)
        digest = hashlib.sha256(joined.encode("utf-8", errors="replace")).hexdigest()
        return f"lines={len(trimmed)} sha256={digest[:24]}"

    def _compress_semantic_state(
        self,
        *,
        history: List[str],
        findings: List[str],
        pending_tasks: List[str],
        reasoning_state: Dict[str, Any],
    ) -> SemanticState:
        cleaned_history = self._normalize_lines(history, max_items=240)
        cleaned_findings = self._normalize_lines(findings, max_items=16)
        cleaned_pending = self._normalize_lines(pending_tasks, max_items=16)

        decisions = self._normalize_lines(reasoning_state.get("decisions", []), max_items=8)
        risks = self._normalize_lines(reasoning_state.get("risks", []), max_items=8)
        next_actions = self._normalize_lines(reasoning_state.get("next_actions", []), max_items=12)

        memory_summary_text = ""
        if self._memory is not None:
            try:
                memory_summary = self._memory.summarize(max_points=6)
                memory_summary_text = getattr(memory_summary, "text", "")
            except Exception:
                memory_summary_text = ""

        summary_points: List[str] = []
        if cleaned_findings:
            summary_points.append(f"Findings: {len(cleaned_findings)} validated")
        if cleaned_pending:
            summary_points.append(f"Pending tasks: {len(cleaned_pending)}")
        if decisions:
            summary_points.append(f"Decisions logged: {len(decisions)}")
        if risks:
            summary_points.append(f"Risk items: {len(risks)}")
        if cleaned_history:
            summary_points.append(f"Recent activity lines: {len(cleaned_history)}")

        if cleaned_history:
            highlights = cleaned_history[-6:]
            summary_points.extend(f"Recent: {line[:180]}" for line in highlights)

        if memory_summary_text:
            summary_points.append("Memory summary: " + memory_summary_text.splitlines()[0][:220])

        if not summary_points:
            summary_points.append("No explicit reasoning state provided.")

        summary = "\n".join(summary_points[:14])

        return SemanticState(
            summary=summary,
            key_findings=cleaned_findings,
            pending_tasks=cleaned_pending,
            next_actions=next_actions,
            key_decisions=decisions,
            risks=risks,
            history_digest=self._history_digest(cleaned_history),
        )

    @staticmethod
    def _sha256_if_small(path: Path, limit_bytes: int = 16 * 1024 * 1024) -> Optional[str]:
        try:
            if not path.is_file():
                return None
            if path.stat().st_size > limit_bytes:
                return None
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                while True:
                    chunk = handle.read(8192)
                    if not chunk:
                        break
                    digest.update(chunk)
            return digest.hexdigest()
        except Exception:
            return None

    def _artifact_category(self, path: Path) -> str:
        suffix = path.suffix.lower()
        if suffix in {".pcap", ".pcapng", ".cap"}:
            return "pcap"
        if suffix in {".jsonl", ".log", ".txt"}:
            return "log"
        if suffix in {".html", ".har"}:
            return "web"
        if suffix in {".md", ".pdf", ".docx"}:
            return "report"
        return "artifact"

    def _discover_window_artifacts(self, *, started_at: str, ended_at: str) -> List[ArtifactRef]:
        try:
            start_ts = datetime.fromisoformat(started_at).timestamp()
            end_ts = datetime.fromisoformat(ended_at).timestamp()
        except Exception:
            return []

        candidates: List[ArtifactRef] = []
        watched_dirs = ["artifacts", "logs", "reports", "shared", "private"]

        for rel in watched_dirs:
            root = self._workspace_root / rel
            if not root.exists() or not root.is_dir():
                continue

            for file_path in root.rglob("*"):
                if not file_path.is_file():
                    continue
                try:
                    mtime = file_path.stat().st_mtime
                except OSError:
                    continue
                if mtime < start_ts or mtime > end_ts:
                    continue

                rel_path = str(file_path.resolve().relative_to(self._workspace_root))
                candidates.append(
                    ArtifactRef(
                        path=rel_path,
                        category=self._artifact_category(file_path),
                        size_bytes=int(file_path.stat().st_size),
                        modified_at=datetime.fromtimestamp(mtime, tz=UTC).isoformat(),
                        sha256=self._sha256_if_small(file_path),
                    )
                )

        candidates.sort(key=lambda item: item.modified_at)
        return candidates[:200]

    def _normalize_tool_usage(self, tools_used: Any) -> List[ToolUsageRef]:
        if tools_used is None:
            return []

        counter: Dict[str, int] = {}

        if isinstance(tools_used, dict):
            for name, count in tools_used.items():
                key = str(name).strip()
                if not key:
                    continue
                try:
                    amount = int(count)
                except Exception:
                    amount = 1
                counter[key] = max(1, amount)

        elif isinstance(tools_used, (list, tuple, set)):
            for value in tools_used:
                key = str(value).strip()
                if not key:
                    continue
                counter[key] = counter.get(key, 0) + 1

        else:
            key = str(tools_used).strip()
            if key:
                counter[key] = 1

        now = self._now_iso()
        refs = [
            ToolUsageRef(name=name, count=count, first_seen=now, last_seen=now)
            for name, count in sorted(counter.items())
        ]
        return refs[:128]

    @staticmethod
    def _sanitize_identifier(value: str) -> str:
        safe = re.sub(r"[^a-zA-Z0-9_-]", "_", value)
        return safe[:128]

    def _checkpoint_file(self, checkpoint_id: str) -> Path:
        return self._checkpoints_dir / f"checkpoint_{self._sanitize_identifier(checkpoint_id)}.json"

    def _load_checkpoint_from_file(self, checkpoint_file: Path) -> SessionCheckpoint:
        payload = json.loads(checkpoint_file.read_text(encoding="utf-8"))
        envelope = SessionEnvelope.model_validate(payload)

        if envelope.encrypted:
            raw_bytes = self._decrypt_payload(envelope.payload)
        else:
            raw_bytes = base64.b64decode(envelope.payload.encode("ascii"))

        snapshot_payload = json.loads(raw_bytes.decode("utf-8"))
        return SessionCheckpoint.model_validate(snapshot_payload)

    def _serialize_checkpoint(self, checkpoint: SessionCheckpoint) -> SessionEnvelope:
        snapshot_bytes = json.dumps(
            clean_data(checkpoint.model_dump(mode="json")),
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")

        encrypted = self._security_mode_enabled()
        if encrypted:
            payload = self._encrypt_payload(snapshot_bytes)
            cipher = "fernet"
        else:
            payload = base64.b64encode(snapshot_bytes).decode("ascii")
            cipher = None

        return SessionEnvelope(
            checkpoint_id=checkpoint.checkpoint_id,
            created_at=checkpoint.created_at,
            encrypted=encrypted,
            cipher=cipher,
            payload=payload,
        )

    def _log_audit(self, message: str, *, actor: str, data: Optional[Dict[str, Any]] = None, tags: Optional[List[str]] = None) -> None:
        if not self._logger:
            return
        try:
            self._logger.audit(message, actor=actor, data=clean_data(data or {}), tags=tags or ["session"])
        except Exception:
            return

    def session_checkpoint(
        self,
        *,
        reasoning_state: Optional[Dict[str, Any]] = None,
        findings: Optional[List[str]] = None,
        pending_tasks: Optional[List[str]] = None,
        history: Optional[List[str]] = None,
        tools_used: Optional[Any] = None,
        artifact_paths: Optional[List[str]] = None,
        agent_id: str = "unknown",
        agent_role: str = "unknown",
        case_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
        checkpoint_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Save a checkpoint with semantic compression and forensic linkage."""
        with self._locked():
            index = self._load_index()

            created_at = self._now_iso()
            started_at = index.last_checkpoint_at or "1970-01-01T00:00:00+00:00"
            cid = checkpoint_id or f"sess_{datetime.now(tz=UTC).strftime('%Y%m%dT%H%M%SZ')}_{uuid.uuid4().hex[:8]}"

            findings_list = self._normalize_lines(findings)
            pending_list = self._normalize_lines(pending_tasks)
            history_list = self._normalize_lines(history, max_items=300)

            semantic = self._compress_semantic_state(
                history=history_list,
                findings=findings_list,
                pending_tasks=pending_list,
                reasoning_state=reasoning_state or {},
            )

            tool_refs = self._normalize_tool_usage(tools_used)

            artifact_refs: List[ArtifactRef] = []
            for path_value in artifact_paths or []:
                path_text = str(path_value).strip()
                if not path_text:
                    continue
                candidate = (self._workspace_root / path_text).resolve() if not os.path.isabs(path_text) else Path(path_text).resolve()
                if not candidate.exists() or not candidate.is_file():
                    continue
                try:
                    rel = str(candidate.relative_to(self._workspace_root))
                except ValueError:
                    rel = str(candidate)
                stat = candidate.stat()
                artifact_refs.append(
                    ArtifactRef(
                        path=rel,
                        category=self._artifact_category(candidate),
                        size_bytes=int(stat.st_size),
                        modified_at=datetime.fromtimestamp(stat.st_mtime, tz=UTC).isoformat(),
                        sha256=self._sha256_if_small(candidate),
                    )
                )

            discovered = self._discover_window_artifacts(started_at=started_at, ended_at=created_at)
            dedup: Dict[str, ArtifactRef] = {item.path: item for item in artifact_refs}
            for item in discovered:
                dedup.setdefault(item.path, item)
            artifact_refs = sorted(dedup.values(), key=lambda item: item.modified_at)[:300]

            checkpoint = SessionCheckpoint(
                checkpoint_id=cid,
                created_at=created_at,
                workspace_root=str(self._workspace_root),
                case_id=case_id,
                agent_id=agent_id,
                agent_role=agent_role,
                checkpoint_window=CheckpointWindow(started_at=started_at, ended_at=created_at),
                semantic_state=semantic,
                reasoning_state=clean_data(reasoning_state or {}),
                findings=findings_list,
                pending_tasks=pending_list,
                tools=tool_refs,
                artifacts=artifact_refs,
                tags=self._normalize_lines(tags or [], max_items=32),
            )

            envelope = self._serialize_checkpoint(checkpoint)
            checkpoint_file = self._checkpoint_file(cid)
            self._atomic_write_json(checkpoint_file, envelope.model_dump(mode="json"))

            entry = CheckpointIndexEntry(
                checkpoint_id=checkpoint.checkpoint_id,
                created_at=checkpoint.created_at,
                file_name=checkpoint_file.name,
                encrypted=envelope.encrypted,
                agent_id=checkpoint.agent_id,
                agent_role=checkpoint.agent_role,
                summary=checkpoint.semantic_state.summary[:360],
                artifact_count=len(checkpoint.artifacts),
                tool_count=len(checkpoint.tools),
                window_started_at=checkpoint.checkpoint_window.started_at,
                window_ended_at=checkpoint.checkpoint_window.ended_at,
            )

            index.entries = [item for item in index.entries if item.checkpoint_id != checkpoint.checkpoint_id]
            index.entries.append(entry)
            index.entries.sort(key=lambda item: item.created_at, reverse=True)
            index.last_checkpoint_at = checkpoint.created_at
            self._write_index(index)

            self._log_audit(
                "Session checkpoint saved",
                actor=agent_id,
                data={
                    "checkpoint_id": checkpoint.checkpoint_id,
                    "agent_role": agent_role,
                    "artifacts": len(checkpoint.artifacts),
                    "tools": len(checkpoint.tools),
                    "encrypted": envelope.encrypted,
                },
                tags=["session", "checkpoint"],
            )

            return {
                "status": "ok",
                "checkpoint_id": checkpoint.checkpoint_id,
                "created_at": checkpoint.created_at,
                "workspace_root": checkpoint.workspace_root,
                "encrypted": envelope.encrypted,
                "artifact_count": len(checkpoint.artifacts),
                "tool_count": len(checkpoint.tools),
                "summary": checkpoint.semantic_state.summary,
            }

    def session_list(self, *, limit: int = 25) -> Dict[str, Any]:
        """List available checkpoints for the active workspace/case."""
        with self._locked():
            index = self._load_index()
            rows = [entry.model_dump(mode="json") for entry in index.entries[: max(1, limit)]]

            self._log_audit(
                "Session checkpoints listed",
                actor="system",
                data={"count": len(rows), "limit": limit},
                tags=["session", "list"],
            )

            return {
                "status": "ok",
                "schema_version": index.schema_version,
                "workspace_root": str(self._workspace_root),
                "count": len(rows),
                "checkpoints": rows,
            }

    def session_resume(self, *, checkpoint_id: Optional[str] = None, timestamp: Optional[str] = None) -> Dict[str, Any]:
        """Reload a previous checkpoint by ID or timestamp."""
        with self._locked():
            index = self._load_index()
            if not index.entries:
                return {"status": "error", "error": "No checkpoints available"}

            selected: Optional[CheckpointIndexEntry] = None
            if checkpoint_id:
                selected = next((entry for entry in index.entries if entry.checkpoint_id == checkpoint_id), None)
            elif timestamp:
                selected = next((entry for entry in index.entries if entry.created_at.startswith(timestamp)), None)
            else:
                selected = index.entries[0]

            if selected is None:
                return {
                    "status": "error",
                    "error": "Checkpoint not found",
                    "checkpoint_id": checkpoint_id,
                    "timestamp": timestamp,
                }

            checkpoint_file = self._checkpoints_dir / selected.file_name
            if not checkpoint_file.exists():
                return {
                    "status": "error",
                    "error": "Checkpoint file missing",
                    "checkpoint_id": selected.checkpoint_id,
                    "path": str(checkpoint_file),
                }

            checkpoint = self._load_checkpoint_from_file(checkpoint_file)

            self._log_audit(
                "Session checkpoint resumed",
                actor=checkpoint.agent_id,
                data={
                    "checkpoint_id": checkpoint.checkpoint_id,
                    "agent_role": checkpoint.agent_role,
                    "encrypted": selected.encrypted,
                },
                tags=["session", "resume"],
            )

            return {
                "status": "ok",
                "checkpoint_id": checkpoint.checkpoint_id,
                "created_at": checkpoint.created_at,
                "agent_id": checkpoint.agent_id,
                "agent_role": checkpoint.agent_role,
                "workspace_root": checkpoint.workspace_root,
                "semantic_state": checkpoint.semantic_state.model_dump(mode="json"),
                "reasoning_state": checkpoint.reasoning_state,
                "findings": checkpoint.findings,
                "pending_tasks": checkpoint.pending_tasks,
                "tools": [tool.model_dump(mode="json") for tool in checkpoint.tools],
                "artifacts": [artifact.model_dump(mode="json") for artifact in checkpoint.artifacts],
                "tags": checkpoint.tags,
            }

    def _build_handoff_memo(self, checkpoint: SessionCheckpoint, target_agent_role: str) -> HandoffMemo:
        role = target_agent_role.strip().lower() or "general"

        if "report" in role:
            title = "Reporting Handoff: Evidence + Findings"
            actions = checkpoint.findings[:6] + checkpoint.pending_tasks[:4]
            recommended = ["read_key_findings", "query_memory", "cat_file"]
        elif "scan" in role or "recon" in role:
            title = "Scanner Handoff: Pending Coverage"
            actions = checkpoint.pending_tasks[:8] or checkpoint.semantic_state.next_actions[:8]
            recommended = ["nmap", "curl", "generic_linux_command"]
        elif "blue" in role or "defend" in role:
            title = "Defense Handoff: Exposure + Mitigations"
            actions = checkpoint.semantic_state.risks[:8] or checkpoint.pending_tasks[:8]
            recommended = ["blue_team_safe_command", "query_memory"]
        else:
            title = "General Handoff Memo"
            actions = checkpoint.pending_tasks[:8] or checkpoint.semantic_state.next_actions[:8]
            recommended = [tool.name for tool in checkpoint.tools[:6]]

        memo = HandoffMemo(
            generated_at=self._now_iso(),
            checkpoint_id=checkpoint.checkpoint_id,
            from_agent_id=checkpoint.agent_id,
            from_agent_role=checkpoint.agent_role,
            target_agent_role=target_agent_role,
            memo_title=title,
            executive_summary=checkpoint.semantic_state.summary,
            priority_actions=actions,
            open_risks=checkpoint.semantic_state.risks[:8],
            recommended_tools=recommended,
            linked_artifacts=[artifact.path for artifact in checkpoint.artifacts[:40]],
        )
        return memo

    def session_export(self, *, checkpoint_id: str, target_agent_role: str) -> Dict[str, Any]:
        """Generate a cross-agent handoff memo from a checkpoint."""
        with self._locked():
            index = self._load_index()
            selected = next((entry for entry in index.entries if entry.checkpoint_id == checkpoint_id), None)
            if selected is None:
                return {"status": "error", "error": f"Checkpoint not found: {checkpoint_id}"}

            checkpoint_file = self._checkpoints_dir / selected.file_name
            if not checkpoint_file.exists():
                return {
                    "status": "error",
                    "error": "Checkpoint file missing",
                    "path": str(checkpoint_file),
                }

            checkpoint = self._load_checkpoint_from_file(checkpoint_file)
            memo = self._build_handoff_memo(checkpoint, target_agent_role)

            safe_role = self._sanitize_identifier(target_agent_role or "general")
            memo_path = self._exports_dir / f"handoff_{checkpoint.checkpoint_id}_{safe_role}.json"
            self._atomic_write_json(memo_path, memo.model_dump(mode="json"))

            self._log_audit(
                "Session handoff memo exported",
                actor=checkpoint.agent_id,
                data={
                    "checkpoint_id": checkpoint.checkpoint_id,
                    "target_agent_role": target_agent_role,
                    "memo_path": str(memo_path),
                },
                tags=["session", "handoff", "export"],
            )

            return {
                "status": "ok",
                "checkpoint_id": checkpoint.checkpoint_id,
                "target_agent_role": target_agent_role,
                "memo_path": str(memo_path),
                "memo": memo.model_dump(mode="json"),
            }


SESSION_TOOL = CerebroSessionTool()


# =============================================================================
# Function-tool wrappers (for agent tool registration)
# =============================================================================


@_function_tool(strict_mode=False)
def session_checkpoint(
    reasoning_state: Optional[Dict[str, Any]] = None,
    findings: Optional[List[str]] = None,
    pending_tasks: Optional[List[str]] = None,
    history: Optional[List[str]] = None,
    tools_used: Optional[Any] = None,
    artifact_paths: Optional[List[str]] = None,
    agent_id: str = "unknown",
    agent_role: str = "unknown",
    case_id: Optional[str] = None,
    tags: Optional[List[str]] = None,
    checkpoint_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Save a semantic checkpoint for the current engagement."""
    return SESSION_TOOL.session_checkpoint(
        reasoning_state=reasoning_state,
        findings=findings,
        pending_tasks=pending_tasks,
        history=history,
        tools_used=tools_used,
        artifact_paths=artifact_paths,
        agent_id=agent_id,
        agent_role=agent_role,
        case_id=case_id,
        tags=tags,
        checkpoint_id=checkpoint_id,
    )


@_function_tool(strict_mode=False)
def session_resume(checkpoint_id: Optional[str] = None, timestamp: Optional[str] = None) -> Dict[str, Any]:
    """Resume a checkpoint by ID or timestamp prefix."""
    return SESSION_TOOL.session_resume(checkpoint_id=checkpoint_id, timestamp=timestamp)


@_function_tool(strict_mode=False)
def session_list(limit: int = 25) -> Dict[str, Any]:
    """List available session checkpoints in the active workspace."""
    return SESSION_TOOL.session_list(limit=limit)


@_function_tool(strict_mode=False)
def session_export(checkpoint_id: str, target_agent_role: str) -> Dict[str, Any]:
    """Export a cross-agent handoff memo from a checkpoint."""
    return SESSION_TOOL.session_export(checkpoint_id=checkpoint_id, target_agent_role=target_agent_role)


@_function_tool(strict_mode=False)
def request_toolbox(category_name: str) -> Dict[str, Any]:
    """Persist a toolbox category selection to apply on the next model turn."""
    requested = str(category_name or "").strip().lower()
    session_id = get_current_toolbox_session_id()

    if not requested:
        return {
            "ok": False,
            "error": {
                "code": "missing_toolbox_category",
                "category": "validation",
                "message": "category_name is required.",
            },
            "session_id": session_id,
        }

    from cerberus.tools.all_tools import get_existing_tool_categories

    valid_categories = get_existing_tool_categories()
    if requested not in valid_categories:
        return {
            "ok": False,
            "error": {
                "code": "invalid_toolbox_category",
                "category": "validation",
                "message": f"Unknown toolbox category: {requested}",
                "valid_categories": valid_categories,
            },
            "session_id": session_id,
        }

    previous = get_toolbox_active_category(session_id)
    state = set_toolbox_active_category(session_id, requested)
    return {
        "ok": True,
        "session_id": session_id,
        "active_category": state.tool_state.active_category,
        "previous_category": previous,
        "applies_on": "next_turn",
    }


# =============================================================================
# Legacy shell session compatibility functions
# =============================================================================


def create_shell_session(command: str, ctf: Any = None, container_id: Optional[str] = None, **kwargs: Any) -> str:
    """Create a new shell session in the current workspace/environment."""
    workspace_dir = kwargs.get("workspace_dir") if "workspace_dir" in kwargs else None

    if container_id:
        session = ShellSession(command, ctf=ctf, container_id=container_id)
    else:
        workspace_dir = workspace_dir or _get_workspace_dir()
        session = ShellSession(command, ctf=ctf, workspace_dir=workspace_dir)

    session.start()
    if session.is_running or (ctf and not session.is_running):
        global SESSION_COUNTER
        with SESSIONS_LOCK:
            SESSION_COUNTER += 1
            friendly = f"S{SESSION_COUNTER}"
            session.friendly_id = friendly
            ACTIVE_SESSIONS[session.session_id] = session
            FRIENDLY_SESSION_MAP[friendly] = session.session_id
            REVERSE_SESSION_MAP[session.session_id] = friendly
        return session.session_id

    error_msg = session.get_output(clear=True)
    print(color(f"Failed to start session: {error_msg}", fg="red"))
    return f"Failed to start session: {error_msg}"


def list_shell_sessions() -> List[Dict[str, Any]]:
    """List active shell sessions with friendly identifiers and status."""
    result: List[Dict[str, Any]] = []
    with SESSIONS_LOCK:
        for session_id, session in list(ACTIVE_SESSIONS.items()):
            if not session.is_running:
                del ACTIVE_SESSIONS[session_id]
                continue

            result.append(
                {
                    "friendly_id": getattr(session, "friendly_id", None),
                    "session_id": session_id,
                    "command": session.command,
                    "running": session.is_running,
                    "last_activity": time.strftime("%H:%M:%S", time.localtime(session.last_activity)),
                }
            )

    return result


def _resolve_session_id(session_identifier: Optional[str]) -> Optional[str]:
    """Resolve friendly aliases (#1, S1, last) to real session IDs."""
    if not session_identifier:
        return None

    sid = str(session_identifier).strip()
    key = sid

    if sid.lower() == "last":
        with SESSIONS_LOCK:
            if not ACTIVE_SESSIONS:
                return None
            latest = None
            latest_t = -1.0
            for real_sid, sess in ACTIVE_SESSIONS.items():
                if hasattr(sess, "created_at") and sess.created_at > latest_t and sess.is_running:
                    latest = real_sid
                    latest_t = float(sess.created_at)
            return latest or next(iter(ACTIVE_SESSIONS.keys()))

    if sid.startswith("#"):
        key = f"S{sid[1:]}"
    elif sid.isdigit():
        key = f"S{sid}"
    elif sid.upper().startswith("S") and sid[1:].isdigit():
        key = sid.upper()

    with SESSIONS_LOCK:
        if sid in ACTIVE_SESSIONS:
            return sid
        if key in FRIENDLY_SESSION_MAP:
            return FRIENDLY_SESSION_MAP[key]

    return None


def get_session(session_id: str) -> Optional[ShellSession]:
    with SESSIONS_LOCK:
        return ACTIVE_SESSIONS.get(session_id)


def send_to_session(session_id: str, input_data: str) -> str:
    resolved = _resolve_session_id(session_id)
    if not resolved:
        return f"Session {session_id} not found"

    with SESSIONS_LOCK:
        if resolved not in ACTIVE_SESSIONS:
            return f"Session {session_id} not found"
        session = ACTIVE_SESSIONS[resolved]

    return session.send_input(input_data)


def get_session_output(session_id: str, clear: bool = True, stdout: bool = True) -> str:
    _ = stdout  # compatibility arg
    resolved = _resolve_session_id(session_id)
    if not resolved:
        return f"Session {session_id} not found"

    with SESSIONS_LOCK:
        if resolved not in ACTIVE_SESSIONS:
            return f"Session {session_id} not found"
        session = ACTIVE_SESSIONS[resolved]

    return session.get_output(clear)


def terminate_session(session_id: str) -> str:
    resolved = _resolve_session_id(session_id)
    if not resolved:
        return f"Session {session_id} not found or already terminated."

    with SESSIONS_LOCK:
        if resolved not in ACTIVE_SESSIONS:
            return f"Session {session_id} not found or already terminated."
        session = ACTIVE_SESSIONS[resolved]

    result = session.terminate()

    with SESSIONS_LOCK:
        if resolved in ACTIVE_SESSIONS:
            del ACTIVE_SESSIONS[resolved]
            friendly = REVERSE_SESSION_MAP.pop(resolved, None)
            if friendly:
                FRIENDLY_SESSION_MAP.pop(friendly, None)

    return result


__all__ = [
    "ShellSession",
    "create_shell_session",
    "list_shell_sessions",
    "_resolve_session_id",
    "send_to_session",
    "get_session_output",
    "terminate_session",
    "get_session",
    "ACTIVE_SESSIONS",
    "SESSION_OUTPUT_COUNTER",
    "CerebroSessionTool",
    "SESSION_TOOL",
    "session_checkpoint",
    "session_resume",
    "session_list",
    "session_export",
    "request_toolbox",
    "ToolboxToolState",
    "ToolSnapshot",
    "ToolboxSessionState",
    "get_or_create_toolbox_session",
    "set_toolbox_active_category",
    "set_toolbox_tool_state",
    "get_toolbox_active_category",
    "get_toolbox_tool_state",
    "append_toolbox_tool_snapshot",
    "get_toolbox_tool_history",
    "set_run_context_toolbox_session_id",
    "set_current_toolbox_session_id",
    "get_current_toolbox_session_id",
    "SessionCheckpoint",
    "SemanticState",
    "HandoffMemo",
]
