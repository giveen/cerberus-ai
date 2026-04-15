"""Hardened tool kernel for command execution and tool response normalization."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import sys
import threading
import types
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from pydantic import BaseModel, Field

from cai.repl.commands.shell import SecureSubprocess
from cai.repl.ui.logging import get_cerebro_logger
from cai.tools.sessions import (
    ACTIVE_SESSIONS,
    _resolve_session_id,
    create_shell_session,
    get_session_output,
    list_shell_sessions,
    send_to_session,
    terminate_session,
)
from cai.tools.validation import sanitize_tool_output
from cai.tools.workspace import (
    _get_container_workspace_path,
    _get_workspace_dir,
    get_project_space,
)
from cai.utils.streamer import run_streaming_subprocess

try:
    from cai.memory.logic import clean_data
except Exception:
    clean_data = lambda value: value  # type: ignore[misc,assignment]


_DEFAULT_EXEC_TIMEOUT = max(15, int(os.getenv("CEREBRO_COMMAND_TIMEOUT_SECONDS", "600")))
_MAX_EXEC_TIMEOUT = max(_DEFAULT_EXEC_TIMEOUT, int(os.getenv("CEREBRO_COMMAND_TIMEOUT_MAX", "3600")))
_DEFAULT_TRUNCATE_HEAD = 50
_DEFAULT_TRUNCATE_TAIL = 50
_AUDIT_DIR = "audit/local_exec"


class ToolResponse(BaseModel):
    ok: bool
    tool_name: str
    agent_id: str
    timestamp: str
    status: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    stdout: str = ""
    stderr: str = ""
    truncated: bool = False
    summary: str = ""
    exit_code: Optional[int] = None
    error: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CommandExecutionResult(BaseModel):
    ok: bool
    status: str
    argv: List[str]
    cwd: str
    started_at: str
    ended_at: str
    exit_code: Optional[int]
    stdout: str
    stderr: str
    truncated: bool = False
    summary: str = ""
    error: Optional[Dict[str, Any]] = None


@dataclass(frozen=True)
class _MappedStatus:
    status: str
    code: str
    message: str


class CerebroBaseTool:
    """Base class enforcing normalized output and metadata injection."""

    def __init__(self, tool_name: Optional[str] = None) -> None:
        self.tool_name = tool_name or self.__class__.__name__
        self._workspace = get_project_space().ensure_initialized().resolve()
        self._secure = SecureSubprocess(workspace_root=self._workspace)
        self._logger = get_cerebro_logger()

    async def execute(self, request: Mapping[str, Any]) -> Any:
        raise NotImplementedError

    async def run(self, *, request: Mapping[str, Any]) -> ToolResponse:
        timestamp = datetime.now(tz=UTC).isoformat()
        agent_id = self._resolve_agent_id()
        base_meta = {
            "agent_id": agent_id,
            "timestamp": timestamp,
            "tool_name": self.tool_name,
        }
        try:
            raw = await self.execute(request)
            normalized = self._normalize_payload(raw)
            redacted = self._redact_payload(normalized)
            response = ToolResponse(
                ok=True,
                tool_name=self.tool_name,
                agent_id=agent_id,
                timestamp=timestamp,
                status="completed",
                payload=redacted,
                stdout=str(redacted.get("stdout", "")),
                stderr=str(redacted.get("stderr", "")),
                truncated=bool(redacted.get("truncated", False)),
                summary=str(redacted.get("summary", "")),
                exit_code=redacted.get("exit_code"),
                metadata=base_meta,
            )
            return response
        except Exception as exc:  # pylint: disable=broad-except
            return ToolResponse(
                ok=False,
                tool_name=self.tool_name,
                agent_id=agent_id,
                timestamp=timestamp,
                status="failed",
                payload={},
                error={"code": "tool_runtime_error", "message": str(exc)},
                metadata=base_meta,
            )

    def _normalize_payload(self, raw: Any) -> Dict[str, Any]:
        if isinstance(raw, ToolResponse):
            return raw.model_dump()
        if isinstance(raw, Mapping):
            return dict(raw)
        if isinstance(raw, BaseModel):
            return raw.model_dump()  # type: ignore[no-any-return]
        return {"result": raw}

    def _redact_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        clean_env, redactions = self._secure.build_clean_environment()
        _ = clean_env
        redacted: Dict[str, Any] = {}
        for key, value in payload.items():
            if isinstance(value, str):
                redacted[key] = self._secure.redact_text(value, redactions)
            else:
                redacted[key] = value
        return clean_data(redacted)

    @staticmethod
    def _resolve_agent_id() -> str:
        for key in ("CEREBRO_AGENT_ID", "AGENT_ID", "CEREBRO_AGENT", "CEREBRO_AGENT_TYPE"):
            value = os.getenv(key, "").strip()
            if value:
                return value
        return "unknown-agent"


def mask_sensitive_cli_args(argv: Sequence[str]) -> List[str]:
    """Mask secrets from CLI args for audit-safe logging."""

    hidden_flags = {
        "-p",
        "--password",
        "--pass",
        "--token",
        "--secret",
        "--api-key",
        "--apikey",
        "--auth",
    }
    hidden_keys = {
        "password",
        "pass",
        "token",
        "secret",
        "apikey",
        "api_key",
        "auth",
        "credential",
    }

    masked: List[str] = []
    skip_next = False
    for idx, token in enumerate(argv):
        if skip_next:
            masked.append("[REDACTED]")
            skip_next = False
            continue
        lowered = token.lower()
        if lowered in hidden_flags:
            masked.append(token)
            skip_next = True
            continue

        if "=" in token:
            key, value = token.split("=", 1)
            key_low = key.strip("-").lower()
            if key_low in hidden_keys:
                masked.append(f"{key}=[REDACTED]")
                continue
            if any(piece in key_low for piece in ("password", "token", "secret", "credential", "apikey")):
                masked.append(f"{key}=[REDACTED]")
                continue
            masked.append(f"{key}={value}")
            continue

        if any(piece in lowered for piece in ("password", "token", "secret", "credential")) and idx + 1 < len(argv):
            masked.append(token)
            skip_next = True
            continue

        masked.append(token)

    return masked


def sanitize_path(path_value: str | os.PathLike[str], workspace_root: Optional[str | os.PathLike[str]] = None) -> Path:
    """Resolve symlinks and block traversal escaping the workspace."""

    root = Path(workspace_root).expanduser().resolve() if workspace_root else get_project_space().ensure_initialized().resolve()
    raw = Path(path_value).expanduser()

    if any(part == ".." for part in raw.parts):
        raise ValueError(f"Path traversal is not allowed: {path_value}")

    candidate = (root / raw).resolve() if not raw.is_absolute() else raw.resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"Path escapes workspace boundary: {path_value}") from exc
    return candidate


def truncate_and_summarize_output(
    text: str,
    *,
    head_lines: int = _DEFAULT_TRUNCATE_HEAD,
    tail_lines: int = _DEFAULT_TRUNCATE_TAIL,
) -> tuple[str, bool, str]:
    """Truncate huge outputs while preserving head/tail context."""

    lines = text.splitlines()
    if len(lines) <= (head_lines + tail_lines):
        return text, False, ""

    top = lines[:head_lines]
    bottom = lines[-tail_lines:]
    omitted = max(0, len(lines) - (head_lines + tail_lines))
    summary = f"Output truncated: omitted {omitted} middle lines from {len(lines)} total lines."
    compact = "\n".join([*top, "", f"[...] {summary}", "", *bottom])
    return compact, True, summary


async def execute_system_command(
    *,
    argv: Sequence[str],
    cwd: Optional[str | os.PathLike[str]] = None,
    timeout_seconds: int = _DEFAULT_EXEC_TIMEOUT,
    env: Optional[Mapping[str, str]] = None,
    redactor: Optional[Callable[[str], str]] = None,
) -> CommandExecutionResult:
    """Secure async command execution without shell invocation."""

    if not argv:
        now = datetime.now(tz=UTC).isoformat()
        return CommandExecutionResult(
            ok=False,
            status="invalid",
            argv=[],
            cwd=str(cwd or get_project_space().ensure_initialized()),
            started_at=now,
            ended_at=now,
            exit_code=None,
            stdout="",
            stderr="",
            error={"code": "empty_argv", "message": "No executable argument supplied."},
        )

    executable = str(argv[0])
    if shutil.which(executable) is None and not Path(executable).exists():
        now = datetime.now(tz=UTC).isoformat()
        return CommandExecutionResult(
            ok=False,
            status="missing_dependency",
            argv=list(argv),
            cwd=str(cwd or get_project_space().ensure_initialized()),
            started_at=now,
            ended_at=now,
            exit_code=None,
            stdout="",
            stderr="",
            error={"code": "command_not_found", "message": f"Executable not found: {executable}"},
        )

    root = get_project_space().ensure_initialized().resolve()
    target_cwd = sanitize_path(str(cwd or root), workspace_root=root)
    secure = SecureSubprocess(workspace_root=root)
    clean_env, redactions = secure.build_clean_environment()
    runtime_env = dict(clean_env)
    if env:
        runtime_env.update({k: v for k, v in env.items() if v is not None})

    timeout_value = max(1, min(int(timeout_seconds), _MAX_EXEC_TIMEOUT))
    started = datetime.now(tz=UTC)

    def _redact(text: str) -> str:
        masked = secure.redact_text(text, redactions)
        if redactor is not None:
            masked = redactor(masked)
        return masked

    process_result = await run_streaming_subprocess(
        argv=[str(item) for item in argv],
        cwd=str(target_cwd),
        env=runtime_env,
        timeout_seconds=timeout_value,
        redactor=_redact,
        stdout_mode="line",
        stderr_mode="line",
        max_output_chars=200_000,
        max_line_chars=8_000,
        timeout_message="Execution timed out by policy",
    )

    ended = datetime.now(tz=UTC)
    stdout_text = process_result.stdout
    stderr_text = process_result.stderr

    compact_stdout, out_truncated, out_summary = truncate_and_summarize_output(stdout_text)
    compact_stderr, err_truncated, err_summary = truncate_and_summarize_output(stderr_text)
    truncated = out_truncated or err_truncated
    summary = " ".join(item for item in (out_summary, err_summary) if item).strip()

    mapped = _map_exit_code(process_result.exit_code, timed_out=process_result.timed_out)
    if mapped is None:
        return CommandExecutionResult(
            ok=True,
            status="completed",
            argv=list(argv),
            cwd=str(target_cwd),
            started_at=started.isoformat(),
            ended_at=ended.isoformat(),
            exit_code=process_result.exit_code,
            stdout=sanitize_tool_output(" ".join(mask_sensitive_cli_args(argv)), compact_stdout),
            stderr=sanitize_tool_output(" ".join(mask_sensitive_cli_args(argv)), compact_stderr),
            truncated=truncated,
            summary=summary,
            error=None,
        )

    return CommandExecutionResult(
        ok=False,
        status=mapped.status,
        argv=list(argv),
        cwd=str(target_cwd),
        started_at=started.isoformat(),
        ended_at=ended.isoformat(),
        exit_code=process_result.exit_code,
        stdout=sanitize_tool_output(" ".join(mask_sensitive_cli_args(argv)), compact_stdout),
        stderr=sanitize_tool_output(" ".join(mask_sensitive_cli_args(argv)), compact_stderr),
        truncated=truncated,
        summary=summary,
        error={"code": mapped.code, "message": mapped.message},
    )


def _map_exit_code(code: Optional[int], *, timed_out: bool) -> Optional[_MappedStatus]:
    if timed_out:
        return _MappedStatus(status="timeout", code="timeout", message="Execution exceeded timeout policy")
    if code in {None, 0}:
        return None
    if code == 1:
        return _MappedStatus(status="failed", code="generic_failure", message="Command failed with a generic error")
    if code == 2:
        return _MappedStatus(status="invalid", code="invalid_usage", message="Command invocation was invalid")
    if code == 126:
        return _MappedStatus(status="failed", code="not_executable", message="File is not executable or permission denied")
    if code == 127:
        return _MappedStatus(status="missing_dependency", code="command_not_found", message="Executable was not found")
    if code == 130:
        return _MappedStatus(status="interrupted", code="interrupted", message="Execution was interrupted")
    if code == 137:
        return _MappedStatus(status="killed", code="killed", message="Execution was terminated (SIGKILL)")
    if code is not None and code < 0:
        return _MappedStatus(status="killed", code="signal_terminated", message=f"Execution terminated by signal {abs(code)}")
    return _MappedStatus(status="failed", code="exit_nonzero", message=f"Command exited with code {code}")


def _audit_command_event(*, tool_name: str, command: Sequence[str], result: CommandExecutionResult) -> None:
    workspace = get_project_space().ensure_initialized().resolve()
    audit_dir = (workspace / _AUDIT_DIR).resolve()
    audit_dir.mkdir(parents=True, exist_ok=True)
    output_digest = hashlib_sha256((result.stdout + "\n" + result.stderr).encode("utf-8", errors="replace"))
    row = {
        "timestamp": datetime.now(tz=UTC).isoformat(),
        "tool": tool_name,
        "command": list(mask_sensitive_cli_args(command)),
        "cwd": result.cwd,
        "exit_code": result.exit_code,
        "status": result.status,
        "output_sha256": output_digest,
    }
    line = json.dumps(clean_data(row), ensure_ascii=True) + "\n"
    with (audit_dir / "executions.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(line)

    logger = get_cerebro_logger()
    with suppress(Exception):
        logger.audit("common kernel command event", actor=tool_name, data=clean_data(row), tags=["common", tool_name])


def hashlib_sha256(raw: bytes) -> str:
    import hashlib

    hasher = hashlib.sha256()
    hasher.update(raw)
    return hasher.hexdigest()


def _run_ctf(ctf: Any, command: str, stdout: bool = False, timeout: int = 100, workspace_dir: Optional[str] = None, stream: bool = False) -> str:
    _ = stream
    target_dir = workspace_dir or _get_workspace_dir()
    try:
        output = ctf.get_shell(command, timeout=timeout)
    except Exception as exc:  # pylint: disable=broad-except
        output = f"Error executing CTF command in {target_dir}: {exc}"
    if stdout:
        print(output)
    return str(output)


def _run_ssh(command: str, stdout: bool = False, timeout: int = 100, workspace_dir: Optional[str] = None, stream: bool = False) -> str:
    _ = workspace_dir, stream
    ssh_user = os.environ.get("SSH_USER", "")
    ssh_host = os.environ.get("SSH_HOST", "")
    ssh_pass = os.environ.get("SSH_PASS", "")
    if not ssh_user or not ssh_host:
        return "SSH environment is not configured"

    argv: List[str]
    if ssh_pass:
        argv = ["sshpass", "-p", ssh_pass, "ssh", f"{ssh_user}@{ssh_host}", command]
    else:
        argv = ["ssh", f"{ssh_user}@{ssh_host}", command]

    result = _run_sync(execute_system_command(argv=argv, timeout_seconds=timeout, cwd=_get_workspace_dir()))
    _audit_command_event(tool_name="ssh", command=argv, result=result)
    output = result.stdout if result.stdout else result.stderr
    if stdout and output:
        print(output)
    return output.strip()


def _run_local(command: str, stdout: bool = False, timeout: int = 100, stream: bool = False, call_id: Optional[str] = None, tool_name: Optional[str] = None, workspace_dir: Optional[str] = None, custom_args: Optional[Mapping[str, Any]] = None) -> str:
    from cai.tools.runners.local import run_local as _run_local_impl

    return _run_local_impl(
        command,
        stdout=stdout,
        timeout=timeout,
        stream=stream,
        call_id=call_id,
        tool_name=tool_name,
        workspace_dir=workspace_dir,
        custom_args=custom_args,
    )


async def _run_local_async(command: str, stdout: bool = False, timeout: int = _DEFAULT_EXEC_TIMEOUT, stream: bool = False, call_id: Optional[str] = None, tool_name: Optional[str] = None, workspace_dir: Optional[str] = None, custom_args: Optional[Mapping[str, Any]] = None) -> str:
    from cai.tools.runners.local import run_local_async as _run_local_async_impl

    return await _run_local_async_impl(
        command,
        stdout=stdout,
        timeout=timeout,
        stream=stream,
        call_id=call_id,
        tool_name=tool_name,
        workspace_dir=workspace_dir,
        custom_args=custom_args,
    )


async def _run_docker_async(command: str, container_id: str, stdout: bool = False, timeout: int = _DEFAULT_EXEC_TIMEOUT, stream: bool = False, call_id: Optional[str] = None, tool_name: Optional[str] = None, args: Optional[Mapping[str, Any]] = None) -> str:
    from cai.tools.runners.docker import run_docker_async as _run_docker_async_impl

    return await _run_docker_async_impl(
        command,
        container_id=container_id,
        stdout=stdout,
        timeout=timeout,
        stream=stream,
        call_id=call_id,
        tool_name=tool_name,
        args=args,
    )


async def run_command_async(command: str, ctf: Any = None, stdout: bool = False, async_mode: bool = False, session_id: Optional[str] = None, timeout: int = _DEFAULT_EXEC_TIMEOUT, stream: bool = False, call_id: Optional[str] = None, tool_name: Optional[str] = None, args: Optional[Mapping[str, Any]] = None) -> str:
    _ = async_mode
    if session_id:
        return send_to_session(session_id, command)

    if ctf and os.getenv("CTF_INSIDE", "true").lower() == "true":
        return await asyncio.to_thread(_run_ctf, ctf, command, stdout, timeout, _get_workspace_dir(), stream)

    is_ssh_env = bool(os.getenv("SSH_USER")) and bool(os.getenv("SSH_HOST"))
    active_container = os.getenv("CEREBRO_ACTIVE_CONTAINER", "").strip()

    if active_container and not is_ssh_env:
        return await _run_docker_async(
            command,
            container_id=active_container,
            stdout=stdout,
            timeout=timeout,
            stream=stream,
            call_id=call_id,
            tool_name=tool_name,
            args=args,
        )

    if is_ssh_env:
        return await asyncio.to_thread(_run_ssh, command, stdout, timeout, _get_workspace_dir(), stream)

    return await _run_local_async(
        command,
        stdout=stdout,
        timeout=timeout,
        stream=stream,
        call_id=call_id,
        tool_name=tool_name,
        workspace_dir=_get_workspace_dir(),
        custom_args=args,
    )


def run_command(command: str, ctf: Any = None, stdout: bool = False, async_mode: bool = False, session_id: Optional[str] = None, timeout: int = _DEFAULT_EXEC_TIMEOUT, stream: bool = False, call_id: Optional[str] = None, tool_name: Optional[str] = None, args: Optional[Mapping[str, Any]] = None) -> str:
    if session_id:
        return send_to_session(session_id, command)

    if async_mode:
        if os.getenv("CEREBRO_ACTIVE_CONTAINER", ""):
            sid = create_shell_session(command, ctf=ctf, container_id=os.getenv("CEREBRO_ACTIVE_CONTAINER"))
        else:
            sid = create_shell_session(command, ctf=ctf, workspace_dir=_get_workspace_dir())
        return f"Started async session {sid}"

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        return _run_sync(
            run_command_async(
                command,
                ctf=ctf,
                stdout=stdout,
                async_mode=False,
                session_id=None,
                timeout=timeout,
                stream=stream,
                call_id=call_id,
                tool_name=tool_name,
                args=args,
            )
        )

    return asyncio.run(
        run_command_async(
            command,
            ctf=ctf,
            stdout=stdout,
            async_mode=False,
            session_id=None,
            timeout=timeout,
            stream=stream,
            call_id=call_id,
            tool_name=tool_name,
            args=args,
        )
    )


def _start_tool_streaming_helper(tool_name: str, tool_args: dict, call_id: Optional[str] = None) -> tuple[str, dict]:
    from cai.tools.agent_info import _get_agent_token_info
    from cai.util import start_tool_streaming

    token_info = _get_agent_token_info()
    new_call_id = start_tool_streaming(tool_name, tool_args, call_id, token_info)
    return new_call_id, token_info


def _update_tool_streaming_helper(tool_name: str, tool_args: dict, content: str, call_id: str, token_info: dict) -> None:
    from cai.util import update_tool_streaming

    update_tool_streaming(tool_name, tool_args, content, call_id, token_info)


def _finish_tool_streaming_helper(tool_name: str, tool_args: dict, content: str, call_id: str, execution_info: dict, token_info: Optional[dict] = None) -> None:
    from cai.tools.agent_info import _get_agent_token_info
    from cai.util import finish_tool_streaming

    resolved = token_info if token_info is not None else _get_agent_token_info()
    finish_tool_streaming(tool_name, tool_args, content, call_id, execution_info, resolved)


def _run_sync(coro: Any) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    result: Dict[str, Any] = {}
    errors: List[BaseException] = []

    def _worker() -> None:
        try:
            value = asyncio.run(coro)
            result["value"] = value
        except BaseException as exc:  # pylint: disable=broad-except
            errors.append(exc)

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()
    thread.join()
    if errors:
        raise errors[0]
    return result.get("value")


def get_all_predefined_models() -> List[Dict[str, Any]]:
    from cai.repl.commands.model import get_all_predefined_models as _impl

    return _impl()


def get_predefined_model_categories() -> Dict[str, List[Dict[str, Any]]]:
    models = get_all_predefined_models()
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for item in models:
        key = str(item.get("category", "other"))
        grouped.setdefault(key, []).append(item)
    return grouped


def _register_get_models_virtual_module() -> None:
    module_name = "cai.tools.common.get_models"
    virtual = types.ModuleType(module_name)
    virtual.get_all_predefined_models = get_all_predefined_models  # type: ignore[attr-defined]
    virtual.get_predefined_model_categories = get_predefined_model_categories  # type: ignore[attr-defined]
    sys.modules[module_name] = virtual


_register_get_models_virtual_module()


__all__ = [
    "ACTIVE_SESSIONS",
    "CerebroBaseTool",
    "CommandExecutionResult",
    "ToolResponse",
    "_finish_tool_streaming_helper",
    "_get_container_workspace_path",
    "_get_workspace_dir",
    "_resolve_session_id",
    "_run_ctf",
    "_run_docker_async",
    "_run_local",
    "_run_local_async",
    "_run_ssh",
    "_start_tool_streaming_helper",
    "_update_tool_streaming_helper",
    "create_shell_session",
    "execute_system_command",
    "get_all_predefined_models",
    "get_predefined_model_categories",
    "get_session_output",
    "list_shell_sessions",
    "mask_sensitive_cli_args",
    "run_command",
    "run_command_async",
    "sanitize_path",
    "send_to_session",
    "terminate_session",
    "truncate_and_summarize_output",
]
