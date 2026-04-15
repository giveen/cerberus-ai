"""Hardened local execution gateway for Cerberus AI."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import random
import re
import shlex
import shutil
import threading
import time
from typing import Any, Callable, Dict, List, Literal, Mapping, Optional, Sequence, Tuple

try:
    from cai.memory.logic import clean_data
except Exception:
    clean_data = lambda value: value  # type: ignore[misc,assignment]

from cai.repl.commands.shell import SecureSubprocess, StreamLine
from cai.repl.ui.logging import get_cerebro_logger
from cai.tools.validation import sanitize_tool_output, validate_command_guardrails
from cai.tools.workspace import get_project_space

_MAX_TIMEOUT_SECONDS = 15
_DEFAULT_MEMORY_LIMIT_MB = 512
_MAX_OUTPUT_CHARS = 50_000
_MAX_LINE_CHARS = 4_000
_DEFAULT_JITTER_MS = 75
_MAX_JITTER_MS = 3_000
_RESTRICTED_PATHS = {
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/master.passwd",
    "/proc/kcore",
    "/dev/mem",
    "/windows/system32/config/sam",
    "/windows/system32/config/security",
}
_ENV_SECRET_KEY_RE = re.compile(
    r"(KEY|TOKEN|SECRET|PASSWORD|PASS|CREDENTIAL|AWS_|AZURE_|GCP_|GOOGLE_|OPENAI_|ANTHROPIC_)",
    re.IGNORECASE,
)
_PASSWD_LINE_RE = re.compile(r"^([^:]+):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*)$", re.MULTILINE)


@dataclass(frozen=True)
class ResourceConstraintError:
    code: str
    message: str
    category: str = "resource"


@dataclass(frozen=True)
class ExecutionRecord:
    ok: bool
    command: str
    argv: List[str]
    cwd: str
    started_at: str
    ended_at: str
    exit_code: Optional[int]
    timed_out: bool
    stdout: str
    stderr: str
    output_sha256: str
    stdout_truncated: bool
    stderr_truncated: bool
    error: Optional[Dict[str, Any]]


class PathGuard:
    """Host path boundary checks for local command arguments."""

    _WRITE_COMMANDS = {
        "touch",
        "tee",
        "cp",
        "mv",
        "rm",
        "mkdir",
        "rmdir",
        "truncate",
        "dd",
        "install",
        "ln",
        "chmod",
        "chown",
        "chgrp",
        "sed",
        "awk",
        "perl",
    }

    def __init__(self, workspace_root: Path) -> None:
        self._workspace = workspace_root.resolve()
        self._tmp_roots = self._build_tmp_roots()

    def validate_command(self, argv: Sequence[str]) -> None:
        if not argv:
            raise PermissionError("No command tokens supplied")

        write_intent = self._has_write_intent(argv)
        for token in argv:
            candidate = token.strip()
            if not candidate or candidate.startswith("-"):
                continue
            if "\x00" in candidate:
                raise PermissionError("Null byte detected in command token")
            path = self._as_path(candidate)
            if path is None:
                continue
            self._assert_not_restricted(path)
            if write_intent:
                self._assert_write_allowed(path)

    def _assert_not_restricted(self, candidate: Path) -> None:
        lowered = str(candidate).lower().replace("\\", "/")
        if lowered in _RESTRICTED_PATHS:
            raise PermissionError(f"Restricted path access denied: {candidate}")

    def _assert_write_allowed(self, candidate: Path) -> None:
        if self._is_within(self._workspace, candidate):
            return
        for tmp_root in self._tmp_roots:
            if self._is_within(tmp_root, candidate):
                return
        raise PermissionError(
            "Write denied by PathGuard: destination must stay inside workspace or approved tmp directories"
        )

    @staticmethod
    def _is_within(root: Path, candidate: Path) -> bool:
        try:
            candidate.relative_to(root)
            return True
        except ValueError:
            return False

    @classmethod
    def _has_write_intent(cls, argv: Sequence[str]) -> bool:
        exe = Path(argv[0]).name.lower()
        if exe in cls._WRITE_COMMANDS:
            return True
        lowered = " ".join(argv).lower()
        return any(flag in lowered for flag in ("--in-place", "--output", "--append", "of="))

    def _as_path(self, token: str) -> Optional[Path]:
        if token in {".", ".."}:
            return (self._workspace / token).resolve()
        if token.startswith("/") or token.startswith("~") or token.startswith("./") or token.startswith("../"):
            raw = Path(token).expanduser()
            return (self._workspace / raw).resolve() if not raw.is_absolute() else raw.resolve()
        if "/" in token or "\\" in token:
            raw = Path(token)
            return (self._workspace / raw).resolve() if not raw.is_absolute() else raw.resolve()
        return None

    @staticmethod
    def _build_tmp_roots() -> List[Path]:
        roots = {Path("/tmp").resolve(), Path("/var/tmp").resolve()}
        env_tmp = os.getenv("TMPDIR", "").strip()
        if env_tmp:
            with suppress(Exception):
                roots.add(Path(env_tmp).expanduser().resolve())
        return sorted(roots)


class CerebroLocalRunner:
    """Async local execution gateway with clean-room env and forensic logging."""

    def __init__(self) -> None:
        self._workspace = get_project_space().ensure_initialized().resolve()
        self._secure = SecureSubprocess(workspace_root=self._workspace)
        self._logger = get_cerebro_logger()
        self._path_guard = PathGuard(self._workspace)
        self._audit_root = (self._workspace / "audit" / "local_exec").resolve()
        self._audit_log = (self._audit_root / "executions.jsonl").resolve()
        self._audit_root.mkdir(parents=True, exist_ok=True)
        self._last_command_finished_at = 0.0
        self._jitter_lock = asyncio.Lock()

    async def execute(
        self,
        *,
        command: str,
        timeout_seconds: int = _MAX_TIMEOUT_SECONDS,
        stream: bool = False,
        tool_name: Optional[str] = None,
        call_id: Optional[str] = None,
        cwd: Optional[str] = None,
        custom_args: Optional[Mapping[str, Any]] = None,
        jitter_ms: Optional[int] = None,
        memory_limit_mb: int = _DEFAULT_MEMORY_LIMIT_MB,
    ) -> Dict[str, Any]:
        command = (command or "").strip()
        if not command:
            return self._error("empty_command", "No command provided.", category="validation")

        guardrail_error = validate_command_guardrails(command)
        if guardrail_error:
            return self._error("guardrail_blocked", guardrail_error, category="policy")

        try:
            argv = shlex.split(command, posix=True)
        except ValueError as exc:
            return self._error("invalid_syntax", f"Unable to parse command tokens: {exc}", category="validation")

        if not argv:
            return self._error("empty_command", "No executable token found.", category="validation")
        if not self._resolve_executable(argv[0]):
            return self._error("command_not_found", f"Command not found: {argv[0]}", category="dependency")

        try:
            self._path_guard.validate_command(argv)
        except PermissionError as exc:
            message = str(exc)
            code = "restricted_path" if "Restricted path" in message else "boundary_violation"
            category = "policy" if code == "restricted_path" else "sandbox"
            return self._error(code, message, category=category)

        resolved_cwd = self._resolve_cwd(cwd)
        timeout_cap = max(1, min(int(timeout_seconds), _MAX_TIMEOUT_SECONDS))
        mem_cap_bytes = max(64, int(memory_limit_mb)) * 1024 * 1024
        await self._apply_jitter(jitter_ms)

        clean_env, redaction_map = self._secure.build_clean_environment()
        runtime_env = self._scrub_environment(clean_env)
        started_at = datetime.now(tz=UTC)

        token_info = None
        start_streaming = update_streaming = finish_streaming = None
        stream_call_id = call_id
        parts = command.split(" ", 1)
        stream_tool_name = tool_name or (f"{parts[0]}_command" if parts else "command")
        stream_args: Dict[str, Any] = dict(custom_args or {})
        if not stream_args:
            stream_args = {
                "command": parts[0] if parts else command,
                "args": parts[1] if len(parts) > 1 else "",
                "full_command": command,
                "workspace": os.path.basename(str(resolved_cwd)),
            }
        else:
            stream_args.setdefault("full_command", command)
            stream_args.setdefault("workspace", os.path.basename(str(resolved_cwd)))

        if stream:
            with suppress(Exception):
                from cai.tools.agent_info import _get_agent_token_info
                from cai.util import start_tool_streaming, update_tool_streaming, finish_tool_streaming

                token_info = _get_agent_token_info()
                start_streaming = start_tool_streaming
                update_streaming = update_tool_streaming
                finish_streaming = finish_tool_streaming
                stream_call_id = start_streaming(stream_tool_name, stream_args, call_id, token_info)

        process = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(resolved_cwd),
            env=runtime_env,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        if process.stdout is None or process.stderr is None:
            process.kill()
            await process.wait()
            return self._error("process_init_failed", "Local subprocess streams were not initialized", category="execution")

        stdout_chunks: List[str] = []
        stderr_chunks: List[str] = []
        stdout_len = 0
        stderr_len = 0
        stdout_truncated = False
        stderr_truncated = False
        resource_error: Optional[ResourceConstraintError] = None
        timed_out = False
        start_perf = time.perf_counter()

        async def _capture_stream(stream_obj: asyncio.StreamReader, stream_name: Literal["stdout", "stderr"]) -> None:
            nonlocal stdout_len, stderr_len, stdout_truncated, stderr_truncated
            while True:
                chunk = await stream_obj.readline()
                if not chunk:
                    break
                raw = chunk.decode("utf-8", errors="replace")
                redacted = self._redact_output(self._secure.redact_text(raw, redaction_map))
                if len(redacted) > _MAX_LINE_CHARS:
                    redacted = redacted[:_MAX_LINE_CHARS] + "\n...[line truncated by policy]"
                bucket = stdout_chunks if stream_name == "stdout" else stderr_chunks
                current_len = stdout_len if stream_name == "stdout" else stderr_len
                if current_len >= _MAX_OUTPUT_CHARS:
                    if stream_name == "stdout":
                        stdout_truncated = True
                    else:
                        stderr_truncated = True
                    continue
                remaining = _MAX_OUTPUT_CHARS - current_len
                if len(redacted) > remaining:
                    bucket.append(redacted[:remaining] + "\n...[output truncated by policy]")
                    if stream_name == "stdout":
                        stdout_len = _MAX_OUTPUT_CHARS
                        stdout_truncated = True
                    else:
                        stderr_len = _MAX_OUTPUT_CHARS
                        stderr_truncated = True
                else:
                    bucket.append(redacted)
                    if stream_name == "stdout":
                        stdout_len += len(redacted)
                    else:
                        stderr_len += len(redacted)

                if stream and update_streaming and stream_call_id:
                    stamp = int((time.perf_counter() - start_perf) * 1000)
                    line = StreamLine(stream=stream_name, text=redacted.rstrip("\r\n"), at_ms=stamp)
                    update_streaming(stream_tool_name, stream_args, line.text, stream_call_id, token_info)

        async def _watchdog() -> None:
            nonlocal resource_error, timed_out
            deadline = time.perf_counter() + float(timeout_cap)
            pid = process.pid
            while process.returncode is None:
                if time.perf_counter() >= deadline:
                    timed_out = True
                    resource_error = ResourceConstraintError(
                        code="execution_cap_exceeded",
                        message=f"Process exceeded mandatory execution cap of {timeout_cap} seconds",
                    )
                    process.kill()
                    return
                rss = self._read_rss_bytes(pid)
                if rss is not None and rss > mem_cap_bytes:
                    resource_error = ResourceConstraintError(
                        code="memory_cap_exceeded",
                        message=f"Process exceeded memory cap of {int(memory_limit_mb)} MB",
                    )
                    process.kill()
                    return
                await asyncio.sleep(0.2)

        capture_tasks = [
            asyncio.create_task(_capture_stream(process.stdout, "stdout")),
            asyncio.create_task(_capture_stream(process.stderr, "stderr")),
        ]
        watchdog_task = asyncio.create_task(_watchdog())

        try:
            await process.wait()
        finally:
            watchdog_task.cancel()
            await asyncio.gather(*capture_tasks, return_exceptions=True)
            with suppress(asyncio.CancelledError, Exception):
                await watchdog_task
            self._last_command_finished_at = time.time()

        ended_at = datetime.now(tz=UTC)
        stdout_text = sanitize_tool_output(command, "".join(stdout_chunks))
        stderr_text = sanitize_tool_output(command, "".join(stderr_chunks))
        combined = (stdout_text + "\n" + stderr_text).encode("utf-8", errors="replace")
        output_sha256 = hashlib.sha256(combined).hexdigest()
        exit_code = process.returncode

        if resource_error is not None:
            error = {"code": resource_error.code, "message": resource_error.message, "category": resource_error.category}
        elif (exit_code or 0) != 0:
            error = {"code": "command_failed", "message": f"Command exited with code {exit_code}", "category": "execution"}
        else:
            error = None

        record = ExecutionRecord(
            ok=error is None,
            command=command,
            argv=list(argv),
            cwd=str(resolved_cwd),
            started_at=started_at.isoformat(),
            ended_at=ended_at.isoformat(),
            exit_code=exit_code,
            timed_out=timed_out,
            stdout=stdout_text,
            stderr=stderr_text,
            output_sha256=output_sha256,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            error=error,
        )
        await self._write_audit(record)

        if stream and finish_streaming and stream_call_id:
            execution_info = {
                "status": "completed" if error is None else "error",
                "return_code": exit_code,
                "environment": "Local",
                "host": os.path.basename(str(resolved_cwd)),
                "tool_time": max(0.0, (ended_at - started_at).total_seconds()),
            }
            finish_streaming(
                stream_tool_name,
                stream_args,
                (stdout_text + ("\n" + stderr_text if stderr_text else "")).strip(),
                stream_call_id,
                execution_info,
                token_info,
            )

        return clean_data(record.__dict__)

    async def _apply_jitter(self, jitter_ms: Optional[int]) -> None:
        value = self._coerce_jitter(jitter_ms)
        if value <= 0:
            return
        async with self._jitter_lock:
            now = time.time()
            elapsed = now - self._last_command_finished_at
            wait_for = max(0.0, (random.uniform(0.0, value) / 1000.0) - elapsed)
            if wait_for > 0:
                await asyncio.sleep(wait_for)

    def _resolve_cwd(self, cwd: Optional[str]) -> Path:
        if not cwd:
            return self._workspace
        candidate = Path(cwd).expanduser()
        if not candidate.is_absolute():
            candidate = (self._workspace / candidate).resolve()
        else:
            candidate = candidate.resolve()
        if not candidate.exists() or not candidate.is_dir():
            raise ValueError(f"Invalid execution directory: {candidate}")
        return candidate

    def _scrub_environment(self, base_env: Dict[str, str]) -> Dict[str, str]:
        clean: Dict[str, str] = {}
        for key, value in base_env.items():
            if not value:
                continue
            if key in {"HISTFILE", "HISTSIZE", "HISTCONTROL", "PYTHONPATH", "LD_PRELOAD", "LD_LIBRARY_PATH"}:
                continue
            if _ENV_SECRET_KEY_RE.search(key):
                continue
            if key in {"AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE", "KUBECONFIG", "SSH_AUTH_SOCK", "GNUPGHOME"}:
                continue
            clean[key] = value
        clean["PATH"] = clean.get("PATH") or os.getenv("PATH", "/usr/bin:/bin")
        clean["WORKSPACE_ROOT"] = str(self._workspace)
        clean["PWD"] = str(self._workspace)
        return clean

    def _redact_output(self, text: str) -> str:
        redacted = text.replace(str(self._workspace), "[WORKSPACE_ROOT]")
        redacted = redacted.replace(str(Path.home()), "[HOME]")

        def _mask_passwd(match: re.Match[str]) -> str:
            user = match.group(1)
            uid = match.group(3)
            gid = match.group(4)
            shell = match.group(7)
            return f"{user}:x:{uid}:{gid}:[REDACTED_USERINFO]:[REDACTED_PATH]:{shell}"

        redacted = _PASSWD_LINE_RE.sub(_mask_passwd, redacted)
        redacted = re.sub(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", "[REDACTED_EMAIL]", redacted)
        return clean_data(redacted)

    async def _write_audit(self, record: ExecutionRecord) -> None:
        payload = {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "command": record.command,
            "argv": record.argv,
            "cwd": record.cwd,
            "exit_code": record.exit_code,
            "timed_out": record.timed_out,
            "output_sha256": record.output_sha256,
            "started_at": record.started_at,
            "ended_at": record.ended_at,
            "error": record.error,
        }
        line = json.dumps(clean_data(payload), ensure_ascii=True) + "\n"
        await asyncio.to_thread(self._append_line, self._audit_log, line)
        if self._logger is not None:
            with suppress(Exception):
                self._logger.audit("local execution event", actor="local", data=clean_data(payload), tags=["local", "execution"])

    @staticmethod
    def _append_line(path: Path, line: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line)

    @staticmethod
    def _coerce_jitter(jitter_ms: Optional[int]) -> int:
        raw = _DEFAULT_JITTER_MS if jitter_ms is None else int(jitter_ms)
        return max(0, min(_MAX_JITTER_MS, raw))

    @staticmethod
    def _resolve_executable(executable: str) -> bool:
        candidate = Path(executable)
        if candidate.is_absolute() and candidate.exists() and candidate.is_file():
            return True
        return shutil.which(executable) is not None

    @staticmethod
    def _read_rss_bytes(pid: int) -> Optional[int]:
        status_file = Path(f"/proc/{pid}/status")
        if not status_file.exists():
            return None
        try:
            for line in status_file.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("VmRSS:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return int(parts[1]) * 1024
        except Exception:
            return None
        return None

    @staticmethod
    def _error(code: str, message: str, *, category: str) -> Dict[str, Any]:
        return {"ok": False, "error": {"code": code, "message": message, "category": category}}


LOCAL_RUNNER = CerebroLocalRunner()


async def run_local_async(command, stdout=False, timeout=100, stream=False, call_id=None, tool_name=None, workspace_dir=None, custom_args=None):
    result = await LOCAL_RUNNER.execute(
        command=str(command),
        timeout_seconds=int(timeout),
        stream=bool(stream),
        tool_name=tool_name,
        call_id=call_id,
        cwd=workspace_dir,
        custom_args=custom_args if isinstance(custom_args, Mapping) else None,
        jitter_ms=(custom_args or {}).get("jitter_ms") if isinstance(custom_args, Mapping) else None,
        memory_limit_mb=int((custom_args or {}).get("memory_limit_mb", _DEFAULT_MEMORY_LIMIT_MB)) if isinstance(custom_args, Mapping) else _DEFAULT_MEMORY_LIMIT_MB,
    )
    output = _format_compat_output(result)
    if stdout and output:
        print(f"(local:{workspace_dir or LOCAL_RUNNER._workspace}) $ {command}\n{output}")
    return output


def run_local(command, stdout=False, timeout=100, stream=False, call_id=None, tool_name=None, workspace_dir=None, custom_args=None):
    result = _run_sync(
        LOCAL_RUNNER.execute(
            command=str(command),
            timeout_seconds=int(timeout),
            stream=bool(stream),
            tool_name=tool_name,
            call_id=call_id,
            cwd=workspace_dir,
            custom_args=custom_args if isinstance(custom_args, Mapping) else None,
            jitter_ms=(custom_args or {}).get("jitter_ms") if isinstance(custom_args, Mapping) else None,
            memory_limit_mb=int((custom_args or {}).get("memory_limit_mb", _DEFAULT_MEMORY_LIMIT_MB)) if isinstance(custom_args, Mapping) else _DEFAULT_MEMORY_LIMIT_MB,
        )
    )
    output = _format_compat_output(result)
    if stdout and output:
        print(f"(local:{workspace_dir or LOCAL_RUNNER._workspace}) $ {command}\n{output}")
    return output


def _format_compat_output(result: Dict[str, Any]) -> str:
    if not result.get("ok"):
        error = result.get("error") or {}
        return str(error.get("message", "Local execution failed"))
    stdout = str(result.get("stdout", "") or "").strip()
    stderr = str(result.get("stderr", "") or "").strip()
    exit_code = result.get("exit_code")
    if stdout and stderr:
        return f"{stdout}\n{stderr}".strip()
    if stdout:
        return stdout
    if stderr:
        return stderr
    if exit_code not in {None, 0}:
        return f"Command exited with code {exit_code}"
    return ""


def _run_sync(coro: Any) -> Dict[str, Any]:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    result: Dict[str, Any] = {}
    error: List[BaseException] = []

    def _target() -> None:
        try:
            result.update(asyncio.run(coro))
        except BaseException as exc:  # pylint: disable=broad-except
            error.append(exc)

    thread = threading.Thread(target=_target, daemon=True)
    thread.start()
    thread.join()
    if error:
        raise error[0]
    return result


__all__ = ["CerebroLocalRunner", "LOCAL_RUNNER", "run_local", "run_local_async"]
