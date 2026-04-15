"""Hardened asynchronous shell proxy for Cerberus AI."""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import re
import shlex
import uuid
from typing import Any, Dict, Iterable, List, Optional, Sequence

from cerberus.memory.logic import clean_data
from cerberus.repl.commands.shell import SecureSubprocess
from cerberus.repl.ui.logging import get_cerberus_logger
from cerberus.sdk.agents import function_tool
from cerberus.tools.common import ACTIVE_SESSIONS, _resolve_session_id, get_session_output, list_shell_sessions, run_command, run_command_async, terminate_session
from cerberus.tools.misc.cli_utils import CLI_UTILS
from cerberus.tools.validation import sanitize_tool_output, validate_command_guardrails
from cerberus.tools.workspace import get_project_space
from cerberus.utils.process_handler import run_streaming_subprocess


_DEFAULT_TIMEOUT_SECONDS = max(30, int(os.getenv("CERBERUS_COMMAND_TIMEOUT_SECONDS", "600")))
_MAX_TIMEOUT_SECONDS = max(_DEFAULT_TIMEOUT_SECONDS, int(os.getenv("CERBERUS_COMMAND_TIMEOUT_MAX", "3600")))
_MAX_OUTPUT_CHARS = 50_000
_MAX_LINE_CHARS = 4_000
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
_RESTRICTED_PATHS = {
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/master.passwd",
    "/windows/system32/config/sam",
    "/windows/system32/config/security",
}
_PASSWD_LINE_RE = re.compile(r"^([^:]+):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*)$", re.MULTILINE)
_ENV_SECRET_KEY_RE = re.compile(
    r"(KEY|TOKEN|SECRET|PASSWORD|PASS|CREDENTIAL|AWS_|AZURE_|GCP_|GOOGLE_|OPENAI_|ANTHROPIC_)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SemanticError:
    code: str
    message: str
    retryable: bool
    category: str


@dataclass(frozen=True)
class CommandResult:
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
    stdout_truncated: bool
    stderr_truncated: bool
    output_limit_chars: int
    error: Optional[Dict[str, Any]]


class PathGuard:
    """Command path policy for workspace-safe execution."""

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

    @staticmethod
    def _has_write_intent(argv: Sequence[str]) -> bool:
        exe = Path(argv[0]).name.lower()
        if exe in _WRITE_COMMANDS:
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
            try:
                roots.add(Path(env_tmp).expanduser().resolve())
            except Exception:
                pass
        return sorted(roots)


class CerberusLinuxCommandTool:
    """Async shell execution proxy with boundary and redaction controls."""

    def __init__(self) -> None:
        self._workspace = get_project_space().ensure_initialized().resolve()
        self._secure = SecureSubprocess(workspace_root=self._workspace)
        self._logger = get_cerberus_logger()
        self._audit_log = (self._workspace / ".cerberus" / "audit" / "linux_command_replay.jsonl").resolve()
        self._audit_log.parent.mkdir(parents=True, exist_ok=True)
        self._guard = PathGuard(self._workspace)

    async def execute(self, *, command: str, timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS) -> Dict[str, Any]:
        command = (command or "").strip()
        if not command:
            return self._error(
                SemanticError(
                    code="empty_command",
                    message="No command provided.",
                    retryable=False,
                    category="validation",
                )
            )

        guardrail_error = validate_command_guardrails(command)
        if guardrail_error:
            return self._error(
                SemanticError(
                    code="guardrail_blocked",
                    message=guardrail_error,
                    retryable=False,
                    category="policy",
                )
            )

        try:
            argv = shlex.split(command, posix=True)
        except ValueError as exc:
            return self._error(
                SemanticError(
                    code="invalid_syntax",
                    message=f"Unable to parse command tokens: {exc}",
                    retryable=False,
                    category="validation",
                )
            )

        if not argv:
            return self._error(
                SemanticError(
                    code="empty_command",
                    message="No executable token found.",
                    retryable=False,
                    category="validation",
                )
            )

        if not self._resolve_executable(argv[0]):
            return self._error(
                SemanticError(
                    code="command_not_found",
                    message=f"Command not found: {argv[0]}",
                    retryable=False,
                    category="dependency",
                )
            )

        try:
            self._guard.validate_command(argv)
        except PermissionError as exc:
            message = str(exc)
            code = "restricted_path" if "Restricted path" in message else "boundary_violation"
            category = "policy" if code == "restricted_path" else "sandbox"
            return self._error(
                SemanticError(
                    code=code,
                    message=message,
                    retryable=False,
                    category=category,
                )
            )

        timeout_seconds = max(1, min(int(timeout_seconds), _MAX_TIMEOUT_SECONDS))
        started_at = datetime.now(tz=UTC)

        clean_env, redactions = self._secure.build_clean_environment()
        runtime_base = self._scrub_environment(clean_env)
        with CLI_UTILS.managed_env_context(base_env=runtime_base) as runtime_env:
            process_result = await run_streaming_subprocess(
                argv=argv,
                cwd=str(self._workspace),
                env=runtime_env,
                timeout_seconds=timeout_seconds,
                redactor=lambda text: self._redact_output(self._secure.redact_text(text, redactions)),
                stdout_mode="line",
                stderr_mode="line",
                max_output_chars=_MAX_OUTPUT_CHARS,
                max_line_chars=_MAX_LINE_CHARS,
                timeout_message="Execution timed out after policy limit.",
            )

        ended_at = datetime.now(tz=UTC)
        exit_code = process_result.exit_code
        stdout_text = process_result.stdout
        stderr_text = process_result.stderr
        timed_out = process_result.timed_out

        semantic = self._translate_exit_error(exit_code=exit_code, stderr=stderr_text, timed_out=timed_out)
        payload = CommandResult(
            ok=semantic is None,
            command=command,
            argv=list(argv),
            cwd=str(self._workspace),
            started_at=started_at.isoformat(),
            ended_at=ended_at.isoformat(),
            exit_code=exit_code,
            timed_out=timed_out,
            stdout=sanitize_tool_output(command, stdout_text),
            stderr=sanitize_tool_output(command, stderr_text),
            stdout_truncated=len(stdout_text) >= _MAX_OUTPUT_CHARS,
            stderr_truncated=len(stderr_text) >= _MAX_OUTPUT_CHARS,
            output_limit_chars=_MAX_OUTPUT_CHARS,
            error=asdict(semantic) if semantic else None,
        )

        await self._log_replay(payload)
        return clean_data(asdict(payload))

    def _scrub_environment(self, base_env: Dict[str, str]) -> Dict[str, str]:
        clean: Dict[str, str] = {}
        for key, value in base_env.items():
            if not value:
                continue
            if key in {"HISTFILE", "HISTSIZE", "HISTCONTROL", "PYTHONPATH"}:
                continue
            if _ENV_SECRET_KEY_RE.search(key):
                continue
            if key in {"HOME", "USER", "LOGNAME"}:
                continue
            clean[key] = value

        clean["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
        clean["WORKSPACE_ROOT"] = str(self._workspace)
        return clean

    @staticmethod
    def _resolve_executable(executable: str) -> bool:
        candidate = Path(executable)
        if candidate.is_absolute() and candidate.exists() and candidate.is_file():
            return True
        from shutil import which

        return which(executable) is not None

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
        return redacted

    def _translate_exit_error(self, *, exit_code: Optional[int], stderr: str, timed_out: bool) -> Optional[SemanticError]:
        if timed_out:
            return SemanticError(
                code="timeout",
                message="Command exceeded execution timeout and was terminated.",
                retryable=True,
                category="watchdog",
            )
        if exit_code in (None, 0):
            return None
        if exit_code == 127:
            return SemanticError(
                code="command_not_found",
                message="The command executable was not found on PATH.",
                retryable=False,
                category="dependency",
            )
        if exit_code == 13 or "permission denied" in stderr.lower():
            return SemanticError(
                code="permission_denied",
                message="Permission denied while executing command or reading target resource.",
                retryable=False,
                category="authorization",
            )
        return SemanticError(
            code="command_failed",
            message=f"Command exited with status {exit_code}.",
            retryable=False,
            category="execution",
        )

    async def _log_replay(self, result: CommandResult) -> None:
        row = {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "command": result.command,
            "argv": result.argv,
            "user_context": {
                "agent_id": self._resolve_agent_id(),
                "cwd": result.cwd,
            },
            "exit_status": result.exit_code,
            "timed_out": result.timed_out,
        }

        line = json.dumps(clean_data(row), ensure_ascii=True) + "\n"
        await asyncio.to_thread(self._append_line, self._audit_log, line)
        if self._logger is not None:
            try:
                self._logger.audit(
                    "linux command replay logged",
                    actor="generic_linux_command",
                    data=clean_data(row),
                    tags=["linux_command", "replay"],
                )
            except Exception:
                pass

    @staticmethod
    def _append_line(path: Path, line: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line)

    @staticmethod
    def _resolve_agent_id() -> str:
        for key in ("CERBERUS_AGENT_ID", "AGENT_ID", "CERBERUS_AGENT", "CERBERUS_AGENT_TYPE"):
            value = os.getenv(key, "").strip()
            if value:
                return value
        return "unknown-agent"

    @staticmethod
    def _error(error: SemanticError) -> Dict[str, Any]:
        return clean_data(
            {
                "ok": False,
                "error": {
                    "code": error.code,
                    "message": error.message,
                    "retryable": error.retryable,
                    "category": error.category,
                },
            }
        )


CerebroLinuxCommandTool = CerberusLinuxCommandTool
LINUX_COMMAND_TOOL = CerberusLinuxCommandTool()


def _sanitize_session_id(raw: Any) -> Optional[str]:
    try:
        if raw is None or isinstance(raw, bool):
            return None
        if isinstance(raw, dict):
            if not raw:
                return None
            for key in ("session_id", "session", "id", "sid", "name"):
                if key in raw and raw[key] is not None:
                    return _sanitize_session_id(raw[key])
            if len(raw) == 1:
                return _sanitize_session_id(next(iter(raw.values())))
            return None
        if isinstance(raw, (list, tuple)):
            if not raw:
                return None
            return _sanitize_session_id(raw[0])
        if isinstance(raw, (int, float)):
            return str(raw)

        text = str(raw).strip()
        while len(text) >= 2 and ((text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'"))):
            text = text[1:-1].strip()

        if not text:
            return None

        if (text.startswith("{") and text.endswith("}")) or (text.startswith("[") and text.endswith("]")):
            try:
                return _sanitize_session_id(json.loads(text))
            except Exception:
                match = re.search(r'"(session_id|id|session|sid|name)"\s*:\s*"([^"]+)"', text)
                if match:
                    return _sanitize_session_id(match.group(2))
                if text in ("{}", "[]"):
                    return None

        lowered = text.lower()
        if lowered in {"none", "null", "nil", "undefined"}:
            return None
        if re.fullmatch(r"[\{\}\[\]\s]*", text):
            return None
        return text
    except Exception:
        return None


def _looks_interactive(command: str) -> bool:
    first = command.strip().split(" ", 1)[0].lower()
    interactive_bins = {
        "bash", "sh", "zsh", "fish", "python", "ipython", "ptpython", "node", "ruby", "irb",
        "psql", "mysql", "sqlite3", "mongo", "redis-cli", "ftp", "sftp", "telnet", "ssh",
        "nc", "ncat", "socat", "gdb", "lldb", "r2", "radare2", "tshark", "tcpdump", "tail",
        "journalctl", "watch", "less", "more",
    }
    if first in interactive_bins:
        return True
    lowered = command.lower()
    return " -i" in lowered or " -it" in lowered or "tail -f" in lowered or "journalctl -f" in lowered or "watch " in lowered


def _format_environment_info() -> str:
    lines: List[str] = []

    try:
        from cerberus.cli import ctf_global  # type: ignore[import-untyped]

        if ctf_global and hasattr(ctf_global, "get_shell"):
            lines.append("CTF Environment: Active")
        else:
            lines.append("CTF Environment: Not available")
    except Exception:
        lines.append("CTF Environment: Not available")

    active_container = os.getenv("CERBERUS_ACTIVE_CONTAINER", "").strip() or os.getenv("CERBERUS_ACTIVE_CONTAINER", "").strip()
    lines.append(f"Container: {active_container[:12]}" if active_container else "Container: Not active")

    ssh_user = os.getenv("SSH_USER", "").strip()
    ssh_host = os.getenv("SSH_HOST", "").strip()
    lines.append(f"SSH: {ssh_user}@{ssh_host}" if ssh_user and ssh_host else "SSH: Not configured")

    try:
        lines.append(f"Workspace: {get_project_space().ensure_initialized().resolve()}")
    except Exception:
        lines.append("Workspace: Unknown")

    return "Current Environment:\n" + "\n".join(lines)


def _format_command_response(command: str, payload: Dict[str, Any]) -> str:
    if not payload.get("ok"):
        error = payload.get("error") or {}
        return sanitize_tool_output(command, str(error.get("message", "Execution failed")))
    stdout = str(payload.get("stdout", "") or "").strip()
    stderr = str(payload.get("stderr", "") or "").strip()
    if stdout and stderr:
        return sanitize_tool_output(command, f"{stdout}\n{stderr}".strip())
    if stdout:
        return sanitize_tool_output(command, stdout)
    if stderr:
        return sanitize_tool_output(command, stderr)
    exit_code = payload.get("exit_code")
    if exit_code not in {None, 0}:
        return sanitize_tool_output(command, f"Command exited with code {exit_code}")
    return ""


@function_tool(strict_mode=False)
async def generic_linux_command(command: str = "", interactive: bool = False, session_id: Optional[str] = None, timeout_seconds: Optional[int] = None) -> str:
    normalized_session_id = _sanitize_session_id(session_id) if session_id is not None else None
    cmd_lower = command.strip().lower()

    if cmd_lower.startswith("output "):
        return get_session_output(command.split(None, 1)[1], clear=False, stdout=True)
    if cmd_lower.startswith("kill "):
        return terminate_session(command.split(None, 1)[1])
    if cmd_lower in ("sessions", "session list", "session ls", "list sessions"):
        sessions = list_shell_sessions()
        if not sessions:
            return "No active sessions"
        lines = ["Active sessions:"]
        for session in sessions:
            friendly_id = session.get("friendly_id") or ""
            prefix = (friendly_id + " ") if friendly_id else ""
            lines.append(
                f"{prefix}({session['session_id'][:8]}) cmd='{session['command']}' last={session['last_activity']} running={session['running']}"
            )
        return "\n".join(lines)
    if cmd_lower.startswith("status "):
        output = get_session_output(command.split(None, 1)[1], clear=False, stdout=False)
        return output if output else "No new output"

    if command.strip().startswith("session"):
        parts = command.split()
        action: Optional[str] = parts[1] if len(parts) > 1 else None
        argument: Optional[str] = parts[2] if len(parts) > 2 else None

        if normalized_session_id and (action is None or action not in {"list", "output", "kill", "status"}):
            if normalized_session_id.startswith("output "):
                action, argument = "output", normalized_session_id.split(" ", 1)[1]
            elif normalized_session_id.startswith("kill "):
                action, argument = "kill", normalized_session_id.split(" ", 1)[1]
            elif normalized_session_id.startswith("status "):
                action, argument = "status", normalized_session_id.split(" ", 1)[1]
            else:
                action, argument = "status", normalized_session_id

        if action in (None, "list"):
            sessions = list_shell_sessions()
            if not sessions:
                return "No active sessions"
            lines = ["Active sessions:"]
            for session in sessions:
                friendly_id = session.get("friendly_id") or ""
                prefix = (friendly_id + " ") if friendly_id else ""
                lines.append(
                    f"{prefix}({session['session_id'][:8]}) cmd='{session['command']}' last={session['last_activity']} running={session['running']}"
                )
            return "\n".join(lines)
        if action == "output" and argument:
            return get_session_output(argument, clear=False, stdout=True)
        if action == "kill" and argument:
            return terminate_session(argument)
        if action == "status" and argument:
            output = get_session_output(argument, clear=False, stdout=False)
            return output if output else f"No new output for session {argument}"
        return "Usage: session list|output <id>|status <id>|kill <id>"

    if command.strip() in {"env info", "environment info"}:
        return _format_environment_info()

    if not command.strip():
        return "Error: No command provided"

    guardrail_error = validate_command_guardrails(command)
    if guardrail_error:
        return guardrail_error

    timeout_value = _DEFAULT_TIMEOUT_SECONDS if timeout_seconds is None else int(timeout_seconds)
    if normalized_session_id and timeout_seconds is None:
        timeout_value = min(timeout_value, 10)

    stream = os.getenv("CERBERUS_STREAM", "true").lower() != "false"
    call_id = uuid.uuid4().hex[:8]

    resolved_session = _resolve_session_id(normalized_session_id) if normalized_session_id else None
    session_exists = resolved_session is not None and resolved_session in ACTIVE_SESSIONS
    if session_exists:
        normalized_session_id = resolved_session

    if normalized_session_id:
        result = run_command(
            command,
            ctf=None,
            stdout=False,
            async_mode=True,
            session_id=normalized_session_id,
            timeout=timeout_value,
            stream=stream,
            call_id=call_id,
            tool_name="generic_linux_command",
        )
        if isinstance(result, str) and result in {"Input sent to session", "Input sent to CTF session"}:
            latest_output = ""
            for _ in range(4):
                session_output = get_session_output(normalized_session_id, clear=True, stdout=True)
                if session_output and "not found" not in session_output.lower():
                    latest_output = session_output
                    if command in session_output:
                        result = session_output
                        break
                await asyncio.sleep(0.05)
            else:
                if latest_output:
                    result = latest_output
    elif interactive and _looks_interactive(command):
        result = run_command(
            command,
            ctf=None,
            stdout=False,
            async_mode=True,
            session_id=None,
            timeout=timeout_value,
            stream=stream,
            call_id=call_id,
            tool_name="generic_linux_command",
        )
    else:
        result = await run_command_async(
            command,
            ctf=None,
            stdout=False,
            async_mode=False,
            session_id=None,
            timeout=timeout_value,
            stream=stream,
            call_id=call_id,
            tool_name="generic_linux_command",
        )
        return sanitize_tool_output(command, result)

    if isinstance(result, str):
        if result.startswith("Started async session "):
            started_session_id = result.removeprefix("Started async session ").strip()
            for session in list_shell_sessions():
                if session.get("session_id") == started_session_id and session.get("friendly_id"):
                    result = f"Started async session {session['friendly_id']}"
                    break
        return sanitize_tool_output(command, result)
    return str(result)


@function_tool
def null_tool() -> str:
    return "Null tool"


__all__ = [
    "SemanticError",
    "PathGuard",
    "CerberusLinuxCommandTool",
    "CerebroLinuxCommandTool",
    "LINUX_COMMAND_TOOL",
    "generic_linux_command",
    "null_tool",
    "run_command",
    "run_command_async",
]
