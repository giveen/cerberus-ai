"""Hardened CLI execution gateway for Cerberus AI."""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import inspect
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import threading
import time
from typing import Any, Awaitable, Callable, Dict, Generator, Iterable, List, Mapping, Optional, Sequence

from cerberus.memory.logic import clean_data
from cerberus.repl.commands.config import CONFIG_STORE, _is_secret, _mask
from cerberus.repl.commands.env import ENV_AUDITOR
from cerberus.repl.commands.shell import SecureSubprocess
from cerberus.repl.ui.logging import get_cerberus_logger
from cerberus.sdk.agents import function_tool
from cerberus.tools import validation
from cerberus.tools.workspace import get_project_space
from cerberus.utils.process_handler import run_streaming_subprocess


_ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
_PATH_TOKEN_RE = re.compile(r"(^[.~\/]|[\\/])")
_SECRET_ENV_HINT_RE = re.compile(
    r"(KEY|TOKEN|SECRET|PASSWORD|PASS|CREDENTIAL|PRIVATE|AWS_|AZURE_|GCP_|GOOGLE_|OPENAI_|ANTHROPIC_)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CommandOutput:
    stdout: str
    stderr: str
    truncated_stdout: bool
    truncated_stderr: bool


@dataclass(frozen=True)
class CommandTelemetry:
    agent_id: str
    timestamp: str
    command_redacted: str
    duration_ms: int
    exit_code: Optional[int]


@dataclass(frozen=True)
class CommandExecutionRecord:
    ok: bool
    command: str
    argv: List[str]
    cwd: str
    timeout_seconds: int
    timed_out: bool
    output: CommandOutput
    telemetry: CommandTelemetry


class CerberusCLIUtils:
    """Managed command execution with redaction, sandboxing, and telemetry."""

    TELEMETRY_FILE = Path(".cerberus/audit/cli_execution.jsonl")
    DEFAULT_TIMEOUT_SECONDS = 30

    def __init__(self) -> None:
        self._workspace_root = get_project_space().ensure_initialized().resolve()
        self._secure_subprocess = SecureSubprocess(workspace_root=self._workspace_root)
        self._logger = get_cerberus_logger()

    async def execute_command(
        self,
        command: str,
        *,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        cwd: Optional[str] = None,
        path_hints: Optional[Sequence[str]] = None,
        max_output_chars: int = 12000,
        head_chars: int = 5000,
        tail_chars: int = 3000,
        stream_callback: Optional[Callable[[str, str], Awaitable[None] | None]] = None,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        guardrail = validation.validate_command_guardrails(command)
        if guardrail:
            return {
                "ok": False,
                "error": {
                    "code": "guardrail_blocked",
                    "message": guardrail,
                },
            }

        timeout_seconds = max(1, int(timeout_seconds))
        requested_cwd = self._secure_subprocess.resolve_cwd(cwd)
        self._secure_subprocess.enforce_denylist(command)

        argv = self._command_to_argv(command)
        if not argv:
            return {
                "ok": False,
                "error": {
                    "code": "empty_command",
                    "message": "No executable token found in command.",
                },
            }

        argv = self._normalize_executable(argv)
        for hinted in (path_hints or []):
            _ = self.resolve_safe_path(hinted)
        for token in argv[1:]:
            if self._looks_like_path(token):
                self.resolve_safe_path(token)

        started = time.perf_counter()
        clean_env, redaction_map = self._secure_subprocess.build_clean_environment()

        with self.managed_env_context(base_env=clean_env) as runtime_env:
            def _redact(text: str) -> str:
                masked = self._secure_subprocess.redact_text(text, redaction_map)
                return self.strip_ansi(masked)

            async def _emit_stream(channel: str, text: str) -> None:
                if stream_callback is None:
                    return
                payload = validation.sanitize_tool_output(command, text.rstrip("\n"))
                if not payload:
                    return
                result = stream_callback(channel, payload)
                if inspect.isawaitable(result):
                    await result

            process_result = await run_streaming_subprocess(
                argv=argv,
                cwd=str(requested_cwd),
                env=runtime_env,
                timeout_seconds=timeout_seconds,
                redactor=_redact,
                event_callback=_emit_stream if stream_callback is not None else None,
                session_id=session_id,
                stdout_mode="line",
                stderr_mode="line",
                max_output_chars=max_output_chars,
                max_line_chars=max(head_chars, tail_chars, 256),
                timeout_message="Execution timed out by policy.",
            )

        exit_code = process_result.exit_code
        timed_out = process_result.timed_out
        stdout_clean = process_result.stdout
        stderr_clean = process_result.stderr

        stdout_trimmed, stdout_cut = self.truncate_output(
            stdout_clean,
            limit=max_output_chars,
            head=head_chars,
            tail=tail_chars,
        )
        stderr_trimmed, stderr_cut = self.truncate_output(
            stderr_clean,
            limit=max_output_chars,
            head=head_chars,
            tail=tail_chars,
        )

        duration_ms = int((time.perf_counter() - started) * 1000)
        telemetry = CommandTelemetry(
            agent_id=self._resolve_agent_id(),
            timestamp=datetime.now(tz=UTC).isoformat(),
            command_redacted=self._secure_subprocess.redact_text(command, redaction_map),
            duration_ms=max(0, duration_ms),
            exit_code=exit_code,
        )

        record = CommandExecutionRecord(
            ok=(not timed_out and (exit_code or 0) == 0),
            command=command,
            argv=argv,
            cwd=str(requested_cwd),
            timeout_seconds=timeout_seconds,
            timed_out=timed_out,
            output=CommandOutput(
                stdout=stdout_trimmed,
                stderr=stderr_trimmed,
                truncated_stdout=stdout_cut,
                truncated_stderr=stderr_cut,
            ),
            telemetry=telemetry,
        )
        payload = asdict(record)
        self._emit_telemetry(payload)
        payload["output"]["stdout"] = validation.sanitize_tool_output(command, payload["output"]["stdout"])
        payload["output"]["stderr"] = validation.sanitize_tool_output(command, payload["output"]["stderr"])
        return clean_data(payload)

    @contextmanager
    def managed_env_context(self, *, base_env: Optional[Mapping[str, str]] = None) -> Generator[Dict[str, str], None, None]:
        """Yield an isolated execution environment based on config and env policies."""
        source = dict(base_env or {})
        isolated: Dict[str, str] = {}

        safe_keys = {
            "PATH",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "TERM",
            "TMP",
            "TEMP",
            "TMPDIR",
            "WORKSPACE_ROOT",
            "CERBERUS_WORKSPACE",
            "CERBERUS_WORKSPACE_DIR",
        }

        for key, value in source.items():
            if not value:
                continue
            if key in {"HOME", "USER", "LOGNAME"}:
                continue
            if _SECRET_ENV_HINT_RE.search(key):
                continue
            if key in safe_keys or key.startswith("CERBERUS_"):
                isolated[key] = value

        for _idx, entry, value, _tier in CONFIG_STORE.all_entries():
            name = entry.name
            if not value or value == "Not set":
                continue
            if _is_secret(name):
                continue
            if name.startswith("CERBERUS_"):
                isolated[name] = value

        for item in ENV_AUDITOR.safe_view():
            if item.name in {"HOME", "USER", "LOGNAME"}:
                continue
            if _SECRET_ENV_HINT_RE.search(item.name):
                continue
            if item.safe and item.value and item.value != "HIDDEN_BY_POLICY":
                isolated[item.name] = item.value

        isolated["WORKSPACE_ROOT"] = str(self._workspace_root)
        yield isolated

    def resolve_safe_path(self, raw_path: str) -> str:
        candidate = Path(raw_path).expanduser()
        if not candidate.is_absolute():
            candidate = (self._workspace_root / candidate).resolve()
        else:
            candidate = candidate.resolve()

        try:
            candidate.relative_to(self._workspace_root)
        except ValueError as exc:
            raise ValueError(f"Path escapes workspace sandbox: {raw_path}") from exc
        return str(candidate)

    @staticmethod
    def strip_ansi(value: str) -> str:
        return _ANSI_RE.sub("", value or "")

    @staticmethod
    def truncate_output(value: str, *, limit: int, head: int, tail: int) -> tuple[str, bool]:
        text = value or ""
        if len(text) <= max(1, limit):
            return text, False

        h = max(64, min(head, len(text)))
        t = max(64, min(tail, len(text) - h))
        omitted = max(0, len(text) - h - t)
        clipped = (
            text[:h]
            + f"\n\n...[truncated {omitted} chars]...\n\n"
            + text[-t:]
        )
        return clipped, True

    def execute_command_sync(self, command: str, **kwargs: Any) -> Dict[str, Any]:
        """Sync bridge for tool systems that cannot await directly."""
        coro = self.execute_command(command, **kwargs)
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)

        holder: Dict[str, Any] = {}
        failure: Dict[str, BaseException] = {}

        def _runner() -> None:
            try:
                holder["result"] = asyncio.run(coro)
            except BaseException as exc:  # pragma: no cover
                failure["error"] = exc

        thread = threading.Thread(target=_runner, daemon=True)
        thread.start()
        thread.join()
        if "error" in failure:
            raise RuntimeError("execute_command_sync bridge failed") from failure["error"]
        return holder.get("result", {"ok": False, "error": {"code": "bridge_failure", "message": "No result."}})

    def _emit_telemetry(self, payload: Dict[str, Any]) -> None:
        safe_payload = clean_data(payload)
        if self._logger is not None:
            try:
                self._logger.audit(
                    "CLI command executed",
                    actor="cli_utils",
                    command=str(safe_payload.get("command", "")),
                    data={
                        "agent_id": safe_payload.get("telemetry", {}).get("agent_id"),
                        "duration_ms": safe_payload.get("telemetry", {}).get("duration_ms"),
                        "exit_code": safe_payload.get("telemetry", {}).get("exit_code"),
                        "timed_out": safe_payload.get("timed_out", False),
                        "cwd": safe_payload.get("cwd"),
                    },
                    tags=["cli", "gateway", "audit"],
                )
            except Exception:
                pass

        log_path = (self._workspace_root / self.TELEMETRY_FILE).resolve()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        forensic_row = {
            "agent_id": safe_payload.get("telemetry", {}).get("agent_id"),
            "timestamp": safe_payload.get("telemetry", {}).get("timestamp"),
            "raw_command_redacted": safe_payload.get("telemetry", {}).get("command_redacted"),
            "duration_ms": safe_payload.get("telemetry", {}).get("duration_ms"),
            "exit_code": safe_payload.get("telemetry", {}).get("exit_code"),
            "timed_out": safe_payload.get("timed_out", False),
            "ok": safe_payload.get("ok", False),
            "cwd": safe_payload.get("cwd"),
        }
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(forensic_row, ensure_ascii=True, default=str) + "\n")

    @staticmethod
    def _resolve_agent_id() -> str:
        for key in ("CERBERUS_AGENT_ID", "AGENT_ID", "CERBERUS_AGENT", "CERBERUS_AGENT_TYPE"):
            val = os.getenv(key, "").strip()
            if val:
                return val
        return "unknown-agent"

    @staticmethod
    def _looks_like_path(token: str) -> bool:
        if not token:
            return False
        if token.startswith("-"):
            return False
        return bool(_PATH_TOKEN_RE.search(token))

    @staticmethod
    def _command_to_argv(command: str) -> List[str]:
        text = command.strip()
        if not text:
            return []
        if os.name == "nt":
            return list(shlex.split(text, posix=False))
        return list(shlex.split(text, posix=True))

    @staticmethod
    def _normalize_executable(argv: List[str]) -> List[str]:
        if not argv:
            return argv
        executable = argv[0]
        if Path(executable).is_absolute() or executable.startswith("."):
            return argv

        resolved = shutil.which(executable)
        if resolved:
            argv[0] = resolved
            return argv

        if os.name == "nt" and not executable.lower().endswith(".exe"):
            alt = shutil.which(executable + ".exe")
            if alt:
                argv[0] = alt
        return argv


CerebroCLIUtils = CerberusCLIUtils
CLI_UTILS = CerberusCLIUtils()


@function_tool
def execute_cli_command(command: str, timeout_seconds: int = 30) -> Dict[str, Any]:
    """Execute a CLI command via the hardened execution gateway."""
    return CLI_UTILS.execute_command_sync(command, timeout_seconds=timeout_seconds)


__all__ = ["CerberusCLIUtils", "CerebroCLIUtils", "execute_cli_command", "CLI_UTILS"]
