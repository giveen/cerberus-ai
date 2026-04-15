"""Hardened shell command for Cerebro REPL."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
import os
from pathlib import Path
import re
import shlex
import subprocess
import time
from typing import Any, Callable, Dict, Iterable, List, Literal, Optional

from pydantic import BaseModel, Field
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cerberus.memory import MemoryManager
from cerberus.memory.logic import clean
from cerberus.repl.commands.base import CommandError, FrameworkCommand, register_command
from cerberus.repl.commands.config import _is_secret, _mask
from cerberus.tools.workspace import get_project_space

console = Console()

_DEFAULT_TIMEOUT_SECONDS = max(30, int(os.getenv("CERBERUS_SHELL_TIMEOUT_SECONDS", os.getenv("CERBERUS_COMMAND_TIMEOUT_SECONDS", "600"))))
_MAX_CAPTURE_LINES = 1200
_MAX_MEMORY_LINES = 300


class ShellOptions(BaseModel):
    command: str
    timeout: int = Field(default=_DEFAULT_TIMEOUT_SECONDS, ge=1, le=3600)
    source: Literal["user", "agent"] = "user"
    cwd: Optional[str] = None
    shell: Literal["auto", "bash", "sh", "cmd", "powershell"] = "auto"


@dataclass
class StreamLine:
    stream: Literal["stdout", "stderr"]
    text: str
    at_ms: int


@dataclass
class SecureSubprocessResult:
    command: str
    wrapped_command: str
    cwd: Path
    started_at: datetime
    ended_at: datetime
    exit_code: Optional[int]
    timed_out: bool
    shell_runtime: str
    stdout_lines: List[str] = field(default_factory=list)
    stderr_lines: List[str] = field(default_factory=list)
    streamed_lines: List[StreamLine] = field(default_factory=list)

    @property
    def duration_ms(self) -> int:
        delta = self.ended_at - self.started_at
        return max(0, int(delta.total_seconds() * 1000))


class SecureSubprocess:
    """Execute shell commands with denylist, redaction, and timeout controls."""

    _SECRET_NAME_PATTERN = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|APIKEY|API_KEY)", re.IGNORECASE)
    _SUSPICIOUS_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        re.compile(r"\b(?:sk|rk)-[A-Za-z0-9]{16,}\b"),
    )

    _DENYLIST_PATTERNS: tuple[re.Pattern[str], ...] = (
        re.compile(r"(^|\s)rm\s+-rf\s+(/|~|\*)", re.IGNORECASE),
        re.compile(r"(^|\s)mkfs(\.|\s|$)", re.IGNORECASE),
        re.compile(r"(^|\s)dd\s+if=/dev/(zero|null|random)", re.IGNORECASE),
        re.compile(r"(^|\s)(shutdown|reboot|poweroff|halt|init\s+0)(\s|$)", re.IGNORECASE),
        re.compile(r":\(\)\s*\{\s*:\|:\s*&\s*\};:", re.IGNORECASE),
        re.compile(r"(^|\s)chattr\s+\+i\s+/", re.IGNORECASE),
        re.compile(r"(^|\s)chmod\s+-R\s+0{3}\s+/", re.IGNORECASE),
        re.compile(r"(^|\s)kill\s+-9\s+1(\s|$)", re.IGNORECASE),
        re.compile(r"(^|\s)(del|erase)\s+/f\s+/s\s+/q\s+[a-z]:\\", re.IGNORECASE),
        re.compile(r"(^|\s)format\s+[a-z]:", re.IGNORECASE),
        re.compile(r"(^|\s)bcdedit\s+/delete", re.IGNORECASE),
    )

    def __init__(self, *, workspace_root: Path) -> None:
        self._workspace_root = workspace_root.resolve()

    def enforce_denylist(self, command: str) -> None:
        normalized = command.strip()
        for pattern in self._DENYLIST_PATTERNS:
            if pattern.search(normalized):
                raise CommandError(
                    "Blocked by shell denylist policy. Command appears destructive or framework-compromising.",
                    command_name="/shell",
                )

    def resolve_cwd(self, requested_cwd: Optional[str]) -> Path:
        if not requested_cwd:
            return self._workspace_root

        candidate = Path(requested_cwd).expanduser()
        if not candidate.is_absolute():
            candidate = (self._workspace_root / candidate).resolve()
        else:
            candidate = candidate.resolve()

        if not candidate.exists() or not candidate.is_dir():
            raise CommandError(f"Invalid --cwd path: {candidate}", command_name="/shell", exit_code=2)

        # Keep shell execution constrained to workspace scope.
        try:
            candidate.relative_to(self._workspace_root)
        except ValueError as exc:
            raise CommandError(
                f"Shell cwd must remain inside workspace root: {self._workspace_root}",
                command_name="/shell",
                exit_code=2,
            ) from exc

        return candidate

    def build_clean_environment(self) -> tuple[Dict[str, str], Dict[str, str]]:
        source_env = dict(os.environ)
        clean_env: Dict[str, str] = {}
        redaction_map: Dict[str, str] = {}

        allowed_core = {
            "PATH",
            "HOME",
            "USER",
            "LOGNAME",
            "SHELL",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "TERM",
            "TMP",
            "TEMP",
            "TMPDIR",
            "PWD",
            "CERBERUS_WORKSPACE",
            "CERBERUS_WORKSPACE_DIR",
        }

        if os.name == "nt":
            allowed_core.update({"COMSPEC", "SYSTEMROOT", "WINDIR", "PATHEXT", "APPDATA", "LOCALAPPDATA"})

        for key, value in source_env.items():
            if value is None:
                continue

            is_secret_name = _is_secret(key) or bool(self._SECRET_NAME_PATTERN.search(key))
            looks_sensitive_value = any(pattern.search(value) for pattern in self._SUSPICIOUS_VALUE_PATTERNS)
            if is_secret_name or looks_sensitive_value:
                redaction_map[value] = _mask(key, value) if is_secret_name else "[REDACTED_SECRET]"
                continue

            if key in allowed_core or key.startswith("LC_") or key.startswith("CERBERUS_"):
                clean_env[key] = value

        clean_env["WORKSPACE_ROOT"] = str(self._workspace_root)
        if "PATH" not in clean_env and "PATH" in source_env:
            clean_env["PATH"] = source_env["PATH"]

        return clean_env, redaction_map

    def resolve_shell_runtime(self, shell_mode: str, command: str) -> tuple[str, Optional[str], str]:
        if os.name == "nt":
            if shell_mode == "powershell":
                wrapped = subprocess.list2cmdline(["powershell", "-NoProfile", "-NonInteractive", "-Command", command])
                return "powershell", None, wrapped
            if shell_mode in {"bash", "sh"}:
                raise CommandError(f"Shell mode '{shell_mode}' is not supported on Windows", command_name="/shell")
            return "cmd", None, command

        if shell_mode == "cmd":
            raise CommandError("Shell mode 'cmd' is only supported on Windows", command_name="/shell")
        if shell_mode == "powershell":
            wrapped = subprocess.list2cmdline(["pwsh", "-NoProfile", "-NonInteractive", "-Command", command])
            return "powershell", None, wrapped

        if shell_mode in {"auto", "bash"} and Path("/bin/bash").exists():
            return "bash", "/bin/bash", command

        return "sh", "/bin/sh", command

    def redact_text(self, text: str, redaction_map: Dict[str, str]) -> str:
        redacted = text
        for raw_value, replacement in sorted(redaction_map.items(), key=lambda item: len(item[0]), reverse=True):
            if raw_value:
                redacted = redacted.replace(raw_value, replacement)
        return clean(redacted)

    async def run(
        self,
        *,
        command: str,
        timeout_seconds: int,
        cwd: Path,
        shell_mode: str,
        on_line: Callable[[StreamLine], None],
    ) -> SecureSubprocessResult:
        self.enforce_denylist(command)
        clean_env, redaction_map = self.build_clean_environment()
        shell_runtime, executable, wrapped_command = self.resolve_shell_runtime(shell_mode, command)

        started_at = datetime.now(tz=UTC)
        start_perf = time.perf_counter()

        process = await asyncio.create_subprocess_shell(
            wrapped_command,
            cwd=str(cwd),
            env=clean_env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            executable=executable,
        )

        stdout_lines: List[str] = []
        stderr_lines: List[str] = []
        streamed_lines: List[StreamLine] = []

        async def _capture_stream(stream: asyncio.StreamReader, stream_name: Literal["stdout", "stderr"]) -> None:
            while True:
                chunk = await stream.readline()
                if not chunk:
                    break
                raw = chunk.decode("utf-8", errors="replace").rstrip("\r\n")
                redacted = self.redact_text(raw, redaction_map)
                stamp = int((time.perf_counter() - start_perf) * 1000)
                line = StreamLine(stream=stream_name, text=redacted, at_ms=stamp)

                if stream_name == "stdout":
                    if len(stdout_lines) < _MAX_CAPTURE_LINES:
                        stdout_lines.append(redacted)
                else:
                    if len(stderr_lines) < _MAX_CAPTURE_LINES:
                        stderr_lines.append(redacted)

                if len(streamed_lines) < (_MAX_CAPTURE_LINES * 2):
                    streamed_lines.append(line)

                on_line(line)

        if process.stdout is None or process.stderr is None:
            process.kill()
            await process.wait()
            raise CommandError("Shell subprocess streams were not initialized", command_name="/shell")

        stream_tasks = [
            asyncio.create_task(_capture_stream(process.stdout, "stdout")),
            asyncio.create_task(_capture_stream(process.stderr, "stderr")),
        ]

        timed_out = False
        try:
            await asyncio.wait_for(process.wait(), timeout=timeout_seconds)
        except asyncio.TimeoutError:
            timed_out = True
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=3)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
        finally:
            await asyncio.gather(*stream_tasks, return_exceptions=True)

        ended_at = datetime.now(tz=UTC)

        return SecureSubprocessResult(
            command=command,
            wrapped_command=wrapped_command,
            cwd=cwd,
            started_at=started_at,
            ended_at=ended_at,
            exit_code=process.returncode,
            timed_out=timed_out,
            shell_runtime=shell_runtime,
            stdout_lines=stdout_lines,
            stderr_lines=stderr_lines,
            streamed_lines=streamed_lines,
        )


class ShellCommand(FrameworkCommand):
    """Execute shell commands through a hardened async subprocess manager."""

    name = "/shell"
    description = "Execute sandboxed shell commands with timeout, redaction, and forensic logging"
    aliases = ["/s", "$"]

    @property
    def help(self) -> str:
        return (
            "/shell [--timeout <seconds>] [--source user|agent] [--cwd <path>] "
            "[--shell auto|bash|sh|cmd|powershell] <command>\n\n"
            "Examples:\n"
            "  /shell --timeout 20 nmap -sV 127.0.0.1\n"
            "  /shell --source agent --cwd scans ls -la\n\n"
            "Security policy:\n"
            "  - Destructive commands are blocked by denylist.\n"
            "  - Sensitive environment variables are removed before execution.\n"
            "  - stdout/stderr are redacted, streamed live, and recorded in workspace memory."
        )

    def sanitize_args(self, args: Optional[List[str]]) -> List[str]:
        if args is None:
            return []

        cleaned: List[str] = []
        for token in args:
            if "\x00" in token:
                raise CommandError("Arguments cannot contain null bytes", command_name=self.name, exit_code=2)
            cleaned.append(token.strip())
        return cleaned

    async def execute(self, args: List[str]) -> bool:
        if len(args) == 1 and args[0] in {"-h", "--help", "help"}:
            console.print(self.help)
            return True

        options = self._parse_options(args)
        workspace_root = get_project_space().ensure_initialized().resolve()
        manager = SecureSubprocess(workspace_root=workspace_root)
        manager.enforce_denylist(options.command)
        cwd = manager.resolve_cwd(options.cwd)

        source_style = "cyan" if options.source == "user" else "magenta"
        source_label = "USER" if options.source == "user" else "AGENT"
        console.print(
            Panel(
                f"[bold]{options.command}[/bold]\n"
                f"runtime={options.shell} timeout={options.timeout}s cwd={cwd}",
                title=f"[{source_style}]Secure Shell Invocation ({source_label})[/{source_style}]",
                border_style=source_style,
            )
        )

        stream_table = Table(show_header=True, header_style="bold")
        stream_table.add_column("ms", style="dim", width=8)
        stream_table.add_column("stream", style="white", width=8)
        stream_table.add_column("line", style="white")
        console.print(stream_table)

        def _on_line(line: StreamLine) -> None:
            stream_style = "green" if line.stream == "stdout" else "red"
            console.print(f"[{stream_style}]{line.at_ms:>6} {line.stream:<7} {line.text}[/{stream_style}]")

        result = await manager.run(
            command=options.command,
            timeout_seconds=options.timeout,
            cwd=cwd,
            shell_mode=options.shell,
            on_line=_on_line,
        )

        await self._record_memory(options=options, result=result)
        self._render_summary(options=options, result=result)

        if result.timed_out:
            return False
        return (result.exit_code or 0) == 0

    def _parse_options(self, args: List[str]) -> ShellOptions:
        timeout = _DEFAULT_TIMEOUT_SECONDS
        source: Literal["user", "agent"] = "user"
        cwd: Optional[str] = None
        shell_mode: Literal["auto", "bash", "sh", "cmd", "powershell"] = "auto"
        command_tokens: List[str] = []

        index = 0
        while index < len(args):
            token = args[index]
            if token == "--":
                command_tokens.extend(args[index + 1 :])
                break
            if token == "--timeout":
                index += 1
                if index >= len(args):
                    raise CommandError("--timeout requires a value", command_name=self.name, exit_code=2)
                try:
                    timeout = max(1, int(args[index]))
                except ValueError as exc:
                    raise CommandError("--timeout must be an integer", command_name=self.name, exit_code=2) from exc
                index += 1
                continue
            if token == "--source":
                index += 1
                if index >= len(args):
                    raise CommandError("--source requires a value", command_name=self.name, exit_code=2)
                candidate = args[index].strip().lower()
                if candidate not in {"user", "agent"}:
                    raise CommandError("--source must be 'user' or 'agent'", command_name=self.name, exit_code=2)
                source = candidate  # type: ignore[assignment]
                index += 1
                continue
            if token == "--cwd":
                index += 1
                if index >= len(args):
                    raise CommandError("--cwd requires a path", command_name=self.name, exit_code=2)
                cwd = args[index]
                index += 1
                continue
            if token == "--shell":
                index += 1
                if index >= len(args):
                    raise CommandError("--shell requires a value", command_name=self.name, exit_code=2)
                candidate_shell = args[index].strip().lower()
                if candidate_shell not in {"auto", "bash", "sh", "cmd", "powershell"}:
                    raise CommandError(
                        "--shell must be one of: auto, bash, sh, cmd, powershell",
                        command_name=self.name,
                        exit_code=2,
                    )
                shell_mode = candidate_shell  # type: ignore[assignment]
                index += 1
                continue
            if token.startswith("--"):
                raise CommandError(f"Unknown option: {token}", command_name=self.name, exit_code=2)

            command_tokens.extend(args[index:])
            break

        command = " ".join(command_tokens).strip()
        if not command:
            raise CommandError("No shell command specified", command_name=self.name, exit_code=2)

        return ShellOptions(command=command, timeout=timeout, source=source, cwd=cwd, shell=shell_mode)

    def _resolve_memory(self) -> MemoryManager:
        if isinstance(self.memory, MemoryManager):
            self.memory.initialize()
            return self.memory
        memory_manager = MemoryManager()
        memory_manager.initialize()
        return memory_manager

    async def _record_memory(self, *, options: ShellOptions, result: SecureSubprocessResult) -> None:
        memory = self._resolve_memory()

        def _trim(lines: Iterable[str]) -> List[str]:
            return list(lines)[:_MAX_MEMORY_LINES]

        payload: Dict[str, Any] = {
            "topic": "shell-execution",
            "finding": (
                f"Shell command '{options.command}' completed with exit_code={result.exit_code} "
                f"timed_out={result.timed_out} in {result.duration_ms}ms"
            ),
            "source": options.source,
            "tags": ["shell", options.source, result.shell_runtime],
            "artifacts": {
                "command": options.command,
                "wrapped_command": result.wrapped_command,
                "cwd": str(result.cwd),
                "started_at": result.started_at.isoformat(),
                "ended_at": result.ended_at.isoformat(),
                "duration_ms": result.duration_ms,
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
                "shell_runtime": result.shell_runtime,
                "stdout": _trim(result.stdout_lines),
                "stderr": _trim(result.stderr_lines),
            },
        }

        await asyncio.to_thread(memory.record, payload)

    def _render_summary(self, *, options: ShellOptions, result: SecureSubprocessResult) -> None:
        status_style = "green"
        status = "ok"
        if result.timed_out:
            status_style = "yellow"
            status = "timeout"
        elif (result.exit_code or 0) != 0:
            status_style = "red"
            status = "failed"

        summary = Table(title="Secure Shell Summary")
        summary.add_column("Field", style="cyan", no_wrap=True)
        summary.add_column("Value", style="white")
        summary.add_row("Source", options.source)
        summary.add_row("Status", f"[{status_style}]{status}[/{status_style}]")
        summary.add_row("Exit code", str(result.exit_code))
        summary.add_row("Timeout", f"{options.timeout}s")
        summary.add_row("Duration", f"{result.duration_ms} ms")
        summary.add_row("Shell", result.shell_runtime)
        summary.add_row("Workspace", str(result.cwd))
        summary.add_row("Stdout lines", str(len(result.stdout_lines)))
        summary.add_row("Stderr lines", str(len(result.stderr_lines)))
        console.print(summary)

        if result.timed_out:
            console.print("[yellow]Command timed out and was terminated by policy.[/yellow]")


SHELL_COMMAND_INSTANCE = ShellCommand()
register_command(SHELL_COMMAND_INSTANCE)
