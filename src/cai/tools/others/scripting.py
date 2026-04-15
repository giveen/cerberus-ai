"""Hardened script lifecycle and execution tooling for Cerberus AI."""

from __future__ import annotations

import asyncio
import ast
from contextlib import suppress
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import re
import shutil
import sys
import threading
from typing import Any, Dict, List, Optional

from cai.memory.logic import clean_data
from cai.repl.commands.shell import SecureSubprocess
from cai.repl.ui.logging import get_cerebro_logger
from cai.sdk.agents import function_tool
from cai.tools.misc.cli_utils import CLI_UTILS
from cai.tools.workspace import get_project_space


_SCRIPT_LANGUAGES = {"bash", "python", "powershell"}
_SCRIPT_EXTENSIONS = {
    "bash": ".sh",
    "python": ".py",
    "powershell": ".ps1",
}

_SCRIPT_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,95}$")
_SECRET_PATTERN = re.compile(
    r"(?i)(password\s*[:=]\s*\S+|api[_-]?key\s*[:=]\s*\S+|secret\s*[:=]\s*\S+|token\s*[:=]\s*\S+)"
)
_ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")

_SUSPICIOUS_GENERIC: tuple[re.Pattern[str], ...] = (
    re.compile(r"(^|\s)rm\s+-rf\s+/(\s|$)", re.IGNORECASE),
    re.compile(r"(^|\s)mkfs(\.|\s|$)", re.IGNORECASE),
    re.compile(r"(^|\s)dd\s+if=/dev/(zero|null|random)", re.IGNORECASE),
    re.compile(r"(^|\s)chmod\s+-R\s+0{3}\s+/", re.IGNORECASE),
    re.compile(r"(^|\s)chown\s+-R\s+root:root\s+/", re.IGNORECASE),
    re.compile(r"(^|\s)shutdown(\s|$)", re.IGNORECASE),
    re.compile(r"(^|\s)reboot(\s|$)", re.IGNORECASE),
)


@dataclass(frozen=True)
class ScriptArtifact:
    name: str
    language: str
    path: str
    updated_at: str
    size_bytes: int


@dataclass(frozen=True)
class ScriptExecutionResult:
    ok: bool
    script_name: str
    language: str
    command: List[str]
    started_at: str
    ended_at: str
    duration_ms: int
    exit_code: Optional[int]
    timed_out: bool
    stdout: str
    stderr: str
    truncated_stdout: bool
    truncated_stderr: bool


class CerebroScriptingTool:
    """Managed script storage and guarded async execution."""

    DEFAULT_TIMEOUT_SECONDS = 60
    DEFAULT_CPU_SECONDS = 30
    DEFAULT_MEMORY_MB = 512
    DEFAULT_MAX_WRITE_MB = 64

    def __init__(self) -> None:
        self._workspace = get_project_space().ensure_initialized().resolve()
        self._scripts_dir = (self._workspace / "work" / "scripts").resolve()
        self._scripts_dir.mkdir(parents=True, exist_ok=True)

        self._secure_subprocess = SecureSubprocess(workspace_root=self._workspace)
        self._logger = get_cerebro_logger()

        self._loop = asyncio.new_event_loop()
        self._loop_thread = threading.Thread(target=self._loop_runner, daemon=True)
        self._loop_thread.start()

    def _loop_runner(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _run_coro(self, coro: Any, timeout: float = 120.0) -> Any:
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result(timeout=timeout)

    def create_script(self, name: str, code: str, language: str = "bash") -> Dict[str, Any]:
        try:
            language_norm = self._normalize_language(language)
            script_name = self._normalize_script_name(name)
            source = self._strip_markdown_fence(code).strip()
            if not source:
                return {"ok": False, "error": {"code": "empty_code", "message": "Script code cannot be empty."}}

            scan = self._scan_script(language_norm, source)
            if not scan["ok"]:
                return scan

            path = self._script_path(script_name, language_norm)
            if path.exists():
                self._backup_script(path)

            path.write_text(source + "\n", encoding="utf-8")
            if language_norm in {"bash", "powershell"}:
                with suppress(OSError):
                    current = path.stat().st_mode
                    path.chmod(current | 0o700)

            artifact = ScriptArtifact(
                name=script_name,
                language=language_norm,
                path=str(path),
                updated_at=datetime.now(tz=UTC).isoformat(),
                size_bytes=path.stat().st_size,
            )
            self._audit("Script created", {"name": script_name, "language": language_norm, "path": str(path)})
            return {"ok": True, "script": asdict(artifact)}
        except Exception as exc:
            return {"ok": False, "error": {"code": "create_failed", "message": str(exc)}}

    def list_scripts(self) -> Dict[str, Any]:
        artifacts: List[ScriptArtifact] = []
        for path in sorted(self._scripts_dir.glob("*")):
            if not path.is_file() or path.name.endswith(".bak"):
                continue
            language = self._language_from_path(path)
            if not language:
                continue
            stat = path.stat()
            artifacts.append(
                ScriptArtifact(
                    name=path.stem,
                    language=language,
                    path=str(path),
                    updated_at=datetime.fromtimestamp(stat.st_mtime, tz=UTC).isoformat(),
                    size_bytes=stat.st_size,
                )
            )
        return {"ok": True, "scripts": [asdict(item) for item in artifacts]}

    def execute_script(
        self,
        name: str,
        language: Optional[str] = None,
        args: str = "",
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        cpu_seconds: int = DEFAULT_CPU_SECONDS,
        memory_mb: int = DEFAULT_MEMORY_MB,
        max_write_mb: int = DEFAULT_MAX_WRITE_MB,
    ) -> Dict[str, Any]:
        try:
            return self._run_coro(
                self._execute_script_async(
                    name=name,
                    language=language,
                    args=args,
                    timeout_seconds=timeout_seconds,
                    cpu_seconds=cpu_seconds,
                    memory_mb=memory_mb,
                    max_write_mb=max_write_mb,
                )
            )
        except Exception as exc:
            return {"ok": False, "error": {"code": "execution_failed", "message": str(exc)}}

    async def _execute_script_async(
        self,
        *,
        name: str,
        language: Optional[str],
        args: str,
        timeout_seconds: int,
        cpu_seconds: int,
        memory_mb: int,
        max_write_mb: int,
    ) -> Dict[str, Any]:
        script_name = self._normalize_script_name(name)
        script_path = self._resolve_script(script_name, language)
        if not script_path:
            return {"ok": False, "error": {"code": "script_not_found", "message": f"Script not found: {script_name}"}}

        language_norm = self._language_from_path(script_path)
        if not language_norm:
            return {"ok": False, "error": {"code": "unknown_language", "message": "Unsupported script extension."}}

        source = script_path.read_text(encoding="utf-8", errors="replace")
        scan = self._scan_script(language_norm, source)
        if not scan["ok"]:
            return scan

        timeout_seconds = max(1, min(int(timeout_seconds), 3600))
        cpu_seconds = max(1, min(int(cpu_seconds), 1800))
        memory_mb = max(64, min(int(memory_mb), 4096))
        max_write_mb = max(8, min(int(max_write_mb), 1024))

        command = self._build_command(script_path, language_norm, args)
        self._secure_subprocess.enforce_denylist(" ".join(command))

        clean_env, redaction_map = self._secure_subprocess.build_clean_environment()
        with CLI_UTILS.managed_env_context(base_env=clean_env) as runtime_env:
            started_perf = asyncio.get_running_loop().time()
            started_at = datetime.now(tz=UTC).isoformat()

            preexec_fn = self._build_preexec(cpu_seconds=cpu_seconds, memory_mb=memory_mb, max_write_mb=max_write_mb)
            process = await asyncio.create_subprocess_exec(
                *command,
                cwd=str(self._workspace),
                env=runtime_env,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                preexec_fn=preexec_fn,
            )

            stdout_lines: List[str] = []
            stderr_lines: List[str] = []

            async def _stream(reader: asyncio.StreamReader, sink: List[str]) -> None:
                while True:
                    chunk = await reader.readline()
                    if not chunk:
                        break
                    line = chunk.decode("utf-8", errors="replace")
                    line = self._secure_subprocess.redact_text(line, redaction_map)
                    line = self._redact_dynamic_secrets(self._strip_ansi(line.rstrip("\r\n")))
                    sink.append(line)

            if process.stdout is None or process.stderr is None:
                return {"ok": False, "error": {"code": "stream_init_failed", "message": "Process stream unavailable."}}

            stream_tasks = [
                asyncio.create_task(_stream(process.stdout, stdout_lines)),
                asyncio.create_task(_stream(process.stderr, stderr_lines)),
            ]

            timed_out = False
            try:
                await asyncio.wait_for(process.wait(), timeout=float(timeout_seconds))
            except asyncio.TimeoutError:
                timed_out = True
                process.terminate()
                with suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(process.wait(), timeout=2.0)
                if process.returncode is None:
                    process.kill()
                    await process.wait()

            await asyncio.gather(*stream_tasks, return_exceptions=True)

            ended_at = datetime.now(tz=UTC).isoformat()
            duration_ms = int((asyncio.get_running_loop().time() - started_perf) * 1000)
            stdout_text, stdout_cut = self._truncate_output("\n".join(stdout_lines), limit=16000)
            stderr_text, stderr_cut = self._truncate_output("\n".join(stderr_lines), limit=12000)

            result = ScriptExecutionResult(
                ok=(not timed_out and (process.returncode or 0) == 0),
                script_name=script_name,
                language=language_norm,
                command=command,
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=max(0, duration_ms),
                exit_code=process.returncode,
                timed_out=timed_out,
                stdout=stdout_text,
                stderr=stderr_text,
                truncated_stdout=stdout_cut,
                truncated_stderr=stderr_cut,
            )

            payload = clean_data(asdict(result))
            self._audit(
                "Script executed",
                {
                    "name": script_name,
                    "language": language_norm,
                    "ok": payload.get("ok"),
                    "exit_code": payload.get("exit_code"),
                    "timed_out": payload.get("timed_out"),
                },
            )
            return payload

    def _scan_script(self, language: str, source: str) -> Dict[str, Any]:
        text = source or ""
        for pattern in _SUSPICIOUS_GENERIC:
            if pattern.search(text):
                return {
                    "ok": False,
                    "error": {
                        "code": "safety_scan_blocked",
                        "message": f"Script blocked by safety policy: {pattern.pattern}",
                    },
                }

        if re.search(r"(?i)/etc/(passwd|shadow)|/usr/(bin|sbin)|C:\\Windows\\System32", text):
            return {
                "ok": False,
                "error": {
                    "code": "safety_scan_blocked",
                    "message": "Script attempts system-level binary or credential store modification.",
                },
            }

        if language == "python":
            try:
                tree = ast.parse(text)
            except SyntaxError as exc:
                return {"ok": False, "error": {"code": "syntax_error", "message": str(exc)}}

            blocked_modules = {"subprocess", "ctypes"}
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.split(".")[0] in blocked_modules:
                            return {
                                "ok": False,
                                "error": {
                                    "code": "safety_scan_blocked",
                                    "message": f"Blocked python module import: {alias.name}",
                                },
                            }
                if isinstance(node, ast.ImportFrom) and node.module:
                    if node.module.split(".")[0] in blocked_modules:
                        return {
                            "ok": False,
                            "error": {
                                "code": "safety_scan_blocked",
                                "message": f"Blocked python module import: {node.module}",
                            },
                        }
            return {"ok": True}

        if language == "bash":
            try:
                compile(text, "<bash-script>", "exec")
            except Exception:
                # Bash syntax cannot be validated reliably via Python compile; continue with regex guardrails.
                pass
            return {"ok": True}

        if language == "powershell":
            if re.search(r"(?i)Set-ExecutionPolicy\s+Bypass", text):
                return {
                    "ok": False,
                    "error": {
                        "code": "safety_scan_blocked",
                        "message": "PowerShell execution policy bypass patterns are blocked.",
                    },
                }
            return {"ok": True}

        return {"ok": False, "error": {"code": "unsupported_language", "message": f"Unsupported language: {language}"}}

    def _resolve_script(self, name: str, language: Optional[str]) -> Optional[Path]:
        if language:
            lang = self._normalize_language(language)
            candidate = self._script_path(name, lang)
            return candidate if candidate.exists() else None
        for lang in ("python", "bash", "powershell"):
            candidate = self._script_path(name, lang)
            if candidate.exists():
                return candidate
        return None

    def _build_command(self, script_path: Path, language: str, args: str) -> List[str]:
        extra = [part for part in (args or "").split() if part]
        if language == "python":
            return [sys.executable, str(script_path), *extra]

        if language == "bash":
            if os.name == "nt":
                bash = shutil.which("bash")
                if not bash:
                    raise RuntimeError("Bash script execution requested on Windows but bash executable not found.")
                return [bash, str(script_path), *extra]
            return ["/bin/bash", str(script_path), *extra]

        if language == "powershell":
            if os.name == "nt":
                host = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
                if not host:
                    raise RuntimeError("PowerShell executable not found.")
                return [host, "-NoProfile", "-NonInteractive", "-File", str(script_path), *extra]
            host = shutil.which("pwsh")
            if not host:
                raise RuntimeError("PowerShell Core (pwsh) not found on this host.")
            return [host, "-NoProfile", "-NonInteractive", "-File", str(script_path), *extra]

        raise RuntimeError(f"Unsupported language for execution: {language}")

    def _script_path(self, name: str, language: str) -> Path:
        return (self._scripts_dir / f"{name}{_SCRIPT_EXTENSIONS[language]}").resolve()

    def _backup_script(self, path: Path) -> None:
        stamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
        backup = path.with_name(f"{path.name}.{stamp}.bak")
        shutil.copy2(path, backup)

    def _normalize_script_name(self, name: str) -> str:
        value = (name or "").strip()
        if not value:
            raise ValueError("Script name is required.")
        if not _SCRIPT_NAME_RE.fullmatch(value):
            raise ValueError("Invalid script name. Use [a-zA-Z0-9_.-] and start with alphanumeric.")
        return value

    @staticmethod
    def _normalize_language(language: str) -> str:
        value = (language or "").strip().lower()
        aliases = {"py": "python", "ps": "powershell", "ps1": "powershell", "sh": "bash"}
        value = aliases.get(value, value)
        if value not in _SCRIPT_LANGUAGES:
            raise ValueError(f"Unsupported language: {language}")
        return value

    def _language_from_path(self, path: Path) -> Optional[str]:
        suffix = path.suffix.lower()
        for language, ext in _SCRIPT_EXTENSIONS.items():
            if suffix == ext:
                return language
        return None

    @staticmethod
    def _strip_markdown_fence(code: str) -> str:
        text = code or ""
        match = re.search(r"^```(?:[a-zA-Z0-9_+-]+)?\s*(.*?)\s*```$", text, flags=re.DOTALL)
        if match:
            return match.group(1)
        return text

    @staticmethod
    def _strip_ansi(text: str) -> str:
        return _ANSI_RE.sub("", text or "")

    @staticmethod
    def _truncate_output(text: str, *, limit: int) -> tuple[str, bool]:
        content = text or ""
        if len(content) <= limit:
            return content, False
        head = int(limit * 0.6)
        tail = int(limit * 0.3)
        omitted = len(content) - head - tail
        return content[:head] + f"\n...[truncated {omitted} chars]...\n" + content[-tail:], True

    @staticmethod
    def _redact_dynamic_secrets(text: str) -> str:
        def _mask(match: re.Match[str]) -> str:
            token = match.group(0)
            if ":" in token:
                key, _sep, _value = token.partition(":")
                return f"{key}:[REDACTED]"
            key, _sep, _value = token.partition("=")
            return f"{key}=[REDACTED]"

        return _SECRET_PATTERN.sub(_mask, text or "")

    def _audit(self, message: str, data: Dict[str, Any]) -> None:
        if self._logger is None:
            return
        try:
            self._logger.audit(message, actor="scripting", data=clean_data(data), tags=["script", "automation"])
        except Exception:
            pass

    def _build_preexec(self, *, cpu_seconds: int, memory_mb: int, max_write_mb: int) -> Any:
        if os.name == "nt":
            return None

        def _apply_limits() -> None:
            import resource

            cpu = max(1, int(cpu_seconds))
            mem_bytes = max(64, int(memory_mb)) * 1024 * 1024
            file_bytes = max(8, int(max_write_mb)) * 1024 * 1024

            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
            resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
            resource.setrlimit(resource.RLIMIT_FSIZE, (file_bytes, file_bytes))

        return _apply_limits


SCRIPTING_TOOL = CerebroScriptingTool()


@function_tool
def create_script(name: str, code: str, language: str = "bash") -> Dict[str, Any]:
    """Create or update a script in workspace work/scripts with forensic backup-on-edit."""
    return SCRIPTING_TOOL.create_script(name=name, code=code, language=language)


@function_tool
def execute_script(
    name: str,
    language: str = "",
    args: str = "",
    timeout_seconds: int = 60,
    cpu_seconds: int = 30,
    memory_mb: int = 512,
    max_write_mb: int = 64,
) -> Dict[str, Any]:
    """Execute a managed script with safety scan, isolated env, redaction, and resource caps."""
    language_opt = language.strip() or None
    return SCRIPTING_TOOL.execute_script(
        name=name,
        language=language_opt,
        args=args,
        timeout_seconds=timeout_seconds,
        cpu_seconds=cpu_seconds,
        memory_mb=memory_mb,
        max_write_mb=max_write_mb,
    )


@function_tool
def list_scripts() -> Dict[str, Any]:
    """List managed script assets available in the active workspace."""
    return SCRIPTING_TOOL.list_scripts()


@function_tool
def scripting_tool(
    action: str = "list_scripts",
    name: str = "",
    code: str = "",
    language: str = "bash",
    args: str = "",
    timeout_seconds: int = 60,
    cpu_seconds: int = 30,
    memory_mb: int = 512,
    max_write_mb: int = 64,
    ctf: Any = None,
) -> Dict[str, Any]:
    """Compatibility multiplexer for script lifecycle operations.

    Supported actions: create_script, execute_script, list_scripts.
    """
    _ = ctf
    action_norm = (action or "").strip().lower()
    if action_norm == "create_script":
        return create_script(name=name, code=code, language=language)
    if action_norm == "execute_script":
        return execute_script(
            name=name,
            language=language,
            args=args,
            timeout_seconds=timeout_seconds,
            cpu_seconds=cpu_seconds,
            memory_mb=memory_mb,
            max_write_mb=max_write_mb,
        )
    if action_norm == "list_scripts":
        return list_scripts()
    return {
        "ok": False,
        "error": {
            "code": "unknown_action",
            "message": "Unsupported action. Use create_script, execute_script, or list_scripts.",
        },
    }


__all__ = [
    "CerebroScriptingTool",
    "SCRIPTING_TOOL",
    "create_script",
    "execute_script",
    "list_scripts",
    "scripting_tool",
]
