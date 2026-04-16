"""Hardened multi-runtime execution controller for reconnaissance code snippets."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional

from cerberus.memory.logic import clean_data
from cerberus.repl.commands.config import CONFIG_STORE
from cerberus.repl.commands.shell import SecureSubprocess
from cerberus.repl.ui.logging import get_cerberus_logger
from cerberus.agents import function_tool
from cerberus.tools._lazy import LazyToolProxy
from cerberus.tools.misc.cli_utils import CLI_UTILS
from cerberus.tools.workspace import get_project_space


DANGEROUS_PATTERNS = {
    "python": [
        "os.system(",
        "subprocess.Popen(",
        "subprocess.run(",
        "__import__(",
        "eval(",
        "exec(",
    ],
    "bash": [
        "rm -rf /",
        "mkfs",
        "shutdown",
        "reboot",
        "chmod -R 000 /",
        "dd if=/dev/zero",
    ],
    "shell": [
        "rm -rf /",
        "mkfs",
        "shutdown",
        "reboot",
        "chmod -R 000 /",
        "dd if=/dev/zero",
    ],
    "powershell": [
        "Remove-Item -Recurse -Force C:\\",
        "Stop-Computer",
        "Restart-Computer",
        "Invoke-Expression",
    ],
}


@dataclass
class ExecutionRecord:
    execution_id: str
    language: str
    started_at: str
    ended_at: str
    duration_ms: int
    exit_code: Optional[int]
    timed_out: bool
    resource_constrained: bool
    output: str
    error: str
    guidance: str
    log_path: str


class CerebroExecTool:
    """Safe, audited, asynchronous snippet execution across runtimes."""

    MAX_RUNTIME_SECONDS = 10
    CPU_PERCENT_LIMIT = 20.0

    def __init__(self) -> None:
        self._workspace = get_project_space().ensure_initialized().resolve()
        self._exec_log_dir = (self._workspace / "work" / "execution_logs").resolve()
        self._exec_log_dir.mkdir(parents=True, exist_ok=True)

        self._secure_subprocess = SecureSubprocess(workspace_root=self._workspace)
        self._logger = get_cerberus_logger()

        self._loop = asyncio.new_event_loop()
        self._loop_thread = threading.Thread(target=self._run_loop, daemon=True)
        self._loop_thread.start()
        self._active: Dict[str, asyncio.subprocess.Process] = {}

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _run_coro(self, coro: Any, timeout: float = 180.0) -> Any:
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result(timeout=timeout)

    def execute(
        self,
        *,
        code: str,
        language: str = "python",
        filename: str = "snippet",
        timeout: int = 10,
        persist: bool = False,
    ) -> Dict[str, Any]:
        try:
            return self._run_coro(
                self._execute_async(
                    code=code,
                    language=language,
                    filename=filename,
                    timeout=timeout,
                    persist=persist,
                ),
                timeout=max(20.0, float(timeout) + 20.0),
            )
        except Exception as exc:
            return {"ok": False, "error": {"code": "execution_failed", "message": str(exc)}}

    def cancel(self, execution_id: str) -> Dict[str, Any]:
        process = self._active.get(execution_id)
        if not process:
            return {"ok": False, "error": {"code": "not_found", "message": f"No active execution {execution_id}"}}
        process.terminate()
        return {"ok": True, "execution_id": execution_id, "status": "termination_requested"}

    async def _execute_async(
        self,
        *,
        code: str,
        language: str,
        filename: str,
        timeout: int,
        persist: bool,
    ) -> Dict[str, Any]:
        if not code or not code.strip():
            return self._error("invalid_input", "No code provided")

        if len(code) > 250_000:
            return self._error("invalid_input", "Code snippet is too large")

        lang = self._normalize_language(language)
        if lang not in {"python", "bash", "shell", "powershell"}:
            return self._error("unsupported_language", f"Unsupported language: {language}")

        blocked = self._guardrail_scan(code, lang)
        if blocked:
            return self._error("guardrail_blocked", blocked)

        timeout = max(1, min(int(timeout), self.MAX_RUNTIME_SECONDS))
        execution_id = f"exec-{secrets.token_hex(6)}"
        started = datetime.now(tz=UTC)

        tmp_root = (self._workspace / ".cerberus" / "tmp").resolve()
        tmp_root.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix=f"cerberus_exec_{execution_id}_", dir=str(tmp_root)))
        script_path = scratch / self._script_name(filename, lang)
        script_path.write_text(code, encoding="utf-8")
        with suppress(OSError):
            script_path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

        argv = self._build_argv(lang, script_path)
        if not argv:
            self._secure_wipe_dir(scratch)
            return self._error("runtime_unavailable", f"No interpreter available for {lang}")

        command_preview = " ".join(argv)
        self._secure_subprocess.enforce_denylist(command_preview)
        clean_env, redactions = self._secure_subprocess.build_clean_environment()

        with CLI_UTILS.managed_env_context(base_env=clean_env) as runtime_env:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                cwd=str(scratch),
                env=runtime_env,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

        self._active[execution_id] = proc

        stdout_lines: List[str] = []
        stderr_lines: List[str] = []
        resource_constrained = False

        async def _stream_reader(reader: asyncio.StreamReader, sink: List[str]) -> None:
            while True:
                chunk = await reader.readline()
                if not chunk:
                    break
                line = chunk.decode("utf-8", errors="replace")
                red = self._secure_subprocess.redact_text(line, redactions)
                red = self._redact_output(red.rstrip("\r\n"))
                sink.append(red)

        if proc.stdout is None or proc.stderr is None:
            self._active.pop(execution_id, None)
            self._secure_wipe_dir(scratch)
            return self._error("process_error", "Process stream initialization failed")

        t_out = asyncio.create_task(_stream_reader(proc.stdout, stdout_lines))
        t_err = asyncio.create_task(_stream_reader(proc.stderr, stderr_lines))

        async def _heartbeat() -> None:
            nonlocal resource_constrained
            start_perf = time.perf_counter()
            hot_samples = 0
            while proc.returncode is None:
                await asyncio.sleep(0.35)
                elapsed = time.perf_counter() - start_perf
                if elapsed > self.MAX_RUNTIME_SECONDS:
                    resource_constrained = True
                    proc.terminate()
                    return
                cpu = await self._pid_cpu_percent(proc.pid)
                if elapsed < 1.0:
                    continue
                if cpu > self.CPU_PERCENT_LIMIT:
                    hot_samples += 1
                else:
                    hot_samples = 0
                if hot_samples >= 3:
                    resource_constrained = True
                    proc.terminate()
                    return

        heartbeat_task = asyncio.create_task(_heartbeat())
        timed_out = False
        try:
            await asyncio.wait_for(proc.wait(), timeout=float(timeout) + 0.5)
        except asyncio.TimeoutError:
            timed_out = True
            proc.terminate()
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(proc.wait(), timeout=1.5)
            if proc.returncode is None:
                proc.kill()
                await proc.wait()

        await asyncio.gather(t_out, t_err, return_exceptions=True)
        heartbeat_task.cancel()
        with suppress(asyncio.CancelledError, Exception):
            await heartbeat_task

        self._active.pop(execution_id, None)

        ended = datetime.now(tz=UTC)
        duration_ms = int((ended - started).total_seconds() * 1000)
        output = self._truncate("\n".join(stdout_lines), 20000)
        error = self._truncate("\n".join(stderr_lines), 12000)

        guidance = self._semantic_guidance(error=error, output=output, language=lang)
        record = ExecutionRecord(
            execution_id=execution_id,
            language=lang,
            started_at=started.isoformat(),
            ended_at=ended.isoformat(),
            duration_ms=max(0, duration_ms),
            exit_code=proc.returncode,
            timed_out=timed_out,
            resource_constrained=resource_constrained,
            output=output,
            error=error,
            guidance=guidance,
            log_path="",
        )

        log_path = self._write_execution_log(record=record, code=code)
        record.log_path = str(log_path)

        if not persist:
            self._secure_wipe_dir(scratch)

        payload = {
            "ok": (proc.returncode == 0 and not timed_out and not resource_constrained),
            "record": asdict(record),
        }
        if resource_constrained:
            payload["error"] = {"code": "resource_constraint", "message": "Execution terminated due to CPU/time constraints"}
        elif timed_out:
            payload["error"] = {"code": "timeout", "message": "Execution timed out"}
        elif proc.returncode != 0:
            payload["error"] = {"code": "runtime_error", "message": guidance or "Execution failed"}

        self._audit_event(payload)
        return clean_data(payload)

    async def _pid_cpu_percent(self, pid: int) -> float:
        ps = shutil.which("ps")
        if not ps:
            return 0.0
        proc = await asyncio.create_subprocess_exec(
            ps,
            "-p",
            str(pid),
            "-o",
            "%cpu=",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await proc.communicate()
        text = (out or b"").decode("utf-8", errors="replace").strip()
        try:
            return float(text.splitlines()[0].strip()) if text else 0.0
        except Exception:
            return 0.0

    def _write_execution_log(self, *, record: ExecutionRecord, code: str) -> Path:
        timestamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
        path = self._exec_log_dir / f"EXEC_{record.execution_id}_{timestamp}.json"
        payload = {
            "record": asdict(record),
            "snippet": code,
        }
        path.write_text(json.dumps(clean_data(payload), ensure_ascii=True, indent=2), encoding="utf-8")
        return path

    def _audit_event(self, payload: Dict[str, Any]) -> None:
        if self._logger is None:
            return
        try:
            rec = payload.get("record", {})
            self._logger.audit(
                "Code execution completed",
                actor="exec_code",
                data={
                    "execution_id": rec.get("execution_id"),
                    "language": rec.get("language"),
                    "duration_ms": rec.get("duration_ms"),
                    "exit_code": rec.get("exit_code"),
                    "resource_constrained": rec.get("resource_constrained"),
                },
                tags=["exec", "runtime"],
            )
        except Exception:
            pass

    def _guardrail_scan(self, code: str, language: str) -> str:
        unrestricted = self._is_unrestricted_mode()
        if unrestricted:
            return ""
        checks = DANGEROUS_PATTERNS.get(language, [])
        lowered = code.lower()
        for pattern in checks:
            if pattern.lower() in lowered:
                return f"Blocked by policy: detected dangerous pattern '{pattern}'"
        return ""

    def _is_unrestricted_mode(self) -> bool:
        for key in ("CERBERUS_EXPERT_MODE", "CERBERUS_UNRESTRICTED_MODE"):
            value = CONFIG_STORE.get(key)
            if value and value != "Not set" and value.strip().lower() in {"1", "true", "yes", "on"}:
                return True
            env = os.getenv(key, "").strip().lower()
            if env in {"1", "true", "yes", "on"}:
                return True
        return False

    @staticmethod
    def _normalize_language(language: str) -> str:
        value = (language or "python").strip().lower()
        alias = {"py": "python", "sh": "bash", "ps": "powershell", "pwsh": "powershell"}
        return alias.get(value, value)

    @staticmethod
    def _script_name(filename: str, language: str) -> str:
        safe = "".join(ch if ch.isalnum() or ch in "_-" else "_" for ch in (filename or "snippet"))[:48] or "snippet"
        suffix = {"python": ".py", "bash": ".sh", "shell": ".sh", "powershell": ".ps1"}.get(language, ".txt")
        return safe + suffix

    @staticmethod
    def _build_argv(language: str, script_path: Path) -> List[str]:
        if language == "python":
            py = shutil.which("python3") or shutil.which("python")
            return [py, str(script_path)] if py else []
        if language in {"bash", "shell"}:
            shell = shutil.which("bash") or shutil.which("sh")
            return [shell, str(script_path)] if shell else []
        if language == "powershell":
            if os.name == "nt":
                host = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
            else:
                host = shutil.which("pwsh")
            return [host, "-NoProfile", "-NonInteractive", "-File", str(script_path)] if host else []
        return []

    @staticmethod
    def _semantic_guidance(*, error: str, output: str, language: str) -> str:
        text = (error or "") + "\n" + (output or "")
        low = text.lower()
        if "syntaxerror" in low or "parseerror" in low:
            return f"{language} syntax issue detected. Check missing delimiters, indentation, and quote closure."
        if "permission denied" in low:
            return "Permission denied. Avoid privileged paths and use workspace-scoped files."
        if "module not found" in low or "importerror" in low:
            return "Missing dependency detected. Install/import required modules before execution."
        if "command not found" in low:
            return "Interpreter or command not available. Switch language/runtime or ensure tool is installed."
        if "resource constraint" in low:
            return "Execution exceeded resource policy. Reduce CPU-heavy loops or runtime duration."
        return "Execution failed. Review stderr and simplify the snippet into smaller test steps."

    @staticmethod
    def _redact_output(line: str) -> str:
        red = line
        patterns = [
            (r"(?i)(password\s*[=:]\s*)(\S+)", r"\1[REDACTED_SECRET]"),
            (r"(?i)(token\s*[=:]\s*)(\S+)", r"\1[REDACTED_SECRET]"),
            (r"(?i)(api[_-]?key\s*[=:]\s*)(\S+)", r"\1[REDACTED_SECRET]"),
            (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_PII]"),
        ]
        import re

        for pattern, repl in patterns:
            red = re.sub(pattern, repl, red)
        return red

    @staticmethod
    def _truncate(text: str, limit: int) -> str:
        if len(text) <= limit:
            return text
        head = int(limit * 0.65)
        tail = int(limit * 0.25)
        omitted = len(text) - head - tail
        return text[:head] + f"\n...[truncated {omitted} chars]...\n" + text[-tail:]

    @staticmethod
    def _secure_wipe_dir(path: Path) -> None:
        if not path.exists():
            return
        for child in path.rglob("*"):
            if child.is_file():
                with suppress(Exception):
                    size = child.stat().st_size
                    child.write_bytes(b"\x00" * min(size, 1024 * 1024))
        shutil.rmtree(path, ignore_errors=True)

    @staticmethod
    def _error(code: str, message: str) -> Dict[str, Any]:
        return {"ok": False, "error": {"code": code, "message": message}}


EXEC_TOOL = LazyToolProxy(CerebroExecTool)


@function_tool
async def execute_code(
    code: str = "",
    language: str = "python",
    filename: str = "exploit",
    timeout: int = 10,
    persist: bool = False,
) -> str:
    result = EXEC_TOOL.execute(code=code, language=language, filename=filename, timeout=timeout, persist=persist)
    if not result.get("ok"):
        err = result.get("error") or {}
        rec = result.get("record") or {}
        guidance = rec.get("guidance", "")
        msg = err.get("message", "Execution failed")
        if guidance:
            return f"Error: {msg}\nGuidance: {guidance}"
        return f"Error: {msg}"

    rec = result.get("record") or {}
    return (
        f"Execution ID: {rec.get('execution_id', '')}\n"
        f"Language: {rec.get('language', '')}\n"
        f"Duration(ms): {rec.get('duration_ms', 0)}\n"
        f"Output:\n{rec.get('output', '')}\n"
        f"Errors:\n{rec.get('error', '')}\n"
        f"Guidance: {rec.get('guidance', '')}\n"
        f"Evidence Log: {rec.get('log_path', '')}"
    )


__all__ = ["CerebroExecTool", "EXEC_TOOL", "execute_code"]
