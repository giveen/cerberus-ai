"""Hardened Python sandbox tool for Cerberus AI."""

from __future__ import annotations

import asyncio
import ast
import contextlib
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import io
import json
import multiprocessing as mp
import os
from pathlib import Path
import re
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import textwrap
import threading
import time
from typing import Any, Dict, Mapping, Optional

from pydantic import BaseModel, Field, ValidationError, field_validator

from cerberus.memory.logic import clean_data
from cerberus.repl.commands.config import CONFIG_STORE
from cerberus.repl.ui.logging import get_cerberus_logger
from cerberus.agents import function_tool
from cerberus.tools.workspace import get_project_space

try:
    import resource  # type: ignore
except Exception:
    resource = None


_DANGEROUS_PATTERNS = (
    re.compile(r"(?i)\b(pip|conda|apt-get|yum|poetry|uv)\b"),
    re.compile(r"(?i)__subclasses__\s*\("),
    re.compile(r"(?i)\bctypes\b"),
    re.compile(r"(?i)\bimportlib\b"),
    re.compile(r"(?i)\bmarshal\b"),
    re.compile(r"(?i)\bpickle\b"),
)


class CodeSubmission(BaseModel):
    code: str = Field(min_length=1, max_length=50000)
    timeout_seconds: int = Field(default=5, ge=1, le=5)
    memory_limit_mb: int = Field(default=128, ge=64, le=128)

    @field_validator("code")
    @classmethod
    def _validate_code(cls, value: str) -> str:
        normalized = value.replace("\r\n", "\n").strip()
        if not normalized:
            raise ValueError("Code snippet cannot be empty.")
        for pattern in _DANGEROUS_PATTERNS:
            if pattern.search(normalized):
                raise ValueError("Code snippet contains blocked payload markers.")
        return normalized


@dataclass(frozen=True)
class SandboxResult:
    ok: bool
    stdout: str
    stderr: str
    result_repr: str
    timed_out: bool
    error: Optional[str]
    duration_ms: int
    state_size: int
    script_path: str
    mode: str


def _child_execute(
    conn: Any,
    code: str,
    state: Mapping[str, Any],
    allowed_modules: Mapping[str, str],
    blocked_modules: set[str],
    memory_limit_mb: int,
) -> None:
    if resource is not None:
        try:
            bytes_limit = int(memory_limit_mb) * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (bytes_limit, bytes_limit))
        except Exception:
            pass

    safe_builtins = {
        "abs": abs,
        "all": all,
        "any": any,
        "bool": bool,
        "bytes": bytes,
        "callable": callable,
        "chr": chr,
        "dict": dict,
        "enumerate": enumerate,
        "filter": filter,
        "float": float,
        "format": format,
        "frozenset": frozenset,
        "hash": hash,
        "hex": hex,
        "int": int,
        "isinstance": isinstance,
        "issubclass": issubclass,
        "iter": iter,
        "len": len,
        "list": list,
        "map": map,
        "max": max,
        "min": min,
        "next": next,
        "object": object,
        "oct": oct,
        "ord": ord,
        "pow": pow,
        "print": print,
        "range": range,
        "repr": repr,
        "reversed": reversed,
        "round": round,
        "set": set,
        "slice": slice,
        "sorted": sorted,
        "str": str,
        "sum": sum,
        "tuple": tuple,
        "type": type,
        "zip": zip,
    }

    def _guarded_import(name: str, globals_dict: Any = None, locals_dict: Any = None, fromlist: Any = (), level: int = 0) -> Any:
        root = name.split(".", 1)[0]
        if root in blocked_modules:
            raise ImportError(f"Module '{root}' is blocked by sandbox policy")
        if root not in allowed_modules:
            raise ImportError(f"Module '{root}' is not allow-listed")
        return __import__(name, globals_dict, locals_dict, fromlist, level)

    safe_builtins["__import__"] = _guarded_import

    scope: Dict[str, Any] = dict(state)
    globals_dict = {
        "__builtins__": safe_builtins,
    }

    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    result_repr = ""

    try:
        module = ast.parse(code, mode="exec")
        if module.body and isinstance(module.body[-1], ast.Expr):
            expr = ast.Expression(module.body[-1].value)
            module.body = module.body[:-1]
            with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
                if module.body:
                    exec(compile(module, "<cerebro-sandbox>", "exec"), globals_dict, scope)  # nosec B102
                value = eval(compile(expr, "<cerebro-sandbox>", "eval"), globals_dict, scope)  # nosec B307
                result_repr = repr(value)
                scope["_"] = value
        else:
            with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
                exec(compile(module, "<cerebro-sandbox>", "exec"), globals_dict, scope)  # nosec B102

        clean_scope: Dict[str, Any] = {}
        for key, value in scope.items():
            if key.startswith("__"):
                continue
            if callable(value):
                continue
            if isinstance(value, (int, float, bool, str, list, dict, tuple, set, type(None))):
                clean_scope[key] = value
            else:
                clean_scope[key] = repr(value)

        conn.send(
            {
                "ok": True,
                "stdout": stdout_buf.getvalue(),
                "stderr": stderr_buf.getvalue(),
                "result_repr": result_repr,
                "state": clean_scope,
            }
        )
    except Exception as exc:  # pylint: disable=broad-except
        conn.send(
            {
                "ok": False,
                "stdout": stdout_buf.getvalue(),
                "stderr": stderr_buf.getvalue(),
                "error": f"{type(exc).__name__}: {exc}",
                "state": dict(state),
            }
        )
    finally:
        try:
            conn.close()
        except Exception:
            pass


class CerebroInterpreter:
    """Managed Python sandbox with stateful workspace session memory."""

    ALLOWED_MODULES = {
        "math": "stdlib",
        "statistics": "stdlib",
        "random": "stdlib",
        "datetime": "stdlib",
        "time": "stdlib",
        "json": "stdlib",
        "re": "stdlib",
        "collections": "stdlib",
        "itertools": "stdlib",
        "functools": "stdlib",
        "decimal": "stdlib",
        "fractions": "stdlib",
        "numpy": "datascience",
        "pandas": "datascience",
        "scapy": "datascience",
    }
    BLOCKED_MODULES = {
        "os",
        "sys",
        "subprocess",
        "socket",
        "pathlib",
        "shutil",
        "importlib",
        "ctypes",
        "builtins",
    }

    def __init__(self) -> None:
        self._workspace = get_project_space().ensure_initialized().resolve()
        self._scripts_dir = (self._workspace / "work" / "scripts").resolve()
        self._scripts_dir.mkdir(parents=True, exist_ok=True)
        self._session_state: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._logger = get_cerberus_logger()

    def execute(self, code: str, timeout_seconds: int = 5, memory_limit_mb: int = 128) -> Dict[str, Any]:
        try:
            request = CodeSubmission(code=code, timeout_seconds=timeout_seconds, memory_limit_mb=memory_limit_mb)
        except ValidationError as exc:
            return {
                "ok": False,
                "error": {
                    "code": "validation_error",
                    "message": self._sanitize_traceback(str(exc)),
                },
            }

        return self._run_sync(self.execute_async(request))

    async def execute_async(self, request: CodeSubmission) -> Dict[str, Any]:
        session_key = self._session_key()
        script_path = self._write_script(request.code)
        high_isolation = self._is_high_isolation_mode()

        with self._lock:
            state = dict(self._session_state.get(session_key, {}))

        started = time.perf_counter()
        if high_isolation:
            raw = await self._run_in_ephemeral_docker(
                code=request.code,
                state=state,
                timeout_seconds=request.timeout_seconds,
                memory_limit_mb=request.memory_limit_mb,
            )
            mode = "docker"
        else:
            raw = await asyncio.to_thread(
                self._run_in_local_process,
                request.code,
                state,
                request.timeout_seconds,
                request.memory_limit_mb,
            )
            mode = "local"

        duration_ms = max(0, int((time.perf_counter() - started) * 1000))
        next_state = raw.get("state", state)

        with self._lock:
            self._session_state[session_key] = dict(next_state)

        result = SandboxResult(
            ok=bool(raw.get("ok", False)),
            stdout=str(raw.get("stdout", "")),
            stderr=str(raw.get("stderr", "")),
            result_repr=str(raw.get("result_repr", "")),
            timed_out=bool(raw.get("timed_out", False)),
            error=self._sanitize_traceback(str(raw.get("error", ""))) if raw.get("error") else None,
            duration_ms=duration_ms,
            state_size=len(next_state),
            script_path=str(script_path),
            mode=mode,
        )

        payload = clean_data(asdict(result))
        self._audit_execution(payload=payload)
        return payload

    def _run_in_local_process(
        self,
        code: str,
        state: Mapping[str, Any],
        timeout_seconds: int,
        memory_limit_mb: int,
    ) -> Dict[str, Any]:
        main_mod = sys.modules.get("__main__")
        has_main_file = bool(getattr(main_mod, "__file__", None))
        if os.name == "nt":
            ctx_name = "spawn"
        else:
            ctx_name = "spawn" if has_main_file else "fork"
        ctx = mp.get_context(ctx_name)
        recv_conn, send_conn = ctx.Pipe(duplex=False)
        proc = ctx.Process(
            target=_child_execute,
            args=(
                send_conn,
                code,
                dict(state),
                self.ALLOWED_MODULES,
                self.BLOCKED_MODULES,
                memory_limit_mb,
            ),
        )

        proc.start()
        send_conn.close()
        proc.join(timeout=float(timeout_seconds))

        if proc.is_alive():
            proc.terminate()
            proc.join(1.0)
            recv_conn.close()
            return {
                "ok": False,
                "stdout": "",
                "stderr": "",
                "error": "Execution timed out by policy.",
                "timed_out": True,
                "state": dict(state),
            }

        if not recv_conn.poll(0.5):
            recv_conn.close()
            return {
                "ok": False,
                "stdout": "",
                "stderr": "",
                "error": "Sandbox process exited without a result payload.",
                "timed_out": False,
                "state": dict(state),
            }
        try:
            payload = dict(recv_conn.recv())
        except EOFError:
            recv_conn.close()
            return {
                "ok": False,
                "stdout": "",
                "stderr": "",
                "error": "Sandbox process closed channel unexpectedly.",
                "timed_out": False,
                "state": dict(state),
            }
        recv_conn.close()
        payload.setdefault("timed_out", False)
        return payload

    async def _run_in_ephemeral_docker(
        self,
        *,
        code: str,
        state: Mapping[str, Any],
        timeout_seconds: int,
        memory_limit_mb: int,
    ) -> Dict[str, Any]:
        docker_bin = shutil.which("docker")
        if not docker_bin:
            return {
                "ok": False,
                "stdout": "",
                "stderr": "",
                "error": "High isolation mode requested but docker is unavailable.",
                "timed_out": False,
                "state": dict(state),
            }

        image = os.getenv("CERBERUS_INTERPRETER_DOCKER_IMAGE", "python:3.12-slim")
        runtime_root = (self._workspace / ".cerberus" / "interpreter_runtime").resolve()
        runtime_root.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory(dir=str(runtime_root)) as tmp:
            tmp_path = Path(tmp)
            code_path = tmp_path / "snippet.py"
            state_path = tmp_path / "state.json"
            result_path = tmp_path / "result.json"
            runner_path = tmp_path / "runner.py"

            code_path.write_text(code, encoding="utf-8")
            state_path.write_text(json.dumps(clean_data(dict(state)), ensure_ascii=True), encoding="utf-8")
            runner_path.write_text(self._docker_runner_script(), encoding="utf-8")

            command = [
                docker_bin,
                "run",
                "--rm",
                "--network",
                "none",
                "--memory",
                f"{int(memory_limit_mb)}m",
                "-v",
                f"{tmp_path}:/sandbox",
                "-w",
                "/sandbox",
                image,
                "python",
                "runner.py",
            ]

            try:
                proc = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                raw_out, raw_err = await asyncio.wait_for(proc.communicate(), timeout=float(timeout_seconds))
            except asyncio.TimeoutError:
                return {
                    "ok": False,
                    "stdout": "",
                    "stderr": "",
                    "error": "Execution timed out by policy.",
                    "timed_out": True,
                    "state": dict(state),
                }

            if result_path.exists():
                try:
                    payload = json.loads(result_path.read_text(encoding="utf-8"))
                    payload.setdefault("stderr", raw_err.decode("utf-8", errors="replace"))
                    payload.setdefault("stdout", raw_out.decode("utf-8", errors="replace"))
                    payload.setdefault("timed_out", False)
                    return payload
                except Exception:
                    pass

            return {
                "ok": False,
                "stdout": raw_out.decode("utf-8", errors="replace"),
                "stderr": raw_err.decode("utf-8", errors="replace"),
                "error": "Docker sandbox failed to return structured payload.",
                "timed_out": False,
                "state": dict(state),
            }

    def _docker_runner_script(self) -> str:
        allowed = sorted(self.ALLOWED_MODULES.keys())
        blocked = sorted(self.BLOCKED_MODULES)
        return textwrap.dedent(
            f"""
            import ast
            import contextlib
            import io
            import json

            ALLOWED = set({allowed!r})
            BLOCKED = set({blocked!r})

            def guarded_import(name, globals_dict=None, locals_dict=None, fromlist=(), level=0):
                root = name.split('.', 1)[0]
                if root in BLOCKED:
                    raise ImportError(f"Module '{{root}}' is blocked by sandbox policy")
                if root not in ALLOWED:
                    raise ImportError(f"Module '{{root}}' is not allow-listed")
                return __import__(name, globals_dict, locals_dict, fromlist, level)

            safe_builtins = {{
                'abs': abs, 'all': all, 'any': any, 'bool': bool, 'bytes': bytes,
                'dict': dict, 'enumerate': enumerate, 'float': float, 'int': int,
                'isinstance': isinstance, 'len': len, 'list': list, 'map': map,
                'max': max, 'min': min, 'print': print, 'range': range,
                'repr': repr, 'round': round, 'set': set, 'sorted': sorted,
                'str': str, 'sum': sum, 'tuple': tuple, 'zip': zip,
                '__import__': guarded_import,
            }}

            state = json.loads(open('state.json', 'r', encoding='utf-8').read())
            code = open('snippet.py', 'r', encoding='utf-8').read()

            out = io.StringIO()
            err = io.StringIO()
            scope = dict(state)
            result_repr = ''
            payload = {{'ok': False, 'stdout': '', 'stderr': '', 'state': state}}
            try:
                module = ast.parse(code, mode='exec')
                globals_dict = {{'__builtins__': safe_builtins}}
                if module.body and isinstance(module.body[-1], ast.Expr):
                    expr = ast.Expression(module.body[-1].value)
                    module.body = module.body[:-1]
                    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                        if module.body:
                            exec(compile(module, '<docker-sandbox>', 'exec'), globals_dict, scope)
                        value = eval(compile(expr, '<docker-sandbox>', 'eval'), globals_dict, scope)
                        result_repr = repr(value)
                        scope['_'] = value
                else:
                    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                        exec(compile(module, '<docker-sandbox>', 'exec'), globals_dict, scope)

                clean_scope = {{}}
                for key, value in scope.items():
                    if key.startswith('__'):
                        continue
                    if callable(value):
                        continue
                    if isinstance(value, (int, float, bool, str, list, dict, tuple, set, type(None))):
                        clean_scope[key] = value
                    else:
                        clean_scope[key] = repr(value)
                payload = {{
                    'ok': True,
                    'stdout': out.getvalue(),
                    'stderr': err.getvalue(),
                    'result_repr': result_repr,
                    'state': clean_scope,
                }}
            except Exception as exc:
                payload = {{
                    'ok': False,
                    'stdout': out.getvalue(),
                    'stderr': err.getvalue(),
                    'error': f"{{type(exc).__name__}}: {{exc}}",
                    'state': state,
                }}
            open('result.json', 'w', encoding='utf-8').write(json.dumps(payload, ensure_ascii=True))
            """
        ).strip() + "\n"

    def _write_script(self, code: str) -> Path:
        stamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%S%fZ")
        script_path = self._scripts_dir / f"snippet_{stamp}.py"
        script_path.write_text(code, encoding="utf-8")
        return script_path

    def _sanitize_traceback(self, text: str) -> str:
        if not text:
            return ""
        cleaned = text.replace(str(self._workspace), "[REDACTED_PATH]")
        cleaned = cleaned.replace(str(Path.home()), "[REDACTED_PATH]")
        cleaned = re.sub(r"File \"[^\"]+\"", 'File "[REDACTED_PATH]"', cleaned)
        cleaned = re.sub(r"(?i)(user|home|cwd|pwd)=\S+", r"\1=[REDACTED]", cleaned)
        return cleaned

    def _is_high_isolation_mode(self) -> bool:
        env_flag = os.getenv("CERBERUS_INTERPRETER_HIGH_ISOLATION", "").strip().lower()
        if env_flag in {"1", "true", "yes", "on"}:
            return True
        try:
            resolved, _tier = CONFIG_STORE.resolve("CERBERUS_INTERPRETER_HIGH_ISOLATION")
            return str(resolved).strip().lower() in {"1", "true", "yes", "on"}
        except Exception:
            return False

    def _session_key(self) -> str:
        return str(self._workspace)

    def _run_sync(self, coro: Any) -> Dict[str, Any]:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)

        result: Dict[str, Any] = {}
        failure: Dict[str, BaseException] = {}

        def _runner() -> None:
            try:
                result["value"] = asyncio.run(coro)
            except BaseException as exc:  # pragma: no cover
                failure["error"] = exc

        thread = threading.Thread(target=_runner, daemon=True)
        thread.start()
        thread.join()
        if "error" in failure:
            raise RuntimeError("CerebroInterpreter async bridge failed") from failure["error"]
        return result.get("value", {"ok": False, "error": {"code": "bridge_failure", "message": "No result."}})

    def _audit_execution(self, payload: Mapping[str, Any]) -> None:
        audit_path = (self._workspace / ".cerberus" / "audit" / "python_interpreter.jsonl").resolve()
        audit_path.parent.mkdir(parents=True, exist_ok=True)

        row = {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "mode": payload.get("mode", "local"),
            "ok": payload.get("ok", False),
            "timed_out": payload.get("timed_out", False),
            "duration_ms": payload.get("duration_ms", 0),
            "script_path": payload.get("script_path", ""),
            "error": payload.get("error"),
            "state_size": payload.get("state_size", 0),
        }
        with audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(clean_data(row), ensure_ascii=True, default=str) + "\n")

        if self._logger is not None:
            try:
                self._logger.audit(
                    "Python sandbox snippet executed",
                    actor="code_interpreter",
                    data=clean_data(row),
                    tags=["interpreter", "sandbox", str(payload.get("mode", "local"))],
                )
            except Exception:
                pass


INTERPRETER = CerebroInterpreter()


@function_tool
def execute_python_code(code: str, timeout_seconds: int = 5, memory_limit_mb: int = 128) -> Dict[str, Any]:
    """Execute Python snippet in Cerebro hardened sandbox."""
    return INTERPRETER.execute(code=code, timeout_seconds=timeout_seconds, memory_limit_mb=memory_limit_mb)


__all__ = ["CerebroInterpreter", "execute_python_code"]
