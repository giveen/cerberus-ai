from __future__ import annotations

import asyncio
from collections import defaultdict
from contextlib import contextmanager, suppress
from contextvars import ContextVar, Token
from dataclasses import dataclass
import inspect
import os
from pathlib import Path
import shlex
import signal
import threading
from types import SimpleNamespace
from typing import Any, Awaitable, Callable, Iterable, Mapping, Optional, Sequence

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None  # type: ignore


StreamCallback = Callable[[str, str], Awaitable[None] | None]
ChunkCallback = Callable[[str], Awaitable[None] | None]
ProcessCallback = Callable[[asyncio.subprocess.Process], Awaitable[None] | None]


@dataclass(frozen=True)
class StreamingContext:
    session_id: Optional[str]
    callback: Optional[StreamCallback]


@dataclass(frozen=True)
class StreamedSubprocessResult:
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    exit_code: Optional[int]
    timed_out: bool
    pid: Optional[int]


@dataclass(frozen=True)
class RegisteredProcess:
    process: asyncio.subprocess.Process
    loop: asyncio.AbstractEventLoop


_CURRENT_STREAM_CALLBACK: ContextVar[Optional[StreamCallback]] = ContextVar("cerberus_stream_callback", default=None)
_CURRENT_STREAM_SESSION_ID: ContextVar[Optional[str]] = ContextVar("cerberus_stream_session_id", default=None)
_PROCESS_REGISTRY: dict[str, dict[int, RegisteredProcess]] = defaultdict(dict)
_PROCESS_REGISTRY_LOCK = threading.Lock()
_CONTAINER_PID_MARKER = "__CERBERUS_CHILD_PID__:"
_CONTAINER_ENV_PREFIXES = (
    "CERBERUS_",
    "CEREBRO_",
    "OPENAI_",
    "LOCAL_",
    "LITELLM_",
    "OLLAMA_",
    "LLAMA_CPP_",
    "LLM_",
)
_CONTAINER_ENV_KEYS = {
    "WORKSPACE_ROOT",
    "CIR_WORKSPACE",
    "PYTHONPATH",
    "PYTHONUNBUFFERED",
}


def _signal_process_group(pid: Optional[int], sig: signal.Signals) -> bool:
    """Signal a full process group when available (POSIX)."""
    if pid is None or os.name == "nt":
        return False
    try:
        pgid = os.getpgid(pid)
        os.killpg(pgid, sig)
        return True
    except Exception:
        return False


def _trim_line(text: str, max_line_chars: int) -> str:
    if max_line_chars <= 0 or len(text) <= max_line_chars:
        return text
    return text[:max_line_chars] + "\n...[line truncated by policy]"


def _append_with_limit(existing: str, addition: str, *, max_output_chars: int, truncated_marker: str) -> tuple[str, bool]:
    if max_output_chars <= 0:
        return existing + addition, False
    if len(existing) >= max_output_chars:
        return existing, True
    remaining = max_output_chars - len(existing)
    if len(addition) <= remaining:
        return existing + addition, False
    return existing + addition[:remaining] + truncated_marker, True


def _resolve_active_container(env: Optional[Mapping[str, str]]) -> Optional[str]:
    if env is not None:
        for key in ("CERBERUS_ACTIVE_CONTAINER", "CEREBRO_ACTIVE_CONTAINER"):
            value = str(env.get(key, "") or "").strip()
            if value:
                return value

    for key in ("CERBERUS_ACTIVE_CONTAINER", "CEREBRO_ACTIVE_CONTAINER"):
        value = str(os.getenv(key, "") or "").strip()
        if value:
            return value

    return None


def _container_command(argv: Sequence[str]) -> str:
    joined = shlex.join([str(item) for item in argv])
    return f"({joined}) & child=$!; printf '{_CONTAINER_PID_MARKER}%s\\n' \"$child\" >&2; wait \"$child\""


def _split_stream_text(buffer: str, *, mode: str, flush: bool) -> tuple[list[str], str]:
    if mode == "chunk":
        return ([buffer] if buffer else []), ""

    pieces = buffer.splitlines(keepends=True)
    pending = ""
    if pieces and not flush and not pieces[-1].endswith(("\n", "\r")):
        pending = pieces.pop()
    return pieces, pending


def _resolve_container_workdir(cwd: str | Path, env: Optional[Mapping[str, str]], *, fallback: str) -> str:
    cwd_str = str(cwd)
    if cwd_str.startswith("/workspace/"):
        return cwd_str

    if env is not None:
        for key in ("CERBERUS_WORKSPACE_ACTIVE_ROOT", "WORKSPACE_ROOT", "CIR_WORKSPACE"):
            value = str(env.get(key, "") or "").strip()
            if value.startswith("/workspace/"):
                return value

    return fallback


def _resolve_container_exec_environment(env: Optional[Mapping[str, str]]) -> Optional[dict[str, str]]:
    if env is None:
        return None

    forwarded: dict[str, str] = {}
    for key, value in env.items():
        if not (key.startswith(_CONTAINER_ENV_PREFIXES) or key in _CONTAINER_ENV_KEYS):
            continue
        text = str(value or "").strip()
        if text:
            forwarded[str(key)] = text

    return forwarded or None


async def _terminate_container_child(client: Any, *, container_id: str, pid: int) -> None:
    def _kill() -> None:
        exec_id = client.api.exec_create(
            container=container_id,
            cmd=["sh", "-lc", f"kill -TERM {pid} 2>/dev/null || true; kill -KILL {pid} 2>/dev/null || true"],
            workdir="/",
            stdout=False,
            stderr=False,
            tty=False,
        )["Id"]
        client.api.exec_start(exec_id, demux=True)

    await asyncio.to_thread(_kill)


async def _run_streaming_container_exec(
    *,
    active_container: str,
    argv: Sequence[str],
    cwd: str | Path,
    env: Optional[Mapping[str, str]],
    timeout_seconds: int,
    redactor: Optional[Callable[[str], str]],
    event_callback: Optional[StreamCallback],
    stdout_callback: Optional[ChunkCallback],
    stderr_callback: Optional[ChunkCallback],
    stdout_mode: str,
    stderr_mode: str,
    emit_stdout: bool,
    emit_stderr: bool,
    started_callback: Optional[ProcessCallback],
    max_output_chars: int,
    max_line_chars: int,
    timeout_message: str,
) -> StreamedSubprocessResult:
    from cerberus.tools.runners.docker import DOCKER_TOOL

    client, error = DOCKER_TOOL._client_or_error()
    if error:
        raise RuntimeError(f"Container execution requested for '{active_container}', but Docker is unavailable: {error}")

    container, container_error = DOCKER_TOOL._get_container(client, active_container)
    if container_error:
        raise RuntimeError(container_error)

    try:
        await asyncio.to_thread(container.reload)
        if container.status != "running":
            await asyncio.to_thread(container.start)
            await asyncio.to_thread(container.reload)
    except Exception as exc:
        raise RuntimeError(f"Unable to start container '{active_container}': {exc}") from exc

    workdir = _resolve_container_workdir(cwd, env, fallback=DOCKER_TOOL._resolve_container_workspace())
    exec_environment = _resolve_container_exec_environment(env)
    await asyncio.to_thread(DOCKER_TOOL._prepare_container_paths, client=client, container_id=active_container, workdir=workdir)

    command = _container_command(argv)
    try:
        exec_id = await asyncio.to_thread(
            lambda: client.api.exec_create(
                container=active_container,
                cmd=["sh", "-lc", command],
                workdir=workdir,
                environment=exec_environment,
                stdout=True,
                stderr=True,
                tty=False,
            )["Id"]
        )
    except Exception as exc:
        raise RuntimeError(f"Unable to create exec in container '{active_container}': {exc}") from exc

    await _maybe_call_process_callback(
        started_callback,
        SimpleNamespace(pid=None, returncode=None, container_id=active_container, exec_id=exec_id),
    )

    def _clean(text: str) -> str:
        value = text
        if redactor is not None:
            value = redactor(value)
        return value

    channels = {
        "stdout": {
            "mode": stdout_mode,
            "callback": stdout_callback,
            "emit": emit_stdout,
            "collected": "",
            "truncated": False,
            "pending": "",
        },
        "stderr": {
            "mode": stderr_mode,
            "callback": stderr_callback,
            "emit": emit_stderr,
            "collected": "",
            "truncated": False,
            "pending": "",
        },
    }

    async def _emit_piece(channel: str, piece: str) -> None:
        state = channels[channel]
        text = _trim_line(_clean(piece), max_line_chars)
        state["collected"], did_truncate = _append_with_limit(
            state["collected"],
            text,
            max_output_chars=max_output_chars,
            truncated_marker="\n...[output truncated by policy]",
        )
        state["truncated"] = bool(state["truncated"] or did_truncate)
        await _maybe_call_text_callback(state["callback"], text)
        if state["emit"]:
            await emit_stream_event(channel, text.rstrip("\r\n"), callback=event_callback)

    async def _consume_payload(channel: str, payload: str, *, flush: bool = False) -> None:
        state = channels[channel]
        buffer = str(state["pending"]) + payload
        pieces, pending = _split_stream_text(buffer, mode=str(state["mode"]), flush=flush)
        state["pending"] = pending
        for piece in pieces:
            await _emit_piece(channel, piece)

    loop = asyncio.get_running_loop()
    stream_queue: asyncio.Queue[tuple[str, Optional[str]]] = asyncio.Queue()
    child_pid: Optional[int] = None
    control_buffer = ""

    def _worker() -> None:
        try:
            for item in client.api.exec_start(exec_id, stream=True, demux=True):
                out_chunk, err_chunk = item if isinstance(item, tuple) else (item, None)
                if out_chunk:
                    loop.call_soon_threadsafe(stream_queue.put_nowait, ("stdout", out_chunk.decode("utf-8", errors="replace")))
                if err_chunk:
                    loop.call_soon_threadsafe(stream_queue.put_nowait, ("stderr", err_chunk.decode("utf-8", errors="replace")))
        except Exception as exc:
            loop.call_soon_threadsafe(stream_queue.put_nowait, ("error", str(exc)))
        finally:
            loop.call_soon_threadsafe(stream_queue.put_nowait, ("done", None))

    thread = threading.Thread(target=_worker, name=f"docker-exec-{active_container[:12]}", daemon=True)
    thread.start()

    async def _strip_control(payload: str) -> str:
        nonlocal child_pid, control_buffer
        if child_pid is not None and not control_buffer:
            return payload

        combined = control_buffer + payload
        while True:
            newline_index = combined.find("\n")
            if newline_index < 0:
                control_buffer = combined
                return ""

            line = combined[: newline_index + 1]
            combined = combined[newline_index + 1 :]
            if line.startswith(_CONTAINER_PID_MARKER):
                pid_text = line[len(_CONTAINER_PID_MARKER) :].strip()
                if pid_text.isdigit():
                    child_pid = int(pid_text)
                control_buffer = ""
                continue

            control_buffer = ""
            return line + combined

    timed_out = False
    deadline = loop.time() + float(timeout_seconds)

    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            timed_out = True
            break

        try:
            kind, payload = await asyncio.wait_for(stream_queue.get(), timeout=remaining)
        except asyncio.TimeoutError:
            timed_out = True
            break

        if kind == "done":
            break
        if kind == "error" and payload:
            await _consume_payload("stderr", payload)
            break
        if payload is None:
            continue

        if kind == "stderr":
            payload = await _strip_control(payload)
            if not payload:
                continue

        await _consume_payload(kind, payload)

    if timed_out and child_pid is not None:
        with suppress(Exception):
            await _terminate_container_child(client, container_id=active_container, pid=child_pid)

    await _consume_payload("stdout", "", flush=True)
    await _consume_payload("stderr", "", flush=True)

    if timed_out:
        await emit_stream_event("stderr", timeout_message, callback=event_callback)
        channels["stderr"]["collected"], did_truncate = _append_with_limit(
            str(channels["stderr"]["collected"]),
            ("\n" if channels["stderr"]["collected"] else "") + timeout_message,
            max_output_chars=max_output_chars,
            truncated_marker="\n...[output truncated by policy]",
        )
        channels["stderr"]["truncated"] = bool(channels["stderr"]["truncated"] or did_truncate)

    exit_code: Optional[int] = None
    with suppress(Exception):
        info = await asyncio.to_thread(client.api.exec_inspect, exec_id)
        exit_code = info.get("ExitCode")

    return StreamedSubprocessResult(
        stdout=str(channels["stdout"]["collected"]),
        stderr=str(channels["stderr"]["collected"]),
        stdout_truncated=bool(channels["stdout"]["truncated"]),
        stderr_truncated=bool(channels["stderr"]["truncated"]),
        exit_code=exit_code,
        timed_out=timed_out,
        pid=child_pid,
    )


async def _maybe_call_text_callback(callback: Optional[ChunkCallback], text: str) -> None:
    if callback is None:
        return
    result = callback(text)
    if inspect.isawaitable(result):
        await result


async def _maybe_call_process_callback(callback: Optional[ProcessCallback], process: asyncio.subprocess.Process) -> None:
    if callback is None:
        return
    result = callback(process)
    if inspect.isawaitable(result):
        await result


async def emit_stream_event(channel: str, message: str, callback: Optional[StreamCallback] = None) -> None:
    resolved = callback if callback is not None else _CURRENT_STREAM_CALLBACK.get()
    if resolved is None:
        return
    result = resolved(channel, message)
    if inspect.isawaitable(result):
        await result


@contextmanager
def streaming_runtime(*, session_id: Optional[str] = None, callback: Optional[StreamCallback] = None) -> Iterable[None]:
    callback_token: Token[Optional[StreamCallback]] | None = None
    session_token: Token[Optional[str]] | None = None
    if callback is not None:
        callback_token = _CURRENT_STREAM_CALLBACK.set(callback)
    if session_id is not None:
        session_token = _CURRENT_STREAM_SESSION_ID.set(session_id)
    try:
        yield
    finally:
        if session_token is not None:
            _CURRENT_STREAM_SESSION_ID.reset(session_token)
        if callback_token is not None:
            _CURRENT_STREAM_CALLBACK.reset(callback_token)


def capture_streaming_context() -> StreamingContext:
    return StreamingContext(
        session_id=_CURRENT_STREAM_SESSION_ID.get(),
        callback=_CURRENT_STREAM_CALLBACK.get(),
    )


def register_process(process: asyncio.subprocess.Process, *, session_id: Optional[str] = None) -> None:
    resolved_session_id = session_id or _CURRENT_STREAM_SESSION_ID.get()
    if not resolved_session_id or process.pid is None:
        return
    loop = asyncio.get_running_loop()
    with _PROCESS_REGISTRY_LOCK:
        _PROCESS_REGISTRY[resolved_session_id][process.pid] = RegisteredProcess(process=process, loop=loop)


def unregister_process(process: asyncio.subprocess.Process, *, session_id: Optional[str] = None) -> None:
    resolved_session_id = session_id or _CURRENT_STREAM_SESSION_ID.get()
    if not resolved_session_id or process.pid is None:
        return
    with _PROCESS_REGISTRY_LOCK:
        session_processes = _PROCESS_REGISTRY.get(resolved_session_id)
        if session_processes is None:
            return
        session_processes.pop(process.pid, None)
        if not session_processes:
            _PROCESS_REGISTRY.pop(resolved_session_id, None)


def get_active_processes() -> dict[str, tuple[int, ...]]:
    with _PROCESS_REGISTRY_LOCK:
        snapshot: dict[str, tuple[int, ...]] = {}
        for session_id, session_processes in _PROCESS_REGISTRY.items():
            live_pids = tuple(
                sorted(
                    pid
                    for pid, entry in session_processes.items()
                    if entry.process.returncode is None
                )
            )
            if live_pids:
                snapshot[session_id] = live_pids
    return snapshot


def get_session_process_count(session_id: str) -> int:
    return len(get_active_processes().get(session_id, ()))


def has_active_processes(session_id: str) -> bool:
    return get_session_process_count(session_id) > 0


async def _await_process_exit(entry: RegisteredProcess, timeout: float) -> None:
    process = entry.process
    if process.returncode is not None:
        return

    if entry.loop.is_closed():
        return

    current_loop = asyncio.get_running_loop()
    if entry.loop is current_loop:
        await asyncio.wait_for(process.wait(), timeout=timeout)
        return

    future = asyncio.run_coroutine_threadsafe(process.wait(), entry.loop)
    try:
        await asyncio.wait_for(asyncio.wrap_future(future), timeout=timeout)
    except Exception:
        future.cancel()
        raise


def _signal_process_tree(pid: Optional[int], sig: signal.Signals) -> bool:
    if pid is None:
        return False

    if _signal_process_group(pid, sig):
        return True

    sent = False
    if psutil is not None:
        try:
            root = psutil.Process(pid)
            targets = [*root.children(recursive=True), root]
        except Exception:
            targets = []
        for target in targets:
            try:
                target.send_signal(sig)
                sent = True
            except Exception:
                continue
        if sent:
            return True

    try:
        os.kill(pid, sig)
        return True
    except Exception:
        return sent


async def terminate_session_task(session_id: str, *, grace_seconds: float = 2.0) -> dict[str, Any]:
    with _PROCESS_REGISTRY_LOCK:
        processes = list(_PROCESS_REGISTRY.get(session_id, {}).values())

    if not processes:
        return {"terminated": 0, "killed": 0, "found": 0, "pids": []}

    terminated = 0
    killed = 0
    live_processes: list[RegisteredProcess] = []
    for entry in processes:
        process = entry.process
        if process.returncode is not None:
            unregister_process(process, session_id=session_id)
            continue
        live_processes.append(entry)
        if _signal_process_tree(process.pid, signal.SIGTERM):
            terminated += 1

    if live_processes:
        await asyncio.gather(*(_await_process_exit(entry, grace_seconds) for entry in live_processes), return_exceptions=True)

    for entry in live_processes:
        process = entry.process
        if process.returncode is not None:
            unregister_process(process, session_id=session_id)
            continue

        if _signal_process_tree(process.pid, signal.SIGKILL):
            killed += 1

        with suppress(Exception):
            await _await_process_exit(entry, max(1.0, grace_seconds))
        unregister_process(process, session_id=session_id)

    return {
        "terminated": terminated,
        "killed": killed,
        "found": len(processes),
        "pids": [entry.process.pid for entry in processes if entry.process.pid is not None],
    }


async def terminate_all_session_tasks(*, grace_seconds: float = 3.0) -> dict[str, Any]:
    with _PROCESS_REGISTRY_LOCK:
        session_ids = tuple(_PROCESS_REGISTRY.keys())

    if not session_ids:
        return {"sessions": {}, "found_sessions": 0, "terminated": 0, "killed": 0, "found": 0}

    results = await asyncio.gather(
        *(terminate_session_task(session_id, grace_seconds=grace_seconds) for session_id in session_ids),
        return_exceptions=True,
    )

    per_session: dict[str, dict[str, Any]] = {}
    total_terminated = 0
    total_killed = 0
    total_found = 0
    for session_id, result in zip(session_ids, results, strict=False):
        if isinstance(result, Exception):
            per_session[session_id] = {
                "error": str(result),
                "terminated": 0,
                "killed": 0,
                "found": 0,
                "pids": [],
            }
            continue

        per_session[session_id] = result
        total_terminated += int(result.get("terminated", 0) or 0)
        total_killed += int(result.get("killed", 0) or 0)
        total_found += int(result.get("found", 0) or 0)

    return {
        "sessions": per_session,
        "found_sessions": len(session_ids),
        "terminated": total_terminated,
        "killed": total_killed,
        "found": total_found,
    }


async def terminate_registered_processes(session_id: str, *, grace_seconds: float = 2.0) -> dict[str, Any]:
    return await terminate_session_task(session_id, grace_seconds=grace_seconds)


async def run_streaming_subprocess(
    *,
    argv: Sequence[str],
    cwd: str | Path,
    env: Optional[Mapping[str, str]] = None,
    timeout_seconds: int,
    redactor: Optional[Callable[[str], str]] = None,
    event_callback: Optional[StreamCallback] = None,
    stdout_callback: Optional[ChunkCallback] = None,
    stderr_callback: Optional[ChunkCallback] = None,
    session_id: Optional[str] = None,
    stdout_mode: str = "line",
    stderr_mode: str = "line",
    stdout_chunk_size: int = 4096,
    stderr_chunk_size: int = 4096,
    emit_stdout: bool = True,
    emit_stderr: bool = True,
    started_callback: Optional[ProcessCallback] = None,
    max_output_chars: int = 50_000,
    max_line_chars: int = 4_000,
    timeout_message: str = "Execution timed out by policy.",
) -> StreamedSubprocessResult:
    active_container = _resolve_active_container(env)
    if active_container:
        return await _run_streaming_container_exec(
            active_container=active_container,
            argv=argv,
            cwd=cwd,
            env=env,
            timeout_seconds=timeout_seconds,
            redactor=redactor,
            event_callback=event_callback,
            stdout_callback=stdout_callback,
            stderr_callback=stderr_callback,
            stdout_mode=stdout_mode,
            stderr_mode=stderr_mode,
            emit_stdout=emit_stdout,
            emit_stderr=emit_stderr,
            started_callback=started_callback,
            max_output_chars=max_output_chars,
            max_line_chars=max_line_chars,
            timeout_message=timeout_message,
        )

    popen_kwargs: dict[str, Any] = {
        "cwd": str(cwd),
        "env": None if env is None else dict(env),
        "stdin": asyncio.subprocess.DEVNULL,
        "stdout": asyncio.subprocess.PIPE,
        "stderr": asyncio.subprocess.PIPE,
    }
    if os.name != "nt":
        # Put each tool execution in its own process group for group-wide termination.
        popen_kwargs["preexec_fn"] = os.setsid

    process = await asyncio.create_subprocess_exec(
        *[str(item) for item in argv],
        **popen_kwargs,
    )

    if process.stdout is None or process.stderr is None:
        process.kill()
        await process.wait()
        raise RuntimeError("Subprocess streams were not initialized.")

    register_process(process, session_id=session_id)
    await _maybe_call_process_callback(started_callback, process)

    def _clean(text: str) -> str:
        value = text
        if redactor is not None:
            value = redactor(value)
        return value

    async def _read_stream(
        stream: asyncio.StreamReader,
        *,
        channel: str,
        mode: str,
        chunk_size: int,
        callback: Optional[ChunkCallback],
        emit: bool,
    ) -> tuple[str, bool]:
        collected = ""
        truncated = False
        while True:
            data = await stream.read(chunk_size) if mode == "chunk" else await stream.readline()
            if not data:
                break
            text = _trim_line(_clean(data.decode("utf-8", errors="replace")), max_line_chars)
            collected, did_truncate = _append_with_limit(
                collected,
                text,
                max_output_chars=max_output_chars,
                truncated_marker="\n...[output truncated by policy]",
            )
            truncated = truncated or did_truncate
            await _maybe_call_text_callback(callback, text)
            if emit:
                await emit_stream_event(channel, text.rstrip("\r\n"), callback=event_callback)
        return collected, truncated

    stdout_task = asyncio.create_task(
        _read_stream(
            process.stdout,
            channel="stdout",
            mode=stdout_mode,
            chunk_size=stdout_chunk_size,
            callback=stdout_callback,
            emit=emit_stdout,
        )
    )
    stderr_task = asyncio.create_task(
        _read_stream(
            process.stderr,
            channel="stderr",
            mode=stderr_mode,
            chunk_size=stderr_chunk_size,
            callback=stderr_callback,
            emit=emit_stderr,
        )
    )

    timed_out = False
    try:
        await asyncio.wait_for(process.wait(), timeout=float(timeout_seconds))
    except asyncio.TimeoutError:
        timed_out = True
        try:
            if not _signal_process_tree(process.pid, signal.SIGTERM):
                process.terminate()
            await asyncio.wait_for(process.wait(), timeout=2.0)
        except Exception:
            if process.returncode is None:
                if not _signal_process_tree(process.pid, signal.SIGKILL):
                    process.kill()
                with suppress(Exception):
                    await process.wait()
        await emit_stream_event("stderr", timeout_message, callback=event_callback)
    finally:
        stdout_result, stderr_result = await asyncio.gather(stdout_task, stderr_task, return_exceptions=False)
        unregister_process(process, session_id=session_id)

    stdout_text, stdout_truncated = stdout_result
    stderr_text, stderr_truncated = stderr_result
    if timed_out:
        stderr_text, timeout_truncated = _append_with_limit(
            stderr_text,
            ("\n" if stderr_text else "") + timeout_message,
            max_output_chars=max_output_chars,
            truncated_marker="\n...[output truncated by policy]",
        )
        stderr_truncated = stderr_truncated or timeout_truncated

    return StreamedSubprocessResult(
        stdout=stdout_text,
        stderr=stderr_text,
        stdout_truncated=stdout_truncated,
        stderr_truncated=stderr_truncated,
        exit_code=process.returncode,
        timed_out=timed_out,
        pid=process.pid,
    )


__all__ = [
    "ChunkCallback",
    "ProcessCallback",
    "RegisteredProcess",
    "StreamCallback",
    "StreamedSubprocessResult",
    "StreamingContext",
    "capture_streaming_context",
    "emit_stream_event",
    "get_active_processes",
    "get_session_process_count",
    "has_active_processes",
    "register_process",
    "run_streaming_subprocess",
    "streaming_runtime",
    "terminate_all_session_tasks",
    "terminate_registered_processes",
    "terminate_session_task",
    "unregister_process",
]