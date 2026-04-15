from __future__ import annotations

import asyncio
from collections import defaultdict
from contextlib import contextmanager, suppress
from contextvars import ContextVar, Token
from dataclasses import dataclass
import inspect
import os
import signal
import threading
from pathlib import Path
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


_CURRENT_STREAM_CALLBACK: ContextVar[Optional[StreamCallback]] = ContextVar("cai_stream_callback", default=None)
_CURRENT_STREAM_SESSION_ID: ContextVar[Optional[str]] = ContextVar("cai_stream_session_id", default=None)
_PROCESS_REGISTRY: dict[str, dict[int, RegisteredProcess]] = defaultdict(dict)
_PROCESS_REGISTRY_LOCK = threading.Lock()


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


def has_active_processes(session_id: str) -> bool:
    with _PROCESS_REGISTRY_LOCK:
        session_processes = _PROCESS_REGISTRY.get(session_id, {})
        return any(entry.process.returncode is None for entry in session_processes.values())


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


async def terminate_registered_processes(session_id: str, *, grace_seconds: float = 2.0) -> dict[str, Any]:
    with _PROCESS_REGISTRY_LOCK:
        processes = list(_PROCESS_REGISTRY.get(session_id, {}).values())

    if not processes:
        return {"terminated": 0, "killed": 0, "found": 0}

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

    return {"terminated": terminated, "killed": killed, "found": len(processes)}


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
    process = await asyncio.create_subprocess_exec(
        *[str(item) for item in argv],
        cwd=str(cwd),
        env=None if env is None else dict(env),
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    if process.stdout is None or process.stderr is None:
        process.kill()
        await process.wait()
        raise RuntimeError("Subprocess streams were not initialized.")

    register_process(process, session_id=session_id)
    await _maybe_call_process_callback(started_callback, process)
    stdout_text = ""
    stderr_text = ""
    stdout_truncated = False
    stderr_truncated = False

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
            if mode == "chunk":
                data = await stream.read(chunk_size)
            else:
                data = await stream.readline()
            if not data:
                break
            text = _clean(data.decode("utf-8", errors="replace"))
            text = _trim_line(text, max_line_chars)
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
            if os.name == "nt":
                process.terminate()
            else:
                with suppress(ProcessLookupError):
                    os.kill(process.pid, signal.SIGTERM)
            await asyncio.wait_for(process.wait(), timeout=2.0)
        except Exception:
            if process.returncode is None:
                if os.name == "nt":
                    process.kill()
                else:
                    with suppress(ProcessLookupError):
                        os.kill(process.pid, signal.SIGKILL)
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