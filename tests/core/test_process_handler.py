from __future__ import annotations

import asyncio
import os
from pathlib import Path
import sys

import pytest

from cerberus.utils.process_handler import has_active_processes, run_streaming_subprocess, streaming_runtime, terminate_session_task
from cerberus.utils.process_handler import StreamedSubprocessResult, _run_streaming_container_exec


@pytest.mark.asyncio
async def test_streaming_runtime_emits_output_and_clears_registry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[tuple[str, str]] = []

    monkeypatch.delenv("CERBERUS_ACTIVE_CONTAINER", raising=False)
    monkeypatch.delenv("CEREBRO_ACTIVE_CONTAINER", raising=False)

    async def callback(channel: str, message: str) -> None:
        events.append((channel, message))

    with streaming_runtime(session_id="AGENT-1", callback=callback):
        result = await run_streaming_subprocess(
            argv=[
                sys.executable,
                "-c",
                "import sys; print('alpha'); print('beta', file=sys.stderr)",
            ],
            cwd=tmp_path,
            timeout_seconds=5,
        )

    assert result.exit_code == 0
    assert ("stdout", "alpha") in events
    assert ("stderr", "beta") in events
    assert not has_active_processes("AGENT-1")


@pytest.mark.asyncio
@pytest.mark.skipif(os.name == "nt", reason="signal-based termination is validated on POSIX runtimes")
async def test_terminate_session_task_stops_registered_process(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    started = asyncio.Event()

    monkeypatch.delenv("CERBERUS_ACTIVE_CONTAINER", raising=False)
    monkeypatch.delenv("CEREBRO_ACTIVE_CONTAINER", raising=False)

    async def mark_started(_process: asyncio.subprocess.Process) -> None:
        started.set()

    task = asyncio.create_task(
        run_streaming_subprocess(
            argv=[
                sys.executable,
                "-c",
                "import time; print('ready', flush=True); time.sleep(30)",
            ],
            cwd=tmp_path,
            timeout_seconds=40,
            session_id="AGENT-2",
            started_callback=mark_started,
        )
    )

    await asyncio.wait_for(started.wait(), timeout=5)
    assert has_active_processes("AGENT-2")

    termination = await terminate_session_task("AGENT-2")
    result = await asyncio.wait_for(task, timeout=5)

    assert termination["found"] >= 1
    assert not has_active_processes("AGENT-2")
    assert result.exit_code is not None


@pytest.mark.asyncio
@pytest.mark.parametrize("env_key", ["CERBERUS_ACTIVE_CONTAINER", "CEREBRO_ACTIVE_CONTAINER"])
async def test_run_streaming_subprocess_routes_to_active_container(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, env_key: str
) -> None:
    captured: dict[str, object] = {}

    async def _fake_run_streaming_container_exec(**kwargs):
        captured.update(kwargs)
        return StreamedSubprocessResult(
            stdout="container stdout",
            stderr="",
            stdout_truncated=False,
            stderr_truncated=False,
            exit_code=0,
            timed_out=False,
            pid=1234,
        )

    monkeypatch.setattr("cerberus.utils.process_handler._run_streaming_container_exec", _fake_run_streaming_container_exec)

    result = await run_streaming_subprocess(
        argv=[sys.executable, "-c", "print('alpha')"],
        cwd=tmp_path,
        env={env_key: "cerberus"},
        timeout_seconds=5,
    )

    assert result.exit_code == 0
    assert result.stdout == "container stdout"
    assert captured["active_container"] == "cerberus"


@pytest.mark.asyncio
async def test_run_streaming_container_exec_forwards_runtime_env_to_docker_exec(monkeypatch: pytest.MonkeyPatch) -> None:
    recorded: dict[str, object] = {}

    class _FakeAPI:
        def exec_create(self, **kwargs):
            recorded.update(kwargs)
            return {"Id": "exec-123"}

        def exec_start(self, _exec_id, stream=True, demux=True):
            assert stream is True
            assert demux is True
            return iter(())

        def exec_inspect(self, _exec_id):
            return {"ExitCode": 0}

    class _FakeContainer:
        status = "running"

        def reload(self):
            return None

    class _FakeClient:
        def __init__(self):
            self.api = _FakeAPI()

    fake_client = _FakeClient()

    from cerberus.tools.runners import docker as docker_runner

    monkeypatch.setattr(docker_runner.DOCKER_TOOL, "_client_or_error", lambda: (fake_client, None))
    monkeypatch.setattr(docker_runner.DOCKER_TOOL, "_get_container", lambda _client, _name: (_FakeContainer(), None))
    monkeypatch.setattr(docker_runner.DOCKER_TOOL, "_prepare_container_paths", lambda **_kwargs: None)
    monkeypatch.setattr(docker_runner.DOCKER_TOOL, "_resolve_container_workspace", lambda: "/workspace/workspaces")

    result = await _run_streaming_container_exec(
        active_container="cerberus",
        argv=[sys.executable, "-c", "print('alpha')"],
        cwd="/workspace/workspaces/dashboard-agent-1",
        env={
            "CERBERUS_MODEL": "Qwen3.5-27B-Aggressive-Q4_K_M",
            "OPENAI_API_KEY": "sk-local",
            "WORKSPACE_ROOT": "/workspace/workspaces/dashboard-agent-1",
            "UNRELATED": "drop-me",
        },
        timeout_seconds=5,
        redactor=None,
        event_callback=None,
        stdout_callback=None,
        stderr_callback=None,
        stdout_mode="line",
        stderr_mode="line",
        emit_stdout=True,
        emit_stderr=True,
        started_callback=None,
        max_output_chars=1000,
        max_line_chars=1000,
        timeout_message="timeout",
    )

    assert result.exit_code == 0
    assert recorded["environment"] == {
        "CERBERUS_MODEL": "Qwen3.5-27B-Aggressive-Q4_K_M",
        "OPENAI_API_KEY": "sk-local",
        "WORKSPACE_ROOT": "/workspace/workspaces/dashboard-agent-1",
    }