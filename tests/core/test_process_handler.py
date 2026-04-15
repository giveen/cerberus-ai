from __future__ import annotations

import asyncio
import os
from pathlib import Path
import sys

import pytest

from cerberus.utils.process_handler import has_active_processes, run_streaming_subprocess, streaming_runtime, terminate_session_task


@pytest.mark.asyncio
async def test_streaming_runtime_emits_output_and_clears_registry(tmp_path: Path) -> None:
    events: list[tuple[str, str]] = []

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
async def test_terminate_session_task_stops_registered_process(tmp_path: Path) -> None:
    started = asyncio.Event()

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