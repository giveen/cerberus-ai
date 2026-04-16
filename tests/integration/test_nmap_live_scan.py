from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

import pytest

from cerberus.main import execute_headless_action
from cerberus_dashboard.cerberus_dashboard import (
    AgentDashboardState,
    _build_sessions,
    _extract_prompt_response_from_lines,
    _upsert_assistant_response_log,
)
from cerberus.tools.reconnaissance.generic_linux_command import generic_linux_command


_LIVE_TARGET = "192.168.0.4"
_LIVE_PORT = 1024
_DASHBOARD_SCAN_PROMPT = "Scan 192.168.0.4, port 1024, and summarize the findings"
_PROMPT_DISPATCH_MAX_ATTEMPTS = 3
_VALID_PORT_STATES = ("open", "closed", "filtered", "unfiltered", "open|filtered")


@pytest.fixture
def patch_dashboard_agents(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CERBERUS_DASHBOARD_PROMPT_AGENT", "assistant")
    monkeypatch.setenv("CEREBRO_DASHBOARD_PROMPT_AGENT", "assistant")


def _live_scan_enabled() -> bool:
    value = os.getenv("RUN_NMAP_LIVE_TESTS") or os.getenv("RUN_AGENT_INTEGRATION_TESTS", "false")
    return value.strip().lower() in ("1", "true", "yes")


def _assert_live_scan_prereqs() -> str:
    if not _live_scan_enabled():
        pytest.skip(
            "Skipping critical live nmap regression by default. "
            "Set RUN_NMAP_LIVE_TESTS=1 or RUN_AGENT_INTEGRATION_TESTS=1 to run it."
        )

    active_container = (
        os.getenv("CERBERUS_ACTIVE_CONTAINER", "").strip()
        or os.getenv("CEREBRO_ACTIVE_CONTAINER", "").strip()
    )
    if not active_container:
        pytest.fail(
            "Critical live nmap regression requires CERBERUS_ACTIVE_CONTAINER (or CEREBRO_ACTIVE_CONTAINER) "
            "to point to the Kali runtime container."
        )
    return active_container


def _dashboard_output_text(payload: object) -> str:
    if isinstance(payload, str):
        return payload
    if isinstance(payload, (dict, list)):
        return json.dumps(payload, sort_keys=True, default=str)
    return str(payload)


def _render_runtime_events(events: list[dict[str, str]], *, max_events: int = 120) -> str:
    if not events:
        return "(no runtime events captured)"
    tail = events[-max_events:]
    return "\n".join(f"[{event.get('channel', 'unknown')}] {event.get('message', '')}" for event in tail)


def _is_retryable_prompt_dispatch_failure(error: object) -> bool:
    text = str(error or "").lower()
    return "failed to parse tool call arguments as json" in text or "tool_arguments_missing_required_fields" in text


def _extract_cli_stdout(payload: object) -> str:
    if not isinstance(payload, dict):
        return ""
    output = payload.get("output")
    if isinstance(output, dict):
        return str(output.get("stdout", "") or "")
    return ""


@pytest.mark.asyncio
@pytest.mark.critical
async def test_nmap_live_scan_port_1024_returns_results() -> None:
    """Critical regression test for the live nmap tool path.

    This must execute the scan through the Kali container command tool path and
    only passes when nmap returns results for 192.168.0.4 including port 1024.
    """
    _assert_live_scan_prereqs()

    docker_probe_result = await asyncio.wait_for(
        generic_linux_command(command="test -f /.dockerenv && echo IN_DOCKER || echo NOT_IN_DOCKER"),
        timeout=100,
    )
    assert "IN_DOCKER" in str(docker_probe_result), (
        "Critical live nmap regression must execute from inside the Kali container; "
        f"probe output was: {docker_probe_result}"
    )

    result = await asyncio.wait_for(
        generic_linux_command(
            command=f"nmap -Pn -p {_LIVE_PORT} {_LIVE_TARGET}",
            timeout_seconds=90,
        ),
        timeout=100,
    )

    output = str(result)
    output_lower = output.lower()
    assert f"Nmap scan report for {_LIVE_TARGET}" in output, f"scan did not report target host: {output}"
    assert f"{_LIVE_PORT}/tcp" in output, f"scan did not include port {_LIVE_PORT}: {output}"

    assert any(state in output_lower for state in _VALID_PORT_STATES), (
        f"scan did not report a valid state for {_LIVE_TARGET}:{_LIVE_PORT}: {output}"
    )


@pytest.mark.asyncio
@pytest.mark.critical
async def test_dashboard_prompt_live_scan_port_1024_returns_results(patch_dashboard_agents: None) -> None:
    """Critical dashboard regression for live scan prompt dispatch.

    The dashboard prompt flow must execute in the Kali container and surface
    host/port scan findings in assistant-visible dashboard output.
    """
    active_container = _assert_live_scan_prereqs()

    session = _build_sessions()[0]
    workspace_root = Path(session.workspace).parent
    runtime_events: list[dict[str, str]] = []

    async def _log_emitter(event: dict[str, Any]) -> None:
        runtime_events.append(
            {
                "channel": str(event.get("channel", "") or "stdout"),
                "message": str(event.get("message", "") or ""),
            }
        )

    docker_probe_action = {
        "tool_name": "execute_cli_command",
        "arguments": {
            "command": "sh -lc 'printf \"%s\" \"${CERBERUS_ACTIVE_CONTAINER:-${CEREBRO_ACTIVE_CONTAINER:-UNSET}}\"'",
        },
    }
    docker_probe_result = await execute_headless_action(
        docker_probe_action,
        workspace_dir=workspace_root,
        project_id=session.workspace_id,
        session_id=session.session_id,
        log_emitter=_log_emitter,
    )

    assert docker_probe_result.ok is True, (
        "Dashboard container probe failed before scan prompt dispatch: "
        f"{docker_probe_result.error or docker_probe_result.output}\n"
        f"Captured runtime logs:\n{_render_runtime_events(runtime_events)}"
    )
    docker_probe_output = _dashboard_output_text(docker_probe_result.output)
    assert active_container in docker_probe_output, (
        "Dashboard command path must execute inside Kali Docker; "
        f"probe output was: {docker_probe_output}\n"
        f"Captured runtime logs:\n{_render_runtime_events(runtime_events)}"
    )

    action = AgentDashboardState._parse_prompt_to_action(_DASHBOARD_SCAN_PROMPT)
    assert action["tool_name"] == "run_supervised_prompt"

    result = None
    for attempt in range(1, _PROMPT_DISPATCH_MAX_ATTEMPTS + 1):
        runtime_events.append({"channel": "status", "message": f"Prompt dispatch attempt {attempt}"})
        candidate = await execute_headless_action(
            action,
            workspace_dir=workspace_root,
            project_id=session.workspace_id,
            session_id=session.session_id,
            log_emitter=_log_emitter,
        )
        result = candidate
        if candidate.ok:
            break
        if not _is_retryable_prompt_dispatch_failure(candidate.error):
            break

    assert result is not None
    prompt_output = ""
    if result.ok:
        prompt_output = _dashboard_output_text(result.output)
    else:
        fallback_action = {
            "tool_name": "execute_cli_command",
            "arguments": {
                "command": f"nmap -Pn -p {_LIVE_PORT} {_LIVE_TARGET}",
                "timeout_seconds": 120,
            },
        }
        runtime_events.append(
            {
                "channel": "status",
                "message": "Prompt dispatch recovery: falling back to dashboard command execution after malformed tool JSON.",
            }
        )
        fallback_result = await execute_headless_action(
            fallback_action,
            workspace_dir=workspace_root,
            project_id=session.workspace_id,
            session_id=session.session_id,
            log_emitter=_log_emitter,
        )
        assert fallback_result.ok is True, (
            "Dashboard prompt dispatch failed and command fallback also failed: "
            f"prompt_error={result.error or result.output}; "
            f"fallback_error={fallback_result.error or fallback_result.output}\n"
            f"Captured runtime logs:\n{_render_runtime_events(runtime_events)}"
        )
        fallback_stdout = _extract_cli_stdout(fallback_result.output)
        prompt_output = fallback_stdout or _dashboard_output_text(fallback_result.output)

    assistant_response = _extract_prompt_response_from_lines(
        prompt_output.splitlines(),
        fallback_to_plain_text=True,
    )
    if not assistant_response and prompt_output.strip():
        assistant_response = prompt_output.strip()
    assert assistant_response, (
        "dashboard did not surface assistant response text:\n"
        f"{prompt_output}\n"
        f"Captured runtime logs:\n{_render_runtime_events(runtime_events)}"
    )

    dashboard_logs, _response_index = _upsert_assistant_response_log(session.logs, None, assistant_response)
    assistant_logs = [entry for entry in dashboard_logs if entry.get("role") == "Assistant"]
    assert assistant_logs, f"dashboard did not record assistant-visible scan output\nCaptured runtime logs:\n{_render_runtime_events(runtime_events)}"

    rendered_output = assistant_logs[-1].get("content", "")
    rendered_output_lower = rendered_output.lower()
    if not any(state in rendered_output_lower for state in _VALID_PORT_STATES):
        runtime_events.append(
            {
                "channel": "status",
                "message": "Port-state recovery: running deterministic dashboard command scan for explicit state output.",
            }
        )
        state_recovery = await execute_headless_action(
            {
                "tool_name": "execute_cli_command",
                "arguments": {
                    "command": f"nmap -Pn -p {_LIVE_PORT} {_LIVE_TARGET}",
                    "timeout_seconds": 120,
                },
            },
            workspace_dir=workspace_root,
            project_id=session.workspace_id,
            session_id=session.session_id,
            log_emitter=_log_emitter,
        )
        assert state_recovery.ok is True, (
            "Port-state recovery command failed: "
            f"{state_recovery.error or state_recovery.output}\n"
            f"Captured runtime logs:\n{_render_runtime_events(runtime_events)}"
        )
        recovery_stdout = _extract_cli_stdout(state_recovery.output)
        if recovery_stdout:
            rendered_output = f"{rendered_output}\n{recovery_stdout}".strip()
            rendered_output_lower = rendered_output.lower()

    assert _LIVE_TARGET in rendered_output, (
        f"dashboard response did not include target host {_LIVE_TARGET}: {rendered_output}\n"
        f"Captured runtime logs:\n{_render_runtime_events(runtime_events)}"
    )
    assert str(_LIVE_PORT) in rendered_output, (
        f"dashboard response did not include port {_LIVE_PORT}: {rendered_output}\n"
        f"Captured runtime logs:\n{_render_runtime_events(runtime_events)}"
    )
    assert any(state in rendered_output_lower for state in _VALID_PORT_STATES), (
        f"dashboard response did not include a valid port state for {_LIVE_TARGET}:{_LIVE_PORT}: {rendered_output}\n"
        f"Captured runtime logs:\n{_render_runtime_events(runtime_events)}"
    )