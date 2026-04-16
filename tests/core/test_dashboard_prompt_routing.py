from __future__ import annotations

from cerberus_dashboard.cerberus_dashboard import (
    AgentDashboardState,
    AgentSession,
    _deserialize_dashboard_snapshot,
    _extract_prompt_response_from_lines,
    _sanitize_prompt_response_text,
    _serialize_dashboard_snapshot,
    _upsert_assistant_response_log,
)


def test_plain_text_routes_to_supervised_prompt() -> None:
    action = AgentDashboardState._parse_prompt_to_action("Hello")

    assert action["tool_name"] == "run_supervised_prompt"
    assert action["arguments"] == {"prompt": "Hello"}


def test_explicit_command_routes_to_cli_execution() -> None:
    action = AgentDashboardState._parse_prompt_to_action("nmap -sV 127.0.0.1")

    assert action["tool_name"] == "execute_cli_command"
    assert action["arguments"] == {"command": "nmap -sV 127.0.0.1"}


def test_runtime_stdout_from_prompt_dispatch_is_treated_as_assistant_output() -> None:
    assert AgentDashboardState._role_for_runtime_event("stdout", "run_supervised_prompt") == "Assistant"
    assert AgentDashboardState._role_for_runtime_event("stdout", "execute_cli_command") == "Tool"
    assert AgentDashboardState._role_for_runtime_event("stderr", "run_supervised_prompt") == "Audit"
    assert AgentDashboardState._role_for_runtime_event("status", "run_supervised_prompt") == "System"


def test_prompt_output_parser_only_returns_final_output_panel_text() -> None:
    lines = [
        "technical safety constraints",
        "Level 25 A AUDIT reasoning Reasoning cycle recorded",
        "mode MODE_CRITIQUE",
        "objective Ensure guardrail decision is not over-protective while",
        "preserving scope and stability",
        "pivot_required False",
        "Cerebro Supervised Mission Summary",
        "╭──────────────────────── Final Output ────────────────────────╮",
        "│ Hello! I'm ready to help validate and critique proposed actions. I'll │",
        "│ evaluate them for correctness, safety, efficiency, and risk - challenging │",
        "│ assumptions and identifying potential failure points. │",
        "│ │",
        "│ What would you like me to evaluate? │",
        "╰──────────────────────────────────────────────────────────────╯",
    ]

    assert _extract_prompt_response_from_lines(lines) == (
        "Hello! I'm ready to help validate and critique proposed actions. I'll\n"
        "evaluate them for correctness, safety, efficiency, and risk - challenging\n"
        "assumptions and identifying potential failure points.\n\n"
        "What would you like me to evaluate?"
    )


def test_prompt_output_parser_refuses_meta_only_fallback_output() -> None:
    lines = [
        "technical safety constraints",
        "mode MODE_CRITIQUE",
        "pivot_required False",
    ]

    assert _extract_prompt_response_from_lines(lines, fallback_to_plain_text=True) == ""


def test_prompt_response_sanitizer_keeps_committing_json_response_text() -> None:
    content = (
        "The error is clear now - the policy engine is complaining about BALANCED.\n\n"
        "Response\n\n"
        "COMMITTING_JSON: {\"tool_name\": \"nmap\", \"arguments\": {\"target\": \"192.168.0.4\"}}"
    )

    assert _sanitize_prompt_response_text(content) == content


def test_prompt_response_sanitizer_hides_raw_model_request_payload() -> None:
    content = (
        '{"messages": [{"role": "system", "content": "# Session Metadata"}], '
        '"model": "Qwen3.5-27B-Aggressive-Q4_K_M", "stream": true, "tools": []}'
    )

    assert _sanitize_prompt_response_text(content) == ""


def test_upsert_assistant_response_log_reuses_existing_assistant_entry() -> None:
    logs = [
        {"role": "System", "content": "Dispatching", "timestamp": "00:00:01"},
        {"role": "Audit", "content": "Verifying", "timestamp": "00:00:02"},
    ]

    logs, response_index = _upsert_assistant_response_log(logs, None, "First line")
    logs.append({"role": "System", "content": "Still running", "timestamp": "00:00:03"})
    logs, response_index = _upsert_assistant_response_log(logs, response_index, "Merged response")

    assistant_logs = [entry for entry in logs if entry["role"] == "Assistant"]
    assert len(assistant_logs) == 1
    assert assistant_logs[0]["content"] == "Merged response"
    assert response_index == 2


def test_dashboard_snapshot_round_trip_preserves_user_and_assistant_messages() -> None:
    session = AgentSession(
        session_id="AGENT-1",
        role="Lead Operator",
        workspace="/tmp/workspaces/dashboard-agent-1",
        workspace_id="dashboard-agent-1",
        logs=[
            {"role": "User", "content": "Scan target host", "timestamp": "12:00:00"},
            {"role": "Assistant", "content": "Starting host reconnaissance.", "timestamp": "12:00:01"},
        ],
        status="ready",
        status_line="Standing by for a prompt or command.",
    )

    snapshot = _serialize_dashboard_snapshot(
        [session],
        active_session_id="AGENT-1",
        cpu_usage=31,
        ram_usage=57,
        net_mbps=6.2,
        alert_count=0,
        sensor_health="Nominal",
    )
    restored = _deserialize_dashboard_snapshot(snapshot)

    assert restored is not None
    restored_session = restored["agent_sessions"][0]
    assert restored["active_session_id"] == "AGENT-1"
    assert restored_session.logs[0]["role"] == "User"
    assert restored_session.logs[0]["content"] == "Scan target host"
    assert restored_session.logs[1]["role"] == "Assistant"
    assert restored_session.logs[1]["content"] == "Starting host reconnaissance."


def test_dashboard_snapshot_deserializer_rejects_invalid_payload() -> None:
    assert _deserialize_dashboard_snapshot("not-json") is None
    assert _deserialize_dashboard_snapshot('{"version": 1, "agent_sessions": []}') is None
