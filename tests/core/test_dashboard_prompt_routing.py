from __future__ import annotations

from cerberus_dashboard.cerberus_dashboard import AgentDashboardState


def test_plain_text_routes_to_supervised_prompt() -> None:
    action = AgentDashboardState._parse_prompt_to_action("Hello")

    assert action["tool_name"] == "run_supervised_prompt"
    assert action["arguments"] == {"prompt": "Hello"}


def test_explicit_command_routes_to_cli_execution() -> None:
    action = AgentDashboardState._parse_prompt_to_action("nmap -sV 127.0.0.1")

    assert action["tool_name"] == "execute_cli_command"
    assert action["arguments"] == {"command": "nmap -sV 127.0.0.1"}
