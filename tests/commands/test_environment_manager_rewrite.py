from __future__ import annotations

import json
from pathlib import Path

from cai.repl.commands.agent import AgentRegistry
from cai.repl.commands.base import FrameworkCommand
from cai.repl.commands.env import EnvCommand, EnvironmentAuditor


def test_environment_auditor_creates_workspace_scoped_session_state(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path / "workspace"))

    auditor = EnvironmentAuditor()
    ok, error = auditor.set_session_value("CEREBRO_MODEL", "openai/local-qwen")

    assert ok is True
    assert error == ""

    state_file = auditor._session_file()
    assert state_file.exists()

    payload = json.loads(state_file.read_text(encoding="utf-8"))
    assert payload["workspace_tag"] == auditor._workspace_tag
    assert payload["overlay"]["CEREBRO_MODEL"] == "openai/local-qwen"


def test_environment_auditor_applies_default_deny_policy(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path / "workspace"))

    auditor = EnvironmentAuditor()
    item = auditor.get("CEREBRO_API_KEY")

    assert item.safe is False
    assert item.value == "HIDDEN_BY_POLICY"
    assert item.source == "policy"


def test_environment_auditor_cleanup_removes_overlay_file(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("WORKSPACE_ROOT", str(tmp_path / "workspace"))

    auditor = EnvironmentAuditor()
    ok, _ = auditor.set_session_value("CEREBRO_MODEL", "openai/local-qwen")
    assert ok is True
    assert auditor._session_file().exists()

    auditor.clear_session_overlay()

    assert auditor._session_file().exists() is False
    assert auditor._session_overlay == {}


def test_framework_command_and_registry_contracts(tmp_path):
    env_cmd = EnvCommand()
    assert isinstance(env_cmd, FrameworkCommand)

    registry_file = tmp_path / "agents.json"
    registry_file.write_text(
        json.dumps(
            [
                {
                    "key": "operator",
                    "name": "Operator",
                    "description": "Security operator profile",
                    "prompt": "Act as a security operator",
                    "model": "openai/gpt-4o-mini",
                    "capabilities": ["triage", "reporting"],
                }
            ]
        ),
        encoding="utf-8",
    )

    registry = AgentRegistry(path=registry_file)
    registry.load()

    assert [cfg.key for cfg in registry.list()] == ["operator"]
    assert registry.get("operator") is not None
