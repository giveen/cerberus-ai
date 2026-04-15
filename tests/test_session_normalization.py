import asyncio
import json

import pytest

from cerberus.tools.reconnaissance import generic_linux_command as glc


def test_session_id_empty_quotes_uses_async(monkeypatch):
    called = {"run_command": False, "run_command_async": False}

    def fake_run_command(*args, **kwargs):
        called["run_command"] = True
        return "run"

    async def fake_run_command_async(*args, **kwargs):
        called["run_command_async"] = True
        return "async-result"

    monkeypatch.setattr(glc, "run_command", fake_run_command)
    monkeypatch.setattr(glc, "run_command_async", fake_run_command_async)

    payload = json.dumps({"command": "ls -la", "interactive": False, "session_id": '""'})
    result = asyncio.run(glc.generic_linux_command.on_invoke_tool(None, payload))

    assert result == "async-result"
    assert called["run_command_async"] is True
    assert called["run_command"] is False


def test_session_id_strip_quotes_uses_run_command(monkeypatch):
    captured = {}

    def fake_run_command(*args, **kwargs):
        # capture the session_id kwarg
        captured["session_id"] = kwargs.get("session_id")
        return "run-result"

    async def fake_run_command_async(*args, **kwargs):
        raise AssertionError("run_command_async should not be called in this path")

    monkeypatch.setattr(glc, "run_command", fake_run_command)
    monkeypatch.setattr(glc, "run_command_async", fake_run_command_async)

    payload = json.dumps({"command": "ls", "interactive": False, "session_id": "'abc'"})
    result = asyncio.run(glc.generic_linux_command.on_invoke_tool(None, payload))

    assert result == "run-result"
    assert captured.get("session_id") == 'abc'
