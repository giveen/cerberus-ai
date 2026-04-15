from __future__ import annotations

import sys

import pytest

from cerberus.main import _invoke_streamable_tool, execute_headless_action


class _FakeStream:
    def __init__(self, *lines: bytes) -> None:
        self._lines = list(lines)

    async def readline(self) -> bytes:
        if not self._lines:
            return b""
        return self._lines.pop(0)


class _FakeProcess:
    def __init__(self, stdout_lines: tuple[bytes, ...] = (), stderr_lines: tuple[bytes, ...] = ()) -> None:
        self.stdout = _FakeStream(*stdout_lines)
        self.stderr = _FakeStream(*stderr_lines)

    async def wait(self) -> int:
        return 0


@pytest.mark.asyncio
async def test_execute_headless_action_preserves_supervised_prompt_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    async def _fake_invoke_streamable_tool(tool_name: str, arguments: dict[str, object], log_emitter, **kwargs):
        assert tool_name == "run_supervised_prompt"
        assert arguments == {"prompt": "Hello"}
        return "Hello from the LLM", True

    monkeypatch.setattr("cerberus.main._invoke_streamable_tool", _fake_invoke_streamable_tool)

    result = await execute_headless_action(
        {"tool_name": "run_supervised_prompt", "arguments": {"prompt": "Hello"}},
        workspace_dir=tmp_path,
        project_id="dashboard-agent-1",
        session_id="dashboard-agent-1",
    )

    assert result.ok is True
    assert result.error is None
    assert result.output == "Hello from the LLM"


@pytest.mark.asyncio
async def test_invoke_streamable_tool_defaults_prompt_dispatch_to_assistant(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    captured: dict[str, object] = {}
    project_root = tmp_path / "dashboard-agent-1"
    workspaces_root = tmp_path / "workspaces"
    project_root.mkdir(parents=True)
    workspaces_root.mkdir(parents=True)

    async def _fake_create_subprocess_exec(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return _FakeProcess((b"Hello from the LLM\n",), ())

    monkeypatch.delenv("CERBERUS_DASHBOARD_PROMPT_AGENT", raising=False)
    monkeypatch.delenv("CEREBRO_DASHBOARD_PROMPT_AGENT", raising=False)
    monkeypatch.setattr("cerberus.main.asyncio.create_subprocess_exec", _fake_create_subprocess_exec)

    output, handled = await _invoke_streamable_tool(
        "run_supervised_prompt",
        {"prompt": "Hello"},
        None,
        project_root=project_root,
        workspaces_root=workspaces_root,
    )

    assert handled is True
    assert output == "Hello from the LLM"
    assert captured["args"] == (
        sys.executable,
        "-m",
        "cerberus.cli",
        "--workspace",
        str(project_root),
        "run",
        "Hello",
    )
    assert captured["kwargs"]["cwd"] == str(project_root)
    assert captured["kwargs"]["env"]["CERBERUS_AGENT_TYPE"] == "assistant"
    assert captured["kwargs"]["env"]["CERBERUS_DASHBOARD_PROMPT_AGENT"] == "assistant"


@pytest.mark.asyncio
async def test_invoke_streamable_tool_respects_dashboard_prompt_agent_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    captured: dict[str, object] = {}

    async def _fake_create_subprocess_exec(*args, **kwargs):
        captured["kwargs"] = kwargs
        return _FakeProcess((b"Hello from the LLM\n",), ())

    monkeypatch.setenv("CERBERUS_DASHBOARD_PROMPT_AGENT", "reasoner")
    monkeypatch.setattr("cerberus.main.asyncio.create_subprocess_exec", _fake_create_subprocess_exec)

    output, handled = await _invoke_streamable_tool(
        "run_supervised_prompt",
        {"prompt": "Hello"},
        None,
        project_root=tmp_path,
        workspaces_root=tmp_path / "workspaces",
    )

    assert handled is True
    assert output == "Hello from the LLM"
    assert captured["kwargs"]["env"]["CERBERUS_AGENT_TYPE"] == "reasoner"
