from __future__ import annotations

import pytest

from cerberus.main import _PROMPT_DISPATCH_AGENT_ENV, _PROMPT_DISPATCH_CONTAINER_PYTHON, _PROMPT_DISPATCH_GLOBAL_AGENT_ENV
from cerberus.main import _invoke_streamable_tool, execute_headless_action
from cerberus.utils.process_handler import StreamedSubprocessResult


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
async def test_invoke_streamable_tool_falls_back_to_assistant_when_no_env_is_set(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    captured: dict[str, object] = {}
    project_root = tmp_path / "dashboard-agent-1"
    workspaces_root = tmp_path / "workspaces"
    project_root.mkdir(parents=True)
    workspaces_root.mkdir(parents=True)

    async def _fake_run_streaming_subprocess(**kwargs):
        captured.update(kwargs)
        return StreamedSubprocessResult(
            stdout="Hello from the LLM\n",
            stderr="",
            stdout_truncated=False,
            stderr_truncated=False,
            exit_code=0,
            timed_out=False,
            pid=None,
        )

    monkeypatch.delenv("CERBERUS_DASHBOARD_PROMPT_AGENT", raising=False)
    monkeypatch.delenv("CEREBRO_DASHBOARD_PROMPT_AGENT", raising=False)
    monkeypatch.delenv("CERBERUS_AGENT_TYPE", raising=False)
    monkeypatch.delenv("CEREBRO_AGENT_TYPE", raising=False)
    monkeypatch.setattr("cerberus.main.run_streaming_subprocess", _fake_run_streaming_subprocess)

    output, handled = await _invoke_streamable_tool(
        "run_supervised_prompt",
        {"prompt": "Hello"},
        None,
        project_root=project_root,
        workspaces_root=workspaces_root,
    )

    assert handled is True
    assert output == "Hello from the LLM"
    assert captured["cwd"] == str(project_root)
    assert captured["argv"][1:] == ["-m", "cerberus.cli", "--workspace", str(project_root), "run", "Hello"]
    assert captured["env"][_PROMPT_DISPATCH_GLOBAL_AGENT_ENV] == "assistant"
    assert captured["env"][_PROMPT_DISPATCH_AGENT_ENV] == "assistant"


@pytest.mark.asyncio
@pytest.mark.parametrize("env_key", ["CERBERUS_AGENT_TYPE", "CEREBRO_AGENT_TYPE"])
async def test_invoke_streamable_tool_inherits_global_agent_when_dashboard_override_is_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path, env_key: str
) -> None:
    captured: dict[str, object] = {}

    async def _fake_run_streaming_subprocess(**kwargs):
        captured.update(kwargs)
        return StreamedSubprocessResult(
            stdout="Hello from the LLM\n",
            stderr="",
            stdout_truncated=False,
            stderr_truncated=False,
            exit_code=0,
            timed_out=False,
            pid=None,
        )

    monkeypatch.delenv("CERBERUS_DASHBOARD_PROMPT_AGENT", raising=False)
    monkeypatch.delenv("CEREBRO_DASHBOARD_PROMPT_AGENT", raising=False)
    monkeypatch.delenv("CERBERUS_AGENT_TYPE", raising=False)
    monkeypatch.delenv("CEREBRO_AGENT_TYPE", raising=False)
    monkeypatch.setenv(env_key, "reasoner")
    monkeypatch.setattr("cerberus.main.run_streaming_subprocess", _fake_run_streaming_subprocess)

    output, handled = await _invoke_streamable_tool(
        "run_supervised_prompt",
        {"prompt": "Hello"},
        None,
        project_root=tmp_path,
        workspaces_root=tmp_path / "workspaces",
    )

    assert handled is True
    assert output == "Hello from the LLM"
    assert captured["env"][_PROMPT_DISPATCH_GLOBAL_AGENT_ENV] == "reasoner"
    assert captured["env"][_PROMPT_DISPATCH_AGENT_ENV] == "reasoner"


@pytest.mark.asyncio
async def test_invoke_streamable_tool_respects_dashboard_prompt_agent_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    captured: dict[str, object] = {}

    async def _fake_run_streaming_subprocess(**kwargs):
        captured.update(kwargs)
        return StreamedSubprocessResult(
            stdout="Hello from the LLM\n",
            stderr="",
            stdout_truncated=False,
            stderr_truncated=False,
            exit_code=0,
            timed_out=False,
            pid=None,
        )

    monkeypatch.setenv("CERBERUS_DASHBOARD_PROMPT_AGENT", "reasoner")
    monkeypatch.setattr("cerberus.main.run_streaming_subprocess", _fake_run_streaming_subprocess)

    output, handled = await _invoke_streamable_tool(
        "run_supervised_prompt",
        {"prompt": "Hello"},
        None,
        project_root=tmp_path,
        workspaces_root=tmp_path / "workspaces",
    )

    assert handled is True
    assert output == "Hello from the LLM"
    assert captured["env"][_PROMPT_DISPATCH_GLOBAL_AGENT_ENV] == "reasoner"


@pytest.mark.asyncio
@pytest.mark.parametrize("env_key", ["CERBERUS_ACTIVE_CONTAINER", "CEREBRO_ACTIVE_CONTAINER"])
async def test_invoke_streamable_tool_uses_container_python_when_active_container_is_set(
    monkeypatch: pytest.MonkeyPatch, tmp_path, env_key: str
) -> None:
    captured: dict[str, object] = {}

    async def _fake_run_streaming_subprocess(**kwargs):
        captured.update(kwargs)
        return StreamedSubprocessResult(
            stdout="Hello from the LLM\n",
            stderr="",
            stdout_truncated=False,
            stderr_truncated=False,
            exit_code=0,
            timed_out=False,
            pid=None,
        )

    monkeypatch.delenv("CERBERUS_ACTIVE_CONTAINER", raising=False)
    monkeypatch.delenv("CEREBRO_ACTIVE_CONTAINER", raising=False)
    monkeypatch.setenv(env_key, "cerberus")
    monkeypatch.setattr("cerberus.main.run_streaming_subprocess", _fake_run_streaming_subprocess)

    output, handled = await _invoke_streamable_tool(
        "run_supervised_prompt",
        {"prompt": "Hello"},
        None,
        project_root=tmp_path,
        workspaces_root=tmp_path / "workspaces",
    )

    assert handled is True
    assert output == "Hello from the LLM"
    assert captured["argv"][0] == _PROMPT_DISPATCH_CONTAINER_PYTHON
    assert captured["env"]["CERBERUS_ACTIVE_CONTAINER"] == "cerberus"
    assert "PYTHONPATH" not in captured["env"]


@pytest.mark.asyncio
async def test_invoke_streamable_tool_uses_explicit_source_root_for_pythonpath_fallback(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    captured: dict[str, object] = {}

    async def _fake_run_streaming_subprocess(**kwargs):
        captured.update(kwargs)
        return StreamedSubprocessResult(
            stdout="Hello from the LLM\n",
            stderr="",
            stdout_truncated=False,
            stderr_truncated=False,
            exit_code=0,
            timed_out=False,
            pid=None,
        )

    monkeypatch.setenv("CERBERUS_SOURCE_ROOT", "/workspace")
    monkeypatch.setattr("cerberus.main.run_streaming_subprocess", _fake_run_streaming_subprocess)

    output, handled = await _invoke_streamable_tool(
        "run_supervised_prompt",
        {"prompt": "Hello"},
        None,
        project_root=tmp_path,
        workspaces_root=tmp_path / "workspaces",
    )

    assert handled is True
    assert output == "Hello from the LLM"
    assert captured["env"]["PYTHONPATH"].split(":")[0] == "/workspace/src"


@pytest.mark.asyncio
async def test_invoke_streamable_tool_bridges_legacy_model_env_for_subprocesses(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    captured: dict[str, object] = {}

    async def _fake_run_streaming_subprocess(**kwargs):
        captured.update(kwargs)
        return StreamedSubprocessResult(
            stdout="Hello from the LLM\n",
            stderr="",
            stdout_truncated=False,
            stderr_truncated=False,
            exit_code=0,
            timed_out=False,
            pid=None,
        )

    monkeypatch.delenv("CERBERUS_MODEL", raising=False)
    monkeypatch.setenv("CEREBRO_MODEL", "Qwen3.5-27B-Aggressive-Q4_K_M")
    monkeypatch.setattr("cerberus.main.run_streaming_subprocess", _fake_run_streaming_subprocess)

    output, handled = await _invoke_streamable_tool(
        "run_supervised_prompt",
        {"prompt": "Hello"},
        None,
        project_root=tmp_path,
        workspaces_root=tmp_path / "workspaces",
    )

    assert handled is True
    assert output == "Hello from the LLM"
    assert captured["env"]["CERBERUS_MODEL"] == "Qwen3.5-27B-Aggressive-Q4_K_M"
