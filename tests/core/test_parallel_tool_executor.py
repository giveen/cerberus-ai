from __future__ import annotations

import pytest

import cerberus.agents.parallel_tool_executor as pte
from cerberus.agents.parallel_tool_executor import ParallelToolMixin
from cerberus.agents.run_context import RunContextWrapper


class _DummyParallelAgent(ParallelToolMixin):
    def __init__(self) -> None:
        self.name = "dummy-agent"
        super().__init__()


async def _reset_parallel_executor() -> None:
    executor = pte.get_parallel_tool_executor()
    try:
        await executor.stop()
    except BaseException:
        pass
    pte._global_executor = None


@pytest.mark.asyncio
async def test_parallel_result_preserves_populated_arguments() -> None:
    await _reset_parallel_executor()

    async def fake_tool(_ctx: RunContextWrapper, arguments: dict) -> dict:
        return {"ok": True, "received": arguments}

    agent = _DummyParallelAgent()
    context = RunContextWrapper(context=None)

    tool_call_id = await agent.submit_parallel_tool(
        tool_name="nmap",
        tool_function=fake_tool,
        arguments={"target": "10.0.0.1", "ports": "80,443"},
        context_wrapper=context,
    )

    # Retry collection briefly in case executor completes slightly after submission.
    collected = []
    for _ in range(20):
        collected = await agent.collect_parallel_results()
        if collected:
            break

    assert len(collected) == 1
    item = collected[0]
    assert item.raw_item["call_id"] == tool_call_id
    assert item.raw_item["name"] == "nmap"
    assert item.raw_item["arguments"] == '{"target":"10.0.0.1","ports":"80,443"}'

    await _reset_parallel_executor()


@pytest.mark.asyncio
async def test_parallel_result_preserves_genuine_empty_arguments() -> None:
    await _reset_parallel_executor()

    async def fake_tool(_ctx: RunContextWrapper, arguments: dict) -> str:
        return f"received={arguments}"

    agent = _DummyParallelAgent()
    context = RunContextWrapper(context=None)

    tool_call_id = await agent.submit_parallel_tool(
        tool_name="gobuster",
        tool_function=fake_tool,
        arguments={},
        context_wrapper=context,
    )

    collected = []
    for _ in range(20):
        collected = await agent.collect_parallel_results()
        if collected:
            break

    assert len(collected) == 1
    item = collected[0]
    assert item.raw_item["call_id"] == tool_call_id
    assert item.raw_item["name"] == "gobuster"
    assert item.raw_item["arguments"] == "{}"

    await _reset_parallel_executor()


@pytest.mark.asyncio
async def test_parallel_result_without_metadata_does_not_fabricate_empty_arguments(monkeypatch) -> None:
    await _reset_parallel_executor()

    async def fake_tool(_ctx: RunContextWrapper, arguments: dict) -> str:
        return f"received={arguments}"

    agent = _DummyParallelAgent()
    context = RunContextWrapper(context=None)

    tool_call_id = await agent.submit_parallel_tool(
        tool_name="whois",
        tool_function=fake_tool,
        arguments={"target": "example.com"},
        context_wrapper=context,
    )

    executor = pte.get_parallel_tool_executor()

    async def _missing_metadata(_tool_call_id: str):
        return None

    monkeypatch.setattr(executor, "get_tool_call_metadata", _missing_metadata)

    collected = []
    for _ in range(20):
        collected = await agent.collect_parallel_results()
        if collected:
            break

    assert len(collected) == 1
    item = collected[0]
    assert item.raw_item["name"] == "parallel_tool"
    assert "arguments" not in item.raw_item
    assert item.output == "received={'target': 'example.com'}"

    await _reset_parallel_executor()
