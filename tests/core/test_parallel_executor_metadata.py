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


async def _collect_with_retries(agent: _DummyParallelAgent, attempts: int = 30):
    collected = []
    for _ in range(attempts):
        collected = await agent.collect_parallel_results()
        if collected:
            break
    return collected


@pytest.mark.asyncio
async def test_parallel_executor_preserves_original_arguments_for_two_mcp_calls() -> None:
    await _reset_parallel_executor()

    async def echo_tool(_ctx: RunContextWrapper, arguments: dict) -> dict:
        return {"ok": True, "arguments": arguments}

    agent = _DummyParallelAgent()
    context = RunContextWrapper(context=None)

    first_args = {
        "target": "10.10.10.10",
        "scan_type": "top-1000",
        "original_arguments": '{"target":"10.10.10.10","scan_type":"top-1000"}',
    }
    second_args = {
        "interface": "eth0",
        "duration": 30,
        "original_arguments": '{"interface":"eth0","duration":30}',
    }

    first_call_id = await agent.submit_parallel_tool(
        tool_name="mcp::nmap-mcp::run_nmap_scan",
        tool_function=echo_tool,
        arguments=first_args,
        context_wrapper=context,
    )
    second_call_id = await agent.submit_parallel_tool(
        tool_name="mcp::wiremcp::capture_packets",
        tool_function=echo_tool,
        arguments=second_args,
        context_wrapper=context,
    )

    collected = await _collect_with_retries(agent)
    assert len(collected) == 2

    by_call_id = {item.raw_item["call_id"]: item for item in collected}
    first_item = by_call_id[first_call_id]
    second_item = by_call_id[second_call_id]

    assert first_item.raw_item["name"] == "mcp::nmap-mcp::run_nmap_scan"
    assert first_item.raw_item["original_arguments"] == '{"target":"10.10.10.10","scan_type":"top-1000"}'
    assert first_item.raw_item["arguments"] == '{"target":"10.10.10.10","scan_type":"top-1000"}'

    assert second_item.raw_item["name"] == "mcp::wiremcp::capture_packets"
    assert second_item.raw_item["original_arguments"] == '{"interface":"eth0","duration":30}'
    assert second_item.raw_item["arguments"] == '{"interface":"eth0","duration":30}'

    await _reset_parallel_executor()


@pytest.mark.asyncio
async def test_parallel_executor_malformed_json_failure_sets_marker_and_preserves_raw_input() -> None:
    await _reset_parallel_executor()

    async def should_not_run(_ctx: RunContextWrapper, _arguments: dict) -> dict:
        return {"ok": True}

    agent = _DummyParallelAgent()
    context = RunContextWrapper(context=None)

    malformed_raw = '{"target":"10.10.10.10",bad_json'
    call_id = await agent.submit_parallel_tool(
        tool_name="mcp::nmap-mcp::run_nmap_scan",
        tool_function=should_not_run,
        arguments={
            "_parse_error": "tool_arguments_malformed_json",
            "_raw_arguments": malformed_raw,
            "original_arguments": malformed_raw,
        },
        context_wrapper=context,
    )

    collected = await _collect_with_retries(agent)
    assert len(collected) == 1

    item = collected[0]
    assert item.raw_item["call_id"] == call_id
    assert item.raw_item["name"] == "mcp::nmap-mcp::run_nmap_scan"
    assert item.raw_item["original_arguments"] == malformed_raw
    assert item.raw_item["arguments"] == malformed_raw

    assert isinstance(item.output, dict)
    assert item.output["error"] == "tool_arguments_malformed_json"
    assert item.output["malformed_json"] is True
    assert "malformed json" in str(item.output["message"]).lower()
    assert item.output["raw_input_preview"] == malformed_raw

    await _reset_parallel_executor()
