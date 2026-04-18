from __future__ import annotations

import json
from typing import Any, cast

import pytest
from pydantic import BaseModel

from cerberus.parsers import parse_json_lenient, parse_response
from cerberus.agents import (
    Agent,
    MessageOutputItem,
    ModelResponse,
    RunConfig,
    RunContextWrapper,
    RunHooks,
    RunItem,
    Runner,
    ToolCallItem,
    ToolCallOutputItem,
    TResponseInputItem,
    Usage,
)
from cerberus.agents._run_impl import (
    NextStepFinalOutput,
    NextStepHandoff,
    NextStepRunAgain,
    RunImpl,
    SingleStepResult,
)
from cerberus.agents.tool import function_tool

from tests.core.test_responses import (
    get_final_output_message,
    get_function_tool,
    get_function_tool_call,
    get_handoff_tool_call,
    get_text_input_item,
    get_text_message,
)


@pytest.mark.asyncio
async def test_empty_response_is_final_output():
    agent = Agent[None](name="test")
    response = ModelResponse(
        output=[],
        usage=Usage(),
        referenceable_id=None,
    )
    result = await get_execute_result(agent, response)

    assert result.original_input == "hello"
    assert result.generated_items == []
    assert isinstance(result.next_step, NextStepFinalOutput)
    assert result.next_step.output == ""


@pytest.mark.asyncio
async def test_plaintext_agent_no_tool_calls_is_final_output():
    agent = Agent(name="test")
    response = ModelResponse(
        output=[get_text_message("hello_world")],
        usage=Usage(),
        referenceable_id=None,
    )
    result = await get_execute_result(agent, response)

    assert result.original_input == "hello"
    assert len(result.generated_items) == 1
    assert_item_is_message(result.generated_items[0], "hello_world")
    assert isinstance(result.next_step, NextStepFinalOutput)
    assert result.next_step.output == "hello_world"


@pytest.mark.asyncio
async def test_plaintext_agent_no_tool_calls_multiple_messages_is_final_output():
    agent = Agent(name="test")
    response = ModelResponse(
        output=[
            get_text_message("hello_world"),
            get_text_message("bye"),
        ],
        usage=Usage(),
        referenceable_id=None,
    )
    result = await get_execute_result(
        agent,
        response,
        original_input=[
            get_text_input_item("test"),
            get_text_input_item("test2"),
        ],
    )

    assert len(result.original_input) == 2
    assert len(result.generated_items) == 2
    assert_item_is_message(result.generated_items[0], "hello_world")
    assert_item_is_message(result.generated_items[1], "bye")

    assert isinstance(result.next_step, NextStepFinalOutput)
    assert result.next_step.output == "bye"


@pytest.mark.asyncio
async def test_plaintext_agent_with_tool_call_is_run_again():
    agent = Agent(name="test", tools=[get_function_tool(name="test", return_value="123")])
    response = ModelResponse(
        output=[get_text_message("hello_world"), get_function_tool_call("test", "")],
        usage=Usage(),
        referenceable_id=None,
    )
    result = await get_execute_result(agent, response)

    assert result.original_input == "hello"

    # 3 items: new message, tool call, tool result
    assert len(result.generated_items) == 3
    assert isinstance(result.next_step, NextStepRunAgain)

    items = result.generated_items
    assert_item_is_message(items[0], "hello_world")
    assert_item_is_function_tool_call(items[1], "test", None)
    assert_item_is_function_tool_call_output(items[2], "123")

    assert isinstance(result.next_step, NextStepRunAgain)


@pytest.mark.asyncio
async def test_plaintext_agent_legacy_action_json_is_recovered_as_tool_call():
    agent = Agent(
        name="test",
        tools=[get_function_tool(name="verify_target_availability", return_value="reachable")],
    )
    response = ModelResponse(
        output=[
            get_text_message(
                "<think>Need a deterministic reachability check first.</think>\n"
                '{"tool_name":"verify_target_availability","parameters":{"target":"natas0.natas.labs.overthewire.org"}}'
            )
        ],
        usage=Usage(),
        referenceable_id=None,
    )

    result = await get_execute_result(agent, response)

    assert result.original_input == "hello"
    assert len(result.generated_items) == 3
    assert isinstance(result.next_step, NextStepRunAgain)

    items = result.generated_items
    assert_item_is_message(
        items[0],
        "<think>Need a deterministic reachability check first.</think>\n"
        '{"tool_name":"verify_target_availability","parameters":{"target":"natas0.natas.labs.overthewire.org"}}',
    )
    assert_item_is_function_tool_call(
        items[1],
        "verify_target_availability",
        '{"target":"natas0.natas.labs.overthewire.org"}',
    )
    assert_item_is_function_tool_call_output(items[2], "reachable")


@pytest.mark.asyncio
async def test_plaintext_agent_legacy_action_without_tool_name_is_inferred():
    @function_tool(name_override="verify_target_availability")
    def verify_target_availability(
        target: str,
        tcp_ports: list[int] | None = None,
        timeout_seconds: int = 3,
    ) -> str:
        _ = target, tcp_ports, timeout_seconds
        return "reachable"

    agent = Agent(
        name="test",
        tools=[verify_target_availability],
    )
    response = ModelResponse(
        output=[
            get_text_message(
                "<think>Check reachability quickly.</think>\n"
                '{"target":"natas0.natas.labs.overthewire.org","tcp_ports":[80],"timeout_seconds":3}'
            )
        ],
        usage=Usage(),
        referenceable_id=None,
    )

    result = await get_execute_result(agent, response)

    assert result.original_input == "hello"
    assert len(result.generated_items) == 3
    assert isinstance(result.next_step, NextStepRunAgain)

    items = result.generated_items
    assert_item_is_function_tool_call(
        items[1],
        "verify_target_availability",
        '{"target":"natas0.natas.labs.overthewire.org","tcp_ports":[80],"timeout_seconds":3}',
    )
    assert_item_is_function_tool_call_output(items[2], "reachable")


@pytest.mark.asyncio
async def test_multiple_tool_calls():
    agent = Agent(
        name="test",
        tools=[
            get_function_tool(name="test_1", return_value="123"),
            get_function_tool(name="test_2", return_value="456"),
            get_function_tool(name="test_3", return_value="789"),
        ],
    )
    response = ModelResponse(
        output=[
            get_text_message("Hello, world!"),
            get_function_tool_call("test_1"),
            get_function_tool_call("test_2"),
        ],
        usage=Usage(),
        referenceable_id=None,
    )

    result = await get_execute_result(agent, response)
    assert result.original_input == "hello"

    # 5 items: new message, 2 tool calls, 2 tool call outputs
    assert len(result.generated_items) == 5
    assert isinstance(result.next_step, NextStepRunAgain)

    items = result.generated_items
    assert_item_is_message(items[0], "Hello, world!")
    assert_item_is_function_tool_call(items[1], "test_1", None)
    assert_item_is_function_tool_call(items[2], "test_2", None)

    assert isinstance(result.next_step, NextStepRunAgain)


@pytest.mark.asyncio
async def test_handoff_output_leads_to_handoff_next_step():
    agent_1 = Agent(name="test_1")
    agent_2 = Agent(name="test_2")
    agent_3 = Agent(name="test_3", handoffs=[agent_1, agent_2])
    response = ModelResponse(
        output=[get_text_message("Hello, world!"), get_handoff_tool_call(agent_1)],
        usage=Usage(),
        referenceable_id=None,
    )
    result = await get_execute_result(agent_3, response)

    assert isinstance(result.next_step, NextStepHandoff)
    assert result.next_step.new_agent == agent_1

    assert len(result.generated_items) == 3


class Foo(BaseModel):
    bar: str


@pytest.mark.asyncio
async def test_final_output_without_tool_runs_again():
    agent = Agent(name="test", output_type=Foo, tools=[get_function_tool("tool_1", "result")])
    response = ModelResponse(
        output=[get_function_tool_call("tool_1")],
        usage=Usage(),
        referenceable_id=None,
    )
    result = await get_execute_result(agent, response)

    assert isinstance(result.next_step, NextStepRunAgain)
    assert len(result.generated_items) == 2, "expected 2 items: tool call, tool call output"


@pytest.mark.asyncio
async def test_final_output_leads_to_final_output_next_step():
    agent = Agent(name="test", output_type=Foo)
    response = ModelResponse(
        output=[
            get_text_message("Hello, world!"),
            get_final_output_message(Foo(bar="123").model_dump_json()),
        ],
        usage=Usage(),
        referenceable_id=None,
    )
    result = await get_execute_result(agent, response)

    assert isinstance(result.next_step, NextStepFinalOutput)
    assert result.next_step.output == Foo(bar="123")


@pytest.mark.asyncio
async def test_handoff_and_final_output_leads_to_handoff_next_step():
    agent_1 = Agent(name="test_1")
    agent_2 = Agent(name="test_2")
    agent_3 = Agent(name="test_3", handoffs=[agent_1, agent_2], output_type=Foo)
    response = ModelResponse(
        output=[
            get_final_output_message(Foo(bar="123").model_dump_json()),
            get_handoff_tool_call(agent_1),
        ],
        usage=Usage(),
        referenceable_id=None,
    )
    result = await get_execute_result(agent_3, response)

    assert isinstance(result.next_step, NextStepHandoff)
    assert result.next_step.new_agent == agent_1


@pytest.mark.asyncio
async def test_multiple_final_output_leads_to_final_output_next_step():
    agent_1 = Agent(name="test_1")
    agent_2 = Agent(name="test_2")
    agent_3 = Agent(name="test_3", handoffs=[agent_1, agent_2], output_type=Foo)
    response = ModelResponse(
        output=[
            get_final_output_message(Foo(bar="123").model_dump_json()),
            get_final_output_message(Foo(bar="456").model_dump_json()),
        ],
        usage=Usage(),
        referenceable_id=None,
    )
    result = await get_execute_result(agent_3, response)

    assert isinstance(result.next_step, NextStepFinalOutput)
    assert result.next_step.output == Foo(bar="456")


@pytest.mark.asyncio
async def test_runner_blocks_empty_required_tool_args_before_execution():
    call_counter = {"count": 0}

    @function_tool(name_override="required_tool")
    def required_tool(url: str) -> str:
        call_counter["count"] += 1
        return f"fetched {url}"

    agent = Agent(name="test", tools=[required_tool])
    response = ModelResponse(
        output=[get_function_tool_call("required_tool", json.dumps({}))],
        usage=Usage(),
        referenceable_id=None,
    )
    context_wrapper = RunContextWrapper(None)

    result = await get_execute_result(agent, response, context_wrapper=context_wrapper)

    assert call_counter["count"] == 0
    assert isinstance(result.next_step, NextStepRunAgain)
    assert len(result.generated_items) == 2
    assert isinstance(result.original_input, list)
    assert_item_is_function_tool_call(result.generated_items[0], "required_tool")
    assert isinstance(result.generated_items[1], ToolCallOutputItem)
    assert "CRITICAL FAILURE" in result.generated_items[1].raw_item["output"]
    assert context_wrapper.last_tool_validation["tool"] == "required_tool"
    assert context_wrapper.last_tool_validation["empty_arguments"] is True
    assert context_wrapper.last_tool_validation["error"] == "tool_arguments_empty_required_fields"
    assert context_wrapper.last_tool_validation["consecutive_error_count"] == 1
    assert context_wrapper.suppress_next_tool_loop_warning is True

    warning_item = cast(dict[str, Any], result.original_input[-1])
    warning_blocks = cast(list[dict[str, Any]], warning_item["content"])
    assert "[SYSTEM][REFLECT]" in str(warning_blocks[0]["text"])
    assert "You drafted arguments in <think> but failed to include them in the JSON" in str(
        warning_blocks[0]["text"]
    )


@pytest.mark.asyncio
async def test_runner_returns_malformed_json_hint_before_tool_execution():
    call_counter = {"count": 0}

    @function_tool(name_override="required_tool")
    def required_tool(url: str) -> str:
        call_counter["count"] += 1
        return f"fetched {url}"

    agent = Agent(name="test", tools=[required_tool])
    response = ModelResponse(
        output=[get_function_tool_call("required_tool", "!!!TOTALLY_INVALID_ARGS!!!")],
        usage=Usage(),
        referenceable_id=None,
    )
    context_wrapper = RunContextWrapper(None)

    result = await get_execute_result(agent, response, context_wrapper=context_wrapper)

    assert call_counter["count"] == 0
    assert isinstance(result.next_step, NextStepRunAgain)
    assert isinstance(result.generated_items[1], ToolCallOutputItem)
    output_text = str(result.generated_items[1].raw_item["output"])
    assert (
        "Error: Malformed JSON arguments. Please ensure you output a valid JSON object." in output_text
        or "tool_arguments_malformed_json" in output_text
    )
    assert context_wrapper.last_tool_validation["error"] == "tool_arguments_malformed_json"
    assert context_wrapper.last_tool_validation["malformed_json"] is True
    assert result.generated_items[1].raw_item["arguments"] == "!!!TOTALLY_INVALID_ARGS!!!"


@pytest.mark.asyncio
async def test_runner_returns_specific_missing_required_field_hint():
    call_counter = {"count": 0}

    @function_tool(name_override="nmap")
    def nmap(target: str, args: str) -> str:
        call_counter["count"] += 1
        return f"scanned {target} {args}"

    agent = Agent(name="test", tools=[nmap])
    response = ModelResponse(
        output=[get_function_tool_call("nmap", json.dumps({"args": "-p 80"}))],
        usage=Usage(),
        referenceable_id=None,
    )
    context_wrapper = RunContextWrapper(None)

    result = await get_execute_result(agent, response, context_wrapper=context_wrapper)

    assert call_counter["count"] == 0
    assert isinstance(result.next_step, NextStepRunAgain)
    assert isinstance(result.generated_items[1], ToolCallOutputItem)
    assert "Error: Missing required field: 'target'." in str(result.generated_items[1].raw_item["output"])
    assert context_wrapper.last_tool_validation["error"] == "tool_arguments_missing_required_fields"
    assert "target" in context_wrapper.last_tool_validation["missing_required_fields"]


@pytest.mark.asyncio
async def test_format_violation_after_tool_validation_forces_correction_turn():
    agent = Agent(name="test")
    response = ModelResponse(
        output=[get_text_message("plain text without think or json")],
        usage=Usage(),
        referenceable_id=None,
    )
    context_wrapper = RunContextWrapper(
        None,
        last_tool_validation={"tool": "required_tool", "required_fields": ["url"]},
    )

    result = await get_execute_result(agent, response, context_wrapper=context_wrapper)

    assert isinstance(result.next_step, NextStepRunAgain)
    assert isinstance(result.original_input, list)
    warning_item = cast(dict[str, Any], result.original_input[-1])
    warning_blocks = cast(list[dict[str, Any]], warning_item["content"])
    assert "Format Violation" in str(warning_blocks[0]["text"])
    assert context_wrapper.format_correction_count == 1


def test_parse_json_lenient_repairs_markdown_noise_and_trailing_commas():
    parsed = parse_json_lenient(
        "```json\nCOMMITTING_JSON: {\"url\": \"https://example.com\",}\n```"
    )

    assert parsed == {"url": "https://example.com"}


def test_parse_response_accepts_commit_anchor_and_repaired_final_json():
    parsed = parse_response(
        "<think>Schema Sync\nJSON_PREVIEW: {\"status\": \"done\"}</think>\n"
        "COMMITTING_JSON: {\"status\": \"done\",}\n"
        "```json\n{\"status\":\"done\",}\n```"
    )

    assert parsed["has_think_block"] is True
    assert parsed["has_valid_json_object"] is True
    assert parsed["format_violation"] is False
    assert parsed["action_json"] == {"status": "done"}


# === Helpers ===


def assert_item_is_message(item: RunItem, text: str) -> None:
    assert isinstance(item, MessageOutputItem)
    assert item.raw_item.type == "message"
    assert item.raw_item.role == "assistant"
    assert item.raw_item.content[0].type == "output_text"
    assert item.raw_item.content[0].text == text


def assert_item_is_function_tool_call(
    item: RunItem, name: str, arguments: str | None = None
) -> None:
    assert isinstance(item, ToolCallItem)
    assert item.raw_item.type == "function_call"
    assert item.raw_item.name == name
    assert not arguments or item.raw_item.arguments == arguments


def assert_item_is_function_tool_call_output(item: RunItem, output: str) -> None:
    assert isinstance(item, ToolCallOutputItem)
    assert item.raw_item["type"] == "function_call_output"
    assert item.raw_item["output"] == output


async def get_execute_result(
    agent: Agent[Any],
    response: ModelResponse,
    *,
    original_input: str | list[TResponseInputItem] | None = None,
    generated_items: list[RunItem] | None = None,
    hooks: RunHooks[Any] | None = None,
    context_wrapper: RunContextWrapper[Any] | None = None,
    run_config: RunConfig | None = None,
) -> SingleStepResult:
    output_schema = Runner._get_output_schema(agent)
    handoffs = Runner._get_handoffs(agent)

    processed_response = RunImpl.process_model_response(
        agent=agent,
        all_tools=await agent.get_all_tools(),
        response=response,
        output_schema=output_schema,
        handoffs=handoffs,
    )
    return await RunImpl.execute_tools_and_side_effects(
        agent=agent,
        original_input=original_input or "hello",
        new_response=response,
        pre_step_items=generated_items or [],
        processed_response=processed_response,
        output_schema=output_schema,
        hooks=hooks or RunHooks(),
        context_wrapper=context_wrapper or RunContextWrapper(None),
        run_config=run_config or RunConfig(),
    )
