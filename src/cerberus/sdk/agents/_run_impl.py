from __future__ import annotations

import asyncio
import dataclasses
import inspect
import json
import os
from collections.abc import Awaitable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, cast

from openai.types.responses import (
    ResponseComputerToolCall,
    ResponseFileSearchToolCall,
    ResponseFunctionToolCall,
    ResponseFunctionWebSearch,
    ResponseOutputMessage,
)
from openai.types.responses.response_computer_tool_call import (
    ActionClick,
    ActionDoubleClick,
    ActionDrag,
    ActionKeypress,
    ActionMove,
    ActionScreenshot,
    ActionScroll,
    ActionType,
    ActionWait,
)
from openai.types.responses.response_input_param import ComputerCallOutput
from openai.types.responses.response_reasoning_item import ResponseReasoningItem

from cerberus.parsers import parse_json_lenient, parse_response

from .agent import Agent, ToolsToFinalOutputResult
from .agent_output import AgentOutputSchema
from .computer import AsyncComputer, Computer
from .exceptions import AgentsException, ModelBehaviorError, UserError
from .guardrail import InputGuardrail, InputGuardrailResult, OutputGuardrail, OutputGuardrailResult
from .handoffs import Handoff, HandoffInputData
from .items import (
    HandoffCallItem,
    HandoffOutputItem,
    ItemHelpers,
    MessageOutputItem,
    ModelResponse,
    ReasoningItem,
    RunItem,
    ToolCallItem,
    ToolCallOutputItem,
    TResponseInputItem,
)
from .lifecycle import RunHooks
from .logger import logger
from .model_settings import ModelSettings
from .models.interface import ModelTracing
from .run_context import RunContextWrapper, TContext
from .stream_events import RunItemStreamEvent, StreamEvent
from .tool import (
    ComputerTool,
    FunctionTool,
    FunctionToolResult,
    Tool,
    _build_schema_retry_hint,
    _missing_required_fields,
    _required_fields_from_schema,
)
from .tracing import (
    SpanError,
    Trace,
    function_span,
    get_current_trace,
    guardrail_span,
    handoff_span,
    trace,
)
from .util import _coro, _error_tracing

if TYPE_CHECKING:
    from .run import RunConfig


class QueueCompleteSentinel:
    pass


QUEUE_COMPLETE_SENTINEL = QueueCompleteSentinel()

_NOT_FINAL_OUTPUT = ToolsToFinalOutputResult(is_final_output=False, final_output=None)


def truncate_output(output: Any, max_length: int = 0) -> str:
    """Truncate tool output before feeding follow-up model turns.

    Uses environment-configured bounds by default and preserves head/tail context
    with a concise truncation summary.
    """
    configured_max = int(os.getenv("CERBERUS_TOOL_OUTPUT_MODEL_MAX_CHARS", "6000"))
    limit = max_length if max_length and max_length > 0 else configured_max
    limit = max(1000, int(limit))

    output_str = str(output)
    if len(output_str) <= limit:
        return output_str

    head = max(500, min(limit // 2, int(os.getenv("CERBERUS_TOOL_OUTPUT_MODEL_HEAD_CHARS", "2500"))))
    tail = max(500, min(limit - head, int(os.getenv("CERBERUS_TOOL_OUTPUT_MODEL_TAIL_CHARS", "2500"))))
    omitted = max(0, len(output_str) - head - tail)
    line_count = output_str.count("\n") + 1 if output_str else 0

    return (
        output_str[:head]
        + f"\n\n...[TRUNCATED: omitted {omitted} chars across ~{line_count} lines for context safety]...\n\n"
        + output_str[-tail:]
    )

@dataclass
class AgentToolUseTracker:
    agent_to_tools: list[tuple[Agent, list[str]]] = field(default_factory=list)
    """Tuple of (agent, list of tools used). Can't use a dict because agents aren't hashable."""

    def add_tool_use(self, agent: Agent[Any], tool_names: list[str]) -> None:
        existing_data = next((item for item in self.agent_to_tools if item[0] == agent), None)
        if existing_data:
            existing_data[1].extend(tool_names)
        else:
            self.agent_to_tools.append((agent, tool_names))

    def has_used_tools(self, agent: Agent[Any]) -> bool:
        existing_data = next((item for item in self.agent_to_tools if item[0] == agent), None)
        return existing_data is not None and len(existing_data[1]) > 0


@dataclass
class ToolRunHandoff:
    handoff: Handoff
    tool_call: ResponseFunctionToolCall


@dataclass
class ToolRunFunction:
    tool_call: ResponseFunctionToolCall
    function_tool: FunctionTool


@dataclass
class ToolRunComputerAction:
    tool_call: ResponseComputerToolCall
    computer_tool: ComputerTool


@dataclass
class ProcessedResponse:
    new_items: list[RunItem]
    handoffs: list[ToolRunHandoff]
    functions: list[ToolRunFunction]
    computer_actions: list[ToolRunComputerAction]
    missing_functions: list[ResponseFunctionToolCall]
    tools_used: list[str]  # Names of all tools used, including hosted tools

    def has_tools_to_run(self) -> bool:
        # Handoffs, functions and computer actions need local processing
        # Hosted tools have already run, so there's nothing to do.
        return any(
            [
                self.handoffs,
                self.functions,
                self.computer_actions,
                self.missing_functions,
            ]
        )


def _parse_legacy_tool_parameters(action: dict[str, Any]) -> dict[str, Any] | None:
    """Extract legacy tool parameters from a structured action payload."""
    for key in ("parameters", "params", "arguments"):
        value = action.get(key)
        if isinstance(value, dict):
            return value
        if isinstance(value, str) and value.strip():
            try:
                parsed = parse_json_lenient(value, prefer_last=True)
            except ValueError:
                continue
            if isinstance(parsed, dict):
                return parsed
    return None


def _infer_legacy_tool_name_from_parameters(
    parameters: dict[str, Any],
    function_map: dict[str, FunctionTool],
) -> str | None:
    """Infer a tool name from argument keys when legacy payload omits tool metadata."""
    if not isinstance(parameters, dict) or not parameters:
        return None

    candidate_name: str | None = None
    candidate_score = -1

    for tool_name, function_tool in function_map.items():
        schema = function_tool.params_json_schema if isinstance(function_tool.params_json_schema, dict) else {}
        properties = schema.get("properties", {}) if isinstance(schema.get("properties", {}), dict) else {}
        required_fields = schema.get("required", []) if isinstance(schema.get("required", []), list) else []

        property_names = {field for field in properties.keys() if isinstance(field, str)}
        required_names = {field for field in required_fields if isinstance(field, str)}
        parameter_names = {field for field in parameters.keys() if isinstance(field, str)}

        if not required_names.issubset(parameter_names):
            continue
        if not parameter_names.issubset(property_names):
            continue

        score = len(parameter_names)
        if score > candidate_score:
            candidate_name = tool_name
            candidate_score = score
        elif score == candidate_score:
            # Ambiguous match; avoid guessing when multiple tools look equivalent.
            candidate_name = None

    return candidate_name


@dataclass
class NextStepHandoff:
    new_agent: Agent[Any]


@dataclass
class NextStepFinalOutput:
    output: Any


@dataclass
class NextStepRunAgain:
    pass


@dataclass
class SingleStepResult:
    original_input: str | list[TResponseInputItem]
    """The input items i.e. the items before run() was called. May be mutated by handoff input
    filters."""

    model_response: ModelResponse
    """The model response for the current step."""

    pre_step_items: list[RunItem]
    """Items generated before the current step."""

    new_step_items: list[RunItem]
    """Items generated during this current step."""

    next_step: NextStepHandoff | NextStepFinalOutput | NextStepRunAgain
    """The next step to take."""

    @property
    def generated_items(self) -> list[RunItem]:
        """Items generated during the agent run (i.e. everything generated after
        `original_input`)."""
        return self.pre_step_items + self.new_step_items


def get_model_tracing_impl(
    tracing_disabled: bool, trace_include_sensitive_data: bool
) -> ModelTracing:
    if tracing_disabled:
        return ModelTracing.DISABLED
    elif trace_include_sensitive_data:
        return ModelTracing.ENABLED
    else:
        return ModelTracing.ENABLED_WITHOUT_DATA


class RunImpl:
    _FORMAT_CORRECTION_MESSAGE = (
        "ERROR: Format Violation. You MUST start with <think> and end with JSON. "
        "Do not provide conversational text."
    )

    @classmethod
    def _build_format_correction_message(
        cls, format_error: str | None, correction_count: int
    ) -> str:
        message = [cls._FORMAT_CORRECTION_MESSAGE]

        if format_error == "missing_think_block":
            message.append("Your last response omitted the required <think> block.")
        elif format_error == "missing_valid_json":
            message.append("Your last response did not end with one valid JSON object.")
        elif format_error == "missing_think_and_json":
            message.append("Your last response omitted both the <think> block and the final JSON object.")
        elif format_error == "invalid_json":
            message.append("Your last response ended with malformed JSON.")
        elif format_error == "invalid_json_object":
            message.append("Your last response did not end with a JSON object.")

        if correction_count > 1:
            message.append(f"This is format correction attempt {correction_count}.")

        message.append("Return only <think>...</think> followed by one JSON object.")
        return " ".join(message)

    @classmethod
    def _format_correction_input_item(
        cls, format_error: str | None, correction_count: int
    ) -> TResponseInputItem:
        return {
            "role": "user",
            "content": [
                {
                    "type": "input_text",
                    "text": cls._build_format_correction_message(format_error, correction_count),
                }
            ],
        }

    @staticmethod
    def _reflect_input_item(message: str) -> TResponseInputItem:
        return {
            "role": "user",
            "content": [{"type": "input_text", "text": f"[SYSTEM][REFLECT] {message}"}],
        }

    @staticmethod
    def _input_contains_system_warning(original_input: str | list[TResponseInputItem]) -> bool:
        if isinstance(original_input, str):
            return False

        for item in original_input:
            if not isinstance(item, dict):
                continue
            content = item.get("content")
            if isinstance(content, str) and (
                "[SYSTEM]" in content or "[REFLECT]" in content or "Format Violation" in content
            ):
                return True
            if isinstance(content, list):
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    text = str(block.get("text", ""))
                    if "[SYSTEM]" in text or "[REFLECT]" in text or "Format Violation" in text:
                        return True
        return False

    @staticmethod
    def _reset_consecutive_error_state(context_wrapper: RunContextWrapper[Any]) -> None:
        context_wrapper.last_tool_error_signature = ""
        context_wrapper.consecutive_tool_error_count = 0

    @staticmethod
    def _record_consecutive_error(
        context_wrapper: RunContextWrapper[Any], error_signature: str
    ) -> int:
        if error_signature == context_wrapper.last_tool_error_signature:
            context_wrapper.consecutive_tool_error_count += 1
        else:
            context_wrapper.last_tool_error_signature = error_signature
            context_wrapper.consecutive_tool_error_count = 1
        return context_wrapper.consecutive_tool_error_count

    @staticmethod
    def _schema_template_json(validation: dict[str, Any]) -> str:
        template = validation.get("suggested_arguments_json")
        if isinstance(template, str) and template.strip():
            return template
        return "{}"

    @classmethod
    def _build_argument_reflect_message(
        cls,
        *,
        tool_name: str,
        validation: dict[str, Any],
        consecutive_error_count: int,
    ) -> str:
        required_fields = validation.get("required_fields")
        message = [
            "CRITICAL: You drafted arguments in <think> but failed to include them in the JSON.",
            "Your previous JSON was {}.",
            f"Tool: {tool_name}.",
            "RE-EMIT the tool call with the values you just drafted.",
        ]

        if isinstance(required_fields, list) and required_fields:
            message.append(
                "Required fields: " + ", ".join(str(field) for field in required_fields) + "."
            )
        if consecutive_error_count > 1:
            message.append(f"ConsecutiveError={consecutive_error_count}.")

        return " ".join(message)

    @classmethod
    def _build_schema_template_message(
        cls,
        *,
        tool_name: str,
        validation: dict[str, Any],
    ) -> str:
        return (
            "ERROR: You are failing to populate JSON. "
            f"Use this exact template for {tool_name}: {cls._schema_template_json(validation)}"
        )

    @classmethod
    def _build_runner_tool_validation_error(
        cls,
        *,
        tool_name: str,
        raw_arguments: str,
        params_json_schema: dict[str, Any],
        missing_fields: list[str],
        empty_args: bool,
    ) -> dict[str, Any]:
        required_fields = _required_fields_from_schema(params_json_schema)
        fields_text = ", ".join(required_fields) if required_fields else "(none declared)"
        retry_hint = _build_schema_retry_hint(tool_name, params_json_schema)

        if empty_args:
            message = (
                f"CRITICAL FAILURE: You provided empty arguments for {tool_name}. "
                f"You must re-read the tool schema. Required fields are: {fields_text}. "
                "Repeat the call with ALL fields populated."
            )
            error_code = "tool_arguments_empty_required_fields"
        else:
            message = (
                f"CRITICAL FAILURE: Tool call for {tool_name} is missing required arguments: "
                f"{', '.join(missing_fields)}. You must re-read the tool schema. "
                f"Required fields are: {fields_text}. Repeat the call with ALL fields populated."
            )
            error_code = "tool_arguments_missing_required_fields"

        return {
            "ok": False,
            "error": error_code,
            "tool": tool_name,
            "message": message,
            **retry_hint,
            "missing_required_fields": missing_fields,
            "required_fields": required_fields,
            "empty_arguments": empty_args,
            "raw_input_preview": raw_arguments[:800],
        }

    @classmethod
    def _validate_tool_args(
        cls,
        *,
        tool_name: str,
        raw_arguments: str,
        params_json_schema: dict[str, Any],
    ) -> dict[str, Any] | None:
        required_fields = _required_fields_from_schema(params_json_schema)
        normalized_arguments = raw_arguments.strip() if isinstance(raw_arguments, str) else ""

        if not required_fields:
            return None

        if not normalized_arguments:
            return cls._build_runner_tool_validation_error(
                tool_name=tool_name,
                raw_arguments="",
                params_json_schema=params_json_schema,
                missing_fields=list(required_fields),
                empty_args=True,
            )

        try:
            parsed_arguments = parse_json_lenient(normalized_arguments, prefer_last=True)
        except ValueError:
            return None

        if not isinstance(parsed_arguments, dict) or not parsed_arguments:
            return cls._build_runner_tool_validation_error(
                tool_name=tool_name,
                raw_arguments=normalized_arguments,
                params_json_schema=params_json_schema,
                missing_fields=list(required_fields),
                empty_args=True,
            )

        missing_fields = _missing_required_fields(parsed_arguments, params_json_schema)
        if missing_fields:
            return cls._build_runner_tool_validation_error(
                tool_name=tool_name,
                raw_arguments=normalized_arguments,
                params_json_schema=params_json_schema,
                missing_fields=missing_fields,
                empty_args=False,
            )

        return None

    @classmethod
    async def execute_tools_and_side_effects(
        cls,
        *,
        agent: Agent[TContext],
        # The original input to the Runner
        original_input: str | list[TResponseInputItem],
        # Everything generated by Runner since the original input, but before the current step
        pre_step_items: list[RunItem],
        new_response: ModelResponse,
        processed_response: ProcessedResponse,
        output_schema: AgentOutputSchema | None,
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        run_config: RunConfig,
    ) -> SingleStepResult:
        # Make a copy of the generated items
        pre_step_items = list(pre_step_items)

        new_step_items: list[RunItem] = []
        new_step_items.extend(processed_response.new_items)

        # First, lets run the tool calls - function tools and computer actions
        # Create tasks separately so we can handle partial results
        function_task = asyncio.create_task(
            cls.execute_function_tool_calls(
                agent=agent,
                tool_runs=processed_response.functions,
                hooks=hooks,
                context_wrapper=context_wrapper,
                config=run_config,
            )
        )
        computer_task = asyncio.create_task(
            cls.execute_computer_actions(
                agent=agent,
                actions=processed_response.computer_actions,
                hooks=hooks,
                context_wrapper=context_wrapper,
                config=run_config,
            )
        )
        
        function_results = []
        computer_results = []
        interrupt_exception = None
        
        try:
            function_results, computer_results = await asyncio.gather(
                function_task, computer_task
            )
        except (KeyboardInterrupt, asyncio.CancelledError) as e:
            interrupt_exception = e
            
            # Try to get partial results from the tasks
            if function_task.done() and not function_task.cancelled():
                try:
                    function_results = function_task.result()
                except Exception:
                    # If the task failed, create synthetic results
                    function_results = []
                    for tool_run in processed_response.functions:
                        result = FunctionToolResult(
                            tool=tool_run.function_tool,
                            output="Tool execution interrupted",
                            run_item=ToolCallOutputItem(
                                output="Tool execution interrupted",
                                raw_item=ItemHelpers.tool_call_output_item(
                                    tool_run.tool_call, "Tool execution interrupted"
                                ),
                                agent=agent,
                            ),
                        )
                        function_results.append(result)
            else:
                # Task was cancelled or not done, create synthetic results
                function_results = []
                for tool_run in processed_response.functions:
                    result = FunctionToolResult(
                        tool=tool_run.function_tool,
                        output="Tool execution interrupted",
                        run_item=ToolCallOutputItem(
                            output="Tool execution interrupted",
                            raw_item=ItemHelpers.tool_call_output_item(
                                tool_run.tool_call, "Tool execution interrupted"
                            ),
                            agent=agent,
                        ),
                    )
                    function_results.append(result)
                    
            if computer_task.done() and not computer_task.cancelled():
                try:
                    computer_results = computer_task.result()
                except Exception:
                    computer_results = []
            else:
                computer_results = []
            
        new_step_items.extend([result.run_item for result in function_results])
        new_step_items.extend(computer_results)

        empty_arg_validation = cls._extract_empty_argument_validation(function_results)
        if empty_arg_validation is not None:
            corrected_input = ItemHelpers.input_to_new_input_list(original_input)
            reflect_message = empty_arg_validation.get("reflect_message")
            if isinstance(reflect_message, str) and reflect_message.strip():
                corrected_input.append(cls._reflect_input_item(reflect_message))

            if int(empty_arg_validation.get("consecutive_error_count", 0) or 0) >= 3:
                schema_template_message = empty_arg_validation.get("schema_template_message")
                if isinstance(schema_template_message, str) and schema_template_message.strip():
                    corrected_input.append(cls._reflect_input_item(schema_template_message))

            context_wrapper.suppress_next_tool_loop_warning = True
            return SingleStepResult(
                original_input=corrected_input,
                model_response=new_response,
                pre_step_items=pre_step_items,
                new_step_items=new_step_items,
                next_step=NextStepRunAgain(),
            )

        # Surface unknown tool calls back to the model as tool outputs so the run can continue.
        for missing_call in processed_response.missing_functions:
            missing_message = (
                f"Tool {missing_call.name} is not available for agent {agent.name}. "
                "Choose one of the tools exposed in this turn."
            )
            new_step_items.append(
                ToolCallOutputItem(
                    output=missing_message,
                    raw_item=ItemHelpers.tool_call_output_item(missing_call, missing_message),
                    agent=agent,
                )
            )
        
        # Re-raise the interruption after ensuring results are added
        if interrupt_exception:
            raise interrupt_exception

        # Second, check if there are any handoffs
        if run_handoffs := processed_response.handoffs:
            return await cls.execute_handoffs(
                agent=agent,
                original_input=original_input,
                pre_step_items=pre_step_items,
                new_step_items=new_step_items,
                new_response=new_response,
                run_handoffs=run_handoffs,
                hooks=hooks,
                context_wrapper=context_wrapper,
                run_config=run_config,
            )

        # Third, we'll check if the tool use should result in a final output
        check_tool_use = await cls._check_for_final_output_from_tools(
            agent=agent,
            tool_results=function_results,
            context_wrapper=context_wrapper,
            config=run_config,
        )

        if check_tool_use.is_final_output:
            # If the output type is str, then let's just stringify it
            if not agent.output_type or agent.output_type is str:
                check_tool_use.final_output = str(check_tool_use.final_output)

            if check_tool_use.final_output is None:
                logger.error(
                    "Model returned a final output of None. Not raising an error because we assume"
                    "you know what you're doing."
                )

            return await cls.execute_final_output(
                agent=agent,
                original_input=original_input,
                new_response=new_response,
                pre_step_items=pre_step_items,
                new_step_items=new_step_items,
                final_output=check_tool_use.final_output,
                hooks=hooks,
                context_wrapper=context_wrapper,
            )

        # Now we can check if the model also produced a final output
        message_items = [item for item in new_step_items if isinstance(item, MessageOutputItem)]
        reasoning_items = [item for item in new_step_items if isinstance(item, ReasoningItem)]

        # We'll use the last content output as the final output
        potential_final_output_text = (
            ItemHelpers.extract_last_text(message_items[-1].raw_item) if message_items else None
        )
        potential_reasoning_output_text = (
            ItemHelpers.text_reasoning_output(reasoning_items[-1]).strip()
            if reasoning_items
            else ""
        )

        # There are two possibilities that lead to a final output:
        # 1. Structured output schema => always leads to a final output
        # 2. Plain text output schema => only leads to a final output if there are no tool calls
        if output_schema and not output_schema.is_plain_text() and potential_final_output_text:
            final_output = output_schema.validate_json(potential_final_output_text)
            return await cls.execute_final_output(
                agent=agent,
                original_input=original_input,
                new_response=new_response,
                pre_step_items=pre_step_items,
                new_step_items=new_step_items,
                final_output=final_output,
                hooks=hooks,
                context_wrapper=context_wrapper,
            )
        elif (
            not output_schema or output_schema.is_plain_text()
        ) and not processed_response.has_tools_to_run():
            candidate_output = potential_final_output_text or potential_reasoning_output_text or ""
            parsed_output = parse_response(candidate_output)
            should_force_format_correction = (
                context_wrapper.format_correction_count > 0
                or bool(context_wrapper.last_tool_validation)
                or cls._input_contains_system_warning(original_input)
                or candidate_output.lstrip().startswith("{")
            )
            if should_force_format_correction and parsed_output.get("format_violation"):
                context_wrapper.format_correction_count += 1
                corrected_input = ItemHelpers.input_to_new_input_list(original_input)
                corrected_input.append(
                    cls._format_correction_input_item(
                        cast(str | None, parsed_output.get("format_error")),
                        context_wrapper.format_correction_count,
                    )
                )
                return SingleStepResult(
                    original_input=corrected_input,
                    model_response=new_response,
                    pre_step_items=pre_step_items,
                    new_step_items=new_step_items,
                    next_step=NextStepRunAgain(),
                )

            context_wrapper.format_correction_count = 0

            return await cls.execute_final_output(
                agent=agent,
                original_input=original_input,
                new_response=new_response,
                pre_step_items=pre_step_items,
                new_step_items=new_step_items,
                final_output=potential_final_output_text or potential_reasoning_output_text,
                hooks=hooks,
                context_wrapper=context_wrapper,
            )
        else:
            # If there's no final output, we can just run again
            return SingleStepResult(
                original_input=original_input,
                model_response=new_response,
                pre_step_items=pre_step_items,
                new_step_items=new_step_items,
                next_step=NextStepRunAgain(),
            )

    @staticmethod
    def _extract_empty_argument_validation(
        tool_results: list[FunctionToolResult],
    ) -> dict[str, Any] | None:
        for tool_result in tool_results:
            output = tool_result.output
            if (
                isinstance(output, dict)
                and output.get("empty_arguments") is True
                and str(output.get("error", "")).startswith("tool_arguments_")
            ):
                return output
        return None

    @classmethod
    def maybe_reset_tool_choice(
        cls, agent: Agent[Any], tool_use_tracker: AgentToolUseTracker, model_settings: ModelSettings
    ) -> ModelSettings:
        """Resets tool choice to None if the agent has used tools and the agent's reset_tool_choice
        flag is True."""

        if agent.reset_tool_choice is True and tool_use_tracker.has_used_tools(agent):
            return dataclasses.replace(model_settings, tool_choice=None)

        return model_settings

    @classmethod
    def process_model_response(
        cls,
        *,
        agent: Agent[Any],
        all_tools: list[Tool],
        response: ModelResponse,
        output_schema: AgentOutputSchema | None,
        handoffs: list[Handoff],
        allow_missing_tools: bool = False,
    ) -> ProcessedResponse:
        items: list[RunItem] = []

        run_handoffs = []
        functions = []
        computer_actions = []
        missing_functions = []
        tools_used: list[str] = []
        handoff_map = {handoff.tool_name: handoff for handoff in handoffs}
        function_map = {tool.name: tool for tool in all_tools if isinstance(tool, FunctionTool)}
        computer_tool = next((tool for tool in all_tools if isinstance(tool, ComputerTool)), None)
        has_native_function_calls = any(
            isinstance(output, ResponseFunctionToolCall) for output in response.output
        )
        legacy_tool_calls_by_name: dict[str, list[ResponseFunctionToolCall]] = {}

        if has_native_function_calls:
            for output in response.output:
                if not isinstance(output, ResponseOutputMessage):
                    continue
                legacy_tool_call = cls._extract_legacy_tool_call(
                    agent=agent,
                    function_map=function_map,
                    message=output,
                )
                if legacy_tool_call is None:
                    continue
                legacy_tool_calls_by_name.setdefault(legacy_tool_call.name, []).append(legacy_tool_call)

        for output in response.output:
            if isinstance(output, ResponseOutputMessage):
                items.append(MessageOutputItem(raw_item=output, agent=agent))
                if not has_native_function_calls:
                    legacy_tool_call = cls._extract_legacy_tool_call(
                        agent=agent,
                        function_map=function_map,
                        message=output,
                    )
                    if legacy_tool_call is not None:
                        items.append(ToolCallItem(raw_item=legacy_tool_call, agent=agent))
                        functions.append(
                            ToolRunFunction(
                                tool_call=legacy_tool_call,
                                function_tool=function_map[legacy_tool_call.name],
                            )
                        )
                        tools_used.append(legacy_tool_call.name)
            elif isinstance(output, ResponseFileSearchToolCall):
                items.append(ToolCallItem(raw_item=output, agent=agent))
                tools_used.append("file_search")
            elif isinstance(output, ResponseFunctionWebSearch):
                items.append(ToolCallItem(raw_item=output, agent=agent))
                tools_used.append("web_search")
            elif isinstance(output, ResponseReasoningItem):
                items.append(ReasoningItem(raw_item=output, agent=agent))
            elif isinstance(output, ResponseComputerToolCall):
                items.append(ToolCallItem(raw_item=output, agent=agent))
                tools_used.append("computer_use")
                if not computer_tool:
                    _error_tracing.attach_error_to_current_span(
                        SpanError(
                            message="Computer tool not found",
                            data={},
                        )
                    )
                    raise ModelBehaviorError(
                        "Model produced computer action without a computer tool."
                    )
                computer_actions.append(
                    ToolRunComputerAction(tool_call=output, computer_tool=computer_tool)
                )
            elif not isinstance(output, ResponseFunctionToolCall):
                logger.warning(f"Unexpected output type, ignoring: {type(output)}")
                continue

            # At this point we know it's a function tool call
            if not isinstance(output, ResponseFunctionToolCall):
                continue

            hydrated_output = output
            if cls._tool_call_has_empty_arguments(output.arguments):
                legacy_candidates = legacy_tool_calls_by_name.get(output.name) or []
                if legacy_candidates:
                    hydrated_output = cls._copy_tool_call_with_arguments(
                        output,
                        legacy_candidates.pop(0).arguments,
                    )

            tools_used.append(hydrated_output.name)

            # Handoffs
            if hydrated_output.name in handoff_map:
                items.append(HandoffCallItem(raw_item=hydrated_output, agent=agent))
                handoff = ToolRunHandoff(
                    tool_call=hydrated_output,
                    handoff=handoff_map[hydrated_output.name],
                )
                run_handoffs.append(handoff)
            # Regular function tool call
            else:
                if hydrated_output.name not in function_map:
                    logger.warning(
                        "Model requested unavailable tool '%s' for agent '%s'",
                        hydrated_output.name,
                        agent.name,
                    )
                    items.append(ToolCallItem(raw_item=hydrated_output, agent=agent))
                    missing_functions.append(hydrated_output)
                    continue

                items.append(ToolCallItem(raw_item=hydrated_output, agent=agent))
                functions.append(
                    ToolRunFunction(
                        tool_call=hydrated_output,
                        function_tool=function_map[hydrated_output.name],
                    )
                )

        if missing_functions and not allow_missing_tools:
            missing_names = ", ".join(
                sorted({str(tool_call.name) for tool_call in missing_functions if getattr(tool_call, "name", None)})
            )
            raise ModelBehaviorError(
                f"Model requested unavailable tool(s) {missing_names or '<unknown>'} for agent {agent.name}"
            )

        return ProcessedResponse(
            new_items=items,
            handoffs=run_handoffs,
            functions=functions,
            computer_actions=computer_actions,
            missing_functions=missing_functions,
            tools_used=tools_used,
        )

    @staticmethod
    def _extract_legacy_tool_call(
        *,
        agent: Agent[Any],
        function_map: dict[str, FunctionTool],
        message: ResponseOutputMessage,
    ) -> ResponseFunctionToolCall | None:
        """Recover a tool call from legacy action JSON embedded in assistant text."""
        message_text = (ItemHelpers.extract_last_text(message) or "").strip()
        if not message_text:
            return None

        parsed = parse_response(message_text)
        action = parsed.get("action_json")
        if not isinstance(action, dict):
            return None

        tool_name = str(
            action.get("tool_name")
            or action.get("tool")
            or action.get("name")
            or ""
        ).strip()
        parameters = _parse_legacy_tool_parameters(action)
        if parameters is None:
            known_meta_fields = {
                "tool_name",
                "tool",
                "name",
                "status",
                "message",
                "format_violation",
                "format_error",
                "format_correction_message",
                "raw_action_json",
                "parse_error",
            }
            parameters = {
                key: value
                for key, value in action.items()
                if key not in known_meta_fields
            }

        if not tool_name:
            tool_name = _infer_legacy_tool_name_from_parameters(parameters, function_map) or ""

        if not tool_name or tool_name not in function_map:
            return None
        if not isinstance(parameters, dict) or not parameters:
            return None

        message_id = str(getattr(message, "id", "") or "legacy_message")
        call_id = f"legacy_{message_id}_{tool_name}"
        return ResponseFunctionToolCall(
            id=f"legacy_call_{message_id}_{tool_name}",
            call_id=call_id,
            type="function_call",
            name=tool_name,
            arguments=json.dumps(parameters, ensure_ascii=True, sort_keys=True, separators=(",", ":")),
        )

    @staticmethod
    def _tool_call_has_empty_arguments(raw_arguments: str | None) -> bool:
        if raw_arguments is None:
            return True

        stripped = str(raw_arguments).strip()
        if not stripped:
            return True

        try:
            parsed = parse_json_lenient(stripped)
        except Exception:
            return False
        return isinstance(parsed, dict) and not parsed

    @staticmethod
    def _copy_tool_call_with_arguments(
        tool_call: ResponseFunctionToolCall,
        arguments: str,
    ) -> ResponseFunctionToolCall:
        try:
            return tool_call.model_copy(update={"arguments": arguments})
        except Exception:
            kwargs: dict[str, Any] = {
                "id": tool_call.id,
                "call_id": tool_call.call_id,
                "type": "function_call",
                "name": tool_call.name,
                "arguments": arguments,
            }
            status = getattr(tool_call, "status", None)
            if status is not None:
                kwargs["status"] = status
            return ResponseFunctionToolCall(**kwargs)

    @classmethod
    async def execute_function_tool_calls(
        cls,
        *,
        agent: Agent[TContext],
        tool_runs: list[ToolRunFunction],
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        config: RunConfig,
    ) -> list[FunctionToolResult]:
        async def run_single_tool(
            func_tool: FunctionTool, tool_call: ResponseFunctionToolCall
        ) -> Any:
            with function_span(func_tool.name) as span_fn:
                if config.trace_include_sensitive_data:
                    span_fn.span_data.input = tool_call.arguments
                try:
                    _, _, result = await asyncio.gather(
                        hooks.on_tool_start(context_wrapper, agent, func_tool),
                        (
                            agent.hooks.on_tool_start(context_wrapper, agent, func_tool)
                            if agent.hooks
                            else _coro.noop_coroutine()
                        ),
                        func_tool.on_invoke_tool(context_wrapper, tool_call.arguments),
                    )

                    await asyncio.gather(
                        hooks.on_tool_end(context_wrapper, agent, func_tool, result),
                        (
                            agent.hooks.on_tool_end(context_wrapper, agent, func_tool, result)
                            if agent.hooks
                            else _coro.noop_coroutine()
                        ),
                    )
                except Exception as e:
                    _error_tracing.attach_error_to_current_span(
                        SpanError(
                            message="Error running tool",
                            data={"tool_name": func_tool.name, "error": str(e)},
                        )
                    )
                    if isinstance(e, AgentsException):
                        raise e
                    raise UserError(f"Error running tool {func_tool.name}: {e}") from e

                if config.trace_include_sensitive_data:
                    span_fn.span_data.output = result
            return result

        indexed_results: dict[int, FunctionToolResult] = {}
        scheduled_tasks: list[tuple[int, ToolRunFunction, asyncio.Task[Any]]] = []
        empty_arg_validation: dict[str, Any] | None = None
        empty_arg_strike_count: int | None = None

        for index, tool_run in enumerate(tool_runs):
            function_tool = tool_run.function_tool
            validation_error = cls._validate_tool_args(
                tool_name=function_tool.name,
                raw_arguments=tool_run.tool_call.arguments,
                params_json_schema=function_tool.params_json_schema,
            )
            if validation_error is not None:
                if validation_error.get("empty_arguments"):
                    if empty_arg_validation is None:
                        empty_arg_strike_count = cls._record_consecutive_error(
                            context_wrapper,
                            f"{function_tool.name}:empty_required_arguments",
                        )
                        validation_error = {
                            **validation_error,
                            "consecutive_error_count": empty_arg_strike_count,
                            "reflect_message": cls._build_argument_reflect_message(
                                tool_name=function_tool.name,
                                validation=validation_error,
                                consecutive_error_count=empty_arg_strike_count,
                            ),
                            "schema_template_message": cls._build_schema_template_message(
                                tool_name=function_tool.name,
                                validation=validation_error,
                            ),
                        }
                        empty_arg_validation = validation_error
                        context_wrapper.last_tool_validation = validation_error
                    elif empty_arg_strike_count is not None:
                        validation_error = {
                            **validation_error,
                            "consecutive_error_count": empty_arg_strike_count,
                        }
                else:
                    context_wrapper.last_tool_validation = validation_error
                indexed_results[index] = FunctionToolResult(
                    tool=function_tool,
                    output=validation_error,
                    run_item=ToolCallOutputItem(
                        output=validation_error,
                        raw_item=ItemHelpers.tool_call_output_item(
                            tool_run.tool_call,
                            truncate_output(validation_error),
                        ),
                        agent=agent,
                    ),
                )
                continue

            scheduled_tasks.append(
                (
                    index,
                    tool_run,
                    asyncio.create_task(run_single_tool(function_tool, tool_run.tool_call)),
                )
            )

        if empty_arg_validation is None:
            cls._reset_consecutive_error_state(context_wrapper)

        try:
            gathered_results = (
                await asyncio.gather(*(task for _, _, task in scheduled_tasks))
                if scheduled_tasks
                else []
            )
        except (KeyboardInterrupt, asyncio.CancelledError) as e:
            for index, tool_run, task in scheduled_tasks:
                result: Any
                if task.done() and not task.cancelled():
                    try:
                        result = task.result()
                    except Exception:
                        result = "Tool execution interrupted"
                else:
                    result = "Tool execution interrupted"

                indexed_results[index] = FunctionToolResult(
                    tool=tool_run.function_tool,
                    output=result,
                    run_item=ToolCallOutputItem(
                        output=result,
                        raw_item=ItemHelpers.tool_call_output_item(
                            tool_run.tool_call,
                            truncate_output(result),
                        ),
                        agent=agent,
                    ),
                )
            raise e

        for (index, tool_run, _task), result in zip(scheduled_tasks, gathered_results):
            indexed_results[index] = FunctionToolResult(
                tool=tool_run.function_tool,
                output=result,
                run_item=ToolCallOutputItem(
                    output=result,
                    raw_item=ItemHelpers.tool_call_output_item(
                        tool_run.tool_call,
                        truncate_output(result),
                    ),
                    agent=agent,
                ),
            )

        return [indexed_results[index] for index in range(len(tool_runs)) if index in indexed_results]

    @classmethod
    async def execute_computer_actions(
        cls,
        *,
        agent: Agent[TContext],
        actions: list[ToolRunComputerAction],
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        config: RunConfig,
    ) -> list[RunItem]:
        results: list[RunItem] = []
        # Need to run these serially, because each action can affect the computer state
        for action in actions:
            results.append(
                await ComputerAction.execute(
                    agent=agent,
                    action=action,
                    hooks=hooks,
                    context_wrapper=context_wrapper,
                    config=config,
                )
            )

        return results

    @classmethod
    async def execute_handoffs(
        cls,
        *,
        agent: Agent[TContext],
        original_input: str | list[TResponseInputItem],
        pre_step_items: list[RunItem],
        new_step_items: list[RunItem],
        new_response: ModelResponse,
        run_handoffs: list[ToolRunHandoff],
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        run_config: RunConfig,
    ) -> SingleStepResult:
        # If there is more than one handoff, add tool responses that reject those handoffs
        multiple_handoffs = len(run_handoffs) > 1
        if multiple_handoffs:
            output_message = "Multiple handoffs detected, ignoring this one."
            new_step_items.extend(
                [
                    ToolCallOutputItem(
                        output=output_message,
                        raw_item=ItemHelpers.tool_call_output_item(
                            handoff.tool_call, output_message
                        ),
                        agent=agent,
                    )
                    for handoff in run_handoffs[1:]
                ]
            )

        actual_handoff = run_handoffs[0]
        with handoff_span(from_agent=agent.name) as span_handoff:
            handoff = actual_handoff.handoff
            new_agent: Agent[Any] = await handoff.on_invoke_handoff(
                context_wrapper, actual_handoff.tool_call.arguments
            )
            span_handoff.span_data.to_agent = new_agent.name
            if multiple_handoffs:
                requested_agents = [handoff.handoff.agent_name for handoff in run_handoffs]
                span_handoff.set_error(
                    SpanError(
                        message="Multiple handoffs requested",
                        data={
                            "requested_agents": requested_agents,
                        },
                    )
                )

            # Append a tool output item for the handoff
            new_step_items.append(
                HandoffOutputItem(
                    agent=agent,
                    raw_item=ItemHelpers.tool_call_output_item(
                        actual_handoff.tool_call,
                        handoff.get_transfer_message(new_agent),
                    ),
                    source_agent=agent,
                    target_agent=new_agent,
                )
            )

            # Execute handoff hooks
            await asyncio.gather(
                hooks.on_handoff(
                    context=context_wrapper,
                    from_agent=agent,
                    to_agent=new_agent,
                ),
                (
                    agent.hooks.on_handoff(
                        context_wrapper,
                        agent=new_agent,
                        source=agent,
                    )
                    if agent.hooks
                    else _coro.noop_coroutine()
                ),
            )

            # If there's an input filter, filter the input for the next agent
            input_filter = handoff.input_filter or (
                run_config.handoff_input_filter if run_config else None
            )
            if input_filter:
                logger.debug("Filtering inputs for handoff")
                handoff_input_data = HandoffInputData(
                    input_history=tuple(original_input)
                    if isinstance(original_input, list)
                    else original_input,
                    pre_handoff_items=tuple(pre_step_items),
                    new_items=tuple(new_step_items),
                )
                if not callable(input_filter):
                    _error_tracing.attach_error_to_span(
                        span_handoff,
                        SpanError(
                            message="Invalid input filter",
                            data={"details": "not callable()"},
                        ),
                    )
                    raise UserError(f"Invalid input filter: {input_filter}")
                filtered = input_filter(handoff_input_data)
                if not isinstance(filtered, HandoffInputData):
                    _error_tracing.attach_error_to_span(
                        span_handoff,
                        SpanError(
                            message="Invalid input filter result",
                            data={"details": "not a HandoffInputData"},
                        ),
                    )
                    raise UserError(f"Invalid input filter result: {filtered}")

                original_input = (
                    filtered.input_history
                    if isinstance(filtered.input_history, str)
                    else list(filtered.input_history)
                )
                pre_step_items = list(filtered.pre_handoff_items)
                new_step_items = list(filtered.new_items)

        return SingleStepResult(
            original_input=original_input,
            model_response=new_response,
            pre_step_items=pre_step_items,
            new_step_items=new_step_items,
            next_step=NextStepHandoff(new_agent),
        )

    @classmethod
    async def execute_final_output(
        cls,
        *,
        agent: Agent[TContext],
        original_input: str | list[TResponseInputItem],
        new_response: ModelResponse,
        pre_step_items: list[RunItem],
        new_step_items: list[RunItem],
        final_output: Any,
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
    ) -> SingleStepResult:
        # Run the on_end hooks
        await cls.run_final_output_hooks(agent, hooks, context_wrapper, final_output)

        return SingleStepResult(
            original_input=original_input,
            model_response=new_response,
            pre_step_items=pre_step_items,
            new_step_items=new_step_items,
            next_step=NextStepFinalOutput(final_output),
        )

    @classmethod
    async def run_final_output_hooks(
        cls,
        agent: Agent[TContext],
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        final_output: Any,
    ):
        await asyncio.gather(
            hooks.on_agent_end(context_wrapper, agent, final_output),
            agent.hooks.on_end(context_wrapper, agent, final_output)
            if agent.hooks
            else _coro.noop_coroutine(),
        )

    @classmethod
    async def run_single_input_guardrail(
        cls,
        agent: Agent[Any],
        guardrail: InputGuardrail[TContext],
        input: str | list[TResponseInputItem],
        context: RunContextWrapper[TContext],
    ) -> InputGuardrailResult:
        with guardrail_span(guardrail.get_name()) as span_guardrail:
            result = await guardrail.run(agent, input, context)
            span_guardrail.span_data.triggered = result.output.tripwire_triggered
            return result

    @classmethod
    async def run_single_output_guardrail(
        cls,
        guardrail: OutputGuardrail[TContext],
        agent: Agent[Any],
        agent_output: Any,
        context: RunContextWrapper[TContext],
    ) -> OutputGuardrailResult:
        with guardrail_span(guardrail.get_name()) as span_guardrail:
            result = await guardrail.run(agent=agent, agent_output=agent_output, context=context)
            span_guardrail.span_data.triggered = result.output.tripwire_triggered
            return result

    @classmethod
    def stream_step_result_to_queue(
        cls,
        step_result: SingleStepResult,
        queue: asyncio.Queue[StreamEvent | QueueCompleteSentinel],
    ):
        for item in step_result.new_step_items:
            if isinstance(item, MessageOutputItem):
                event = RunItemStreamEvent(item=item, name="message_output_created")
            elif isinstance(item, HandoffCallItem):
                event = RunItemStreamEvent(item=item, name="handoff_requested")
            elif isinstance(item, HandoffOutputItem):
                event = RunItemStreamEvent(item=item, name="handoff_occured")
            elif isinstance(item, ToolCallItem):
                event = RunItemStreamEvent(item=item, name="tool_called")
            elif isinstance(item, ToolCallOutputItem):
                event = RunItemStreamEvent(item=item, name="tool_output")
            elif isinstance(item, ReasoningItem):
                event = RunItemStreamEvent(item=item, name="reasoning_item_created")
            else:
                logger.warning(f"Unexpected item type: {type(item)}")
                event = None

            if event:
                queue.put_nowait(event)

    @classmethod
    async def _check_for_final_output_from_tools(
        cls,
        *,
        agent: Agent[TContext],
        tool_results: list[FunctionToolResult],
        context_wrapper: RunContextWrapper[TContext],
        config: RunConfig,
    ) -> ToolsToFinalOutputResult:
        """Returns (i, final_output)."""
        if not tool_results:
            return _NOT_FINAL_OUTPUT

        if agent.tool_use_behavior == "run_llm_again":
            return _NOT_FINAL_OUTPUT
        elif agent.tool_use_behavior == "stop_on_first_tool":
            return ToolsToFinalOutputResult(
                is_final_output=True, final_output=tool_results[0].output
            )
        elif isinstance(agent.tool_use_behavior, dict):
            names = agent.tool_use_behavior.get("stop_at_tool_names", [])
            for tool_result in tool_results:
                if tool_result.tool.name in names:
                    return ToolsToFinalOutputResult(
                        is_final_output=True, final_output=tool_result.output
                    )
            return ToolsToFinalOutputResult(is_final_output=False, final_output=None)
        elif callable(agent.tool_use_behavior):
            if inspect.iscoroutinefunction(agent.tool_use_behavior):
                return await cast(
                    Awaitable[ToolsToFinalOutputResult],
                    agent.tool_use_behavior(context_wrapper, tool_results),
                )
            else:
                return cast(
                    ToolsToFinalOutputResult, agent.tool_use_behavior(context_wrapper, tool_results)
                )

        logger.error(f"Invalid tool_use_behavior: {agent.tool_use_behavior}")
        raise UserError(f"Invalid tool_use_behavior: {agent.tool_use_behavior}")


class TraceCtxManager:
    """Creates a trace only if there is no current trace, and manages the trace lifecycle."""

    def __init__(
        self,
        workflow_name: str,
        trace_id: str | None,
        group_id: str | None,
        metadata: dict[str, Any] | None,
        disabled: bool,
    ):
        self.trace: Trace | None = None
        self.workflow_name = workflow_name
        self.trace_id = trace_id
        self.group_id = group_id
        self.metadata = metadata
        self.disabled = disabled

    def __enter__(self) -> TraceCtxManager:
        current_trace = get_current_trace()
        if not current_trace:
            self.trace = trace(
                workflow_name=self.workflow_name,
                trace_id=self.trace_id,
                group_id=self.group_id,
                metadata=self.metadata,
                disabled=self.disabled,
            )
            self.trace.start(mark_as_current=True)

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.trace:
            self.trace.finish(reset_current=True)


class ComputerAction:
    @classmethod
    async def execute(
        cls,
        *,
        agent: Agent[TContext],
        action: ToolRunComputerAction,
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        config: RunConfig,
    ) -> RunItem:
        output_func = (
            cls._get_screenshot_async(action.computer_tool.computer, action.tool_call)
            if isinstance(action.computer_tool.computer, AsyncComputer)
            else cls._get_screenshot_sync(action.computer_tool.computer, action.tool_call)
        )

        _, _, output = await asyncio.gather(
            hooks.on_tool_start(context_wrapper, agent, action.computer_tool),
            (
                agent.hooks.on_tool_start(context_wrapper, agent, action.computer_tool)
                if agent.hooks
                else _coro.noop_coroutine()
            ),
            output_func,
        )

        await asyncio.gather(
            hooks.on_tool_end(context_wrapper, agent, action.computer_tool, output),
            (
                agent.hooks.on_tool_end(context_wrapper, agent, action.computer_tool, output)
                if agent.hooks
                else _coro.noop_coroutine()
            ),
        )

        # TODO: don't send a screenshot every single time, use references
        image_url = f"data:image/png;base64,{output}"
        return ToolCallOutputItem(
            agent=agent,
            output=image_url,
            raw_item=ComputerCallOutput(
                call_id=action.tool_call.call_id,
                output={
                    "type": "computer_screenshot",
                    "image_url": image_url,
                },
                type="computer_call_output",
            ),
        )

    @classmethod
    async def _get_screenshot_sync(
        cls,
        computer: Computer,
        tool_call: ResponseComputerToolCall,
    ) -> str:
        action = tool_call.action
        if isinstance(action, ActionClick):
            computer.click(action.x, action.y, action.button)
        elif isinstance(action, ActionDoubleClick):
            computer.double_click(action.x, action.y)
        elif isinstance(action, ActionDrag):
            computer.drag([(p.x, p.y) for p in action.path])
        elif isinstance(action, ActionKeypress):
            computer.keypress(action.keys)
        elif isinstance(action, ActionMove):
            computer.move(action.x, action.y)
        elif isinstance(action, ActionScreenshot):
            computer.screenshot()
        elif isinstance(action, ActionScroll):
            computer.scroll(action.x, action.y, action.scroll_x, action.scroll_y)
        elif isinstance(action, ActionType):
            computer.type(action.text)
        elif isinstance(action, ActionWait):
            computer.wait()

        return computer.screenshot()

    @classmethod
    async def _get_screenshot_async(
        cls,
        computer: AsyncComputer,
        tool_call: ResponseComputerToolCall,
    ) -> str:
        action = tool_call.action
        if isinstance(action, ActionClick):
            await computer.click(action.x, action.y, action.button)
        elif isinstance(action, ActionDoubleClick):
            await computer.double_click(action.x, action.y)
        elif isinstance(action, ActionDrag):
            await computer.drag([(p.x, p.y) for p in action.path])
        elif isinstance(action, ActionKeypress):
            await computer.keypress(action.keys)
        elif isinstance(action, ActionMove):
            await computer.move(action.x, action.y)
        elif isinstance(action, ActionScreenshot):
            await computer.screenshot()
        elif isinstance(action, ActionScroll):
            await computer.scroll(action.x, action.y, action.scroll_x, action.scroll_y)
        elif isinstance(action, ActionType):
            await computer.type(action.text)
        elif isinstance(action, ActionWait):
            await computer.wait()

        return await computer.screenshot()
