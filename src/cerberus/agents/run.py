from __future__ import annotations

import asyncio
import copy
import json
import os
import logging
import random
import sys
import time
import uuid
import weakref
from dataclasses import dataclass, field
from typing import Any, cast

from openai.types.responses import ResponseCompletedEvent

logger = logging.getLogger(__name__)

from ._run_impl import (
    AgentToolUseTracker,
    NextStepFinalOutput,
    NextStepHandoff,
    NextStepRunAgain,
    QueueCompleteSentinel,
    RunImpl,
    SingleStepResult,
    TraceCtxManager,
    get_model_tracing_impl,
)
from .agent import Agent
from .agent_output import AgentOutputSchema
from .exceptions import (
    AgentLoopError,
    AgentsException,
    InputGuardrailTripwireTriggered,
    MaxTurnsExceeded,
    ModelBehaviorError,
    OutputGuardrailTripwireTriggered,
)
from .guardrail import InputGuardrail, InputGuardrailResult, OutputGuardrail, OutputGuardrailResult
from .handoffs import Handoff, HandoffInputFilter, handoff
from .items import ItemHelpers, ModelResponse, RunItem, TResponseInputItem
from .lifecycle import RunHooks
from .logger import logger
from .model_settings import ModelSettings
from .models.interface import Model, ModelProvider
from .models.openai_provider import OpenAIProvider
from .result import RunResult, RunResultStreaming
from .run_context import RunContextWrapper, TContext
from .stream_events import AgentUpdatedStreamEvent, RawResponsesStreamEvent
from .tool import Tool
from .tracing import Span, SpanError, agent_span, get_current_trace, trace
from .tracing.span_data import AgentSpanData
from .usage import Usage
from .util import _error_tracing
from cerberus.util import safe_duration_to_float
from cerberus.verification.policy_engine import (
    PolicyEngine,
    PolicyReport,
    format_logic_audit_report,
    render_logic_audit_report_markdown,
)
from cerberus.tools.all_tools import (
    build_execution_plan,
    build_execution_plan_for_category,
    get_existing_tool_categories,
    get_tool,
    inject_core_tools,
    resolve_category,
    ResolutionResult,
    ExecutionPlan,
    ToolResolutionState,
    validate_execution_plan,
)
from cerberus.tools.sessions import (
    append_toolbox_tool_snapshot,
    get_toolbox_active_category,
    set_toolbox_tool_state,
    set_current_toolbox_session_id,
    set_run_context_toolbox_session_id,
)
from cerberus.planner.executor import select_tools_for_execution


_ACTIVE_STREAMED_RESULTS: "weakref.WeakSet[RunResultStreaming]" = weakref.WeakSet()

# CERBERUS_MAX_TURNS must be converted to an int to avoid type mismatch error when comparing.
max_turns_env = os.getenv("CERBERUS_MAX_TURNS")
if max_turns_env is not None:
    try:
        DEFAULT_MAX_TURNS = int(max_turns_env)
    except ValueError:
        DEFAULT_MAX_TURNS = sys.maxsize
else:
    DEFAULT_MAX_TURNS = sys.maxsize

price_limit_env = os.getenv("CERBERUS_PRICE_LIMIT")
if price_limit_env is not None:
    try:
        DEFAULT_PRICE_LIMIT = float(price_limit_env)
    except ValueError:
        DEFAULT_PRICE_LIMIT = float("inf")
else:
    DEFAULT_PRICE_LIMIT = float("inf")


@dataclass
class RunConfig:
    """Configures settings for the entire agent run."""

    model: str | Model | None = None
    """The model to use for the entire agent run. If set, will override the model set on every
    agent. The model_provider passed in below must be able to resolve this model name.
    """

    model_provider: ModelProvider = field(default_factory=OpenAIProvider)
    """The model provider to use when looking up string model names. Defaults to OpenAI."""

    model_settings: ModelSettings | None = None
    """Configure global model settings. Any non-null values will override the agent-specific model
    settings.
    """

    handoff_input_filter: HandoffInputFilter | None = None
    """A global input filter to apply to all handoffs. If `Handoff.input_filter` is set, then that
    will take precedence. The input filter allows you to edit the inputs that are sent to the new
    agent. See the documentation in `Handoff.input_filter` for more details.
    """

    input_guardrails: list[InputGuardrail[Any]] | None = None
    """A list of input guardrails to run on the initial run input."""

    output_guardrails: list[OutputGuardrail[Any]] | None = None
    """A list of output guardrails to run on the final output of the run."""

    tracing_disabled: bool = False
    """Whether tracing is disabled for the agent run. If disabled, we will not trace the agent run.
    """

    trace_include_sensitive_data: bool = True
    """Whether we include potentially sensitive data (for example: inputs/outputs of tool calls or
    LLM generations) in traces. If False, we'll still create spans for these events, but the
    sensitive data will not be included.
    """

    workflow_name: str = "Agent workflow"
    """The name of the run, used for tracing. Should be a logical name for the run, like
    "Code generation workflow" or "Customer support agent".
    """

    trace_id: str | None = None
    """A custom trace ID to use for tracing. If not provided, we will generate a new trace ID."""

    group_id: str | None = None
    """
    A grouping identifier to use for tracing, to link multiple traces from the same conversation
    or process. For example, you might use a chat thread ID.
    """

    trace_metadata: dict[str, Any] | None = None
    """
    An optional dictionary of additional metadata to include with the trace.
    """


class Runner:
    _CIRCUIT_BREAKER_WARNING = (
        "SYSTEM WARNING: STRATEGY SHIFT REQUIRED. You have executed this exact tool pattern 3 times "
        "in a row. It is not working. You MUST use your <think> tags to perform Schema Sync, explain "
        "why it failed, and then choose a different tool or corrected parameters."
    )

    @staticmethod
    def _is_truthy_env(value: str) -> bool:
        raw = str(value or "").strip().lower()
        if not raw:
            return False
        if raw.isdigit():
            return int(raw) > 0
        return raw in {"1", "true", "yes", "on", "debug", "verbose"}

    @classmethod
    def _jit_debug_enabled(cls) -> bool:
        explicit = os.getenv("CERBERUS_JIT_DEBUG")
        if explicit is not None:
            return cls._is_truthy_env(explicit)
        return cls._is_truthy_env(os.getenv("CERBERUS_DEBUG", ""))

    @staticmethod
    def _jit_trace(message: str, enabled: bool) -> None:
        if enabled:
            print(f"[JIT] {message}")

    @classmethod
    def _emit_jit_selection_trace(
        cls,
        *,
        enabled: bool,
        detected_intent: str | None,
        active_category_override: str | None,
        final_selected_category: str | None,
        selected_tools: list[Tool],
    ) -> None:
        if not enabled:
            return
        tool_names = cls._resolve_tool_names(selected_tools)
        cls._jit_trace(f"Intent: {detected_intent or 'None'}", enabled=enabled)
        cls._jit_trace(
            f"Active Category Override: {active_category_override or 'None'}",
            enabled=enabled,
        )
        cls._jit_trace(f"Final Category: {final_selected_category or 'None'}", enabled=enabled)
        cls._jit_trace(f"Tools Loaded: {len(selected_tools)}", enabled=enabled)
        cls._jit_trace(f"Tools: {', '.join(tool_names)}", enabled=enabled)

    @classmethod
    def _build_circuit_breaker_warning(
        cls,
        tool_name: str,
        tool_args: str,
        validation: dict[str, Any] | None = None,
    ) -> str:
        """Build a concrete warning message to break repeated identical tool calls."""
        warning = [
            cls._CIRCUIT_BREAKER_WARNING,
            f"Last repeated call: tool={tool_name!r}, arguments={tool_args!r}.",
            "MANDATORY NEXT STEP: output one corrected tool call JSON with required fields populated.",
            "DO NOT repeat the same arguments again.",
        ]

        if validation:
            required_fields = validation.get("required_fields")
            if isinstance(required_fields, list) and required_fields:
                warning.append(
                    "Parameter fix: populate all required fields: "
                    f"{', '.join(str(field) for field in required_fields)}."
                )
            suggested_arguments = validation.get("suggested_arguments_json")
            if isinstance(suggested_arguments, str) and suggested_arguments.strip():
                warning.append(f"Example repaired arguments: {suggested_arguments}")

        if tool_name == "web_request_framework":
            warning.append(
                "Example corrected call arguments: "
                '{"url":"http://natas0.natas.labs.overthewire.org","method":"GET"}'
            )

        # Common degenerate loop signature where model keeps emitting empty args.
        if tool_args in {"", "{}"}:
            warning.append("Your previous arguments were empty. Empty arguments are invalid here.")

        return " ".join(warning)

    @staticmethod
    def _reset_tool_retry_state(context_wrapper: RunContextWrapper[Any]) -> None:
        context_wrapper.last_tool_name = ""
        context_wrapper.last_tool_args = ""
        context_wrapper.consecutive_tool_count = 0
        context_wrapper.last_tool_validation = {}
        context_wrapper.pending_approval = {}
        context_wrapper.pending_approval_decision = {}
        context_wrapper.last_tool_error_signature = ""
        context_wrapper.consecutive_tool_error_count = 0
        context_wrapper.suppress_next_tool_loop_warning = False

    @staticmethod
    def _reset_primary_tool_signature_state(context_wrapper: RunContextWrapper[Any]) -> None:
        context_wrapper.last_tool_name = ""
        context_wrapper.last_tool_args = ""
        context_wrapper.consecutive_tool_count = 0
        context_wrapper.last_tool_validation = {}
        context_wrapper.pending_approval = {}
        context_wrapper.pending_approval_decision = {}

    @staticmethod
    def _record_tool_attempt(
        context_wrapper: RunContextWrapper[Any], tool_name: str, tool_args: str
    ) -> int:
        if tool_name == context_wrapper.last_tool_name and tool_args == context_wrapper.last_tool_args:
            context_wrapper.consecutive_tool_count += 1
        else:
            context_wrapper.last_tool_name = tool_name
            context_wrapper.last_tool_args = tool_args
            context_wrapper.consecutive_tool_count = 1
            context_wrapper.last_tool_validation = {}
            context_wrapper.pending_approval = {}
            context_wrapper.pending_approval_decision = {}

        return context_wrapper.consecutive_tool_count

    @staticmethod
    def set_pending_approval_decision(
        context_wrapper: RunContextWrapper[Any],
        *,
        decision: str,
        repaired_arguments: dict[str, Any] | None = None,
        reason: str | None = None,
    ) -> None:
        normalized = str(decision or "").strip().upper()
        if normalized not in {"APPROVE", "REJECT"}:
            raise ValueError("decision must be APPROVE or REJECT")

        context_wrapper.pending_approval_decision = {
            "decision": normalized,
            "repaired_arguments": repaired_arguments if isinstance(repaired_arguments, dict) else None,
            "reason": str(reason or "").strip(),
        }

    @staticmethod
    def _normalize_tool_args(raw_args: Any) -> str:
        """Normalize tool arguments for stable exact-match detection across turns."""
        if raw_args is None:
            return ""
        if isinstance(raw_args, str):
            candidate = raw_args.strip()
            if not candidate:
                return ""
            try:
                parsed = json.loads(candidate)
                return json.dumps(parsed, sort_keys=True, separators=(",", ":"))
            except Exception:
                return candidate
        try:
            return json.dumps(raw_args, sort_keys=True, separators=(",", ":"), default=str)
        except Exception:
            return str(raw_args)

    @classmethod
    def _extract_primary_tool_signature(
        cls,
        step_result: SingleStepResult,
    ) -> tuple[str | None, str | None]:
        """Extract the first tool-call signature (tool name + normalized args) from a turn."""
        for output_item in step_result.model_response.output:
            item_type = getattr(output_item, "type", None)
            if item_type == "function_call":
                tool_name = str(getattr(output_item, "name", "") or "").strip()
                args = cls._normalize_tool_args(getattr(output_item, "arguments", ""))
                if tool_name:
                    return tool_name, args
            elif item_type in {"computer_call", "web_search_call", "file_search_call"}:
                tool_name = str(item_type)
                try:
                    payload = output_item.model_dump(exclude_unset=True)
                except Exception:
                    payload = str(output_item)
                args = cls._normalize_tool_args(payload)
                return tool_name, args
        return None, None

    @staticmethod
    def _system_warning_input_item(message: str) -> TResponseInputItem:
        # Use "user" role — some LiteLLM Jinja chat templates (e.g. Qwen, Llama)
        # require the system message to be at position 0 and raise an error if a
        # "system" role entry appears anywhere else in the conversation.  Injecting
        # the circuit-breaker warning as a user turn is semantically equivalent and
        # avoids that constraint while still providing the same guidance to the model.
        return {
            "role": "user",
            "content": [{"type": "input_text", "text": f"[SYSTEM] {message}"}],
        }

    @staticmethod
    def _append_policy_audit(context_wrapper: RunContextWrapper[Any], report: PolicyReport) -> None:
        history = list(getattr(context_wrapper, "policy_audit_history", []))
        history.append(report.to_dict())
        setattr(context_wrapper, "policy_audit_history", history[-25:])

    @classmethod
    def _build_policy_warning_message(cls, report: PolicyReport) -> str:
        payload = {
            "status": report.status,
            "mode": "MODE_CRITIQUE",
            "rationale": "; ".join(f.message for f in report.findings[:3]) or "No issues",
            "suggested_adjustment": "Revise plan based on failed policy checks.",
            "risk_level": "High" if report.risk_score >= 70 else ("Medium" if report.risk_score >= 30 else "Low"),
        }
        table_rows = format_logic_audit_report(payload)
        return (
            "Policy engine found issues in the current plan. "
            "Re-evaluate the next action before execution.\n\n"
            f"{render_logic_audit_report_markdown(table_rows)}"
        )

    @classmethod
    def _extract_planned_calls(cls, processed_response: Any) -> list[dict[str, Any]]:
        planned_calls: list[dict[str, Any]] = []

        for tool_run in getattr(processed_response, "functions", []):
            tool_call = getattr(tool_run, "tool_call", None)
            planned_calls.append(
                {
                    "tool_name": str(getattr(tool_call, "name", "") or "").strip(),
                    "arguments": str(getattr(tool_call, "arguments", "") or ""),
                }
            )

        for tool_call in getattr(processed_response, "missing_functions", []):
            planned_calls.append(
                {
                    "tool_name": str(getattr(tool_call, "name", "") or "").strip(),
                    "arguments": str(getattr(tool_call, "arguments", "") or ""),
                }
            )

        for computer_action in getattr(processed_response, "computer_actions", []):
            tool_call = getattr(computer_action, "tool_call", None)
            payload: Any
            try:
                payload = tool_call.model_dump(exclude_unset=True) if tool_call is not None else {}
            except Exception:
                payload = str(tool_call)
            planned_calls.append(
                {
                    "tool_name": "computer_use",
                    "arguments": payload,
                }
            )

        return planned_calls

    @classmethod
    def _apply_policy_preflight(
        cls,
        *,
        input_items: list[TResponseInputItem],
        all_tools: list[Tool],
        context_wrapper: RunContextWrapper[Any],
    ) -> list[TResponseInputItem]:
        policy_engine = PolicyEngine(
            workspace_dir=cls._workspace_path(),
            project_id=os.getenv("CERBERUS_PROJECT_ID"),
        )
        report = policy_engine.run_preflight(
            input_items=cast(list[Any], input_items),
            available_tools=cls._resolve_tool_names(cast(list[Any], all_tools)),
        )
        cls._append_policy_audit(context_wrapper, report)

        if not report.findings:
            return input_items

        augmented = ItemHelpers.input_to_new_input_list(input_items)
        augmented.append(cls._system_warning_input_item(cls._build_policy_warning_message(report)))
        return augmented

    @staticmethod
    def _workspace_path() -> str:
        return (
            os.getenv("CIR_WORKSPACE")
            or os.getenv("CERBERUS_WORKSPACE_ROOT")
            or os.getcwd()
        )

    @staticmethod
    def _agent_uuid(agent: Agent[Any] | None) -> str:
        if agent is None:
            return "unknown"
        for attr in ("agent_uuid", "agent_id", "id"):
            value = getattr(agent, attr, None)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return getattr(agent, "name", "unknown")

    @staticmethod
    def _resolve_tool_name(tool: Any) -> str:
        """Extract a stable tool name from tool objects, functions, or dict entries."""
        try:
            if hasattr(tool, "name"):
                value = getattr(tool, "name")
                if isinstance(value, str) and value.strip():
                    return value.strip()
            if isinstance(tool, dict):
                value = tool.get("name")
                if isinstance(value, str) and value.strip():
                    return value.strip()
            value = getattr(tool, "__name__", None)
            if isinstance(value, str) and value.strip():
                return value.strip()
        except Exception:
            pass

        return type(tool).__name__

    @classmethod
    def _resolve_tool_names(cls, tools: list[Any]) -> list[str]:
        return [cls._resolve_tool_name(tool) for tool in tools]

    @classmethod
    def _dedupe_tools_by_name(cls, tools: list[Tool]) -> list[Tool]:
        seen: set[str] = set()
        deduped: list[Tool] = []
        for tool in tools:
            name = cls._resolve_tool_name(tool)
            if name in seen:
                continue
            seen.add(name)
            deduped.append(tool)
        return deduped

    @classmethod
    def _ensure_request_toolbox_present(cls, tools: list[Tool]) -> list[Tool]:
        """Guarantee request_toolbox is present after deduplication."""
        deduped = cls._dedupe_tools_by_name(tools)
        if any(cls._resolve_tool_name(tool) == "request_toolbox" for tool in deduped):
            return deduped

        try:
            request_toolbox_tool = cast(Tool, get_tool("request_toolbox"))
        except Exception as exc:
            logger.critical("Failed to inject required tool 'request_toolbox': %s", exc)
            raise AgentsException(
                "Critical tool resolution failure: required tool 'request_toolbox' is unavailable"
            ) from exc

        return deduped + [request_toolbox_tool]

    @classmethod
    def _finalize_turn_tools(cls, tools: list[Tool]) -> list[Tool]:
        """Deduplicate selected tools and inject request_toolbox last."""
        finalized = cls._ensure_request_toolbox_present(tools)
        cls._validate_final_toolset_safety(finalized)
        return finalized

    @classmethod
    def _is_valid_tool_schema(cls, tool: Tool) -> bool:
        """Return True when a tool schema is structurally valid.

        FunctionTool instances are expected to expose `params_json_schema` as a dict
        with object semantics. Hosted tools do not carry parameter schemas and are
        treated as valid when they expose a stable name.
        """
        name = cls._resolve_tool_name(tool)
        if not name:
            return False

        has_schema_attr = hasattr(tool, "params_json_schema")
        has_invoke = hasattr(tool, "on_invoke_tool")

        # Function-like tools must carry a valid JSON schema.
        if has_schema_attr or has_invoke:
            schema = getattr(tool, "params_json_schema", None)
            if not isinstance(schema, dict) or not schema:
                return False

            schema_type = schema.get("type")
            if schema_type not in {None, "object"}:
                return False

            if "properties" in schema and not isinstance(schema.get("properties"), dict):
                return False

            if "required" in schema and not isinstance(schema.get("required"), list):
                return False

        return True

    @classmethod
    def _validate_final_toolset_safety(cls, tools: list[Tool]) -> None:
        """Assert final pre-LLM toolset safety invariants.

        Invariants:
        - non-empty list
        - request_toolbox present
        - no duplicate names
        - all tool schemas structurally valid
        """
        if not tools:
            logger.critical("Final tool safety check failed: tool list is empty")
            raise AgentsException(
                "Critical tool resolution failure: finalized tool list is empty"
            )

        names = cls._resolve_tool_names(tools)
        if "request_toolbox" not in names:
            logger.critical("Final tool safety check failed: request_toolbox missing")
            raise AgentsException(
                "Critical tool resolution failure: required tool 'request_toolbox' missing from finalized list"
            )

        seen: set[str] = set()
        duplicates: set[str] = set()
        for name in names:
            if name in seen:
                duplicates.add(name)
            seen.add(name)
        if duplicates:
            logger.critical(
                "Final tool safety check failed: duplicate tool names detected: %s",
                sorted(duplicates),
            )
            raise AgentsException(
                "Critical tool resolution failure: duplicate tool names detected in finalized list"
            )

        invalid_schema_tools = [
            cls._resolve_tool_name(tool)
            for tool in tools
            if not cls._is_valid_tool_schema(tool)
        ]
        if invalid_schema_tools:
            logger.critical(
                "Final tool safety check failed: invalid tool schemas for tools=%s",
                invalid_schema_tools,
            )
            raise AgentsException(
                "Critical tool resolution failure: one or more finalized tools have invalid schemas"
            )

    @classmethod
    def _normalize_selected_category(
        cls,
        selected_category: str | None,
        valid_categories: set[str],
    ) -> str | None:
        """Ensure category selection is valid before any loader call."""
        if not selected_category:
            return None

        if selected_category in valid_categories:
            return selected_category

        warning_message = (
            f"Invalid active toolbox category '{selected_category}' encountered; "
            "falling back to 'misc'"
        )
        logger.warning(warning_message)

        if "misc" in valid_categories:
            return "misc"

        logger.critical(
            "Invalid active toolbox category '%s' encountered and 'misc' fallback is unavailable. Valid categories=%s",
            selected_category,
            sorted(valid_categories),
        )
        raise AgentsException(
            "Critical tool resolution failure: invalid category encountered and 'misc' fallback is unavailable"
        )

    @classmethod
    def _normalize_detected_intent_category(
        cls,
        resolution_result: ResolutionResult,
        valid_categories: set[str],
        *,
        debug_enabled: bool,
    ) -> str | None:
        """Normalize scored category resolution with safe, non-crashing fallbacks.

        Intent-derived categories should never crash routing; if resolver emits an
        unknown category, fall back to misc, then to any available category.
        """
        detected_intent = str(resolution_result.primary_category or "").strip()
        if not detected_intent:
            return None

        if detected_intent not in resolution_result.confidence_scores:
            warning_message = (
                f"Resolver returned unscored category '{detected_intent}'; "
                "falling back to 'misc'"
            )
            logger.warning(warning_message)
            cls._jit_trace(warning_message, enabled=debug_enabled)
            detected_intent = "misc"

        if detected_intent in valid_categories:
            if resolution_result.fallback_reason:
                reason_message = (
                    "Category resolver fallback applied: "
                    f"reason='{resolution_result.fallback_reason}', "
                    f"selected='{detected_intent}'"
                )
                logger.warning(reason_message)
                cls._jit_trace(reason_message, enabled=debug_enabled)
            elif detected_intent == "misc":
                low_confidence_message = "Low-confidence intent match: resolver selected 'misc'"
                logger.warning(low_confidence_message)
                cls._jit_trace(low_confidence_message, enabled=debug_enabled)
            return detected_intent

        warning_message = (
            f"Unknown resolver category '{detected_intent}' encountered; "
            "falling back to 'misc'"
        )
        logger.warning(warning_message)
        cls._jit_trace(warning_message, enabled=debug_enabled)

        if "misc" in valid_categories:
            return "misc"

        if valid_categories:
            safe_fallback = sorted(valid_categories)[0]
            logger.warning(
                "'misc' category unavailable; falling back to first available category '%s'",
                safe_fallback,
            )
            cls._jit_trace(
                f"'misc' unavailable; using fallback category: {safe_fallback}",
                enabled=debug_enabled,
            )
            return safe_fallback

        logger.warning("No categories available for detected intent fallback; using all tools")
        cls._jit_trace("No available categories for intent fallback; using all tools", enabled=debug_enabled)
        return None

    @staticmethod
    def _extract_latest_user_prompt(input_payload: str | list[TResponseInputItem]) -> str:
        if isinstance(input_payload, str):
            return input_payload.strip()

        for item in reversed(input_payload):
            if not isinstance(item, dict):
                continue
            role = str(item.get("role", "") or "").strip().lower()
            if role != "user":
                continue

            content = item.get("content")
            if isinstance(content, str) and content.strip():
                return content.strip()

            if isinstance(content, list):
                fragments: list[str] = []
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    value = block.get("text") or block.get("input_text")
                    if isinstance(value, str) and value.strip():
                        fragments.append(value.strip())
                if fragments:
                    return "\n".join(fragments)

        return ""

    @classmethod
    def _select_tools_for_turn(
        cls,
        all_tools: list[Tool],
        context_wrapper: RunContextWrapper[Any],
        input_payload: str | list[TResponseInputItem],
    ) -> list[Tool]:
        # Phase 1: Parse session
        debug_enabled = cls._jit_debug_enabled()
        existing_session_id = str(getattr(context_wrapper, "toolbox_session_id", "") or "").strip()
        session_id = set_run_context_toolbox_session_id(
            context_wrapper,
            session_id=existing_session_id or uuid.uuid4().hex,
        )
        set_current_toolbox_session_id(session_id)

        active_category = get_toolbox_active_category(session_id)
        detected_intent: str | None = None
        resolution_result: ResolutionResult | None = None
        latest_prompt = cls._extract_latest_user_prompt(input_payload)

        # Phase 2: Build execution plan
        if active_category:
            execution_plan = build_execution_plan_for_category(active_category)
            selected_category = active_category
        else:
            resolution_result = resolve_category(latest_prompt)
            detected_intent = resolution_result.primary_category
            selected_category = detected_intent
            execution_plan = build_execution_plan(latest_prompt)

            if debug_enabled:
                ranked_scores = sorted(
                    resolution_result.confidence_scores.items(),
                    key=lambda item: (-item[1], item[0]),
                )
                score_preview = ", ".join(
                    f"{category}={score:.3f}" for category, score in ranked_scores
                )
                cls._jit_trace(f"Resolution Scores: {score_preview}", enabled=debug_enabled)
                if resolution_result.fallback_reason:
                    cls._jit_trace(
                        f"Resolution Fallback Reason: {resolution_result.fallback_reason}",
                        enabled=debug_enabled,
                    )

        # Phase 3: Inject core tools
        execution_plan = inject_core_tools(execution_plan)

        # Phase 4: Validate tool graph (non-mutating hard gate)
        validation_result = validate_execution_plan(execution_plan)
        if not validation_result.is_valid:
            logger.critical(
                "Execution plan validation failed for category '%s': errors=%s",
                selected_category,
                validation_result.errors,
            )
            raise AgentsException(
                "Deterministic execution-plan validation failure: "
                + ",".join(validation_result.errors)
            )

        normalized_state = execution_plan.resolution_state
        if (
            validation_result.unresolved_references
            and normalized_state == ToolResolutionState.SUCCESS
        ):
            normalized_state = ToolResolutionState.DEGRADED

        execution_plan = execution_plan.model_copy(
            update={
                "resolution_state": normalized_state,
                "unresolved_references": validation_result.unresolved_references,
                "reasoning_trace": [
                    *execution_plan.reasoning_trace,
                    "plan_graph_validation="
                    f"validated:{len(validation_result.validated_tool_ids)} "
                    f"errors:{'|'.join(validation_result.errors) or 'none'}",
                    "plan_dependency_resolution="
                    f"unresolved:{'|'.join(validation_result.unresolved_references) or 'none'}",
                    *validation_result.dependency_trace,
                ]
            }
        )

        allowed_tool_names = {node.name for node in execution_plan.tool_nodes}

        if debug_enabled:
            reasoning_preview = " | ".join(execution_plan.reasoning_trace)
            cls._jit_trace(
                (
                    "Execution Plan State: "
                    f"{execution_plan.resolution_state.value} "
                    f"(resolved={execution_plan.resolved_category or 'None'}, "
                    f"tool_nodes={len(execution_plan.tool_nodes)})"
                ),
                enabled=debug_enabled,
            )
            cls._jit_trace(
                f"Execution Plan Trace: {reasoning_preview}",
                enabled=debug_enabled,
            )

        if execution_plan.resolution_state == ToolResolutionState.FAILED:
            logger.critical(
                "Execution planning failed for category '%s': resolved=%s trace=%s",
                selected_category,
                execution_plan.resolved_category,
                execution_plan.reasoning_trace,
            )
            raise AgentsException(
                "Critical execution planning failure: no deterministic tool plan available"
            )

        if execution_plan.resolution_state == ToolResolutionState.DEGRADED:
            logger.warning(
                "Execution planning degraded: resolved=%s trace=%s",
                execution_plan.resolved_category,
                execution_plan.reasoning_trace,
            )

        # Phase 5: Send to LLM (precomputed tool set only)
        selection = select_tools_for_execution(
            available_tools=all_tools,
            allowed_tool_names=allowed_tool_names,
        )
        filtered_tools = selection.selected_tools
        if selection.missing_tool_names and debug_enabled:
            cls._jit_trace(
                "Execution Plan Missing Runtime Tools: "
                + ", ".join(selection.missing_tool_names),
                enabled=debug_enabled,
            )
        if filtered_tools:
            finalized_tools = cls._finalize_turn_tools(filtered_tools)

            # Phase 6: Capture snapshot
            append_toolbox_tool_snapshot(
                session_id,
                prompt=latest_prompt,
                resolved_category=execution_plan.resolved_category,
                tool_list=cls._resolve_tool_names(finalized_tools),
                execution_plan=execution_plan,
            )

            # Phase 7: Update session state
            set_toolbox_tool_state(
                session_id,
                active_category=execution_plan.resolved_category or None,
                resolution_state=execution_plan.resolution_state,
                last_execution_plan=execution_plan,
            )
            cls._emit_jit_selection_trace(
                enabled=debug_enabled,
                detected_intent=detected_intent,
                active_category_override=active_category,
                final_selected_category=execution_plan.resolved_category,
                selected_tools=finalized_tools,
            )
            return finalized_tools

        logger.critical(
            "Critical tool resolution failure for category '%s': merged tool names=%s but no active tools matched",
            selected_category,
            sorted(allowed_tool_names),
        )
        raise AgentsException(
            "Critical tool resolution failure: category/global tool selection produced an empty active tool list"
        )

    @staticmethod
    def _get_model_message_history(agent: Agent[Any]) -> Any | None:
        model_obj = getattr(agent, "model", None)
        if model_obj is None or isinstance(model_obj, str):
            return None
        return getattr(cast(Any, model_obj), "message_history", None)

    @staticmethod
    def _set_model_message_history(agent: Agent[Any], history: Any) -> bool:
        model_obj = getattr(agent, "model", None)
        if model_obj is None or isinstance(model_obj, str):
            return False
        if not hasattr(model_obj, "message_history"):
            return False
        setattr(cast(Any, model_obj), "message_history", history)
        return True

    @classmethod
    def _try_share_handoff_message_history(
        cls,
        previous_agent: Agent[Any],
        current_agent: Agent[Any],
    ) -> None:
        previous_history = cls._get_model_message_history(previous_agent)
        if previous_history is None:
            return

        try:
            from cerberus.agents.patterns.utils import is_swarm_pattern

            if is_swarm_pattern(previous_agent) or is_swarm_pattern(current_agent):
                if cls._set_model_message_history(current_agent, previous_history):
                    from cerberus.agents.simple_agent_manager import AGENT_MANAGER

                    AGENT_MANAGER.share_swarm_history(previous_agent.name, current_agent.name)
                return
        except ImportError:
            pass

        for handoff_item in current_agent.handoffs:
            if isinstance(handoff_item, Handoff):
                can_handoff_back = handoff_item.agent_name == previous_agent.name
            elif isinstance(handoff_item, Agent):
                can_handoff_back = handoff_item.name == previous_agent.name
            else:
                can_handoff_back = False

            if can_handoff_back:
                cls._set_model_message_history(current_agent, previous_history)
                break

    @staticmethod
    def _audit_runner_exception(
        stage: str,
        exc: Exception,
        *,
        agent_uuid: str = "unknown",
        workspace_path: str | None = None,
    ) -> None:
        """Log runner task failures to the Cerebro audit channel when available."""
        workspace = workspace_path or Runner._workspace_path()
        try:
            from cerberus.repl.ui.logging import get_cerberus_logger

            get_cerberus_logger().audit(
                "Runner streaming task failure",
                actor="runner",
                data={
                    "stage": stage,
                    "error": str(exc),
                    "type": type(exc).__name__,
                    "agent_uuid": agent_uuid,
                    "workspace": workspace,
                },
                tags=["runner", "stream", "exception"],
            )
            return
        except Exception:
            pass

        logger.exception(
            "Runner streaming task failure at %s for %s in %s: %s",
            stage,
            agent_uuid,
            workspace,
            exc,
        )

    @classmethod
    def _consume_task_exception(
        cls,
        task: asyncio.Task[Any],
        *,
        stage: str,
        agent_uuid: str = "unknown",
        workspace_path: str | None = None,
    ) -> None:
        """Retrieve task exceptions to prevent unhandled task warnings."""
        try:
            exc = task.exception()
        except asyncio.CancelledError:
            return
        except Exception as callback_exc:
            cls._audit_runner_exception(
                stage,
                callback_exc,
                agent_uuid=agent_uuid,
                workspace_path=workspace_path,
            )
            return

        if isinstance(exc, (AttributeError, TypeError)):
            cls._audit_runner_exception(
                stage,
                exc,
                agent_uuid=agent_uuid,
                workspace_path=workspace_path,
            )
        elif isinstance(exc, Exception):
            logger.exception("Unhandled runner task exception at %s: %s", stage, exc)

    @classmethod
    async def _persist_graceful_interruption(cls, agent: Agent[Any] | None) -> None:
        """Persist in-memory findings during cooperative cancellation."""
        workspace = cls._workspace_path()
        try:
            from cerberus.memory.memory import CerberusMemoryBus

            bus = CerberusMemoryBus.get_instance(workspace_root=workspace)
            await asyncio.to_thread(bus.commit)
        except Exception as exc:
            cls._audit_runner_exception(
                "graceful_interrupt_commit",
                exc,
                agent_uuid=cls._agent_uuid(agent),
                workspace_path=workspace,
            )

    @classmethod
    async def _run_streamed_impl_safe(
        cls,
        *,
        starting_input: str | list[TResponseInputItem],
        streamed_result: RunResultStreaming,
        starting_agent: Agent[TContext],
        max_turns: int,
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        run_config: RunConfig,
    ) -> None:
        try:
            await cls._run_streamed_impl(
                starting_input=starting_input,
                streamed_result=streamed_result,
                starting_agent=starting_agent,
                max_turns=max_turns,
                hooks=hooks,
                context_wrapper=context_wrapper,
                run_config=run_config,
            )
        except (AttributeError, TypeError) as exc:
            cls._audit_runner_exception(
                "_run_streamed_impl",
                exc,
                agent_uuid=cls._agent_uuid(starting_agent),
                workspace_path=cls._workspace_path(),
            )
            raise
        finally:
            try:
                _ACTIVE_STREAMED_RESULTS.discard(streamed_result)
            except TypeError as exc:
                cls._audit_runner_exception(
                    "stream_registry_discard",
                    exc,
                    agent_uuid=cls._agent_uuid(streamed_result.current_agent),
                    workspace_path=cls._workspace_path(),
                )

    @classmethod
    async def shutdown_active_streams(cls) -> int:
        """Cancel and settle active streaming runner tasks for clean shutdown."""
        results = list(_ACTIVE_STREAMED_RESULTS)
        if not results:
            return 0

        pending_tasks: list[asyncio.Task[Any]] = []
        for result in results:
            result.is_complete = True
            try:
                result._event_queue.put_nowait(QueueCompleteSentinel())
            except Exception:
                pass

            for task in (
                result._run_impl_task,
                result._input_guardrails_task,
                result._output_guardrails_task,
            ):
                if task is not None and not task.done():
                    task.cancel()
                    pending_tasks.append(task)

        if pending_tasks:
            await asyncio.gather(*pending_tasks, return_exceptions=True)

        return len(results)

    @classmethod
    async def run(
        cls,
        starting_agent: Agent[TContext],
        input: str | list[TResponseInputItem],
        *,
        context: TContext | None = None,
        max_turns: int = DEFAULT_MAX_TURNS,
        hooks: RunHooks[TContext] | None = None,
        run_config: RunConfig | None = None,
    ) -> RunResult:
        """Run a workflow starting at the given agent. The agent will run in a loop until a final
        output is generated. The loop runs like so:
        1. The agent is invoked with the given input.
        2. If there is a final output (i.e. the agent produces something of type
            `agent.output_type`, the loop terminates.
        3. If there's a handoff, we run the loop again, with the new agent.
        4. Else, we run tool calls (if any), and re-run the loop.

        In two cases, the agent may raise an exception:
        1. If the max_turns is exceeded, a MaxTurnsExceeded exception is raised.
        2. If a guardrail tripwire is triggered, a GuardrailTripwireTriggered exception is raised.

        Note that only the first agent's input guardrails are run.

        Args:
            starting_agent: The starting agent to run.
            input: The initial input to the agent. You can pass a single string for a user message,
                or a list of input items.
            context: The context to run the agent with.
            max_turns: The maximum number of turns to run the agent for. A turn is defined as one
                AI invocation (including any tool calls that might occur).
            hooks: An object that receives callbacks on various lifecycle events.
            run_config: Global settings for the entire agent run.

        Returns:
            A run result containing all the inputs, guardrail results and the output of the last
            agent. Agents may perform handoffs, so we don't know the specific type of the output.
        """
        if hooks is None:
            hooks = RunHooks[Any]()
        if run_config is None:
            run_config = RunConfig()

        tool_use_tracker = AgentToolUseTracker()

        with TraceCtxManager(
            workflow_name=run_config.workflow_name,
            trace_id=run_config.trace_id,
            group_id=run_config.group_id,
            metadata=run_config.trace_metadata,
            disabled=run_config.tracing_disabled,
        ):
            current_turn = 0
            original_input: str | list[TResponseInputItem] = copy.deepcopy(input)
            generated_items: list[RunItem] = []
            model_responses: list[ModelResponse] = []

            context_wrapper: RunContextWrapper[TContext] = RunContextWrapper(
                context=context,  # type: ignore
            )

            input_guardrail_results: list[InputGuardrailResult] = []

            current_span: Span[AgentSpanData] | None = None
            current_agent = starting_agent
            should_run_agent_start_hooks = True
            all_tools: list[Tool] = []

            try:
                while True:
                    # Start an agent span if we don't have one. This span is ended if the current
                    # agent changes, or if the agent loop ends.
                    if current_span is None:
                        handoff_names = [h.agent_name for h in cls._get_handoffs(current_agent)]
                        if output_schema := cls._get_output_schema(current_agent):
                            output_type_name = output_schema.output_type_name()
                        else:
                            output_type_name = "str"

                        current_span = agent_span(
                            name=current_agent.name,
                            handoffs=handoff_names,
                            output_type=output_type_name,
                        )
                        current_span.start(mark_as_current=True)

                        all_tools = await cls._get_all_tools(current_agent)
                        current_span.span_data.tools = cls._resolve_tool_names(all_tools)

                    current_turn += 1
                    if current_turn > max_turns:
                        _error_tracing.attach_error_to_span(
                            current_span,
                            SpanError(
                                message="Max turns exceeded",
                                data={"max_turns": max_turns},
                            ),
                        )
                        raise MaxTurnsExceeded(f"Max turns ({max_turns}) exceeded")

                    logger.debug(
                        f"Running agent {current_agent.name} (turn {current_turn})",
                    )

                    if current_turn == 1:
                        input_guardrail_results = await cls._run_input_guardrails(
                            starting_agent,
                            starting_agent.input_guardrails
                            + (run_config.input_guardrails or []),
                            copy.deepcopy(input),
                            context_wrapper,
                        )
                        turn_tools = cls._select_tools_for_turn(
                            all_tools,
                            cast(RunContextWrapper[Any], context_wrapper),
                            original_input,
                        )
                        turn_result = await cls._run_single_turn(
                            agent=current_agent,
                            all_tools=turn_tools,
                            original_input=original_input,
                            generated_items=generated_items,
                            hooks=hooks,
                            context_wrapper=context_wrapper,
                            run_config=run_config,
                            should_run_agent_start_hooks=should_run_agent_start_hooks,
                            tool_use_tracker=tool_use_tracker,
                        )
                    else:
                        turn_tools = cls._select_tools_for_turn(
                            all_tools,
                            cast(RunContextWrapper[Any], context_wrapper),
                            original_input,
                        )
                        turn_result = await cls._run_single_turn(
                            agent=current_agent,
                            all_tools=turn_tools,
                            original_input=original_input,
                            generated_items=generated_items,
                            hooks=hooks,
                            context_wrapper=context_wrapper,
                            run_config=run_config,
                            should_run_agent_start_hooks=should_run_agent_start_hooks,
                            tool_use_tracker=tool_use_tracker,
                        )
                    should_run_agent_start_hooks = False

                    model_responses.append(turn_result.model_response)
                    original_input = turn_result.original_input
                    generated_items = turn_result.generated_items

                    if isinstance(turn_result.next_step, NextStepFinalOutput):
                        output_guardrail_results = await cls._run_output_guardrails(
                            current_agent.output_guardrails + (run_config.output_guardrails or []),
                            current_agent,
                            turn_result.next_step.output,
                            context_wrapper,
                        )
                        return RunResult(
                            input=original_input,
                            new_items=generated_items,
                            raw_responses=model_responses,
                            final_output=turn_result.next_step.output,
                            _last_agent=current_agent,
                            input_guardrail_results=input_guardrail_results,
                            output_guardrail_results=output_guardrail_results,
                        )
                    elif isinstance(turn_result.next_step, NextStepHandoff):
                        # Get the previous agent before switching
                        previous_agent = current_agent
                        current_agent = cast(Agent[TContext], turn_result.next_step.new_agent)
                        cls._try_share_handoff_message_history(previous_agent, current_agent)
                        
                        # Register the handoff agent with AGENT_MANAGER for tracking
                        # This ensures patterns/swarms work with commands like /history and /graph
                        from cerberus.agents.simple_agent_manager import AGENT_MANAGER
                        if hasattr(current_agent, 'name'):
                            # For non-parallel patterns, use set_active_agent which will handle it as single agent
                            # This maintains compatibility with single agent commands
                            AGENT_MANAGER.set_active_agent(current_agent, current_agent.name)
                        
                        current_span.finish(reset_current=True)
                        current_span = None
                        should_run_agent_start_hooks = True
                        cls._reset_tool_retry_state(context_wrapper)
                    elif isinstance(turn_result.next_step, NextStepRunAgain):
                        if context_wrapper.suppress_next_tool_loop_warning:
                            context_wrapper.suppress_next_tool_loop_warning = False
                            cls._reset_primary_tool_signature_state(context_wrapper)
                            continue

                        tool_name, tool_args = cls._extract_primary_tool_signature(turn_result)
                        if tool_name is not None and tool_args is not None:
                            consecutive_tool_count = cls._record_tool_attempt(
                                context_wrapper,
                                tool_name,
                                tool_args,
                            )

                            if consecutive_tool_count == 3:
                                warning_item = cls._system_warning_input_item(
                                    cls._build_circuit_breaker_warning(
                                        tool_name,
                                        tool_args,
                                        context_wrapper.last_tool_validation or None,
                                    )
                                )
                                original_input = ItemHelpers.input_to_new_input_list(original_input)
                                original_input.append(warning_item)
                            elif consecutive_tool_count == 7:
                                raise AgentLoopError(
                                    "[SYSTEM] Agent execution terminated due to infinite tool loop."
                                )
                    else:
                        raise AgentsException(
                            f"Unknown next step type: {type(turn_result.next_step)}"
                        )
            finally:
                if current_span:
                    current_span.finish(reset_current=True)

    @classmethod
    def run_sync(
        cls,
        starting_agent: Agent[TContext],
        input: str | list[TResponseInputItem],
        *,
        context: TContext | None = None,
        max_turns: int = DEFAULT_MAX_TURNS,
        hooks: RunHooks[TContext] | None = None,
        run_config: RunConfig | None = None,
    ) -> RunResult:
        """Run a workflow synchronously, starting at the given agent. Note that this just wraps the
        `run` method, so it will not work if there's already an event loop (e.g. inside an async
        function, or in a Jupyter notebook or async context like FastAPI). For those cases, use
        the `run` method instead.

        The agent will run in a loop until a final output is generated. The loop runs like so:
        1. The agent is invoked with the given input.
        2. If there is a final output (i.e. the agent produces something of type
            `agent.output_type`, the loop terminates.
        3. If there's a handoff, we run the loop again, with the new agent.
        4. Else, we run tool calls (if any), and re-run the loop.

        In two cases, the agent may raise an exception:
        1. If the max_turns is exceeded, a MaxTurnsExceeded exception is raised.
        2. If a guardrail tripwire is triggered, a GuardrailTripwireTriggered exception is raised.

        Note that only the first agent's input guardrails are run.

        Args:
            starting_agent: The starting agent to run.
            input: The initial input to the agent. You can pass a single string for a user message,
                or a list of input items.
            context: The context to run the agent with.
            max_turns: The maximum number of turns to run the agent for. A turn is defined as one
                AI invocation (including any tool calls that might occur).
            hooks: An object that receives callbacks on various lifecycle events.
            run_config: Global settings for the entire agent run.

        Returns:
            A run result containing all the inputs, guardrail results and the output of the last
            agent. Agents may perform handoffs, so we don't know the specific type of the output.
        """
        return asyncio.get_event_loop().run_until_complete(
            cls.run(
                starting_agent,
                input,
                context=context,
                max_turns=max_turns,
                hooks=hooks,
                run_config=run_config,
            )
        )

    @classmethod
    def run_streamed(
        cls,
        starting_agent: Agent[TContext],
        input: str | list[TResponseInputItem],
        context: TContext | None = None,
        max_turns: int = DEFAULT_MAX_TURNS,
        hooks: RunHooks[TContext] | None = None,
        run_config: RunConfig | None = None,
    ) -> RunResultStreaming:
        """Run a workflow starting at the given agent in streaming mode. The returned result object
        contains a method you can use to stream semantic events as they are generated.

        The agent will run in a loop until a final output is generated. The loop runs like so:
        1. The agent is invoked with the given input.
        2. If there is a final output (i.e. the agent produces something of type
            `agent.output_type`, the loop terminates.
        3. If there's a handoff, we run the loop again, with the new agent.
        4. Else, we run tool calls (if any), and re-run the loop.

        In two cases, the agent may raise an exception:
        1. If the max_turns is exceeded, a MaxTurnsExceeded exception is raised.
        2. If a guardrail tripwire is triggered, a GuardrailTripwireTriggered exception is raised.

        Note that only the first agent's input guardrails are run.

        Args:
            starting_agent: The starting agent to run.
            input: The initial input to the agent. You can pass a single string for a user message,
                or a list of input items.
            context: The context to run the agent with.
            max_turns: The maximum number of turns to run the agent for. A turn is defined as one
                AI invocation (including any tool calls that might occur).
            hooks: An object that receives callbacks on various lifecycle events.
            run_config: Global settings for the entire agent run.

        Returns:
            A result object that contains data about the run, as well as a method to stream events.
        """
        if hooks is None:
            hooks = RunHooks[Any]()
        if run_config is None:
            run_config = RunConfig()

        # If there's already a trace, we don't create a new one. In addition, we can't end the
        # trace here, because the actual work is done in `stream_events` and this method ends
        # before that.
        new_trace = (
            None
            if get_current_trace()
            else trace(
                workflow_name=run_config.workflow_name,
                trace_id=run_config.trace_id,
                group_id=run_config.group_id,
                metadata=run_config.trace_metadata,
                disabled=run_config.tracing_disabled,
            )
        )
        # Need to start the trace here, because the current trace contextvar is captured at
        # asyncio.create_task time
        if new_trace:
            new_trace.start(mark_as_current=True)

        output_schema = cls._get_output_schema(starting_agent)
        context_wrapper: RunContextWrapper[TContext] = RunContextWrapper(
            context=context  # type: ignore
        )

        streamed_result = RunResultStreaming(
            input=copy.deepcopy(input),
            new_items=[],
            current_agent=starting_agent,
            raw_responses=[],
            final_output=None,
            is_complete=False,
            current_turn=0,
            max_turns=max_turns,
            input_guardrail_results=[],
            output_guardrail_results=[],
            _current_agent_output_schema=output_schema,
            _trace=new_trace,
        )

        # Kick off the actual agent loop in the background and return the streamed result object.
        streamed_result._run_impl_task = asyncio.create_task(
            cls._run_streamed_impl_safe(
                starting_input=input,
                streamed_result=streamed_result,
                starting_agent=starting_agent,
                max_turns=max_turns,
                hooks=hooks,
                context_wrapper=context_wrapper,
                run_config=run_config,
            )
        )
        streamed_result._run_impl_task.add_done_callback(
            lambda task: cls._consume_task_exception(task, stage="run_streamed")
        )
        try:
            _ACTIVE_STREAMED_RESULTS.add(streamed_result)
        except TypeError as exc:
            cls._audit_runner_exception(
                "stream_registry_add",
                exc,
                agent_uuid=cls._agent_uuid(starting_agent),
                workspace_path=cls._workspace_path(),
            )
        return streamed_result

    @classmethod
    async def _run_input_guardrails_with_queue(
        cls,
        agent: Agent[Any],
        guardrails: list[InputGuardrail[TContext]],
        input: str | list[TResponseInputItem],
        context: RunContextWrapper[TContext],
        streamed_result: RunResultStreaming,
        parent_span: Span[Any],
    ):
        queue = streamed_result._input_guardrail_queue

        # We'll run the guardrails and push them onto the queue as they complete
        guardrail_tasks = [
            asyncio.create_task(
                RunImpl.run_single_input_guardrail(agent, guardrail, input, context)
            )
            for guardrail in guardrails
        ]
        guardrail_results = []
        try:
            for done in asyncio.as_completed(guardrail_tasks):
                result = await done
                if result.output.tripwire_triggered:
                    # Cancel all guardrail tasks if a tripwire is triggered.
                    for t in guardrail_tasks:
                        t.cancel()
                    _error_tracing.attach_error_to_span(
                        parent_span,
                        SpanError(
                            message="Guardrail tripwire triggered",
                            data={
                                "guardrail": result.guardrail.get_name(),
                                "type": "input_guardrail",
                            },
                        ),
                    )
                    # Put the tripwire result on the queue and include it in results
                    queue.put_nowait(result)
                    guardrail_results.append(result)
                    break
                else:
                    queue.put_nowait(result)
                    guardrail_results.append(result)
        except Exception:
            for t in guardrail_tasks:
                t.cancel()
            raise

        streamed_result.input_guardrail_results = guardrail_results
        return guardrail_results

    @classmethod
    async def _run_streamed_impl(
        cls,
        starting_input: str | list[TResponseInputItem],
        streamed_result: RunResultStreaming,
        starting_agent: Agent[TContext],
        max_turns: int,
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        run_config: RunConfig,
    ):
        current_span: Span[AgentSpanData] | None = None
        current_agent = starting_agent
        current_turn = 0
        should_run_agent_start_hooks = True
        tool_use_tracker = AgentToolUseTracker()
        all_tools: list[Tool] = []

        streamed_result._event_queue.put_nowait(AgentUpdatedStreamEvent(new_agent=current_agent))

        try:
            while True:
                if streamed_result.is_complete:
                    break

                # Start an agent span if we don't have one. This span is ended if the current
                # agent changes, or if the agent loop ends.
                if current_span is None:
                    handoff_names = [h.agent_name for h in cls._get_handoffs(current_agent)]
                    if output_schema := cls._get_output_schema(current_agent):
                        output_type_name = output_schema.output_type_name()
                    else:
                        output_type_name = "str"

                    current_span = agent_span(
                        name=current_agent.name,
                        handoffs=handoff_names,
                        output_type=output_type_name,
                    )
                    current_span.start(mark_as_current=True)

                    all_tools = await cls._get_all_tools(current_agent)
                    tool_names = cls._resolve_tool_names(all_tools)
                    current_span.span_data.tools = tool_names
                current_turn += 1
                streamed_result.current_turn = current_turn

                if current_turn > max_turns:
                    _error_tracing.attach_error_to_span(
                        current_span,
                        SpanError(
                            message="Max turns exceeded",
                            data={"max_turns": max_turns},
                        ),
                    )
                    streamed_result._event_queue.put_nowait(QueueCompleteSentinel())
                    break

                if current_turn == 1:
                    # Run the input guardrails in the background and put the results on the queue
                    streamed_result._input_guardrails_task = asyncio.create_task(
                        cls._run_input_guardrails_with_queue(
                            starting_agent,
                            starting_agent.input_guardrails + (run_config.input_guardrails or []),
                            copy.deepcopy(ItemHelpers.input_to_new_input_list(starting_input)),
                            context_wrapper,
                            streamed_result,
                            current_span,
                        )
                    )
                try:
                    turn_tools = cls._select_tools_for_turn(
                        all_tools,
                        cast(RunContextWrapper[Any], context_wrapper),
                        streamed_result.input,
                    )
                    turn_result = await cls._run_single_turn_streamed(
                        streamed_result,
                        current_agent,
                        hooks,
                        context_wrapper,
                        run_config,
                        should_run_agent_start_hooks,
                        tool_use_tracker,
                        turn_tools,
                    )
                    should_run_agent_start_hooks = False
                    
                    # Process the turn result
                    streamed_result.raw_responses = streamed_result.raw_responses + [
                        turn_result.model_response
                    ]
                    streamed_result.input = turn_result.original_input
                    streamed_result.new_items = turn_result.generated_items

                    if isinstance(turn_result.next_step, NextStepHandoff):
                        # Get the previous agent before switching
                        previous_agent = current_agent
                        current_agent = turn_result.next_step.new_agent
                        cls._try_share_handoff_message_history(previous_agent, current_agent)
                        
                        current_span.finish(reset_current=True)
                        current_span = None
                        should_run_agent_start_hooks = True
                        cls._reset_tool_retry_state(context_wrapper)
                        streamed_result._event_queue.put_nowait(
                            AgentUpdatedStreamEvent(new_agent=current_agent)
                        )
                    elif isinstance(turn_result.next_step, NextStepFinalOutput):
                        streamed_result._output_guardrails_task = asyncio.create_task(
                            cls._run_output_guardrails(
                                current_agent.output_guardrails
                                + (run_config.output_guardrails or []),
                                current_agent,
                                turn_result.next_step.output,
                                context_wrapper,
                            )
                        )

                        try:
                            output_guardrail_results = await streamed_result._output_guardrails_task
                        except Exception:
                            # Exceptions will be checked in the stream_events loop
                            output_guardrail_results = []

                        streamed_result.output_guardrail_results = output_guardrail_results
                        streamed_result.final_output = turn_result.next_step.output
                        streamed_result.is_complete = True
                        streamed_result._event_queue.put_nowait(QueueCompleteSentinel())
                    elif isinstance(turn_result.next_step, NextStepRunAgain):
                        if context_wrapper.suppress_next_tool_loop_warning:
                            context_wrapper.suppress_next_tool_loop_warning = False
                            cls._reset_primary_tool_signature_state(context_wrapper)
                            continue

                        tool_name, tool_args = cls._extract_primary_tool_signature(turn_result)
                        if tool_name is not None and tool_args is not None:
                            consecutive_tool_count = cls._record_tool_attempt(
                                context_wrapper,
                                tool_name,
                                tool_args,
                            )

                            if consecutive_tool_count == 3:
                                warning_item = cls._system_warning_input_item(
                                    cls._build_circuit_breaker_warning(
                                        tool_name,
                                        tool_args,
                                        context_wrapper.last_tool_validation or None,
                                    )
                                )
                                streamed_result.input = ItemHelpers.input_to_new_input_list(streamed_result.input)
                                streamed_result.input.append(warning_item)
                            elif consecutive_tool_count == 7:
                                raise AgentLoopError(
                                    "[SYSTEM] Agent execution terminated due to infinite tool loop."
                                )
                except asyncio.CancelledError:
                    await cls._persist_graceful_interruption(current_agent)
                    streamed_result.is_complete = True
                    streamed_result._event_queue.put_nowait(QueueCompleteSentinel())
                    break
                except KeyboardInterrupt as exc:
                    raise exc
                except Exception as e:
                    if current_span:
                        _error_tracing.attach_error_to_span(
                            current_span,
                            SpanError(
                                message="Error in agent run",
                                data={"error": str(e)},
                            ),
                        )
                    streamed_result.is_complete = True
                    streamed_result._event_queue.put_nowait(QueueCompleteSentinel())
                    raise

            streamed_result.is_complete = True
        except asyncio.CancelledError:
            await cls._persist_graceful_interruption(current_agent)
            streamed_result.is_complete = True
            try:
                streamed_result._event_queue.put_nowait(QueueCompleteSentinel())
            except Exception:
                pass
        finally:
            if current_span:
                current_span.finish(reset_current=True)

    @classmethod
    async def _run_single_turn_streamed(
        cls,
        streamed_result: RunResultStreaming,
        agent: Agent[TContext],
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        run_config: RunConfig,
        should_run_agent_start_hooks: bool,
        tool_use_tracker: AgentToolUseTracker,
        all_tools: list[Tool],
    ) -> SingleStepResult:
        if should_run_agent_start_hooks:
            await hooks.on_agent_start_awaited(context_wrapper, agent)
            if agent.hooks:
                await agent.hooks.on_start_awaited(context_wrapper, agent)

        output_schema = cls._get_output_schema(agent)

        streamed_result.current_agent = agent
        streamed_result._current_agent_output_schema = output_schema

        system_prompt = await agent.get_system_prompt(context_wrapper)

        handoffs = cls._get_handoffs(agent)
        model = cls._get_model(agent, run_config)
        model_settings = agent.model_settings.resolve(run_config.model_settings)
        model_settings = RunImpl.maybe_reset_tool_choice(agent, tool_use_tracker, model_settings)

        # Ensure agent model is set in model_settings for streaming mode
        if not hasattr(model_settings, "agent_model") or not model_settings.agent_model:
            if isinstance(agent.model, str):
                model_settings.agent_model = agent.model
            elif isinstance(run_config.model, str):
                model_settings.agent_model = run_config.model

        final_response: ModelResponse | None = None
        stream_event_seen = False

        input = ItemHelpers.input_to_new_input_list(streamed_result.input)
        input.extend([item.to_input_item() for item in streamed_result.new_items])
        input = cls._apply_policy_preflight(
            input_items=input,
            all_tools=all_tools,
            context_wrapper=cast(RunContextWrapper[Any], context_wrapper),
        )

        # 1. Stream the output events
        try:
            async for event in model.stream_response(
                system_prompt,
                input,
                model_settings,
                all_tools,
                output_schema,
                handoffs,
                get_model_tracing_impl(
                    run_config.tracing_disabled, run_config.trace_include_sensitive_data
                ),
            ):
                stream_event_seen = True
                if isinstance(event, ResponseCompletedEvent):
                    usage = (
                        Usage(
                            requests=1,
                            input_tokens=event.response.usage.input_tokens,
                            output_tokens=event.response.usage.output_tokens,
                            total_tokens=event.response.usage.total_tokens,
                        )
                        if event.response.usage
                        else Usage()
                    )
                    final_response = ModelResponse(
                        output=event.response.output,
                        usage=usage,
                        referenceable_id=event.response.id,
                    )

                streamed_result._event_queue.put_nowait(RawResponsesStreamEvent(data=event))
        except Exception as exc:
            cls._audit_runner_exception(
                "llm_stream_call",
                exc,
                agent_uuid=cls._agent_uuid(agent),
                workspace_path=cls._workspace_path(),
            )
            raise

        # 2. At this point, the streaming is complete for this turn of the agent loop.
        if not final_response:
            if not stream_event_seen:
                cls._audit_runner_exception(
                    "llm_not_contacted",
                    RuntimeError("No events received from model.stream_response"),
                    agent_uuid=cls._agent_uuid(agent),
                    workspace_path=cls._workspace_path(),
                )
            raise ModelBehaviorError("Model did not produce a final response!")

        # 3. Now, we can process the turn as we do in the non-streaming case
        single_step_result = None
        # Start a lightweight heartbeat while we wait for tool execution to complete.
        # This periodically enqueues a RawResponsesStreamEvent so streaming clients
        # remain active and can show progress while tools run.
        heartbeat_task = None
        try:
            raw_heartbeat_interval = os.getenv("CERBERUS_HEARTBEAT_INTERVAL", "5")
            heartbeat_interval = safe_duration_to_float(raw_heartbeat_interval) or 5.0
            heartbeat_interval = max(1.0, heartbeat_interval)

            async def _streaming_heartbeat():
                jitter = random.random() * (heartbeat_interval * 0.2)
                await asyncio.sleep(jitter)
                while True:
                    try:
                        streamed_result._event_queue.put_nowait(
                            RawResponsesStreamEvent(
                                data=cast(Any, {"type": "heartbeat", "ts": time.time()})
                            )
                        )
                    except Exception:
                        pass
                    await asyncio.sleep(heartbeat_interval)

            if hasattr(streamed_result, "_event_queue") and streamed_result._event_queue is not None:
                heartbeat_task = asyncio.create_task(_streaming_heartbeat())

            single_step_result = await cls._get_single_step_result_from_response(
                agent=agent,
                original_input=streamed_result.input,
                pre_step_items=streamed_result.new_items,
                new_response=final_response,
                output_schema=output_schema,
                all_tools=all_tools,
                handoffs=handoffs,
                hooks=hooks,
                context_wrapper=context_wrapper,
                run_config=run_config,
                tool_use_tracker=tool_use_tracker,
            )

            RunImpl.stream_step_result_to_queue(single_step_result, streamed_result._event_queue)
            return single_step_result
        except (KeyboardInterrupt, asyncio.CancelledError) as e:
            # When interrupted, we need to ensure the message history is consistent
            # The tool calls were already added during streaming, but results were not
            # If we have a partial result, stream it before re-raising
            if single_step_result:
                RunImpl.stream_step_result_to_queue(single_step_result, streamed_result._event_queue)
            raise e
        finally:
            if heartbeat_task:
                heartbeat_task.cancel()
                try:
                    await heartbeat_task
                except asyncio.CancelledError:
                    pass
                except Exception:
                    pass

    @classmethod
    async def _run_single_turn(
        cls,
        *,
        agent: Agent[TContext],
        all_tools: list[Tool],
        original_input: str | list[TResponseInputItem],
        generated_items: list[RunItem],
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        run_config: RunConfig,
        should_run_agent_start_hooks: bool,
        tool_use_tracker: AgentToolUseTracker,
    ) -> SingleStepResult:
        # Ensure we run the hooks before anything else
        if should_run_agent_start_hooks:
            await hooks.on_agent_start_awaited(context_wrapper, agent)
            if agent.hooks:
                await agent.hooks.on_start_awaited(context_wrapper, agent)

        system_prompt = await agent.get_system_prompt(context_wrapper)

        output_schema = cls._get_output_schema(agent)
        handoffs = cls._get_handoffs(agent)
        input = ItemHelpers.input_to_new_input_list(original_input)
        input.extend([generated_item.to_input_item() for generated_item in generated_items])
        input = cls._apply_policy_preflight(
            input_items=input,
            all_tools=all_tools,
            context_wrapper=cast(RunContextWrapper[Any], context_wrapper),
        )

        new_response = await cls._get_new_response(
            agent,
            system_prompt,
            input,
            output_schema,
            all_tools,
            handoffs,
            context_wrapper,
            run_config,
            tool_use_tracker,
        )

        return await cls._get_single_step_result_from_response(
            agent=agent,
            original_input=original_input,
            pre_step_items=generated_items,
            new_response=new_response,
            output_schema=output_schema,
            all_tools=all_tools,
            handoffs=handoffs,
            hooks=hooks,
            context_wrapper=context_wrapper,
            run_config=run_config,
            tool_use_tracker=tool_use_tracker,
        )

    @classmethod
    async def _get_single_step_result_from_response(
        cls,
        *,
        agent: Agent[TContext],
        all_tools: list[Tool],
        original_input: str | list[TResponseInputItem],
        pre_step_items: list[RunItem],
        new_response: ModelResponse,
        output_schema: AgentOutputSchema | None,
        handoffs: list[Handoff],
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        run_config: RunConfig,
        tool_use_tracker: AgentToolUseTracker,
    ) -> SingleStepResult:
        processed_response = RunImpl.process_model_response(
            agent=agent,
            all_tools=all_tools,
            response=new_response,
            output_schema=output_schema,
            handoffs=handoffs,
        )

        planned_calls = cls._extract_planned_calls(processed_response)
        policy_engine = PolicyEngine(
            workspace_dir=cls._workspace_path(),
            project_id=os.getenv("CERBERUS_PROJECT_ID"),
        )
        previous_signature = (
            (context_wrapper.last_tool_name, context_wrapper.last_tool_args)
            if context_wrapper.last_tool_name
            else None
        )
        post_audit = policy_engine.run_post_audit(
            planned_calls=planned_calls,
            available_tools=cls._resolve_tool_names(cast(list[Any], all_tools)),
            previous_signature=previous_signature,
        )
        cls._append_policy_audit(cast(RunContextWrapper[Any], context_wrapper), post_audit)

        if post_audit.blocked:
            corrected_input = ItemHelpers.input_to_new_input_list(original_input)
            corrected_input.append(
                cls._system_warning_input_item(cls._build_policy_warning_message(post_audit))
            )
            return SingleStepResult(
                original_input=corrected_input,
                model_response=new_response,
                pre_step_items=pre_step_items,
                new_step_items=list(processed_response.new_items),
                next_step=NextStepRunAgain(),
            )

        # Log tools used with robust type checking
        if hasattr(processed_response, "tools_used") and processed_response.tools_used:
            for i, tool_call in enumerate(processed_response.tools_used):
                tool_call_obj = cast(Any, tool_call)
                try:
                    # Safely extract tool name with multiple fallbacks
                    tool_name = "Unknown"
                    try:
                        tool_field = getattr(tool_call_obj, "tool", None)
                        if isinstance(tool_field, str):
                            tool_name = tool_field
                        elif hasattr(tool_field, "name"):
                            tool_name = str(getattr(tool_field, "name"))
                        elif tool_field is not None:
                            tool_name = str(tool_field)
                    except Exception:
                        pass

                    # Safely extract call_id
                    call_id = "Unknown"
                    try:
                        call_id_field = getattr(tool_call_obj, "call_id", None)
                        if call_id_field is not None:
                            call_id = str(call_id_field)
                    except Exception:
                        pass

                    # Safely extract parsed_args
                    parsed_args = "Unknown"
                    try:
                        parsed_args_field = getattr(tool_call_obj, "parsed_args", None)
                        if parsed_args_field is not None:
                            parsed_args = str(parsed_args_field)
                    except Exception:
                        pass
                except Exception:
                    pass

        tool_use_tracker.add_tool_use(agent, processed_response.tools_used)

        return await RunImpl.execute_tools_and_side_effects(
            agent=agent,
            original_input=original_input,
            pre_step_items=pre_step_items,
            new_response=new_response,
            processed_response=processed_response,
            output_schema=output_schema,
            hooks=hooks,
            context_wrapper=context_wrapper,
            run_config=run_config,
        )

    @classmethod
    async def _run_input_guardrails(
        cls,
        agent: Agent[Any],
        guardrails: list[InputGuardrail[TContext]],
        input: str | list[TResponseInputItem],
        context: RunContextWrapper[TContext],
    ) -> list[InputGuardrailResult]:
        if not guardrails:
            return []

        guardrail_tasks = [
            asyncio.create_task(
                RunImpl.run_single_input_guardrail(agent, guardrail, input, context)
            )
            for guardrail in guardrails
        ]

        guardrail_results = []

        for done in asyncio.as_completed(guardrail_tasks):
            result = await done
            if result.output.tripwire_triggered:
                # Cancel all guardrail tasks if a tripwire is triggered.
                for t in guardrail_tasks:
                    t.cancel()
                _error_tracing.attach_error_to_current_span(
                    SpanError(
                        message="Guardrail tripwire triggered",
                        data={"guardrail": result.guardrail.get_name()},
                    )
                )
                raise InputGuardrailTripwireTriggered(result)
            else:
                guardrail_results.append(result)

        return guardrail_results

    @classmethod
    async def _run_output_guardrails(
        cls,
        guardrails: list[OutputGuardrail[TContext]],
        agent: Agent[TContext],
        agent_output: Any,
        context: RunContextWrapper[TContext],
    ) -> list[OutputGuardrailResult]:
        if not guardrails:
            return []

        guardrail_tasks = [
            asyncio.create_task(
                RunImpl.run_single_output_guardrail(guardrail, agent, agent_output, context)
            )
            for guardrail in guardrails
        ]

        guardrail_results = []

        for done in asyncio.as_completed(guardrail_tasks):
            result = await done
            if result.output.tripwire_triggered:
                # Cancel all guardrail tasks if a tripwire is triggered.
                for t in guardrail_tasks:
                    t.cancel()
                _error_tracing.attach_error_to_current_span(
                    SpanError(
                        message="Guardrail tripwire triggered",
                        data={"guardrail": result.guardrail.get_name()},
                    )
                )
                raise OutputGuardrailTripwireTriggered(result)
            else:
                guardrail_results.append(result)

        return guardrail_results

    @classmethod
    async def _get_new_response(
        cls,
        agent: Agent[TContext],
        system_prompt: str | None,
        input: list[TResponseInputItem],
        output_schema: AgentOutputSchema | None,
        all_tools: list[Tool],
        handoffs: list[Handoff],
        context_wrapper: RunContextWrapper[TContext],
        run_config: RunConfig,
        tool_use_tracker: AgentToolUseTracker,
    ) -> ModelResponse:
        model = cls._get_model(agent, run_config)
        model_settings = agent.model_settings.resolve(run_config.model_settings)
        model_settings = RunImpl.maybe_reset_tool_choice(agent, tool_use_tracker, model_settings)

        # Ensure agent model is set in model_settings
        if not hasattr(model_settings, "agent_model") or not model_settings.agent_model:
            if isinstance(agent.model, str):
                model_settings.agent_model = agent.model
            elif isinstance(run_config.model, str):
                model_settings.agent_model = run_config.model

        new_response = await model.get_response(
            system_instructions=system_prompt,
            input=input,
            model_settings=model_settings,
            tools=all_tools,
            output_schema=output_schema,
            handoffs=handoffs,
            tracing=get_model_tracing_impl(
                run_config.tracing_disabled, run_config.trace_include_sensitive_data
            ),
        )

        context_wrapper.usage.add(new_response.usage)

        return new_response

    @classmethod
    def _get_output_schema(cls, agent: Agent[Any]) -> AgentOutputSchema | None:
        if agent.output_type is None or agent.output_type is str:
            return None

        return AgentOutputSchema(agent.output_type)

    @classmethod
    def _get_handoffs(cls, agent: Agent[Any]) -> list[Handoff]:
        handoffs = []
        for handoff_item in agent.handoffs:
            if isinstance(handoff_item, Handoff):
                handoffs.append(handoff_item)
            elif isinstance(handoff_item, Agent):
                handoffs.append(handoff(handoff_item))
        return handoffs

    @classmethod
    async def _get_all_tools(cls, agent: Agent[Any]) -> list[Tool]:
        return await agent.get_all_tools()

    @classmethod
    def _get_model(cls, agent: Agent[Any], run_config: RunConfig) -> Model:
        model = None
        agent_model = None
        if isinstance(run_config.model, Model):
            model = run_config.model
        elif isinstance(run_config.model, str):
            model = run_config.model_provider.get_model(run_config.model)
            agent_model = run_config.model
        elif isinstance(agent.model, Model):
            model = agent.model
        else:
            model = run_config.model_provider.get_model(agent.model)
            agent_model = agent.model

        # Store the original agent model in model_settings for later use
        if agent_model and hasattr(agent, "model_settings"):
            agent.model_settings.agent_model = agent_model

        # Set agent name if the model supports it (for CLI display)
        set_agent_name = getattr(model, "set_agent_name", None)
        if callable(set_agent_name):
            set_agent_name(agent.name)

        return model
