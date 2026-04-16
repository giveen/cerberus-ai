from __future__ import annotations

import inspect
import json
import ast
import re
from collections.abc import Awaitable
from dataclasses import dataclass
from typing import Any, Callable, Literal, Union, overload

from openai.types.responses.file_search_tool_param import Filters, RankingOptions
from openai.types.responses.web_search_tool_param import UserLocation
from pydantic import ValidationError
from typing_extensions import Concatenate, ParamSpec

from cerberus.parsers import parse_json_lenient

from . import _debug
from .computer import AsyncComputer, Computer
from .exceptions import ModelBehaviorError
from .function_schema import DocstringStyle, function_schema
from .items import RunItem
from .logger import logger
from .run_context import RunContextWrapper
from .tracing import SpanError
from .util import _error_tracing
from .util._types import MaybeAwaitable


def truncate_for_logging(output: Any, max_length: int = 1000) -> str:
    """Truncate output for logging purposes."""
    output_str = str(output)
    if len(output_str) <= max_length:
        return output_str
    return f"{output_str[:max_length]}... (truncated)"


def _forgiving_json_loads(s: str) -> Any:
    """Attempt to repair and parse common malformed JSON emitted by LLMs.

    Heuristics (best-effort, non-destructive):
    - extract a JSON-like substring between the first { and last } or [ and ]
    - try ast.literal_eval for python-style dicts
    - replace single quotes with double quotes and normalize True/False/None
    - fall back to simple key:value pair extraction
    Raises ValueError if unable to parse.
    """
    if not isinstance(s, str):
        raise ValueError("input must be a string")
    return parse_json_lenient(s, prefer_last=True)


def _placeholder_value_for_schema(prop_name: str, prop_schema: dict[str, Any]) -> Any:
    """Return a simple placeholder value for a JSON-schema property."""
    prop_type = prop_schema.get("type")
    if prop_type == "string":
        if prop_name.lower() in {"url", "uri"}:
            return "https://example.com"
        if prop_name.lower() in {"method", "http_method"}:
            return "GET"
        return f"<{prop_name}>"
    if prop_type in {"integer", "number"}:
        return 0
    if prop_type == "boolean":
        return False
    if prop_type == "array":
        return []
    if prop_type == "object":
        return {}
    return f"<{prop_name}>"


def _build_schema_retry_hint(schema_name: str, params_json_schema: dict[str, Any]) -> dict[str, Any]:
    """Build a structured, schema-aware retry hint for tool self-correction."""
    required_fields = _required_fields_from_schema(params_json_schema)
    properties = _schema_properties(params_json_schema)
    if not isinstance(properties, dict):
        properties = {}

    suggested_arguments: dict[str, Any] = {}
    for field in required_fields:
        field_schema = properties.get(field, {})
        if isinstance(field_schema, dict):
            suggested_arguments[field] = _placeholder_value_for_schema(field, field_schema)
        else:
            suggested_arguments[field] = f"<{field}>"

    # High-frequency failure path in this project: empty args for web_request_framework.
    if schema_name == "web_request_framework" and "url" in required_fields:
        suggested_arguments["url"] = "http://natas0.natas.labs.overthewire.org"
        suggested_arguments.setdefault("method", "GET")

    return {
        "required_fields": required_fields,
        "suggested_arguments": suggested_arguments,
        "suggested_arguments_json": json.dumps(suggested_arguments, ensure_ascii=True),
    }


def _schema_properties(params_json_schema: dict[str, Any]) -> dict[str, Any]:
    """Return normalized JSON-schema properties for a tool parameter schema."""
    properties = params_json_schema.get("properties", {})
    return properties if isinstance(properties, dict) else {}


def _required_fields_from_schema(params_json_schema: dict[str, Any]) -> list[str]:
    """Return the required field names declared by a tool schema."""
    return [field for field in params_json_schema.get("required", []) if isinstance(field, str)]


def _missing_required_fields(
    json_data: dict[str, Any], params_json_schema: dict[str, Any]
) -> list[str]:
    """Return required fields that are missing or blank in the parsed tool payload."""
    properties = _schema_properties(params_json_schema)
    missing: list[str] = []

    for field in _required_fields_from_schema(params_json_schema):
        if field not in json_data:
            missing.append(field)
            continue

        value = json_data.get(field)
        field_schema = properties.get(field, {})
        field_type = field_schema.get("type") if isinstance(field_schema, dict) else None
        if value is None:
            missing.append(field)
        elif field_type == "string" and isinstance(value, str) and not value.strip():
            # Only flag a blank string as missing when the field has no default
            # (or whose default is non-empty). Fields with default="" are optional
            # by intent — the model legitimately passes "" to accept the default.
            has_default = isinstance(field_schema, dict) and "default" in field_schema
            if not has_default:
                missing.append(field)

    return missing

ToolParams = ParamSpec("ToolParams")

ToolFunctionWithoutContext = Callable[ToolParams, Any]
ToolFunctionWithContext = Callable[Concatenate[RunContextWrapper[Any], ToolParams], Any]

ToolFunction = Union[ToolFunctionWithoutContext[ToolParams], ToolFunctionWithContext[ToolParams]]


@dataclass
class FunctionToolResult:
    tool: FunctionTool
    """The tool that was run."""

    output: Any
    """The output of the tool."""

    run_item: RunItem
    """The run item that was produced as a result of the tool call."""


@dataclass
class FunctionTool:
    """A tool that wraps a function. In most cases, you should use  the `function_tool` helpers to
    create a FunctionTool, as they let you easily wrap a Python function.
    """

    name: str
    """The name of the tool, as shown to the LLM. Generally the name of the function."""

    description: str
    """A description of the tool, as shown to the LLM."""

    params_json_schema: dict[str, Any]
    """The JSON schema for the tool's parameters."""

    on_invoke_tool: Callable[[RunContextWrapper[Any], str], Awaitable[Any]]
    """A function that invokes the tool with the given context and parameters. The params passed
    are:
    1. The tool run context.
    2. The arguments from the LLM, as a JSON string.

    You must return a string representation of the tool output, or something we can call `str()` on.
    In case of errors, you can either raise an Exception (which will cause the run to fail) or
    return a string error message (which will be sent back to the LLM).
    """

    strict_json_schema: bool = True
    """Whether the JSON schema is in strict mode. We **strongly** recommend setting this to True,
    as it increases the likelihood of correct JSON input."""

    params_pydantic_model: Any | None = None
    """Pydantic model backing this tool's argument schema."""

    risk_tier: int = 1
    """Execution risk tier for policy-gated tool invocation.

    Tier 1: Read-only/local context.
    Tier 2: Low-risk utility.
    Tier 3: Elevated impact.
    Tier 4: High-risk network/system mutation.
    """


@dataclass
class FileSearchTool:
    """A hosted tool that lets the LLM search through a vector store. Currently only supported with
    OpenAI models, using the Responses API.
    """

    vector_store_ids: list[str]
    """The IDs of the vector stores to search."""

    max_num_results: int | None = None
    """The maximum number of results to return."""

    include_search_results: bool = False
    """Whether to include the search results in the output produced by the LLM."""

    ranking_options: RankingOptions | None = None
    """Ranking options for search."""

    filters: Filters | None = None
    """A filter to apply based on file attributes."""

    @property
    def name(self):
        return "file_search"


@dataclass
class WebSearchTool:
    """A hosted tool that lets the LLM search the web. Currently only supported with OpenAI models,
    using the Responses API.
    """

    user_location: UserLocation | None = None
    """Optional location for the search. Lets you customize results to be relevant to a location."""

    search_context_size: Literal["low", "medium", "high"] = "medium"
    """The amount of context to use for the search."""

    @property
    def name(self):
        return "web_search_preview"


@dataclass
class ComputerTool:
    """A hosted tool that lets the LLM control a computer."""

    computer: Computer | AsyncComputer
    """The computer implementation, which describes the environment and dimensions of the computer,
    as well as implements the computer actions like click, screenshot, etc.
    """

    @property
    def name(self):
        return "computer_use_preview"


Tool = Union[FunctionTool, FileSearchTool, WebSearchTool, ComputerTool]
"""A tool that can be used in an agent."""


def default_tool_error_function(ctx: RunContextWrapper[Any], error: Exception) -> str:
    """The default tool error function, which just returns a generic error message."""
    return f"An error occurred while running the tool. Please try again. Error: {str(error)}"


ToolErrorFunction = Callable[[RunContextWrapper[Any], Exception], MaybeAwaitable[str]]


@overload
def function_tool(
    func: ToolFunction[...],
    *,
    name_override: str | None = None,
    description_override: str | None = None,
    docstring_style: DocstringStyle | None = None,
    use_docstring_info: bool = True,
    failure_error_function: ToolErrorFunction | None = None,
    strict_mode: bool = True,
    risk_tier: int = 1,
) -> FunctionTool:
    """Overload for usage as @function_tool (no parentheses)."""
    ...


@overload
def function_tool(
    *,
    name_override: str | None = None,
    description_override: str | None = None,
    docstring_style: DocstringStyle | None = None,
    use_docstring_info: bool = True,
    failure_error_function: ToolErrorFunction | None = None,
    strict_mode: bool = True,
    risk_tier: int = 1,
) -> Callable[[ToolFunction[...]], FunctionTool]:
    """Overload for usage as @function_tool(...)."""
    ...


def function_tool(
    func: ToolFunction[...] | None = None,
    *,
    name_override: str | None = None,
    description_override: str | None = None,
    docstring_style: DocstringStyle | None = None,
    use_docstring_info: bool = True,
    failure_error_function: ToolErrorFunction | None = default_tool_error_function,
    strict_mode: bool = True,
    risk_tier: int = 1,
) -> FunctionTool | Callable[[ToolFunction[...]], FunctionTool]:
    """
    Decorator to create a FunctionTool from a function. By default, we will:
    1. Parse the function signature to create a JSON schema for the tool's parameters.
    2. Use the function's docstring to populate the tool's description.
    3. Use the function's docstring to populate argument descriptions.
    The docstring style is detected automatically, but you can override it.

    If the function takes a `RunContextWrapper` as the first argument, it *must* match the
    context type of the agent that uses the tool.

    Args:
        func: The function to wrap.
        name_override: If provided, use this name for the tool instead of the function's name.
        description_override: If provided, use this description for the tool instead of the
            function's docstring.
        docstring_style: If provided, use this style for the tool's docstring. If not provided,
            we will attempt to auto-detect the style.
        use_docstring_info: If True, use the function's docstring to populate the tool's
            description and argument descriptions.
        failure_error_function: If provided, use this function to generate an error message when
            the tool call fails. The error message is sent to the LLM. If you pass None, then no
            error message will be sent and instead an Exception will be raised.
        strict_mode: Whether to enable strict mode for the tool's JSON schema. We *strongly*
            recommend setting this to True, as it increases the likelihood of correct JSON input.
            If False, it allows non-strict JSON schemas. For example, if a parameter has a default
            value, it will be optional, additional properties are allowed, etc. See here for more:
            https://platform.openai.com/docs/guides/structured-outputs?api-mode=responses#supported-schemas
        risk_tier: Security risk tier for policy gating. Tier 4 should be used for high-risk
            network/system mutation tools (for example shell or exploit orchestration wrappers).
    """

    def _create_function_tool(the_func: ToolFunction[...]) -> FunctionTool:
        schema = function_schema(
            func=the_func,
            name_override=name_override,
            description_override=description_override,
            docstring_style=docstring_style,
            use_docstring_info=use_docstring_info,
            strict_json_schema=strict_mode,
        )

        def _sanitize_parsed_json(json_data: Any) -> Any:
            """Attempt to repair common nesting issues in parsed tool JSON.

            Heuristics:
            - If top-level expected parameter names are missing, look for them
              inside nested dict values and promote them to top-level.
            - If promoted primitive values are numeric/bool but likely expected
              as strings (e.g., host/domain), coerce to `str` to satisfy Pydantic.
            This is intentionally conservative and only promotes when the
            top-level key is absent.
            """
            try:
                if not isinstance(json_data, dict):
                    return json_data

                # discover expected param names from the pydantic model
                expected_fields = set()
                try:
                    expected_fields = set(getattr(schema.params_pydantic_model, "__fields__", {}).keys())
                except Exception:
                    try:
                        expected_fields = set(getattr(schema.params_pydantic_model, "model_fields", {}).keys())
                    except Exception:
                        expected_fields = set()

                if not expected_fields:
                    return json_data

                # Promote nested keys when missing at top-level
                missing = expected_fields - set(json_data.keys())
                if missing:
                    # First, if some top-level entries are dicts containing expected keys,
                    # promote those nested keys to top-level.
                    for k, v in list(json_data.items()):
                        if isinstance(v, dict):
                            for nk in list(v.keys()):
                                if nk in missing and nk not in json_data:
                                    val = v.get(nk)
                                    # Coerce primitive numeric/bool to str for safety
                                    if isinstance(val, (int, float, bool)):
                                        val = str(val)
                                    json_data[nk] = val
                                    missing.discard(nk)

                    # If still missing, search deeper across other nested dicts
                    if missing:
                        for want in list(missing):
                            for k, v in list(json_data.items()):
                                if isinstance(v, dict) and want in v:
                                    val = v.get(want)
                                    if isinstance(val, (int, float, bool)):
                                        val = str(val)
                                    json_data[want] = val
                                    missing.discard(want)
                                    break

                # Determine expected field types (pydantic v1/v2 compat) so we
                # only coerce dict->str when the schema actually expects a string
                expected_types: dict[str, Any] = {}
                try:
                    # Pydantic v1
                    if hasattr(schema.params_pydantic_model, "__fields__") and getattr(schema.params_pydantic_model, "__fields__", None):
                        for fname, fobj in getattr(schema.params_pydantic_model, "__fields__", {}).items():
                            expected_types[fname] = getattr(fobj, "outer_type_", None) or getattr(fobj, "type_", None)
                    # Pydantic v2
                    elif hasattr(schema.params_pydantic_model, "model_fields") and getattr(schema.params_pydantic_model, "model_fields", None):
                        for fname, finfo in getattr(schema.params_pydantic_model, "model_fields", {}).items():
                            # finfo is a dict-like with an 'annotation' key
                            try:
                                expected_types[fname] = finfo.get("annotation") if isinstance(finfo, dict) else None
                            except Exception:
                                expected_types[fname] = None
                except Exception:
                    expected_types = {}

                def _expects_str(tp: Any) -> bool:
                    """Return True when the expected type is (or includes) `str`."""
                    try:
                        if tp is str:
                            return True
                        # Handle typing.Union and other generic aliases
                        from typing import get_origin, get_args

                        origin = get_origin(tp)
                        if origin is None:
                            # If it's a typing alias like 'str' wrapped, try equality
                            return False
                        if origin is Union:
                            return any(_expects_str(a) for a in get_args(tp))
                        return False
                    except Exception:
                        return False

                # Finally, if some values are dicts but the schema expects primitives (notably str),
                # try to coerce simple dict->str by JSON-encoding the dict. Only do this when the
                # expected type explicitly includes `str` to avoid converting model/dict types.
                for k in list(json_data.keys()):
                    if k in expected_fields and isinstance(json_data[k], dict):
                        exp = expected_types.get(k)
                        if _expects_str(exp):
                            try:
                                json_data[k] = json.dumps(json_data[k])
                            except Exception:
                                json_data[k] = str(json_data[k])

                return json_data
            except Exception:
                return json_data


        async def _on_invoke_tool_impl(ctx: RunContextWrapper[Any], input: str) -> Any:
            # Parse JSON input; attempt forgiving repairs for common LLM output formats
            json_data: dict[str, Any] = {}
            if input:
                try:
                    json_data = json.loads(input)
                except Exception as e:
                    try:
                        json_data = _forgiving_json_loads(input)
                        if not isinstance(json_data, dict):
                            # Repaired to a non-object type — not a valid tool argument payload
                            raise ModelBehaviorError(
                                f"Invalid JSON input for tool {schema.name}: "
                                f"parsed as {type(json_data).__name__}, expected object"
                            )
                        if _debug.DONT_LOG_TOOL_DATA:
                            logger.debug(f"Forgiving-parse succeeded for tool {schema.name}")
                        else:
                            logger.debug(f"Forgiving-parse succeeded for tool {schema.name}: {input}")
                    except Exception as e2:
                        if _debug.DONT_LOG_TOOL_DATA:
                            logger.debug(f"Invalid JSON input for tool {schema.name}")
                        else:
                            logger.debug(f"Invalid JSON input for tool {schema.name}: {input}")
                        raise ModelBehaviorError(
                            f"Invalid JSON input for tool {schema.name}: {input}"
                        ) from e2

            # Sanitize parsed JSON to handle common nesting/mis-formatting cases
            try:
                json_data = _sanitize_parsed_json(json_data)
            except Exception:
                # If sanitizer fails for any reason, continue with original json_data
                pass

            # Fail loudly when malformed non-empty payload collapses to an empty object
            # for tools that require arguments. This avoids silently dispatching {}.
            required_fields = _required_fields_from_schema(schema.params_json_schema)
            input_stripped = input.strip() if isinstance(input, str) else ""
            if (
                required_fields
                and isinstance(json_data, dict)
                and not json_data
                and input_stripped
                and input_stripped != "{}"
            ):
                schema_hint = _build_schema_retry_hint(
                    schema.name,
                    schema.params_json_schema,
                ).get("suggested_arguments_json", "{}")
                error_msg = (
                    f"Malformed JSON input for tool {schema.name}: parsed arguments collapsed to empty object. "
                    f"Required fields: {', '.join(required_fields)}. "
                    f"Retry with JSON like: {schema_hint}."
                )
                if _debug.DONT_LOG_TOOL_DATA:
                    logger.debug(
                        "Malformed JSON input collapsed to empty object for tool %s",
                        schema.name,
                    )
                else:
                    logger.debug("%s Raw input: %s", error_msg, input)
                raise ModelBehaviorError(error_msg)

            if _debug.DONT_LOG_TOOL_DATA:
                logger.debug(f"Invoking tool {schema.name}")
            else:
                logger.debug(f"Invoking tool {schema.name} with input {input}")

            try:
                parsed = (
                    schema.params_pydantic_model(**json_data)
                    if json_data
                    else schema.params_pydantic_model()
                )
            except ValidationError as e:
                raise ModelBehaviorError(f"Invalid JSON input for tool {schema.name}: {e}") from e

            args, kwargs_dict = schema.to_call_args(parsed)

            if not _debug.DONT_LOG_TOOL_DATA:
                logger.debug(f"Tool call args: {args}, kwargs: {kwargs_dict}")

            if inspect.iscoroutinefunction(the_func):
                if schema.takes_context:
                    result = await the_func(ctx, *args, **kwargs_dict)
                else:
                    result = await the_func(*args, **kwargs_dict)
            else:
                # Run synchronous functions in a thread pool to avoid blocking the event loop
                import asyncio
                import functools
                
                if schema.takes_context:
                    func_with_args = functools.partial(the_func, ctx, *args, **kwargs_dict)
                else:
                    func_with_args = functools.partial(the_func, *args, **kwargs_dict)
                
                # Run in thread pool executor to prevent blocking
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(None, func_with_args)

            if _debug.DONT_LOG_TOOL_DATA:
                logger.debug(f"Tool {schema.name} completed.")
            else:
                logger.debug(f"Tool {schema.name} returned {truncate_for_logging(result)}")

            return result

        async def _on_invoke_tool(ctx: RunContextWrapper[Any], input: str) -> Any:
            try:
                return await _on_invoke_tool_impl(ctx, input)
            except Exception as e:
                if "HARD_STOP" in str(e):
                    raise ModelBehaviorError(str(e)) from e
                if failure_error_function is None:
                    raise

                result = failure_error_function(ctx, e)
                if inspect.isawaitable(result):
                    return await result

                _error_tracing.attach_error_to_current_span(
                    SpanError(
                        message="Error running tool (non-fatal)",
                        data={
                            "tool_name": schema.name,
                            "error": str(e),
                        },
                    )
                )
                return result

        return FunctionTool(
            name=schema.name,
            description=schema.description or "",
            params_json_schema=schema.params_json_schema,
            params_pydantic_model=schema.params_pydantic_model,
            on_invoke_tool=_on_invoke_tool,
            strict_json_schema=strict_mode,
            risk_tier=max(1, min(int(risk_tier), 4)),
        )

    # If func is actually a callable, we were used as @function_tool with no parentheses
    if callable(func):
        return _create_function_tool(func)

    # Otherwise, we were used as @function_tool(...), so return a decorator
    def decorator(real_func: ToolFunction[...]) -> FunctionTool:
        return _create_function_tool(real_func)

    return decorator
