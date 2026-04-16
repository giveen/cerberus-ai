import pytest
from pydantic import BaseModel

from cerberus.agents import Agent, Handoff, function_tool, handoff
from cerberus.agents.exceptions import UserError
from cerberus.agents.models.openai_chatcompletions import ToolConverter
from cerberus.agents.tool import FileSearchTool, WebSearchTool


def some_function(a: str, b: list[int]) -> str:
    return "hello"


def test_to_openai_with_function_tool():
    some_function(a="foo", b=[1, 2, 3])

    tool = function_tool(some_function)
    result = ToolConverter.to_openai(tool)

    assert result["type"] == "function"
    assert result["function"]["name"] == "some_function"
    params = result.get("function", {}).get("parameters")
    assert params is not None
    properties = params.get("properties", {})
    assert isinstance(properties, dict)
    assert properties.keys() == {"a", "b"}


class Foo(BaseModel):
    a: str
    b: list[int]


def test_convert_handoff_tool():
    agent = Agent(name="test_1", handoff_description="test_2")
    handoff_obj = handoff(agent=agent)
    result = ToolConverter.convert_handoff_tool(handoff_obj)

    assert result["type"] == "function"
    assert result["function"]["name"] == Handoff.default_tool_name(agent)
    assert result["function"].get("description") == Handoff.default_tool_description(agent)
    params = result.get("function", {}).get("parameters")
    assert params is not None

    for key, value in handoff_obj.input_json_schema.items():
        assert params[key] == value


def test_tool_converter_hosted_tools_errors():
    with pytest.raises(UserError):
        ToolConverter.to_openai(WebSearchTool())

    with pytest.raises(UserError):
        ToolConverter.to_openai(FileSearchTool(vector_store_ids=["abc"], max_num_results=1))


def test_to_openai_with_raw_callable_tool():
    def scan(host: str, port: int = 443, secure: bool = True):
        """Scan a remote service endpoint."""
        return None

    result = ToolConverter.to_openai(scan)

    assert result["type"] == "function"
    assert result["function"]["name"] == "scan"
    assert result["function"]["description"] == "Scan a remote service endpoint."
    params = result["function"]["parameters"]
    assert params["type"] == "object"
    assert params["additionalProperties"] is False
    assert params["required"] == ["host"]
    assert params["properties"]["host"]["type"] == "string"
    assert params["properties"]["port"]["type"] == "integer"
    assert params["properties"]["port"]["default"] == 443
    assert params["properties"]["secure"]["type"] == "boolean"
    assert params["properties"]["secure"]["default"] is True


def test_to_openai_accepts_already_formatted_dict_tool():
    tool = {
        "type": "function",
        "function": {
            "name": "lookup",
            "description": "Lookup records.",
            "parameters": {
                "type": "object",
                "properties": {"q": {"type": "string"}},
                "required": ["q"],
                "additionalProperties": False,
            },
        },
    }

    result = ToolConverter.to_openai(tool)

    assert result == tool


def test_to_openai_accepts_shorthand_dict_tool():
    tool = {
        "name": "lookup",
        "description": "Lookup records.",
        "parameters": {
            "type": "object",
            "properties": {"q": {"type": "string"}},
            "required": ["q"],
            "additionalProperties": False,
        },
    }

    result = ToolConverter.to_openai(tool)

    assert result["type"] == "function"
    assert result["function"]["name"] == "lookup"
    assert result["function"]["description"] == "Lookup records."
    assert result["function"]["parameters"] == tool["parameters"]
