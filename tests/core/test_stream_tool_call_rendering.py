from __future__ import annotations

import types

import pytest
from openai import AsyncOpenAI
from openai.types.responses import Response

from cai.sdk.agents.model_settings import ModelSettings
from cai.sdk.agents.models.openai_chatcompletions import OpenAIChatCompletionsModel


# Keep a direct reference so autouse fixtures that monkeypatch the class method
# do not block this focused rendering regression test.
_ORIGINAL_STREAM_RESPONSE = OpenAIChatCompletionsModel.stream_response


class _DummyTracing:
    def is_disabled(self) -> bool:
        return True

    def include_data(self) -> bool:
        return False


@pytest.mark.asyncio
async def test_streamed_tool_call_renders_once_after_finalized(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, object]] = []

    def _capture_cli_print(messages, *, title=None, **_kwargs):
        calls.append({"messages": list(messages), "title": title})

    monkeypatch.setattr(
        "cai.sdk.agents.models.openai_chatcompletions.cli_print_agent_messages",
        _capture_cli_print,
    )

    model = OpenAIChatCompletionsModel(
        model="gpt-4o",
        openai_client=AsyncOpenAI(api_key="test-key", base_url="http://127.0.0.1:1/v1"),
        agent_name="StreamTester",
    )

    async def _stream_chunks():
        yield {
            "choices": [
                {
                    "delta": {
                        "function_call": {
                            "name": "run_command",
                            "arguments": '{"command":"ec',
                        }
                    }
                }
            ]
        }
        yield {
            "choices": [
                {
                    "delta": {
                        "function_call": {
                            "arguments": 'ho test"}',
                        }
                    }
                }
            ]
        }

    async def _fake_fetch_response(
        self,
        system_instructions,
        input,
        model_settings,
        tools,
        output_schema,
        handoffs,
        span_generation,
        tracing,
        stream=False,
    ):
        response = Response(
            id="resp_1",
            created_at=1,
            model="gpt-4o",
            object="response",
            output=[],
            tool_choice="none",
            tools=[],
            top_p=None,
            parallel_tool_calls=False,
        )
        return response, _stream_chunks()

    model._fetch_response = types.MethodType(_fake_fetch_response, model)

    stream_iter = _ORIGINAL_STREAM_RESPONSE(
        model,
        system_instructions=None,
        input="run a command",
        model_settings=ModelSettings(),
        tools=[],
        output_schema=None,
        handoffs=[],
        tracing=_DummyTracing(),
    )

    async for _event in stream_iter:
        pass

    assert len(calls) == 1
    assert calls[0]["title"] == "StreamTester"
    rendered = calls[0]["messages"][0]
    assert rendered["role"] == "assistant"
    assert "Agent executing: run_command" in rendered["content"]
    assert '{"command":"echo test"}' in rendered["content"]
