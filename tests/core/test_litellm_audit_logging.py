from __future__ import annotations

from types import SimpleNamespace

import pytest

from cerberus.agents.exceptions import UserError
from cerberus.agents.model_settings import ModelSettings
from cerberus.agents.models import openai_chatcompletions as occ


class _AuditRecorder:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def audit(self, message: str, **kwargs):
        self.calls.append({"message": message, "kwargs": kwargs})


@pytest.mark.asyncio
async def test_litellm_bad_request_logs_sanitized_audit(monkeypatch):
    recorder = _AuditRecorder()

    def _fake_logger():
        return recorder

    async def _raise_bad_request(**_kwargs):
        raise RuntimeError("request rejected\nTraceback (most recent call last): internal")

    monkeypatch.setattr(occ, "LiteLLMBadRequestError", RuntimeError)
    monkeypatch.setattr(occ.litellm, "acompletion", _raise_bad_request)

    import cerberus.repl.ui.logging as logging_module

    monkeypatch.setattr(logging_module, "get_cerberus_logger", _fake_logger)

    model = occ.OpenAIChatCompletionsModel(
        model="openai/gpt-4o-mini",
        openai_client=SimpleNamespace(),
    )

    kwargs = {
        "model": "openai/gpt-4o-mini",
        "messages": [{"role": "user", "content": "hello"}],
        "stream": False,
    }

    with pytest.raises(UserError):
        await model._fetch_response_litellm_openai(
            kwargs=kwargs,
            model_settings=ModelSettings(),
            tool_choice="auto",
            stream=False,
            parallel_tool_calls=False,
        )

    assert len(recorder.calls) == 1
    call = recorder.calls[0]
    assert call["message"] == "LiteLLM request error"
    payload = call["kwargs"]["data"]
    assert payload["kind"] == "bad_request"
    assert "Traceback" in payload["error"]
    assert "traceback" not in payload
