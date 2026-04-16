import os

import openai
import pytest

from cerberus.sdk.agents import set_default_openai_api, set_default_openai_client, set_default_openai_key
from cerberus.sdk.agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from cerberus.sdk.agents.models.openai_provider import OpenAIProvider
from cerberus.sdk.agents.models.openai_responses import OpenAIResponsesModel


import os
cai_model = os.getenv('CERBERUS_MODEL', "qwen2.5:14b")

def test_cc_no_default_key_errors(monkeypatch):
    # Cerberus now provides a fallback API key via get_effective_api_key(), so
    # removing OPENAI_API_KEY no longer raises at model-construction time.
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    model = OpenAIProvider(use_responses=False).get_model(cai_model)
    assert isinstance(model, OpenAIChatCompletionsModel)


def test_cc_set_default_openai_key():
    set_default_openai_key("test_key")
    chat_model = OpenAIProvider(use_responses=False).get_model(cai_model)
    assert chat_model._client.api_key == "test_key"  # type: ignore


def test_cc_set_default_openai_client():
    client = openai.AsyncOpenAI(api_key="test_key")
    set_default_openai_client(client)
    chat_model = OpenAIProvider(use_responses=False).get_model(cai_model)
    assert chat_model._client.api_key == "test_key"  # type: ignore


def test_resp_no_default_key_errors(monkeypatch):
    # Cerberus now provides a fallback API key via get_effective_api_key(), so
    # removing OPENAI_API_KEY no longer raises at model-construction time.
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert os.getenv("OPENAI_API_KEY") is None
    model = OpenAIProvider(use_responses=True).get_model(cai_model)
    assert isinstance(model, OpenAIResponsesModel)


def test_resp_set_default_openai_key():
    set_default_openai_key("test_key")
    resp_model = OpenAIProvider(use_responses=True).get_model(cai_model)
    assert resp_model._client.api_key == "test_key"  # type: ignore


def test_resp_set_default_openai_client():
    client = openai.AsyncOpenAI(api_key="test_key")
    set_default_openai_client(client)
    resp_model = OpenAIProvider(use_responses=True).get_model(cai_model)
    assert resp_model._client.api_key == "test_key"  # type: ignore


def test_set_default_openai_api():
    set_default_openai_key("test_key")

    assert isinstance(OpenAIProvider().get_model(cai_model), OpenAIResponsesModel), (
        "Default should be responses"
    )

    set_default_openai_api("chat_completions")
    assert isinstance(OpenAIProvider().get_model(cai_model), OpenAIChatCompletionsModel), (
        "Should be chat completions model"
    )

    set_default_openai_api("responses")
    assert isinstance(OpenAIProvider().get_model(cai_model), OpenAIResponsesModel), (
        "Should be responses model"
    )
