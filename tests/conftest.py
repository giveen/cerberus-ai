from __future__ import annotations

import os
import pytest

from cai.sdk.agents.models import _openai_shared
from cai.sdk.agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from cai.sdk.agents.models.openai_responses import OpenAIResponsesModel
from cai.sdk.agents.tracing import set_trace_processors
from cai.sdk.agents.tracing.setup import GLOBAL_TRACE_PROVIDER

from tests.testing_processor import SPAN_PROCESSOR_TESTING


# This fixture will run once before any tests are executed
@pytest.fixture(scope="session", autouse=True)
def setup_span_processor():
    set_trace_processors([SPAN_PROCESSOR_TESTING])


# This fixture will run before each test
@pytest.fixture(autouse=True)
def clear_span_processor():
    SPAN_PROCESSOR_TESTING.force_flush()
    SPAN_PROCESSOR_TESTING.shutdown()
    SPAN_PROCESSOR_TESTING.clear()


# This fixture will run before each test
@pytest.fixture(autouse=True)
def clear_openai_settings():
    _openai_shared._default_openai_key = None
    _openai_shared._default_openai_client = None
    _openai_shared._use_responses_by_default = True


# This fixture will run after all tests end
@pytest.fixture(autouse=True, scope="session")
def shutdown_trace_provider():
    yield
    GLOBAL_TRACE_PROVIDER.shutdown()


@pytest.fixture(autouse=True)
def ensure_guardrails_enabled(monkeypatch):
    """Override CEREBRO_GUARDRAILS to 'true' for every test.

    The ambient shell environment may have CEREBRO_GUARDRAILS=false for development
    purposes.  Tests that specifically need it disabled call
    monkeypatch.setenv("CEREBRO_GUARDRAILS", "false") themselves, which overrides
    this fixture's setting for that single test.
    """
    monkeypatch.setenv("CEREBRO_GUARDRAILS", "true")


@pytest.fixture(autouse=True)
def disable_real_model_clients(monkeypatch, request):
    # If the test is marked to allow the method call, don't override it.
    if request.node.get_closest_marker("allow_call_model_methods"):
        return

    def failing_version(*args, **kwargs):
        pytest.fail("Real models should not be used in tests!")

    monkeypatch.setattr(OpenAIResponsesModel, "get_response", failing_version)
    monkeypatch.setattr(OpenAIResponsesModel, "stream_response", failing_version)
    monkeypatch.setattr(OpenAIChatCompletionsModel, "get_response", failing_version)
    monkeypatch.setattr(OpenAIChatCompletionsModel, "stream_response", failing_version)


# Skip heavy integration-style agent tests by default to avoid running
# tests that execute system tools or require elevated privileges. To
# run these tests locally set `RUN_AGENT_INTEGRATION_TESTS=1`.
@pytest.fixture(autouse=True)
def skip_integration_agent_tests(request):
    if request.node.get_closest_marker("allow_call_model_methods"):
        enabled = os.getenv("RUN_AGENT_INTEGRATION_TESTS", "false").lower()
        if enabled not in ("1", "true", "yes"):
            pytest.skip("Skipping integration tests that call real model/methods by default. Set RUN_AGENT_INTEGRATION_TESTS=1 to run them.")


@pytest.fixture(autouse=True)
def ensure_guardrails_enabled(monkeypatch):
    """Override CEREBRO_GUARDRAILS to 'true' for every test.

    The ambient shell environment may have CEREBRO_GUARDRAILS=false for development
    purposes.  Tests that specifically need it disabled call
    monkeypatch.setenv("CEREBRO_GUARDRAILS", "false") themselves, which overrides
    this fixture's setting for that single test.
    """
    monkeypatch.setenv("CEREBRO_GUARDRAILS", "true")
