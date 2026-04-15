from __future__ import annotations

import httpx
import os
from openai import AsyncOpenAI, DefaultAsyncHttpxClient

from cerberus.internal.debug_logger import get_debug_logger
from cerberus.util.config import get_effective_api_base, get_effective_api_key

from . import _openai_shared
from .interface import Model, ModelProvider
from .openai_chatcompletions import OpenAIChatCompletionsModel
from .openai_responses import OpenAIResponsesModel

DEFAULT_MODEL: str = "gpt-4o"


_http_client: httpx.AsyncClient | None = None


# If we create a new httpx client for each request, that would mean no sharing of connection pools,
# which would mean worse latency and resource usage. So, we share the client across requests.
def shared_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None:
        _http_client = DefaultAsyncHttpxClient()
    return _http_client


class OpenAIProvider(ModelProvider):
    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        openai_client: AsyncOpenAI | None = None,
        organization: str | None = None,
        project: str | None = None,
        use_responses: bool | None = None,
    ) -> None:
        """Create a new OpenAI provider.

        Args:
            api_key: The API key to use for the OpenAI client. If not provided, we will use the
                default API key.
            base_url: The base URL to use for the OpenAI client. If not provided, we will use the
                default base URL.
            openai_client: An optional OpenAI client to use. If not provided, we will create a new
                OpenAI client using the api_key and base_url.
            organization: The organization to use for the OpenAI client.
            project: The project to use for the OpenAI client.
            use_responses: Whether to use the OpenAI responses API.
        """
        self._stored_api_key = api_key
        self._stored_base_url = base_url
        self._stored_organization = organization
        self._stored_project = project

        if openai_client is not None:
            assert api_key is None and base_url is None, (
                "Don't provide api_key or base_url if you provide openai_client"
            )
            self._client: AsyncOpenAI | None = openai_client
        else:
            self._client = None

        if use_responses is not None:
            self._use_responses = use_responses
        else:
            self._use_responses = _openai_shared.get_use_responses_by_default()
        self._debug_logger = get_debug_logger()

    # We lazy load the client in case you never actually use OpenAIProvider(). Otherwise
    # AsyncOpenAI() raises an error if you don't have an API key set.
    def _get_client(self) -> AsyncOpenAI:
        if self._client is None:
            default_client = _openai_shared.get_default_openai_client()
            if default_client is not None:
                self._client = default_client
                return self._client

            api_key = (
                self._stored_api_key
                or _openai_shared.get_default_openai_key()
                or os.getenv("OPENAI_API_KEY")
            )
            base_url = self._stored_base_url
            self._client = AsyncOpenAI(
                api_key=api_key,
                base_url=base_url,
                organization=self._stored_organization,
                project=self._stored_project,
                http_client=shared_http_client(),
                default_headers={"User-Agent": "Cerberus AI Auditor"},
            )

        return self._client

    def get_model(self, model_name: str | None) -> Model:
        if model_name is None:
            model_name = DEFAULT_MODEL

        model_lower = model_name.lower()
        if "cerebro" in model_lower:
            self._stored_api_key = self._stored_api_key or get_effective_api_key(
                default="sk-cerebro-local"
            )
            self._stored_base_url = self._stored_base_url or get_effective_api_base()

        target_base_url = self._stored_base_url or get_effective_api_base()
        self._debug_logger.write(
            channel="llm_provider",
            message="provider_model_selected",
            payload={"model": model_name, "base_url": target_base_url},
        )

        client = self._get_client()

        return (
            OpenAIResponsesModel(model=model_name, openai_client=client)
            if self._use_responses
            else OpenAIChatCompletionsModel(model=model_name, openai_client=client)
        )
