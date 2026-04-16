from __future__ import annotations

from cerberus.util.config import (
    get_effective_api_base,
    get_effective_api_key,
    get_effective_model,
    has_explicit_api_base_config,
    has_explicit_model_config,
)


def test_effective_api_base_honors_legacy_and_universal_envs(monkeypatch) -> None:
    for key in (
        "CERBERUS_API_BASE",
        "CEREBRO_API_BASE",
        "LOCAL_API_BASE",
        "OPENAI_API_BASE",
        "OPENAI_BASE_URL",
        "LITELLM_BASE_URL",
        "LITELLM_SERVER",
    ):
        monkeypatch.delenv(key, raising=False)

    monkeypatch.setenv("CEREBRO_API_BASE", "http://legacy.example/v1")
    monkeypatch.setenv("LOCAL_API_BASE", "http://local.example/v1")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://openai.example/v1")

    assert has_explicit_api_base_config() is True
    assert get_effective_api_base() == "http://legacy.example/v1"

    monkeypatch.setenv("CERBERUS_API_BASE", "http://preferred.example/v1")

    assert get_effective_api_base() == "http://preferred.example/v1"


def test_effective_api_key_honors_legacy_cerebro_key(monkeypatch) -> None:
    for key in (
        "CERBERUS_API_KEY",
        "CEREBRO_API_KEY",
        "ALIAS_API_KEY",
        "OPENAI_API_KEY",
        "LITELLM_API_KEY",
    ):
        monkeypatch.delenv(key, raising=False)

    monkeypatch.setenv("CEREBRO_API_KEY", "sk-legacy")

    assert get_effective_api_key() == "sk-legacy"


def test_effective_model_honors_legacy_cerebro_model(monkeypatch) -> None:
    for key in (
        "CERBERUS_MODEL",
        "CEREBRO_MODEL",
        "CERBERUS_LOCAL_MODEL",
    ):
        monkeypatch.delenv(key, raising=False)

    monkeypatch.setenv("CEREBRO_MODEL", "Qwen3.5-27B-Aggressive-Q4_K_M")

    assert has_explicit_model_config() is True
    assert get_effective_model() == "Qwen3.5-27B-Aggressive-Q4_K_M"

    monkeypatch.setenv("CERBERUS_MODEL", "override-model")

    assert get_effective_model() == "override-model"