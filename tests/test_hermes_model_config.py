from __future__ import annotations

import os

import pytest

from prometheus.config import hermes_bridge
from prometheus.config.hermes_bridge import (
    HermesModelResolutionError,
    apply_hermes_model_defaults,
    resolve_active_hermes_model,
)
from prometheus.config.models import configure_sdk_model_defaults, uses_chat_completions_tool_schema
from prometheus.config.settings import Settings


def test_resolves_active_hermes_provider_and_model_from_loader(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        hermes_bridge,
        "_load_hermes_config",
        lambda: {
            "profile": "test",
            "model": {
                "provider": "openai-codex",
                "default": "gpt-5.4",
                "base_url": "https://chatgpt.com/backend-api/codex",
            },
        },
    )

    resolved = resolve_active_hermes_model()

    assert resolved.provider == "openai-codex"
    assert resolved.model == "gpt-5.4"
    assert resolved.base_url == "https://chatgpt.com/backend-api/codex"
    assert resolved.source_profile == "test"


def test_applies_hermes_base_url_to_sdk_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(
        hermes_bridge,
        "_load_hermes_config",
        lambda: {
            "model": {
                "provider": "openai-codex",
                "default": "gpt-5.4",
                "base_url": "https://chatgpt.com/backend-api/codex",
            },
        },
    )
    settings = Settings()

    resolved = configure_sdk_model_defaults(settings)

    assert resolved.provider == "openai-codex"
    assert settings.llm.model == "gpt-5.4"
    assert settings.llm.api_base == "https://chatgpt.com/backend-api/codex"
    assert settings.llm.api_key == "no-key-required"
    assert settings.llm.use_hermes_model is True
    assert os.environ["OPENAI_BASE_URL"] == "https://chatgpt.com/backend-api/codex"
    assert os.environ["OPENAI_API_KEY"] == "no-key-required"


def test_fails_loud_on_invalid_hermes_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hermes_bridge, "_load_hermes_config", lambda: {"model": {"provider": "openai-codex"}})

    with pytest.raises(HermesModelResolutionError, match="model.default"):
        resolve_active_hermes_model()


def test_does_not_fall_back_to_local_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        hermes_bridge,
        "_load_hermes_config",
        lambda: {"model": {"provider": "openai-codex", "default": "gpt-5.4", "base_url": "https://chatgpt.com/backend-api/codex"}},
    )
    settings = Settings()

    apply_hermes_model_defaults(settings)

    assert settings.llm.model != "default"
    assert settings.llm.api_base != "http://127.0.0.1:1337/v1"
    assert settings.llm.api_key == "no-key-required"


def test_custom_base_url_uses_chat_completions_tool_schema() -> None:
    settings = Settings()
    settings.llm.api_base = "https://chatgpt.com/backend-api/codex"

    assert uses_chat_completions_tool_schema("gpt-5.4", settings) is True
