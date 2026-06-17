"""Tests for prometheus.config.providers (per-provider helper modules).

Covers:
  * TokenRouter helper: default base URL + env-key fallback
  * OpenRouter helper: openrouter/auto is flagged with the DeepSeek
    tool_choice quirk (drop_tool_choice_with_thinking + force_store_false)
  * Custom helper: openai vs anthropic protocol selection
  * Custom helper: explicit ``type: custom`` in YAML forces the inline
    parser even for names that have a registered helper
  * Loader wiring: helper-produced overrides land in MODEL_OPTIONS
"""

from __future__ import annotations

import sys
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[1]
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from prometheus.config import llm_config  # noqa: E402
from prometheus.config.llm_config import Protocol  # noqa: E402
from prometheus.config.model_options import MODEL_OPTIONS  # noqa: E402
from prometheus.config.providers import (  # noqa: E402
    PROVIDER_HELPERS,
    get_helper,
    is_known_provider,
)
from prometheus.config.providers.openrouter import OPENROUTER_BASE_URL  # noqa: E402
from prometheus.config.providers.tokenrouter import TOKENROUTER_BASE_URL  # noqa: E402


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_registry_contains_core_providers():
    expected = {"tokenrouter", "openrouter", "deepseek", "anthropic", "openai", "custom"}
    assert expected.issubset(PROVIDER_HELPERS.keys())


def test_get_helper_is_case_insensitive():
    assert get_helper("TokenRouter") is not None
    assert get_helper("OPENROUTER") is not None
    assert get_helper("custom") is not None
    assert get_helper("totally-unknown-vendor") is None


def test_is_known_provider_matches_registry():
    assert is_known_provider("tokenrouter") is True
    assert is_known_provider("TokenRouter") is True
    assert is_known_provider("nonexistent") is False
    assert is_known_provider("") is False


# ---------------------------------------------------------------------------
# TokenRouter
# ---------------------------------------------------------------------------


def test_tokenrouter_helper_uses_default_base_url(monkeypatch):
    monkeypatch.delenv("TOKENROUTER_API_KEY", raising=False)
    helper = get_helper("tokenrouter")
    assert helper is not None
    pdata = {"__name": "tokenrouter", "models": {"MiniMax-M3": {"tier": "hard"}}}
    result = helper(pdata)
    assert result.provider.base_url == TOKENROUTER_BASE_URL
    assert result.provider.protocol == Protocol.OPENAI
    assert result.provider.models["MiniMax-M3"].tier.value == "hard"
    assert result.provider.api_keys == []


def test_tokenrouter_helper_picks_up_env_key(monkeypatch):
    monkeypatch.setenv("TOKENROUTER_API_KEY", "sk-test-tokenrouter")
    helper = get_helper("tokenrouter")
    result = helper({"__name": "tokenrouter", "models": {}})
    assert result.provider.api_keys == ["sk-test-tokenrouter"]


def test_tokenrouter_helper_allows_base_url_override():
    helper = get_helper("tokenrouter")
    result = helper(
        {
            "__name": "tokenrouter",
            "base_url": "https://private-gateway.example/v1",
            "models": {},
        }
    )
    assert result.provider.base_url == "https://private-gateway.example/v1"


# ---------------------------------------------------------------------------
# OpenRouter
# ---------------------------------------------------------------------------


def test_openrouter_helper_injects_attribution_headers():
    helper = get_helper("openrouter")
    pdata = {
        "__name": "openrouter",
        "models": {"openrouter/auto": {"tier": "hard"}},
    }
    result = helper(pdata)
    assert result.provider.base_url == OPENROUTER_BASE_URL
    assert "HTTP-Referer" in result.provider.extra_headers
    assert "X-OpenRouter-Categories" in result.provider.extra_headers


def test_openrouter_user_headers_override_defaults():
    helper = get_helper("openrouter")
    pdata = {
        "__name": "openrouter",
        "models": {},
        "extra_headers": {"X-OpenRouter-Title": "MyFork"},
    }
    result = helper(pdata)
    assert result.provider.extra_headers["X-OpenRouter-Title"] == "MyFork"
    # Untouched default survives.
    assert result.provider.extra_headers["HTTP-Referer"]


def test_openrouter_auto_flagged_for_deepseek_tool_choice_quirk():
    """openrouter/auto: drop tool_choice + force store=False.

    The upstream is unknown at config time and may be DeepSeek, which
    rejects tool_choice with thinking on and doesn't support multi-turn
    Responses store persistence.
    """
    helper = get_helper("openrouter")
    pdata = {
        "__name": "openrouter",
        "models": {
            "openrouter/auto": {"tier": "hard"},
            "anthropic/claude-sonnet-4-6": {"tier": "hard"},
        },
    }
    result = helper(pdata)
    overrides = result.model_option_overrides
    assert overrides["openrouter/auto"]["drop_tool_choice_with_thinking"] is True
    assert overrides["openrouter/auto"]["force_store_false"] is True
    # All openrouter models get the tool_choice flag (cheap, conservative)
    assert overrides["anthropic/claude-sonnet-4-6"]["drop_tool_choice_with_thinking"] is True


# ---------------------------------------------------------------------------
# Custom endpoint
# ---------------------------------------------------------------------------


def test_custom_helper_default_protocol_is_openai():
    helper = get_helper("custom")
    pdata = {
        "__name": "internal-gateway",
        "base_url": "https://llm.internal/v1",
        "models": {},
    }
    result = helper(pdata)
    assert result.provider.protocol == Protocol.OPENAI
    assert result.provider.base_url == "https://llm.internal/v1"


def test_custom_helper_honors_anthropic_protocol():
    helper = get_helper("custom")
    pdata = {
        "__name": "anthropic-gateway",
        "base_url": "https://anthropic.internal/v1",
        "protocol": "anthropic",
        "models": {"claude-sonnet-4-6": {"tier": "hard"}},
    }
    result = helper(pdata)
    assert result.provider.protocol == Protocol.ANTHROPIC
    assert "claude-sonnet-4-6" in result.provider.models


def test_custom_helper_rejects_missing_base_url():
    helper = get_helper("custom")
    pdata = {"__name": "broken", "models": {}}
    try:
        helper(pdata)
    except ValueError as exc:
        assert "base_url" in str(exc)
    else:
        raise AssertionError("expected ValueError for missing base_url")


# ---------------------------------------------------------------------------
# Loader wiring
# ---------------------------------------------------------------------------


def _parse_yaml(tmp_path, body: str):
    p = tmp_path / "llm.yaml"
    p.write_text(body)
    return llm_config._parse_config(_yaml_load(body), p)


def _yaml_load(body: str) -> dict:
    import yaml

    return yaml.safe_load(body) or {}


def test_helper_overrides_merged_into_model_options(tmp_path):
    """openrouter/auto's drop_tool_choice override must reach MODEL_OPTIONS."""
    yaml_body = """
providers:
  openrouter:
    base_url: https://openrouter.ai/api/v1
    protocol: openai
    api_keys:
      - env: OPENROUTER_API_KEY
    models:
      openrouter/auto:
        tier: hard
routing:
  hard:
    models:
      - openrouter/openrouter/auto
defaults:
  tier: hard
"""
    cfg = _parse_yaml(tmp_path, yaml_body)
    assert "openrouter" in cfg.providers
    assert "openrouter/auto" in MODEL_OPTIONS
    assert MODEL_OPTIONS["openrouter/auto"].drop_tool_choice_with_thinking is True
    assert MODEL_OPTIONS["openrouter/auto"].force_store_false is True


def test_type_custom_in_yaml_forces_inline_parser(tmp_path):
    """A user can opt out of a named helper by setting ``type: custom``."""
    # Snapshot the current MODEL_OPTIONS so the assertion below only
    # checks for changes introduced by THIS load.
    before = dict(MODEL_OPTIONS)
    yaml_body = """
providers:
  openrouter:
    type: custom          # bypass the openrouter helper
    base_url: https://my-fork.example/v1
    protocol: openai
    models:
      openrouter/auto:
        tier: hard
"""
    cfg = _parse_yaml(tmp_path, yaml_body)
    # The provider was built by the inline parser, so its base_url
    # reflects the user's override verbatim.
    assert cfg.providers["openrouter"].base_url == "https://my-fork.example/v1"
    # And the openrouter helper's model_option_overrides were NOT
    # applied (this is the point of opting out).
    new_keys = set(MODEL_OPTIONS) - set(before)
    assert "openrouter/auto" not in new_keys


def test_unknown_provider_falls_through_to_inline_parser(tmp_path):
    """A name with no registered helper still loads via the inline path."""
    yaml_body = """
providers:
  my-internal-proxy:
    base_url: https://llm.example/v1
    protocol: openai
    api_keys:
      - env: MY_PROXY_KEY
    models:
      llama-3.1-70b:
        tier: hard
"""
    cfg = _parse_yaml(tmp_path, yaml_body)
    assert "my-internal-proxy" in cfg.providers
    p = cfg.providers["my-internal-proxy"]
    assert p.base_url == "https://llm.example/v1"
    assert p.protocol == Protocol.OPENAI
    assert "llama-3.1-70b" in p.models
