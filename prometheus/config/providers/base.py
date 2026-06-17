"""Provider-helper base + the shared OpenAI-compatible default.

A :class:`ProviderHelper` owns everything provider-specific:

  * the canonical ``base_url`` (used when the user does not override it),
  * the default protocol,
  * the env-var name the SDK reads for the API key,
  * per-model quirks that need to be applied at parse time (e.g. flag
    the OpenRouter ``openrouter/auto`` model so the harness drops
    ``tool_choice`` while thinking is on — because the upstream may be
    DeepSeek, which rejects that combination).

A helper is a pure function from a raw config dict to a
:class:`ProviderParseResult`. The loader in
:mod:`prometheus.config.llm_config` consumes the result and stitches
it into the rest of the config (routing, defaults, env-var fallback).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from prometheus.config.llm_config import (
    ModelSpec,
    Protocol as LlmProtocol,
    ProviderConfig,
    Tier,
    _PROVIDER_ENV_KEY_MAP,
    _resolve_api_key,
)

logger = logging.getLogger(__name__)


# A "model option" is one of the fields the harness reads from
# :class:`prometheus.config.model_options.ModelOptionOverrides`. A helper
# can attach these to a ModelSpec at parse time.
ModelOptionOverride = dict[str, Any]


@dataclass
class ProviderParseResult:
    """What a helper hands back to the loader.

    The loader is responsible for wiring this into the global
    :class:`LlmConfig`. The helper only produces the bits it owns.
    """

    provider: ProviderConfig
    # Extra per-model option overrides keyed by model id, merged into
    # MODEL_OPTIONS at load time. Lets a helper flag models whose
    # behaviour is only known via the helper layer (e.g. openrouter/auto
    # being routed to DeepSeek at call time).
    model_option_overrides: dict[str, ModelOptionOverride] = field(default_factory=dict)


class ProviderHelper(Protocol):
    """Build a :class:`ProviderConfig` from the raw YAML ``pdata`` dict.

    The callable signature is intentionally simple so a new helper is
    a 10-line function — see ``tokenrouter.py`` for the smallest
    possible example.
    """

    name: str

    def __call__(self, pdata: dict[str, Any]) -> ProviderParseResult: ...


# ---------------------------------------------------------------------------
# Shared parsing helpers
# ---------------------------------------------------------------------------


def parse_protocol(pdata: dict[str, Any], default: LlmProtocol) -> LlmProtocol:
    """Read the ``protocol`` field, falling back to ``default`` on miss/unknown."""
    raw = str(pdata.get("protocol", "")).strip().lower() or default.value
    try:
        return LlmProtocol(raw)
    except ValueError:
        logger.warning(
            "Provider %s: unknown protocol %r, defaulting to %s",
            pdata.get("__name", "?"),
            raw,
            default.value,
        )
        return default


def resolve_api_keys(provider_name: str, pdata: dict[str, Any]) -> list[str]:
    """Resolve ``api_keys`` from the YAML, falling back to env-var conventions."""
    keys: list[str] = []
    raw_keys = pdata.get("api_keys", [])
    if isinstance(raw_keys, list):
        for entry in raw_keys:
            k = _resolve_api_key(entry)
            if k:
                keys.append(k)
    elif isinstance(raw_keys, str):
        k = _resolve_api_key(raw_keys)
        if k:
            keys.append(k)

    if not keys:
        env_name = _PROVIDER_ENV_KEY_MAP.get(provider_name.lower())
        if env_name:
            env_val = os.environ.get(env_name)
            if env_val:
                keys.append(env_val)
    return keys


def parse_models(pdata: dict[str, Any]) -> dict[str, ModelSpec]:
    """Translate the ``models:`` block into :class:`ModelSpec` objects."""
    models: dict[str, ModelSpec] = {}
    raw = pdata.get("models", {})
    if not isinstance(raw, dict):
        return models
    provider_name = str(pdata.get("__name", ""))
    for model_id, mdata in raw.items():
        if isinstance(mdata, dict):
            tier_str = str(mdata.get("tier", "medium")).lower()
            try:
                tier = Tier(tier_str)
            except ValueError:
                tier = Tier.MEDIUM
            models[str(model_id)] = ModelSpec(
                provider_name=provider_name,
                model_id=str(model_id),
                tier=tier,
                max_tokens=int(mdata.get("max_tokens", 8192)),
                supports_thinking=bool(mdata.get("supports_thinking", False)),
                context_window=(
                    int(mdata["context_window"])
                    if mdata.get("context_window") is not None
                    else None
                ),
            )
        elif isinstance(mdata, str):
            try:
                tier = Tier(str(mdata).lower())
            except ValueError:
                tier = Tier.MEDIUM
            models[str(model_id)] = ModelSpec(
                provider_name=provider_name,
                model_id=str(model_id),
                tier=tier,
            )
    return models


def parse_extra_headers(pdata: dict[str, Any]) -> dict[str, str]:
    raw = pdata.get("extra_headers", {})
    if not isinstance(raw, dict):
        return {}
    return {str(k): str(v) for k, v in raw.items()}


# ---------------------------------------------------------------------------
# OpenAI-compatible default helper (used for "openai" provider)
# ---------------------------------------------------------------------------


def default_openai_helper() -> ProviderHelper:
    """The generic OpenAI-compatible helper — base_url is fully user-supplied."""

    class _OpenAIHelper:
        name = "openai"

        def __call__(self, pdata: dict[str, Any]) -> ProviderParseResult:
            base_url = str(pdata.get("base_url", "")).strip()
            if not base_url:
                raise ValueError(
                    "openai provider requires an explicit base_url "
                    "(e.g. https://api.openai.com/v1). "
                    "Use the 'custom' provider for unknown vendors."
                )
            provider_name = str(pdata.get("__name", "openai"))
            provider = ProviderConfig(
                name=provider_name,
                base_url=base_url,
                protocol=parse_protocol(pdata, LlmProtocol.OPENAI),
                api_keys=resolve_api_keys(provider_name, pdata),
                models=parse_models(pdata),
                extra_headers=parse_extra_headers(pdata),
            )
            return ProviderParseResult(provider=provider)

    return _OpenAIHelper()


__all__ = [
    "ProviderHelper",
    "ProviderParseResult",
    "ModelOptionOverride",
    "default_openai_helper",
    "parse_protocol",
    "resolve_api_keys",
    "parse_models",
    "parse_extra_headers",
]
