"""OpenRouter helper — handles the openrouter/auto router's DeepSeek quirk.

The interesting case: when the user configures
``openrouter/auto`` (or any ``openrouter/...`` model that may resolve to
a DeepSeek upstream), the upstream is unknown at config time. DeepSeek
rejects ``tool_choice=required`` while thinking/reasoning is active, and
OpenRouter can route to it. So this helper flags every OpenRouter model
with a ``drop_tool_choice_with_thinking`` override and adds the
``openrouter`` provider to the ``should_set_tool_choice`` set in
:mod:`prometheus.config.llm_config` (already true today — kept for
parity when this helper is the authoritative source).

The HTTP attribution headers (HTTP-Referer, X-Title) are injected as
``extra_headers`` by default; OpenRouter's app-attribution ranking
penalises requests without them.
"""

from __future__ import annotations

from typing import Any

from prometheus.config.llm_config import Protocol as LlmProtocol
from prometheus.config.providers.base import (
    ProviderHelper,
    ProviderParseResult,
    parse_models,
    parse_protocol,
    resolve_api_keys,
)
from prometheus.config.llm_config import ProviderConfig


OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
OPENROUTER_DEFAULT_HEADERS: dict[str, str] = {
    "HTTP-Referer": "https://github.com/StefanIsMe/Prometheus",
    "X-OpenRouter-Title": "Prometheus",
    "X-Title": "Prometheus",
    "X-OpenRouter-Categories": "security-tool",
}


def build_helper() -> ProviderHelper:
    class _OpenRouterHelper:
        name = "openrouter"

        def __call__(self, pdata: dict[str, Any]) -> ProviderParseResult:
            provider_name = str(pdata.get("__name", "openrouter"))
            base_url = str(pdata.get("base_url", "")).strip() or OPENROUTER_BASE_URL

            # Merge user-supplied headers on top of the default attribution
            # block so the user can still override the Referer/Title.
            headers = dict(OPENROUTER_DEFAULT_HEADERS)
            user_headers = pdata.get("extra_headers", {})
            if isinstance(user_headers, dict):
                headers.update({str(k): str(v) for k, v in user_headers.items()})

            models = parse_models(pdata)

            # Flag every model on the openrouter provider with
            # drop_tool_choice_with_thinking. The upstream is unknown at
            # config time and may be DeepSeek, which rejects tool_choice
            # with thinking on. This is conservative — non-DeepSeek
            # upstreams don't care if the field is omitted.
            overrides: dict[str, dict[str, Any]] = {}
            for model_id in models:
                overrides[model_id] = {"drop_tool_choice_with_thinking": True}

            # openrouter/auto in particular should also force
            # store=False (multi-turn Responses store persistence is
            # not supported on the auto router — same root cause as
            # the claude-4.5 entries in MODEL_OPTIONS).
            if "openrouter/auto" in models:
                overrides["openrouter/auto"]["force_store_false"] = True

            return ProviderParseResult(
                provider=ProviderConfig(
                    name=provider_name,
                    base_url=base_url,
                    protocol=parse_protocol(pdata, LlmProtocol.OPENAI),
                    api_keys=resolve_api_keys(provider_name, pdata),
                    models=models,
                    extra_headers=headers,
                ),
                model_option_overrides=overrides,
            )

    return _OpenRouterHelper()


__all__ = ["build_helper", "OPENROUTER_BASE_URL", "OPENROUTER_DEFAULT_HEADERS"]
