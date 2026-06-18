"""Anthropic helper.

Anthropic's API is the Messages API (``/v1/messages``), which speaks the
Anthropic protocol rather than OpenAI Chat-Completions. The harness
auto-converts via the SDK when ``protocol: anthropic`` is set, so this
helper's only job is the env-var / base-url plumbing.
"""

from __future__ import annotations

import os
from typing import Any

from prometheus.config.llm_config import Protocol as LlmProtocol
from prometheus.config.providers.base import (
    ProviderHelper,
    ProviderParseResult,
    parse_extra_headers,
    parse_models,
    parse_protocol,
    resolve_api_keys,
)
from prometheus.config.llm_config import ProviderConfig


ANTHROPIC_BASE_URL = "https://api.anthropic.com/v1"
ANTHROPIC_ENV_KEY = "ANTHROPIC_API_KEY"


def build_helper() -> ProviderHelper:
    class _AnthropicHelper:
        name = "anthropic"

        def __call__(self, pdata: dict[str, Any]) -> ProviderParseResult:
            provider_name = str(pdata.get("__name", "anthropic"))
            base_url = str(pdata.get("base_url", "")).strip() or ANTHROPIC_BASE_URL
            keys = resolve_api_keys(provider_name, pdata)
            if not keys:
                env_val = os.environ.get(ANTHROPIC_ENV_KEY)
                if env_val:
                    keys.append(env_val)
            return ProviderParseResult(
                provider=ProviderConfig(
                    name=provider_name,
                    base_url=base_url,
                    protocol=parse_protocol(pdata, LlmProtocol.ANTHROPIC),
                    api_keys=keys,
                    models=parse_models(pdata),
                    extra_headers=parse_extra_headers(pdata),
                )
            )

    return _AnthropicHelper()


__all__ = ["build_helper", "ANTHROPIC_BASE_URL"]
