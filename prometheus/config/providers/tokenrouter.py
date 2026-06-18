"""TokenRouter helper.

TokenRouter is a custom OpenAI-compatible proxy that fronts multiple
upstream providers (Anthropic, DeepSeek, GPT, etc.). The user passes
``TOKENROUTER_API_KEY`` via env, the base URL is fixed, and the protocol
is always OpenAI Chat-Completions.
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


TOKENROUTER_BASE_URL = "https://api.tokenrouter.com/v1"
TOKENROUTER_ENV_KEY = "TOKENROUTER_API_KEY"


def build_helper() -> ProviderHelper:
    class _TokenRouterHelper:
        name = "tokenrouter"

        def __call__(self, pdata: dict[str, Any]) -> ProviderParseResult:
            provider_name = str(pdata.get("__name", "tokenrouter"))
            # Base URL: the user can override (some users point at a
            # private TokenRouter gateway), but the default is the
            # public one.
            base_url = str(pdata.get("base_url", "")).strip() or TOKENROUTER_BASE_URL
            keys = resolve_api_keys(provider_name, pdata)
            if not keys:
                # Last-ditch: read directly. The .env loader already
                # calls _load_dotenv, so by the time we get here the env
                # var should be populated if it exists at all.
                env_val = os.environ.get(TOKENROUTER_ENV_KEY)
                if env_val:
                    keys.append(env_val)
            return ProviderParseResult(
                provider=ProviderConfig(
                    name=provider_name,
                    base_url=base_url,
                    protocol=parse_protocol(pdata, LlmProtocol.OPENAI),
                    api_keys=keys,
                    models=parse_models(pdata),
                    extra_headers=parse_extra_headers(pdata),
                )
            )

    return _TokenRouterHelper()


__all__ = ["build_helper", "TOKENROUTER_BASE_URL"]
