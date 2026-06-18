"""DeepSeek helper.

DeepSeek rejects ``tool_choice`` when thinking mode is active — the
audit's most-cited configuration drift bug. The
:data:`_THINKING_NO_TOOL_CHOICE_PROVIDERS` set in
:mod:`prometheus.config.llm_config` already covers this; this helper
keeps the env-var/key resolution in one place.
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


DEEPSEEK_BASE_URL = "https://api.deepseek.com/v1"
DEEPSEEK_ENV_KEY = "DEEPSEEK_API_KEY"


def build_helper() -> ProviderHelper:
    class _DeepSeekHelper:
        name = "deepseek"

        def __call__(self, pdata: dict[str, Any]) -> ProviderParseResult:
            provider_name = str(pdata.get("__name", "deepseek"))
            base_url = str(pdata.get("base_url", "")).strip() or DEEPSEEK_BASE_URL
            keys = resolve_api_keys(provider_name, pdata)
            if not keys:
                env_val = os.environ.get(DEEPSEEK_ENV_KEY)
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

    return _DeepSeekHelper()


__all__ = ["build_helper", "DEEPSEEK_BASE_URL"]
