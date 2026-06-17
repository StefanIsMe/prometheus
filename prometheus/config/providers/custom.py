"""Custom endpoint helper — the explicit "I know what I'm doing" path.

Use this when:
  * the provider is not in the registry (e.g. an internal gateway,
    MiniMax direct, a self-hosted LiteLLM proxy),
  * the user wants to pick the protocol explicitly (openai | anthropic),
  * the user wants to attach arbitrary ``extra_headers`` without
    piggy-backing on a generic openai helper.

Config shape::

    providers:
      my-internal-gateway:
        type: custom  # or use the ``custom:`` block below
        base_url: https://llm.internal.example/v1
        protocol: openai          # or anthropic
        api_keys:
          - env: MY_GATEWAY_KEY
        extra_headers:
          X-Org: acme
        models:
          llama-3.1-70b-internal:
            tier: hard
"""

from __future__ import annotations

import logging
from typing import Any

from prometheus.config.llm_config import Protocol as LlmProtocol
from prometheus.config.providers.base import (
    ProviderHelper,
    ProviderParseResult,
    parse_extra_headers,
    parse_models,
    resolve_api_keys,
)
from prometheus.config.llm_config import ProviderConfig


logger = logging.getLogger(__name__)


def build_helper() -> ProviderHelper:
    class _CustomHelper:
        name = "custom"

        def __call__(self, pdata: dict[str, Any]) -> ProviderParseResult:
            provider_name = str(pdata.get("__name", "custom"))
            base_url = str(pdata.get("base_url", "")).strip()
            if not base_url:
                raise ValueError(f"Custom provider {provider_name!r} requires base_url.")

            protocol_raw = str(pdata.get("protocol", "openai")).strip().lower()
            try:
                protocol = LlmProtocol(protocol_raw)
            except ValueError:
                logger.warning(
                    "Custom provider %s: unknown protocol %r, defaulting to openai",
                    provider_name,
                    protocol_raw,
                )
                protocol = LlmProtocol.OPENAI

            return ProviderParseResult(
                provider=ProviderConfig(
                    name=provider_name,
                    base_url=base_url,
                    protocol=protocol,
                    api_keys=resolve_api_keys(provider_name, pdata),
                    models=parse_models(pdata),
                    extra_headers=parse_extra_headers(pdata),
                )
            )

    return _CustomHelper()


__all__ = ["build_helper"]
