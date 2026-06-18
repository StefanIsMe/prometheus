"""Per-provider helper modules for Prometheus LLM routing.

Each provider in :data:`PROVIDER_HELPERS` is responsible for turning the
``pdata`` dict the user wrote in ``~/.prometheus/llm.yaml`` into a
fully-resolved :class:`~prometheus.config.llm_config.ProviderConfig`.

The split exists so a new provider is a one-file change: drop a
``<name>.py`` next to the others, register it in :data:`PROVIDER_HELPERS`,
and the loader wires it in. A helper may also expose provider-specific
quirks (e.g. tool_choice suppression for OpenRouter's auto-router when
the upstream is DeepSeek).

Custom endpoints (anything not in the registry) fall through to the
generic OpenAI/Anthropic parser in
:func:`prometheus.config.llm_config._parse_config`. The custom helper
itself is the explicit "I want to configure a vendor manually" path
and supports the openai | anthropic protocol switch.
"""

from __future__ import annotations

from prometheus.config.providers.base import (
    ProviderHelper,
    ProviderParseResult,
    default_openai_helper,
)
from prometheus.config.providers.deepseek import build_helper as _deepseek
from prometheus.config.providers.anthropic import build_helper as _anthropic
from prometheus.config.providers.openrouter import build_helper as _openrouter
from prometheus.config.providers.tokenrouter import build_helper as _tokenrouter
from prometheus.config.providers.custom import build_helper as _custom

# Ordered registry: explicit provider-name → helper builder. ``custom``
# is the wildcard fallback for names that don't match a dedicated helper.
PROVIDER_HELPERS: dict[str, ProviderHelper] = {
    "tokenrouter": _tokenrouter(),
    "openrouter": _openrouter(),
    "deepseek": _deepseek(),
    "anthropic": _anthropic(),
    "openai": default_openai_helper(),
    "custom": _custom(),
}


def get_helper(provider_name: str) -> ProviderHelper | None:
    """Return the helper for ``provider_name`` (case-insensitive), or None."""
    if not provider_name:
        return None
    return PROVIDER_HELPERS.get(provider_name.lower())


def is_known_provider(provider_name: str) -> bool:
    """Return True if ``provider_name`` has a dedicated helper."""
    return bool(provider_name) and provider_name.lower() in PROVIDER_HELPERS


__all__ = [
    "ProviderHelper",
    "ProviderParseResult",
    "PROVIDER_HELPERS",
    "get_helper",
    "is_known_provider",
]
