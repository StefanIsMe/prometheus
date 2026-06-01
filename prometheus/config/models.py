"""SDK model configuration helpers."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from agents import set_default_openai_api, set_default_openai_key
from agents.retry import (
    ModelRetryBackoffSettings,
    ModelRetrySettings,
    retry_policies,
)


if TYPE_CHECKING:
    from prometheus.config.settings import Settings


_SDK_PREFIXES = {"any-llm", "litellm", "openai"}


def _patch_httpx_no_zstd() -> None:
    """Force httpx to request identity encoding (no zstd/gzip).

    Some API proxies (OpenGateway) send ``Content-Encoding: gzip`` but
    deliver zstd-compressed bodies, which causes httpx decompression
    errors.  Requesting ``identity`` avoids the issue entirely.
    """
    import httpx

    if getattr(httpx.AsyncClient, "_prometheus_no_zstd", False):
        return  # already patched

    _orig_init = httpx.AsyncClient.__init__

    def _patched_init(self: httpx.AsyncClient, *args: object, **kwargs: object) -> None:
        headers = kwargs.pop("headers", None) or {}
        if isinstance(headers, list):
            headers = dict(headers)
        else:
            headers = dict(headers)
        headers.setdefault("Accept-Encoding", "identity")
        kwargs["headers"] = headers
        _orig_init(self, *args, **kwargs)  # type: ignore[call-arg]

    httpx.AsyncClient.__init__ = _patched_init  # type: ignore[assignment]
    httpx.AsyncClient._prometheus_no_zstd = True  # type: ignore[attr-defined]


DEFAULT_MODEL_RETRY = ModelRetrySettings(
    max_retries=5,
    backoff=ModelRetryBackoffSettings(
        initial_delay=2.0,
        max_delay=90.0,
        multiplier=2.0,
        jitter=False,
    ),
    policy=retry_policies.any(
        retry_policies.provider_suggested(),
        retry_policies.network_error(),
        retry_policies.http_status((429, 500, 502, 503, 504)),
    ),
)


def configure_sdk_model_defaults(settings: Settings) -> None:
    """Apply prometheus config to SDK-native defaults.

    OpenAI-compatible base URLs are handled by the SDK OpenAI provider.
    Non-OpenAI providers should use the SDK's native ``litellm/`` or
    ``any-llm/`` routing, produced by :func:`normalize_model_name`.
    """
    _patch_httpx_no_zstd()

    # Reset the shared httpx client singleton so it gets recreated on the
    # current event loop.  warm_up_llm() creates it on a throwaway event
    # loop; if we reuse that stale client from a different loop (e.g. the
    # scan-thread's loop), httpcore hangs because the transport is bound
    # to the dead loop.
    try:
        import agents.models.openai_provider as _op

        _op._http_client = None
    except Exception:
        pass

    # Set a 90s timeout on the OpenAI HTTP client so LLM calls don't hang forever.
    # The default is 600s which is too long for a scan that's stuck.
    try:
        import httpx
        import agents.models.openai_provider as _op

        _original_shared_http_client = _op.shared_http_client

        def _shared_http_client_with_timeout() -> httpx.AsyncClient:
            if _op._http_client is None:
                _op._http_client = _op.DefaultAsyncHttpxClient(
                    timeout=httpx.Timeout(connect=10.0, read=90.0, write=10.0, pool=10.0),
                )
            return _op._http_client

        _op.shared_http_client = _shared_http_client_with_timeout
    except Exception:
        pass

    llm = settings.llm
    _configure_litellm_compatibility()
    if llm.api_key:
        set_default_openai_key(llm.api_key, use_for_tracing=False)
        _configure_litellm_default("api_key", llm.api_key)
    if llm.api_base:
        os.environ["OPENAI_BASE_URL"] = llm.api_base
        _configure_litellm_default("api_base", llm.api_base)
        set_default_openai_api("chat_completions")
    else:
        set_default_openai_api("responses")


def _configure_litellm_compatibility() -> None:
    """Enable LiteLLM's permissive param-handling mode."""
    import litellm

    litellm.drop_params = True
    litellm.modify_params = True


def _configure_litellm_default(name: str, value: str) -> None:
    """Set LiteLLM's module-level defaults without adding a provider wrapper."""
    import litellm

    setattr(litellm, name, value)


def normalize_model_name(model_name: str) -> str:
    """Normalize friendly prometheus model names to SDK-native model ids."""
    model = model_name.strip()
    if not model:
        return model

    if "/" in model:
        prefix = model.split("/", 1)[0].lower()
        if prefix in _SDK_PREFIXES:
            return model
        return f"litellm/{model}"

    lower = model.lower()
    if lower.startswith("claude"):
        return f"litellm/anthropic/{model}"
    if lower.startswith("gemini"):
        return f"litellm/gemini/{model}"

    return model


def uses_chat_completions_tool_schema(model_name: str, settings: Settings) -> bool:
    """Return whether the resolved SDK route can only receive JSON function tools."""
    model = model_name.strip().lower()
    if model.startswith(("litellm/", "any-llm/")):
        return True
    return bool(settings.llm.api_base)
