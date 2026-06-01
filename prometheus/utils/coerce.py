"""Shared coercion utilities for LLM tool parameter handling."""

from __future__ import annotations

import json
from typing import TypeVar

T = TypeVar("T")


def coerce_to_list(
    value: list[T] | str | None,
    *,
    fallback: list[T] | None = None,
) -> list[T] | None:
    """Coerce a JSON string or single value to a list.

    The LLM sometimes passes ``'["a", "b"]'`` (a JSON string) instead of
    ``["a", "b"]`` (an actual list).  This function handles both cases
    plus ``None`` and bare strings.

    Returns *fallback* (default ``None``) when *value* is ``None`` or
    an empty string after stripping.
    """
    if value is None:
        return fallback
    if isinstance(value, list):
        return value
    if not isinstance(value, str):
        return [value]  # type: ignore[list-item]

    text = value.strip()
    if not text:
        return fallback

    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return [text]  # type: ignore[list-item]

    if isinstance(parsed, list):
        return parsed  # type: ignore[return-value]
    return [parsed]  # type: ignore[list-item]
