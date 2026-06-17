"""LLM knowledge base — local lookup for provider/model metadata.

Reads ``llm_knowledge.yaml`` files (bundled defaults + user override) and
exposes a single :func:`lookup` function the TUI meta panel uses to get
context windows, pricing, and free-tier windows without making API calls
or doing runtime inference.

The KB is keyed by ``(provider, model_id)`` first, then by ``alias``,
then by ``model_id``-only — see :func:`lookup` for full precedence.

Layering mirrors ``llm.yaml``:

1. ``~/.prometheus/llm_knowledge.yaml`` — user override (wins on duplicates)
2. Bundled ``llm_knowledge.yaml`` shipped with the package — curated defaults

A mtime-based cache keeps the lookup O(1) on the hot path. The cache
invalidates automatically when either file's mtime changes, so editing
``~/.prometheus/llm_knowledge.yaml`` and saving is picked up on the
next meta-panel refresh (within ~350ms, the TUI's UI tick).
"""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any
from collections.abc import Iterable

import yaml

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------


# Bundled defaults — always present, version-controlled with the package.
_BUNDLED_KB_PATH = Path(__file__).resolve().parent / "llm_knowledge.yaml"

# User override — at the standard Prometheus config dir, like llm.yaml.
_USER_KB_PATH = Path.home() / ".prometheus" / "llm_knowledge.yaml"

# Env var override for tests / unusual setups (matches llm.yaml's
# PROMETHEUS_LLM_CONFIG convention).
_ENV_KB_PATH = "PROMETHEUS_LLM_KNOWLEDGE"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ModelPricing:
    """Per-million-token USD pricing. ``None`` = unknown / not set."""

    input_per_million_usd: float | None = None
    output_per_million_usd: float | None = None
    cached_input_per_million_usd: float | None = None

    def is_free(self) -> bool:
        """Return True when every known rate is exactly 0.0.

        Treats ``None`` as "unknown, not necessarily free" — only rates
        the KB explicitly records as 0 are considered free.
        """
        rates = [
            self.input_per_million_usd,
            self.output_per_million_usd,
            self.cached_input_per_million_usd,
        ]
        return all(r == 0.0 for r in rates if r is not None)


@dataclass(frozen=True)
class ModelKnowledge:
    """One row of the LLM knowledge base — a single (provider, model_id) entry."""

    provider: str
    model_id: str
    aliases: tuple[str, ...] = ()
    context_window: int | None = None
    max_output_tokens: int | None = None
    supports_thinking: bool = False
    pricing: ModelPricing = field(default_factory=ModelPricing)
    free_until: date | None = None
    notes: str = ""

    def is_free_now(self, today: date | None = None) -> bool:
        """Return True when this model is in a currently-free window.

        A model is "free now" when ``free_until`` is set AND is strictly
        after ``today`` AND every recorded pricing rate is 0. The pricing
        check guards against stale ``free_until`` dates that were
        forgotten after the KB was updated to non-zero rates.
        """
        free_until = self.free_until
        if free_until is None:
            return False
        check = today if today is not None else date.today()
        if free_until <= check:
            return False
        return self.pricing.is_free()

    def days_until_free_ends(self, today: date | None = None) -> int | None:
        """Return the number of days remaining in the free window, or None if not free."""
        free_until = self.free_until
        if free_until is None:
            return None
        if not self.is_free_now(today):
            return None
        check = today if today is not None else date.today()
        return (free_until - check).days

    def estimate_cost(
        self,
        *,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cached_tokens: int = 0,
    ) -> float | None:
        """Estimate cost from KB pricing. Returns None if pricing is unknown.

        Free models always return 0.0. This is the cost *the user would
        pay if the model were not free* — useful for showing savings.
        For the actual ledger cost, use the report state's
        ``llm_usage.cost`` field instead.
        """
        if self.is_free_now():
            return 0.0
        p = self.pricing
        if p.input_per_million_usd is None or p.output_per_million_usd is None:
            return None
        # Cached tokens are billed at the cached rate (if set), the
        # remainder of input at the input rate.
        cached_rate = p.cached_input_per_million_usd
        if cached_rate is None:
            cached_rate = p.input_per_million_usd
        uncached_input = max(0, input_tokens - cached_tokens)
        cost = (
            uncached_input * p.input_per_million_usd
            + cached_tokens * cached_rate
            + output_tokens * p.output_per_million_usd
        ) / 1_000_000
        return cost


# ---------------------------------------------------------------------------
# Loader + cache
# ---------------------------------------------------------------------------


@dataclass
class _CacheEntry:
    """In-memory snapshot of the merged KB + the source-file mtimes."""

    by_provider_model: dict[tuple[str, str], ModelKnowledge]
    by_alias: dict[str, ModelKnowledge]
    by_model_id: dict[str, ModelKnowledge]
    bundled_mtime: float
    user_mtime: float
    bundled_path: Path
    user_path: Path | None


_cache_lock = threading.Lock()
_cache: _CacheEntry | None = None


def _parse_date(value: Any) -> date | None:
    """Parse a YAML date / string into a ``date``. Returns None on failure."""
    if value is None:
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, str):
        try:
            return date.fromisoformat(value.strip())
        except ValueError:
            logger.debug("llm_knowledge: could not parse date %r", value)
            return None
    return None


def _parse_pricing(raw: Any) -> ModelPricing:
    """Parse the ``pricing:`` block of one KB entry. Tolerant of missing fields."""
    if not isinstance(raw, dict):
        return ModelPricing()
    return ModelPricing(
        input_per_million_usd=_parse_optional_float(raw.get("input_per_million_usd")),
        output_per_million_usd=_parse_optional_float(raw.get("output_per_million_usd")),
        cached_input_per_million_usd=_parse_optional_float(raw.get("cached_input_per_million_usd")),
    )


def _parse_optional_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _parse_entry(raw: dict[str, Any]) -> ModelKnowledge | None:
    """Parse one KB entry. Returns None on validation failure (logged)."""
    provider = raw.get("provider")
    model_id = raw.get("model_id")
    if not isinstance(provider, str) or not provider.strip():
        logger.debug("llm_knowledge: skipping entry with no provider: %r", raw)
        return None
    if not isinstance(model_id, str) or not model_id.strip():
        logger.debug("llm_knowledge: skipping entry with no model_id: %r", raw)
        return None

    aliases_raw = raw.get("aliases") or []
    aliases: tuple[str, ...] = ()
    if isinstance(aliases_raw, list):
        aliases = tuple(str(a).strip().lower() for a in aliases_raw if str(a).strip())

    context_window = _parse_optional_float(raw.get("context_window"))
    max_output_tokens = _parse_optional_float(raw.get("max_output_tokens"))

    return ModelKnowledge(
        provider=provider.strip().lower(),
        model_id=model_id.strip(),
        aliases=aliases,
        context_window=int(context_window) if context_window else None,
        max_output_tokens=int(max_output_tokens) if max_output_tokens else None,
        supports_thinking=bool(raw.get("supports_thinking", False)),
        pricing=_parse_pricing(raw.get("pricing")),
        free_until=_parse_date(raw.get("free_until")),
        notes=str(raw.get("notes") or "").strip(),
    )


def _parse_kb_file(path: Path) -> list[ModelKnowledge]:
    """Parse a single KB YAML file. Returns [] on missing/invalid file."""
    if not path.is_file():
        return []
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        logger.exception("llm_knowledge: failed to parse %s", path)
        return []
    if not isinstance(raw, dict):
        logger.warning("llm_knowledge: %s is not a mapping, ignoring", path)
        return []
    entries_raw = raw.get("models")
    if not isinstance(entries_raw, list):
        logger.warning("llm_knowledge: %s has no 'models' list, ignoring", path)
        return []
    entries: list[ModelKnowledge] = []
    for item in entries_raw:
        if not isinstance(item, dict):
            continue
        entry = _parse_entry(item)
        if entry is not None:
            entries.append(entry)
    return entries


def _merge_entries(
    *iterables: Iterable[ModelKnowledge],
) -> tuple[
    list[ModelKnowledge],
    dict[tuple[str, str], ModelKnowledge],
    dict[str, ModelKnowledge],
    dict[str, ModelKnowledge],
]:
    """Merge KB entries, with later iterables winning on (provider, model_id) collision.

    Aliases accumulate across both files — if the bundled KB has
    ``minimax-m3`` as an alias and the user adds ``m3-budget`` to the
    same row, both aliases end up on the merged entry. To make that
    merge-by-alias work, the *user* entry re-uses the *bundled*
    entry's aliases when the (provider, model_id) pair collides.

    Returns ``(entries, by_provider_model, alias_to_entry, by_model_id)``.
    """
    by_key: dict[tuple[str, str], ModelKnowledge] = {}
    alias_to_entry: dict[str, ModelKnowledge] = {}
    model_id_to_entries: dict[str, list[ModelKnowledge]] = {}

    for iterable in iterables:
        for entry in iterable:
            key = (entry.provider, entry.model_id)
            existing = by_key.get(key)
            if existing is not None:
                # Collision — newer entry wins, but merge aliases so
                # both files' aliases resolve to the same row.
                merged_aliases = tuple(dict.fromkeys(existing.aliases + entry.aliases))
                # Replace with a new dataclass instance carrying the
                # merged alias set. Other fields come from the new entry.
                entry = ModelKnowledge(
                    provider=entry.provider,
                    model_id=entry.model_id,
                    aliases=merged_aliases,
                    context_window=entry.context_window
                    if entry.context_window is not None
                    else existing.context_window,
                    max_output_tokens=entry.max_output_tokens
                    if entry.max_output_tokens is not None
                    else existing.max_output_tokens,
                    supports_thinking=entry.supports_thinking or existing.supports_thinking,
                    pricing=entry.pricing,  # user's pricing wins wholesale
                    free_until=entry.free_until
                    if entry.free_until is not None
                    else existing.free_until,
                    notes=entry.notes or existing.notes,
                )
            by_key[key] = entry
            for alias in entry.aliases:
                alias_to_entry[alias] = entry
            model_id_to_entries.setdefault(entry.model_id, []).append(entry)

    # Index by model_id (case-insensitive on the alias side, exact on
    # the model_id side — the first hit wins for collision cases).
    by_model_id: dict[str, ModelKnowledge] = {}
    for model_id, entries in model_id_to_entries.items():
        by_model_id[model_id] = entries[0]
        # Also case-insensitive lookup for convenience.
        by_model_id[model_id.lower()] = entries[0]

    # Build the cache entry — alias map is built last so the user's
    # alias takes precedence over the bundled one.
    return list(by_key.values()), by_key, alias_to_entry, by_model_id


def _resolve_paths() -> tuple[Path, Path | None]:
    """Return (bundled_path, user_path_or_None) honoring the env override."""
    env_override = os.environ.get(_ENV_KB_PATH)
    if env_override:
        # When the env var is set, it replaces the user path. The
        # bundled defaults are still loaded alongside.
        return _BUNDLED_KB_PATH, Path(env_override)
    return _BUNDLED_KB_PATH, _USER_KB_PATH if _USER_KB_PATH.is_file() else None


def _mtime(path: Path | None) -> float:
    """Return the file's mtime, or 0.0 if missing."""
    if path is None:
        return 0.0
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def _load_cache() -> _CacheEntry:
    """Build the cache entry, refreshing if any source file changed."""
    global _cache
    bundled_path, user_path = _resolve_paths()
    bundled_mtime = _mtime(bundled_path)
    user_mtime = _mtime(user_path)

    with _cache_lock:
        if _cache is not None:
            if (
                _cache.bundled_path == bundled_path
                and _cache.user_path == user_path
                and _cache.bundled_mtime == bundled_mtime
                and _cache.user_mtime == user_mtime
            ):
                return _cache

        # User file wins — load it second so its entries override the bundled ones.
        bundled_entries = _parse_kb_file(bundled_path)
        user_entries = _parse_kb_file(user_path) if user_path else []
        entries, by_key, alias_map, by_model_id = _merge_entries(bundled_entries, user_entries)

        logger.info(
            "llm_knowledge: loaded %d bundled + %d user override entries (total %d unique)",
            len(bundled_entries),
            len(user_entries),
            len(entries),
        )

        _cache = _CacheEntry(
            by_provider_model=by_key,
            by_alias=alias_map,
            by_model_id=by_model_id,
            bundled_mtime=bundled_mtime,
            user_mtime=user_mtime,
            bundled_path=bundled_path,
            user_path=user_path,
        )
        return _cache


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def lookup(
    model_id: str | None,
    *,
    provider: str | None = None,
) -> ModelKnowledge | None:
    """Look up a model in the local knowledge base.

    Precedence:

    1. Exact ``(provider, model_id)`` match (provider lowercased)
    2. Alias match on ``model_id`` (case-insensitive)
    3. ``model_id``-only match (case-insensitive) — first hit wins

    Returns ``None`` when the model is not in the KB. Callers should
    fall back to ``LlmConfig`` / "unknown" in that case.
    """
    if not model_id:
        return None
    cache = _load_cache()

    if provider:
        hit = cache.by_provider_model.get((provider.strip().lower(), model_id.strip()))
        if hit is not None:
            return hit

    alias_hit = cache.by_alias.get(model_id.strip().lower())
    if alias_hit is not None:
        return alias_hit

    return cache.by_model_id.get(model_id.strip().lower())


def all_entries() -> list[ModelKnowledge]:
    """Return every entry in the merged KB, for tooling / debug panels."""
    cache = _load_cache()
    return list(cache.by_provider_model.values())


def invalidate_cache() -> None:
    """Drop the in-memory cache. Next lookup re-reads the YAML files."""
    global _cache
    with _cache_lock:
        _cache = None


__all__ = [
    "ModelKnowledge",
    "ModelPricing",
    "lookup",
    "all_entries",
    "invalidate_cache",
]
