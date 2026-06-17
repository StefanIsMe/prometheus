"""LLM meta panel — agnostic LLM metadata display for the TUI sidebar.

Renders a compact "meta window" inside the manual-scan sidebar showing the
currently active model, its context window, current context occupancy,
cumulative token usage, and cost. Designed to work with any provider/model
configured in ``~/.prometheus/llm.yaml`` — adding a new model requires no
changes here as long as ``context_window`` is set on the model spec.

The module exposes three pieces:

* :class:`LLMMeta` — a pure dataclass snapshot of the metadata. Snapshot
  first, render second: callers can serialize, log, or unit-test the
  snapshot without touching Textual/Rich.
* :func:`collect_llm_meta` — gathers the snapshot from the report state
  plus the active LLM config and the local KB (:mod:`llm_knowledge`).
  Resilient to missing config, missing context windows, missing cost
  data, and missing usage records.
* :func:`build_llm_meta_text` — turns the snapshot into a Rich ``Text``
  ready to drop into a ``Static`` widget.

Agnosticism contract:

* The model name is sourced from the active ``ResolvedModel`` (set at
  scan start by :func:`configure_sdk_model_defaults`), and only falls
  back to ``ReportState`` / settings if that is not yet populated.
* Context-window + pricing metadata is looked up first in the local
  knowledge base (:mod:`llm_knowledge`), then in
  :class:`LlmConfig.providers`. Add a new model to either and the meta
  panel picks it up automatically — no code change required.
* Tokens come from :class:`LLMUsageLedger`, which itself aggregates
  SDK ``Usage`` objects. The KB is used as a fallback source for cost
  when the LiteLLM-based ledger has no pricing data.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import date
from typing import TYPE_CHECKING, Any

from rich.text import Text

if TYPE_CHECKING:
    from prometheus.interface.tui.llm_knowledge import ModelKnowledge

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LLMMeta:
    """Pure-data snapshot of LLM metadata for the TUI meta window.

    All fields are best-effort. ``None`` / 0 values mean "unknown" or
    "not yet recorded" — the renderer is responsible for displaying a
    sane placeholder instead of leaking ``None`` to the user.
    """

    model_id: str | None = None
    provider_name: str | None = None
    tier: str | None = None
    # The agent this snapshot is scoped to. None = global (no agent
    # selected, or running in "show the whole scan" mode). The TUI
    # passes the currently-selected agent ID from the agents tree;
    # tooling / tests can pass any agent ID to inspect its usage.
    agent_id: str | None = None
    agent_name: str | None = None
    # Total prompt + output token budget advertised by the model. None
    # when neither the KB nor the LLM config declares one (e.g.
    # dynamic OpenRouter auto-router).
    context_window: int | None = None
    # Source of context_window — "knowledge_base" (preferred),
    # "llm_config" (from ~/.prometheus/llm.yaml), or None (unknown).
    context_window_source: str | None = None
    # Cumulative input tokens across every request in this run. This is
    # the closest proxy we have for "how much of the context window
    # has been consumed" — the SDK does not expose per-conversation
    # current context occupancy, so input tokens (which include the
    # prior conversation history on every turn) is the best signal.
    context_used: int = 0
    # Cumulative token usage across the whole run (input + output).
    total_tokens: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0
    requests: int = 0
    cost: float = 0.0
    has_cost: bool = False  # True when cost came from a real estimate, not a default 0.0
    cost_source: str | None = None  # "ledger" | "knowledge_base" | None
    # Free-tier window fields, populated when the KB has a free_until
    # date in the future AND pricing rates are all 0.
    is_free_now: bool = False
    free_until: date | None = None
    free_days_remaining: int | None = None
    # The matching KB entry, if any. Exposed so future panels (debug,
    # /llm-info modal) can show full notes + pricing detail without
    # re-doing the lookup.
    knowledge: ModelKnowledge | None = None

    @property
    def context_pct(self) -> float | None:
        """Return context utilization as a 0..100 float, or None if unknown."""
        if not self.context_window or self.context_window <= 0:
            return None
        return max(0.0, min(100.0, 100.0 * self.context_used / self.context_window))


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------


def _format_token_count(count: int | float | None) -> str:
    """Compact token count (e.g. ``524K``, ``1.2M``). Mirrors utils.format_token_count."""
    value = int(count or 0)
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}M"
    if value >= 1_000:
        return f"{value / 1_000:.1f}K"
    return str(value)


def _safe_int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _safe_float(value: Any) -> float:
    try:
        result = float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0
    return result if result >= 0 else 0.0


def _lookup_context_window(
    model_id: str | None,
    *,
    provider: str | None = None,
) -> tuple[int | None, str | None]:
    """Find the context window for a model.

    Lookup chain:

    1. Local KB (:mod:`llm_knowledge`) — checked first because the KB
       carries explicit per-(provider, model) windows and survives
       even when ``~/.prometheus/llm.yaml`` is misconfigured.
    2. ``LlmConfig.providers[*].models[*].context_window`` — the
       fall-back when the KB doesn't know about the model.

    Returns ``(context_window, source)`` where ``source`` is one of
    ``"knowledge_base"``, ``"llm_config"``, or ``None`` (unknown).
    """
    if not model_id:
        return None, None

    # --- 1. Knowledge base ------------------------------------------
    try:
        from prometheus.interface.tui.llm_knowledge import lookup as kb_lookup
    except Exception:
        logger.debug("llm_knowledge import failed in meta panel", exc_info=True)
        kb_lookup = None

    if kb_lookup is not None:
        try:
            entry = kb_lookup(model_id, provider=provider)
        except Exception:
            entry = None
            logger.debug("llm_knowledge lookup failed in meta panel", exc_info=True)
        if entry is not None and entry.context_window:
            return int(entry.context_window), "knowledge_base"

    # --- 2. LlmConfig -----------------------------------------------
    try:
        from prometheus.config.llm_config import (
            get_config,
        )  # local import: TUI may render before config is loaded
        from prometheus.config.models import get_active_model_resolution
    except Exception:
        logger.debug("LLM config import failed in meta panel", exc_info=True)
        return None, None

    try:
        config = get_config()
    except Exception:
        logger.debug("get_config() failed in meta panel", exc_info=True)
        return None, None

    # Prefer the active resolution — covers the case where the same
    # model_id appears on multiple providers with different windows.
    try:
        resolution = get_active_model_resolution()
    except Exception:
        resolution = None
        logger.debug("get_active_model_resolution failed in meta panel", exc_info=True)

    if resolution and resolution.model_id == model_id:
        prov = config.providers.get(resolution.provider_name)
        if prov and model_id in prov.models:
            cw = prov.models[model_id].context_window
            if cw:
                return int(cw), "llm_config"

    # Fall back to scanning every provider. First match wins — providers
    # rarely declare overlapping model_ids.
    for prov in config.providers.values():
        spec = prov.models.get(model_id)
        if spec and spec.context_window:
            return int(spec.context_window), "llm_config"

    return None, None


def _lookup_model_id(report_state: Any) -> tuple[str | None, str | None, str | None]:
    """Return (model_id, provider_name, tier) from the active resolution, falling back to state."""
    try:
        from prometheus.config.models import get_active_model_resolution
    except Exception:
        return None, None, None

    try:
        resolution = get_active_model_resolution()
    except Exception:
        resolution = None

    if resolution is not None:
        return resolution.model_id, resolution.provider_name, resolution.tier.value

    # Last-ditch: report state or settings (covers the moment between
    # app start and ``configure_sdk_model_defaults``).
    if report_state is not None:
        usage = getattr(report_state, "_llm_usage", None)
        if usage is not None:
            # The first agent's model is a reasonable fallback — the
            # active resolution hasn't been set yet but a record exists.
            metadata = getattr(usage, "_agent_metadata", None) or {}
            for entry in metadata.values():
                raw_model = entry.get("model") if isinstance(entry, dict) else None
                if isinstance(raw_model, str) and raw_model:
                    # Split "provider/model" so the KB / LlmConfig
                    # lookups can use the bare model_id. The renderer
                    # reassembles "provider/model_id" for display.
                    provider, model_id = _split_provider_model(raw_model)
                    return model_id, provider, None

    try:
        from prometheus.config import load_settings

        model = load_settings().llm.model
        if model:
            provider, model_id = _split_provider_model(model)
            return model_id, provider, None
    except Exception:
        pass

    return None, None, None


def _extract_usage_payload(report_state: Any) -> dict[str, Any]:
    """Pull the ledger's serialized usage record out of the report state.

    Tolerant of older report states that pre-date :class:`LLMUsageLedger`
    — returns an empty dict in that case, which the renderer treats as
    "no usage yet".
    """
    if report_state is None:
        return {}
    usage: Any = None
    getter = getattr(report_state, "get_total_llm_usage", None)
    if callable(getter):
        try:
            usage = getter()
        except Exception:
            usage = None
    if not isinstance(usage, dict):
        record = getattr(report_state, "run_record", None)
        if isinstance(record, dict):
            usage = record.get("llm_usage")
    return usage if isinstance(usage, dict) else {}


def _kb_lookup_safe(model_id: str | None, provider: str | None) -> ModelKnowledge | None:
    """Run the KB lookup, swallowing any error. Returns None on failure."""
    if not model_id:
        return None
    try:
        from prometheus.interface.tui.llm_knowledge import lookup as kb_lookup
    except Exception:
        return None
    try:
        return kb_lookup(model_id, provider=provider)
    except Exception:
        logger.debug("llm_knowledge lookup raised in meta panel", exc_info=True)
        return None


def _split_provider_model(model_str: str | None) -> tuple[str | None, str | None]:
    """Split ``provider/model`` into ``(provider, model_id)``.

    Returns ``(None, model_str)`` for unprefixed ids so the caller
    can still feed ``model_str`` to the KB's model_id-only path.
    """
    if not model_str or "/" not in model_str:
        return None, model_str
    provider, _, model_id = model_str.partition("/")
    provider = provider.strip() or None
    model_id = model_id.strip() or None
    return provider, model_id


def _extract_per_agent_payload(report_state: Any, agent_id: str | None) -> dict[str, Any] | None:
    """Return the per-agent usage record, in-memory if possible.

    Reads ``report_state._llm_usage._agent_usage[agent_id]`` first
    (the live in-memory ledger) so the panel reflects the current
    per-agent state as tokens flow in. Falls back to the serialized
    per-agent entry in ``run_record["llm_usage"]["agents"]`` when
    the in-memory ledger is unavailable — e.g. after a hydrate
    re-load from disk, or in tests that build a state without a
    live ledger object.

    Returns ``None`` when the agent has no recorded data — caller
    should fall back to the global snapshot.
    """
    if report_state is None or not agent_id:
        return None

    # --- 1. In-memory ledger (preferred) ---------------------------
    ledger = getattr(report_state, "_llm_usage", None)
    if ledger is not None:
        usage_obj = getattr(ledger, "_agent_usage", {}).get(agent_id)
        if usage_obj is not None:
            try:
                from agents.usage import serialize_usage

                record = serialize_usage(usage_obj)
                cost_value = getattr(ledger, "_agent_cost", {}).get(agent_id)
                if cost_value is not None:
                    record["cost"] = _safe_float(cost_value)
                record["agent_id"] = agent_id
                return record
            except Exception:
                logger.debug("serialize_usage failed for agent %s", agent_id, exc_info=True)

    # --- 2. Serialized per-agent record (fallback) -----------------
    total = _extract_usage_payload(report_state)
    agents_list = total.get("agents") if isinstance(total, dict) else None
    if isinstance(agents_list, list):
        for entry in agents_list:
            if isinstance(entry, dict) and entry.get("agent_id") == agent_id:
                return entry
    return None


def _lookup_per_agent_identity(
    report_state: Any, agent_id: str | None
) -> tuple[str | None, str | None, str | None]:
    """Return ``(model_id, provider, agent_name)`` for a specific agent.

    Pulls from the in-memory ledger's ``_agent_metadata`` when
    available, falls back to the serialized per-agent record, and
    finally to the live ``live_view.agents`` dict (for the human
    name only — model info is not stored there).
    """
    if report_state is None or not agent_id:
        return None, None, None

    model_str: str | None = None
    agent_name: str | None = None

    ledger = getattr(report_state, "_llm_usage", None)
    if ledger is not None:
        meta = getattr(ledger, "_agent_metadata", {}).get(agent_id)
        if isinstance(meta, dict):
            raw_model = meta.get("model")
            if isinstance(raw_model, str) and raw_model:
                model_str = raw_model
            raw_name = meta.get("agent_name")
            if isinstance(raw_name, str) and raw_name:
                agent_name = raw_name

    if model_str is None or agent_name is None:
        per_agent = _extract_per_agent_payload(report_state, agent_id)
        if isinstance(per_agent, dict):
            if model_str is None:
                raw = per_agent.get("model")
                if isinstance(raw, str) and raw:
                    model_str = raw
            if agent_name is None:
                raw = per_agent.get("agent_name")
                if isinstance(raw, str) and raw:
                    agent_name = raw

    if agent_name is None:
        # Last-ditch: live_view.agents is keyed by agent_id and carries
        # the user-facing name. Use it purely for the display name —
        # model info is authoritative from the ledger.
        live_view = getattr(report_state, "_live_view", None)  # optional
        if live_view is None:
            # TUI stores it on the app, not on the report state. Callers
            # that need the name fallback should pass it via
            # ``live_view_agents`` (see collect_llm_meta).
            pass
        agents_map = getattr(report_state, "agents", None)
        if isinstance(agents_map, dict):
            entry = agents_map.get(agent_id)
            if isinstance(entry, dict):
                raw = entry.get("name")
                if isinstance(raw, str) and raw:
                    agent_name = raw

    provider, model_id = _split_provider_model(model_str)
    return model_id, provider, agent_name


def collect_llm_meta(
    report_state: Any,
    *,
    agent_id: str | None = None,
    live_view_agents: dict[str, Any] | None = None,
) -> LLMMeta:
    """Build a :class:`LLMMeta` snapshot from the report state, LLM config, and KB.

    When ``agent_id`` is set, the snapshot is scoped to that specific
    agent: model name, context window, usage, and cost all reflect
    that agent's LLM calls only. When ``agent_id`` is ``None`` the
    snapshot is the global (whole-scan) view.

    ``live_view_agents`` is an optional fallback for the human agent
    name — the TUI passes its ``live_view.agents`` dict here so the
    panel shows the user-visible name (e.g. "recon_3") rather than
    the internal id ("agent-7f3a").

    Never raises. Missing data becomes a placeholder in the snapshot.
    """
    # --- Resolve model_id / provider / agent_name -------------------
    if agent_id:
        per_agent_model, per_agent_provider, per_agent_name = _lookup_per_agent_identity(
            report_state, agent_id
        )
        if per_agent_model is not None:
            model_id = per_agent_model
            provider_name = per_agent_provider
            agent_name = per_agent_name
            tier = "simple" if _is_child_agent(report_state, agent_id) else None
        else:
            # Agent selected but the ledger has nothing for it yet
            # (just spawned, no LLM calls). Fall back to the global
            # resolved model so the panel still shows something
            # useful — will auto-update on the next ledger record.
            model_id, provider_name, tier = _lookup_model_id(report_state)
            agent_name = _lookup_agent_name(report_state, agent_id, live_view_agents)
    else:
        model_id, provider_name, tier = _lookup_model_id(report_state)
        agent_name = None

    # --- Resolve usage + cost payload ------------------------------
    if agent_id:
        per_agent_record = _extract_per_agent_payload(report_state, agent_id)
        if per_agent_record is not None:
            usage = per_agent_record
        else:
            # No recorded usage for this agent yet — empty payload
            # so the renderer shows "0 / N tokens · 0 req".
            usage = {}
    else:
        usage = _extract_usage_payload(report_state)

    requests = _safe_int(usage.get("requests"))
    input_tokens = _safe_int(usage.get("input_tokens"))
    output_tokens = _safe_int(usage.get("output_tokens"))
    total_tokens = _safe_int(usage.get("total_tokens"))
    if total_tokens <= 0:
        total_tokens = input_tokens + output_tokens

    # Cached tokens (prompt caching) live in input_tokens_details.
    cached_tokens = 0
    details = usage.get("input_tokens_details")
    if isinstance(details, list) and details:
        first = details[0]
        if isinstance(first, dict):
            cached_tokens = _safe_int(first.get("cached_tokens"))
    elif isinstance(details, dict):
        cached_tokens = _safe_int(details.get("cached_tokens"))

    ledger_cost = _safe_float(usage.get("cost"))
    has_ledger_cost = bool(usage) and "cost" in usage and ledger_cost > 0

    # KB lookup — uses the per-agent model when available so a child
    # agent using a different (simpler/cheaper) model picks up that
    # model's context window, pricing, and free-tier.
    kb_entry = _kb_lookup_safe(model_id, provider_name)

    # Context window: KB first, then LlmConfig.
    context_window, context_source = _lookup_context_window(model_id, provider=provider_name)

    # context_used: prefer the latest per-agent request's input_tokens
    # when scoped to an agent — that's the "what the model is chewing
    # on right now for THIS agent" signal. The Usage object's
    # request_usage_entries list survives serialize/deserialize.
    context_used = _latest_request_input_tokens(usage)
    if context_used <= 0:
        # Fallback: cumulative input tokens for this agent/scan.
        # Less precise (includes prior turns) but always present.
        context_used = input_tokens

    # Cost: prefer the ledger. Fall back to the KB when the ledger
    # has no cost (typical for custom proxies / private providers
    # where LiteLLM has no price table) and the KB has pricing.
    cost = ledger_cost
    has_cost = has_ledger_cost
    cost_source: str | None = "ledger" if has_ledger_cost else None

    if (not has_cost) and kb_entry is not None and total_tokens > 0:
        kb_estimate = kb_entry.estimate_cost(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cached_tokens=cached_tokens,
        )
        if kb_estimate is not None:
            cost = kb_estimate
            has_cost = True
            cost_source = "knowledge_base"

    # Free-tier state — only meaningful when the KB says so AND we're
    # currently inside the window. Per-agent: a child agent that uses
    # a paid model still inherits the right free-tier flag from its
    # own KB entry.
    is_free_now = bool(kb_entry and kb_entry.is_free_now())
    free_until = kb_entry.free_until if kb_entry else None
    free_days_remaining = kb_entry.days_until_free_ends() if kb_entry else None

    return LLMMeta(
        agent_id=agent_id,
        agent_name=agent_name,
        model_id=model_id,
        provider_name=provider_name,
        tier=tier,
        context_window=context_window,
        context_window_source=context_source,
        context_used=context_used,
        total_tokens=total_tokens,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cached_tokens=cached_tokens,
        requests=requests,
        cost=cost,
        has_cost=has_cost,
        cost_source=cost_source,
        is_free_now=is_free_now,
        free_until=free_until,
        free_days_remaining=free_days_remaining,
        knowledge=kb_entry,
    )


def _is_child_agent(report_state: Any, agent_id: str) -> bool:
    """Return True when the agent has a parent in the live view.

    Used to pick the right tier for the fallback model lookup. The
    TUI's live view exposes parent/child relationships through
    ``agents[agent_id].parent_id``; we read it from the
    ``live_view_agents`` fallback when present.
    """
    live_view = getattr(report_state, "live_view", None)
    if live_view is not None:
        agents_map = getattr(live_view, "agents", None)
        if isinstance(agents_map, dict):
            entry = agents_map.get(agent_id)
            if isinstance(entry, dict) and entry.get("parent_id"):
                return True
    return False


def _lookup_agent_name(
    report_state: Any,
    agent_id: str | None,
    live_view_agents: dict[str, Any] | None,
) -> str | None:
    """Return the human agent name from the TUI's live view, if known."""
    if not agent_id:
        return None
    if isinstance(live_view_agents, dict):
        entry = live_view_agents.get(agent_id)
        if isinstance(entry, dict):
            name = entry.get("name")
            if isinstance(name, str) and name:
                return name
    return None


def _latest_request_input_tokens(usage: Any) -> int:
    """Return the input_tokens of the most recent request entry, or 0."""
    if not isinstance(usage, dict):
        return 0
    entries = usage.get("request_usage_entries")
    if not isinstance(entries, list) or not entries:
        return 0
    last = entries[-1]
    if not isinstance(last, dict):
        return 0
    return _safe_int(last.get("input_tokens"))


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


# Colors
_DIM = "dim"
_LABEL = "bold #a8a29e"  # stone-400-ish, neutral label
_VALUE = "white"
_VALUE_DIM = "#a3a3a3"  # for "unknown" values
_COST = "#fbbf24"  # amber-400, matches the existing cost color elsewhere
_COST_EST = "#a3a3a3"  # dim grey for KB-estimated cost (less certain than ledger)
_FREE = "#22c55e"  # green for free-tier indicator
_GREEN = "#22c55e"
_YELLOW = "#eab308"
_RED = "#dc2626"


def _context_color(pct: float | None) -> str:
    """Color the context utilization by load."""
    if pct is None:
        return _VALUE_DIM
    if pct >= 80:
        return _RED
    if pct >= 50:
        return _YELLOW
    return _GREEN


def _append_kv_line(
    text: Text,
    label: str,
    value: str,
    *,
    value_style: str = _VALUE,
    trailing: str | None = None,
    trailing_style: str = _DIM,
    newline: bool = True,
) -> None:
    """Append a single ``Label  value`` row, padding the label for alignment.

    12-char label column matches the layout used in the rest of the TUI
    sidebar (vulnerability count, etc.) so the meta panel sits flush
    with its neighbours.
    """
    text.append(f"{label:<12}", style=_LABEL)
    text.append(value, style=value_style)
    if trailing:
        text.append("  ")
        text.append(trailing, style=trailing_style)
    if newline:
        text.append("\n")


def build_llm_meta_text(meta: LLMMeta) -> Text:
    """Render :class:`LLMMeta` as a Rich ``Text``.

    When ``meta.agent_name`` is set, an "Agent" row is shown at the top
    so the user can see which agent's metadata they're viewing. The
    rest of the rows always show in the same order:

    * Agent (only when an agent is selected)
    * Model
    * Context (used / window + percent)
    * Total Used (cumulative input + output tokens + cached annotation)
    * Cost
    """
    text = Text()

    # --- Agent (only when scoped to a specific agent) ---------------
    if meta.agent_name:
        text.append(f"{'Agent':<12}", style=_LABEL)
        # Truncate long agent names so the panel layout stays clean.
        # The agents tree already shortens names; this is the second
        # line of defense.
        name = meta.agent_name
        if len(name) > 28:
            name = name[:25] + "…"
        text.append(name, style="bold white")
        if meta.tier:
            text.append("  ")
            text.append(f"({meta.tier} tier)", style=_VALUE_DIM)
        text.append("\n")

    # --- Model --------------------------------------------------------
    model_display = meta.model_id or "unknown"
    if meta.provider_name:
        # Avoid double-prefixing when model_id already contains a
        # "provider/" segment (common with OpenRouter-style routing).
        if meta.model_id and "/" in meta.model_id:
            model_display_full = meta.model_id
        else:
            model_display_full = (
                f"{meta.provider_name}/{meta.model_id}" if meta.model_id else meta.provider_name
            )
    else:
        model_display_full = model_display
    _append_kv_line(text, "Model", model_display_full)

    # --- Context window / used ---------------------------------------
    if meta.context_window:
        used_str = _format_token_count(meta.context_used)
        win_str = _format_token_count(meta.context_window)
        pct = meta.context_pct
        pct_str = f"{pct:.1f}%" if pct is not None else None
        pct_color = _context_color(pct)

        text.append(f"{'Context':<12}", style=_LABEL)
        text.append(used_str, style=pct_color)
        text.append(" / ", style=_DIM)
        text.append(win_str, style=_VALUE)
        if pct_str:
            text.append("  ")
            text.append(f"({pct_str})", style=pct_color)
        text.append("\n")
    else:
        text.append(f"{'Context':<12}", style=_LABEL)
        text.append("unknown", style=_VALUE_DIM)
        text.append("  ", style=_DIM)
        text.append("(no context_window in llm.yaml)", style=_VALUE_DIM)
        text.append("\n")

    # --- Total tokens used (cumulative) ------------------------------
    total_str = _format_token_count(meta.total_tokens)
    trailing_parts: list[str] = []
    if meta.cached_tokens > 0:
        trailing_parts.append(f"cached {_format_token_count(meta.cached_tokens)}")
    trailing_parts.append(f"{meta.requests} req")
    trailing = " · ".join(trailing_parts)
    _append_kv_line(text, "Total Used", total_str, trailing=trailing)

    # --- Cost ---------------------------------------------------------
    if meta.is_free_now and meta.has_cost:
        # Free-tier model with usage — show a prominent FREE indicator
        # in green plus the dollar figure so the user knows both
        # "what it cost" and "what it would have cost".
        days = meta.free_days_remaining
        until = meta.free_until
        if days is not None and days == 0:
            free_trailing = "last day"
        elif days is not None and days == 1:
            free_trailing = "1 day left"
        elif days is not None:
            free_trailing = f"{days} days left"
        elif until is not None:
            free_trailing = f"until {until.isoformat()}"
        else:
            free_trailing = "free tier"

        text.append(f"{'Cost':<12}", style=_LABEL)
        text.append("FREE", style=f"bold {_FREE}")
        text.append("  ")
        text.append(f"({free_trailing})", style=_FREE)
        if meta.total_tokens > 0:
            text.append("  ")
            text.append(f"· ${meta.cost:.4f} if paid", style=_VALUE_DIM)
        text.append("\n")
    elif meta.has_cost or meta.cost > 0:
        # Normal cost display. Distinguish ledger-reported (bright
        # amber) from KB-estimated (dim grey) so the user knows how
        # confident the figure is.
        cost_str = f"${meta.cost:.4f}"
        cost_style = _COST_EST if meta.cost_source == "knowledge_base" else _COST
        trailing: str | None = "(est.)" if meta.cost_source == "knowledge_base" else None
        trailing_style = _VALUE_DIM
        _append_kv_line(
            text,
            "Cost",
            cost_str,
            value_style=cost_style,
            trailing=trailing,
            trailing_style=trailing_style,
        )
    elif meta.total_tokens > 0:
        # Usage exists but no cost source at all — neither ledger nor
        # KB has pricing. Honest "n/a" beats a misleading zero.
        _append_kv_line(text, "Cost", "n/a", value_style=_VALUE_DIM)
    else:
        # No usage yet — render an empty placeholder so the row exists
        # for layout stability as tokens flow in.
        _append_kv_line(text, "Cost", "$0.0000", value_style=_COST)

    return text


__all__ = [
    "LLMMeta",
    "collect_llm_meta",
    "build_llm_meta_text",
]
