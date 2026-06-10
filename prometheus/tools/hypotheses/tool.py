"""Agent tools for hypothesis driven novel threat discovery."""

from __future__ import annotations

import json
from typing import Any

from agents import RunContextWrapper, function_tool

from prometheus.core.hypotheses import (
    DifficultyFactors,
    calculate_task_difficulty,
    require_active_hypothesis_manager,
)


def _json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, default=str)


@function_tool(timeout=30, strict_mode=False)
async def create_hypothesis(
    ctx: RunContextWrapper,
    target_id: str,
    endpoint: str,
    method: str,
    parameter: str,
    auth_state: str,
    role: str,
    workflow_step: str,
    vulnerability_class: str,
    exploit_goal: str,
    oracle: str,
    preconditions: list[str] | None = None,
    payload_family: str = "",
    source: str = "agent",
    novelty_score: float = 0.5,
    exploitability_score: float = 0.5,
    difficulty_score: float = 0.5,
    evidence_score: float = 0.0,
) -> str:
    """Create a target-specific vulnerability hypothesis.

    Use this after recon finds interesting behaviour. A useful hypothesis
    includes a vulnerable surface, exploit goal, and a concrete oracle that can
    prove or disprove exploitability.
    """

    try:
        manager = require_active_hypothesis_manager()
        hypothesis = manager.create_hypothesis(
            target_id=target_id,
            endpoint=endpoint,
            method=method,
            parameter=parameter,
            auth_state=auth_state,
            role=role,
            workflow_step=workflow_step,
            vulnerability_class=vulnerability_class,
            exploit_goal=exploit_goal,
            oracle=oracle,
            preconditions=preconditions or [],
            payload_family=payload_family,
            source=source,
            novelty_score=novelty_score,
            exploitability_score=exploitability_score,
            difficulty_score=difficulty_score,
            evidence_score=evidence_score,
        )
        return _json({"success": True, "hypothesis": hypothesis})
    except Exception as exc:  # noqa: BLE001
        return _json({"success": False, "error": str(exc)})


@function_tool(timeout=30, strict_mode=False)
async def score_hypothesis(
    ctx: RunContextWrapper,
    hypothesis_id: str,
    novelty_score: float | None = None,
    exploitability_score: float | None = None,
    difficulty_score: float | None = None,
    evidence_score: float | None = None,
    horizon: float | None = None,
    unknowns: float | None = None,
    context_load: float | None = None,
    state_complexity: float | None = None,
    tool_risk: float | None = None,
) -> str:
    """Update hypothesis scores or calculate difficulty from TDI factors."""

    try:
        difficulty_values = [horizon, unknowns, context_load, state_complexity, tool_risk]
        if any(value is not None for value in difficulty_values):
            difficulty_score = calculate_task_difficulty(
                DifficultyFactors(
                    horizon=horizon or 0.0,
                    unknowns=unknowns or 0.0,
                    context_load=context_load or 0.0,
                    state_complexity=state_complexity or 0.0,
                    tool_risk=tool_risk or 0.0,
                ),
            )
        hypothesis = require_active_hypothesis_manager().score_hypothesis(
            hypothesis_id,
            novelty_score=novelty_score,
            exploitability_score=exploitability_score,
            difficulty_score=difficulty_score,
            evidence_score=evidence_score,
        )
        return _json({"success": True, "hypothesis": hypothesis})
    except Exception as exc:  # noqa: BLE001
        return _json({"success": False, "error": str(exc)})


@function_tool(timeout=30, strict_mode=False)
async def select_next_hypothesis(ctx: RunContextWrapper) -> str:
    """Select the next hypothesis using exploitability, evidence, novelty, and difficulty."""

    try:
        hypothesis = require_active_hypothesis_manager().select_next_hypothesis()
        return _json({"success": True, "hypothesis": hypothesis})
    except Exception as exc:  # noqa: BLE001
        return _json({"success": False, "error": str(exc)})


@function_tool(timeout=30, strict_mode=False)
async def record_hypothesis_evidence(
    ctx: RunContextWrapper,
    hypothesis_id: str,
    evidence_type: str,
    summary: str,
    request: dict[str, Any] | None = None,
    response_fingerprint: dict[str, Any] | None = None,
    control_passed: bool = False,
) -> str:
    """Attach evidence to a hypothesis.

    Use evidence_type values like observation, positive_control, negative_control,
    validation_agent_result, or side_effect.
    """

    try:
        evidence = require_active_hypothesis_manager().record_evidence(
            hypothesis_id,
            evidence_type=evidence_type,
            summary=summary,
            request=request or {},
            response_fingerprint=response_fingerprint or {},
            control_passed=control_passed,
        )
        return _json({"success": True, "evidence": evidence})
    except Exception as exc:  # noqa: BLE001
        return _json({"success": False, "error": str(exc)})


@function_tool(timeout=30, strict_mode=False)
async def mark_hypothesis_status(
    ctx: RunContextWrapper,
    hypothesis_id: str,
    status: str,
    last_error: str = "",
) -> str:
    """Move a hypothesis through its lifecycle."""

    try:
        manager = require_active_hypothesis_manager()
        hypothesis = manager.mark_status(hypothesis_id, status, last_error)
        if status in {"validated", "dead_end", "abandoned"}:
            manager.store_trajectory(hypothesis_id, status)
        return _json({"success": True, "hypothesis": hypothesis})
    except Exception as exc:  # noqa: BLE001
        return _json({"success": False, "error": str(exc)})


@function_tool(timeout=30, strict_mode=False)
async def get_hypothesis_portfolio(
    ctx: RunContextWrapper,
    status: str | None = None,
) -> str:
    """Return active, validated, dead-end, and abandoned hypotheses."""

    try:
        items = require_active_hypothesis_manager().list_hypotheses(status=status)
        return _json({"success": True, "count": len(items), "hypotheses": items})
    except Exception as exc:  # noqa: BLE001
        return _json({"success": False, "error": str(exc)})


@function_tool(timeout=30, strict_mode=False)
async def check_hypothesis_report_gate(
    ctx: RunContextWrapper,
    hypothesis_id: str,
) -> str:
    """Check whether a hypothesis has enough validation evidence to report."""

    try:
        gate = require_active_hypothesis_manager().report_gate(hypothesis_id)
        return _json({"success": True, "gate": gate})
    except Exception as exc:  # noqa: BLE001
        return _json({"success": False, "error": str(exc)})


@function_tool(timeout=30, strict_mode=False)
async def get_reusable_trajectories(
    ctx: RunContextWrapper,
    target_id: str = "",
    vulnerability_class: str = "",
    endpoint_pattern: str = "",
    limit: int = 10,
) -> str:
    """Search reusable successful or failed attack trajectories."""

    try:
        items = require_active_hypothesis_manager().search_reusable_trajectories(
            target_id=target_id,
            vulnerability_class=vulnerability_class,
            endpoint_pattern=endpoint_pattern,
            limit=limit,
        )
        return _json({"success": True, "count": len(items), "trajectories": items})
    except Exception as exc:  # noqa: BLE001
        return _json({"success": False, "error": str(exc)})
