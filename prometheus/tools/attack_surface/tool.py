"""Agent tools for attack surface graph and workflow mutation planning."""

from __future__ import annotations

import json
from typing import Any

from agents import RunContextWrapper, function_tool

from prometheus.core.attack_surface import (
    WorkflowMutationPlanner,
    require_active_attack_surface_graph,
)


def _json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, default=str)


@function_tool(timeout=30, strict_mode=False)
async def register_attack_surface_node(
    ctx: RunContextWrapper,
    node_type: str,
    key: str,
    attrs: dict[str, Any] | None = None,
) -> str:
    """Register a host, endpoint, parameter, role, workflow, JS route, or sink node."""

    try:
        node_id = require_active_attack_surface_graph().add_node(
            node_type=node_type,
            key=key,
            attrs=attrs or {},
        )
        return _json({"success": True, "node_id": node_id})
    except Exception as exc:  # noqa: BLE001
        return _json({"success": False, "error": str(exc)})


@function_tool(timeout=30, strict_mode=False)
async def register_attack_surface_edge(
    ctx: RunContextWrapper,
    source_id: str,
    target_id: str,
    relation: str,
    evidence: str = "",
) -> str:
    """Register a typed attack surface relationship."""

    try:
        edge_id = require_active_attack_surface_graph().add_edge(
            source_id,
            target_id,
            relation=relation,
            evidence=evidence,
        )
        return _json({"success": True, "edge_id": edge_id})
    except Exception as exc:  # noqa: BLE001
        return _json({"success": False, "error": str(exc)})


@function_tool(timeout=30, strict_mode=False)
async def get_attack_surface_summary(ctx: RunContextWrapper) -> str:
    """Return attack surface graph counts and signature."""

    try:
        return _json({"success": True, "summary": require_active_attack_surface_graph().summary()})
    except Exception as exc:  # noqa: BLE001
        return _json({"success": False, "error": str(exc)})


@function_tool(timeout=30, strict_mode=False)
async def suggest_workflow_mutations(
    ctx: RunContextWrapper,
    endpoint: str,
    method: str,
    parameters: list[str] | None = None,
    auth_state: str = "",
    content_type: str = "",
    workflow_step: str = "",
) -> str:
    """Suggest agnostic request and workflow mutations for a discovered surface."""

    mutations = WorkflowMutationPlanner().suggest_mutations(
        endpoint=endpoint,
        method=method,
        parameters=parameters or [],
        auth_state=auth_state,
        content_type=content_type,
        workflow_step=workflow_step,
    )
    return _json({"success": True, "count": len(mutations), "mutations": mutations})
