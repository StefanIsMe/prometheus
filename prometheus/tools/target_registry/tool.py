"""Agent-facing target registry tools.

These tools let the prometheus agent manage scan targets: add, remove,
list, update, and inspect targets in the persistent registry.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from agents import RunContextWrapper, function_tool

from prometheus.core.target_registry import TargetRegistry


logger = logging.getLogger(__name__)


def _registry() -> TargetRegistry:
    return TargetRegistry()


# ------------------------------------------------------------------
# Tools
# ------------------------------------------------------------------


@function_tool(timeout=30)
async def add_target(
    ctx: RunContextWrapper,
    target_id: str,
    target_type: str,
    target_config_json: str = "{}",
    instructions: str = "",
    custom_headers: str = "",
    interval_hours: int = 24,
) -> str:
    """Add a new scan target to the persistent registry.

    Args:
        target_id: Target domain or URL (e.g. ``example.com``).
        target_type: Type of target (e.g. ``web``, ``api``, ``mobile``).
        target_config_json: JSON string with target-specific config
            (e.g. ``{"scope": ["*.example.com"], "auth": {...}}``).
        instructions: Free-form instructions for the scanner agent.
        custom_headers: JSON string of custom HTTP headers to include.
        interval_hours: Hours between scheduled scans (default 24).
    """
    try:
        target_config: dict[str, Any] = json.loads(target_config_json) if target_config_json else {}
    except json.JSONDecodeError as exc:
        return json.dumps({"success": False, "error": f"Invalid target_config_json: {exc}"})

    scan_config: dict[str, Any] = {
        "instructions": instructions,
        "custom_headers": custom_headers,
    }
    schedule = {"interval_hours": interval_hours}

    try:
        result = await asyncio.to_thread(
            _registry().add_target,
            domain=target_id,
            target_type=target_type,
            target_config=target_config,
            scan_config=scan_config,
            schedule=schedule,
        )
    except Exception as exc:
        logger.exception("add_target failed")
        return json.dumps({"success": False, "error": str(exc)})
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool(timeout=30)
async def remove_target(
    ctx: RunContextWrapper,
    target_id: str,
) -> str:
    """Remove a target from the registry.

    Args:
        target_id: The target's unique ID (12-char hex string).
    """
    try:
        result = await asyncio.to_thread(
            _registry().remove_target,
            target_id=target_id,
        )
    except Exception as exc:
        logger.exception("remove_target failed")
        return json.dumps({"success": False, "error": str(exc)})
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool(timeout=30)
async def list_targets(
    ctx: RunContextWrapper,
    status: str = "active",
) -> str:
    """List all targets in the registry, filtered by status.

    Args:
        status: Filter by status — ``active``, ``paused``, ``archived``.
            Default ``active``.
    """
    try:
        targets = await asyncio.to_thread(
            _registry().list_targets,
            status=status,
        )
    except Exception as exc:
        logger.exception("list_targets failed")
        return json.dumps({"success": False, "error": str(exc)})
    return json.dumps(
        {"success": True, "count": len(targets), "targets": targets},
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def update_target(
    ctx: RunContextWrapper,
    target_id: str,
    instructions: str | None = None,
    interval_hours: int | None = None,
    status: str | None = None,
) -> str:
    """Update an existing target's configuration.

    Only specified fields are changed; pass ``None`` (omit) to leave
    a field unchanged.

    Args:
        target_id: The target's unique ID.
        instructions: New scanner instructions.
        interval_hours: New scan interval in hours.
        status: New status (``active``, ``paused``, ``archived``).
    """
    try:
        result = await asyncio.to_thread(
            _registry().update_target,
            target_id=target_id,
            instructions=instructions,
            interval_hours=interval_hours,
            status=status,
        )
    except Exception as exc:
        logger.exception("update_target failed")
        return json.dumps({"success": False, "error": str(exc)})
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool(timeout=30)
async def get_target(
    ctx: RunContextWrapper,
    target_id: str,
) -> str:
    """Get full details for a single target.

    Args:
        target_id: The target's unique ID.
    """
    try:
        target = await asyncio.to_thread(
            _registry().get_target,
            target_id=target_id,
        )
    except Exception as exc:
        logger.exception("get_target failed")
        return json.dumps({"success": False, "error": str(exc)})
    if target is None:
        return json.dumps(
            {"success": False, "error": f"Target '{target_id}' not found"},
            default=str,
        )
    return json.dumps(
        {"success": True, "target": target},
        ensure_ascii=False,
        default=str,
    )
