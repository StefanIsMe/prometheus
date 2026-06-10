"""Coverage tracking for prometheus security scans.

Tracks a matrix of (endpoint × vulnerability_type) cells so agents can
see which attack-surface areas have been tested and which remain.

Persistence mirrors the todo-tool pattern: a module-level ``CoverageTracker``
singleton is hydrated once from ``{state_dir}/coverage.json`` and flushed
after every mutation.
"""

from __future__ import annotations

import json
import logging
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)

# ── constants ───────────────────────────────────────────────────────────────

VALID_STATUSES = ["untested", "testing", "tested_clean", "tested_vulnerable", "skipped"]

DEFAULT_VULN_TYPES = [
    "sqli",
    "xss",
    "idor",
    "cors",
    "ssrf",
    "csrf",
    "auth_bypass",
]


# ── data model ──────────────────────────────────────────────────────────────


@dataclass
class CoverageEntry:
    """A single cell in the endpoint × vuln_type coverage matrix.

    Attributes:
        endpoint: The URL or API path being tested.
        vuln_type: The vulnerability class (sqli, xss, idor, …).
        method: HTTP method when known.
        parameter: Specific parameter/body field/header under test.
        role: Account role or privilege level used for the test.
        auth_state: Authentication state used for the test.
        workflow_step: Business workflow step under test.
        status: One of ``untested``, ``testing``, ``tested_clean``,
            ``tested_vulnerable``, ``skipped``.
        agent_id: Which agent last updated this cell.
        notes: Free-form notes from the agent.
        tested_at: Unix-epoch timestamp when the cell was last updated,
            or ``None`` if still untested.
    """

    endpoint: str
    vuln_type: str
    method: str = ""
    parameter: str = ""
    role: str = ""
    auth_state: str = ""
    workflow_step: str = ""
    status: str = "untested"
    agent_id: str = ""
    notes: str = ""
    tested_at: float | None = None


# ── tracker ─────────────────────────────────────────────────────────────────


class CoverageTracker:
    """In-memory coverage matrix with JSON persistence.

    The matrix is keyed by endpoint, method, parameter, role, auth state,
    workflow step, and vulnerability type.  Mutations
    are *not* auto-persisted — call :meth:`persist` explicitly (or use
    the module-level helpers which do it for you).

    Args:
        state_dir: Directory that holds ``coverage.json``.
    """

    def __init__(self, state_dir: Path) -> None:
        self._state_dir = state_dir
        self._path = state_dir / "coverage.json"
        self._entries: dict[tuple[str, str, str, str, str, str, str], CoverageEntry] = {}

    # ── registration ────────────────────────────────────────────────────

    def register_endpoint(self, endpoint: str) -> None:
        """Add *endpoint* to tracking for every vuln_type already in the matrix.

        If the matrix is empty (no vuln_types registered yet), this is a
        no-op — use :func:`generate_coverage_matrix` to bootstrap both
        dimensions at once.
        """
        vuln_types = {e.vuln_type for e in self._entries.values()}
        for vt in vuln_types:
            key = self._key(endpoint, vt)
            if key not in self._entries:
                self._entries[key] = CoverageEntry(endpoint=endpoint, vuln_type=vt)

    def register_test(
        self,
        endpoint: str,
        vuln_type: str,
        status: str,
        agent_id: str = "",
        notes: str = "",
        method: str = "",
        parameter: str = "",
        role: str = "",
        auth_state: str = "",
        workflow_step: str = "",
    ) -> None:
        """Record a test result for *(endpoint, vuln_type)*.

        Args:
            endpoint: URL or path tested.
            vuln_type: Vulnerability class tested.
            status: One of :data:`VALID_STATUSES`.
            agent_id: Identifier of the agent that ran the test.
            notes: Free-form notes.

        Raises:
            ValueError: If *status* is not a valid coverage status.
        """
        status = status.lower()
        if status not in VALID_STATUSES:
            raise ValueError(
                f"Invalid status '{status}'. Must be one of: {', '.join(VALID_STATUSES)}"
            )
        key = self._key(endpoint, vuln_type, method, parameter, role, auth_state, workflow_step)
        existing = self._entries.get(key)
        self._entries[key] = CoverageEntry(
            endpoint=endpoint,
            vuln_type=vuln_type,
            method=method.upper() if method else (existing.method if existing else ""),
            parameter=parameter or (existing.parameter if existing else ""),
            role=role or (existing.role if existing else ""),
            auth_state=auth_state or (existing.auth_state if existing else ""),
            workflow_step=workflow_step or (existing.workflow_step if existing else ""),
            status=status,
            agent_id=agent_id or (existing.agent_id if existing else ""),
            notes=notes or (existing.notes if existing else ""),
            tested_at=time.time() if status != "untested" else None,
        )

    # ── queries ─────────────────────────────────────────────────────────

    def get_coverage(self) -> dict[str, Any]:
        """Return a summary dict: total cells, tested, untested, percentage."""
        total = len(self._entries)
        tested = sum(
            1
            for e in self._entries.values()
            if e.status not in ("untested", "testing")
        )
        untested = total - tested
        pct = round((tested / total) * 100, 1) if total else 0.0
        return {
            "total_cells": total,
            "tested": tested,
            "untested": untested,
            "percentage": pct,
        }

    def get_untested(self) -> list[dict[str, str]]:
        """Return untested endpoint/input/role/workflow cells."""
        return [
            {
                "endpoint": e.endpoint,
                "vuln_type": e.vuln_type,
                "method": e.method,
                "parameter": e.parameter,
                "role": e.role,
                "auth_state": e.auth_state,
                "workflow_step": e.workflow_step,
            }
            for e in self._entries.values()
            if e.status in ("untested", "testing")
        ]

    def get_endpoint_coverage(self, endpoint: str) -> dict[str, Any]:
        """Per-endpoint summary: how many vuln_types tested vs total."""
        cells = [e for e in self._entries.values() if e.endpoint == endpoint]
        total = len(cells)
        tested = sum(1 for e in cells if e.status not in ("untested", "testing"))
        return {
            "endpoint": endpoint,
            "total": total,
            "tested": tested,
            "untested": total - tested,
            "percentage": round((tested / total) * 100, 1) if total else 0.0,
            "cells": [asdict(e) for e in cells],
        }

    def get_vuln_type_coverage(self, vuln_type: str) -> dict[str, Any]:
        """Per-vuln-type summary: how many endpoints tested vs total."""
        cells = [e for e in self._entries.values() if e.vuln_type == vuln_type]
        total = len(cells)
        tested = sum(1 for e in cells if e.status not in ("untested", "testing"))
        return {
            "vuln_type": vuln_type,
            "total": total,
            "tested": tested,
            "untested": total - tested,
            "percentage": round((tested / total) * 100, 1) if total else 0.0,
            "cells": [asdict(e) for e in cells],
        }

    # ── persistence ─────────────────────────────────────────────────────

    def persist(self) -> None:
        """Save the current matrix to ``{state_dir}/coverage.json``."""
        payload = [asdict(e) for e in self._entries.values()]
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            data = json.dumps(payload, ensure_ascii=False, indent=2)
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=str(self._path.parent),
                prefix=f".{self._path.name}.",
                suffix=".tmp",
                delete=False,
            ) as tmp:
                tmp.write(data)
                tmp_path = Path(tmp.name)
            tmp_path.replace(self._path)
        except Exception:
            logger.exception("coverage persist to %s failed", self._path)

    def load(self) -> None:
        """Load the matrix from ``{state_dir}/coverage.json``."""
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception(
                "coverage.json at %s is unreadable; starting empty", self._path
            )
            return
        self._entries.clear()
        for item in raw:
            if not isinstance(item, dict):
                continue
            ep = item.get("endpoint", "")
            vt = item.get("vuln_type", "")
            if not ep or not vt:
                continue
            method = str(item.get("method", ""))
            parameter = str(item.get("parameter", ""))
            role = str(item.get("role", ""))
            auth_state = str(item.get("auth_state", ""))
            workflow_step = str(item.get("workflow_step", ""))
            self._entries[self._key(ep, vt, method, parameter, role, auth_state, workflow_step)] = CoverageEntry(
                endpoint=ep,
                vuln_type=vt,
                method=method,
                parameter=parameter,
                role=role,
                auth_state=auth_state,
                workflow_step=workflow_step,
                status=item.get("status", "untested"),
                agent_id=item.get("agent_id", ""),
                notes=item.get("notes", ""),
                tested_at=item.get("tested_at"),
            )
        logger.info(
            "coverage hydrated from %s (%d cells)",
            self._path,
            len(self._entries),
        )

    # ── helpers ─────────────────────────────────────────────────────────

    def ensure_cell(self, endpoint: str, vuln_type: str) -> None:
        """Add a cell with ``status='untested'`` if it doesn't already exist."""
        key = self._key(endpoint, vuln_type)
        if key not in self._entries:
            self._entries[key] = CoverageEntry(endpoint=endpoint, vuln_type=vuln_type)

    @staticmethod
    def _key(
        endpoint: str,
        vuln_type: str,
        method: str = "",
        parameter: str = "",
        role: str = "",
        auth_state: str = "",
        workflow_step: str = "",
    ) -> tuple[str, str, str, str, str, str, str]:
        return (
            endpoint,
            vuln_type,
            method.upper() if method else "",
            parameter,
            role,
            auth_state,
            workflow_step,
        )

    def all_entries(self) -> list[dict[str, Any]]:
        """Return every cell as a list of dicts."""
        return [asdict(e) for e in self._entries.values()]

    def __len__(self) -> int:
        return len(self._entries)


# ── module-level singleton ──────────────────────────────────────────────────

_tracker: CoverageTracker | None = None
_tracker_lock = threading.RLock()


def _get_tracker() -> CoverageTracker:
    """Return the module-level tracker, raising if not initialised."""
    if _tracker is None:
        raise RuntimeError(
            "CoverageTracker not initialised — call hydrate_coverage_from_disk first"
        )
    return _tracker


def hydrate_coverage_from_disk(state_dir: Path) -> None:
    """Bootstrap the module-level :class:`CoverageTracker` from *state_dir*.

    Call once at startup (from ``runner.py``) before any tool invocations.
    """
    global _tracker  # noqa: PLW0603
    with _tracker_lock:
        _tracker = CoverageTracker(state_dir)
        _tracker.load()


def _persist() -> None:
    """Persist the module-level tracker (no-op if not initialised)."""
    if _tracker is not None:
        with _tracker_lock:
            _tracker.persist()


def _agent_id_from(ctx: RunContextWrapper) -> str:
    """Extract the agent id from a run context."""
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    return str(inner.get("agent_id") or "default")


# ── matrix generator ───────────────────────────────────────────────────────


def generate_coverage_matrix(
    endpoints: list[str],
    vuln_types: list[str] | None = None,
) -> None:
    """Create the full coverage matrix for *endpoints* × *vuln_types*.

    Existing cells are preserved; only missing ``(endpoint, vuln_type)``
    pairs are added with ``status='untested'``.

    Args:
        endpoints: List of URLs or API paths to track.
        vuln_types: Vulnerability classes to test.  Defaults to
            :data:`DEFAULT_VULN_TYPES`.
    """
    tracker = _get_tracker()
    if vuln_types is None:
        vuln_types = DEFAULT_VULN_TYPES
    with _tracker_lock:
        for ep in endpoints:
            for vt in vuln_types:
                tracker.ensure_cell(ep, vt)
        tracker.persist()


# ── agent-callable tools ───────────────────────────────────────────────────


@function_tool(timeout=30)
async def register_coverage(
    ctx: RunContextWrapper,
    endpoint: str,
    vuln_type: str,
    status: str,
    notes: str = "",
    method: str = "",
    parameter: str = "",
    role: str = "",
    auth_state: str = "",
    workflow_step: str = "",
) -> str:
    """Record a test result for an endpoint × vuln_type pair.

    Use this after testing a specific vulnerability class against an
    endpoint so that coverage tracking stays up to date.

    Args:
        endpoint: URL or API path that was tested (e.g. ``/api/users``).
        vuln_type: Vulnerability class — one of ``sqli``, ``xss``,
            ``idor``, ``cors``, ``ssrf``, ``csrf``, ``auth_bypass``.
        status: Test outcome — ``tested_clean``, ``tested_vulnerable``,
            ``testing``, or ``skipped``.
        notes: Optional free-form notes (payloads tried, WAF notes, etc.).
    """
    agent_id = _agent_id_from(ctx)
    logger.debug("register_coverage: endpoint=%s vuln_type=%s status=%s agent=%s", endpoint, vuln_type, status, agent_id)
    try:
        tracker = _get_tracker()
        with _tracker_lock:
            tracker.register_test(
                endpoint,
                vuln_type,
                status,
                agent_id,
                notes,
                method=method,
                parameter=parameter,
                role=role,
                auth_state=auth_state,
                workflow_step=workflow_step,
            )
            tracker.persist()
        return json.dumps(
            {
                "success": True,
                "endpoint": endpoint,
                "vuln_type": vuln_type,
                "status": status,
                "coverage": tracker.get_coverage(),
            },
            ensure_ascii=False,
            default=str,
        )
    except Exception as exc:
        logger.warning("register_coverage failed: endpoint=%s vuln_type=%s", endpoint, vuln_type, exc_info=True)
        return json.dumps(
            {"success": False, "error": str(exc)},
            ensure_ascii=False,
            default=str,
        )


@function_tool(timeout=30)
async def get_coverage_summary(ctx: RunContextWrapper) -> str:
    """Return a JSON summary of overall scan coverage.

    Shows total cells, how many have been tested, how many remain, and
    the completion percentage.  Also includes per-endpoint and per-vuln-type
    breakdowns.
    """
    logger.debug("get_coverage_summary called")
    try:
        tracker = _get_tracker()
        with _tracker_lock:
            overall = tracker.get_coverage()
            endpoints = sorted({e["endpoint"] for e in tracker.all_entries()})
            vuln_types = sorted({e["vuln_type"] for e in tracker.all_entries()})
            by_endpoint = {
                ep: tracker.get_endpoint_coverage(ep) for ep in endpoints
            }
            by_vuln = {
                vt: tracker.get_vuln_type_coverage(vt) for vt in vuln_types
            }
        return json.dumps(
            {
                "success": True,
                "overall": overall,
                "by_endpoint": by_endpoint,
                "by_vuln_type": by_vuln,
            },
            ensure_ascii=False,
            default=str,
        )
    except Exception as exc:
        logger.warning("get_coverage_summary failed", exc_info=True)
        return json.dumps(
            {"success": False, "error": str(exc)},
            ensure_ascii=False,
            default=str,
        )


@function_tool(timeout=30)
async def get_untested_areas(ctx: RunContextWrapper) -> str:
    """Return a JSON list of endpoint × vuln_type pairs not yet tested.

    Use this to discover what still needs work — each entry has
    ``endpoint`` and ``vuln_type`` keys.
    """
    logger.debug("get_untested_areas called")
    try:
        tracker = _get_tracker()
        with _tracker_lock:
            untested = tracker.get_untested()
        return json.dumps(
            {
                "success": True,
                "untested_count": len(untested),
                "untested": untested,
            },
            ensure_ascii=False,
            default=str,
        )
    except Exception as exc:
        logger.warning("get_untested_areas failed", exc_info=True)
        return json.dumps(
            {"success": False, "error": str(exc)},
            ensure_ascii=False,
            default=str,
        )
