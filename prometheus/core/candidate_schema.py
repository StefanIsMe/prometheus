"""Canonical finding candidate schema and lifecycle rules."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

LifecycleStatus = Literal[
    "new",
    "needs_review",
    "validating",
    "verified",
    "rejected",
    "archived",
    "ready_to_submit",
    "submitted",
    "duplicate",
    "accepted",
]

EVIDENCE_KINDS = frozenset(
    {
        "request",
        "response",
        "diff",
        "control",
        "screenshot",
        "code_location",
        "note",
        "payload_result",
        "browser_trace",
    }
)

VALIDATORS = frozenset(
    {
        "deterministic_gate",
        "live_verification",
        "poc_execution",
        "browser_validation",
        "manual_review",
        "heuristic_judge",
    }
)

LEGAL_TRANSITIONS: dict[str, set[str]] = {
    "new": {"needs_review", "validating", "rejected", "archived"},
    "needs_review": {"validating", "rejected", "archived"},
    "validating": {"verified", "rejected", "needs_review"},
    "verified": {"ready_to_submit", "rejected", "archived"},
    "ready_to_submit": {"submitted", "rejected", "archived"},
    "submitted": {"accepted", "duplicate", "rejected"},
    "duplicate": {"archived"},
    "accepted": set(),
    "rejected": {"archived", "needs_review"},
    "archived": {"needs_review"},
}


@dataclass(slots=True)
class FindingCandidate:
    id: str
    domain: str
    scan_id: str
    source_tool: str
    source_type: str
    title: str
    vuln_type: str
    fingerprint: str
    raw_finding_json: str
    lifecycle_status: LifecycleStatus = "new"
    severity: str | None = None
    confidence: float | None = None
    endpoint: str | None = None
    method: str | None = None
    parameter: str | None = None
    auth_state: str | None = None
    role: str | None = None
    workflow_step: str | None = None
    rejection_reason: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    last_seen_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_row(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class EvidenceArtifact:
    id: str
    finding_id: str
    evidence_kind: str
    summary: str | None = None
    path: str | None = None
    inline_json: str | None = None
    metadata_json: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_row(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ValidationRunRecord:
    id: str
    finding_id: str
    validator: str
    status: str
    output_json: str
    started_at: str
    confidence: float | None = None
    finished_at: str | None = None

    def to_row(self) -> dict[str, Any]:
        return asdict(self)


def assert_legal_transition(from_status: str, to_status: str) -> None:
    allowed = LEGAL_TRANSITIONS.get(from_status, set())
    if to_status not in allowed and from_status != to_status:
        raise ValueError(f"Illegal lifecycle transition: {from_status} -> {to_status}")
