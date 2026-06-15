"""Engagement state dataclass.

Mirrors the CBH ``engine/state.py`` schema: ``name``, ``created``,
``phase``, ``targets``, ``surface``, ``tested``, ``candidates``,
``confirmed``. Atomic-saved to ``state.json`` via
:func:`prometheus.engagement.manager.Engagement.save`.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class SurfaceSet:
    """The set of endpoints/parameters the engagement has classified."""

    endpoints: list[dict[str, Any]] = field(default_factory=list)
    js_bundles: list[str] = field(default_factory=list)
    openapi: dict[str, Any] | None = None
    secrets: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "SurfaceSet":
        return cls(
            endpoints=list(raw.get("endpoints", [])),
            js_bundles=list(raw.get("js_bundles", [])),
            openapi=raw.get("openapi"),
            secrets=list(raw.get("secrets", [])),
        )


@dataclass
class EngagementState:
    """The full state of an engagement, persisted to ``state.json``."""

    name: str
    created: str
    phase: str = "scoping"  # scoping | recon | hunting | validating | reporting | done
    targets: list[str] = field(default_factory=list)
    surface: SurfaceSet = field(default_factory=SurfaceSet)
    tested: list[dict[str, Any]] = field(default_factory=list)
    candidates: list[dict[str, Any]] = field(default_factory=list)
    confirmed: list[dict[str, Any]] = field(default_factory=list)
    threat_model: dict[str, Any] | None = None
    notes: list[str] = field(default_factory=list)

    @classmethod
    def new(cls, name: str) -> "EngagementState":
        return cls(
            name=name,
            created=datetime.now(UTC).isoformat(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "created": self.created,
            "phase": self.phase,
            "targets": list(self.targets),
            "surface": self.surface.to_dict(),
            "tested": list(self.tested),
            "candidates": list(self.candidates),
            "confirmed": list(self.confirmed),
            "threat_model": self.threat_model,
            "notes": list(self.notes),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "EngagementState":
        surface_raw = raw.get("surface") or {}
        return cls(
            name=str(raw.get("name", "")),
            created=str(raw.get("created", "")),
            phase=str(raw.get("phase", "scoping")),
            targets=list(raw.get("targets", [])),
            surface=SurfaceSet.from_dict(surface_raw if isinstance(surface_raw, dict) else {}),
            tested=list(raw.get("tested", [])),
            candidates=list(raw.get("candidates", [])),
            confirmed=list(raw.get("confirmed", [])),
            threat_model=raw.get("threat_model"),
            notes=list(raw.get("notes", [])),
        )

    @classmethod
    def from_json(cls, text: str) -> "EngagementState":
        raw = json.loads(text)
        if not isinstance(raw, dict):
            raise ValueError("Engagement state JSON must be a dict")
        return cls.from_dict(raw)
