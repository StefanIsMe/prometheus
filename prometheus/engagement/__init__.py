"""Engagement-folder filesystem for Prometheus.

Each engagement is a per-target folder under
``~/.prometheus/engagements/<domain>/`` that mirrors the CBH hunt-acme-bb
scaffold. A scan reads + writes to this folder instead of (or alongside)
the existing ``prometheus_runs/`` layout.

Layout
------

::

    ~/.prometheus/engagements/<domain>/
    ├── scope.md            # human-editable scope notes
    ├── scope.yaml          # machine-readable scope config (in/out_of_scope)
    ├── state.json          # atomic-saved engagement state
    ├── engine.log          # append-only log of engagement events
    ├── findings/           # per-finding markdown reports
    ├── evidence/           # per-finding evidence files
    └── runs/<run_id>/      # per-run artifacts (stages, recon, etc.)
        ├── stages/
        ├── recon/
        └── run_manifest.json
"""

from __future__ import annotations

from .manager import Engagement, EngagementExistsError, EngagementNotFoundError
from .scope import Scope
from .state import EngagementState, SurfaceSet

__all__ = [
    "Engagement",
    "EngagementExistsError",
    "EngagementNotFoundError",
    "EngagementState",
    "Scope",
    "SurfaceSet",
]
