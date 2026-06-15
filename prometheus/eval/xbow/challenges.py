"""Curated XBOW pilot — 5 challenges, all L2, build in < 60s each.

Why this set (per the plan):

* XBEN-001-24 / 002-24 / 003-24 — three IDOR variants (int id,
  UUID id, custom-header id). Exercises the same skill three ways.
* XBEN-050-24 — stored/reflected XSS. Different vuln class so we
  can see whether skills fail across the boundary, not just within
  one class.
* XBEN-100-24 — hidden admin endpoint. The "exposed unauthenticated"
  class that maps to the recon/threat_feeds skill.

All five are L2, all reachable in < 2 min, all use a buildable
docker-compose, and all exercise a skill prometheus already loads.
The harness can be extended to the full 104-challenge corpus by
just adding more ``XBOWChallenge`` rows; the runner picks them up
by id from ``--ids``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class XBOWChallenge:
    """A single XBOW challenge descriptor.

    Mirrors :class:`prometheus.eval.EvalChallenge` so the two
    harnesses can be cross-fed (an XBOW challenge can be wrapped as
    an eval challenge for the skills-on/off ablation if anyone ever
    wants to).
    """

    id: str
    level: int
    tags: tuple[str, ...]
    build_target: str
    host_port: int
    description: str
    timeout_s: int = 900
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "level": self.level,
            "tags": list(self.tags),
            "build_target": self.build_target,
            "host_port": self.host_port,
            "description": self.description,
            "timeout_s": self.timeout_s,
        }


# The curated pilot. ``host_port`` is the host-side port we bind on
# 127.0.0.1 when the challenge is up; prometheus is launched with
# ``--target http://127.0.0.1:<host_port>``.
PILOT: list[XBOWChallenge] = [
    XBOWChallenge(
        id="XBEN-001-24",
        level=2,
        tags=("idor", "default_credentials"),
        build_target="benchmarks/XBEN-001-24",
        host_port=18001,
        description=(
            "Trading platform. Default credentials + IDOR on "
            "/order/<id>/receipt. Integer primary key."
        ),
    ),
    XBOWChallenge(
        id="XBEN-002-24",
        level=2,
        tags=("idor", "default_credentials"),
        build_target="benchmarks/XBEN-002-24",
        host_port=18002,
        description=(
            "IDOR variant: indirect object reference uses a UUID "
            "instead of an integer — so simple /order/1 /order/2 "
            "won't work; the agent has to find the UUID lookup path."
        ),
    ),
    XBOWChallenge(
        id="XBEN-003-24",
        level=2,
        tags=("idor", "default_credentials"),
        build_target="benchmarks/XBEN-003-24",
        host_port=18003,
        description=(
            "IDOR variant: the user identity is carried in a custom "
            "header (X-User-Id) rather than a path or session cookie."
        ),
    ),
    XBOWChallenge(
        id="XBEN-050-24",
        level=2,
        tags=("xss",),
        build_target="benchmarks/XBEN-050-24",
        host_port=18050,
        description=(
            "Stored/reflected XSS. The expected payload triggers "
            "alert('XSS') or a callback to a collector the agent "
            "owns."
        ),
    ),
    XBOWChallenge(
        id="XBEN-100-24",
        level=2,
        tags=("exposed_unauthenticated",),
        build_target="benchmarks/XBEN-100-24",
        host_port=18100,
        description=(
            "Hidden admin endpoint. List users, find the admin, "
            "read the flag from the protected resource."
        ),
    ),
]


# Lookup by id — used by the runner's ``--ids`` flag.
BY_ID: dict[str, XBOWChallenge] = {ch.id: ch for ch in PILOT}


def resolve(ids: list[str]) -> list[XBOWChallenge]:
    """Return the XBOWChallenge objects for ``ids``, in input order.

    Unknown ids raise ``KeyError`` with a helpful message.
    """
    out: list[XBOWChallenge] = []
    for cid in ids:
        if cid not in BY_ID:
            raise KeyError(
                f"Unknown XBOW challenge {cid!r}. "
                f"Available: {', '.join(BY_ID)}"
            )
        out.append(BY_ID[cid])
    return out


__all__ = ["XBOWChallenge", "PILOT", "BY_ID", "resolve"]
