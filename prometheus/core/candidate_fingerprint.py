"""Deterministic finding fingerprints."""

from __future__ import annotations

import hashlib
import re
from typing import Any


def normalize_token(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"https?://", "", text)
    text = re.sub(r"^www\.", "", text)
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"/[0-9a-f]{16,}(?=/|$)", "/{hex}", text)
    text = re.sub(r"/\d+(?=/|$)", "/{id}", text)
    return text[:500]


def fingerprint_candidate(
    *,
    domain: str,
    vuln_type: str,
    title: str,
    endpoint: str | None = None,
    method: str | None = None,
    parameter: str | None = None,
    auth_state: str | None = None,
    role: str | None = None,
) -> str:
    parts = [
        normalize_token(domain),
        normalize_token(vuln_type),
        normalize_token(method or "GET"),
        normalize_token(endpoint or title),
        normalize_token(parameter),
        normalize_token(auth_state),
        normalize_token(role),
    ]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
