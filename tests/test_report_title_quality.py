"""Tests for the title-quality gate on create_vulnerability_report.

The launchdarkly scan that produced 0 vulns logged nine reports for one
underlying finding, plus five placeholder titles ("test", "Test",
"Test GraphQL finding", "Test target=https://example.com"). The
existing placeholder-pattern list only covered full-sentence filler in
body fields, not bare titles, and had no rule against scratch hosts
(example.com / localhost).

These tests pin down the new ``_validate_title_quality`` behaviour.
"""

from __future__ import annotations

import sys
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[1]
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from prometheus.tools.reporting.tool import _validate_title_quality  # noqa: E402


# ---------------------------------------------------------------------------
# Placeholder titles
# ---------------------------------------------------------------------------


def test_bare_test_is_rejected():
    err = _validate_title_quality("test", "https://app.example.com")
    assert err is not None
    assert "placeholder" in err.lower()


def test_bare_test_with_punctuation_is_rejected():
    for t in ("Test", "test.", "Test.", "tests", "testing"):
        err = _validate_title_quality(t, "https://app.example.com")
        assert err is not None, f"expected reject for {t!r}"


def test_test_prefix_is_rejected():
    for t in (
        "Test: SQL Injection",
        "Test - CORS Misconfiguration",
        "Test_XSS",
        "Fuzz: path traversal",
        "Sample: open redirect",
        "Example: missing CSP header",
    ):
        err = _validate_title_quality(t, "https://app.example.com")
        assert err is not None, f"expected reject for {t!r}"


def test_real_title_passes():
    err = _validate_title_quality(
        "Unauthenticated GraphQL Introspection Discloses Full Schema",
        "https://pri.observability.app.launchdarkly.com/",
    )
    assert err is None


# ---------------------------------------------------------------------------
# Scratch-host leakage
# ---------------------------------------------------------------------------


def test_example_com_target_is_rejected():
    """The LLM filed a 'Test target=https://example.com' report. Block."""
    err = _validate_title_quality(
        "SQL Injection in /api/users login parameter",
        "https://example.com/",
    )
    assert err is not None
    assert "example.com" in err


def test_example_com_in_title_is_rejected():
    """The LLM filed a 'XSS at https://example.com' report. Block.

    Note: we deliberately don't start the title with 'Test:' here —
    the placeholder-prefix rule fires first and would return a
    different message. The host-leak rule is the second gate.
    """
    err = _validate_title_quality(
        "XSS at https://example.com reflects user input",
        "https://app.launchdarkly.com/",
    )
    assert err is not None
    assert "example.com" in err


def test_localhost_target_is_rejected():
    err = _validate_title_quality(
        "IDOR on /api/orders/{id}",
        "http://localhost:8080/api/orders/1",
    )
    assert err is not None
    assert "localhost" in err


def test_loopback_ip_target_is_rejected():
    err = _validate_title_quality(
        "Auth bypass on /admin",
        "http://127.0.0.1:9000/admin",
    )
    assert err is not None
    assert "127.0.0.1" in err


def test_in_scope_target_passes_host_check():
    err = _validate_title_quality(
        "SQL Injection in /api/users login parameter",
        "https://app.launchdarkly.com/",
    )
    assert err is None


# ---------------------------------------------------------------------------
# Vulnerability noun requirement
# ---------------------------------------------------------------------------


def test_long_title_without_vuln_noun_is_rejected():
    err = _validate_title_quality(
        "Found something interesting while clicking around the dashboard",
        "https://app.launchdarkly.com/",
    )
    assert err is not None
    assert "vulnerability noun" in err.lower()


def test_short_title_without_noun_passes():
    """CVE-style shorthand (e.g. 'CVE-2024-1234') has no vuln noun but is
    short enough that it doesn't look like a description sneaked into the
    title slot."""
    err = _validate_title_quality("CVE-2024-50312", "https://app.launchdarkly.com/")
    assert err is None


def test_each_common_noun_class_is_recognised():
    """Sanity check: every noun in the canonical class list is matched
    by the regex. Locks the list down so adding/removing nouns is a
    conscious change.

    Targets are real in-scope domains — never example.com, since the
    scratch-host check is its own gate and would short-circuit these.
    """
    samples = [
        ("SQL Injection on /login endpoint", "https://app.example.com"),
        ("Stored XSS in profile page", "https://app.example.com"),
        ("CSRF on email change form", "https://app.example.com"),
        ("SSRF via image proxy URL parameter", "https://app.example.com"),
        ("IDOR allows reading other users' orders", "https://app.example.com"),
        ("Remote Code Execution via deserialization", "https://app.example.com"),
        ("Authentication bypass on admin endpoint", "https://app.example.com"),
        ("PII disclosure in API response body", "https://app.example.com"),
        ("Information exposure via verbose error page", "https://app.example.com"),
        ("Path traversal in file download parameter", "https://app.example.com"),
        ("Unrestricted file upload on avatar endpoint", "https://app.example.com"),
        ("Open redirect via return_url parameter", "https://app.example.com"),
        ("Privilege escalation via role parameter", "https://app.example.com"),
        ("Insecure deserialization of cookie payload", "https://app.example.com"),
        ("CORS misconfiguration exposes API key header", "https://app.example.com"),
        ("Missing CSP header allows script injection", "https://app.example.com"),
        ("Session token leaked in referrer header", "https://app.example.com"),
        ("Hardcoded credentials leak in source repo", "https://app.example.com"),
    ]
    for title, target in samples:
        err = _validate_title_quality(title, target)
        assert err is None, f"expected accept for {title!r}, got {err!r}"


def test_combined_test_prefix_and_example_host_yields_one_rejection():
    """A title that trips multiple rules gets one rejection — the first
    matching rule. Test-prefix is checked before host leakage so the
    agent sees the most actionable message."""
    err = _validate_title_quality(
        "Test: SQL Injection",
        "https://example.com/",
    )
    assert err is not None
    # Whichever rule fired, the message must mention either 'placeholder'
    # or 'example.com' — the agent gets a clear next action either way.
    assert "placeholder" in err.lower() or "example.com" in err.lower()
