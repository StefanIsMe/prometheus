"""Tests for extended coverage and report validation gates."""

from __future__ import annotations

from prometheus.tools.coverage.tool import CoverageTracker
from prometheus.tools.reporting.tool import _validate_report_control_gate


def test_coverage_tracker_records_input_role_and_workflow_dimensions(tmp_path):
    tracker = CoverageTracker(tmp_path)

    tracker.register_test(
        endpoint="/api/orders/123",
        vuln_type="idor",
        status="tested_clean",
        method="GET",
        parameter="order_id",
        role="customer",
        auth_state="authenticated",
        workflow_step="order detail view",
        notes="swapped order_id between two owned accounts",
    )

    entries = tracker.all_entries()
    assert len(entries) == 1
    entry = entries[0]
    assert entry["method"] == "GET"
    assert entry["parameter"] == "order_id"
    assert entry["role"] == "customer"
    assert entry["auth_state"] == "authenticated"
    assert entry["workflow_step"] == "order detail view"

    tracker.persist()
    reloaded = CoverageTracker(tmp_path)
    reloaded.load()
    loaded = reloaded.all_entries()[0]
    assert loaded["parameter"] == "order_id"
    assert loaded["workflow_step"] == "order detail view"


def test_report_control_gate_requires_validated_hypothesis_or_controls():
    no_controls = _validate_report_control_gate(
        hypothesis_id=None,
        positive_controls=None,
        negative_controls=None,
        validation_agent_id=None,
    )
    assert no_controls
    assert any("validated hypothesis" in err for err in no_controls)

    ok_controls = _validate_report_control_gate(
        hypothesis_id=None,
        positive_controls=[
            {"summary": "first exploit run returned another user record", "passed": True},
            {
                "summary": "second exploit run reproduced the same unauthorized record",
                "passed": True,
            },
        ],
        negative_controls=[{"summary": "logged out request returned 401", "passed": True}],
        validation_agent_id="agent-1234",
    )
    assert ok_controls == []
