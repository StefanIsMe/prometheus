"""Tests for hypothesis driven novel threat discovery."""

from __future__ import annotations

from prometheus.core.hypotheses import (
    DifficultyFactors,
    HypothesisManager,
    calculate_task_difficulty,
)


def test_hypothesis_lifecycle_persistence_and_report_gate(tmp_path):
    manager = HypothesisManager(tmp_path)

    hypothesis = manager.create_hypothesis(
        target_id="https://example.com",
        endpoint="/api/orders/123",
        method="GET",
        parameter="order_id",
        auth_state="authenticated",
        role="customer",
        workflow_step="order detail view",
        vulnerability_class="idor",
        exploit_goal="read another customer's order",
        oracle="HTTP 200 response contains a different customer's order data",
        preconditions=["two customer accounts exist"],
        payload_family="identifier swap",
        source="differential_response",
    )

    assert hypothesis.id
    assert hypothesis.status == "new"
    assert hypothesis.oracle.startswith("HTTP 200")

    first_gate = manager.report_gate(hypothesis.id)
    assert not first_gate.allowed
    assert "two positive controls" in " ".join(first_gate.missing)
    assert "negative control" in " ".join(first_gate.missing)

    manager.record_evidence(
        hypothesis.id,
        evidence_type="positive_control",
        summary="customer A requested /api/orders/124 and received customer B order JSON",
        request={"method": "GET", "path": "/api/orders/124"},
        response_fingerprint={"status_code": 200, "body_hash": "abc", "body_length": 441},
        control_passed=True,
    )
    manager.record_evidence(
        hypothesis.id,
        evidence_type="positive_control",
        summary="repeat request returned same unauthorized order JSON",
        request={"method": "GET", "path": "/api/orders/124"},
        response_fingerprint={"status_code": 200, "body_hash": "abc", "body_length": 441},
        control_passed=True,
    )
    manager.record_evidence(
        hypothesis.id,
        evidence_type="negative_control",
        summary="logged out request returned 401 and no order body",
        request={"method": "GET", "path": "/api/orders/124"},
        response_fingerprint={"status_code": 401, "body_hash": "def", "body_length": 28},
        control_passed=True,
    )
    manager.mark_status(hypothesis.id, "validated")

    final_gate = manager.report_gate(hypothesis.id)
    assert final_gate.allowed
    assert final_gate.positive_controls == 2
    assert final_gate.negative_controls == 1

    reloaded = HypothesisManager(tmp_path)
    reloaded.load()
    loaded = reloaded.get_hypothesis(hypothesis.id)
    assert loaded is not None
    assert loaded.status == "validated"
    assert len(loaded.evidence) == 3


def test_task_difficulty_and_selection_prefers_strong_evidence_with_manageable_difficulty(tmp_path):
    manager = HypothesisManager(tmp_path)

    easy = manager.create_hypothesis(
        target_id="example.com",
        endpoint="/api/profile",
        method="GET",
        parameter="id",
        auth_state="authenticated",
        role="user",
        workflow_step="profile view",
        vulnerability_class="idor",
        exploit_goal="read another profile",
        oracle="different id returns another profile",
        evidence_score=0.8,
        exploitability_score=0.9,
        difficulty_score=0.3,
        novelty_score=0.7,
    )
    rabbit_hole = manager.create_hypothesis(
        target_id="example.com",
        endpoint="/oauth/callback",
        method="GET",
        parameter="code",
        auth_state="oauth_partial",
        role="user",
        workflow_step="oauth callback",
        vulnerability_class="oauth",
        exploit_goal="steal authorization code",
        oracle="attacker receives victim code",
        evidence_score=0.2,
        exploitability_score=0.8,
        difficulty_score=0.9,
        novelty_score=0.9,
    )

    selected = manager.select_next_hypothesis()
    assert selected is not None
    assert selected.id == easy.id
    assert selected.id != rabbit_hole.id

    difficulty = calculate_task_difficulty(
        DifficultyFactors(
            horizon=0.5,
            unknowns=0.4,
            context_load=0.2,
            state_complexity=0.6,
            tool_risk=0.1,
        ),
    )
    assert difficulty == 0.39
