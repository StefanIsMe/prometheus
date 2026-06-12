"""
Test for the REVIEW escalation heuristic.

Regression test for the withapurpose.co incident where prometheus
classified `/data/dashboard-data.json` as 'reconnaissance-only exposure'
(info) when it should have been P3 (internal field name disclosure) and
chained with `/markdown/../data/dashboard-data.json` to P2.

Verifies that action_review's severity_recommendation matches the
heuristic for these inputs.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import prom_rl_loop  # type: ignore[import-not-found]


def _make_run_dir(tmp_path: Path, name: str, report_text: str) -> Path:
    rd = tmp_path / name
    rd.mkdir()
    (rd / "run.json").write_text(json.dumps({
        "run_id": name,
        "status": "completed",
        "findings": [],
    }))
    (rd / "penetration_test_report.md").write_text(report_text)
    return rd


def test_escalation_internal_fields_only(tmp_path, monkeypatch):
    """Internal field names present, no traversal → P3 / medium."""
    rd = _make_run_dir(
        tmp_path, "test-internal",
        "# Report\nFound /data/dashboard-data.json exposing "
        "linkedin.briefs_pending, articles_ready, posts_total — "
        "internal business logic state.\n",
    )
    marker = tmp_path / "complete.json"
    marker.write_text(json.dumps({
        "scan_id": "test-internal",
        "target": "withapurpose",
        "target_name": "withapurpose",
        "findings_count": 0,
        "run_dir": str(rd),
    }))
    archive = tmp_path / "archive.json"
    monkeypatch.setattr(prom_rl_loop, "SCAN_COMPLETE", marker)
    monkeypatch.setattr(prom_rl_loop, "SCAN_COMPLETE_ARCHIVE", archive)
    result = prom_rl_loop.action_review({})
    assert result["action"] == "REVIEW"
    assert "sev=medium" in result["result"]
    assert result["score"] >= 0.6


def test_escalation_path_traversal_only(tmp_path, monkeypatch):
    """Path traversal present, no internal fields → P3 / medium."""
    rd = _make_run_dir(
        tmp_path, "test-traversal",
        "# Report\nThe /markdown/../data/dashboard-data.json path "
        "normalization quirk allows path traversal to public resources.\n",
    )
    marker = tmp_path / "complete.json"
    marker.write_text(json.dumps({
        "scan_id": "test-traversal",
        "target": "withapurpose",
        "target_name": "withapurpose",
        "findings_count": 0,
        "run_dir": str(rd),
    }))
    archive = tmp_path / "archive.json"
    monkeypatch.setattr(prom_rl_loop, "SCAN_COMPLETE", marker)
    monkeypatch.setattr(prom_rl_loop, "SCAN_COMPLETE_ARCHIVE", archive)
    result = prom_rl_loop.action_review({})
    assert "sev=medium" in result["result"]


def test_escalation_chained_high(tmp_path, monkeypatch):
    """Internal fields AND path traversal → P2 / high (chained)."""
    rd = _make_run_dir(
        tmp_path, "test-chained",
        "# Report\nFound /data/dashboard-data.json exposing "
        "linkedin.briefs_pending. Also /markdown/../data/dashboard-data.json "
        "path traversal resolves to the same internal resource — chained.\n",
    )
    marker = tmp_path / "complete.json"
    marker.write_text(json.dumps({
        "scan_id": "test-chained",
        "target": "withapurpose",
        "target_name": "withapurpose",
        "findings_count": 0,
        "run_dir": str(rd),
    }))
    archive = tmp_path / "archive.json"
    monkeypatch.setattr(prom_rl_loop, "SCAN_COMPLETE", marker)
    monkeypatch.setattr(prom_rl_loop, "SCAN_COMPLETE_ARCHIVE", archive)
    # Triage file is written to /tmp, not tmp_path — clean any prior copy
    import os
    triage_path = "/tmp/prom-rl-review-test-chained.json"
    if os.path.exists(triage_path):
        os.unlink(triage_path)
    result = prom_rl_loop.action_review({})
    assert "sev=high" in result["result"]
    assert result["score"] >= 0.9
    assert os.path.exists(triage_path), f"triage file not written at {triage_path}"


def test_escalation_clean_run_no_flags(tmp_path, monkeypatch):
    """No internal fields, no traversal, no info disclosure → none / 0."""
    rd = _make_run_dir(
        tmp_path, "test-clean",
        "# Report\nAll endpoints behave as expected. No issues found.\n",
    )
    marker = tmp_path / "complete.json"
    marker.write_text(json.dumps({
        "scan_id": "test-clean",
        "target": "cleanapp",
        "target_name": "CleanApp",
        "findings_count": 0,
        "run_dir": str(rd),
    }))
    archive = tmp_path / "archive.json"
    monkeypatch.setattr(prom_rl_loop, "SCAN_COMPLETE", marker)
    monkeypatch.setattr(prom_rl_loop, "SCAN_COMPLETE_ARCHIVE", archive)
    result = prom_rl_loop.action_review({})
    assert "sev=none" in result["result"]
    assert result["score"] == 0.0


def test_triage_file_shape(tmp_path, monkeypatch):
    """Triage JSON written for every REVIEW should have these keys."""
    rd = _make_run_dir(tmp_path, "test-shape", "# nothing")
    marker = tmp_path / "complete.json"
    marker.write_text(json.dumps({
        "scan_id": "test-shape",
        "target": "x",
        "target_name": "X",
        "findings_count": 0,
        "run_dir": str(rd),
    }))
    archive = tmp_path / "archive.json"
    monkeypatch.setattr(prom_rl_loop, "SCAN_COMPLETE", marker)
    monkeypatch.setattr(prom_rl_loop, "SCAN_COMPLETE_ARCHIVE", archive)
    # Triage file is written to /tmp, not tmp_path — read it from there
    import os
    if os.path.exists("/tmp/prom-rl-review-test-shape.json"):
        os.unlink("/tmp/prom-rl-review-test-shape.json")
    prom_rl_loop.action_review({})
    triage = json.loads(Path("/tmp/prom-rl-review-test-shape.json").read_text())
    for k in ("scan_id", "target", "run_dir", "raw_findings_count",
              "parsed_findings_count", "severity_recommendation",
              "chain_potential", "heuristic_flags"):
        assert k in triage, f"missing key: {k}"
