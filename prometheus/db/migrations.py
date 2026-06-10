"""Prometheus SQLite migration framework.

Migrations run in place. They never wipe the live DB.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

Migration = Callable[[sqlite3.Connection], None]


def apply_prometheus_migrations(conn: sqlite3.Connection) -> list[int]:
    """Apply all pending migrations and return applied versions."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL
        )
        """
    )
    applied = {
        int(row[0])
        for row in conn.execute("SELECT version FROM schema_migrations").fetchall()
    }

    applied_now: list[int] = []
    for version, name, migration in _MIGRATIONS:
        if version in applied:
            continue
        with conn:
            migration(conn)
            conn.execute(
                "INSERT INTO schema_migrations(version, name, applied_at) VALUES (?, ?, ?)",
                (version, name, datetime.now(UTC).isoformat()),
            )
        applied_now.append(version)
    return applied_now


def _migration_001_candidate_lifecycle_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS finding_candidates (
            id TEXT PRIMARY KEY,
            domain TEXT NOT NULL,
            scan_id TEXT NOT NULL,
            source_tool TEXT NOT NULL,
            source_type TEXT NOT NULL,
            title TEXT NOT NULL,
            vuln_type TEXT NOT NULL,
            severity TEXT,
            confidence REAL,
            endpoint TEXT,
            method TEXT,
            parameter TEXT,
            auth_state TEXT,
            role TEXT,
            workflow_step TEXT,
            fingerprint TEXT NOT NULL,
            lifecycle_status TEXT NOT NULL,
            rejection_reason TEXT,
            raw_finding_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_finding_candidates_domain_fingerprint
            ON finding_candidates(domain, fingerprint);
        CREATE INDEX IF NOT EXISTS idx_finding_candidates_status
            ON finding_candidates(lifecycle_status);
        CREATE INDEX IF NOT EXISTS idx_finding_candidates_domain_status
            ON finding_candidates(domain, lifecycle_status);
        CREATE INDEX IF NOT EXISTS idx_finding_candidates_scan
            ON finding_candidates(scan_id);

        CREATE TABLE IF NOT EXISTS finding_evidence (
            id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL,
            evidence_kind TEXT NOT NULL,
            summary TEXT,
            path TEXT,
            inline_json TEXT,
            metadata_json TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(finding_id) REFERENCES finding_candidates(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_finding_evidence_finding
            ON finding_evidence(finding_id);
        CREATE INDEX IF NOT EXISTS idx_finding_evidence_kind
            ON finding_evidence(evidence_kind);

        CREATE TABLE IF NOT EXISTS validation_runs (
            id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL,
            validator TEXT NOT NULL,
            status TEXT NOT NULL,
            confidence REAL,
            output_json TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            FOREIGN KEY(finding_id) REFERENCES finding_candidates(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_validation_runs_finding
            ON validation_runs(finding_id);
        CREATE INDEX IF NOT EXISTS idx_validation_runs_status
            ON validation_runs(status);

        CREATE TABLE IF NOT EXISTS submission_artifacts (
            id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL,
            platform TEXT NOT NULL,
            artifact_type TEXT NOT NULL,
            version INTEGER NOT NULL,
            path TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(finding_id) REFERENCES finding_candidates(id) ON DELETE CASCADE,
            UNIQUE(finding_id, platform, artifact_type, version)
        );

        CREATE INDEX IF NOT EXISTS idx_submission_artifacts_finding
            ON submission_artifacts(finding_id);
        CREATE INDEX IF NOT EXISTS idx_submission_artifacts_kind
            ON submission_artifacts(platform, artifact_type);

        CREATE TABLE IF NOT EXISTS submission_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            from_status TEXT,
            to_status TEXT,
            actor TEXT NOT NULL,
            payload_json TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(finding_id) REFERENCES finding_candidates(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_submission_events_finding
            ON submission_events(finding_id);
        CREATE INDEX IF NOT EXISTS idx_submission_events_type
            ON submission_events(event_type);

        CREATE TABLE IF NOT EXISTS outcome_feedback_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_key TEXT NOT NULL UNIQUE,
            vuln_type TEXT,
            endpoint_pattern TEXT,
            outcome TEXT NOT NULL,
            rejection_hint TEXT,
            accepted_count INTEGER NOT NULL DEFAULT 0,
            rejected_count INTEGER NOT NULL DEFAULT 0,
            duplicate_count INTEGER NOT NULL DEFAULT 0,
            last_seen_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
    )
    _backfill_candidates_from_report_status(conn)


def _backfill_candidates_from_report_status(conn: sqlite3.Connection) -> None:
    rows = conn.execute("SELECT * FROM report_status").fetchall()
    now = datetime.now(UTC).isoformat()
    for row in rows:
        row_dict = _row_to_dict(row)
        raw_json = row_dict.get("full_finding_json") or json.dumps(row_dict, ensure_ascii=False, default=str)
        parsed = _json_or_empty(raw_json)
        report_id = row_dict.get("id")
        finding_id = f"report-{report_id}"
        fingerprint = str(row_dict.get("finding_hash") or finding_id)
        domain = str(row_dict.get("domain") or "unknown")
        title = str(row_dict.get("finding_title") or parsed.get("title") or "Untitled finding")
        status = _map_legacy_status(str(row_dict.get("status") or "new"))
        created_at = str(row_dict.get("created_at") or now)
        updated_at = str(row_dict.get("updated_at") or created_at)
        vuln_type = str(parsed.get("vuln_type") or parsed.get("type") or row_dict.get("cwe") or "unknown")
        method = parsed.get("method") or row_dict.get("method")

        conn.execute(
            """
            INSERT INTO finding_candidates (
                id, domain, scan_id, source_tool, source_type, title, vuln_type,
                severity, confidence, endpoint, method, parameter, auth_state,
                role, workflow_step, fingerprint, lifecycle_status,
                rejection_reason, raw_finding_json, created_at, updated_at, last_seen_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(domain, fingerprint) DO UPDATE SET
                last_seen_at = excluded.last_seen_at,
                updated_at = excluded.updated_at,
                raw_finding_json = excluded.raw_finding_json
            """,
            (
                finding_id,
                domain,
                str(row_dict.get("scan_id") or "legacy"),
                "report_status",
                "legacy_projection",
                title,
                vuln_type,
                row_dict.get("severity"),
                None,
                row_dict.get("endpoint") or parsed.get("endpoint"),
                method,
                parsed.get("parameter"),
                parsed.get("auth_state"),
                parsed.get("role"),
                parsed.get("workflow_step"),
                fingerprint,
                status,
                None,
                raw_json,
                created_at,
                updated_at,
                updated_at,
            ),
        )


def _row_to_dict(row: Any) -> dict[str, Any]:
    if hasattr(row, "keys"):
        return {key: row[key] for key in row.keys()}
    return dict(row)


def _json_or_empty(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def _map_legacy_status(status: str) -> str:
    return {
        "new": "needs_review",
        "reviewing": "needs_review",
        "needs_info": "needs_review",
        "dismissed": "archived",
        "revalidated": "verified",
    }.get(status, status if status else "needs_review")


def _migration_002_normalize_lifecycle_statuses(conn: sqlite3.Connection) -> None:
    conn.execute(
        "UPDATE finding_candidates SET lifecycle_status = 'rejected', rejection_reason = COALESCE(rejection_reason, 'informative outcome') WHERE lifecycle_status = 'informative'"
    )
    conn.execute(
        "UPDATE finding_candidates SET lifecycle_status = 'archived' WHERE lifecycle_status = 'superseded'"
    )
    conn.execute("UPDATE report_status SET status = 'rejected' WHERE status = 'informative'")
    conn.execute("UPDATE report_status SET status = 'archived' WHERE status = 'superseded'")


_MIGRATIONS: list[tuple[int, str, Migration]] = [
    (1, "candidate_lifecycle_tables", _migration_001_candidate_lifecycle_tables),
    (2, "normalize_lifecycle_statuses", _migration_002_normalize_lifecycle_statuses),
]
