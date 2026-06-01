"""Persistent cross-scan knowledge store backed by SQLite.

Stores facts discovered during scans so future scans against the same
domain can leverage prior knowledge.  Thread-safe singleton pattern —
one ``KnowledgeStore`` instance per process.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_VALID_CATEGORIES = frozenset(
    {
        "tech_stack",
        "endpoint",
        "auth_mechanism",
        "vulnerability",
        "failed_approach",
        "successful_technique",
    }
)

_DEFAULT_DB_PATH = Path.home() / ".prometheus" / "knowledge.db"

_instance: KnowledgeStore | None = None
_instance_lock = threading.Lock()


class KnowledgeStore:
    """SQLite-backed persistent knowledge store for cross-scan learning.

    Use the class-method ``KnowledgeStore()`` — the singleton pattern
    guarantees one connection per process.
    """

    def __new__(cls, db_path: Path | str | None = None) -> KnowledgeStore:
        global _instance  # noqa: PLW0603
        if _instance is not None:
            return _instance
        with _instance_lock:
            if _instance is not None:
                return _instance
            inst = super().__new__(cls)
            inst._init(db_path)  # type: ignore[attr-defined]
            _instance = inst
            return inst

    # ------------------------------------------------------------------
    # Internal init (called once)
    # ------------------------------------------------------------------

    def _init(self, db_path: Path | str | None = None) -> None:
        self._lock = threading.RLock()
        self._db_path = Path(db_path) if db_path else _DEFAULT_DB_PATH
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            str(self._db_path),
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._create_tables()
        self._migrate()
        logger.info("KnowledgeStore initialised at %s", self._db_path)

    def _create_tables(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS knowledge (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain     TEXT    NOT NULL,
                    category   TEXT    NOT NULL,
                    key        TEXT    NOT NULL,
                    value      TEXT    NOT NULL,
                    confidence REAL    NOT NULL DEFAULT 0.8,
                    source     TEXT    NOT NULL DEFAULT 'scan',
                    created_at TEXT    NOT NULL,
                    updated_at TEXT    NOT NULL,
                    scan_id    TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_knowledge_domain
                    ON knowledge(domain);
                CREATE INDEX IF NOT EXISTS idx_knowledge_domain_cat
                    ON knowledge(domain, category);
                CREATE INDEX IF NOT EXISTS idx_knowledge_key
                    ON knowledge(key);

                CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts
                    USING fts5(key, value, content=knowledge, content_rowid=id);

                -- Triggers to keep FTS in sync
                CREATE TRIGGER IF NOT EXISTS knowledge_ai AFTER INSERT ON knowledge BEGIN
                    INSERT INTO knowledge_fts(rowid, key, value)
                        VALUES (new.id, new.key, new.value);
                END;
                CREATE TRIGGER IF NOT EXISTS knowledge_ad AFTER DELETE ON knowledge BEGIN
                    INSERT INTO knowledge_fts(knowledge_fts, rowid, key, value)
                        VALUES ('delete', old.id, old.key, old.value);
                END;
                CREATE TRIGGER IF NOT EXISTS knowledge_au AFTER UPDATE ON knowledge BEGIN
                    INSERT INTO knowledge_fts(knowledge_fts, rowid, key, value)
                        VALUES ('delete', old.id, old.key, old.value);
                    INSERT INTO knowledge_fts(rowid, key, value)
                        VALUES (new.id, new.key, new.value);
                END;

                -- Target profiles: one row per domain, aggregated stats
                CREATE TABLE IF NOT EXISTS target_profiles (
                    domain          TEXT PRIMARY KEY,
                    scan_count      INTEGER NOT NULL DEFAULT 0,
                    total_findings  INTEGER NOT NULL DEFAULT 0,
                    critical_count  INTEGER NOT NULL DEFAULT 0,
                    high_count      INTEGER NOT NULL DEFAULT 0,
                    medium_count    INTEGER NOT NULL DEFAULT 0,
                    low_count       INTEGER NOT NULL DEFAULT 0,
                    info_count      INTEGER NOT NULL DEFAULT 0,
                    first_scan_at   TEXT,
                    last_scan_at    TEXT,
                    last_scan_id    TEXT,
                    last_status     TEXT,
                    notes           TEXT,
                    created_at      TEXT NOT NULL,
                    updated_at      TEXT NOT NULL
                );

                -- Scan history: one row per scan run per domain
                CREATE TABLE IF NOT EXISTS scan_history (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain          TEXT    NOT NULL,
                    scan_id         TEXT    NOT NULL,
                    started_at      TEXT    NOT NULL,
                    ended_at        TEXT,
                    status          TEXT    NOT NULL DEFAULT 'running',
                    scan_mode       TEXT,
                    finding_count   INTEGER NOT NULL DEFAULT 0,
                    critical_count  INTEGER NOT NULL DEFAULT 0,
                    high_count      INTEGER NOT NULL DEFAULT 0,
                    medium_count    INTEGER NOT NULL DEFAULT 0,
                    low_count       INTEGER NOT NULL DEFAULT 0,
                    info_count      INTEGER NOT NULL DEFAULT 0,
                    llm_requests    INTEGER,
                    total_tokens    INTEGER,
                    instruction     TEXT,
                    custom_headers  TEXT,
                    UNIQUE(domain, scan_id)
                );

                CREATE INDEX IF NOT EXISTS idx_scan_history_domain
                    ON scan_history(domain);
                CREATE INDEX IF NOT EXISTS idx_scan_history_scan_id
                    ON scan_history(scan_id);

                -- Report lifecycle tracking: one row per unique finding per domain
                CREATE TABLE IF NOT EXISTS report_status (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain          TEXT    NOT NULL,
                    scan_id         TEXT    NOT NULL,
                    finding_title   TEXT    NOT NULL,
                    finding_hash    TEXT    NOT NULL,
                    status          TEXT    NOT NULL DEFAULT 'new',
                    severity        TEXT,
                    cvss            REAL,
                    endpoint        TEXT,
                    cwe             TEXT,
                    platform        TEXT,
                    report_url      TEXT,
                    h1_report_id    TEXT,
                    notes           TEXT,
                    submitted_at    TEXT,
                    resolved_at     TEXT,
                    last_verified_at TEXT,
                    created_at      TEXT    NOT NULL,
                    updated_at      TEXT    NOT NULL,
                    UNIQUE(domain, finding_hash)
                );

                CREATE INDEX IF NOT EXISTS idx_report_status_domain
                    ON report_status(domain);
                CREATE INDEX IF NOT EXISTS idx_report_status_status
                    ON report_status(status);
                CREATE INDEX IF NOT EXISTS idx_report_status_hash
                    ON report_status(finding_hash);

                -- Finding comments timeline: multiple notes per finding
                CREATE TABLE IF NOT EXISTS finding_comments (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id      INTEGER NOT NULL REFERENCES report_status(id),
                    comment_type    TEXT    NOT NULL DEFAULT 'note',
                    content         TEXT    NOT NULL,
                    created_at      TEXT    NOT NULL,
                    version         INTEGER DEFAULT 1
                );

                CREATE INDEX IF NOT EXISTS idx_finding_comments_finding
                    ON finding_comments(finding_id);
                CREATE INDEX IF NOT EXISTS idx_finding_comments_type
                    ON finding_comments(comment_type);
                """
            )
            self._conn.commit()

    def _migrate(self) -> None:
        """Apply schema migrations for existing databases."""
        with self._lock:
            cols = [c[1] for c in self._conn.execute("PRAGMA table_info(report_status)").fetchall()]
            # Add last_verified_at column to report_status if missing
            if "last_verified_at" not in cols:
                self._conn.execute("ALTER TABLE report_status ADD COLUMN last_verified_at TEXT")
                self._conn.commit()
                logger.info("Migration: added last_verified_at column to report_status")
            # Add full_finding_json column for complete finding content
            if "full_finding_json" not in cols:
                self._conn.execute("ALTER TABLE report_status ADD COLUMN full_finding_json TEXT")
                self._conn.commit()
                logger.info("Migration: added full_finding_json column to report_status")

        # Migrate finding_comments table
        with self._lock:
            comment_cols = [c[1] for c in self._conn.execute("PRAGMA table_info(finding_comments)").fetchall()]
            if "version" not in comment_cols:
                self._conn.execute("ALTER TABLE finding_comments ADD COLUMN version INTEGER DEFAULT 1")
                self._conn.commit()
                logger.info("Migration: added version column to finding_comments")

        # Add active_h1_version to report_status
        with self._lock:
            cols = [c[1] for c in self._conn.execute("PRAGMA table_info(report_status)").fetchall()]
            if "active_h1_version" not in cols:
                self._conn.execute("ALTER TABLE report_status ADD COLUMN active_h1_version INTEGER")
                self._conn.commit()
                logger.info("Migration: added active_h1_version column to report_status")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def store(
        self,
        domain: str,
        category: str,
        key: str,
        value: str,
        confidence: float = 0.8,
        source: str = "scan",
        scan_id: str | None = None,
    ) -> dict[str, Any]:
        """Persist a knowledge entry.  Returns the new row id."""
        if category not in _VALID_CATEGORIES:
            return {
                "success": False,
                "error": (
                    f"Invalid category '{category}'. "
                    f"Must be one of: {', '.join(sorted(_VALID_CATEGORIES))}"
                ),
            }
        domain = self._domain_from_url(domain) or domain
        now = datetime.now(UTC).isoformat()
        with self._lock:
            cur = self._conn.execute(
                """
                INSERT INTO knowledge
                    (domain, category, key, value, confidence, source,
                     created_at, updated_at, scan_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (domain, category, key, value, confidence, source, now, now, scan_id),
            )
            self._conn.commit()
            row_id = cur.lastrowid
        logger.debug(
            "Stored knowledge id=%d domain=%s cat=%s key=%s",
            row_id, domain, category, key,
        )
        return {"success": True, "id": row_id}

    def query(
        self,
        domain: str,
        category: str | None = None,
        key: str | None = None,
    ) -> list[dict[str, Any]]:
        """Retrieve knowledge entries for *domain*, optionally filtered."""
        domain = self._domain_from_url(domain) or domain
        clauses = ["domain = ?"]
        params: list[Any] = [domain]
        if category is not None:
            clauses.append("category = ?")
            params.append(category)
        if key is not None:
            clauses.append("key = ?")
            params.append(key)
        sql = (
            "SELECT id, domain, category, key, value, confidence, "
            "source, created_at, updated_at, scan_id "
            "FROM knowledge WHERE " + " AND ".join(clauses) + " ORDER BY updated_at DESC"
        )
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def search(self, query_text: str) -> list[dict[str, Any]]:
        """Full-text search across key + value columns."""
        # Escape special FTS5 characters and build a safe query
        # Wrap each word in quotes to avoid syntax errors
        safe_query = " OR ".join(
            f'"{word}"' for word in query_text.split() if word
        )
        if not safe_query:
            return []
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT k.id, k.domain, k.category, k.key, k.value,
                       k.confidence, k.source, k.created_at, k.updated_at,
                       k.scan_id
                FROM knowledge_fts f
                JOIN knowledge k ON k.id = f.rowid
                WHERE knowledge_fts MATCH ?
                ORDER BY rank
                LIMIT 200
                """,
                (safe_query,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_domain_summary(self, domain: str) -> list[dict[str, Any]]:
        """Return all knowledge for a domain, grouped by category."""
        return self.query(domain)

    def update_confidence(self, entry_id: int, delta: float) -> dict[str, Any]:
        """Adjust confidence for an existing entry by *delta*.

        Clamps to [0.0, 1.0].
        """
        now = datetime.now(UTC).isoformat()
        with self._lock:
            row = self._conn.execute(
                "SELECT id, confidence FROM knowledge WHERE id = ?",
                (entry_id,),
            ).fetchone()
            if row is None:
                return {"success": False, "error": f"Entry id={entry_id} not found"}
            new_conf = max(0.0, min(1.0, row["confidence"] + delta))
            self._conn.execute(
                "UPDATE knowledge SET confidence = ?, updated_at = ? WHERE id = ?",
                (new_conf, now, entry_id),
            )
            self._conn.commit()
        return {"success": True, "id": entry_id, "confidence": new_conf}

    def expire_old(self, days: int = 90) -> dict[str, Any]:
        """Remove entries older than *days*."""
        cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM knowledge WHERE updated_at < ?", (cutoff,)
            )
            self._conn.commit()
            deleted = cur.rowcount
        logger.info("Expired %d knowledge entries older than %d days", deleted, days)
        return {"success": True, "deleted": deleted}

    def hydrate(self, domain: str) -> list[dict[str, Any]]:
        """Load existing knowledge for *domain* — called at scan start.

        Returns the entries so the caller can log them.
        """
        normalized = self._domain_from_url(domain) or domain
        entries = self.query(normalized)
        logger.info(
            "Hydrated %d knowledge entries for domain '%s' (normalized from '%s')",
            len(entries), normalized, domain,
        )
        return entries

    # ------------------------------------------------------------------
    # Target Profile API
    # ------------------------------------------------------------------

    @staticmethod
    def _domain_from_url(url: str) -> str:
        """Extract domain from a URL, stripping protocol, www, and path."""
        import re
        d = re.sub(r"^https?://", "", url.strip().lower())
        d = re.sub(r"^www\.", "", d)
        d = d.split("/")[0].split(":")[0]
        return d

    def record_scan_start(
        self,
        domain: str,
        scan_id: str,
        scan_mode: str = "deep",
        instruction: str = "",
        custom_headers: list[str] | None = None,
    ) -> dict[str, Any]:
        """Record that a scan has started for a domain. Creates profile if needed."""
        now = datetime.now(UTC).isoformat()
        domain = self._domain_from_url(domain)
        headers_json = json.dumps(custom_headers) if custom_headers else None
        with self._lock:
            # Upsert profile
            self._conn.execute(
                """
                INSERT INTO target_profiles
                    (domain, scan_count, first_scan_at, last_scan_at,
                     last_scan_id, last_status, created_at, updated_at)
                VALUES (?, 1, ?, ?, ?, 'running', ?, ?)
                ON CONFLICT(domain) DO UPDATE SET
                    scan_count = scan_count + 1,
                    last_scan_at = excluded.last_scan_at,
                    last_scan_id = excluded.last_scan_id,
                    last_status = 'running',
                    updated_at = excluded.updated_at
                """,
                (domain, now, now, scan_id, now, now),
            )
            # Insert scan history row
            self._conn.execute(
                """
                INSERT OR IGNORE INTO scan_history
                    (domain, scan_id, started_at, status, scan_mode,
                     instruction, custom_headers)
                VALUES (?, ?, ?, 'running', ?, ?, ?)
                """,
                (domain, scan_id, now, scan_mode, instruction, headers_json),
            )
            self._conn.commit()
        return {"success": True, "domain": domain, "scan_id": scan_id}

    def record_scan_end(
        self,
        domain: str,
        scan_id: str,
        status: str = "completed",
        findings: list[dict[str, Any]] | None = None,
        llm_requests: int | None = None,
        total_tokens: int | None = None,
    ) -> dict[str, Any]:
        """Record scan completion with finding counts. Updates profile totals."""
        now = datetime.now(UTC).isoformat()
        domain = self._domain_from_url(domain)

        # Count findings by severity
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        if findings:
            for f in findings:
                sev = str(f.get("severity", "info")).lower()
                if sev in counts:
                    counts[sev] += 1
                else:
                    counts["info"] += 1
        total = sum(counts.values())

        with self._lock:
            # Update scan history row
            self._conn.execute(
                """
                UPDATE scan_history SET
                    ended_at = ?, status = ?, finding_count = ?,
                    critical_count = ?, high_count = ?, medium_count = ?,
                    low_count = ?, info_count = ?,
                    llm_requests = ?, total_tokens = ?
                WHERE domain = ? AND scan_id = ?
                """,
                (
                    now, status, total,
                    counts["critical"], counts["high"], counts["medium"],
                    counts["low"], counts["info"],
                    llm_requests, total_tokens,
                    domain, scan_id,
                ),
            )
            # Recalculate profile totals from all scans
            row = self._conn.execute(
                """
                SELECT
                    COUNT(*) as scan_count,
                    SUM(finding_count) as total_findings,
                    SUM(critical_count) as critical_count,
                    SUM(high_count) as high_count,
                    SUM(medium_count) as medium_count,
                    SUM(low_count) as low_count,
                    SUM(info_count) as info_count
                FROM scan_history WHERE domain = ?
                """,
                (domain,),
            ).fetchone()
            if row:
                self._conn.execute(
                    """
                    UPDATE target_profiles SET
                        scan_count = ?, total_findings = ?,
                        critical_count = ?, high_count = ?, medium_count = ?,
                        low_count = ?, info_count = ?,
                        last_status = ?, updated_at = ?
                    WHERE domain = ?
                    """,
                    (
                        row["scan_count"], row["total_findings"] or 0,
                        row["critical_count"] or 0, row["high_count"] or 0,
                        row["medium_count"] or 0, row["low_count"] or 0,
                        row["info_count"] or 0,
                        status, now, domain,
                    ),
                )
            self._conn.commit()
        return {"success": True, "domain": domain, "total_findings": total}

    def get_target_profile(self, domain: str) -> dict[str, Any]:
        """Get full target profile: stats, scan history, consolidated knowledge."""
        domain = self._domain_from_url(domain)
        with self._lock:
            # Profile stats
            profile = self._conn.execute(
                "SELECT * FROM target_profiles WHERE domain = ?",
                (domain,),
            ).fetchone()

            if not profile:
                return {"exists": False, "domain": domain}

            # Scan history
            scans = self._conn.execute(
                """
                SELECT scan_id, started_at, ended_at, status, scan_mode,
                       finding_count, critical_count, high_count, medium_count,
                       low_count, info_count, llm_requests, total_tokens,
                       instruction
                FROM scan_history WHERE domain = ?
                ORDER BY started_at DESC
                """,
                (domain,),
            ).fetchall()

            # Knowledge summary by category
            knowledge = self._conn.execute(
                """
                SELECT category, key, value, confidence, source, scan_id
                FROM knowledge WHERE domain = ?
                ORDER BY category, updated_at DESC
                """,
                (domain,),
            ).fetchall()

            # Failed approaches (to avoid repeating)
            failed = self._conn.execute(
                """
                SELECT key, value, scan_id FROM knowledge
                WHERE domain = ? AND category = 'failed_approach'
                ORDER BY updated_at DESC LIMIT 10
                """,
                (domain,),
            ).fetchall()

            # Successful techniques
            success = self._conn.execute(
                """
                SELECT key, value, scan_id FROM knowledge
                WHERE domain = ? AND category = 'successful_technique'
                ORDER BY updated_at DESC LIMIT 10
                """,
                (domain,),
            ).fetchall()

        # Group knowledge by category
        knowledge_by_cat: dict[str, list[dict]] = {}
        for row in [dict(r) for r in knowledge]:
            cat = row["category"]
            knowledge_by_cat.setdefault(cat, []).append(row)

        return {
            "exists": True,
            "domain": domain,
            "profile": dict(profile),
            "scan_history": [dict(r) for r in scans],
            "knowledge_by_category": knowledge_by_cat,
            "failed_approaches": [dict(r) for r in failed],
            "successful_techniques": [dict(r) for r in success],
        }

    def list_profiles(self) -> list[dict[str, Any]]:
        """List all target profiles with summary stats."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT domain, scan_count, total_findings,
                       critical_count, high_count, medium_count,
                       first_scan_at, last_scan_at, last_status
                FROM target_profiles ORDER BY last_scan_at DESC
                """
            ).fetchall()
        return [dict(r) for r in rows]

    def get_scan_details(self, domain: str, scan_id: str) -> dict[str, Any] | None:
        """Get details for a specific scan run."""
        domain = self._domain_from_url(domain)
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM scan_history WHERE domain = ? AND scan_id = ?",
                (domain, scan_id),
            ).fetchone()
        return dict(row) if row else None

    def update_profile_notes(self, domain: str, notes: str) -> dict[str, Any]:
        """Update notes field on a target profile (manual annotations)."""
        domain = self._domain_from_url(domain)
        now = datetime.now(UTC).isoformat()
        with self._lock:
            self._conn.execute(
                "UPDATE target_profiles SET notes = ?, updated_at = ? WHERE domain = ?",
                (notes, now, domain),
            )
            self._conn.commit()
        return {"success": True, "domain": domain}

    # ------------------------------------------------------------------
    # Report Status API
    # ------------------------------------------------------------------

    @staticmethod
    def _finding_hash(title: str, endpoint: str = "") -> str:
        """Generate a stable hash for deduping findings across scans."""
        import hashlib
        raw = f"{title.strip().lower()}|{endpoint.strip().lower()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @staticmethod
    def _cwe_endpoint_hash(cwe: str, endpoint: str) -> str:
        """Generate hash for CWE+endpoint dedup layer."""
        import hashlib
        raw = f"{cwe.strip().lower()}|{endpoint.strip().lower()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def find_duplicate_finding(
        self,
        domain: str,
        finding_title: str,
        endpoint: str = "",
        cwe: str = "",
    ) -> dict[str, Any] | None:
        """Multi-layer duplicate detection (DefectDojo-style).

        Layer 1: Exact hash match (title + endpoint)
        Layer 2: CWE + endpoint match (same vuln class on same endpoint)
        Layer 3: Title similarity (fuzzy match on normalized title)

        Returns the existing finding if duplicate found, None otherwise.
        """
        domain = self._domain_from_url(domain) or domain

        with self._lock:
            # Layer 1: Exact hash match
            finding_hash = self._finding_hash(finding_title, endpoint)
            row = self._conn.execute(
                "SELECT * FROM report_status WHERE domain = ? AND finding_hash = ?",
                (domain, finding_hash),
            ).fetchone()
            if row:
                return {"layer": "exact_hash", "finding": dict(row)}

            # Layer 2: CWE + endpoint match
            if cwe and endpoint:
                cwe_hash = self._cwe_endpoint_hash(cwe, endpoint)
                row = self._conn.execute(
                    "SELECT * FROM report_status WHERE domain = ? AND cwe = ? AND endpoint = ?",
                    (domain, cwe, endpoint),
                ).fetchone()
                if row:
                    return {"layer": "cwe_endpoint", "finding": dict(row)}

            # Layer 3: Title similarity (normalized comparison)
            normalized_title = finding_title.strip().lower()
            # Remove common prefixes/suffixes that vary
            for prefix in ["missing ", "weak ", "insecure ", "exposed "]:
                if normalized_title.startswith(prefix):
                    normalized_title = normalized_title[len(prefix):]
            for suffix in [" header", " configuration", " vulnerability"]:
                if normalized_title.endswith(suffix):
                    normalized_title = normalized_title[:-len(suffix)]

            # Search for similar titles in the same domain
            rows = self._conn.execute(
                "SELECT * FROM report_status WHERE domain = ?",
                (domain,),
            ).fetchall()
            for row in rows:
                existing_title = (row["finding_title"] or "").strip().lower()
                for prefix in ["missing ", "weak ", "insecure ", "exposed "]:
                    if existing_title.startswith(prefix):
                        existing_title = existing_title[len(prefix):]
                for suffix in [" header", " configuration", " vulnerability"]:
                    if existing_title.endswith(suffix):
                        existing_title = existing_title[:-len(suffix)]

                # Check if normalized titles match
                if normalized_title == existing_title:
                    return {"layer": "title_similarity", "finding": dict(row)}

        return None

    def upsert_report_status(
        self,
        domain: str,
        scan_id: str,
        finding_title: str,
        status: str = "new",
        severity: str | None = None,
        cvss: float | None = None,
        endpoint: str | None = None,
        cwe: str | None = None,
        platform: str | None = None,
        report_url: str | None = None,
        h1_report_id: str | None = None,
        notes: str | None = None,
        full_finding_json: str | None = None,
    ) -> dict[str, Any]:
        """Create or update a report status entry.

        Uses (domain, finding_hash) as the dedup key — if a finding with
        the same title+endpoint already exists for this domain, it updates
        instead of duplicating.
        """
        domain = self._domain_from_url(domain) or domain
        finding_hash = self._finding_hash(finding_title, endpoint or "")
        now = datetime.now(UTC).isoformat()

        submitted_at = now if status == "submitted" else None
        resolved_at = now if status in ("accepted", "rejected") else None

        with self._lock:
            existing = self._conn.execute(
                "SELECT id, status FROM report_status WHERE domain = ? AND finding_hash = ?",
                (domain, finding_hash),
            ).fetchone()

            if existing:
                # Update existing — only overwrite fields that are provided
                sets = ["updated_at = ?"]
                params: list[Any] = [now]
                if status:
                    sets.append("status = ?")
                    params.append(status)
                if severity is not None:
                    sets.append("severity = ?")
                    params.append(severity)
                if cvss is not None:
                    sets.append("cvss = ?")
                    params.append(cvss)
                if endpoint is not None:
                    sets.append("endpoint = ?")
                    params.append(endpoint)
                if cwe is not None:
                    sets.append("cwe = ?")
                    params.append(cwe)
                if platform is not None:
                    sets.append("platform = ?")
                    params.append(platform)
                if report_url is not None:
                    sets.append("report_url = ?")
                    params.append(report_url)
                if h1_report_id is not None:
                    sets.append("h1_report_id = ?")
                    params.append(h1_report_id)
                if notes is not None:
                    sets.append("notes = ?")
                    params.append(notes)
                if full_finding_json is not None:
                    sets.append("full_finding_json = ?")
                    params.append(full_finding_json)
                if submitted_at:
                    sets.append("submitted_at = ?")
                    params.append(submitted_at)
                if resolved_at:
                    sets.append("resolved_at = ?")
                    params.append(resolved_at)

                params.extend([existing["id"]])
                sql = f"UPDATE report_status SET {', '.join(sets)} WHERE id = ?"
                self._conn.execute(sql, params)
                self._conn.commit()
                return {"success": True, "id": existing["id"], "action": "updated"}
            else:
                cur = self._conn.execute(
                    """
                    INSERT INTO report_status
                        (domain, scan_id, finding_title, finding_hash, status,
                         severity, cvss, endpoint, cwe, platform, report_url,
                         h1_report_id, notes, full_finding_json, submitted_at, resolved_at,
                         created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        domain, scan_id, finding_title, finding_hash, status,
                        severity, cvss, endpoint, cwe, platform, report_url,
                        h1_report_id, notes, full_finding_json, submitted_at, resolved_at, now, now,
                    ),
                )
                self._conn.commit()
                return {"success": True, "id": cur.lastrowid, "action": "created"}

    def get_report(
        self,
        domain: str,
        finding_title: str,
        endpoint: str = "",
    ) -> dict[str, Any] | None:
        """Get a single report status entry."""
        domain = self._domain_from_url(domain) or domain
        finding_hash = self._finding_hash(finding_title, endpoint)
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM report_status WHERE domain = ? AND finding_hash = ?",
                (domain, finding_hash),
            ).fetchone()
        return dict(row) if row else None

    def list_reports(
        self,
        domain: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        """List report statuses, optionally filtered by domain and/or status."""
        clauses = []
        params: list[Any] = []
        if domain:
            domain = self._domain_from_url(domain) or domain
            clauses.append("domain = ?")
            params.append(domain)
        if status:
            clauses.append("status = ?")
            params.append(status)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"""
            SELECT * FROM report_status {where}
            ORDER BY
                CASE status
                    WHEN 'new' THEN 0
                    WHEN 'reviewing' THEN 1
                    WHEN 'needs_info' THEN 2
                    WHEN 'submitted' THEN 3
                    WHEN 'accepted' THEN 4
                    WHEN 'rejected' THEN 5
                    ELSE 6
                END,
                updated_at DESC
        """
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def sync_scan_findings(
        self,
        domain: str,
        scan_id: str,
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Auto-register new findings from a scan into report_status.

        Called at scan end. Creates 'new' entries for findings that don't
        already exist. Returns count of new entries created.

        Does NOT overwrite status on existing findings — if a finding
        was already tracked (e.g. submitted, accepted), its status is preserved.
        """
        import json as _json

        created = 0
        for f in findings:
            title = f.get("title", "")
            if not title:
                continue

            # Serialize full finding content for storage
            try:
                full_json = _json.dumps(f, default=str, ensure_ascii=False)
            except Exception:
                full_json = None

            # Check if finding already exists
            finding_hash = self._finding_hash(title, f.get("endpoint", ""))
            domain_clean = self._domain_from_url(domain) or domain
            existing = self._conn.execute(
                "SELECT id, status FROM report_status WHERE domain = ? AND finding_hash = ?",
                (domain_clean, finding_hash),
            ).fetchone()

            if existing:
                # Finding already tracked — update metadata only, preserve status
                result = self.upsert_report_status(
                    domain=domain,
                    scan_id=scan_id,
                    finding_title=title,
                    status=existing["status"],  # Keep existing status
                    severity=f.get("severity"),
                    cvss=f.get("cvss"),
                    endpoint=f.get("endpoint"),
                    cwe=f.get("cwe"),
                    full_finding_json=full_json,
                )
                # Auto-log verification entry
                self.update_last_verified(existing["id"])
                self.add_comment(
                    finding_id=existing["id"],
                    content=f"Re-verified in scan {scan_id}. Still present.",
                    comment_type="verification",
                )
            else:
                # New finding — create with status "new"
                result = self.upsert_report_status(
                    domain=domain,
                    scan_id=scan_id,
                    finding_title=title,
                    status="new",
                    severity=f.get("severity"),
                    cvss=f.get("cvss"),
                    endpoint=f.get("endpoint"),
                    cwe=f.get("cwe"),
                    full_finding_json=full_json,
                )
                if result.get("action") == "created":
                    created += 1
        return {"success": True, "created": created, "total": len(findings)}

    # ------------------------------------------------------------------
    # Comment Timeline API
    # ------------------------------------------------------------------

    def add_comment(
        self,
        finding_id: int,
        content: str,
        comment_type: str = "note",
        version: int = 1,
    ) -> dict[str, Any]:
        """Add a comment to a finding's timeline.

        comment_type: note, evidence, verification, submission, status_change, h1_draft, validation
        version: version number for h1_draft comments (default 1)
        """
        now = datetime.now(UTC).isoformat()
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO finding_comments (finding_id, comment_type, content, created_at, version) VALUES (?, ?, ?, ?, ?)",
                (finding_id, comment_type, content, now, version),
            )
            self._conn.commit()
        return {"success": True, "id": cur.lastrowid, "created_at": now}

    def get_comments(
        self,
        finding_id: int,
    ) -> list[dict[str, Any]]:
        """Get all comments for a finding, ordered chronologically."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM finding_comments WHERE finding_id = ? ORDER BY created_at ASC",
                (finding_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def update_last_verified(
        self,
        finding_id: int,
    ) -> dict[str, Any]:
        """Update the last_verified_at timestamp for a finding."""
        now = datetime.now(UTC).isoformat()
        with self._lock:
            self._conn.execute(
                "UPDATE report_status SET last_verified_at = ?, updated_at = ? WHERE id = ?",
                (now, now, finding_id),
            )
            self._conn.commit()
        return {"success": True, "last_verified_at": now}

    def set_active_h1_version(
        self,
        finding_id: int,
        version: int,
    ) -> dict[str, Any]:
        """Set which H1 draft version is the 'active' (current) one."""
        with self._lock:
            self._conn.execute(
                "UPDATE report_status SET active_h1_version = ?, updated_at = ? WHERE id = ?",
                (version, datetime.now(UTC).isoformat(), finding_id),
            )
            self._conn.commit()
        return {"success": True, "active_h1_version": version}

    def get_active_h1_version(
        self,
        finding_id: int,
    ) -> int | None:
        """Get the active H1 version for a finding. Returns None if not set."""
        with self._lock:
            row = self._conn.execute(
                "SELECT active_h1_version FROM report_status WHERE id = ?",
                (finding_id,),
            ).fetchone()
        if row and row["active_h1_version"] is not None:
            return int(row["active_h1_version"])
        return None

    def get_latest_h1_draft(
        self,
        finding_id: int,
    ) -> dict[str, Any] | None:
        """Get the active (or latest) H1 draft for a finding."""
        # Try active version first
        active_ver = self.get_active_h1_version(finding_id)
        comments = self.get_comments(finding_id)
        h1_drafts = [c for c in comments if c.get("comment_type") == "h1_draft"]

        if not h1_drafts:
            return None

        if active_ver is not None:
            for draft in h1_drafts:
                if draft.get("version") == active_ver:
                    return draft

        # Fall back to latest
        return h1_drafts[-1]

    # ------------------------------------------------------------------
    # Finding Lifecycle Enhancements
    # ------------------------------------------------------------------

    def revalidate_findings(
        self,
        domain: str,
        new_cve_ids: list[str],
    ) -> list[dict[str, Any]]:
        """Check if existing findings for *domain* match any of *new_cve_ids*.

        Searches the ``full_finding_json``, ``finding_title``, and ``notes``
        columns for each CVE ID.  Matching findings have their status updated
        to ``'revalidated'`` and a comment is logged.

        Returns a list of revalidated findings.
        """
        domain = self._domain_from_url(domain) or domain
        now = datetime.now(UTC).isoformat()
        normalized_ids = [c.strip().upper() for c in new_cve_ids if c.strip()]
        if not normalized_ids:
            return []

        revalidated: list[dict[str, Any]] = []
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM report_status WHERE domain = ?",
                (domain,),
            ).fetchall()

            for row in rows:
                row_dict = dict(row)
                searchable = " ".join([
                    row_dict.get("finding_title", "") or "",
                    row_dict.get("notes", "") or "",
                    row_dict.get("full_finding_json", "") or "",
                ]).upper()

                matched_cve = None
                for cve_id in normalized_ids:
                    if cve_id in searchable:
                        matched_cve = cve_id
                        break

                if matched_cve:
                    self._conn.execute(
                        "UPDATE report_status SET status = 'revalidated', updated_at = ? WHERE id = ?",
                        (now, row_dict["id"]),
                    )
                    self.add_comment(
                        finding_id=row_dict["id"],
                        content=f"Revalidated: matched new CVE {matched_cve}",
                        comment_type="status_change",
                    )
                    row_dict["status"] = "revalidated"
                    row_dict["matched_cve"] = matched_cve
                    revalidated.append(row_dict)

            self._conn.commit()

        logger.info(
            "Revalidated %d findings for domain '%s' matching CVEs %s",
            len(revalidated), domain, normalized_ids,
        )
        return revalidated

    def get_findings_summary(
        self,
        domain: str | None = None,
    ) -> dict[str, Any]:
        """Return an aggregate summary of all tracked findings.

        If *domain* is given, the summary is scoped to that domain only.

        Returns::

            {
                "total": N,
                "by_status": {"new": N, "reviewing": N, ...},
                "by_severity": {"critical": N, "high": N, ...},
                "by_target": {"example.com": N, ...},
            }
        """
        clauses: list[str] = []
        params: list[Any] = []
        if domain:
            domain = self._domain_from_url(domain) or domain
            clauses.append("domain = ?")
            params.append(domain)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        with self._lock:
            # Total
            total = self._conn.execute(
                f"SELECT COUNT(*) as cnt FROM report_status {where}", params
            ).fetchone()["cnt"]

            # By status
            status_rows = self._conn.execute(
                f"SELECT status, COUNT(*) as cnt FROM report_status {where} GROUP BY status",
                params,
            ).fetchall()
            by_status: dict[str, int] = {}
            for r in status_rows:
                by_status[r["status"]] = r["cnt"]

            # By severity
            sev_rows = self._conn.execute(
                f"SELECT severity, COUNT(*) as cnt FROM report_status {where} GROUP BY severity",
                params,
            ).fetchall()
            by_severity: dict[str, int] = {}
            for r in sev_rows:
                key = r["severity"] or "unknown"
                by_severity[key] = r["cnt"]

            # By target domain
            target_rows = self._conn.execute(
                f"SELECT domain, COUNT(*) as cnt FROM report_status {where} GROUP BY domain",
                params,
            ).fetchall()
            by_target: dict[str, int] = {}
            for r in target_rows:
                by_target[r["domain"]] = r["cnt"]

        # Ensure all standard statuses appear in by_status even if zero
        for s in ("new", "reviewing", "submitted", "accepted", "rejected", "revalidated"):
            by_status.setdefault(s, 0)

        return {
            "total": total,
            "by_status": by_status,
            "by_severity": by_severity,
            "by_target": by_target,
        }

    def get_ready_to_submit(self) -> list[dict[str, Any]]:
        """Return findings with status ``'new'`` that have all required
        fields for a bug-bounty report submission.

        Required fields: ``finding_title``, ``severity``, ``endpoint``,
        ``cwe``, and ``full_finding_json`` (the full finding content).

        Returns a list of finding dicts.
        """
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM report_status
                WHERE status = 'new'
                  AND finding_title IS NOT NULL AND finding_title != ''
                  AND severity IS NOT NULL AND severity != ''
                  AND endpoint IS NOT NULL AND endpoint != ''
                  AND cwe IS NOT NULL AND cwe != ''
                  AND full_finding_json IS NOT NULL AND full_finding_json != ''
                ORDER BY
                    CASE severity
                        WHEN 'critical' THEN 0
                        WHEN 'high' THEN 1
                        WHEN 'medium' THEN 2
                        WHEN 'low' THEN 3
                        ELSE 4
                    END,
                    updated_at DESC
                """,
            ).fetchall()

        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Housekeeping
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the underlying connection (rarely needed)."""
        with self._lock:
            self._conn.close()
