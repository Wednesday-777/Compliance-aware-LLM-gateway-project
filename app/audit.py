import json
import logging
import os
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timezone

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("gateway.audit")


DB_PATH = os.getenv("AUDIT_DB_PATH", "audit.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    outcome TEXT NOT NULL,
    block_reason TEXT,
    pii_redacted TEXT NOT NULL DEFAULT '[]',
    pii_allowed TEXT NOT NULL DEFAULT '[]',
    pii_blocked TEXT NOT NULL DEFAULT '[]',
    injection_score INTEGER NOT NULL DEFAULT 0,
    injection_rules TEXT NOT NULL DEFAULT '[]',
    injection_flagged INTEGER NOT NULL DEFAULT 0,
    message_count INTEGER NOT NULL DEFAULT 0,
    input_chars INTEGER NOT NULL DEFAULT 0,
    latency_ms INTEGER NOT NULL DEFAULT 0,
    model TEXT,
    client TEXT
)
"""

JSON_COLUMNS = ("pii_redacted", "pii_allowed", "pii_blocked", "injection_rules")


def _connect(path=None):
    conn = sqlite3.connect(path or DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(path=None) -> None:
    
    with closing(_connect(path)) as conn, conn:
        conn.execute(SCHEMA)
        existing = {row[1] for row in conn.execute("PRAGMA table_info(audit_log)")}
        if "client" not in existing:  # migrate a database created before Phase 6
            conn.execute("ALTER TABLE audit_log ADD COLUMN client TEXT")


def log_request(
    *,
    outcome: str,
    block_reason: str | None = None,
    pii_redacted=(),
    pii_allowed=(),
    pii_blocked=(),
    injection_score: int = 0,
    injection_rules=(),
    injection_flagged: bool = False,
    message_count: int = 0,
    input_chars: int = 0,
    latency_ms: int = 0,
    model: str | None = None,
    client: str | None = None,
    path=None,
) -> str:
    """Record metadata about one request. Returns its request_id."""
    request_id = str(uuid.uuid4())
    try:
        with closing(_connect(path)) as conn, conn:
            conn.execute(
                "INSERT INTO audit_log (request_id, timestamp, outcome, block_reason, "
                "pii_redacted, pii_allowed, pii_blocked, injection_score, injection_rules, "
                "injection_flagged, message_count, input_chars, latency_ms, model, client) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    request_id,
                    datetime.now(timezone.utc).isoformat(),
                    outcome,
                    block_reason,
                    json.dumps(sorted(pii_redacted)),
                    json.dumps(sorted(pii_allowed)),
                    json.dumps(sorted(pii_blocked)),
                    injection_score,
                    json.dumps(sorted(injection_rules)),
                    int(injection_flagged),
                    message_count,
                    input_chars,
                    latency_ms,
                    model,
                    client,
                ),
            )
    except sqlite3.Error:
        
        logger.exception("Failed to write audit log entry")
    return request_id


def _row_to_dict(row) -> dict:
    d = dict(row)
    for col in JSON_COLUMNS:
        d[col] = json.loads(d[col])
    d["injection_flagged"] = bool(d["injection_flagged"])
    return d


def recent_entries(limit: int = 50, path=None) -> list[dict]:
    with closing(_connect(path)) as conn:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def summary_stats(path=None) -> dict:
    with closing(_connect(path)) as conn:
        total = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        blocked = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE outcome = 'blocked'"
        ).fetchone()[0]
        reasons = conn.execute(
            "SELECT block_reason, COUNT(*) FROM audit_log "
            "WHERE outcome = 'blocked' GROUP BY block_reason"
        ).fetchall()
        outcomes = conn.execute(
            "SELECT outcome, COUNT(*) FROM audit_log GROUP BY outcome"
        ).fetchall()
        clients = conn.execute(
            "SELECT COALESCE(client, 'unknown'), COUNT(*) FROM audit_log GROUP BY client"
        ).fetchall()
        pii_rows = conn.execute(
            "SELECT pii_redacted, pii_blocked FROM audit_log"
        ).fetchall()

    pii_counts: dict = {}
    for row in pii_rows:
        for col in ("pii_redacted", "pii_blocked"):
            for pii_type in json.loads(row[col]):
                pii_counts[pii_type] = pii_counts.get(pii_type, 0) + 1

    return {
        "total_requests": total,
        "blocked": blocked,
        "block_reasons": {r[0]: r[1] for r in reasons},
        "outcomes": {r[0]: r[1] for r in outcomes},
        "by_client": {r[0]: r[1] for r in clients},
        "pii_counts": pii_counts,
    }