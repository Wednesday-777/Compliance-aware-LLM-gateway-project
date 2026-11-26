import sqlite3

from app.audit import init_db, log_request, recent_entries, summary_stats


def test_log_and_read_back(tmp_path):
    db = str(tmp_path / "t.db")
    init_db(db)
    rid = log_request(
        outcome="allowed",
        pii_redacted=["PAN"],
        message_count=1,
        input_chars=20,
        latency_ms=5,
        path=db,
    )
    rows = recent_entries(10, path=db)
    assert len(rows) == 1
    assert rows[0]["request_id"] == rid
    assert rows[0]["pii_redacted"] == ["PAN"]
    assert rows[0]["outcome"] == "allowed"


def test_stats_counts(tmp_path):
    db = str(tmp_path / "t.db")
    init_db(db)
    log_request(outcome="allowed", pii_redacted=["EMAIL"], path=db)
    log_request(
        outcome="blocked", block_reason="pii_blocked", pii_blocked=["AADHAAR"], path=db
    )
    s = summary_stats(path=db)
    assert s["total_requests"] == 2
    assert s["blocked"] == 1
    assert s["block_reasons"] == {"pii_blocked": 1}
    assert s["pii_counts"] == {"EMAIL": 1, "AADHAAR": 1}


def test_log_never_stores_message_content(tmp_path):
    """Privacy by design: the table must have no column that could hold prompts."""
    db = str(tmp_path / "t.db")
    init_db(db)
    conn = sqlite3.connect(db)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(audit_log)")}
    conn.close()
    forbidden = {"content", "prompt", "text", "message", "messages", "reply"}
    assert columns.isdisjoint(forbidden)