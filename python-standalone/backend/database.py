"""SQLite storage for analysis history (scans + findings).

The database file lives in the data/ directory and is created automatically on
first use — no migrations needed for this project's scope.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

DB_DIR = Path(__file__).resolve().parent.parent / "data"
DB_PATH = DB_DIR / "history.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    filename           TEXT    NOT NULL,
    source             TEXT    NOT NULL DEFAULT 'upload',
    verdict            TEXT    NOT NULL,
    total_events       INTEGER NOT NULL,
    normal_events      INTEGER NOT NULL,
    anomalies          INTEGER NOT NULL,
    critical_anomalies INTEGER NOT NULL,
    max_severity       TEXT    NOT NULL,
    final_state        TEXT    NOT NULL,
    accepted           INTEGER NOT NULL,
    detection_ms       REAL    NOT NULL,
    event_sequence     TEXT    NOT NULL,
    created_at         TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    position        INTEGER NOT NULL,
    event           TEXT    NOT NULL,
    previous_state  TEXT    NOT NULL,
    current_state   TEXT    NOT NULL,
    severity        TEXT    NOT NULL,
    anomaly_type    TEXT    NOT NULL,
    reason          TEXT    NOT NULL,
    expected_events TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);
"""


def get_connection() -> sqlite3.Connection:
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with get_connection() as conn:
        conn.executescript(_SCHEMA)


def save_scan(result: dict) -> int:
    """Persist one analysis result; returns the new scan id."""
    summary = result["summary"]
    findings = [r for r in result["results"] if r["status"] == "ANOMALY"]
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    conn = get_connection()
    try:
        cur = conn.execute(
            """INSERT INTO scans
               (filename, source, verdict, total_events, normal_events,
                anomalies, critical_anomalies, max_severity, final_state,
                accepted, detection_ms, event_sequence, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                result["filename"], result.get("source", "upload"),
                summary["verdict"], summary["total_events"],
                summary["normal_events"], summary["anomalies"],
                summary["critical_anomalies"], summary["max_severity"],
                summary["final_state"], int(summary["accepted"]),
                summary["detection_ms"],
                " ".join(result["event_sequence"]), now,
            ),
        )
        scan_id = cur.lastrowid
        for f in findings:
            conn.execute(
                """INSERT INTO findings
                   (scan_id, position, event, previous_state, current_state,
                    severity, anomaly_type, reason, expected_events)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id, f["position"], f["event"], f["previous_state"],
                    f["current_state"], f["severity"], f["anomaly_type"] or "",
                    f["reason"], " ".join(f["expected_events"]),
                ),
            )
        conn.commit()
        return scan_id
    finally:
        conn.close()


def list_scans(limit: int = 50) -> List[dict]:
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY created_at DESC, id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) | {"event_sequence": r["event_sequence"].split()}
                for r in rows]
    finally:
        conn.close()


def get_scan(scan_id: int) -> Optional[dict]:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            return None
        scan = dict(row) | {"event_sequence": row["event_sequence"].split()}
        frows = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY position",
            (scan_id,),
        ).fetchall()
        findings = []
        for fr in frows:
            d = dict(fr)
            d["expected_events"] = d["expected_events"].split()
            findings.append(d)
        scan["findings"] = findings
        return scan
    finally:
        conn.close()


def delete_scan(scan_id: int) -> bool:
    conn = get_connection()
    try:
        cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def clear_history() -> int:
    conn = get_connection()
    try:
        cur = conn.execute("DELETE FROM scans")
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def history_stats() -> dict:
    conn = get_connection()
    try:
        row = conn.execute(
            """SELECT COUNT(*) AS scans,
                      COALESCE(SUM(total_events), 0)   AS total_events,
                      COALESCE(SUM(anomalies), 0)      AS anomalies,
                      COALESCE(SUM(critical_anomalies), 0) AS critical_anomalies
               FROM scans"""
        ).fetchone()
        return dict(row)
    finally:
        conn.close()
