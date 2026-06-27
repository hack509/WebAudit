"""
Audit History — SQLite persistence layer.

Stores every completed audit run (URL, timestamp, global score, grade,
per-module scores, full JSON report) so the dashboard can display history
and trend comparisons.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from utils.logger import get_logger

logger = get_logger("storage.history")

_DB_PATH = Path("storage/webaudit.db")


def _connect() -> sqlite3.Connection:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create tables if they don't exist."""
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audits (
                id          TEXT PRIMARY KEY,
                url         TEXT NOT NULL,
                started_at  TEXT NOT NULL,
                completed_at TEXT,
                status      TEXT NOT NULL DEFAULT 'pending',
                global_score REAL,
                global_grade TEXT,
                modules_json TEXT,
                report_json TEXT,
                error       TEXT
            )
        """)
        conn.commit()
    logger.debug("Database initialised")


@dataclass
class AuditRecord:
    id: str
    url: str
    started_at: str
    completed_at: Optional[str]
    status: str
    global_score: Optional[float]
    global_grade: Optional[str]
    modules: Optional[list[dict]]
    error: Optional[str]


def save_audit(
    audit_id: str,
    url: str,
    started_at: str,
    status: str = "pending",
    completed_at: Optional[str] = None,
    global_score: Optional[float] = None,
    global_grade: Optional[str] = None,
    modules: Optional[list[dict]] = None,
    report: Optional[dict] = None,
    error: Optional[str] = None,
) -> None:
    with _connect() as conn:
        conn.execute("""
            INSERT INTO audits
                (id, url, started_at, completed_at, status,
                 global_score, global_grade, modules_json, report_json, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                completed_at = excluded.completed_at,
                status       = excluded.status,
                global_score = excluded.global_score,
                global_grade = excluded.global_grade,
                modules_json = excluded.modules_json,
                report_json  = excluded.report_json,
                error        = excluded.error
        """, (
            audit_id, url, started_at, completed_at, status,
            global_score, global_grade,
            json.dumps(modules) if modules else None,
            json.dumps(report) if report else None,
            error,
        ))
        conn.commit()


def get_audit(audit_id: str) -> Optional[AuditRecord]:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM audits WHERE id = ?", (audit_id,)
        ).fetchone()
    if not row:
        return None
    return _row_to_record(row)


def list_audits(limit: int = 50) -> list[AuditRecord]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM audits ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_row_to_record(r) for r in rows]


def get_audit_report_json(audit_id: str) -> Optional[dict]:
    with _connect() as conn:
        row = conn.execute(
            "SELECT report_json FROM audits WHERE id = ?", (audit_id,)
        ).fetchone()
    if not row or not row["report_json"]:
        return None
    return json.loads(row["report_json"])


def _row_to_record(row: sqlite3.Row) -> AuditRecord:
    return AuditRecord(
        id=row["id"],
        url=row["url"],
        started_at=row["started_at"],
        completed_at=row["completed_at"],
        status=row["status"],
        global_score=row["global_score"],
        global_grade=row["global_grade"],
        modules=json.loads(row["modules_json"]) if row["modules_json"] else None,
        error=row["error"],
    )
