"""
Schedule routes — POST /api/v1/schedule, GET /api/v1/schedule, DELETE /api/v1/schedule/{id}

Persists cron-style audit schedules in SQLite and runs them via an
asyncio background loop started at application lifespan.

Cron expression subset supported (5 fields):
    minute  hour  day-of-month  month  day-of-week
    *       *     *             *      *   → every minute

Usage:
    POST /api/v1/schedule
    {
        "url": "https://example.com",
        "cron": "0 8 * * 1-5",     ← Monday-Friday at 08:00
        "label": "Daily prod check",
        "profile": "prod",
        "score_threshold": 70,
        "slack_webhook": "https://hooks.slack.com/..."
    }
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.auth import verify_api_key
from utils.logger import get_logger

logger = get_logger("api.schedule")
router = APIRouter(prefix="/schedule", tags=["schedule"])

_DB_PATH = Path("storage/webaudit.db")


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def _init_schedule_table() -> None:
    with _conn() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS schedules (
                id          TEXT PRIMARY KEY,
                label       TEXT,
                url         TEXT NOT NULL,
                cron        TEXT NOT NULL,
                profile     TEXT,
                options_json TEXT,
                enabled     INTEGER NOT NULL DEFAULT 1,
                last_run    TEXT,
                next_run    TEXT,
                created_at  TEXT NOT NULL
            )
        """)
        c.commit()


# ---------------------------------------------------------------------------
# Cron-next helper (minimal — no external lib)
# ---------------------------------------------------------------------------

def _cron_matches(cron: str, dt: datetime) -> bool:
    """Return True if dt matches the cron expression (5-field subset)."""
    fields = cron.strip().split()
    if len(fields) != 5:
        return False
    minute, hour, dom, month, dow = fields

    def _match(field: str, value: int) -> bool:
        if field == "*":
            return True
        for part in field.split(","):
            if "-" in part:
                lo, hi = part.split("-", 1)
                if int(lo) <= value <= int(hi):
                    return True
            elif part.isdigit() and int(part) == value:
                return True
        return False

    return (
        _match(minute, dt.minute)
        and _match(hour, dt.hour)
        and _match(dom, dt.day)
        and _match(month, dt.month)
        and _match(dow, dt.isoweekday() % 7)  # 0=Sunday
    )


# ---------------------------------------------------------------------------
# Background scheduler loop (started from app lifespan)
# ---------------------------------------------------------------------------

async def run_scheduler() -> None:
    """Check every 60 s whether any schedule should fire."""
    _init_schedule_table()
    logger.info("Audit scheduler started")

    while True:
        await asyncio.sleep(60)
        now = datetime.now(tz=timezone.utc)

        try:
            with _conn() as c:
                rows = c.execute(
                    "SELECT * FROM schedules WHERE enabled = 1"
                ).fetchall()
        except Exception as e:
            logger.error(f"Scheduler DB error: {e}")
            continue

        for row in rows:
            if not _cron_matches(row["cron"], now):
                continue

            options = json.loads(row["options_json"] or "{}")
            logger.info(f"Firing scheduled audit '{row['label']}' for {row['url']}")

            try:
                from api.routes.audit import _run_audit_task
                from api.models import AuditRequest

                request = AuditRequest(
                    url=row["url"],
                    profile=row["profile"],
                    score_threshold=options.get("score_threshold"),
                    slack_webhook=options.get("slack_webhook"),
                    email_to=options.get("email_to"),
                )
                task_id = str(uuid.uuid4())
                asyncio.create_task(
                    _run_audit_task(task_id, request, "http://localhost:8000")
                )

                with _conn() as c:
                    c.execute(
                        "UPDATE schedules SET last_run = ? WHERE id = ?",
                        (now.isoformat(), row["id"]),
                    )
                    c.commit()
            except Exception as e:
                logger.error(f"Scheduled audit failed for {row['url']}: {e}")


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class ScheduleCreate(BaseModel):
    url: str
    cron: str
    label: Optional[str] = None
    profile: Optional[str] = None
    score_threshold: Optional[float] = None
    slack_webhook: Optional[str] = None
    email_to: Optional[list[str]] = None


class ScheduleResponse(BaseModel):
    id: str
    label: Optional[str]
    url: str
    cron: str
    profile: Optional[str]
    enabled: bool
    last_run: Optional[str]
    created_at: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("", response_model=ScheduleResponse, status_code=201)
async def create_schedule(
    body: ScheduleCreate,
    _key: str | None = Depends(verify_api_key),
):
    """Register a recurring audit schedule."""
    _init_schedule_table()

    schedule_id = str(uuid.uuid4())
    created_at = datetime.now().isoformat()
    options = {}
    if body.score_threshold is not None:
        options["score_threshold"] = body.score_threshold
    if body.slack_webhook:
        options["slack_webhook"] = body.slack_webhook
    if body.email_to:
        options["email_to"] = body.email_to

    with _conn() as c:
        c.execute("""
            INSERT INTO schedules (id, label, url, cron, profile, options_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            schedule_id, body.label, body.url, body.cron,
            body.profile, json.dumps(options), created_at,
        ))
        c.commit()

    logger.info(f"Schedule created: {schedule_id} — '{body.label}' @ {body.cron}")
    return ScheduleResponse(
        id=schedule_id,
        label=body.label,
        url=body.url,
        cron=body.cron,
        profile=body.profile,
        enabled=True,
        last_run=None,
        created_at=created_at,
    )


@router.get("", response_model=list[ScheduleResponse])
async def list_schedules(_key: str | None = Depends(verify_api_key)):
    """List all registered schedules."""
    _init_schedule_table()
    with _conn() as c:
        rows = c.execute("SELECT * FROM schedules ORDER BY created_at DESC").fetchall()
    return [
        ScheduleResponse(
            id=r["id"],
            label=r["label"],
            url=r["url"],
            cron=r["cron"],
            profile=r["profile"],
            enabled=bool(r["enabled"]),
            last_run=r["last_run"],
            created_at=r["created_at"],
        )
        for r in rows
    ]


@router.delete("/{schedule_id}", status_code=204)
async def delete_schedule(
    schedule_id: str,
    _key: str | None = Depends(verify_api_key),
):
    """Delete a schedule."""
    _init_schedule_table()
    with _conn() as c:
        result = c.execute("DELETE FROM schedules WHERE id = ?", (schedule_id,))
        c.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Schedule not found")


@router.patch("/{schedule_id}/toggle", response_model=ScheduleResponse)
async def toggle_schedule(
    schedule_id: str,
    _key: str | None = Depends(verify_api_key),
):
    """Enable or disable a schedule."""
    _init_schedule_table()
    with _conn() as c:
        row = c.execute("SELECT * FROM schedules WHERE id = ?", (schedule_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Schedule not found")
        new_state = 0 if row["enabled"] else 1
        c.execute("UPDATE schedules SET enabled = ? WHERE id = ?", (new_state, schedule_id))
        c.commit()
        row = c.execute("SELECT * FROM schedules WHERE id = ?", (schedule_id,)).fetchone()

    return ScheduleResponse(
        id=row["id"],
        label=row["label"],
        url=row["url"],
        cron=row["cron"],
        profile=row["profile"],
        enabled=bool(row["enabled"]),
        last_run=row["last_run"],
        created_at=row["created_at"],
    )
