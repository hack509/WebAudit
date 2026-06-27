"""
Audit routes — POST /audit, GET /audit/{id}, GET /audit/{id}/report.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException

from api.auth import verify_api_key
from api.models import AuditRequest, AuditStatusResponse, AuditTaskResponse
from storage.history import get_audit, get_audit_report_json, save_audit
from utils.logger import get_logger

logger = get_logger("api.routes.audit")
router = APIRouter(prefix="/audit", tags=["audit"])

# In-memory cache for active task metadata (augments SQLite for real-time status)
_active_tasks: dict[str, dict] = {}


async def _run_audit_task(
    task_id: str,
    request: AuditRequest,
    base_url: str,
) -> None:
    """Background task: build config, run audit, persist result, send alerts."""
    started_at = datetime.now().isoformat()
    save_audit(task_id, request.url, started_at, status="running")

    try:
        from config.settings import AuditConfig, TargetConfig, AuthConfig, ReportConfig
        from audit.runner import AuditRunner
        from reports.generator import ReportGenerator

        # Build config from request
        config = AuditConfig(
            target=TargetConfig(url=request.url),
            auth=AuthConfig(
                jwt_token=request.jwt_token,
                username=request.username,
                password=request.password,
            ),
            report=ReportConfig(
                formats=request.formats,
                language=request.language,
            ),
        )

        # Apply profile if requested
        if request.profile:
            try:
                profile_config = AuditConfig.from_profile(request.profile)
                config.crawl = profile_config.crawl
                config.security = profile_config.security
                config.performance = profile_config.performance
            except FileNotFoundError:
                logger.warning(f"Profile '{request.profile}' not found — using defaults")

        # Apply env overrides last
        config.apply_env_overrides()

        runner = AuditRunner(config)
        runner.register_all_auditors()

        if request.modules:
            report = await runner.run_selected(request.modules)
        else:
            report = await runner.run_all()

        # Persist full report
        completed_at = datetime.now().isoformat()
        modules_summary = [
            {
                "name": r.module_name,
                "score": r.score.score if r.score else None,
                "grade": r.score.grade if r.score else None,
                "passed": r.score.passed_checks if r.score else 0,
                "failed": r.score.failed_checks if r.score else 0,
                "critical": r.score.critical_issues if r.score else 0,
            }
            for r in report.results
        ]

        save_audit(
            task_id,
            request.url,
            started_at,
            status="completed",
            completed_at=completed_at,
            global_score=report.global_score,
            global_grade=report.global_grade,
            modules=modules_summary,
            report=report.to_dict(),
        )

        _active_tasks[task_id]["status"] = "completed"
        _active_tasks[task_id]["global_score"] = report.global_score
        _active_tasks[task_id]["global_grade"] = report.global_grade
        _active_tasks[task_id]["completed_at"] = completed_at

        # Send alerts if configured
        await _maybe_alert(task_id, request, report, base_url, started_at, completed_at)

        logger.info(f"Audit {task_id} completed — {report.global_score:.1f}/100 ({report.global_grade})")

    except Exception as e:
        logger.error(f"Audit {task_id} failed: {e}", exc_info=True)
        completed_at = datetime.now().isoformat()
        save_audit(
            task_id, request.url, started_at,
            status="failed", completed_at=completed_at, error=str(e)[:500],
        )
        _active_tasks[task_id]["status"] = "failed"
        _active_tasks[task_id]["error"] = str(e)[:200]


async def _maybe_alert(task_id, request, report, base_url, started_at, completed_at) -> None:
    """Send Slack/email notifications if configured."""
    from notifications.base import NotificationPayload
    from notifications.slack import SlackNotifier
    from notifications.email import EmailNotifier

    payload = NotificationPayload(
        audit_id=task_id,
        target_url=request.url,
        global_score=report.global_score,
        global_grade=report.global_grade,
        started_at=started_at,
        completed_at=completed_at,
        total_issues=report.total_issues,
        critical_count=report.critical_count,
        high_count=report.high_count,
        dashboard_url=f"{base_url}/api/v1/audit/{task_id}/report",
    )

    import os
    from notifications.base import BaseNotifier

    threshold = request.score_threshold or 0.0
    notifiers: list[BaseNotifier] = []

    if request.slack_webhook:
        notifiers.append(SlackNotifier(webhook_url=request.slack_webhook, score_threshold=threshold))
    if request.email_to:
        notifiers.append(EmailNotifier(smtp_to=request.email_to, score_threshold=threshold))

    # Also pick up env-configured notifiers
    if os.environ.get("WEBAUDIT_SLACK_WEBHOOK") and not request.slack_webhook:
        notifiers.append(SlackNotifier(score_threshold=threshold))
    if os.environ.get("WEBAUDIT_SMTP_TO") and not request.email_to:
        notifiers.append(EmailNotifier(score_threshold=threshold))

    for notifier in notifiers:
        try:
            await notifier.send(payload)
        except Exception as e:
            logger.warning(f"Notifier {type(notifier).__name__} failed: {e}")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("", response_model=AuditTaskResponse, status_code=202)
async def create_audit(
    request: AuditRequest,
    background_tasks: BackgroundTasks,
    _key: str | None = Depends(verify_api_key),
):
    """Launch an audit in the background and return a task ID."""
    task_id = str(uuid.uuid4())

    _active_tasks[task_id] = {
        "url": request.url,
        "status": "pending",
        "started_at": datetime.now().isoformat(),
    }

    # Determine base URL for dashboard links (set by the server at startup)
    base_url = "http://localhost:8000"

    background_tasks.add_task(_run_audit_task, task_id, request, base_url)

    return AuditTaskResponse(
        task_id=task_id,
        status="pending",
        url=request.url,
        message=f"Audit queued. Poll GET /api/v1/audit/{task_id} for status.",
    )


@router.get("/{task_id}", response_model=AuditStatusResponse)
async def get_audit_status(task_id: str, _key: str | None = Depends(verify_api_key)):
    """Get the current status and result of an audit task."""
    # Check in-memory cache first (fastest for active tasks)
    if task_id in _active_tasks:
        meta = _active_tasks[task_id]
        return AuditStatusResponse(
            task_id=task_id,
            url=meta["url"],
            status=meta["status"],
            started_at=meta["started_at"],
            completed_at=meta.get("completed_at"),
            global_score=meta.get("global_score"),
            global_grade=meta.get("global_grade"),
            error=meta.get("error"),
        )

    # Fall back to SQLite for completed/old tasks
    record = get_audit(task_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Audit '{task_id}' not found")

    return AuditStatusResponse(
        task_id=record.id,
        url=record.url,
        status=record.status,
        started_at=record.started_at,
        completed_at=record.completed_at,
        global_score=record.global_score,
        global_grade=record.global_grade,
        error=record.error,
    )


@router.get("/{task_id}/report")
async def get_audit_report(task_id: str, _key: str | None = Depends(verify_api_key)):
    """Return the full JSON report for a completed audit."""
    report = get_audit_report_json(task_id)
    if report is None:
        record = get_audit(task_id)
        if not record:
            raise HTTPException(status_code=404, detail="Audit not found")
        if record.status != "completed":
            raise HTTPException(status_code=409, detail=f"Audit not completed yet (status: {record.status})")
        raise HTTPException(status_code=404, detail="Report data not available")
    return report
