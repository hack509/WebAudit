"""
Slack Notifier — posts audit results to a Slack webhook URL.

Configuration via environment variable or direct constructor:
    WEBAUDIT_SLACK_WEBHOOK=https://hooks.slack.com/services/XXX/YYY/ZZZ

Usage:
    notifier = SlackNotifier(webhook_url="https://hooks.slack.com/...")
    await notifier.send(payload)
"""

from __future__ import annotations

import os
from typing import Optional

import httpx

from notifications.base import BaseNotifier, NotificationPayload
from utils.logger import get_logger

logger = get_logger("notifications.slack")


class SlackNotifier(BaseNotifier):
    """Sends a rich Slack Block Kit message via an incoming webhook."""

    def __init__(self, webhook_url: Optional[str] = None, score_threshold: float = 0.0):
        self._webhook = webhook_url or os.environ.get("WEBAUDIT_SLACK_WEBHOOK", "")
        self._threshold = score_threshold

    async def send(self, payload: NotificationPayload) -> None:
        if not self._webhook:
            logger.debug("Slack notifier skipped — no webhook URL configured")
            return

        if payload.global_score >= self._threshold and self._threshold > 0:
            return

        color = self._score_color(payload.global_score)
        grade_emoji = {"A": "🟢", "B": "🟢", "C": "🟡", "D": "🟠", "E": "🔴", "F": "🔴"}.get(
            payload.global_grade, "⚪"
        )

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"WebAudit Report — {payload.target_url}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Score global*\n{grade_emoji} {payload.global_score:.1f}/100 ({payload.global_grade})"},
                    {"type": "mrkdwn", "text": f"*Problèmes*\n🔴 {payload.critical_count} critiques · 🟠 {payload.high_count} hauts"},
                    {"type": "mrkdwn", "text": f"*Cible*\n{payload.target_url}"},
                    {"type": "mrkdwn", "text": f"*Terminé à*\n{payload.completed_at[:19]}"},
                ],
            },
        ]

        if payload.dashboard_url:
            blocks.append({
                "type": "actions",
                "elements": [{
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Voir le rapport"},
                    "url": payload.dashboard_url,
                    "style": "primary" if color == "good" else "danger",
                }],
            })

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(self._webhook, json={"blocks": blocks})
                if resp.status_code != 200:
                    logger.warning(f"Slack webhook returned {resp.status_code}: {resp.text[:100]}")
                else:
                    logger.info(f"Slack notification sent for audit {payload.audit_id}")
        except Exception as e:
            logger.error(f"Slack notification failed: {e}")
