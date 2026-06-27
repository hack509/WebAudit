"""
Email Notifier — sends audit results via SMTP.

Configuration via environment variables:
    WEBAUDIT_SMTP_HOST     (default: localhost)
    WEBAUDIT_SMTP_PORT     (default: 587)
    WEBAUDIT_SMTP_USER
    WEBAUDIT_SMTP_PASSWORD
    WEBAUDIT_SMTP_FROM     (default: webaudit@localhost)
    WEBAUDIT_SMTP_TO       (comma-separated list of recipients)
    WEBAUDIT_SMTP_TLS      (1/true to use STARTTLS, default: true)
"""

from __future__ import annotations

import asyncio
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from notifications.base import BaseNotifier, NotificationPayload
from utils.logger import get_logger

logger = get_logger("notifications.email")


class EmailNotifier(BaseNotifier):
    """Sends an HTML summary email via SMTP using stdlib smtplib in a thread pool."""

    def __init__(
        self,
        smtp_host: Optional[str] = None,
        smtp_port: Optional[int] = None,
        smtp_user: Optional[str] = None,
        smtp_password: Optional[str] = None,
        smtp_from: Optional[str] = None,
        smtp_to: Optional[list[str]] = None,
        use_tls: Optional[bool] = None,
        score_threshold: float = 0.0,
    ):
        env = os.environ
        self._host = smtp_host or env.get("WEBAUDIT_SMTP_HOST", "localhost")
        self._port = smtp_port or int(env.get("WEBAUDIT_SMTP_PORT", "587"))
        self._user = smtp_user or env.get("WEBAUDIT_SMTP_USER", "")
        self._password = smtp_password or env.get("WEBAUDIT_SMTP_PASSWORD", "")
        self._from = smtp_from or env.get("WEBAUDIT_SMTP_FROM", "webaudit@localhost")
        raw_to = smtp_to or [t.strip() for t in env.get("WEBAUDIT_SMTP_TO", "").split(",") if t.strip()]
        self._to = raw_to
        tls_env = env.get("WEBAUDIT_SMTP_TLS", "true")
        self._use_tls = use_tls if use_tls is not None else tls_env.lower() in ("1", "true", "yes")
        self._threshold = score_threshold

    async def send(self, payload: NotificationPayload) -> None:
        if not self._to:
            logger.debug("Email notifier skipped — no recipients configured")
            return
        if payload.global_score >= self._threshold and self._threshold > 0:
            return

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._send_sync, payload)

    def _send_sync(self, payload: NotificationPayload) -> None:
        grade_emoji = {"A": "✅", "B": "✅", "C": "⚠️", "D": "⚠️", "E": "❌", "F": "❌"}.get(
            payload.global_grade, "📊"
        )
        subject = (
            f"[WebAudit] {grade_emoji} {payload.global_score:.1f}/100 ({payload.global_grade})"
            f" — {payload.target_url}"
        )

        html = f"""
        <html><body style="font-family:sans-serif;color:#333">
        <h2>WebAudit — Rapport d'audit</h2>
        <table cellpadding="8" style="border-collapse:collapse;width:100%">
          <tr style="background:#f5f5f5">
            <td><b>Cible</b></td><td>{payload.target_url}</td>
          </tr>
          <tr>
            <td><b>Score global</b></td>
            <td style="color:{'green' if payload.global_score>=80 else 'orange' if payload.global_score>=60 else 'red'}">
              <b>{payload.global_score:.1f}/100 ({payload.global_grade})</b>
            </td>
          </tr>
          <tr style="background:#f5f5f5">
            <td><b>Problèmes critiques</b></td>
            <td style="color:red"><b>{payload.critical_count}</b></td>
          </tr>
          <tr>
            <td><b>Problèmes hauts</b></td>
            <td style="color:orange"><b>{payload.high_count}</b></td>
          </tr>
          <tr style="background:#f5f5f5">
            <td><b>Total problèmes</b></td><td>{payload.total_issues}</td>
          </tr>
          <tr>
            <td><b>Démarré</b></td><td>{payload.started_at[:19]}</td>
          </tr>
          <tr style="background:#f5f5f5">
            <td><b>Terminé</b></td><td>{payload.completed_at[:19]}</td>
          </tr>
        </table>
        {f'<p><a href="{payload.dashboard_url}">Voir le rapport complet →</a></p>' if payload.dashboard_url else ''}
        <hr><p style="color:#999;font-size:11px">Généré par WebAudit v1.0.0</p>
        </body></html>
        """

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self._from
        msg["To"] = ", ".join(self._to)
        msg.attach(MIMEText(html, "html", "utf-8"))

        try:
            with smtplib.SMTP(self._host, self._port, timeout=15) as server:
                if self._use_tls:
                    server.starttls()
                if self._user:
                    server.login(self._user, self._password)
                server.sendmail(self._from, self._to, msg.as_string())
            logger.info(f"Email sent to {self._to} for audit {payload.audit_id}")
        except Exception as e:
            logger.error(f"Email notification failed: {e}")
