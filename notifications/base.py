"""Base notifier interface and shared payload dataclass."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class NotificationPayload:
    """Data passed to every notifier when an audit completes."""
    audit_id: str
    target_url: str
    global_score: float
    global_grade: str
    started_at: str
    completed_at: str
    total_issues: int
    critical_count: int
    high_count: int
    dashboard_url: Optional[str] = None


class BaseNotifier(ABC):
    """Abstract base for all notification channels."""

    @abstractmethod
    async def send(self, payload: NotificationPayload) -> None:
        """Send the notification. Must not raise — log errors internally."""
        ...

    def _score_color(self, score: float) -> str:
        if score >= 80:
            return "good"
        if score >= 60:
            return "warning"
        return "danger"
