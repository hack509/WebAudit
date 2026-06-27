"""
Audit Result Data Models.

Defines the data structures for audit findings and results.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from utils.scoring import ModuleScore


class Severity(str, Enum):
    """Severity levels for audit findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    PASS = "pass"

    @property
    def emoji(self) -> str:
        emojis = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
            "info": "ℹ️",
            "pass": "✅",
        }
        return emojis.get(self.value, "⚪")

    @property
    def weight(self) -> int:
        """Numeric weight for sorting (higher = more severe)."""
        weights = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
            "pass": 0,
        }
        return weights.get(self.value, 0)


class AuditCategory(str, Enum):
    """Categories for audit findings."""

    DISCOVERY = "discovery"
    BACKEND = "backend"
    API = "api"
    FRONTEND = "frontend"
    SECURITY = "security"
    PERFORMANCE = "performance"
    UX = "ux"
    JAVASCRIPT = "javascript"
    AUTH = "auth"
    DATABASE = "database"
    MOBILE = "mobile"
    E2E = "e2e"
    SEO = "seo"
    ACCESSIBILITY = "accessibility"
    PWA = "pwa"


@dataclass
class AuditFinding:
    """A single audit finding/check result."""

    title: str
    description: str
    severity: Severity
    category: str = ""
    module: str = ""
    recommendation: str = ""
    url: str = ""
    evidence: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category,
            "module": self.module,
            "recommendation": self.recommendation,
            "url": self.url,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


@dataclass
class AuditResult:
    """Result of a single audit module run."""

    module_name: str
    module_description: str
    findings: list[AuditFinding] = field(default_factory=list)
    score: Optional[ModuleScore] = None
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: Optional[str] = None
    duration_ms: float = 0.0
    error: Optional[str] = None

    @property
    def critical_findings(self) -> list[AuditFinding]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    @property
    def high_findings(self) -> list[AuditFinding]:
        return [f for f in self.findings if f.severity == Severity.HIGH]

    @property
    def medium_findings(self) -> list[AuditFinding]:
        return [f for f in self.findings if f.severity == Severity.MEDIUM]

    @property
    def low_findings(self) -> list[AuditFinding]:
        return [f for f in self.findings if f.severity == Severity.LOW]

    @property
    def passed_findings(self) -> list[AuditFinding]:
        return [f for f in self.findings if f.severity == Severity.PASS]

    @property
    def failed_findings(self) -> list[AuditFinding]:
        return [f for f in self.findings if f.severity not in (Severity.PASS, Severity.INFO)]

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_name": self.module_name,
            "module_description": self.module_description,
            "findings": [f.to_dict() for f in self.findings],
            "score": {
                "value": self.score.score if self.score else 0,
                "grade": self.score.grade if self.score else "F",
                "passed": self.score.passed_checks if self.score else 0,
                "total": self.score.total_checks if self.score else 0,
            },
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_ms": self.duration_ms,
            "error": self.error,
        }


@dataclass
class FullAuditReport:
    """Complete audit report aggregating all module results."""

    target_url: str
    results: list[AuditResult] = field(default_factory=list)
    global_score: float = 0.0
    global_grade: str = "F"
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: Optional[str] = None
    total_duration_ms: float = 0.0
    technologies_detected: dict[str, Any] = field(default_factory=dict)
    screenshots: list[str] = field(default_factory=list)

    @property
    def all_findings(self) -> list[AuditFinding]:
        findings = []
        for result in self.results:
            findings.extend(result.findings)
        return findings

    @property
    def total_issues(self) -> int:
        return len([f for f in self.all_findings if f.severity not in (Severity.PASS, Severity.INFO)])

    @property
    def critical_count(self) -> int:
        return len([f for f in self.all_findings if f.severity == Severity.CRITICAL])

    @property
    def high_count(self) -> int:
        return len([f for f in self.all_findings if f.severity == Severity.HIGH])

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "global_score": round(self.global_score, 1),
            "global_grade": self.global_grade,
            "total_issues": self.total_issues,
            "critical_issues": self.critical_count,
            "high_issues": self.high_count,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "total_duration_ms": round(self.total_duration_ms, 1),
            "technologies": self.technologies_detected,
            "screenshots": self.screenshots,
            "modules": [r.to_dict() for r in self.results],
        }
