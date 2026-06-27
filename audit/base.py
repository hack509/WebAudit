"""
Base Auditor — Abstract base class for all audit modules.

All audit modules inherit from BaseAuditor and implement the `run()` method.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from config.settings import AuditConfig
from audit.result import AuditResult, AuditFinding, Severity
from utils.logger import get_logger
from utils.scoring import ModuleScore


class BaseAuditor(ABC):
    """Abstract base class for all audit modules."""

    # Must be overridden by subclasses
    MODULE_NAME: str = "base"
    MODULE_DESCRIPTION: str = "Base auditor"

    def __init__(self, config: AuditConfig):
        self.config = config
        self.logger = get_logger(f"audit.{self.MODULE_NAME}")
        self.findings: list[AuditFinding] = []
        self.passed_checks: int = 0
        self.failed_checks: int = 0
        self.total_checks: int = 0
        self.warnings: int = 0
        self.critical_issues: int = 0
        self._base_url: str = config.target.url

    @abstractmethod
    async def run(self) -> AuditResult:
        """Execute the audit and return results. Must be implemented by subclasses."""
        ...

    def add_finding(
        self,
        title: str,
        description: str,
        severity: Severity,
        category: str = "",
        recommendation: str = "",
        url: str = "",
        evidence: str = "",
    ) -> AuditFinding:
        """Add an audit finding."""
        finding = AuditFinding(
            title=title,
            description=description,
            severity=severity,
            category=category or self.MODULE_NAME,
            recommendation=recommendation,
            url=url,
            evidence=evidence,
            module=self.MODULE_NAME,
        )
        self.findings.append(finding)

        # Update counters
        self.total_checks += 1
        if severity == Severity.PASS:
            self.passed_checks += 1
        elif severity == Severity.CRITICAL:
            self.failed_checks += 1
            self.critical_issues += 1
        elif severity == Severity.HIGH:
            self.failed_checks += 1
            self.critical_issues += 1
        elif severity == Severity.MEDIUM:
            self.failed_checks += 1
        elif severity == Severity.LOW:
            self.failed_checks += 1
            self.warnings += 1
        elif severity == Severity.INFO:
            self.warnings += 1

        return finding

    def pass_check(self, title: str, description: str = "", **kwargs) -> AuditFinding:
        """Record a passed check."""
        return self.add_finding(
            title=title,
            description=description or f"{title} — OK",
            severity=Severity.PASS,
            **kwargs,
        )

    def fail_check(
        self, title: str, description: str, severity: Severity = Severity.MEDIUM, **kwargs
    ) -> AuditFinding:
        """Record a failed check."""
        return self.add_finding(
            title=title,
            description=description,
            severity=severity,
            **kwargs,
        )

    def info(self, title: str, description: str, **kwargs) -> AuditFinding:
        """Record an informational finding."""
        return self.add_finding(
            title=title,
            description=description,
            severity=Severity.INFO,
            **kwargs,
        )

    def get_score(self) -> ModuleScore:
        """Calculate the module score based on findings."""
        return ModuleScore(
            module_name=self.MODULE_NAME,
            score=self._calculate_score(),
            total_checks=self.total_checks,
            passed_checks=self.passed_checks,
            failed_checks=self.failed_checks,
            warnings=self.warnings,
            critical_issues=self.critical_issues,
        )

    def _calculate_score(self) -> float:
        """Calculate a score from 0 to 100."""
        if self.total_checks == 0:
            return 0.0

        base_score = (self.passed_checks / self.total_checks) * 100
        critical_penalty = self.critical_issues * 10
        warning_penalty = self.warnings * 2

        return max(0.0, min(100.0, base_score - critical_penalty - warning_penalty))

    def build_result(self) -> AuditResult:
        """Build the final AuditResult for this module."""
        return AuditResult(
            module_name=self.MODULE_NAME,
            module_description=self.MODULE_DESCRIPTION,
            findings=self.findings.copy(),
            score=self.get_score(),
        )
