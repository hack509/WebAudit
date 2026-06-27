"""
Scoring Engine for WebAudit.

Calculates individual module scores and weighted global score.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from utils.logger import get_logger

logger = get_logger("scoring")


# Default weights for global score calculation
DEFAULT_WEIGHTS: dict[str, float] = {
    "security": 0.20,
    "performance": 0.15,
    "backend": 0.15,
    "api": 0.10,
    "frontend": 0.10,
    "ux": 0.10,
    "accessibility": 0.05,
    "seo": 0.05,
    "javascript": 0.05,
    "mobile": 0.05,
}


@dataclass
class ModuleScore:
    """Score for a single audit module."""

    module_name: str
    score: float  # 0–100
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    warnings: int = 0
    critical_issues: int = 0
    details: dict[str, float] = field(default_factory=dict)

    @property
    def grade(self) -> str:
        """Return a letter grade based on the score."""
        if self.score >= 90:
            return "A"
        elif self.score >= 80:
            return "B"
        elif self.score >= 70:
            return "C"
        elif self.score >= 60:
            return "D"
        elif self.score >= 50:
            return "E"
        else:
            return "F"

    @property
    def status_emoji(self) -> str:
        """Return a status emoji based on the grade."""
        grade_emojis = {
            "A": "🟢", "B": "🟢", "C": "🟡",
            "D": "🟠", "E": "🔴", "F": "🔴",
        }
        return grade_emojis.get(self.grade, "⚪")

    @property
    def pass_rate(self) -> float:
        """Return the pass rate as a percentage."""
        if self.total_checks == 0:
            return 0.0
        return (self.passed_checks / self.total_checks) * 100


class ScoreCalculator:
    """Calculates and aggregates audit scores."""

    def __init__(self, weights: Optional[dict[str, float]] = None):
        self.weights = weights or DEFAULT_WEIGHTS.copy()
        self.module_scores: dict[str, ModuleScore] = {}

    def add_module_score(self, score: ModuleScore) -> None:
        """Register a module score."""
        self.module_scores[score.module_name] = score
        logger.debug(
            f"Score [{score.module_name}]: {score.score:.1f}/100 "
            f"({score.grade}) — {score.passed_checks}/{score.total_checks} passed"
        )

    def calculate_module_score(
        self,
        module_name: str,
        passed: int,
        total: int,
        critical_issues: int = 0,
        warnings: int = 0,
        details: Optional[dict[str, float]] = None,
    ) -> ModuleScore:
        """
        Calculate a score for a single module.

        Critical issues apply a penalty. Warnings apply a smaller penalty.
        """
        if total == 0:
            base_score = 0.0
        else:
            base_score = (passed / total) * 100

        # Penalties
        critical_penalty = critical_issues * 10  # -10 per critical issue
        warning_penalty = warnings * 2  # -2 per warning

        final_score = max(0.0, min(100.0, base_score - critical_penalty - warning_penalty))

        score = ModuleScore(
            module_name=module_name,
            score=final_score,
            total_checks=total,
            passed_checks=passed,
            failed_checks=total - passed,
            warnings=warnings,
            critical_issues=critical_issues,
            details=details or {},
        )

        self.add_module_score(score)
        return score

    def get_global_score(self) -> float:
        """
        Calculate the weighted global score across all modules.

        Only considers modules that have been scored.
        """
        if not self.module_scores:
            return 0.0

        total_weight = 0.0
        weighted_sum = 0.0

        for module_name, score in self.module_scores.items():
            weight = self.weights.get(module_name, 0.05)  # Default weight of 5%
            weighted_sum += score.score * weight
            total_weight += weight

        if total_weight == 0:
            return 0.0

        return weighted_sum / total_weight

    def get_global_grade(self) -> str:
        """Return a letter grade for the global score."""
        score = self.get_global_score()
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        elif score >= 50:
            return "E"
        else:
            return "F"

    def get_summary(self) -> dict:
        """Return a full summary of all scores."""
        return {
            "global_score": round(self.get_global_score(), 1),
            "global_grade": self.get_global_grade(),
            "modules": {
                name: {
                    "score": round(score.score, 1),
                    "grade": score.grade,
                    "passed": score.passed_checks,
                    "total": score.total_checks,
                    "critical": score.critical_issues,
                    "warnings": score.warnings,
                }
                for name, score in self.module_scores.items()
            },
        }
