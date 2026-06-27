"""
Audit Runner — Orchestrates all audit modules.

Manages the execution of selected audit modules and aggregates results.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel

from config.settings import AuditConfig
from audit.base import BaseAuditor
from audit.result import AuditResult, FullAuditReport
from utils.logger import get_logger
from utils.scoring import ScoreCalculator

logger = get_logger("runner")
console = Console()


class AuditRunner:
    """Orchestrates the execution of audit modules."""

    def __init__(self, config: AuditConfig):
        self.config = config
        self.auditors: dict[str, BaseAuditor] = {}
        self.results: list[AuditResult] = []
        self.score_calculator = ScoreCalculator()
        self.report: Optional[FullAuditReport] = None

    def register_auditor(self, auditor: BaseAuditor) -> None:
        """Register an auditor module."""
        self.auditors[auditor.MODULE_NAME] = auditor
        logger.debug(f"Registered auditor: {auditor.MODULE_NAME}")

    def register_all_auditors(self) -> None:
        """Register all available audit modules based on config."""
        from audit.discovery.detector import DiscoveryAuditor
        from audit.backend.auditor import BackendAuditor
        from audit.api.auditor import APIAuditor
        from audit.frontend.auditor import FrontendAuditor
        from audit.security.auditor import SecurityAuditor
        from audit.performance.auditor import PerformanceAuditor
        from audit.ux.auditor import UXAuditor
        from audit.javascript.auditor import JavaScriptAuditor
        from audit.auth.auditor import AuthAuditor
        from audit.database.auditor import DatabaseAuditor
        from audit.mobile.auditor import MobileAuditor
        from audit.e2e.auditor import E2EAuditor
        from audit.screenshots.capturer import ScreenshotCapturer

        module_map = {
            "discovery": DiscoveryAuditor,
            "backend": BackendAuditor,
            "api": APIAuditor,
            "frontend": FrontendAuditor,
            "security": SecurityAuditor,
            "performance": PerformanceAuditor,
            "ux": UXAuditor,
            "javascript": JavaScriptAuditor,
            "auth": AuthAuditor,
            "database": DatabaseAuditor,
            "mobile": MobileAuditor,
            "e2e": E2EAuditor,
            "screenshots": ScreenshotCapturer,
        }

        for module_name in self.config.modules_enabled:
            if module_name in module_map:
                auditor = module_map[module_name](self.config)
                self.register_auditor(auditor)
            else:
                logger.warning(f"Unknown module: {module_name}")

    async def run_single(self, module_name: str) -> Optional[AuditResult]:
        """Run a single audit module."""
        if module_name not in self.auditors:
            logger.error(f"Module '{module_name}' not registered")
            return None

        auditor = self.auditors[module_name]
        logger.info(f"Starting module: {auditor.MODULE_NAME} — {auditor.MODULE_DESCRIPTION}")

        start = time.perf_counter()
        try:
            result = await auditor.run()
            result.completed_at = datetime.now().isoformat()
            result.duration_ms = (time.perf_counter() - start) * 1000

            self.results.append(result)
            if result.score:
                self.score_calculator.add_module_score(result.score)

            logger.info(
                f"Completed [{auditor.MODULE_NAME}] — "
                f"Score: {result.score.score:.1f}/100 ({result.score.grade}) — "
                f"{result.score.passed_checks}/{result.score.total_checks} passed — "
                f"{result.duration_ms:.0f}ms"
            )
            return result

        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            logger.error(f"Error in module [{auditor.MODULE_NAME}]: {e}", exc_info=True)
            error_result = AuditResult(
                module_name=auditor.MODULE_NAME,
                module_description=auditor.MODULE_DESCRIPTION,
                error=str(e),
                duration_ms=elapsed,
                completed_at=datetime.now().isoformat(),
            )
            self.results.append(error_result)
            return error_result

    async def run_all(self) -> FullAuditReport:
        """Run all registered audit modules sequentially."""
        start = time.perf_counter()
        started_at = datetime.now().isoformat()

        console.print()
        console.print(
            Panel(
                f"[bold cyan]🔍 WebAudit — Audit complet[/bold cyan]\n"
                f"[dim]Cible: {self.config.target.url}[/dim]\n"
                f"[dim]Modules: {len(self.auditors)}[/dim]",
                border_style="cyan",
            )
        )
        console.print()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Audit en cours...", total=len(self.auditors))

            for module_name, auditor in self.auditors.items():
                progress.update(task, description=f"[cyan]{auditor.MODULE_DESCRIPTION}[/cyan]")
                await self.run_single(module_name)
                progress.advance(task)

        total_duration = (time.perf_counter() - start) * 1000

        # Build report
        self.report = FullAuditReport(
            target_url=self.config.target.url,
            results=self.results,
            global_score=self.score_calculator.get_global_score(),
            global_grade=self.score_calculator.get_global_grade(),
            started_at=started_at,
            completed_at=datetime.now().isoformat(),
            total_duration_ms=total_duration,
        )

        self._print_summary()
        return self.report

    async def run_selected(self, module_names: list[str]) -> FullAuditReport:
        """Run specific audit modules."""
        start = time.perf_counter()
        started_at = datetime.now().isoformat()

        for name in module_names:
            if name in self.auditors:
                await self.run_single(name)
            else:
                logger.warning(f"Module '{name}' not available")

        total_duration = (time.perf_counter() - start) * 1000

        self.report = FullAuditReport(
            target_url=self.config.target.url,
            results=self.results,
            global_score=self.score_calculator.get_global_score(),
            global_grade=self.score_calculator.get_global_grade(),
            started_at=started_at,
            completed_at=datetime.now().isoformat(),
            total_duration_ms=total_duration,
        )

        self._print_summary()
        return self.report

    def _print_summary(self) -> None:
        """Print a formatted summary to the console."""
        console.print()

        # Global score
        score = self.score_calculator.get_global_score()
        grade = self.score_calculator.get_global_grade()
        color = "green" if score >= 80 else "yellow" if score >= 60 else "red"

        console.print(
            Panel(
                f"[bold {color}]Score Global: {score:.1f}/100 ({grade})[/bold {color}]",
                title="📊 Résultat",
                border_style=color,
            )
        )

        # Module table
        table = Table(title="Résultats par Module", show_header=True, header_style="bold magenta")
        table.add_column("Module", style="cyan", width=20)
        table.add_column("Score", justify="center", width=12)
        table.add_column("Grade", justify="center", width=8)
        table.add_column("Réussis", justify="center", width=10)
        table.add_column("Échoués", justify="center", width=10)
        table.add_column("Critiques", justify="center", width=10)
        table.add_column("Durée", justify="right", width=10)

        for result in self.results:
            if result.score:
                s = result.score
                s_color = "green" if s.score >= 80 else "yellow" if s.score >= 60 else "red"
                table.add_row(
                    result.module_name,
                    f"[{s_color}]{s.score:.1f}[/{s_color}]",
                    f"[{s_color}]{s.grade}[/{s_color}]",
                    f"[green]{s.passed_checks}[/green]",
                    f"[red]{s.failed_checks}[/red]" if s.failed_checks > 0 else "0",
                    f"[red bold]{s.critical_issues}[/red bold]" if s.critical_issues > 0 else "0",
                    f"{result.duration_ms:.0f}ms",
                )
            elif result.error:
                table.add_row(
                    result.module_name,
                    "[red]Erreur[/red]",
                    "[red]—[/red]",
                    "—", "—", "—",
                    f"{result.duration_ms:.0f}ms",
                )

        console.print(table)

        # Issue summary
        if self.report:
            total_issues = self.report.total_issues
            critical = self.report.critical_count
            high = self.report.high_count

            if critical > 0:
                console.print(f"\n[red bold]⚠️  {critical} problème(s) critique(s) détecté(s) ![/red bold]")
            if high > 0:
                console.print(f"[yellow]⚠️  {high} problème(s) de haute sévérité détecté(s)[/yellow]")

            console.print(
                f"\n[dim]Total: {total_issues} problème(s) — "
                f"Durée: {self.report.total_duration_ms / 1000:.1f}s[/dim]\n"
            )
