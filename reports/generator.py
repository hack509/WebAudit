"""
Report Generator — Module 14.

Orchestrates report generation in all formats: HTML, PDF, JSON, CSV, Markdown.
Supports bilingual output (FR/EN).
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from audit.result import FullAuditReport
from config.settings import ReportConfig
from utils.logger import get_logger

logger = get_logger("reports")


class ReportGenerator:
    """Orchestrates generation of audit reports in multiple formats."""

    def __init__(self, config: ReportConfig):
        self.config = config
        self.output_dir = Path(config.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.generated_files: list[str] = []

    def generate_all(self, report: FullAuditReport) -> list[str]:
        """Generate reports in all configured formats."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        for fmt in self.config.formats:
            try:
                if fmt == "html":
                    path = self._generate_html(report, timestamp)
                elif fmt == "pdf":
                    path = self._generate_pdf(report, timestamp)
                elif fmt == "json":
                    path = self._generate_json(report, timestamp)
                elif fmt == "csv":
                    path = self._generate_csv(report, timestamp)
                elif fmt == "markdown" or fmt == "md":
                    path = self._generate_markdown(report, timestamp)
                else:
                    logger.warning(f"Unknown report format: {fmt}")
                    continue

                if path:
                    self.generated_files.append(path)
                    logger.info(f"Report generated: {path}")

            except Exception as e:
                logger.error(f"Failed to generate {fmt} report: {e}")

        return self.generated_files

    def _generate_json(self, report: FullAuditReport, timestamp: str) -> str:
        """Generate JSON report."""
        import json

        filepath = self.output_dir / f"audit_report_{timestamp}.json"
        data = report.to_dict()

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)

        return str(filepath)

    def _generate_csv(self, report: FullAuditReport, timestamp: str) -> str:
        """Generate CSV report."""
        import csv

        filepath = self.output_dir / f"audit_report_{timestamp}.csv"

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Module", "Severity", "Title", "Description",
                "URL", "Recommendation", "Timestamp",
            ])

            for finding in report.all_findings:
                writer.writerow([
                    finding.module,
                    finding.severity.value,
                    finding.title,
                    finding.description,
                    finding.url,
                    finding.recommendation,
                    finding.timestamp,
                ])

        return str(filepath)

    def _generate_markdown(self, report: FullAuditReport, timestamp: str) -> str:
        """Generate Markdown report."""
        lang = self.config.language
        filepath = self.output_dir / f"audit_report_{timestamp}.md"

        lines = []
        title = "Rapport d'Audit Web" if lang == "fr" else "Web Audit Report"
        lines.append(f"# {title}")
        lines.append("")
        lines.append(f"**{'Cible' if lang == 'fr' else 'Target'}:** {report.target_url}")
        lines.append(f"**Date:** {report.started_at}")
        lines.append(f"**{'Durée' if lang == 'fr' else 'Duration'}:** {report.total_duration_ms / 1000:.1f}s")
        lines.append("")

        # Global score
        lines.append(f"## {'Score Global' if lang == 'fr' else 'Global Score'}")
        lines.append("")
        lines.append(f"**{report.global_score:.1f}/100 ({report.global_grade})**")
        lines.append("")

        # Summary
        lines.append(f"## {'Résumé' if lang == 'fr' else 'Summary'}")
        lines.append("")
        lines.append(f"| {'Métrique' if lang == 'fr' else 'Metric'} | {'Valeur' if lang == 'fr' else 'Value'} |")
        lines.append("|---|---|")
        lines.append(f"| {'Problèmes critiques' if lang == 'fr' else 'Critical Issues'} | {report.critical_count} |")
        lines.append(f"| {'Problèmes élevés' if lang == 'fr' else 'High Issues'} | {report.high_count} |")
        lines.append(f"| {'Total problèmes' if lang == 'fr' else 'Total Issues'} | {report.total_issues} |")
        lines.append("")

        # Module results
        lines.append(f"## {'Résultats par Module' if lang == 'fr' else 'Results by Module'}")
        lines.append("")
        lines.append(f"| Module | Score | Grade | {'Réussis' if lang == 'fr' else 'Passed'} | {'Échoués' if lang == 'fr' else 'Failed'} |")
        lines.append("|---|---|---|---|---|")

        for result in report.results:
            if result.score:
                s = result.score
                lines.append(f"| {result.module_name} | {s.score:.1f} | {s.grade} | {s.passed_checks} | {s.failed_checks} |")

        lines.append("")

        # Findings by severity
        for severity_label, findings in [
            ("🔴 " + ("Critique" if lang == "fr" else "Critical"),
             [f for f in report.all_findings if f.severity.value == "critical"]),
            ("🟠 " + ("Élevé" if lang == "fr" else "High"),
             [f for f in report.all_findings if f.severity.value == "high"]),
            ("🟡 " + ("Moyen" if lang == "fr" else "Medium"),
             [f for f in report.all_findings if f.severity.value == "medium"]),
            ("🔵 " + ("Faible" if lang == "fr" else "Low"),
             [f for f in report.all_findings if f.severity.value == "low"]),
        ]:
            if findings:
                lines.append(f"### {severity_label} ({len(findings)})")
                lines.append("")
                for f in findings:
                    lines.append(f"- **{f.title}**: {f.description}")
                    if f.recommendation:
                        rec_label = "Recommandation" if lang == "fr" else "Recommendation"
                        lines.append(f"  - *{rec_label}:* {f.recommendation}")
                lines.append("")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        return str(filepath)

    def _generate_html(self, report: FullAuditReport, timestamp: str) -> str:
        """Generate HTML report with embedded CSS."""
        lang = self.config.language
        filepath = self.output_dir / f"audit_report_{timestamp}.html"

        t = _T(lang)

        # Build findings HTML
        findings_html = ""
        severity_groups = [
            ("critical", t("Critique", "Critical"), "#e74c3c"),
            ("high", t("Élevé", "High"), "#e67e22"),
            ("medium", t("Moyen", "Medium"), "#f39c12"),
            ("low", t("Faible", "Low"), "#3498db"),
        ]

        for sev_value, sev_label, color in severity_groups:
            findings = [f for f in report.all_findings if f.severity.value == sev_value]
            if not findings:
                continue

            findings_html += f'<h3 style="color:{color};margin-top:2em;">{sev_label} ({len(findings)})</h3>\n'
            for f in findings:
                rec_html = f'<p class="recommendation">💡 {f.recommendation}</p>' if f.recommendation else ""
                url_html = f'<p class="url">🔗 <a href="{f.url}">{f.url}</a></p>' if f.url else ""
                findings_html += f"""
                <div class="finding" style="border-left:4px solid {color};">
                    <h4>{f.title}</h4>
                    <p>{f.description}</p>
                    {url_html}
                    {rec_html}
                    <span class="badge" style="background:{color};">{f.module}</span>
                </div>
                """

        # Module table rows
        module_rows = ""
        for result in report.results:
            if result.score:
                s = result.score
                color = "#27ae60" if s.score >= 80 else "#f39c12" if s.score >= 60 else "#e74c3c"
                module_rows += f"""
                <tr>
                    <td>{result.module_name}</td>
                    <td style="color:{color};font-weight:bold;">{s.score:.1f}</td>
                    <td style="color:{color};font-weight:bold;">{s.grade}</td>
                    <td>{s.passed_checks}</td>
                    <td style="color:#e74c3c;">{s.failed_checks}</td>
                    <td style="color:#e74c3c;font-weight:bold;">{s.critical_issues}</td>
                </tr>
                """

        score_color = "#27ae60" if report.global_score >= 80 else "#f39c12" if report.global_score >= 60 else "#e74c3c"

        html = f"""<!DOCTYPE html>
<html lang="{lang}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebAudit — {t("Rapport d'Audit", "Audit Report")}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: #0f1117; color: #e1e5ee; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 2em; }}
        header {{ background: linear-gradient(135deg, #1a1d2e 0%, #2d1b69 100%); padding: 3em 2em; text-align: center; border-bottom: 3px solid #6c5ce7; }}
        header h1 {{ font-size: 2.5em; color: #a29bfe; margin-bottom: 0.3em; }}
        header p {{ color: #b2bec3; font-size: 1.1em; }}
        .score-card {{ background: linear-gradient(135deg, #1e2235 0%, #252a40 100%); border-radius: 16px; padding: 2em; margin: 2em 0; text-align: center; border: 1px solid rgba(108,92,231,0.3); }}
        .score-value {{ font-size: 5em; font-weight: 800; color: {score_color}; }}
        .score-grade {{ font-size: 2em; color: {score_color}; margin-top: 0.2em; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1em; margin: 2em 0; }}
        .stat {{ background: #1e2235; padding: 1.5em; border-radius: 12px; text-align: center; border: 1px solid rgba(255,255,255,0.05); }}
        .stat-value {{ font-size: 2em; font-weight: 700; }}
        .stat-label {{ color: #636e72; margin-top: 0.3em; }}
        table {{ width: 100%; border-collapse: collapse; margin: 1em 0; }}
        th {{ background: #1a1d2e; color: #a29bfe; padding: 12px 16px; text-align: left; font-weight: 600; }}
        td {{ padding: 10px 16px; border-bottom: 1px solid rgba(255,255,255,0.05); }}
        tr:hover {{ background: rgba(108,92,231,0.08); }}
        h2 {{ color: #a29bfe; margin-top: 2em; margin-bottom: 0.5em; font-size: 1.6em; }}
        h3 {{ margin-top: 1.5em; }}
        .finding {{ background: #1e2235; padding: 1.2em; margin: 0.8em 0; border-radius: 8px; }}
        .finding h4 {{ color: #dfe6e9; margin-bottom: 0.3em; }}
        .finding p {{ color: #b2bec3; font-size: 0.95em; }}
        .recommendation {{ color: #00cec9 !important; margin-top: 0.5em; font-style: italic; }}
        .url {{ margin-top: 0.3em; }}
        .url a {{ color: #74b9ff; text-decoration: none; }}
        .badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px; color: #fff; font-size: 0.8em; margin-top: 0.5em; }}
        footer {{ text-align: center; padding: 2em; color: #636e72; border-top: 1px solid rgba(255,255,255,0.05); margin-top: 3em; }}
    </style>
</head>
<body>
    <header>
        <h1>🔍 WebAudit</h1>
        <p>{t("Rapport d'Audit Web", "Web Audit Report")}</p>
        <p style="margin-top:0.5em;">{report.target_url}</p>
        <p style="color:#636e72;margin-top:0.5em;">{report.started_at}</p>
    </header>

    <div class="container">
        <div class="score-card">
            <div class="score-value">{report.global_score:.1f}</div>
            <div class="score-grade">{t("Note", "Grade")}: {report.global_grade}</div>
        </div>

        <div class="stats">
            <div class="stat">
                <div class="stat-value" style="color:#e74c3c;">{report.critical_count}</div>
                <div class="stat-label">{t("Critiques", "Critical")}</div>
            </div>
            <div class="stat">
                <div class="stat-value" style="color:#e67e22;">{report.high_count}</div>
                <div class="stat-label">{t("Élevés", "High")}</div>
            </div>
            <div class="stat">
                <div class="stat-value" style="color:#f39c12;">{report.total_issues}</div>
                <div class="stat-label">{t("Total Problèmes", "Total Issues")}</div>
            </div>
            <div class="stat">
                <div class="stat-value" style="color:#b2bec3;">{report.total_duration_ms/1000:.1f}s</div>
                <div class="stat-label">{t("Durée", "Duration")}</div>
            </div>
        </div>

        <h2>{t("Résultats par Module", "Results by Module")}</h2>
        <table>
            <thead>
                <tr>
                    <th>Module</th>
                    <th>Score</th>
                    <th>Grade</th>
                    <th>{t("Réussis", "Passed")}</th>
                    <th>{t("Échoués", "Failed")}</th>
                    <th>{t("Critiques", "Critical")}</th>
                </tr>
            </thead>
            <tbody>
                {module_rows}
            </tbody>
        </table>

        <h2>{t("Détail des Problèmes", "Issue Details")}</h2>
        {findings_html}
    </div>

    <footer>
        <p>WebAudit v1.0 — {t("Généré le", "Generated on")} {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </footer>
</body>
</html>"""

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        return str(filepath)

    def _generate_pdf(self, report: FullAuditReport, timestamp: str) -> Optional[str]:
        """Generate PDF report."""
        try:
            from fpdf import FPDF
        except ImportError:
            logger.warning("fpdf2 not installed — skipping PDF generation")
            return None

        lang = self.config.language
        filepath = self.output_dir / f"audit_report_{timestamp}.pdf"
        t = _T(lang)

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)

        # Title page
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 28)
        pdf.cell(0, 40, "WebAudit", ln=True, align="C")
        pdf.set_font("Helvetica", "", 16)
        pdf.cell(0, 10, t("Rapport d'Audit Web", "Web Audit Report"), ln=True, align="C")
        pdf.ln(10)

        pdf.set_font("Helvetica", "", 12)
        pdf.cell(0, 8, f"{t('Cible', 'Target')}: {report.target_url}", ln=True)
        pdf.cell(0, 8, f"Date: {report.started_at}", ln=True)
        pdf.cell(0, 8, f"Score: {report.global_score:.1f}/100 ({report.global_grade})", ln=True)
        pdf.cell(0, 8, f"{t('Problemes', 'Issues')}: {report.total_issues} ({report.critical_count} {t('critiques', 'critical')})", ln=True)
        pdf.ln(10)

        # Module table
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 12, t("Resultats par Module", "Results by Module"), ln=True)
        pdf.ln(5)

        pdf.set_font("Helvetica", "B", 10)
        col_widths = [40, 25, 20, 25, 25, 25]
        headers = ["Module", "Score", "Grade", t("Reussis", "Passed"), t("Echoues", "Failed"), t("Critiques", "Critical")]
        for i, header in enumerate(headers):
            pdf.cell(col_widths[i], 8, header, border=1)
        pdf.ln()

        pdf.set_font("Helvetica", "", 10)
        for result in report.results:
            if result.score:
                s = result.score
                pdf.cell(col_widths[0], 7, result.module_name[:20], border=1)
                pdf.cell(col_widths[1], 7, f"{s.score:.1f}", border=1)
                pdf.cell(col_widths[2], 7, s.grade, border=1)
                pdf.cell(col_widths[3], 7, str(s.passed_checks), border=1)
                pdf.cell(col_widths[4], 7, str(s.failed_checks), border=1)
                pdf.cell(col_widths[5], 7, str(s.critical_issues), border=1)
                pdf.ln()

        pdf.ln(10)

        # Findings
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 12, t("Problemes Detectes", "Issues Found"), ln=True)
        pdf.ln(5)

        for finding in report.all_findings:
            if finding.severity.value in ("pass", "info"):
                continue

            pdf.set_font("Helvetica", "B", 10)
            severity_label = finding.severity.value.upper()
            title_text = f"[{severity_label}] {finding.title}"
            pdf.multi_cell(0, 6, title_text[:90])

            pdf.set_font("Helvetica", "", 9)
            pdf.multi_cell(0, 5, finding.description[:200])

            if finding.recommendation:
                pdf.set_font("Helvetica", "I", 9)
                rec_text = f"{t('Recommandation', 'Recommendation')}: {finding.recommendation}"
                pdf.multi_cell(0, 5, rec_text[:200])

            pdf.ln(3)

            if pdf.get_y() > 270:
                pdf.add_page()

        pdf.output(str(filepath))
        return str(filepath)


class _T:
    """Simple bilingual text helper."""

    def __init__(self, lang: str = "fr"):
        self.lang = lang

    def __call__(self, fr: str, en: str) -> str:
        return fr if self.lang == "fr" else en
