"""
Unit tests for WebAudit core modules.
"""

import json
import pytest
from pathlib import Path

from config.settings import AuditConfig, TargetConfig, AuthConfig, ReportConfig
from utils.scoring import ScoreCalculator, ModuleScore
from utils.helpers import (
    normalize_url,
    build_url,
    is_same_domain,
    is_valid_url,
    extract_domain,
    truncate,
    sanitize_filename,
    bytes_to_human,
    ms_to_human,
    calculate_contrast_ratio,
    parse_color,
)
from audit.result import AuditFinding, AuditResult, FullAuditReport, Severity


# =============================================================================
# Config Tests
# =============================================================================

class TestAuditConfig:
    """Tests for AuditConfig."""

    def test_default_config(self):
        config = AuditConfig()
        assert config.target.url == "http://localhost:3000"
        assert config.verbose is False
        assert "discovery" in config.modules_enabled

    def test_config_with_url(self):
        config = AuditConfig(target=TargetConfig(url="https://example.com"))
        assert config.target.url == "https://example.com"

    def test_config_with_auth(self):
        config = AuditConfig(auth=AuthConfig(jwt_token="test-token"))
        assert config.auth.jwt_token == "test-token"

    def test_config_from_json(self, tmp_path):
        config_data = {
            "target": {"url": "https://test.com"},
            "report": {"formats": ["json"]},
        }
        config_file = tmp_path / "test_config.json"
        config_file.write_text(json.dumps(config_data))

        config = AuditConfig.from_json(str(config_file))
        assert config.target.url == "https://test.com"
        assert config.report.formats == ["json"]

    def test_config_to_json(self, tmp_path):
        config = AuditConfig(target=TargetConfig(url="https://example.com"))
        output_file = tmp_path / "output_config.json"
        config.to_json(str(output_file))

        assert output_file.exists()
        loaded = json.loads(output_file.read_text())
        assert loaded["target"]["url"] == "https://example.com"


# =============================================================================
# Scoring Tests
# =============================================================================

class TestScoring:
    """Tests for ScoreCalculator."""

    def test_empty_score(self):
        calc = ScoreCalculator()
        assert calc.get_global_score() == 0.0
        assert calc.get_global_grade() == "F"

    def test_perfect_score(self):
        calc = ScoreCalculator()
        calc.add_module_score(ModuleScore(
            module_name="security",
            score=100.0,
            total_checks=10,
            passed_checks=10,
        ))
        assert calc.get_global_score() == 100.0
        assert calc.get_global_grade() == "A"

    def test_module_score_grade(self):
        score = ModuleScore(module_name="test", score=85.0)
        assert score.grade == "B"

        score.score = 45.0
        assert score.grade == "F"

        score.score = 72.0
        assert score.grade == "C"

    def test_calculate_module_score(self):
        calc = ScoreCalculator()
        score = calc.calculate_module_score(
            module_name="test",
            passed=8,
            total=10,
            critical_issues=0,
            warnings=1,
        )
        assert score.score == 78.0  # 80 - 2 (1 warning * 2)
        assert score.grade == "C"

    def test_weighted_global_score(self):
        calc = ScoreCalculator()
        calc.add_module_score(ModuleScore(module_name="security", score=100.0))
        calc.add_module_score(ModuleScore(module_name="performance", score=50.0))

        # security: 20% weight, performance: 15% weight
        # (100 * 0.20 + 50 * 0.15) / (0.20 + 0.15) = (20 + 7.5) / 0.35 = 78.57
        expected = (100 * 0.20 + 50 * 0.15) / (0.20 + 0.15)
        assert abs(calc.get_global_score() - expected) < 0.1

    def test_score_summary(self):
        calc = ScoreCalculator()
        calc.add_module_score(ModuleScore(
            module_name="test",
            score=75.0,
            total_checks=10,
            passed_checks=8,
            failed_checks=2,
        ))
        summary = calc.get_summary()
        assert "global_score" in summary
        assert "modules" in summary
        assert "test" in summary["modules"]


# =============================================================================
# Helpers Tests
# =============================================================================

class TestHelpers:
    """Tests for helper functions."""

    def test_normalize_url(self):
        assert normalize_url("https://example.com/") == "https://example.com/"
        assert normalize_url("https://example.com/path/") == "https://example.com/path"
        assert normalize_url("https://example.com/path#frag") == "https://example.com/path"

    def test_build_url(self):
        assert build_url("https://example.com", "/api/users") == "https://example.com/api/users"
        assert build_url("https://example.com/", "api/users") == "https://example.com/api/users"

    def test_is_same_domain(self):
        assert is_same_domain("https://example.com/page", "https://example.com")
        assert not is_same_domain("https://other.com/page", "https://example.com")

    def test_is_valid_url(self):
        assert is_valid_url("https://example.com")
        assert is_valid_url("http://localhost:3000")
        assert not is_valid_url("not-a-url")
        assert not is_valid_url("")

    def test_extract_domain(self):
        assert extract_domain("https://example.com/path") == "example.com"
        assert extract_domain("http://localhost:3000") == "localhost:3000"

    def test_truncate(self):
        assert truncate("short", 10) == "short"
        assert truncate("a" * 300, 50) == "a" * 47 + "..."

    def test_sanitize_filename(self):
        assert sanitize_filename('file:name<>"test') == "file_name___test"

    def test_bytes_to_human(self):
        assert bytes_to_human(500) == "500.0 B"
        assert bytes_to_human(1500) == "1.5 KB"
        assert bytes_to_human(1500000) == "1.4 MB"

    def test_ms_to_human(self):
        assert ms_to_human(500) == "500ms"
        assert ms_to_human(2500) == "2.5s"
        assert ms_to_human(120000) == "2.0min"

    def test_contrast_ratio(self):
        # Black on white = 21:1
        ratio = calculate_contrast_ratio((0, 0, 0), (255, 255, 255))
        assert abs(ratio - 21.0) < 0.1

        # Same color = 1:1
        ratio = calculate_contrast_ratio((128, 128, 128), (128, 128, 128))
        assert abs(ratio - 1.0) < 0.01

    def test_parse_color(self):
        assert parse_color("#ff0000") == (255, 0, 0)
        assert parse_color("#fff") == (255, 255, 255)
        assert parse_color("rgb(0, 128, 255)") == (0, 128, 255)
        assert parse_color("rgba(0, 128, 255, 0.5)") == (0, 128, 255)
        assert parse_color("invalid") is None


# =============================================================================
# Result Model Tests
# =============================================================================

class TestResultModels:
    """Tests for audit result data models."""

    def test_severity_ordering(self):
        assert Severity.CRITICAL.weight > Severity.HIGH.weight
        assert Severity.HIGH.weight > Severity.MEDIUM.weight
        assert Severity.MEDIUM.weight > Severity.LOW.weight
        assert Severity.LOW.weight > Severity.INFO.weight

    def test_finding_creation(self):
        finding = AuditFinding(
            title="Test Finding",
            description="A test finding",
            severity=Severity.HIGH,
            module="test",
        )
        assert finding.title == "Test Finding"
        assert finding.severity == Severity.HIGH

    def test_finding_to_dict(self):
        finding = AuditFinding(
            title="Test",
            description="Desc",
            severity=Severity.MEDIUM,
            module="test",
            recommendation="Fix it",
        )
        d = finding.to_dict()
        assert d["title"] == "Test"
        assert d["severity"] == "medium"
        assert d["recommendation"] == "Fix it"

    def test_audit_result(self):
        result = AuditResult(
            module_name="test",
            module_description="Test module",
            findings=[
                AuditFinding(title="F1", description="", severity=Severity.CRITICAL),
                AuditFinding(title="F2", description="", severity=Severity.PASS),
                AuditFinding(title="F3", description="", severity=Severity.MEDIUM),
            ],
        )
        assert len(result.critical_findings) == 1
        assert len(result.passed_findings) == 1
        assert len(result.failed_findings) == 2  # critical + medium

    def test_full_report(self):
        report = FullAuditReport(target_url="https://example.com")
        assert report.total_issues == 0
        assert report.critical_count == 0

        result = AuditResult(
            module_name="test",
            module_description="Test",
            findings=[
                AuditFinding(title="Critical", description="", severity=Severity.CRITICAL),
                AuditFinding(title="Pass", description="", severity=Severity.PASS),
            ],
        )
        report.results.append(result)

        assert report.total_issues == 1
        assert report.critical_count == 1

    def test_full_report_to_dict(self):
        report = FullAuditReport(target_url="https://example.com")
        d = report.to_dict()
        assert d["target_url"] == "https://example.com"
        assert "modules" in d
        assert "global_score" in d
