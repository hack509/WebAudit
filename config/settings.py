"""
WebAudit Configuration Settings.

Defines all configuration models using Pydantic for type safety and validation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field, HttpUrl


class TargetConfig(BaseModel):
    """Target application configuration."""

    url: str = Field(default="http://localhost:3000", description="Base URL of the target application")
    source_dir: Optional[str] = Field(default=None, description="Path to source code directory")
    api_base: Optional[str] = Field(default=None, description="API base path (e.g., /api/v1)")


class AuthConfig(BaseModel):
    """Authentication configuration."""

    jwt_token: Optional[str] = Field(default=None, description="JWT token for authenticated requests")
    username: Optional[str] = Field(default=None, description="Username for login tests")
    password: Optional[str] = Field(default=None, description="Password for login tests")
    login_url: Optional[str] = Field(default=None, description="Login endpoint URL")
    oauth_client_id: Optional[str] = Field(default=None, description="OAuth client ID")
    oauth_client_secret: Optional[str] = Field(default=None, description="OAuth client secret")


class DatabaseConfig(BaseModel):
    """Database configuration for DB auditing."""

    connection_string: Optional[str] = Field(default=None, description="Database connection string")
    db_type: Optional[str] = Field(default=None, description="Database type: postgres, mysql, sqlite")


class PerformanceConfig(BaseModel):
    """Performance thresholds."""

    max_response_time_ms: int = Field(default=3000, description="Max acceptable response time in ms")
    max_page_load_ms: int = Field(default=5000, description="Max acceptable page load time in ms")
    max_bundle_size_kb: int = Field(default=500, description="Max acceptable JS/CSS bundle size in KB")
    max_image_size_kb: int = Field(default=200, description="Max acceptable image size in KB")
    lcp_threshold_ms: float = Field(default=2500, description="LCP threshold in ms")
    cls_threshold: float = Field(default=0.1, description="CLS threshold")
    fid_threshold_ms: float = Field(default=100, description="FID threshold in ms")
    ttfb_threshold_ms: float = Field(default=800, description="TTFB threshold in ms")


class SecurityConfig(BaseModel):
    """Security audit configuration."""

    test_injections: bool = Field(default=True, description="Test SQL/NoSQL/XSS injections")
    test_csrf: bool = Field(default=True, description="Test CSRF vulnerabilities")
    test_headers: bool = Field(default=True, description="Test security headers")
    custom_payloads_file: Optional[str] = Field(default=None, description="Path to custom payloads file")
    max_injection_tests: int = Field(default=50, description="Max injection test iterations")


class ReportConfig(BaseModel):
    """Report generation configuration."""

    output_dir: str = Field(default="reports", description="Output directory for reports")
    formats: list[str] = Field(default=["html", "json"], description="Report formats to generate")
    include_screenshots: bool = Field(default=True, description="Include screenshots in reports")
    include_recommendations: bool = Field(default=True, description="Include fix recommendations")
    language: str = Field(default="fr", description="Report language: fr, en")


class CrawlConfig(BaseModel):
    """Crawling configuration."""

    max_pages: int = Field(default=100, description="Maximum number of pages to crawl")
    max_depth: int = Field(default=5, description="Maximum crawl depth")
    follow_external: bool = Field(default=False, description="Follow external links")
    respect_robots: bool = Field(default=True, description="Respect robots.txt")
    request_delay_ms: int = Field(default=100, description="Delay between requests in ms")
    timeout_s: int = Field(default=30, description="Request timeout in seconds")
    user_agent: str = Field(
        default="WebAudit/1.0 (Automated Security & Quality Scanner)",
        description="User-Agent header",
    )


class AuditConfig(BaseModel):
    """Main audit configuration — aggregates all sub-configs."""

    target: TargetConfig = Field(default_factory=TargetConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    performance: PerformanceConfig = Field(default_factory=PerformanceConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    crawl: CrawlConfig = Field(default_factory=CrawlConfig)

    # Module toggles
    modules_enabled: list[str] = Field(
        default=[
            "discovery",
            "backend",
            "api",
            "frontend",
            "security",
            "performance",
            "ux",
            "javascript",
            "auth",
            "mobile",
            "screenshots",
        ],
        description="List of enabled audit modules",
    )

    verbose: bool = Field(default=False, description="Enable verbose output")

    @classmethod
    def from_json(cls, path: str | Path) -> "AuditConfig":
        """Load configuration from a JSON file."""
        config_path = Path(path)
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(**data)

    def to_json(self, path: str | Path) -> None:
        """Save configuration to a JSON file."""
        config_path = Path(path)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(self.model_dump(), f, indent=2, ensure_ascii=False)
