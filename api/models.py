"""Pydantic request/response models for the WebAudit REST API."""

from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, HttpUrl, Field


class AuditRequest(BaseModel):
    """Body for POST /api/v1/audit."""
    url: str = Field(..., description="Target URL to audit")
    modules: Optional[list[str]] = Field(default=None, description="Specific modules to run (omit for all)")
    profile: Optional[str] = Field(default=None, description="Config profile: dev | staging | prod | ci")
    jwt_token: Optional[str] = Field(default=None, description="JWT token for authenticated requests")
    username: Optional[str] = None
    password: Optional[str] = None
    formats: list[str] = Field(default=["json"], description="Report output formats")
    language: str = Field(default="fr", description="Report language: fr | en")
    score_threshold: Optional[float] = Field(
        default=None,
        description="Alert threshold — send notifications if score drops below this value",
    )
    slack_webhook: Optional[str] = Field(default=None, description="Slack webhook URL for score alerts")
    email_to: Optional[list[str]] = Field(default=None, description="Email recipients for score alerts")


class AuditTaskResponse(BaseModel):
    """Response for POST /api/v1/audit."""
    task_id: str
    status: str
    url: str
    message: str


class AuditStatusResponse(BaseModel):
    """Response for GET /api/v1/audit/{task_id}."""
    task_id: str
    url: str
    status: str
    started_at: str
    completed_at: Optional[str] = None
    global_score: Optional[float] = None
    global_grade: Optional[str] = None
    total_issues: Optional[int] = None
    critical_count: Optional[int] = None
    high_count: Optional[int] = None
    error: Optional[str] = None


class HistoryResponse(BaseModel):
    """Response for GET /api/v1/history."""
    total: int
    audits: list[dict]


class HealthResponse(BaseModel):
    status: str
    version: str
