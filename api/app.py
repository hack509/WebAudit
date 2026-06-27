"""
FastAPI application factory — WebAudit REST API + dashboard.

Endpoints:
    POST   /api/v1/audit              — launch audit (background task)
    GET    /api/v1/audit/{id}         — poll status + result
    GET    /api/v1/audit/{id}/report  — full JSON report
    GET    /api/v1/history            — last N audits
    GET    /api/v1/health             — liveness probe
    WS     /api/v1/ws/audit/{id}      — real-time audit progress
    GET    /                          — HTML dashboard
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from api.models import HealthResponse
from api.routes.audit import router as audit_router
from api.routes.history import router as history_router
from api.routes.schedule import router as schedule_router, run_scheduler
from api.routes.ws import router as ws_router
from storage.history import init_db

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_VERSION = "1.0.0"


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    """FastAPI lifespan — DB init + background scheduler."""
    import asyncio
    init_db()
    scheduler_task = asyncio.create_task(run_scheduler())
    yield
    scheduler_task.cancel()


def create_app() -> FastAPI:
    app = FastAPI(
        title="WebAudit API",
        description="Audit web accessibility, security, performance and UX at scale.",
        version=_VERSION,
        lifespan=_lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    # Routers
    app.include_router(audit_router, prefix="/api/v1")
    app.include_router(history_router, prefix="/api/v1")
    app.include_router(schedule_router, prefix="/api/v1")
    app.include_router(ws_router, prefix="/api/v1")

    # Health endpoint
    @app.get("/api/v1/health", response_model=HealthResponse, tags=["meta"])
    async def health() -> HealthResponse:
        return HealthResponse(status="ok", version=_VERSION)

    # Dashboard (SPA served from templates/dashboard.html)
    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def dashboard() -> HTMLResponse:
        html = (_TEMPLATE_DIR / "dashboard.html").read_text(encoding="utf-8")
        return HTMLResponse(content=html)

    return app


# Expose the ASGI app directly so uvicorn can import it:
#   uvicorn api.app:app
app = create_app()
