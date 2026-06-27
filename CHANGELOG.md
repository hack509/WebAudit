# Changelog

All notable changes to WebAudit are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and
this project adheres to [Semantic Versioning](https://semver.org/).

---

## [1.1.0] — 2026-06-27

### Added

#### Phase 4 — Hardening & Production
- **API key auth** (`api/auth.py`): `X-API-Key` header via `WEBAUDIT_API_KEY_REQUIRED` + `storage/api_keys.json`
- **WebSocket progress** (`api/routes/ws.py`): `WS /api/v1/ws/audit/{id}` streams module-level events in real time
- **Scheduled audits** (`api/routes/schedule.py`): `POST/GET/DELETE /api/v1/schedule` + cron loop started at lifespan
- **Test suite extended** (`tests/test_audit_modules.py`): 43 new tests — security, performance, frontend, API, auth, discovery, storage, notifications, FastAPI routes, plugin loader
- **CONTRIBUTING.md**: dev setup, auditor/notifier extension guide, PR checklist
- **CLAUDE.md**: project context, conventions, common pitfalls for AI-assisted sessions

### Fixed
- `asyncio.get_event_loop()` → `asyncio.run()` in tests (Python 3.14 compat)
- FastAPI `@app.on_event` → `asynccontextmanager` lifespan
- `_run_audit_task` background task mocked in API route tests to prevent real network calls
- `audit.discovery` import path (`detector.py`, not `auditor.py`)
- `time.perf_counter` patched correctly for TTFB timing tests

---

## [1.0.0] — 2026-06-27

### Added

#### Phase 3 — Product evolution
- **Plugin system** (`utils/plugin_loader.py`): third-party auditors via `entry_points("webaudit.auditors")`
- **REST API** (`api/`): FastAPI app with `POST /api/v1/audit`, `GET /api/v1/audit/{id}`, `GET /api/v1/history`
- **Dashboard web** (`api/templates/dashboard.html`): dark-mode SPA, real-time polling, score bars, history table
- **Slack notifications** (`notifications/slack.py`): Block Kit message on score threshold breach
- **Email notifications** (`notifications/email.py`): HTML email via SMTP on score threshold breach
- **Multi-target mode** (`--urls`): parallel audits via `asyncio.gather`
- **API server mode** (`--serve`): `python main.py --serve` launches uvicorn
- **SQLite history** (`storage/history.py`): persistent audit history across sessions
- **English documentation** (`README.en.md`)

#### Phase 2 — Consolidation
- **httpx** replaces requests + aiohttp (unified sync/async HTTP client)
- **BrowserPool** (`utils/playwright_pool.py`): single shared Playwright browser across all 4 modules
- **HTTP cache** in `AsyncHttpClient`: TTL-based GET response cache with ETag support
- **RateLimiter** (`utils/http_client.py`): token-bucket with exponential back-off on HTTP 429
- **CaseInsensitiveDict**: case-insensitive header dict compatible with httpx
- **Config profiles** (`config/profiles/`): dev / staging / prod / ci JSON profiles
- **Environment variable overrides** (`WEBAUDIT_*`): highest-priority config layer
- **pre-commit** (`.pre-commit-config.yaml`): ruff, mypy, trailing-whitespace, json/yaml validators
- **Test suite** (`tests/test_auditors.py`): 31 tests — HTTP client, auditors, config, Playwright pool

#### Phase 1 — Foundations
- **pyproject.toml**: PEP 517/518, replaces setup.py; optional `[dev]` extras
- **CI/CD** (`.github/workflows/ci.yml`): lint, test matrix (3.10/3.11/3.12), pip-audit security scan
- **Dockerfile**: multi-stage build, non-root user, Playwright deps
- **Legal disclaimer**: `show_legal_disclaimer()` + `--accept-tos` flag for CI
- **Connection string validator**: reject non-whitelisted DB schemes in `DatabaseConfig`

### Changed
- `requirements.txt`: pinned all versions; removed `requests`, `aiohttp`; added `httpx==0.27.2`, `fastapi==0.111.0`, `uvicorn==0.30.1`
- `audit/runner.py`: `BrowserPool` lifecycle + external plugin registration
- `main.py`: `build_config()` priority chain (profile → JSON → CLI → env); `--profile`, `--urls`, `--serve` flags

### Fixed
- Header case-sensitivity bug in `BackendAuditor._check_cors()` after migration to httpx
- Playwright cold-start × 4 — replaced with single shared `BrowserPool`
- Unused `asyncio` import in `audit/runner.py`
- Broken indentation in `audit/javascript/auditor.py` after partial Edit

---

## [0.1.0] — initial

Initial project with 13 audit modules, Rich CLI, Pydantic v2 config, HTML/PDF/JSON/CSV report generation.
