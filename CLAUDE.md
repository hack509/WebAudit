# CLAUDE.md — WebAudit

Project context and conventions for Claude Code sessions.

## Project overview

WebAudit is a Python 3.10+ CLI + REST API tool that audits web applications
across 13 dimensions: security, performance, UX, accessibility, API quality,
mobile, authentication, database config, end-to-end flows, and more.

## Architecture

```
BaseAuditor          — abstract base (audit/base.py)
  └─ 13 concrete auditors (audit/*/auditor.py)
AuditRunner          — orchestrates modules, manages BrowserPool
FullAuditReport      — aggregates results → global score A–F
ReportGenerator      — renders HTML/PDF/JSON/CSV/Markdown
FastAPI app          — REST API + WebSocket + dashboard (api/)
SQLite               — audit history (storage/webaudit.db)
```

## Key conventions

- **HTTP client**: always use `utils/http_client.HttpClient` (sync) or `AsyncHttpClient` (async). Never import `requests` or `aiohttp`.
- **Headers**: always use `CaseInsensitiveDict` for header dicts — httpx returns lowercase, old code used mixed case.
- **Playwright**: never instantiate a browser directly inside an auditor. Check `get_pool()` first; fall back to own browser only for standalone tests.
- **Config**: build order is `profile JSON → config file JSON → CLI args → env vars`. Env vars always win.
- **Tests**: mock HTTP at `auditor.client.get/post/…` level with `unittest.mock.patch`. Never hit live servers. Playwright modules are mocked entirely.
- **No `asyncio` import in runner.py** — it was removed; `await` works without it.

## Common tasks

```bash
# Run the CLI
python main.py --url https://example.com --accept-tos

# Start the API server + dashboard
python main.py --serve

# Run tests
pytest tests/ -v

# Lint
ruff check . && ruff format .

# Add a new auditor
# 1. Create audit/<name>/auditor.py (inherit BaseAuditor)
# 2. Register in audit/runner.py _build_module_map()
# 3. Add tests in tests/test_audit_modules.py
```

## Environment variables (all optional)

| Variable | Purpose |
|---|---|
| `WEBAUDIT_TARGET_URL` | Override target URL |
| `WEBAUDIT_VERBOSE` | `1` = verbose logging |
| `WEBAUDIT_FORMATS` | Comma-separated report formats |
| `WEBAUDIT_API_KEY_REQUIRED` | `1` = enforce X-API-Key on API |
| `WEBAUDIT_API_KEY_FILE` | Path to JSON key store |
| `WEBAUDIT_SLACK_WEBHOOK` | Slack incoming webhook |
| `WEBAUDIT_SMTP_*` | SMTP credentials for email alerts |

## Pitfalls to avoid

- **Don't add `asyncio` import to runner.py** — it's unused since the BrowserPool migration.
- **Don't use `@app.on_event`** — deprecated in FastAPI 0.111; use lifespan context manager.
- **Don't call `list_audits` inside audit routes** — it's in the history router only.
- **Don't store secrets in `config/profiles/*.json`** — profiles are committed; use env vars for secrets.
- **Don't use `requests` or `aiohttp`** — the whole codebase was migrated to `httpx`.

## Test isolation

Tests use `monkeypatch` to redirect `storage.history._DB_PATH` to a temp directory.
Never share a SQLite DB between test cases.
