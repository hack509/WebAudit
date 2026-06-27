# WebAudit

**Professional web application auditing tool** — security, performance, accessibility, UX and API quality in a single command.

## Features

| Module | What it checks |
|---|---|
| Discovery | Sitemap crawl, page inventory |
| Backend | HTTP headers, CORS, compression, HSTS |
| API | REST endpoints, auth schemes, rate limiting |
| Security | XSS, SQL injection, exposed secrets, CSP |
| Performance | TTFB, asset sizes, caching headers |
| UX | Readability, contrast, responsive design |
| JavaScript | Console errors, third-party scripts, CSP violations |
| Mobile | Viewport, touch targets, font scaling |
| Auth | JWT, session management, 2FA hints |
| Database | Connection string safety, injection vectors |
| E2E | Full browser flows via Playwright |
| Screenshots | Automated page captures |

## Quick start

```bash
# Install
python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # macOS/Linux
pip install -r requirements.txt
playwright install chromium

# Interactive mode
python main.py

# CLI — single target
python main.py --url https://example.com --accept-tos

# Multi-target parallel
python main.py --urls https://a.com https://b.com --accept-tos

# Use a config profile
python main.py --url https://staging.example.com --profile staging --accept-tos

# REST API + dashboard
python main.py --serve
# → http://localhost:8000/        dashboard
# → http://localhost:8000/api/docs  Swagger UI
```

## REST API

```bash
# Start server
python main.py --serve --port 8000

# Launch an audit
curl -X POST http://localhost:8000/api/v1/audit \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
# → {"task_id": "...", "status": "pending", ...}

# Poll for completion
curl http://localhost:8000/api/v1/audit/{task_id}

# Get full report
curl http://localhost:8000/api/v1/audit/{task_id}/report

# Audit history
curl http://localhost:8000/api/v1/history
```

## Configuration

### Config profiles (`config/profiles/`)

| Profile | Use case |
|---|---|
| `dev` | Local development — fast, verbose, low delay |
| `staging` | Pre-production — balanced depth |
| `prod` | Production — cautious, no injection tests |
| `ci` | CI/CD — JSON only, deterministic |

```bash
python main.py --url http://localhost:3000 --profile dev --accept-tos
```

### Environment variables

| Variable | Description |
|---|---|
| `WEBAUDIT_TARGET_URL` | Override target URL |
| `WEBAUDIT_VERBOSE` | `1` to enable verbose output |
| `WEBAUDIT_REPORT_FORMATS` | Comma-separated: `html,json,csv` |
| `WEBAUDIT_SLACK_WEBHOOK` | Slack incoming webhook URL |
| `WEBAUDIT_SMTP_TO` | Email recipients (comma-separated) |
| `WEBAUDIT_SMTP_HOST` | SMTP server host |
| `WEBAUDIT_SMTP_PORT` | SMTP server port (default: 587) |
| `WEBAUDIT_SMTP_USER` | SMTP username |
| `WEBAUDIT_SMTP_PASSWORD` | SMTP password |

### Docker

```bash
docker build -t webaudit .
docker run --rm -v $(pwd)/reports:/app/reports \
  webaudit python main.py --url https://example.com --accept-tos
```

## Notifications

Alert when the audit score drops below a threshold:

```bash
# Via API
curl -X POST http://localhost:8000/api/v1/audit \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "score_threshold": 70,
    "slack_webhook": "https://hooks.slack.com/services/...",
    "email_to": ["team@example.com"]
  }'
```

## Plugin system

Register custom audit modules as Python package entry points:

```toml
# your_package/pyproject.toml
[project.entry-points."webaudit.auditors"]
my_module = "your_package.auditors:MyAuditor"
```

Your auditor must inherit from `audit.base.BaseAuditor` and implement `async def run(self) -> AuditResult`.

## Development

```bash
# Install dev extras
pip install -e ".[dev]"

# Run tests
pytest tests/ -v --cov=.

# Lint + format
ruff check . && ruff format .
mypy .

# Pre-commit hooks
pre-commit install
```

## License

MIT — see [LICENSE](LICENSE)
