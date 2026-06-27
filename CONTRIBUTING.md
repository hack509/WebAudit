# Contributing to WebAudit

## Quick start

```bash
git clone https://github.com/hack509/webAudit.git
cd webAudit
python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate       # macOS/Linux
pip install -e ".[dev]"
playwright install chromium
pre-commit install
```

## Project layout

```
audit/          — 13 audit modules (one subdirectory each)
api/            — FastAPI REST API + WebSocket + dashboard
config/         — Pydantic settings, config profiles
notifications/  — Slack + email alert channels
reports/        — HTML/PDF/JSON/CSV/Markdown report generator
storage/        — SQLite persistence layer
tests/          — pytest test suite
utils/          — HTTP client, logger, helpers, plugin loader
main.py         — CLI entry point
```

## Adding an audit module

1. Create `audit/<name>/` with `__init__.py` and `auditor.py`.
2. Inherit from `BaseAuditor` and implement `async def run(self) -> AuditResult`.
3. Set `MODULE_NAME` and `MODULE_DESCRIPTION` class attributes.
4. Register in `audit/runner.py → _build_module_map()`.
5. Add at least 3 tests in `tests/test_audit_modules.py`.

```python
from audit.base import BaseAuditor
from audit.result import AuditResult, Severity

class MyAuditor(BaseAuditor):
    MODULE_NAME = "my_module"
    MODULE_DESCRIPTION = "My custom audit"

    async def run(self) -> AuditResult:
        resp = self.client.get(self._base_url)
        if resp.status_code != 200:
            self.add_finding("Site unreachable", "", Severity.CRITICAL)
        else:
            self.pass_check("Site reachable", "HTTP 200 OK")
        return self.build_result()
```

## Adding a notification channel

1. Create `notifications/<channel>.py`.
2. Inherit from `BaseNotifier` and implement `async def send(self, payload: NotificationPayload) -> None`.
3. Wire it up in `api/routes/audit.py → _maybe_alert()`.

## Running tests

```bash
pytest tests/ -v --cov=. --cov-report=term-missing
```

Playwright tests are skipped automatically if Chromium is not installed.
Mock HTTP responses with `unittest.mock.patch` — never hit live servers in tests.

## Code style

```bash
ruff check . && ruff format .
mypy . --ignore-missing-imports
```

All PRs must pass `ruff`, `mypy`, and the full test suite on Python 3.10, 3.11, and 3.12.

## Pull request checklist

- [ ] Tests added or updated for every changed module
- [ ] `ruff` and `mypy` pass with no new errors
- [ ] CHANGELOG.md updated under `[Unreleased]`
- [ ] No secrets or real URLs committed

## Commit style

```
feat: add GraphQL endpoint auditor
fix: correct CORS wildcard detection after httpx migration
docs: translate README to English
```

## Reporting bugs

Open an issue with:
- Python version (`python --version`)
- WebAudit version (`python main.py --version`)
- Minimal reproduction steps
- Full traceback from `logs/`
