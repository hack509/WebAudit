"""
Constants for WebAudit.

Shared constants used across all audit modules.
"""

# Application info
APP_NAME = "WebAudit"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = "Professional Web Application Auditing Tool"

# Default viewports
VIEWPORTS = {
    "desktop": {"width": 1920, "height": 1080},
    "tablet": {"width": 768, "height": 1024},
    "mobile": {"width": 375, "height": 812},
}

# Common user agents
USER_AGENTS = {
    "desktop": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "mobile": (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
    ),
    "tablet": (
        "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
    ),
    "bot": "WebAudit/1.0 (Automated Security & Quality Scanner)",
}

# Security headers to check
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "HSTS - Force HTTPS connections",
        "severity": "high",
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header",
    },
    "Content-Security-Policy": {
        "description": "CSP - Prevent XSS and injection attacks",
        "severity": "high",
        "recommendation": "Implement a Content Security Policy header",
    },
    "X-Content-Type-Options": {
        "description": "Prevent MIME-type sniffing",
        "severity": "medium",
        "recommendation": "Add 'X-Content-Type-Options: nosniff' header",
    },
    "X-Frame-Options": {
        "description": "Prevent clickjacking",
        "severity": "medium",
        "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header",
    },
    "X-XSS-Protection": {
        "description": "XSS filter (legacy browsers)",
        "severity": "low",
        "recommendation": "Add 'X-XSS-Protection: 1; mode=block' header",
    },
    "Referrer-Policy": {
        "description": "Control referrer information",
        "severity": "low",
        "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header",
    },
    "Permissions-Policy": {
        "description": "Control browser features",
        "severity": "low",
        "recommendation": "Add Permissions-Policy header to restrict browser features",
    },
    "X-Permitted-Cross-Domain-Policies": {
        "description": "Control cross-domain policies",
        "severity": "low",
        "recommendation": "Add 'X-Permitted-Cross-Domain-Policies: none' header",
    },
}

# Cookie security attributes to check
COOKIE_SECURITY_FLAGS = {
    "Secure": {
        "description": "Cookie sent only over HTTPS",
        "severity": "high",
    },
    "HttpOnly": {
        "description": "Cookie not accessible via JavaScript",
        "severity": "high",
    },
    "SameSite": {
        "description": "CSRF protection via SameSite attribute",
        "severity": "medium",
    },
}

# SQL Injection payloads (safe testing)
SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "1; DROP TABLE users --",
    "' UNION SELECT NULL --",
    "1' AND '1'='1",
    "admin'--",
    "' OR 1=1 --",
    "'; EXEC xp_cmdshell('dir') --",
    "1 AND 1=1",
]

# XSS payloads (safe testing)
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    '<img src=x onerror=alert("XSS")>',
    "<svg onload=alert('XSS')>",
    '"><script>alert("XSS")</script>',
    "javascript:alert('XSS')",
    "<iframe src='javascript:alert(1)'>",
    "';alert('XSS');//",
    "<body onload=alert('XSS')>",
    '<input onfocus=alert("XSS") autofocus>',
    "{{7*7}}",  # SSTI
]

# NoSQL Injection payloads
NOSQL_INJECTION_PAYLOADS = [
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$regex": ".*"}',
    "true, $where: '1 == 1'",
    '{"$or": [{"a": 1}, {"b": 2}]}',
]

# Directory traversal payloads
DIRECTORY_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
]

# Open redirect payloads
OPEN_REDIRECT_PAYLOADS = [
    "//evil.com",
    "https://evil.com",
    "/\\evil.com",
    "//evil.com/%2f..",
]

# Common sensitive files to check
SENSITIVE_FILES = [
    "/.env",
    "/.git/config",
    "/.gitignore",
    "/wp-config.php",
    "/config.php",
    "/database.yml",
    "/.htaccess",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/package.json",
    "/composer.json",
    "/.dockerenv",
    "/Dockerfile",
    "/docker-compose.yml",
    "/.aws/credentials",
    "/server-status",
    "/server-info",
    "/phpinfo.php",
    "/info.php",
    "/debug",
    "/trace",
    "/actuator",
    "/swagger-ui.html",
    "/api-docs",
    "/graphql",
    "/.svn/entries",
]

# Secret patterns to detect in source code
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
    "GitHub Token": r"gh[ps]_[A-Za-z0-9_]{36,}",
    "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z-]+",
    "Private Key": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
    "JWT Token": r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+",
    "Generic API Key": r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9]{20,}['\"]",
    "Generic Secret": r"(?i)(secret|password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    "Database URL": r"(?i)(postgres|mysql|mongodb|redis)://[^\s'\"]+",
}

# Framework detection signatures
FRONTEND_FRAMEWORKS = {
    "React": {
        "scripts": ["react", "react-dom", "__NEXT_DATA__"],
        "meta": [],
        "headers": [],
        "patterns": ["_next/", "react-root", "__react", "data-reactroot"],
    },
    "Vue.js": {
        "scripts": ["vue", "vuex", "vue-router"],
        "meta": [],
        "headers": [],
        "patterns": ["__vue__", "data-v-", "v-cloak", "nuxt"],
    },
    "Angular": {
        "scripts": ["angular", "@angular/core", "zone.js"],
        "meta": [],
        "headers": [],
        "patterns": ["ng-version", "ng-app", "ng-controller", "_ng"],
    },
    "Svelte": {
        "scripts": ["svelte"],
        "meta": [],
        "headers": [],
        "patterns": ["svelte-", "__svelte"],
    },
    "jQuery": {
        "scripts": ["jquery"],
        "meta": [],
        "headers": [],
        "patterns": ["jQuery"],
    },
    "Next.js": {
        "scripts": [],
        "meta": [],
        "headers": ["x-powered-by: Next.js"],
        "patterns": ["__NEXT_DATA__", "_next/static"],
    },
    "Nuxt.js": {
        "scripts": [],
        "meta": [],
        "headers": [],
        "patterns": ["__NUXT__", "_nuxt/"],
    },
}

BACKEND_FRAMEWORKS = {
    "Django": {
        "headers": ["x-frame-options: DENY"],
        "cookies": ["csrftoken", "sessionid"],
        "patterns": ["django", "csrfmiddlewaretoken"],
    },
    "Flask": {
        "headers": ["server: Werkzeug"],
        "cookies": ["session"],
        "patterns": [],
    },
    "Express": {
        "headers": ["x-powered-by: Express"],
        "cookies": ["connect.sid"],
        "patterns": [],
    },
    "Laravel": {
        "headers": [],
        "cookies": ["laravel_session", "XSRF-TOKEN"],
        "patterns": ["laravel"],
    },
    "Rails": {
        "headers": ["x-powered-by: Phusion Passenger"],
        "cookies": ["_session_id"],
        "patterns": ["rails", "csrf-token"],
    },
    "ASP.NET": {
        "headers": ["x-powered-by: ASP.NET", "x-aspnet-version"],
        "cookies": ["ASP.NET_SessionId", ".AspNetCore."],
        "patterns": ["__VIEWSTATE", "__EVENTVALIDATION"],
    },
    "Spring": {
        "headers": [],
        "cookies": ["JSESSIONID"],
        "patterns": ["spring"],
    },
    "FastAPI": {
        "headers": [],
        "cookies": [],
        "patterns": ["fastapi", "openapi.json", "/docs", "/redoc"],
    },
}

# HTTP status code descriptions
HTTP_STATUS_DESCRIPTIONS = {
    200: "OK",
    201: "Created",
    204: "No Content",
    301: "Moved Permanently",
    302: "Found (Redirect)",
    304: "Not Modified",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    408: "Request Timeout",
    429: "Too Many Requests",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}

# WCAG contrast ratios
WCAG_AA_NORMAL = 4.5
WCAG_AA_LARGE = 3.0
WCAG_AAA_NORMAL = 7.0
WCAG_AAA_LARGE = 4.5

# Minimum touch target size (pixels)
MIN_TOUCH_TARGET_SIZE = 44
