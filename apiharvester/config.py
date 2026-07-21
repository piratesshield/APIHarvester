"""Shared constants, wordlists, regexes — extracted from apisec.py."""
import os
import re
import secrets

from . import VERSION

UA = "apiharvester/%s (+authorized-testing-only)" % VERSION

METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

# ---------------------------------------------------------------------------
# On-disk payload directory — populated by scripts/install_requirements.sh.
# Every path below is optional: each caller checks os.path.exists() first and
# falls back to the built-in wordlists in this file (or skips that
# accelerator) when the download hasn't been run.
# Override with APISECSCAN_WORDLIST_DIR to point at a different location.
# ---------------------------------------------------------------------------
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORDLIST_DIR = os.environ.get(
    "APISECSCAN_WORDLIST_DIR", os.path.join(_PROJECT_ROOT, "payloads"))

SUBDOMAIN_WORDLIST_FILE = os.path.join(WORDLIST_DIR, "subdomains.txt")
DIR_WORDLIST_FILE = os.path.join(WORDLIST_DIR, "directories.txt")
PARAM_WORDLIST_FILE = os.path.join(WORDLIST_DIR, "params.txt")
KITERUNNER_ROUTES_FILE = os.path.join(
    WORDLIST_DIR, "kiterunner", "routes-large.kite")

# ---------------------------------------------------------------------------
# Endpoint discovery wordlists
# ---------------------------------------------------------------------------

PATH_WORDS = [
    "", "api", "api/v1", "api/v2", "api/v3", "v1", "v2", "graphql", "rest",
    "auth", "login", "logout", "register", "signup", "token", "oauth",
    "oauth/token", "refresh", "session", "sessions", "users", "user", "me",
    "accounts", "account", "admin", "admin/users", "internal", "debug",
    "config", "settings", "status", "health", "healthz", "ping", "version",
    "metrics", "actuator", "actuator/env", "actuator/health", "manage",
    "management", "console", "search", "orders", "order", "products",
    "product", "items", "cart", "payments", "payment", "invoices", "files",
    "upload", "download", "export", "import", "backup", "logs", "webhook",
    "webhooks", "notifications", "messages", "profile", "roles", "permissions",
    "keys", "apikeys", "secrets", "info", "swagger", "api-docs", "openapi",
    "docs", "graphiql", ".env", ".git/config", "server-status", "phpinfo.php",
]

ACTION_WORDS = [
    "list", "create", "update", "delete", "get", "add", "remove", "edit",
    "reset", "verify", "confirm", "enable", "disable", "activate", "grant",
    "revoke", "impersonate", "sudo", "elevate", "all", "count", "search",
    "login", "logout", "register", "signup", "signin",
    "forgot-password", "reset-password", "validate",
    "refresh", "token", "revoke",
    "export", "import", "upload", "download",
    "status", "health", "ping", "metrics", "info", "version",
    "users", "user", "profile", "account", "accounts",
    "admin", "admins", "roles", "permissions", "groups",
    "orders", "order", "cart", "checkout", "payment", "payments",
    "products", "product", "catalog", "inventory",
    "notifications", "alerts", "messages",
    "settings", "config", "configuration", "preferences",
    "reports", "report", "analytics", "stats", "statistics",
    "audit", "logs", "events", "history",
    "debug", "test", "internal", "private", "secret",
    "graphql", "query", "mutation", "subscription",
    "webhook", "callback", "notify",
    "v1", "v2", "v3", "api", "rest",
]

SPEC_PATHS = [
    "swagger.json", "swagger/v1/swagger.json", "openapi.json", "openapi.yaml",
    "v2/api-docs", "v3/api-docs", "api-docs", "api/swagger.json",
    ".well-known/openapi.json", "swagger-ui.html", "api/openapi.json",
    "swagger/v2/swagger.json", "api/v1/swagger.json", "api/v2/swagger.json",
    "docs/openapi.json", "docs/swagger.json",
]

EXTENSIONS = [".json", ".yaml", ".xml", ".bak", ".old", ".txt"]

# ---------------------------------------------------------------------------
# Subdomain discovery wordlist (top common subdomains)
# ---------------------------------------------------------------------------

SUBDOMAIN_WORDS = [
    "www", "api", "dev", "staging", "stage", "test", "testing", "uat",
    "qa", "pre", "preprod", "prod", "production", "beta", "alpha",
    "admin", "portal", "app", "apps", "mobile", "m", "internal",
    "intranet", "vpn", "mail", "email", "smtp", "pop", "imap",
    "ftp", "sftp", "ssh", "dns", "ns1", "ns2", "ns3",
    "cdn", "static", "assets", "media", "images", "img", "files",
    "docs", "doc", "help", "support", "status", "monitor", "monitoring",
    "grafana", "kibana", "jenkins", "ci", "cd", "git", "gitlab", "github",
    "jira", "confluence", "wiki", "blog", "cms", "shop", "store",
    "pay", "payment", "payments", "billing", "checkout",
    "auth", "sso", "login", "oauth", "id", "identity",
    "search", "elastic", "es", "redis", "db", "database", "mysql", "postgres",
    "mongo", "rabbitmq", "kafka", "mq", "queue",
    "ws", "websocket", "socket", "realtime", "rt",
    "graphql", "gql", "rest", "rpc", "grpc",
    "sandbox", "demo", "trial", "preview",
    "v1", "v2", "v3", "legacy", "old", "new",
    "dashboard", "panel", "console", "manage", "management",
    "proxy", "gateway", "lb", "loadbalancer", "edge",
    "logs", "logging", "sentry", "error", "errors",
    "metrics", "prometheus", "datadog", "newrelic",
    "backup", "backups", "archive", "storage", "s3", "bucket",
    "webhook", "webhooks", "callback", "notify", "notifications",
    "cron", "scheduler", "worker", "workers", "job", "jobs",
    "report", "reports", "analytics", "stats",
]

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

API_PATH_RE = re.compile(
    r"(/api/|/v[1-9]\d?/|/graphql|/rest/|/oauth|/token|/auth)", re.I)

AUTH_PATH_RE = re.compile(
    r"(login|logout|register|signup|signin|token|oauth|refresh)", re.I)

SENSITIVE_PATH_RE = re.compile(
    r"(/admin|/internal|/debug|/config|/actuator|/manage|/console|/secret|"
    r"/backup|/\.env|/\.git|/metrics|/phpinfo|/server-status|/keys|/apikeys)", re.I)

ID_SEGMENT_RE = re.compile(
    r"(/\d+(?:/|$)|/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|/[0-9a-fA-F]{24,}|[?&](id|uid|user_id|"
    r"account_id|order_id)=)", re.I)

BFLA_PATH_RE = re.compile(
    r"(/admin|/internal|/manage|/console|/impersonate|/sudo|/elevate|"
    r"/grant|/revoke|/roles|/permissions|/users/.+/(delete|disable|ban)|"
    r"actuator)", re.I)

BEARER_JWT_RE = re.compile(
    r"Bearer\s+(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)")

# API detection heuristics
API_CONTENT_TYPES = re.compile(
    r"application/(json|xml|hal\+json|vnd\.api\+json|problem\+json|"
    r"graphql-response\+json|cbor|msgpack)", re.I)

API_HEADER_CLUES = re.compile(
    r"(x-ratelimit|x-rate-limit|x-api-version|x-request-id|x-correlation-id|"
    r"x-trace-id|x-amzn-requestid)", re.I)

API_SERVER_CLUES = re.compile(
    r"(express|kestrel|uvicorn|gunicorn|fastapi|flask|django|"
    r"spring|tomcat|jetty|rails|phoenix|gin-gonic)", re.I)

API_ERROR_BODY_RE = re.compile(
    r'^\s*\{[^}]*"(error|message|detail|errors|status|code)"', re.I)

# ---------------------------------------------------------------------------
# Secret detection patterns
# ---------------------------------------------------------------------------

SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("Stripe Live Key", re.compile(r"sk_live_[0-9a-zA-Z]{24}")),
    ("GitHub Token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}")),
    ("Private Key Block", re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("JWT", re.compile(
        r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("Generic Secret Assignment", re.compile(
        r"(?i)(api[_-]?key|secret|passwd|password|access[_-]?token)"
        r"['\"\s:=]{1,4}[A-Za-z0-9\-_./+]{16,}")),
]

# ---------------------------------------------------------------------------
# Error signatures for verbose error / stack trace detection
# ---------------------------------------------------------------------------

ERROR_SIGNATURES = [
    ("Python", re.compile(r"Traceback \(most recent call last\)")),
    ("Java", re.compile(
        r"(?:java\.lang\.|at [a-z]+(?:\.[a-z0-9]+)+\([A-Za-z]+\.java)")),
    (".NET", re.compile(r"System\.[A-Za-z.]+Exception")),
    ("PHP", re.compile(
        r"(?:PHP (?:Warning|Fatal error|Notice)|on line \d+ in)")),
    ("Ruby", re.compile(r"(?:rack|actionpack|activerecord)-[\d.]+/lib")),
    ("SQL", re.compile(
        r"(?i)(SQL syntax|mysql_fetch|SQLException|ORA-\d{5}|"
        r"PostgreSQL.*ERROR|SQLite3::|near \".*\": syntax error)")),
]

# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS not set (no transport security policy)",
    "content-security-policy": "CSP not set",
    "x-content-type-options": "X-Content-Type-Options not set (MIME sniffing)",
    "x-frame-options": "X-Frame-Options not set (clickjacking)",
    "referrer-policy": "Referrer-Policy not set",
}

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ---------------------------------------------------------------------------
# Parameter discovery wordlist (arjun-style)
# ---------------------------------------------------------------------------

PARAM_WORDLIST = [
    "id", "uid", "user_id", "account_id", "order_id", "token", "api_key",
    "apikey", "key", "secret", "debug", "test", "admin", "role", "roles",
    "is_admin", "isAdmin", "internal", "callback", "redirect", "redirect_uri",
    "next", "url", "file", "filename", "path", "page", "limit", "offset",
    "sort", "order", "filter", "query", "search", "q", "format", "type",
    "action", "cmd", "command", "access_token", "session", "sessionid",
    "email", "username", "password", "code", "state", "client_id",
    "client_secret", "version", "env", "environment", "source", "ref",
    "name", "title", "description", "status", "category", "tag", "tags",
    "price", "amount", "quantity", "total", "discount", "coupon",
    "webhook", "proxy", "target", "host", "port", "ip",
    "from", "to", "date", "start", "end", "created", "updated",
    "include", "exclude", "fields", "expand", "embed", "populate",
    "lang", "locale", "currency", "country", "region",
    "size", "width", "height", "color", "theme",
    "verified", "active", "enabled", "deleted", "archived",
    "parent_id", "group_id", "team_id", "org_id", "project_id",
]

# URL-accepting parameter names (SSRF candidates)
URL_PARAM_NAMES = {
    "url", "uri", "link", "href", "src", "source", "target", "dest",
    "destination", "redirect", "redirect_uri", "redirect_url", "return",
    "return_url", "callback", "callback_url", "webhook", "webhook_url",
    "proxy", "proxy_url", "fetch", "fetch_url", "load", "load_url",
    "image", "image_url", "img", "img_url", "icon", "icon_url",
    "avatar", "avatar_url", "file", "file_url", "download", "download_url",
    "next", "continue", "forward", "goto", "to",
}

# Business logic parameter names
BUSINESS_PARAM_NAMES = {
    "price", "amount", "total", "subtotal", "quantity", "qty", "count",
    "discount", "coupon", "coupon_code", "promo", "promo_code",
    "balance", "credit", "payment", "cost", "fee", "tax",
    "shipping", "tip", "donation", "refund",
}

# ---------------------------------------------------------------------------
# JWT weak secrets
# ---------------------------------------------------------------------------

JWT_WEAK_SECRETS = [
    "secret", "secret123", "password", "123456", "changeme",
    "your-256-bit-secret", "jwt_secret", "jwtsecret", "supersecret",
    "mysecretkey", "key", "test", "qwerty", "admin", "default",
    "s3cr3t", "abc123", "letmein", "", "null",
    "development", "production", "staging",
]

# ---------------------------------------------------------------------------
# Mass assignment fields
# ---------------------------------------------------------------------------

MASS_ASSIGNMENT_FIELDS = {
    "role": "admin", "roles": ["admin"], "is_admin": True, "isAdmin": True,
    "admin": True, "permissions": ["*"], "account_type": "admin",
    "user_id": 1, "owner_id": 1, "verified": True, "is_verified": True,
    "balance": 999999, "credit": 999999, "price": 0, "status": "approved",
}

# ---------------------------------------------------------------------------
# Soft-404 markers
# ---------------------------------------------------------------------------

SOFT_404_MARKERS = re.compile(
    r"(Whitelabel Error Page|This application has no explicit mapping for /error|"
    r"404 Not Found|Not Found</title>|The requested URL was not found|"
    r"Cannot GET /|Cannot POST /|page could not be found|"
    r"nginx</center>|Apache.*Server at|does not exist on this server|"
    r"<title>Error</title>|We could not find the page)", re.I)

# Volatile fields stripped before soft-404 body comparison
VOLATILE_FIELD_RE = re.compile(
    r'"(?:path|url|request_?id|trace_?id|timestamp|time|instance)"\s*:\s*'
    r'"[^"]*"', re.I)

VOLATILE_RE = re.compile(r"\d+")

# ---------------------------------------------------------------------------
# 403 bypass techniques
# ---------------------------------------------------------------------------

BYPASS_PATH_SUFFIXES = [
    "/", "//", "/.", "/./", "/..;/", ";/", "/%2e", "/%2e/", "/%20", "/%09",
    "/*", "/.json", "/..%2f", "/..%2f..%2f",
]
BYPASS_PATH_PREFIXES = ["/.", "//", "/./"]
BYPASS_CASE_VARIANTS = True
BYPASS_HEADER_SETS = [
    {"X-Original-URL": None},
    {"X-Rewrite-URL": None},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "localhost"},
    {"X-Forwarded-Host": "127.0.0.1"},
    {"X-Forwarded-Scheme": "http", "X-Forwarded-Proto": "https"},
    {"X-Host": "127.0.0.1"},
    {"X-HTTP-Method-Override": "GET"},
    {"Referer": None},
]

# ---------------------------------------------------------------------------
# SSRF payloads
# ---------------------------------------------------------------------------

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
    "http://100.100.100.200/latest/meta-data/",  # Alibaba
    "http://169.254.169.254/metadata/v1/",  # DigitalOcean
    "http://127.0.0.1/",
    "http://127.0.0.1:80/",
    "http://127.0.0.1:443/",
    "http://127.0.0.1:8080/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://localhost/",
    # Bypass variants (parser/allowlist evasion)
    "http://169.254.169.254.nip.io/latest/meta-data/",
    "http://[0:0:0:0:0:ffff:169.254.169.254]/latest/meta-data/",
    "http://2852039166/latest/meta-data/",  # decimal IP for 169.254.169.254
]

# AWS IMDSv2 requires a session token obtained via PUT to /latest/api/token.
# A server that proxies our URL *and* forwards our headers can be walked
# through the two-step flow. See REAL_WORLD_RESEARCH.md §4 (Capital One).
IMDSV2_TOKEN_URL = "http://169.254.169.254/latest/api/token"
IMDSV2_CRED_URL = ("http://169.254.169.254/latest/meta-data/iam/"
                   "security-credentials/")

SSRF_INDICATORS = re.compile(
    r"(ami-id|instance-id|instance-type|local-ipv4|security-credentials|"
    r"computeMetadata|metadata\.google|iam/info|"
    r"<html|<!DOCTYPE|<title>|Index of /|Directory listing)", re.I)

# ---------------------------------------------------------------------------
# SSPP payloads
# ---------------------------------------------------------------------------

SSPP_TRUNCATION = "%23"
SSPP_INJECTION = "%26"

# ---------------------------------------------------------------------------
# WAF vendor signatures (header/body-based detection fallback)
# ---------------------------------------------------------------------------

WAF_SIGNATURES = {
    "Cloudflare": [re.compile(r"(cf-ray|cloudflare|cf-chl)", re.I)],
    "AWS WAF": [re.compile(r"(awselb|x-amzn-requestid|x-amz-apigw-id)", re.I)],
    "Akamai": [re.compile(r"(akamai|x-akamai|akamaighost)", re.I)],
    "Imperva": [re.compile(r"(incapsula|imperva|visid_incap)", re.I)],
    "Sucuri": [re.compile(r"(sucuri|x-sucuri)", re.I)],
    "F5 BIG-IP": [re.compile(r"(bigip|f5|x-wa-info)", re.I)],
    "ModSecurity": [re.compile(r"(mod_security|modsecurity)", re.I)],
    "Barracuda": [re.compile(r"(barracuda|barra_)", re.I)],
    "Fortinet": [re.compile(r"(fortigate|fortiweb|forticdn)", re.I)],
}

JS_CHALLENGE_RE = re.compile(
    r"(cf-chl|jschl-answer|checking your browser|captcha|challenge-platform)",
    re.I)

# ---------------------------------------------------------------------------
# Version path variants for inventory attack
# ---------------------------------------------------------------------------

VERSION_VARIANTS = [
    "/v1/", "/v2/", "/v3/", "/v4/", "/v5/",
    "/beta/", "/alpha/", "/internal/", "/staging/", "/dev/",
    "/test/", "/sandbox/", "/preview/", "/legacy/", "/old/",
]

# Unique marker for injection testing
INJECTION_MARKER = "apiharvester_" + secrets.token_hex(4)
