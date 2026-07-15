#!/usr/bin/env python3
"""
apiscan.py — Unified black-box API security scanner (standard library only)

Give it a host and it discovers API endpoints, probes them across HTTP methods,
reasons about authentication/authorization, and runs a set of deterministic
classifiers to surface API security issues. No third-party dependencies.

    python3 apiscan.py api.example.com
    python3 apiscan.py https://api.example.com --auth "Bearer eyJ..." --threads 30
    python3 apiscan.py api.example.com --json out.jsonl --html report.html

AUTHORIZATION: Only scan systems you own or are explicitly permitted to test.
Unauthorized scanning may be illegal. You are responsible for how you use this.
"""

import argparse
import base64
import concurrent.futures as futures
import difflib
import hashlib
import hmac
import json
import re
import secrets
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

# --------------------------------------------------------------------------- #
# Constants: wordlists, regexes, severity ordering
# --------------------------------------------------------------------------- #

VERSION = "1.0"
UA = "apiscan/%s (+authorized-testing-only)" % VERSION

METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

# Endpoint discovery wordlist (paths appended to host root and /api, /api/v1 ...)
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

# Action words appended to discovered API bases to expand surface
ACTION_WORDS = [
    "list", "create", "update", "delete", "get", "add", "remove", "edit",
    "reset", "verify", "confirm", "enable", "disable", "activate", "grant",
    "revoke", "impersonate", "sudo", "elevate", "all", "count", "search",
]

# OpenAPI / spec discovery paths
SPEC_PATHS = [
    "swagger.json", "swagger/v1/swagger.json", "openapi.json", "openapi.yaml",
    "v2/api-docs", "v3/api-docs", "api-docs", "api/swagger.json",
    ".well-known/openapi.json", "swagger-ui.html", "api/openapi.json",
]

# Path classification regexes
API_PATH_RE = re.compile(r"(/api/|/v[1-9]\d?/|/graphql|/rest/|/oauth|/token|/auth)", re.I)
AUTH_PATH_RE = re.compile(r"(login|logout|register|signup|signin|token|oauth|refresh)", re.I)
SENSITIVE_PATH_RE = re.compile(
    r"(/admin|/internal|/debug|/config|/actuator|/manage|/console|/secret|"
    r"/backup|/\.env|/\.git|/metrics|/phpinfo|/server-status|/keys|/apikeys)", re.I)
ID_SEGMENT_RE = re.compile(
    r"(/\d+(?:/|$)|/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|/[0-9a-fA-F]{24,}|[?&](id|uid|user_id|"
    r"account_id|order_id)=)", re.I)

# Secret patterns for response-body scanning
SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("Stripe Live Key", re.compile(r"sk_live_[0-9a-zA-Z]{24}")),
    ("GitHub Token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}")),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("Generic Secret Assignment",
     re.compile(r"(?i)(api[_-]?key|secret|passwd|password|access[_-]?token)"
                r"['\"\s:=]{1,4}[A-Za-z0-9\-_./+]{16,}")),
]

# Stack-trace / error signatures indicating verbose error disclosure
ERROR_SIGNATURES = [
    ("Python", re.compile(r"Traceback \(most recent call last\)")),
    ("Java", re.compile(r"(?:java\.lang\.|at [a-z]+(?:\.[a-z0-9]+)+\([A-Za-z]+\.java)")),
    (".NET", re.compile(r"System\.[A-Za-z.]+Exception")),
    ("PHP", re.compile(r"(?:PHP (?:Warning|Fatal error|Notice)|on line \d+ in)")),
    ("Ruby", re.compile(r"(?:rack|actionpack|activerecord)-[\d.]+/lib")),
    ("SQL", re.compile(r"(?i)(SQL syntax|mysql_fetch|SQLException|ORA-\d{5}|"
                       r"PostgreSQL.*ERROR|SQLite3::|near \".*\": syntax error)")),
]

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS not set (no transport security policy)",
    "content-security-policy": "CSP not set",
    "x-content-type-options": "X-Content-Type-Options not set (MIME sniffing)",
    "x-frame-options": "X-Frame-Options not set (clickjacking)",
    "referrer-policy": "Referrer-Policy not set",
}

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Hidden-parameter wordlist for Arjun-style discovery (kept small & high-signal
# rather than exhaustive, to stay fast on a black-box scan)
PARAM_WORDLIST = [
    "id", "uid", "user_id", "account_id", "order_id", "token", "api_key",
    "apikey", "key", "secret", "debug", "test", "admin", "role", "roles",
    "is_admin", "isAdmin", "internal", "callback", "redirect", "redirect_uri",
    "next", "url", "file", "filename", "path", "page", "limit", "offset",
    "sort", "order", "filter", "query", "search", "q", "format", "type",
    "action", "cmd", "command", "access_token", "session", "sessionid",
    "email", "username", "password", "code", "state", "client_id",
    "client_secret", "version", "env", "environment", "source", "ref",
]

# jwt_tool-style dictionary of well-known/default HMAC secrets used to
# offline-verify whether a JWT's signature was signed with a weak key
JWT_WEAK_SECRETS = [
    "secret", "secret123", "password", "123456", "changeme", "your-256-bit-secret",
    "jwt_secret", "jwtsecret", "supersecret", "mysecretkey", "key", "test",
    "qwerty", "admin", "default", "s3cr3t", "abc123", "letmein", "", "null",
    "development", "production", "staging",
]

SQLI_ERROR_PAYLOAD = "'"
INJECTION_MARKER = "apiscan_" + secrets.token_hex(4)

# API3: fields injected into PUT/PATCH bodies to test for mass-assignment
# (server accepting client-supplied privilege/ownership fields it shouldn't)
MASS_ASSIGNMENT_FIELDS = {
    "role": "admin", "roles": ["admin"], "is_admin": True, "isAdmin": True,
    "admin": True, "permissions": ["*"], "account_type": "admin",
    "user_id": 1, "owner_id": 1, "verified": True, "is_verified": True,
    "balance": 999999, "credit": 999999, "price": 0, "status": "approved",
}

# Function-level-authz: path fragments that should require elevated privilege
BFLA_PATH_RE = re.compile(
    r"(/admin|/internal|/manage|/console|/impersonate|/sudo|/elevate|"
    r"/grant|/revoke|/roles|/permissions|/users/.+/(delete|disable|ban)|"
    r"actuator)", re.I)

BEARER_JWT_RE = re.compile(r"Bearer\s+(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)")

# Generic "soft 404" / catch-all error page markers. Frameworks like Spring Boot
# return an identical "Whitelabel Error Page" (or a SPA's index.html) for every
# unmapped path with a 2xx/404/500 status — treating that as a discovered
# endpoint floods every other check with false positives.
SOFT_404_MARKERS = re.compile(
    r"(Whitelabel Error Page|This application has no explicit mapping for /error|"
    r"404 Not Found|Not Found</title>|The requested URL was not found|"
    r"Cannot GET /|Cannot POST /|page could not be found|"
    r"nginx</center>|Apache.*Server at|does not exist on this server|"
    r"<title>Error</title>|We could not find the page)", re.I)

# Volatile tokens (timestamps, request ids, ports) stripped before hashing a
# body for soft-404 baseline comparison so near-identical error pages match.
_VOLATILE_RE = re.compile(r"\d+")
# Volatile JSON/HTML fields that legitimately vary per-request even on an
# otherwise-identical soft-404/error page (request id, timestamp, echoed
# path) — these must be stripped BEFORE comparing bodies, or a framework
# that echoes the request path (Express's "Cannot GET /foo/bar", or a JSON
# body like {"error":"Not Found","path":"/foo/bar"}) will look unique on
# every single candidate and never match the soft-404 baseline.
_VOLATILE_FIELD_RE = re.compile(
    r'"(?:path|url|request_?id|trace_?id|timestamp|time|instance)"\s*:\s*'
    r'"[^"]*"', re.I)

# Path/header mutations for 403-bypass verification, following the common
# access-control-bypass technique catalogue (see LucasPDiniz/403-Bypass).
BYPASS_PATH_SUFFIXES = [
    "/", "//", "/.", "/./", "/..;/", ";/", "/%2e", "/%2e/", "/%20", "/%09",
    "/*", "/.json", "/..%2f", "/..%2f..%2f",
]
BYPASS_PATH_PREFIXES = ["/.", "//", "/./"]
BYPASS_CASE_VARIANTS = True  # try UPPER/Title-case of the final path segment
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


def _normalize_body(body, url=None):
    text = body or ""
    text = _VOLATILE_FIELD_RE.sub('"F":"X"', text)
    if url:
        path = urllib.parse.urlparse(url).path or ""
        if path and path != "/":
            # Strip the echoed request path itself (Express: "Cannot GET
            # /foo/bar"; many JSON error bodies embed the path verbatim)
            # and each of its individual segments, so per-candidate path
            # text doesn't make every soft-404 page look unique.
            text = text.replace(path, "")
            for seg in path.split("/"):
                if len(seg) >= 3:
                    text = text.replace(seg, "")
    text = _VOLATILE_RE.sub("N", text)
    return text[:2000]


def _b64url_decode(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())


def jwt_parts(token):
    """Return (header_dict, payload_dict, signing_input, sig_bytes) or None."""
    segs = token.split(".")
    if len(segs) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(segs[0]))
        payload = json.loads(_b64url_decode(segs[1]))
        sig = _b64url_decode(segs[2] + "==") if segs[2] else b""
    except Exception:
        return None
    signing_input = (segs[0] + "." + segs[1]).encode()
    return header, payload, signing_input, sig


def jwt_crack_weak_secret(token):
    """jwt_tool-style offline HMAC dictionary attack. Returns secret or None."""
    parsed = jwt_parts(token)
    if not parsed:
        return None
    header, _, signing_input, sig = parsed
    alg = header.get("alg", "").upper()
    hashfn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
              "HS512": hashlib.sha512}.get(alg)
    if not hashfn:
        return None
    for candidate in JWT_WEAK_SECRETS:
        mac = hmac.new(candidate.encode(), signing_input, hashfn).digest()
        if hmac.compare_digest(mac, sig):
            return candidate
    return None


def jwt_forge_alg_none(token):
    """Build an alg=none forged token with an unmodified payload (alg-confusion)."""
    parsed = jwt_parts(token)
    if not parsed:
        return None
    header, payload, _, _ = parsed
    header = dict(header)
    header["alg"] = "none"
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=")
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=")
    return (h + b"." + p + b".").decode()

# --------------------------------------------------------------------------- #
# HTTP client (urllib, no redirects, permissive TLS for testing)
# --------------------------------------------------------------------------- #

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


@dataclass
class Response:
    url: str
    method: str
    status: int = 0
    length: int = 0
    ctype: str = ""
    headers: dict = field(default_factory=dict)
    body: str = ""
    error: str = ""
    elapsed_ms: int = 0


class HTTPClient:
    def __init__(self, timeout=10, extra_headers=None, max_body=65536):
        self.timeout = timeout
        self.max_body = max_body
        self.extra = extra_headers or {}
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(
            _NoRedirect(), urllib.request.HTTPSHandler(context=ctx))

    def request(self, method, url, body=None, headers=None):
        h = {"User-Agent": UA, "Accept": "*/*"}
        h.update(self.extra)
        if headers:
            h.update(headers)
        data = body.encode() if isinstance(body, str) else body
        req = urllib.request.Request(url, data=data, method=method, headers=h)
        t0 = time.time()
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                raw = r.read(self.max_body)
                return Response(url, method, r.status, len(raw),
                                r.headers.get("Content-Type", ""),
                                {k.lower(): v for k, v in r.headers.items()},
                                raw.decode("utf-8", "replace"),
                                elapsed_ms=int((time.time() - t0) * 1000))
        except urllib.error.HTTPError as e:
            try:
                raw = e.read(self.max_body) if hasattr(e, "read") else b""
            except Exception:
                raw = b""
            return Response(url, method, e.code, len(raw),
                            e.headers.get("Content-Type", "") if e.headers else "",
                            {k.lower(): v for k, v in (e.headers or {}).items()},
                            raw.decode("utf-8", "replace") if raw else "",
                            elapsed_ms=int((time.time() - t0) * 1000))
        except Exception as e:  # timeout, DNS, TLS, connection reset
            return Response(url, method, 0, 0, "", {}, "",
                            error=type(e).__name__ + ": " + str(e)[:120],
                            elapsed_ms=int((time.time() - t0) * 1000))


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    title: str
    severity: str          # critical|high|medium|low|info
    category: str          # authn|authz|exposure|robustness|transport|config|injection
    method: str
    path: str
    status: int
    evidence: str
    remediation: str

    def key(self):
        return (self.category, self.method, self.path, self.title)


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #

class Scanner:
    def __init__(self, base, args):
        self.args = args
        self.base = base.rstrip("/")
        self.host = urllib.parse.urlparse(self.base).netloc
        self.client = HTTPClient(timeout=args.timeout,
                                 extra_headers=self._auth_header())
        # separate client for "authenticated baseline" if a token is provided
        self.auth_present = bool(args.auth)
        self.auth2_present = bool(getattr(args, "auth2", None))
        if self.auth2_present:
            self.client2 = HTTPClient(timeout=args.timeout,
                                      extra_headers={"Authorization": args.auth2})
        self.findings = {}
        self.responses = {}     # (method, url) -> Response
        self.responses2 = {}    # (method, url) -> Response, using --auth2
        self.endpoints = set()
        self.soft404_baselines = []   # [(status, normalized_text, length)]

    def _auth_header(self):
        if self.args.auth:
            return {"Authorization": self.args.auth}
        return {}

    def _add(self, f: Finding):
        self.findings.setdefault(f.key(), f)

    def log(self, *a):
        if not self.args.quiet:
            print("[*]", *a, file=sys.stderr)

    # ---- Phase 0: soft-404 / catch-all error page fingerprinting ----------- #
    def _fingerprint_soft404(self):
        """Probe several definitely-nonexistent paths, at different depths/
        namespaces, and record their normalized body as a baseline. Many
        frameworks vary their catch-all error page per route prefix (e.g. a
        JSON 404 under /api/** vs an HTML Whitelabel page at the root), so a
        single sample isn't enough — and a naive exact-match on the raw body
        fails outright whenever the page echoes the request path back (e.g.
        Express's "Cannot GET /foo/bar", or a JSON body with a "path" field),
        since every candidate's echoed path differs. We normalize the path
        out (see _normalize_body) and additionally fall back to fuzzy
        similarity so near-identical pages still match even if some other
        volatile fragment differs."""
        probes = [
            self.base + "/__apiscan_nonexistent_%s" % secrets.token_hex(6),
            self.base + "/api/__apiscan_nonexistent_%s" % secrets.token_hex(6),
            self.base + "/api/v1/__apiscan_nonexistent_%s" % secrets.token_hex(6),
        ]
        for u in probes:
            r = self.client.request("GET", u)
            if r.status == 0:
                continue
            self.soft404_baselines.append(
                (r.status, _normalize_body(r.body, u), r.length))

    def _is_soft_404(self, r):
        if SOFT_404_MARKERS.search(r.body or ""):
            return True
        if not self.soft404_baselines:
            return False
        norm = _normalize_body(r.body, r.url)
        for status, base_text, base_len in self.soft404_baselines:
            if status != r.status:
                continue
            if not base_text and not norm:
                return True
            if abs(len(norm) - len(base_text)) > max(64, base_len * 0.15):
                continue
            ratio = difflib.SequenceMatcher(None, norm, base_text).quick_ratio()
            if ratio >= 0.90:
                return True
        return False

    # ---- Phase 1: discovery ------------------------------------------------ #
    def discover(self):
        self.log("Phase 1: endpoint discovery")
        self._fingerprint_soft404()
        bases = [self.base, self.base + "/api", self.base + "/api/v1",
                 self.base + "/api/v2"]
        candidates = set()
        for b in bases:
            for w in PATH_WORDS:
                candidates.add((b + "/" + w).rstrip("/") if w else b)
        for w in SPEC_PATHS:
            candidates.add(self.base + "/" + w)
        # Probe candidates lightly with GET to see what exists
        live = self._probe_existence(candidates)
        self.endpoints |= live
        self.log("  %d live endpoints from wordlist" % len(live))
        # Parse discovered spec files for declared paths
        self._harvest_specs(live)
        # Expand action words on confirmed API bases
        self._expand_actions(live)
        # Light crawl: pull links/paths out of returned bodies
        self._crawl(live)
        self.log("  %d total endpoints after expansion" % len(self.endpoints))

    def _probe_existence(self, urls):
        live = set()
        def check(u):
            r = self.client.request("GET", u)
            self.responses[("GET", u)] = r
            if self._is_soft_404(r):
                return None
            # "Exists" = any response that isn't a hard connection failure or
            # a clean 404 with no body.
            if r.status and r.status != 404:
                return u
            if r.status == 404 and r.length > 200:
                return u
            return None
        with futures.ThreadPoolExecutor(max_workers=self.args.threads) as ex:
            for res in ex.map(check, urls):
                if res:
                    live.add(res)
        return live

    def _harvest_specs(self, live):
        for u in list(live):
            if not re.search(r"(swagger|openapi|api-docs)", u, re.I):
                continue
            r = self.responses.get(("GET", u))
            if not r or "json" not in r.ctype.lower():
                continue
            try:
                spec = json.loads(r.body)
            except Exception:
                continue
            paths = spec.get("paths", {})
            server = self.base
            for p in paths:
                clean = re.sub(r"\{[^}]+\}", "1", p)  # fill path params
                self.endpoints.add(server + clean)
            if paths:
                self.log("  spec %s declared %d paths" % (u, len(paths)))
                self._add(Finding(
                    "OpenAPI/Swagger specification publicly exposed", "low",
                    "exposure", "GET", urllib.parse.urlparse(u).path, r.status,
                    "Machine-readable API spec reachable without auth (%d paths)"
                    % len(paths),
                    "Restrict spec access to authenticated internal consumers; "
                    "do not ship swagger/openapi docs to production edge."))

    def _expand_actions(self, live):
        api_bases = {u for u in live if API_PATH_RE.search(u)}
        expanded = set()
        for b in list(api_bases)[:40]:            # cap to keep runtime crisp
            for a in ACTION_WORDS:
                expanded.add(b.rstrip("/") + "/" + a)
        found = self._probe_existence(expanded)
        self.endpoints |= found

    def _crawl(self, live):
        link_re = re.compile(r"""["'(](/[A-Za-z0-9_\-./]{2,80})["')]""")
        for u in list(live):
            r = self.responses.get(("GET", u))
            if not r or not r.body:
                continue
            for m in link_re.findall(r.body)[:200]:
                if API_PATH_RE.search(m) or SENSITIVE_PATH_RE.search(m):
                    self.endpoints.add(self.base + m)

    # ---- Phase 2: method probing ------------------------------------------ #
    def probe(self):
        self.log("Phase 2: HTTP method probing (%d endpoints)" % len(self.endpoints))
        jobs = [(m, u) for u in self.endpoints for m in
                (self.args.methods or METHODS)]
        def do(job):
            m, u = job
            if ("GET", u) in self.responses and m == "GET":
                return
            body = "{}" if m in ("POST", "PUT", "PATCH") else None
            hdr = {"Content-Type": "application/json"} if body else None
            r = self.client.request(m, u, body=body, headers=hdr)
            self.responses[(m, u)] = r
        with futures.ThreadPoolExecutor(max_workers=self.args.threads) as ex:
            list(ex.map(do, jobs))

    # ---- Phase 3: unauthenticated baseline for auth reasoning ------------- #
    def auth_baseline(self):
        """If a token was supplied, re-request each endpoint WITHOUT it to
        detect endpoints that behave identically authed vs unauthed."""
        if not self.auth_present:
            return
        self.log("Phase 3: unauthenticated baseline comparison")
        anon = HTTPClient(timeout=self.args.timeout)
        for (m, u), r in list(self.responses.items()):
            if m != "GET" or r.status == 0:
                continue
            ar = anon.request("GET", u)
            # same 2xx status and similar body length => no auth enforcement
            if 200 <= ar.status < 300 and 200 <= r.status < 300 and \
               abs(ar.length - r.length) < max(64, r.length * 0.1):
                self.responses[("GET", u)] = ar   # treat as anon-accessible

    # ---- Phase 3b: JWT weak-secret / alg-confusion (API2) ------------------ #
    def jwt_checks(self):
        if not self.auth_present:
            return
        m = BEARER_JWT_RE.search(self.args.auth or "")
        token = m.group(1) if m else None
        if not token and (self.args.auth or "").count(".") == 2:
            token = self.args.auth.strip()
        if not token:
            return
        self.log("Phase 3b: JWT weak-secret / alg-confusion checks")
        secret = jwt_crack_weak_secret(token)
        if secret is not None:
            self._add(Finding(
                "JWT signed with a weak/guessable HMAC secret", "critical",
                "authn", "N/A", "/", 0,
                "Offline dictionary attack recovered the signing secret: %r"
                % (secret or "<empty string>"),
                "Use a high-entropy secret (>=256 bits) generated with a CSPRNG "
                "and rotate the compromised key immediately; consider RS256."))
        forged = jwt_forge_alg_none(token)
        if forged:
            probe_url = None
            for (method, url) in self.responses:
                if method == "GET" and API_PATH_RE.search(url):
                    probe_url = url
                    break
            if probe_url:
                baseline = self.client.request("GET", probe_url)
                forged_resp = self.client.request(
                    "GET", probe_url, headers={"Authorization": "Bearer " + forged})
                if forged_resp.status and forged_resp.status == baseline.status and \
                   200 <= forged_resp.status < 300:
                    self._add(Finding(
                        "JWT alg-confusion — server accepts 'alg: none' token",
                        "critical", "authn", "GET",
                        urllib.parse.urlparse(probe_url).path, forged_resp.status,
                        "Forged unsigned token (alg=none) accepted with status %d"
                        % forged_resp.status,
                        "Reject tokens whose header alg is not an explicitly "
                        "allow-listed algorithm; never trust the alg claim from "
                        "the token itself."))

    # ---- Phase 3c: mass assignment (API3) ---------------------------------- #
    def mass_assignment_checks(self):
        self.log("Phase 3c: mass-assignment probing (PUT/PATCH)")
        targets = {u for (m, u) in self.responses
                   if m in ("PUT", "PATCH") and self.responses[(m, u)].status
                   and not AUTH_PATH_RE.search(urllib.parse.urlparse(u).path)}
        for u in list(targets)[:60]:      # cap requests to stay black-box-fast
            body = json.dumps(MASS_ASSIGNMENT_FIELDS)
            r = self.client.request("PATCH", u, body=body,
                                    headers={"Content-Type": "application/json"})
            if not (200 <= r.status < 300):
                continue
            hit_fields = [k for k in ("role", "is_admin", "isAdmin", "admin",
                                      "account_type", "verified", "balance",
                                      "price", "status")
                          if re.search(r'"%s"\s*:\s*(%s)' %
                                       (re.escape(k),
                                        re.escape(json.dumps(MASS_ASSIGNMENT_FIELDS[k]))),
                                       r.body)]
            if hit_fields:
                path = urllib.parse.urlparse(u).path
                self._add(Finding(
                    "Mass assignment — privileged fields accepted", "high",
                    "authz", "PATCH", path, r.status,
                    "Server echoed/accepted attacker-supplied field(s): %s"
                    % ", ".join(hit_fields),
                    "Use an explicit allow-list of writable fields per endpoint; "
                    "never bind request bodies directly onto internal models."))

    # ---- Phase 3d: BOLA/BFLA differential testing (API1/API5) -------------- #
    def differential_authz_checks(self):
        if not self.auth2_present:
            return
        self.log("Phase 3d: BOLA/BFLA differential testing (--auth2)")
        candidates = [(m, u) for (m, u), r in self.responses.items()
                     if m == "GET" and self._is_accessible(r)]
        for m, u in candidates:
            r2 = self.client2.request("GET", u)
            self.responses2[(m, u)] = r2
            path = urllib.parse.urlparse(u).path
            if not (200 <= r2.status < 300):
                continue
            if BFLA_PATH_RE.search(path):
                self._add(Finding(
                    "Broken Function-Level Authorization (BFLA)", "critical",
                    "authz", m, path, r2.status,
                    "Lower-privileged token (--auth2) reached a privileged "
                    "function endpoint and received %d" % r2.status,
                    "Enforce role/permission checks server-side on every "
                    "privileged function, not just at the UI layer."))
            elif ID_SEGMENT_RE.search(u) and not AUTH_PATH_RE.search(path):
                self._add(Finding(
                    "Possible Broken Object-Level Authorization (BOLA/IDOR) — "
                    "confirmed cross-token access", "high",
                    "authz", m, path, r2.status,
                    "Object-identifier endpoint returned %d for BOTH --auth and "
                    "--auth2 tokens; if these identities do not own the same "
                    "object this is a confirmed IDOR" % r2.status,
                    "Verify server-side that the authenticated caller owns/may "
                    "access the specific object id requested, on every call."))

    # ---- Phase 3e: rate limiting / resource consumption (API4) ------------- #
    def rate_limit_checks(self):
        if not self.args.burst:
            return
        self.log("Phase 3e: rate-limit / resource-consumption probing")
        auth_targets = {u for (m, u) in self.responses
                        if m == "GET" and AUTH_PATH_RE.search(
                            urllib.parse.urlparse(u).path)}
        sample = list(auth_targets)[:3] or list(self.endpoints)[:1]
        for u in sample:
            statuses = []
            with futures.ThreadPoolExecutor(max_workers=min(self.args.burst, 20)) as ex:
                jobs = [u] * self.args.burst
                for r in ex.map(lambda uu: self.client.request("GET", uu), jobs):
                    statuses.append(r.status)
            throttled = any(s == 429 for s in statuses)
            if not throttled and statuses.count(0) < len(statuses):
                path = urllib.parse.urlparse(u).path
                sensitive = AUTH_PATH_RE.search(path)
                self._add(Finding(
                    "Unrestricted resource consumption — no rate limiting observed",
                    "high" if sensitive else "medium", "resource", "GET", path, 0,
                    "%d rapid requests to %s returned no HTTP 429/Retry-After"
                    % (len(statuses), path),
                    "Apply per-client/per-token rate limiting and quotas, "
                    "especially on authentication and business-critical endpoints."))

    # ---- Phase 4: classifiers --------------------------------------------- #
    def classify(self):
        self.log("Phase 4: deterministic classification")
        for (method, url), r in self.responses.items():
            if r.status == 0 or url not in self.endpoints:
                continue
            if self._is_soft_404(r):
                continue
            path = urllib.parse.urlparse(url).path or "/"
            self._c_auth(method, path, url, r)
            self._c_bola(method, path, url, r)
            self._c_sensitive_path(method, path, url, r)
            self._c_data_exposure(method, path, url, r)
            self._c_method_oracle(method, path, url, r)
            self._c_server_error(method, path, url, r)
            self._c_secrets(method, path, url, r)
            self._c_verbose_error(method, path, url, r)
            self._c_dangerous_methods(method, path, url, r)
        # per-endpoint (GET) passive checks
        seen_host_hdrs = False
        for (method, url), r in self.responses.items():
            if method != "GET" or r.status == 0 or url not in self.endpoints:
                continue
            if self._is_soft_404(r):
                continue
            path = urllib.parse.urlparse(url).path or "/"
            self._c_cors(path, url, r)
            if not seen_host_hdrs and r.headers:
                self._c_headers(path, r)          # header hygiene once at root-ish
                seen_host_hdrs = True
            self._c_server_banner(path, r)
        self._c_graphql()

    def _is_accessible(self, r):
        return 200 <= r.status < 300

    def _try_403_bypass(self, url, headers=None):
        """Attempt the common access-control-bypass techniques (path
        mutation / spoofed headers, per the LucasPDiniz/403-Bypass catalogue)
        against a URL that returned 403. Returns (Response, technique) for the
        first variant that yields 2xx, or (None, None) if nothing worked."""
        parsed = urllib.parse.urlparse(url)
        base_path = parsed.path or "/"
        variants = []
        for suf in BYPASS_PATH_SUFFIXES:
            variants.append((base_path.rstrip("/") + suf, None, "path suffix %r" % suf))
        for pre in BYPASS_PATH_PREFIXES:
            variants.append((pre + base_path.lstrip("/"), None, "path prefix %r" % pre))
        if BYPASS_CASE_VARIANTS:
            segs = base_path.rstrip("/").split("/")
            if segs and segs[-1]:
                upper = "/".join(segs[:-1] + [segs[-1].upper()])
                variants.append((upper, None, "uppercase final segment"))
        for hdrset in BYPASS_HEADER_SETS:
            filled = {k: (v if v is not None else url) for k, v in hdrset.items()}
            variants.append((base_path, filled, "header %s" % list(hdrset.keys())[0]))
        for new_path, hdrs, technique in variants:
            new_url = parsed._replace(path=new_path).geturl()
            req_headers = dict(headers or {})
            if hdrs:
                req_headers.update(hdrs)
            resp = self.client.request("GET", new_url, headers=req_headers or None)
            if 200 <= resp.status < 300 and not self._is_soft_404(resp):
                return resp, technique
        return None, None

    def _c_auth(self, method, path, url, r):
        if self._is_soft_404(r):
            return
        if not (API_PATH_RE.search(path) and self._is_accessible(r)):
            return
        if AUTH_PATH_RE.search(path):     # login/register are meant to be open
            return
        sensitive = bool(SENSITIVE_PATH_RE.search(path)) or \
            re.search(r"(user|account|admin|order|payment|key|secret)", path, re.I)
        sev = "high" if sensitive else "medium"
        self._add(Finding(
            "Broken authentication — API endpoint reachable without credentials",
            sev, "authn", method, path, r.status,
            "%s %s returned %d with no authentication (%d bytes)"
            % (method, path, r.status, r.length),
            "Enforce authentication on all non-public API routes; deny by "
            "default and require a valid session/token before processing."))

    def _c_bola(self, method, path, url, r):
        if self._is_soft_404(r):
            return
        if not (self._is_accessible(r) and ID_SEGMENT_RE.search(url)):
            return
        if AUTH_PATH_RE.search(path):
            return
        self._add(Finding(
            "Possible Broken Object-Level Authorization (BOLA/IDOR)",
            "high", "authz", method, path, r.status,
            "Object-identifier endpoint served %d without ownership check: %s"
            % (r.status, path),
            "Enforce per-object authorization: verify the caller owns/*may* "
            "access the referenced object id on every request, server-side."))

    def _c_sensitive_path(self, method, path, url, r):
        if not SENSITIVE_PATH_RE.search(path):
            return
        if self._is_soft_404(r) or r.status in (404, 410):
            return
        public = self._is_accessible(r)
        if public:
            self._add(Finding(
                "Sensitive/internal endpoint exposed", "high",
                "exposure", method, path, r.status,
                "%s %s -> %d (publicly reachable)" % (method, path, r.status),
                "Remove internal/admin/debug endpoints from the public edge or "
                "gate them behind network controls and strong authentication."))
            return
        if r.status == 403 and method == "GET":
            # A bare 403 is not itself a vulnerability — confirm it's actually
            # enforced before reporting, instead of flagging every WAF/gateway
            # deny-by-default response as a finding (a common false positive).
            bypass_resp, technique = self._try_403_bypass(url)
            if bypass_resp:
                self._add(Finding(
                    "403 access control bypassed on sensitive endpoint",
                    "critical", "authz", method, path, bypass_resp.status,
                    "Direct request returned 403, but bypass via %s returned "
                    "%d and served content" % (technique, bypass_resp.status),
                    "Enforce access control in application logic (not only at "
                    "the edge/proxy layer); normalize paths before authz "
                    "decisions so proxies and the app agree on the same URL."))
            # else: genuinely restricted — intentionally not reported, this is
            # the expected/secure state and was previously a false positive.

    def _c_data_exposure(self, method, path, url, r):
        if self._is_soft_404(r):
            return
        if method not in ("GET",) or not self._is_accessible(r):
            return
        if "json" not in r.ctype.lower() or r.length < 50:
            return
        if AUTH_PATH_RE.search(path):
            return
        # Only flag if it also looks like it returns records, not static config
        if re.search(r'("email"|"password"|"ssn"|"token"|"phone"|"address"|'
                     r'"first_?name"|"user"|"role")', r.body, re.I):
            self._add(Finding(
                "Sensitive data exposure — records returned without auth",
                "medium", "exposure", method, path, r.status,
                "JSON response (%d bytes) contains user/record-like fields "
                "without authentication" % r.length,
                "Require authorization and return only fields the caller is "
                "entitled to; apply response filtering / field-level authz."))

    def _c_method_oracle(self, method, path, url, r):
        if r.status == 405:
            self._add(Finding(
                "Method-not-allowed oracle confirms endpoint", "info",
                "exposure", method, path, r.status,
                "405 confirms %s exists though %s is rejected" % (path, method),
                "Not exploitable alone; ensure the endpoint enforces authz for "
                "its allowed methods."))

    def _c_server_error(self, method, path, url, r):
        if r.status >= 500:
            self._add(Finding(
                "Server error on probe — potential injection/parsing fault",
                "medium", "robustness", method, path, r.status,
                "%s %s -> %d (unhandled error under crafted/empty input)"
                % (method, path, r.status),
                "Add input validation and error handling; a 5xx under simple "
                "probing often marks an injection or deserialization surface."))

    def _c_secrets(self, method, path, url, r):
        if not r.body:
            return
        for name, pat in SECRET_PATTERNS:
            m = pat.search(r.body)
            if m:
                snippet = m.group(0)
                snippet = snippet[:12] + "…" if len(snippet) > 12 else snippet
                self._add(Finding(
                    "Secret leaked in API response: %s" % name, "high",
                    "exposure", method, path, r.status,
                    "Pattern '%s' matched in response body (redacted: %s)"
                    % (name, snippet),
                    "Never return credentials/keys in responses. Rotate the "
                    "exposed secret immediately and scrub it from the payload."))
                break

    def _c_verbose_error(self, method, path, url, r):
        if not r.body:
            return
        for tech, pat in ERROR_SIGNATURES:
            if pat.search(r.body):
                self._add(Finding(
                    "Verbose error / stack trace disclosure (%s)" % tech,
                    "low", "exposure", method, path, r.status,
                    "Response leaks %s error internals" % tech,
                    "Return generic error messages to clients; log details "
                    "server-side only. Disable debug mode in production."))
                break

    def _c_dangerous_methods(self, method, path, url, r):
        if method in ("PUT", "DELETE") and self._is_accessible(r):
            self._add(Finding(
                "Dangerous HTTP method enabled (%s)" % method, "medium",
                "config", method, path, r.status,
                "%s %s accepted (%d) — write/delete reachable"
                % (method, path, r.status),
                "Disable unused verbs; ensure PUT/DELETE require strong authz "
                "and cannot mutate objects the caller doesn't own."))
        if method == "OPTIONS" and r.status and r.headers.get("allow"):
            allow = r.headers["allow"]
            if "TRACE" in allow.upper():
                self._add(Finding(
                    "TRACE method advertised", "low", "config", method, path,
                    r.status, "Allow header advertises TRACE: %s" % allow,
                    "Disable TRACE to prevent cross-site tracing."))

    def _c_cors(self, path, url, r):
        probe = self.client.request("GET", url,
                                    headers={"Origin": "https://evil.example"})
        acao = probe.headers.get("access-control-allow-origin", "")
        acac = probe.headers.get("access-control-allow-credentials", "")
        if acao == "*" and acac.lower() == "true":
            self._add(Finding(
                "CORS misconfiguration — wildcard origin with credentials",
                "high", "config", "GET", path, r.status,
                "ACAO '*' returned together with Allow-Credentials: true",
                "Never combine ACAO '*' with credentials. Reflect only an "
                "explicit allow-list of trusted origins."))
        elif acao == "https://evil.example":
            self._add(Finding(
                "CORS misconfiguration — arbitrary origin reflected",
                "high" if acac.lower() == "true" else "medium", "config",
                "GET", path, r.status,
                "Untrusted Origin reflected in ACAO%s"
                % (" with credentials" if acac.lower() == "true" else ""),
                "Validate Origin against an explicit allow-list; do not echo "
                "the request Origin blindly."))

    def _c_headers(self, path, r):
        for hk, msg in SECURITY_HEADERS.items():
            if hk not in r.headers:
                self._add(Finding(
                    "Missing security header: %s" % hk, "low", "transport",
                    "GET", path, r.status, msg,
                    "Set %s at the API edge/gateway for all responses." % hk))

    def _c_server_banner(self, path, r):
        for hk in ("server", "x-powered-by", "x-aspnet-version"):
            v = r.headers.get(hk, "")
            if v and re.search(r"\d", v):
                self._add(Finding(
                    "Version disclosure via %s header" % hk, "info", "config",
                    "GET", path, r.status, "%s: %s" % (hk, v),
                    "Strip or genericize server/version headers to reduce "
                    "fingerprinting."))
                break

    def _c_graphql(self):
        for u in list(self.endpoints):
            if not u.endswith("/graphql") and "/graphql" not in u:
                continue
            q = json.dumps({"query": "{__schema{types{name}}}"})
            r = self.client.request("POST", u, body=q,
                                    headers={"Content-Type": "application/json"})
            if r.status and "__schema" in r.body:
                self._add(Finding(
                    "GraphQL introspection enabled", "medium", "exposure",
                    "POST", urllib.parse.urlparse(u).path, r.status,
                    "__schema introspection query succeeded",
                    "Disable introspection in production or restrict it to "
                    "authenticated internal clients."))

    # ---- run --------------------------------------------------------------- #
    def run(self):
        t0 = time.time()
        self.discover()
        self.probe()
        self.auth_baseline()
        self.jwt_checks()
        self.mass_assignment_checks()
        self.differential_authz_checks()
        self.rate_limit_checks()
        self.classify()
        self.elapsed = time.time() - t0
        return sorted(self.findings.values(),
                      key=lambda f: (SEV_RANK.get(f.severity, 9), f.category, f.path))


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

COLORS = {"critical": "\033[95m", "high": "\033[91m", "medium": "\033[93m",
          "low": "\033[94m", "info": "\033[90m", "reset": "\033[0m"}

def report_console(base, findings, elapsed, quiet):
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    print("\n" + "=" * 70)
    print("apiscan %s — %s" % (VERSION, base))
    print("%d findings in %.1fs" % (len(findings), elapsed))
    order = ["critical", "high", "medium", "low", "info"]
    print("  " + "  ".join("%s:%d" % (s, counts.get(s, 0)) for s in order))
    print("=" * 70)
    use_color = sys.stdout.isatty()
    for f in findings:
        c = COLORS[f.severity] if use_color else ""
        z = COLORS["reset"] if use_color else ""
        print("\n%s[%s]%s %s" % (c, f.severity.upper(), z, f.title))
        print("    %-6s %s  (HTTP %s, %s)" % (f.method, f.path, f.status, f.category))
        print("    evidence:    %s" % f.evidence)
        print("    remediation: %s" % f.remediation)
    print()


def report_jsonl(path, base, findings):
    with open(path, "w") as fh:
        meta = {"_meta": True, "target": base, "version": VERSION,
                "generated": datetime.now(timezone.utc).isoformat(),
                "total": len(findings)}
        fh.write(json.dumps(meta) + "\n")
        for f in findings:
            fh.write(json.dumps(asdict(f)) + "\n")


def report_html(path, base, findings, elapsed):
    rows = []
    for f in findings:
        rows.append(
            "<tr class='{sev}'><td>{sev}</td><td>{cat}</td><td>{m}</td>"
            "<td>{p}</td><td>{s}</td><td>{t}</td><td>{e}</td><td>{r}</td></tr>"
            .format(sev=f.severity, cat=f.category, m=f.method,
                    p=_esc(f.path), s=f.status, t=_esc(f.title),
                    e=_esc(f.evidence), r=_esc(f.remediation)))
    html = """<!doctype html><meta charset=utf-8><title>apiscan report</title>
<style>body{{font:14px system-ui;margin:2rem;color:#111}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ddd;
padding:6px 8px;text-align:left;vertical-align:top}}th{{background:#111;color:#fff}}
tr.critical td:first-child{{background:#7c3aed;color:#fff}}
tr.high td:first-child{{background:#dc2626;color:#fff}}
tr.medium td:first-child{{background:#f59e0b}}
tr.low td:first-child{{background:#3b82f6;color:#fff}}
tr.info td:first-child{{background:#9ca3af;color:#fff}}</style>
<h1>apiscan report</h1><p><b>{base}</b> — {n} findings in {t:.1f}s</p>
<table><tr><th>Severity</th><th>Category</th><th>Method</th><th>Path</th>
<th>Status</th><th>Title</th><th>Evidence</th><th>Remediation</th></tr>
{rows}</table>""".format(base=_esc(base), n=len(findings), t=elapsed,
                         rows="\n".join(rows))
    with open(path, "w") as fh:
        fh.write(html)


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def normalize(target):
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target


def main():
    ap = argparse.ArgumentParser(
        description="Unified black-box API security scanner (stdlib only).",
        epilog="Authorized testing only. Scan systems you own or may test.")
    ap.add_argument("target", help="API host or URL, e.g. api.example.com")
    ap.add_argument("--auth", help="Authorization header value, e.g. 'Bearer xxx'")
    ap.add_argument("--auth2",
                     help="Second, LOWER-privileged Authorization header value. "
                          "Enables real BOLA/BFLA differential testing (API1/API5): "
                          "endpoints reachable with --auth are re-requested with "
                          "--auth2 to detect missing object/function-level authz.")
    ap.add_argument("--burst", type=int, default=20,
                     help="Requests fired in the API4 rate-limit probe burst (0 disables)")
    ap.add_argument("--threads", type=int, default=20)
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--methods", nargs="*", help="Restrict probed HTTP methods")
    ap.add_argument("--json", metavar="FILE", help="Write findings as JSONL")
    ap.add_argument("--html", metavar="FILE", help="Write findings as HTML")
    ap.add_argument("--quiet", action="store_true", help="Suppress progress")
    ap.add_argument("--yes", action="store_true",
                    help="(deprecated, no-op; kept for compatibility)")
    args = ap.parse_args()

    base = normalize(args.target)
    if not args.quiet:
        print("[*] Target: %s" % urllib.parse.urlparse(base).netloc,
              file=sys.stderr)

    scanner = Scanner(base, args)
    findings = scanner.run()
    report_console(base, findings, scanner.elapsed, args.quiet)
    if args.json:
        report_jsonl(args.json, base, findings)
        print("[+] JSONL written to %s" % args.json, file=sys.stderr)
    if args.html:
        report_html(args.html, base, findings, scanner.elapsed)
        print("[+] HTML written to %s" % args.html, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
