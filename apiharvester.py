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

import concurrent.futures as futures

import json

import re

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

            raw = e.read(self.max_body) if hasattr(e, "read") else b""

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

        self.findings = {}

        self.responses = {}     # (method, url) -> Response

        self.endpoints = set()



    def _auth_header(self):

        if self.args.auth:

            return {"Authorization": self.args.auth}

        return {}



    def _add(self, f: Finding):

        self.findings.setdefault(f.key(), f)



    def log(self, *a):

        if not self.args.quiet:

            print("[*]", *a, file=sys.stderr)



    # ---- Phase 1: discovery ------------------------------------------------ #

    def discover(self):

        self.log("Phase 1: endpoint discovery")

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

            if 200 <= ar.status < 300 and 200 <= r.status < 300 and abs(ar.length - r.length) < max(64, r.length * 0.1):


                self.responses[("GET", u)] = ar   # treat as anon-accessible



    # ---- Phase 4: classifiers --------------------------------------------- #

    def classify(self):

        self.log("Phase 4: deterministic classification")

        for (method, url), r in self.responses.items():

            if r.status == 0:

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

            if method != "GET" or r.status == 0:

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



    def _c_auth(self, method, path, url, r):

        if not (API_PATH_RE.search(path) and self._is_accessible(r)):

            return

        if AUTH_PATH_RE.search(path):     # login/register are meant to be open

            return

        sensitive = bool(SENSITIVE_PATH_RE.search(path)) or re.search(r"(user|account|admin|order|payment|key|secret)", path, re.I)


        sev = "high" if sensitive else "medium"

        self._add(Finding(

            "Broken authentication — API endpoint reachable without credentials",

            sev, "authn", method, path, r.status,

            "%s %s returned %d with no authentication (%d bytes)"

            % (method, path, r.status, r.length),

            "Enforce authentication on all non-public API routes; deny by "

            "default and require a valid session/token before processing."))



    def _c_bola(self, method, path, url, r):

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

        if r.status in (404, 410):

            return

        public = self._is_accessible(r)

        self._add(Finding(

            "Sensitive/internal endpoint exposed", "high" if public else "medium",

            "exposure", method, path, r.status,

            "%s %s -> %d (%s)" % (method, path, r.status,

                                  "publicly reachable" if public

                                  else "present but restricted"),

            "Remove internal/admin/debug endpoints from the public edge or "

            "gate them behind network controls and strong authentication."))



    def _c_data_exposure(self, method, path, url, r):

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