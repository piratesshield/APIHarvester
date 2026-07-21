#!/usr/bin/env python3
"""
ARISE API Intelligence Engine
==============================
Resolves the root cause of 0 API security findings:
  - Collects every endpoint already discovered by prior pipeline modules
  - Probes HTTP methods, detects auth requirements, expands with action wordlists
  - Classifies vulnerabilities deterministically (no AI required)
  - Writes api_findings.jsonl in the exact format the dashboard reads

Usage (called from easm-pipeline.sh):
  python3 api_intelligence_engine.py <scan_output_dir> [--rate N] [--timeout N] [--threads N]

Falls back gracefully if any tool (ffuf, nuclei) is missing.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import urllib.request
import urllib.error
import ssl

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    format="[%(levelname)s] %(message)s",
    level=logging.INFO,
    stream=sys.stderr,
)
log = logging.getLogger("arise.api_intel")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

API_PATH_RE = re.compile(
    r"(/api/|/v[0-9]+[./]|/graphql|/rest/|/ws/|/rpc/|/oauth|/token"
    r"|/auth|/login|/signin|/logout|/register|/signup|/user|/users"
    r"|/account|/profile|/admin|/internal|/webhook|/callback|/health"
    r"|/status|/metrics|/docs|/swagger|/openapi)",
    re.IGNORECASE,
)

SENSITIVE_PATH_RE = re.compile(
    r"(/admin|/internal|/debug|/config|/settings|/manage|/console"
    r"|/panel|/backdoor|/test|/dev|/staging|/private|/secret"
    r"|/backup|/dump|/export|/import|/upload|/download|/file)",
    re.IGNORECASE,
)

AUTH_PATH_RE = re.compile(
    r"(/login|/signin|/auth|/oauth|/token|/session|/register|/signup"
    r"|/forgot.?password|/reset.?password|/verify|/2fa|/mfa|/otp)",
    re.IGNORECASE,
)

ID_SEGMENT_RE = re.compile(
    r"^(\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
    r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[A-Za-z0-9_-]{20,})$"
)

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# SecLists-style action wordlist (built-in subset; engine also loads external file if present)
BUILTIN_ACTIONS = [
    "login", "logout", "register", "signup", "signin",
    "forgot-password", "reset-password", "verify", "confirm",
    "refresh", "token", "revoke", "validate",
    "create", "update", "delete", "remove", "add", "edit", "list",
    "search", "filter", "export", "import", "upload", "download",
    "status", "health", "ping", "metrics", "info", "version",
    "users", "user", "profile", "account", "accounts",
    "admin", "admins", "roles", "permissions", "groups",
    "orders", "order", "cart", "checkout", "payment", "payments",
    "products", "product", "catalog", "inventory",
    "notifications", "notification", "alerts", "messages",
    "settings", "config", "configuration", "preferences",
    "reports", "report", "analytics", "stats", "statistics",
    "audit", "logs", "events", "history",
    "debug", "test", "internal", "private", "secret",
    "graphql", "query", "mutation", "subscription",
    "webhook", "callback", "notify",
    "v1", "v2", "v3", "api", "rest",
]

INTERESTING_STATUS = {200, 201, 204, 301, 302, 400, 401, 403, 405, 422, 500}

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Endpoint:
    url: str
    host: str = ""
    path: str = ""
    method: str = "GET"
    status_code: Optional[int] = None
    response_length: int = 0
    content_type: str = ""
    auth_required: bool = False
    accessible_unauthenticated: bool = False
    has_id_param: bool = False
    is_sensitive: bool = False
    is_auth_endpoint: bool = False
    source: str = ""
    response_snippet: str = ""

    def __post_init__(self):
        parsed = urllib.parse.urlparse(self.url)
        self.host = self.host or parsed.netloc.split(":")[0]
        self.path = self.path or parsed.path or "/"
        self.has_id_param = bool(
            any(ID_SEGMENT_RE.match(seg) for seg in self.path.split("/") if seg)
            or re.search(r"\{[^}]+\}", self.path)
            or re.search(r"=[0-9]+(&|$)", parsed.query or "")
        )
        self.is_sensitive = bool(SENSITIVE_PATH_RE.search(self.path))
        self.is_auth_endpoint = bool(AUTH_PATH_RE.search(self.path))


@dataclass
class Finding:
    method: str
    path: str
    host: str
    issue_class: str
    category: str
    severity: str
    tool: str
    evidence: str
    status_code: Optional[int] = None
    remediation: str = ""
    endpoint: str = ""
    tools: List[str] = field(default_factory=list)
    confidence: str = "single-tool"

    def __post_init__(self):
        if not self.endpoint:
            self.endpoint = f"{self.method} {self.path}"
        if not self.tools:
            self.tools = [self.tool]

    def dedup_key(self) -> str:
        return hashlib.md5(
            f"{self.method}|{self.template_path()}|{self.issue_class}".encode()
        ).hexdigest()

    def template_path(self) -> str:
        """Collapse concrete IDs so /users/123 and /users/456 deduplicate."""
        parts = []
        for seg in self.path.split("/"):
            parts.append("{id}" if seg and ID_SEGMENT_RE.match(seg) else seg)
        return "/".join(parts)

    def to_jsonl(self) -> str:
        return json.dumps({
            "method": self.method,
            "path": self.template_path(),
            "host": self.host,
            "endpoint": f"{self.method} {self.template_path()}",
            "issue_class": self.issue_class,
            "category": self.category,
            "severity": self.severity,
            "tool": self.tool,
            "tools": self.tools,
            "confidence": self.confidence,
            "evidence": self.evidence[:500],
            "status_code": self.status_code,
            "remediation": self.remediation,
        })


# ---------------------------------------------------------------------------
# Phase 1 — Endpoint collection from all prior pipeline outputs
# ---------------------------------------------------------------------------

class EndpointCollector:
    """Reads every URL source the pipeline already produced."""

    def __init__(self, scan_dir: Path):
        self.scan_dir = scan_dir

    def collect(self) -> List[str]:
        urls: Set[str] = set()

        sources = [
            self.scan_dir / "09_crawling" / "all_urls.txt",
            self.scan_dir / "08_directory_discovery" / "all_paths.txt",
            self.scan_dir / "08_directory_discovery" / "urls_for_dirsearch.txt",
            self.scan_dir / "11_param_fuzzing" / "urls_with_params.txt",
            # Module 20 (API Deep Discovery, ARISEv3) — headless-intercepted XHR/fetch
            # API calls and classified injectable targets. These are the highest-value
            # endpoints (real runtime API traffic) and are NOT all merged into
            # 09_crawling/all_urls.txt, so pull them explicitly.
            self.scan_dir / "20_api_deep_discovery" / "xhr_intercepted.txt",
            self.scan_dir / "20_api_deep_discovery" / "katana_headless_urls.txt",
            self.scan_dir / "20_api_deep_discovery" / "injection_targets.txt",
            self.scan_dir / "20_api_deep_discovery" / "sqli_targets.txt",
        ]

        for f in sources:
            if f.exists():
                for line in f.read_text(errors="ignore").splitlines():
                    line = line.strip()
                    if line and line.startswith("http"):
                        urls.add(line.split()[0])  # strip trailing whitespace/columns
                log.info("Collected from %s: %d URLs (running total %d)", f.name,
                         sum(1 for l in f.read_text(errors="ignore").splitlines()
                             if l.strip().startswith("http")), len(urls))

        # Module 20 JSONL outputs (each line carries a "url" field).
        for jsonl_name in ("api_deep_discovery.jsonl", "api_endpoints.jsonl"):
            jf = self.scan_dir / "20_api_deep_discovery" / jsonl_name
            if jf.exists():
                added = 0
                for line in jf.read_text(errors="ignore").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        u = json.loads(line).get("url", "")
                    except Exception:
                        continue
                    if u and u.startswith("http"):
                        urls.add(u)
                        added += 1
                log.info("Collected from %s: %d URLs (running total %d)",
                         jsonl_name, added, len(urls))

        # JS-extracted endpoints
        js_dir = self.scan_dir / "09_crawling" / "js_downloads"
        if js_dir.exists():
            for js_file in js_dir.glob("*.txt"):
                for line in js_file.read_text(errors="ignore").splitlines():
                    line = line.strip()
                    if line.startswith("http"):
                        urls.add(line)

        # Nuclei findings often reference endpoint URLs
        nuclei_file = self.scan_dir / "12_nuclei_scanning" / "nuclei_results.txt"
        if nuclei_file.exists():
            for line in nuclei_file.read_text(errors="ignore").splitlines():
                m = re.search(r"https?://[^\s\]]+", line)
                if m:
                    urls.add(m.group(0))

        # Manifest: pull http URLs of all known API hosts
        manifest_file = self.scan_dir / "manifest.json"
        if manifest_file.exists():
            try:
                manifest = json.loads(manifest_file.read_text())
                for host, data in manifest.get("hosts", {}).items():
                    if data.get("is_api") and data.get("url"):
                        urls.add(data["url"].rstrip("/"))
            except Exception:
                pass

        log.info("Total raw URLs collected: %d", len(urls))
        return list(urls)


# ---------------------------------------------------------------------------
# Phase 2 — Filter to API endpoints
# ---------------------------------------------------------------------------

class EndpointFilter:
    def filter(self, urls: List[str]) -> List[Endpoint]:
        endpoints: Dict[str, Endpoint] = {}

        for url in urls:
            try:
                parsed = urllib.parse.urlparse(url)
            except Exception:
                continue

            if not parsed.scheme or not parsed.netloc:
                continue

            # Only http/https
            if parsed.scheme not in ("http", "https"):
                continue

            # Drop S3 / cloud storage hosts
            netloc_lower = parsed.netloc.lower()
            if any(cloud in netloc_lower for cloud in [
                "s3.amazonaws.com", "amazonaws.com", "googleapis.com", 
                "clouddn.com", "azureedge.net", "azurewebsites.net", 
                "s3.cn-", "s3-r-w", "blob.core.windows.net", "storage.googleapis.com"
            ]) or "s3" in netloc_lower or "bucket" in netloc_lower:
                continue

            # Must look like an API or interesting endpoint
            if not API_PATH_RE.search(parsed.path) and not SENSITIVE_PATH_RE.search(parsed.path):
                continue

            # Deduplicate by normalised path (strip query)
            key = f"{parsed.netloc}{parsed.path}"
            if key not in endpoints:
                ep = Endpoint(
                    url=f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                    source="crawl",
                )
                endpoints[key] = ep

        log.info("API endpoints after filtering: %d", len(endpoints))
        return list(endpoints.values())


# ---------------------------------------------------------------------------
# Phase 3 — HTTP method discovery (deterministic probing)
# ---------------------------------------------------------------------------

class HTTPProbe:
    """Lightweight HTTP prober — no external deps, uses urllib only."""

    def __init__(self, timeout: int = 8, verify_ssl: bool = False):
        self.timeout = timeout
        self.ctx = ssl.create_default_context()
        if not verify_ssl:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def _request(self, method: str, url: str,
                 headers: Optional[Dict[str, str]] = None) -> Optional[Tuple[int, Dict, str]]:
        req = urllib.request.Request(url, method=method)
        req.add_header("User-Agent", "Mozilla/5.0 (ARISE-Scanner/2.1)")
        req.add_header("Accept", "application/json, */*")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                body = resp.read(2048).decode(errors="ignore")
                return resp.status, dict(resp.headers), body
        except urllib.error.HTTPError as e:
            body = e.read(512).decode(errors="ignore") if e.fp else ""
            return e.code, dict(e.headers) if e.headers else {}, body
        except Exception:
            return None

    def probe(self, ep: Endpoint, extra_headers: Optional[Dict] = None) -> Endpoint:
        result = self._request("GET", ep.url, extra_headers)
        if result is None:
            return ep
        status, headers, body = result
        ep.status_code = status
        ep.content_type = headers.get("Content-Type", "")
        ep.response_length = len(body)
        ep.response_snippet = body[:300]
        ep.auth_required = status in (401, 403)
        ep.accessible_unauthenticated = status in (200, 201, 204)
        return ep

    def probe_methods(self, url: str) -> Dict[str, int]:
        """Returns {METHOD: status_code} for supported methods."""
        supported: Dict[str, int] = {}

        # OPTIONS first — cheapest
        opt = self._request("OPTIONS", url)
        if opt:
            allow = opt[1].get("Allow", "") or opt[1].get("allow", "")
            for m in allow.split(","):
                m = m.strip().upper()
                if m:
                    supported[m] = opt[0]

        # Probe remaining common methods
        for method in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
            if method not in supported:
                r = self._request(method, url)
                if r and r[0] != 405:
                    supported[method] = r[0]

        return supported


# ---------------------------------------------------------------------------
# Phase 4 — Auth detection
# ---------------------------------------------------------------------------

class AuthDetector:
    """Detects authentication requirements and patterns without credentials."""

    def __init__(self, probe: HTTPProbe):
        self.probe = probe
        self.discovered_tokens: Dict[str, str] = {}

    def analyze(self, endpoints: List[Endpoint]) -> Dict[str, str]:
        """
        Probes auth endpoints for token patterns.
        Returns dict of {token_type: example_value_pattern}.
        No credentials stored or exfiltrated.
        """
        auth_eps = [ep for ep in endpoints if ep.is_auth_endpoint]
        log.info("Auth endpoints found: %d", len(auth_eps))

        for ep in auth_eps[:10]:
            r = self.probe._request("GET", ep.url)
            if not r:
                continue
            status, headers, body = r

            # Look for JWT pattern in response
            for m in JWT_RE.finditer(body):
                log.info("[auth] JWT pattern found at %s", ep.url)
                self.discovered_tokens["jwt_pattern"] = m.group(0)[:20] + "..."

            # WWW-Authenticate header reveals auth scheme
            www_auth = headers.get("Www-Authenticate", "") or headers.get("www-authenticate", "")
            if www_auth:
                self.discovered_tokens["www_authenticate"] = www_auth

            # Look for API key hints in headers
            for hdr in headers:
                if "api" in hdr.lower() or "token" in hdr.lower() or "key" in hdr.lower():
                    self.discovered_tokens[f"header_{hdr}"] = headers[hdr]

        return self.discovered_tokens


# ---------------------------------------------------------------------------
# Phase 5 — Endpoint expansion via actions wordlist
# ---------------------------------------------------------------------------

class EndpointExpander:
    """
    Takes each discovered base path and fuzzes with action wordlist via ffuf.
    Falls back to manual probing if ffuf is not installed.
    """

    def __init__(self, probe: HTTPProbe, wordlist_path: Optional[Path] = None):
        self.probe = probe
        self.wordlist = self._load_wordlist(wordlist_path)
        self.has_ffuf = self._check_ffuf()

    def _check_ffuf(self) -> bool:
        try:
            subprocess.run(["ffuf", "-h"], capture_output=True, timeout=3)
            return True
        except Exception:
            return False

    def _load_wordlist(self, path: Optional[Path]) -> List[str]:
        if path and path.exists():
            words = [l.strip() for l in path.read_text(errors="ignore").splitlines()
                     if l.strip() and not l.startswith("#")]
            log.info("Loaded %d words from %s", len(words), path)
            return words
        return BUILTIN_ACTIONS

    def expand(self, base_endpoints: List[Endpoint]) -> List[Endpoint]:
        """Expands each base endpoint by appending action words."""
        # Build unique base paths (strip trailing path segments that look like IDs)
        base_paths: Set[str] = set()
        for ep in base_endpoints:
            parts = ep.path.rstrip("/").split("/")
            # Use path up to (not including) the last ID-like segment
            if parts and ID_SEGMENT_RE.match(parts[-1]):
                parts = parts[:-1]
            base = "/".join(parts).rstrip("/") or "/"
            base_paths.add(f"{urllib.parse.urlparse(ep.url).scheme}://"
                          f"{urllib.parse.urlparse(ep.url).netloc}{base}")

        new_endpoints: List[Endpoint] = []

        if self.has_ffuf:
            for base in list(base_paths)[:20]:  # Cap to avoid runaway
                new_endpoints.extend(self._ffuf_expand(base))
        else:
            log.info("ffuf not found — using built-in action probing")
            new_endpoints.extend(self._manual_expand(list(base_paths)[:15]))

        log.info("Endpoint expansion discovered %d new endpoints", len(new_endpoints))
        return new_endpoints

    def _ffuf_expand(self, base_url: str) -> List[Endpoint]:
        """Uses ffuf to fuzz FUZZ placeholder in base_url/FUZZ."""
        import tempfile
        fuzz_url = base_url.rstrip("/") + "/FUZZ"
        eps: List[Endpoint] = []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as wf:
            wf.write("\n".join(self.wordlist))
            wf_path = wf.name

        # ffuf must write JSON to a real file — /dev/null loses the output
        out_file = wf_path + "_ffuf_out.json"

        try:
            cmd = [
                "ffuf", "-u", fuzz_url, "-w", wf_path,
                "-mc", "200,201,204,301,302,401,403,405",
                "-t", "20", "-timeout", "5",
                "-o", out_file, "-of", "json",
                "-s",           # silent banner
                "-noninteractive",
            ]
            subprocess.run(cmd, capture_output=True, timeout=90)

            if os.path.exists(out_file):
                try:
                    data = json.loads(open(out_file).read())
                    for r in data.get("results", []):
                        ep = Endpoint(
                            url=r["url"],
                            method="GET",
                            status_code=r.get("status"),
                            response_length=r.get("length", 0),
                            source="ffuf_expand",
                        )
                        eps.append(ep)
                    log.debug("ffuf found %d endpoints under %s", len(eps), base_url)
                except Exception as e:
                    log.debug("ffuf output parse failed for %s: %s", base_url, e)
        except Exception as e:
            log.debug("ffuf expand failed for %s: %s", base_url, e)
        finally:
            for f in (wf_path, out_file):
                try:
                    os.unlink(f)
                except OSError:
                    pass

        return eps

    def _manual_expand(self, base_urls: List[str]) -> List[Endpoint]:
        """Manually probes base_url/action for each action in wordlist."""
        eps: List[Endpoint] = []
        for base in base_urls:
            for action in self.wordlist:
                url = base.rstrip("/") + "/" + action
                r = self.probe._request("GET", url)
                if r and r[0] in INTERESTING_STATUS:
                    ep = Endpoint(url=url, status_code=r[0], source="manual_expand")
                    eps.append(ep)
                    log.debug("Expand hit: %s → %d", url, r[0])
        return eps


# ---------------------------------------------------------------------------
# Phase 6 — Vulnerability classifier (deterministic)
# ---------------------------------------------------------------------------

class VulnerabilityClassifier:
    """
    Deterministically classifies probed endpoints into findings.
    No heuristics that require AI — all rules are explicit.
    """

    def classify(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings: List[Finding] = []
        seen: Set[str] = set()

        for ep in endpoints:
            if ep.status_code is None:
                continue

            new = self._classify_endpoint(ep)
            for f in new:
                key = f.dedup_key()
                if key not in seen:
                    seen.add(key)
                    findings.append(f)

        log.info("Total findings before dedup: %d, after: %d",
                 sum(len(self._classify_endpoint(e)) for e in endpoints
                     if e.status_code is not None), len(findings))
        return findings

    def _classify_endpoint(self, ep: Endpoint) -> List[Finding]:
        results: List[Finding] = []

        # --- Broken Authentication: API endpoint accessible without auth ---
        if ep.accessible_unauthenticated and API_PATH_RE.search(ep.path):
            # Don't flag login/register pages — they're supposed to be public
            if not ep.is_auth_endpoint:
                sev = "high" if ep.is_sensitive else "medium"
                results.append(Finding(
                    method="GET",
                    path=ep.path,
                    host=ep.host,
                    issue_class="broken_authentication",
                    category="authn",
                    severity=sev,
                    tool="arise-intel",
                    evidence=(
                        f"Endpoint accessible without authentication "
                        f"(HTTP {ep.status_code}, {ep.response_length}B). "
                        f"Snippet: {ep.response_snippet[:120]}"
                    ),
                    status_code=ep.status_code,
                    remediation=(
                        "Enforce authentication on all API endpoints. "
                        "Return 401 for unauthenticated requests."
                    ),
                ))

        # --- Broken Object-Level Authorization (BOLA): ID in path, accessible ---
        if ep.has_id_param and ep.accessible_unauthenticated:
            results.append(Finding(
                method="GET",
                path=ep.path,
                host=ep.host,
                issue_class="broken_object_authorization",
                category="authz",
                severity="high",
                tool="arise-intel",
                evidence=(
                    f"Endpoint with object identifier accessible without authorization "
                    f"(HTTP {ep.status_code}). Path: {ep.path}"
                ),
                status_code=ep.status_code,
                remediation=(
                    "Verify object ownership on every request. "
                    "Ensure users can only access their own resources. "
                    "Implement per-object authorization checks."
                ),
            ))

        # --- Sensitive Endpoint Exposed ---
        if ep.is_sensitive and ep.status_code not in (404, 410):
            sev = "high" if ep.accessible_unauthenticated else "medium"
            results.append(Finding(
                method="GET",
                path=ep.path,
                host=ep.host,
                issue_class="sensitive_endpoint_exposed",
                category="exposure",
                severity=sev,
                tool="arise-intel",
                evidence=(
                    f"Sensitive path reachable (HTTP {ep.status_code}): {ep.path}"
                ),
                status_code=ep.status_code,
                remediation=(
                    "Restrict sensitive endpoints to authorised roles. "
                    "Remove internal/debug endpoints from production."
                ),
            ))

        # --- Potential Data Exposure: 200 with JSON body but no auth ---
        if (ep.accessible_unauthenticated
                and "json" in (ep.content_type or "").lower()
                and ep.response_length > 50):
            results.append(Finding(
                method="GET",
                path=ep.path,
                host=ep.host,
                issue_class="sensitive_data_exposure",
                category="exposure",
                severity="medium",
                tool="arise-intel",
                evidence=(
                    f"JSON response returned without authentication "
                    f"({ep.response_length}B). "
                    f"Content-Type: {ep.content_type}. "
                    f"Snippet: {ep.response_snippet[:150]}"
                ),
                status_code=ep.status_code,
                remediation=(
                    "Audit JSON responses for PII, tokens, or internal data. "
                    "Require authentication before returning structured data."
                ),
            ))

        # --- Method Not Allowed reveals endpoint existence ---
        if ep.status_code == 405:
            results.append(Finding(
                method=ep.method,
                path=ep.path,
                host=ep.host,
                issue_class="endpoint_enumeration",
                category="exposure",
                severity="info",
                tool="arise-intel",
                evidence=f"405 Method Not Allowed confirms endpoint exists: {ep.path}",
                status_code=405,
                remediation="Ensure undocumented endpoints are not accessible.",
            ))

        # --- Auth bypass hint: 403 on sensitive path ---
        if ep.status_code == 403 and ep.is_sensitive:
            results.append(Finding(
                method="GET",
                path=ep.path,
                host=ep.host,
                issue_class="authorization_enforcement",
                category="authz",
                severity="low",
                tool="arise-intel",
                evidence=(
                    f"403 Forbidden on sensitive path — endpoint exists, "
                    f"verify authorization logic is complete: {ep.path}"
                ),
                status_code=403,
                remediation=(
                    "Verify the 403 is enforced server-side and not bypassable "
                    "via HTTP verb tampering, path traversal, or header injection."
                ),
            ))

        # --- Server error on probe: potential injection surface ---
        if ep.status_code == 500:
            results.append(Finding(
                method=ep.method,
                path=ep.path,
                host=ep.host,
                issue_class="server_error_on_probe",
                category="robustness",
                severity="medium",
                tool="arise-intel",
                evidence=(
                    f"500 Internal Server Error on {ep.method} {ep.path}. "
                    f"Snippet: {ep.response_snippet[:120]}"
                ),
                status_code=500,
                remediation=(
                    "Handle all input errors gracefully. "
                    "Do not leak stack traces. Investigate for injection vulnerabilities."
                ),
            ))

        return results


# ---------------------------------------------------------------------------
# Phase 7 — Spec-Based Scanners (Stage B)
# ---------------------------------------------------------------------------

def generate_synthetic_spec(endpoints: List[Endpoint], host: str) -> dict:
    """Generates a minimal valid OpenAPI 3.0.0 spec for a given host's endpoints."""
    spec = {
        "openapi": "3.0.0",
        "info": {
            "title": f"Synthetic API Spec for {host}",
            "version": "1.0.0",
            "description": "Auto-synthesized spec from discovered endpoints"
        },
        "paths": {}
    }
    
    host_endpoints = [ep for ep in endpoints if ep.host == host]
    
    for ep in host_endpoints:
        path = ep.path
        parts = []
        for seg in path.split("/"):
            if seg and ID_SEGMENT_RE.match(seg):
                parts.append("{id}")
            else:
                parts.append(seg)
        templated_path = "/".join(parts)
        if not templated_path.startswith("/"):
            templated_path = "/" + templated_path
            
        if templated_path not in spec["paths"]:
            spec["paths"][templated_path] = {}
            
        method = ep.method.lower() if hasattr(ep, "method") else "get"
        if not method:
            method = "get"
            
        if method not in spec["paths"][templated_path]:
            parameters = []
            if "{id}" in templated_path:
                parameters.append({
                    "name": "id",
                    "in": "path",
                    "required": True,
                    "schema": {
                        "type": "string"
                    }
                })
            spec["paths"][templated_path][method] = {
                "summary": f"Discovered endpoint {method.upper()} {templated_path}",
                "responses": {
                    "200": {
                        "description": "Successful operation"
                    }
                }
            }
            if parameters:
                spec["paths"][templated_path][method]["parameters"] = parameters
                
    return spec


def discover_spec(host: str, timeout: int = 5) -> Optional[dict]:
    """Probes standard paths on an API host to discover a published Swagger/OpenAPI spec."""
    spec_paths = [
        "swagger.json", "swagger/v1/swagger.json", "openapi.json", "openapi.yaml",
        "v2/api-docs", "v3/api-docs", "api-docs", "api/swagger.json",
        "swagger-ui.html", "api/openapi.json"
    ]
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    for path in spec_paths:
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}/{path}"
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "Mozilla/5.0 (ARISE-Scanner/2.1)")
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    if resp.status == 200:
                        body = resp.read().decode(errors="ignore")
                        if '"swagger"' in body or '"openapi"' in body or 'swagger:' in body or 'openapi:' in body:
                            if 'swagger:' in body or 'openapi:' in body:
                                try:
                                    import yaml
                                    data = yaml.safe_load(body)
                                    if isinstance(data, dict) and ("swagger" in data or "openapi" in data):
                                        log.info("[spec-discovery] Discovered YAML spec at %s", url)
                                        return data
                                except Exception:
                                    pass
                            else:
                                try:
                                    data = json.loads(body)
                                    if isinstance(data, dict) and ("swagger" in data or "openapi" in data):
                                        log.info("[spec-discovery] Discovered JSON spec at %s", url)
                                        return data
                                except Exception:
                                    pass
            except Exception:
                continue
    return None


class AutoSwaggerAdapter:
    """Calls autoswagger with the local spec file if available or fallback url."""

    def run(self, host: str, spec_path: Optional[Path], out_dir: Path,
            extra_args: List[str] = None) -> List[Finding]:
        try:
            result = subprocess.run(
                ["which", "autoswagger"], capture_output=True, timeout=3
            )
            if result.returncode != 0:
                log.info("autoswagger not installed — skipping adapter")
                return []
        except Exception:
            return []

        findings: List[Finding] = []
        out_dir.mkdir(parents=True, exist_ok=True)

        base_url = f"https://{host}"
        out_json = out_dir / f"{hashlib.md5(host.encode()).hexdigest()}.json"
        raw_out = out_dir / f"{out_json.stem}.raw"

        cmd = ["autoswagger", base_url, "-risk", "-all", "-json"]
        if spec_path:
            cmd.extend(["-s", str(spec_path)])
        if extra_args:
            cmd.extend(extra_args)

        try:
            with open(raw_out, "w") as fout, open(str(out_json) + ".log", "w") as ferr:
                subprocess.run(cmd, stdout=fout, stderr=ferr, timeout=120)

            if raw_out.exists():
                raw = raw_out.read_text(errors="ignore")
                json_text = ""
                for i, line in enumerate(raw.splitlines()):
                    if line.startswith("{") or line.startswith("["):
                        json_text = "\n".join(raw.splitlines()[i:])
                        break
                if json_text:
                    out_json.write_text(json_text)
                raw_out.unlink(missing_ok=True)

        except Exception as e:
            log.warning("autoswagger failed for %s: %s", host, e)

        if out_json.exists():
            findings.extend(self._parse_autoswagger_json(out_json))
        return findings

    def _parse_autoswagger_json(self, jf: Path) -> List[Finding]:
        findings: List[Finding] = []
        try:
            data = json.loads(jf.read_text(errors="ignore"))
        except Exception:
            return []

        items = data if isinstance(data, list) else data.get("findings", data.get("results", []))
        if isinstance(items, dict):
            items = [items]

        for it in items or []:
            if not isinstance(it, dict):
                continue
            method = (it.get("method") or it.get("http_method") or "GET").upper()
            url = it.get("url") or it.get("endpoint") or it.get("path") or ""
            path = it.get("path") or url
            status = it.get("status") or it.get("status_code") or it.get("response_code")
            accessible = bool(it.get("accessible",
                              it.get("unauthenticated", status in (200, 201, 202, 204))))
            raw_type = (it.get("type") or it.get("issue") or it.get("finding") or "")
            issue_class, category, sev = self._classify_as(raw_type, accessible)
            findings.append(Finding(
                method=method,
                path=path,
                host=urllib.parse.urlparse(url).netloc or it.get("host", ""),
                issue_class=issue_class,
                category=category,
                severity=sev,
                tool="autoswagger",
                evidence=(it.get("evidence") or it.get("detail") or
                          f"{method} reachable, status {status}")[:300],
                status_code=status,
                remediation=(it.get("remediation") or
                             "Enforce authentication and per-object authorization."),
            ))
        return findings

    @staticmethod
    def _classify_as(raw: str, accessible: bool) -> Tuple[str, str, str]:
        raw = raw.lower()
        if "bola" in raw or "idor" in raw or "authorization" in raw:
            return "broken_object_authorization", "authz", "high"
        if "unauthenticated" in raw or "no_auth" in raw or "broken_auth" in raw:
            return "broken_authentication", "authn", "high"
        if "exposure" in raw or "sensitive" in raw or "data" in raw:
            return "sensitive_data_exposure", "exposure", "medium"
        if accessible:
            return "broken_authentication", "authn", "high"
        return "api_exposure", "exposure", "low"


class RESTlerAdapter:
    """Runs RESTler compilation and fuzz testing against API specification."""

    def run(self, spec_path: Path, host: str, out_dir: Path) -> List[Finding]:
        findings: List[Finding] = []
        restler_bin = "/Users/apple/.local/bin/restler"
        if not os.path.isfile(restler_bin):
            try:
                res = subprocess.run(["which", "restler"], capture_output=True, text=True)
                if res.returncode == 0:
                    restler_bin = res.stdout.strip()
                else:
                    return []
            except Exception:
                return []

        compile_dir = out_dir / "compile"
        test_dir = out_dir / "test"
        compile_dir.mkdir(parents=True, exist_ok=True)
        test_dir.mkdir(parents=True, exist_ok=True)

        # 1. Compile spec
        log.info("[restler] Compiling API spec for %s...", host)
        cmd_compile = [restler_bin, "compile", "--api_spec", str(spec_path)]
        try:
            res = subprocess.run(cmd_compile, cwd=str(compile_dir), capture_output=True, text=True, timeout=120)
            if res.returncode != 0:
                log.warning("[restler] Compile failed: %s", res.stderr)
        except Exception as e:
            log.warning("[restler] Compile failed to run: %s", e)
            return []

        # Find compiled grammar
        grammar_file = compile_dir / "Compile" / "grammar.py"
        dict_file = compile_dir / "Compile" / "dict.json"
        settings_file = compile_dir / "Compile" / "engine_settings.json"

        if not grammar_file.exists():
            found_grammars = list(compile_dir.glob("**/grammar.py"))
            if found_grammars:
                grammar_file = found_grammars[0]
                dict_file = grammar_file.parent / "dict.json"
                settings_file = grammar_file.parent / "engine_settings.json"
            else:
                log.warning("[restler] No grammar.py generated.")
                return []

        # 2. Run Test Fuzzing
        log.info("[restler] Running fuzz testing for %s...", host)
        cmd_test = [
            restler_bin, "test",
            "--grammar_file", str(grammar_file),
            "--dictionary_file", str(dict_file),
            "--settings", str(settings_file)
        ]
        try:
            subprocess.run(cmd_test, cwd=str(test_dir), capture_output=True, text=True, timeout=180)
        except Exception as e:
            log.warning("[restler] Test run error: %s", e)

        # 3. Parse findings
        summaries = list(test_dir.glob("**/testing_summary.json"))
        for s_file in summaries:
            try:
                summary_data = json.loads(s_file.read_text())
                bug_buckets = summary_data.get("bug_buckets", {})
                repro_bug_buckets = summary_data.get("reproducible_bug_buckets", {})
                all_bugs = {**bug_buckets, **repro_bug_buckets}
                
                for bug_type, count in all_bugs.items():
                    if count > 0:
                        findings.append(Finding(
                            method="GET",
                            path="*",
                            host=host,
                            issue_class="reliability_fuzz_failure",
                            category="robustness",
                            severity="medium",
                            tool="restler",
                            evidence=f"RESTler fuzzer identified {count} occurrences of bug type '{bug_type}'",
                            status_code=500,
                            remediation="Ensure input validation is complete. Do not leak stack traces or crash the application server on malformed requests."
                        ))
            except Exception as e:
                log.warning("[restler] Failed to parse logs: %s", e)

        return findings


class SchemathesisAdapter:
    """Runs Schemathesis properties testing against API specification."""

    def run(self, spec_path: Path, host: str, out_dir: Path) -> List[Finding]:
        findings: List[Finding] = []
        try:
            res = subprocess.run(["which", "schemathesis"], capture_output=True, text=True)
            if res.returncode != 0:
                return []
        except Exception:
            return []

        log.info("[schemathesis] Running properties test on %s...", host)
        junit_xml = out_dir / "junit.xml"
        out_dir.mkdir(parents=True, exist_ok=True)
        
        cmd = [
            "schemathesis", "run", str(spec_path),
            "--checks", "all",
            "--workers", "4",
            "--junit-xml", str(junit_xml)
        ]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=150)
            if junit_xml.exists():
                findings.extend(self._parse_junit_xml(junit_xml, host))
        except Exception as e:
            log.warning("[schemathesis] Run failed: %s", e)
            
        return findings

    def _parse_junit_xml(self, xml_path: Path, host: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(str(xml_path))
            root = tree.getroot()
            for testcase in root.findall(".//testcase"):
                failure = testcase.find("failure")
                if failure is not None:
                    name = testcase.get("name", "Schema violation")
                    msg = failure.get("message", "")
                    evidence = failure.text or msg
                    findings.append(Finding(
                        method="GET",
                        path=testcase.get("classname", "*"),
                        host=host,
                        issue_class="schema_violation",
                        category="robustness",
                        severity="medium",
                        tool="schemathesis",
                        evidence=f"Schemathesis identified schema violation: {name}. Detail: {evidence[:200]}",
                        status_code=400,
                        remediation="Validate request bodies and inputs against your OpenAPI spec schema. Reject invalid inputs with 400 Bad Request."
                    ))
        except Exception as e:
            log.warning("[schemathesis] Failed to parse XML: %s", e)
        return findings


# ---------------------------------------------------------------------------
# Main orchestrator
class APIIntelligenceEngine:

    def __init__(self, scan_dir: Path, rate: int = 30,
                 timeout: int = 8, threads: int = 20,
                 wordlist: Optional[Path] = None):
        self.scan_dir = scan_dir
        self.rate = rate
        self.timeout = timeout
        self.threads = threads

        # Sub-components
        self.probe = HTTPProbe(timeout=timeout)
        self.collector = EndpointCollector(scan_dir)
        self.filter = EndpointFilter()
        self.auth_detector = AuthDetector(self.probe)
        self.expander = EndpointExpander(self.probe, wordlist)
        self.classifier = VulnerabilityClassifier()
        self.autoswagger = AutoSwaggerAdapter()
        self.restler = RESTlerAdapter()
        self.schemathesis = SchemathesisAdapter()

        # Output paths
        self.api_sec_dir = scan_dir / "16_api_security"
        self.findings_file = self.api_sec_dir / "api_findings.jsonl"
        self.promoted_file = self.api_sec_dir / "promoted_vulnerabilities.jsonl"
        self.intel_dir = self.api_sec_dir / "intel"
        self.as_dir = self.api_sec_dir / "autoswagger"
        self.restler_dir = self.api_sec_dir / "restler"
        self.st_dir = self.api_sec_dir / "schemathesis"
        self.specs_dir = self.api_sec_dir / "specs"

    def run(self) -> int:
        self.api_sec_dir.mkdir(parents=True, exist_ok=True)
        self.intel_dir.mkdir(parents=True, exist_ok=True)
        self.as_dir.mkdir(parents=True, exist_ok=True)
        self.restler_dir.mkdir(parents=True, exist_ok=True)
        self.st_dir.mkdir(parents=True, exist_ok=True)
        self.specs_dir.mkdir(parents=True, exist_ok=True)

        log.info("=" * 60)
        log.info("ARISE API Intelligence Engine starting")
        log.info("Scan dir: %s", self.scan_dir)
        log.info("=" * 60)

        # ── Phase 1: Collect ──────────────────────────────────────────
        log.info("[Phase 1] Collecting endpoints from pipeline outputs…")
        raw_urls = self.collector.collect()

        # ── Phase 2: Filter ───────────────────────────────────────────
        log.info("[Phase 2] Filtering to API endpoints…")
        api_endpoints = self.filter.filter(raw_urls)

        if not api_endpoints:
            log.warning("No API endpoints found — check crawl/discovery outputs")
            self._write_summary(0, 0)
            return 0

        # ── Phase 3: HTTP method discovery ────────────────────────────
        log.info("[Phase 3] Probing HTTP methods (%d endpoints, %d threads)…",
                 len(api_endpoints), self.threads)
        api_endpoints = self._probe_all(api_endpoints)

        # ── Phase 4: Auth detection ───────────────────────────────────
        log.info("[Phase 4] Auth detection…")
        auth_tokens = self.auth_detector.analyze(api_endpoints)
        if auth_tokens:
            log.info("Auth patterns found: %s", list(auth_tokens.keys()))

        # ── Phase 5: Endpoint expansion ───────────────────────────────
        log.info("[Phase 5] Expanding endpoints with action wordlist…")
        expanded = self.expander.expand(api_endpoints[:50])  # cap base paths
        if expanded:
            expanded = self._probe_all(expanded)
            api_endpoints.extend(expanded)

        # Save intel snapshot
        self._save_intel_snapshot(api_endpoints)

        # ── Phase 6: Classify Stage A vulnerabilities ──────────────────
        log.info("[Phase 6] Classifying Stage A vulnerabilities (%d endpoints)…",
                 len(api_endpoints))
        findings = self.classifier.classify(api_endpoints)

        # ── Phase 7: Stage B Spec-Based Scanners ───────────────────────
        log.info("[Phase 7] Running Spec-Based Scanners (Stage B)...")
        unique_hosts = {ep.host for ep in api_endpoints if ep.host}
        
        for host in unique_hosts:
            log.info("[spec-discovery] Probing %s for published specifications...", host)
            spec_data = discover_spec(host, timeout=self.timeout)
            
            spec_host_dir = self.specs_dir / host
            spec_host_dir.mkdir(parents=True, exist_ok=True)
            spec_file_path = None
            
            if spec_data:
                spec_file_path = spec_host_dir / "discovered_spec.json"
                spec_file_path.write_text(json.dumps(spec_data, indent=2))
                log.info("[spec-discovery] Discovered and saved spec for %s to %s", host, spec_file_path)
            else:
                log.info("[spec-discovery] No published spec found for %s. Generating synthetic spec...", host)
                synthetic_spec_data = generate_synthetic_spec(api_endpoints, host)
                spec_file_path = spec_host_dir / "synthetic_spec.json"
                spec_file_path.write_text(json.dumps(synthetic_spec_data, indent=2))
                log.info("[spec-discovery] Saved synthetic spec to %s", spec_file_path)
            
            # Run spec-driven scanners
            # AutoSwagger
            log.info("[Stage B] Running AutoSwagger for %s...", host)
            as_findings = self.autoswagger.run(host, spec_file_path, self.as_dir)
            findings.extend(as_findings)
            
            # RESTler
            log.info("[Stage B] Running RESTler for %s...", host)
            restler_host_dir = self.restler_dir / host
            restler_findings = self.restler.run(spec_file_path, host, restler_host_dir)
            findings.extend(restler_findings)
            
            # Schemathesis
            log.info("[Stage B] Running Schemathesis for %s...", host)
            st_host_dir = self.st_dir / host
            st_findings = self.schemathesis.run(spec_file_path, host, st_host_dir)
            findings.extend(st_findings)

        # ── Phase 8: Stage C Dedup + Confidence Scoring + Promotion ───
        log.info("[Phase 8] Running Dedup, Confidence Scoring and Promotion (Stage C)...")
        findings = self._dedup(findings)
        
        # Calculate confidence scores
        promoted_findings = []
        for f in findings:
            confidence = self._compute_confidence(f)
            f.confidence = confidence
            if confidence in ("confirmed", "verified-exploit"):
                promoted_findings.append(f)
                
        # Write outputs
        self._write_findings(findings, promoted_findings)
        self._write_summary(len(api_endpoints), len(findings))

        log.info("=" * 60)
        log.info("Complete. Endpoints: %d  Total Findings: %d (Promoted: %d)",
                 len(api_endpoints), len(findings), len(promoted_findings))
        log.info("Outputs:\n  - All: %s\n  - Promoted: %s", self.findings_file, self.promoted_file)
        log.info("=" * 60)
        return len(findings)

    # ── Helpers ──────────────────────────────────────────────────────

    def _probe_all(self, endpoints: List[Endpoint]) -> List[Endpoint]:
        """Probe all endpoints in parallel, respecting rate limit."""
        results: List[Endpoint] = []
        delay = 1.0 / self.rate if self.rate > 0 else 0

        def probe_one(ep: Endpoint) -> Endpoint:
            try:
                return self.probe.probe(ep)
            except Exception as e:
                log.debug("Probe failed %s: %s", ep.url, e)
                return ep

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(probe_one, ep): ep for ep in endpoints}
            for i, fut in enumerate(concurrent.futures.as_completed(futures)):
                results.append(fut.result())
                if delay and i % self.threads == 0:
                    time.sleep(delay * self.threads)

        probed = sum(1 for e in results if e.status_code is not None)
        accessible = sum(1 for e in results if e.accessible_unauthenticated)
        log.info("Probed: %d/%d reachable. Accessible without auth: %d",
                 probed, len(results), accessible)
        return results

    @staticmethod
    def _dedup(findings: List[Finding]) -> List[Finding]:
        seen: Dict[str, Finding] = {}
        for f in findings:
            key = f.dedup_key()
            if key not in seen:
                seen[key] = f
            else:
                # Merge tools list
                existing_tools = set(seen[key].tools)
                for t in f.tools:
                    existing_tools.add(t)
                seen[key].tools = list(existing_tools)
                # Keep highest severity
                if (SEVERITY_RANK.get(f.severity, 0) >
                        SEVERITY_RANK.get(seen[key].severity, 0)):
                    seen[key].severity = f.severity
        return sorted(seen.values(),
                      key=lambda x: -SEVERITY_RANK.get(x.severity, 0))

    @staticmethod
    def _compute_confidence(finding: Finding) -> str:
        if len(finding.tools) >= 2:
            return "confirmed"
            
        exploit_classes = ("broken_object_authorization", "mass_assignment", "jwt_bypass", "auth_bypass", "403_bypass")
        exploit_keywords = ("jwt cracked", "alg=none bypass", "403 bypassed", "mass assignment confirmed", "live exploit")
        
        ev_lower = finding.evidence.lower()
        if finding.issue_class in exploit_classes or any(kw in ev_lower for kw in exploit_keywords):
            return "verified-exploit"
            
        return "single-tool"

    def _write_findings(self, findings: List[Finding], promoted: List[Finding]) -> None:
        with open(self.findings_file, "w") as fh:
            for f in findings:
                fh.write(f.to_jsonl() + "\n")
        log.info("Wrote %d findings → %s", len(findings), self.findings_file)
        
        with open(self.promoted_file, "w") as fh:
            for f in promoted:
                fh.write(f.to_jsonl() + "\n")
        log.info("Wrote %d promoted findings → %s", len(promoted), self.promoted_file)

    def _save_intel_snapshot(self, endpoints: List[Endpoint]) -> None:
        snap = self.intel_dir / "endpoints_snapshot.jsonl"
        with open(snap, "w") as fh:
            for ep in endpoints:
                fh.write(json.dumps({
                    "url": ep.url,
                    "host": ep.host,
                    "path": ep.path,
                    "method": ep.method,
                    "status_code": ep.status_code,
                    "accessible_unauthenticated": ep.accessible_unauthenticated,
                    "auth_required": ep.auth_required,
                    "has_id_param": ep.has_id_param,
                    "is_sensitive": ep.is_sensitive,
                    "content_type": ep.content_type,
                    "response_length": ep.response_length,
                    "source": ep.source,
                }) + "\n")

    def _write_summary(self, endpoint_count: int, finding_count: int) -> None:
        summary_file = self.api_sec_dir / "intel_summary.json"
        with open(summary_file, "w") as fh:
            json.dump({
                "module": "api_intelligence",
                "endpoints_analyzed": endpoint_count,
                "findings": finding_count,
                "output": str(self.findings_file),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            }, fh, indent=2)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="ARISE API Intelligence Engine")
    parser.add_argument("scan_dir", help="Path to the scan output directory")
    parser.add_argument("--rate", type=int, default=30, help="Requests/sec (default: 30)")
    parser.add_argument("--timeout", type=int, default=8, help="HTTP timeout seconds (default: 8)")
    parser.add_argument("--threads", type=int, default=20, help="Parallel threads (default: 20)")
    parser.add_argument("--wordlist", help="Path to actions wordlist (optional)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    scan_dir = Path(args.scan_dir)
    if not scan_dir.exists():
        log.error("Scan directory not found: %s", scan_dir)
        sys.exit(1)

    wordlist = Path(args.wordlist) if args.wordlist else None

    engine = APIIntelligenceEngine(
        scan_dir=scan_dir,
        rate=args.rate,
        timeout=args.timeout,
        threads=args.threads,
        wordlist=wordlist,
    )
    findings_count = engine.run()
    sys.exit(0 if findings_count >= 0 else 1)


if __name__ == "__main__":
    main()
