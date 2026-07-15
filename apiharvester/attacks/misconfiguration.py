"""Attack 8: Security Misconfiguration — CORS, headers, verbose errors, secrets."""
import sys

from ..config import (SECURITY_HEADERS, SECRET_PATTERNS, ERROR_SIGNATURES,
                      BEARER_JWT_RE)
from ..http_client import HTTPClient
from ..models import Finding, ScanContext


def _log(msg):
    print(f"[*] Attack 8 (misconfig): {msg}", file=sys.stderr)


def _check_cors(client, ep, ctx, headers):
    """Test CORS misconfiguration."""
    url = ep.base_url()

    # Test 1: Reflected origin
    evil_origin = "https://evil-attacker.com"
    req_headers = dict(headers)
    req_headers["Origin"] = evil_origin
    resp = client.request("GET", url, headers=req_headers)
    acao = resp.headers.get("access-control-allow-origin", "")

    if acao == evil_origin:
        creds = resp.headers.get("access-control-allow-credentials", "")
        sev = "critical" if creds.lower() == "true" else "high"
        ctx.add_finding(Finding(
            title="CORS: arbitrary origin reflected"
                  + (" with credentials" if creds.lower() == "true" else ""),
            severity=sev,
            category="API8:2023 Security Misconfiguration",
            method="GET",
            path=ep.path,
            host=ep.host,
            status=resp.status,
            evidence=f"Origin {evil_origin} reflected in ACAO"
                     + (f", credentials={creds}" if creds else ""),
            remediation="Whitelist specific origins. Never reflect "
                        "arbitrary Origin with credentials.",
            attack_phase="misconfiguration"))
        return 1

    if acao == "*":
        ctx.add_finding(Finding(
            title="CORS: wildcard origin (Access-Control-Allow-Origin: *)",
            severity="medium",
            category="API8:2023 Security Misconfiguration",
            method="GET",
            path=ep.path,
            host=ep.host,
            status=resp.status,
            evidence="ACAO is wildcard *",
            remediation="Restrict to specific trusted origins.",
            attack_phase="misconfiguration"))
        return 1

    # Test 2: Null origin
    req_headers["Origin"] = "null"
    resp2 = client.request("GET", url, headers=req_headers)
    acao2 = resp2.headers.get("access-control-allow-origin", "")
    if acao2 == "null":
        ctx.add_finding(Finding(
            title="CORS: null origin accepted",
            severity="high",
            category="API8:2023 Security Misconfiguration",
            method="GET",
            path=ep.path,
            host=ep.host,
            status=resp2.status,
            evidence="Origin: null reflected in ACAO",
            remediation="Reject null origin requests.",
            attack_phase="misconfiguration"))
        return 1

    return 0


def _check_headers(resp, ep, ctx):
    """Check for missing security headers."""
    count = 0
    for header, desc in SECURITY_HEADERS.items():
        if header not in resp.headers:
            ctx.add_finding(Finding(
                title=desc,
                severity="low",
                category="API8:2023 Security Misconfiguration",
                method="GET",
                path=ep.path,
                host=ep.host,
                status=resp.status,
                evidence=f"Missing header: {header}",
                remediation=f"Add {header} header.",
                attack_phase="misconfiguration"))
            count += 1

    # Server banner leak
    server = resp.headers.get("server", "")
    if server and any(c.isdigit() for c in server):
        ctx.add_finding(Finding(
            title=f"Server version exposed: {server}",
            severity="low",
            category="API8:2023 Security Misconfiguration",
            method="GET",
            path=ep.path,
            host=ep.host,
            status=resp.status,
            evidence=f"Server: {server}",
            remediation="Remove or genericize the Server header.",
            attack_phase="misconfiguration"))
        count += 1

    # X-Powered-By leak
    powered = resp.headers.get("x-powered-by", "")
    if powered:
        ctx.add_finding(Finding(
            title=f"Technology exposed: X-Powered-By: {powered}",
            severity="low",
            category="API8:2023 Security Misconfiguration",
            method="GET",
            path=ep.path,
            host=ep.host,
            status=resp.status,
            evidence=f"X-Powered-By: {powered}",
            remediation="Remove X-Powered-By header.",
            attack_phase="misconfiguration"))
        count += 1

    return count


def _check_verbose_errors(client, ep, ctx, headers):
    """Trigger error responses and check for stack traces."""
    url = ep.base_url()
    count = 0

    # Trigger errors with malformed input
    for suffix in ("?id='", "?id=<script>", "/../../../etc/passwd",
                    "?format=xxx"):
        resp = client.request("GET", url + suffix, headers=headers)
        if resp.status >= 400:
            for tech, pattern in ERROR_SIGNATURES:
                if pattern.search(resp.body or ""):
                    ctx.add_finding(Finding(
                        title=f"Verbose error: {tech} stack trace exposed",
                        severity="medium",
                        category="API8:2023 Security Misconfiguration",
                        method="GET",
                        path=ep.path,
                        host=ep.host,
                        status=resp.status,
                        evidence=f"Triggered with {suffix}, "
                                 f"found {tech} error signature",
                        remediation="Disable debug mode in production. "
                                    "Return generic error messages.",
                        attack_phase="misconfiguration"))
                    count += 1
                    break

    return count


def _check_secrets(resp, ep, ctx):
    """Scan response for leaked secrets/credentials."""
    count = 0
    for name, pattern in SECRET_PATTERNS:
        if pattern.search(resp.body or ""):
            ctx.add_finding(Finding(
                title=f"Secret leaked in response: {name}",
                severity="high",
                category="API8:2023 Security Misconfiguration",
                method="GET",
                path=ep.path,
                host=ep.host,
                status=resp.status,
                evidence=f"Pattern match: {name}",
                remediation="Remove secrets from API responses. "
                            "Rotate exposed credentials.",
                attack_phase="misconfiguration"))
            count += 1
    return count


def run_misconfiguration(ctx: ScanContext):
    """Test for security misconfiguration across all hosts."""
    hosts = ctx.active_hosts()
    endpoints = ctx.api_endpoints()[:50]
    if not endpoints:
        endpoints = ctx.endpoints[:30]
    _log(f"Testing {len(hosts)} hosts, {len(endpoints)} endpoints")

    client = HTTPClient(timeout=ctx.timeout)
    headers = {}
    if ctx.auth:
        headers["Authorization"] = ctx.auth

    found = 0
    seen_hosts = set()

    for ep in endpoints:
        url = ep.base_url()

        # CORS — once per host
        if ep.host not in seen_hosts:
            found += _check_cors(client, ep, ctx, headers)
            seen_hosts.add(ep.host)

            # Headers — once per host
            resp = client.request("GET", url, headers=headers)
            found += _check_headers(resp, ep, ctx)
            found += _check_secrets(resp, ep, ctx)

        # Verbose errors
        found += _check_verbose_errors(client, ep, ctx, headers)

    _log(f"Misconfiguration findings: {found}")
