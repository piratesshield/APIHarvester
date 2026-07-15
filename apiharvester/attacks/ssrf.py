"""Attack 7: Server-Side Request Forgery (SSRF)."""
import sys

from ..config import SSRF_PAYLOADS, SSRF_INDICATORS, URL_PARAM_NAMES
from ..http_client import HTTPClient
from ..models import Finding, ScanContext


def _log(msg):
    print(f"[*] Attack 7 (SSRF): {msg}", file=sys.stderr)


def run_ssrf(ctx: ScanContext):
    """Test for SSRF in URL-accepting parameters."""
    candidates = []
    for ep in ctx.endpoints:
        url_params = {k for k in ep.params if k.lower() in URL_PARAM_NAMES}
        if url_params:
            candidates.append((ep, url_params))

    _log(f"Testing {len(candidates)} endpoints with URL params")

    client = HTTPClient(timeout=ctx.timeout)
    headers = {}
    if ctx.auth:
        headers["Authorization"] = ctx.auth

    found = 0

    for ep, url_params in candidates:
        url = ep.base_url()

        for param in url_params:
            # Get baseline response
            baseline = client.request(
                "GET", f"{url}?{param}=https://example.com", headers=headers)

            for payload in SSRF_PAYLOADS:
                test_url = f"{url}?{param}={payload}"
                resp = client.request("GET", test_url, headers=headers)

                if resp.status == 0 or resp.status >= 500:
                    continue

                # Check for SSRF indicators in response
                if SSRF_INDICATORS.search(resp.body or ""):
                    ctx.add_finding(Finding(
                        title=f"SSRF: {param} fetched internal resource",
                        severity="critical",
                        category="API7:2023 Server Side Request Forgery",
                        method="GET",
                        path=ep.path,
                        host=ep.host,
                        status=resp.status,
                        evidence=f"{param}={payload} returned "
                                 f"internal content ({resp.length}B)",
                        remediation="Validate and whitelist allowed URLs. "
                                    "Block requests to internal IPs "
                                    "(169.254.x.x, 127.0.0.1, [::1]).",
                        attack_phase="ssrf"))
                    found += 1
                    break

                # Check for different response vs baseline (blind SSRF)
                if (baseline.status != resp.status and
                        resp.status == 200 and resp.length > 100):
                    if abs(resp.length - baseline.length) > baseline.length * 0.5:
                        ctx.add_finding(Finding(
                            title=f"Potential blind SSRF: {param} response "
                                  f"changed with internal URL",
                            severity="medium",
                            category="API7:2023 Server Side Request Forgery",
                            method="GET",
                            path=ep.path,
                            host=ep.host,
                            status=resp.status,
                            evidence=f"{param}={payload} got different response "
                                     f"(baseline {baseline.length}B vs "
                                     f"{resp.length}B)",
                            remediation="Validate URL parameters. "
                                        "Use an allowlist for external URLs.",
                            attack_phase="ssrf"))
                        found += 1
                        break

    _log(f"SSRF findings: {found}")
