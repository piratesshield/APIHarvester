"""Attack 4: Unrestricted Resource Consumption — rate limit checks."""
import sys
import time

from ..http_client import HTTPClient
from ..models import Finding, ScanContext


def _log(msg):
    print(f"[*] Attack 4 (rate limit): {msg}", file=sys.stderr)


def run_rate_limit(ctx: ScanContext):
    """Test for missing rate limiting on sensitive endpoints."""
    # Prioritise auth endpoints and sensitive paths
    targets = [e for e in ctx.endpoints if e.is_auth_endpoint]
    if not targets:
        targets = ctx.api_endpoints()[:20]
    _log(f"Testing {len(targets)} endpoints with {ctx.burst} burst requests")

    client = HTTPClient(timeout=ctx.timeout)
    headers = {}
    if ctx.auth:
        headers["Authorization"] = ctx.auth

    found = 0

    for ep in targets:
        url = ep.base_url()
        statuses = []
        t0 = time.time()

        for _ in range(ctx.burst):
            resp = client.request("GET", url, headers=headers)
            statuses.append(resp.status)
            if resp.status == 429:
                break

        elapsed = time.time() - t0
        got_429 = 429 in statuses
        success = sum(1 for s in statuses if 200 <= s < 300)

        if not got_429 and success >= ctx.burst * 0.9:
            sev = "high" if ep.is_auth_endpoint else "medium"
            ctx.add_finding(Finding(
                title=f"No rate limiting ({ctx.burst} requests in {elapsed:.1f}s)",
                severity=sev,
                category="API4:2023 Unrestricted Resource Consumption",
                method="GET",
                path=ep.path,
                host=ep.host,
                status=statuses[-1],
                evidence=f"Sent {ctx.burst} requests in {elapsed:.1f}s, "
                         f"{success} succeeded, no 429 received",
                remediation="Implement rate limiting (e.g., token bucket). "
                            "Return 429 Too Many Requests with Retry-After.",
                attack_phase="rate_limit"))
            found += 1

        # Check for resource exhaustion via large pagination
        for param_name in ("limit", "size", "per_page", "count", "page_size"):
            if param_name in ep.params or True:
                big_url = f"{url}?{param_name}=999999"
                resp = client.request("GET", big_url, headers=headers)
                if resp.status == 200 and resp.length > 50000:
                    ctx.add_finding(Finding(
                        title=f"Unbounded pagination: {param_name}=999999 "
                              f"returned {resp.length}B",
                        severity="medium",
                        category="API4:2023 Unrestricted Resource Consumption",
                        method="GET",
                        path=ep.path,
                        host=ep.host,
                        status=resp.status,
                        evidence=f"{param_name}=999999 accepted, "
                                 f"response {resp.length} bytes",
                        remediation="Enforce maximum page size server-side. "
                                    "Cap limit/size parameters.",
                        attack_phase="rate_limit"))
                    found += 1
                break  # only test one pagination param per endpoint

    _log(f"Rate limit findings: {found}")
