"""Attack 5: Broken Function-Level Authorization (BFLA)."""
import sys

from ..config import BFLA_PATH_RE
from ..http_client import HTTPClient
from ..models import Finding, ScanContext
from ..utils.bypass403 import try_403_bypass
from ..utils.soft404 import Soft404Detector


def _log(msg):
    print(f"[*] Attack 5 (BFLA): {msg}", file=sys.stderr)


def run_bfla(ctx: ScanContext):
    """Test for broken function-level authorization."""
    # is_sensitive (SENSITIVE_PATH_RE) covers /admin, /internal, /debug,
    # /config, etc. but not privileged-function-specific paths like
    # /roles, /permissions, /impersonate, /sudo, /elevate, /grant, /revoke,
    # or /users/{id}/delete — those only match BFLA_PATH_RE, so both must
    # be checked or this whole class of endpoint is silently skipped.
    sensitive = [e for e in ctx.endpoints
                 if e.is_sensitive or BFLA_PATH_RE.search(e.path)]
    all_eps = ctx.api_endpoints()
    _log(f"Testing {len(sensitive)} sensitive + {len(all_eps)} total endpoints")

    client = HTTPClient(timeout=ctx.timeout)
    headers_high = {}
    headers_low = {}
    if ctx.auth:
        headers_high["Authorization"] = ctx.auth
    if ctx.auth2:
        headers_low["Authorization"] = ctx.auth2

    soft404 = Soft404Detector()
    found = 0

    # Test 1: Access admin/internal paths with low-priv or no token
    for ep in sensitive:
        url = ep.base_url()

        # Try with no auth
        resp_none = client.request("GET", url)
        if 200 <= resp_none.status < 300 and resp_none.length > 50:
            ctx.add_finding(Finding(
                title=f"Sensitive path accessible without auth: {ep.path}",
                severity="high",
                category="API5:2023 Broken Function Level Authorization",
                method="GET",
                path=ep.path,
                host=ep.host,
                status=resp_none.status,
                evidence=f"No auth, got {resp_none.status} with {resp_none.length}B",
                remediation="Require authentication and admin role for "
                            "sensitive endpoints.",
                attack_phase="bfla"))
            found += 1

        # Try with low-priv token (cross-function)
        if ctx.auth2:
            resp_low = client.request("GET", url, headers=headers_low)
            if 200 <= resp_low.status < 300 and resp_low.length > 50:
                ctx.add_finding(Finding(
                    title=f"BFLA: low-priv user can access {ep.path}",
                    severity="critical",
                    category="API5:2023 Broken Function Level Authorization",
                    method="GET",
                    path=ep.path,
                    host=ep.host,
                    status=resp_low.status,
                    evidence=f"Low-priv token accessed admin path, "
                             f"got {resp_low.status} {resp_low.length}B",
                    remediation="Enforce role-based access control. "
                                "Deny admin functions to non-admin users.",
                    attack_phase="bfla"))
                found += 1

    # Test 2: 403 bypass on forbidden endpoints
    for ep in all_eps:
        url = ep.base_url()
        resp = client.request("GET", url, headers=headers_high or None)
        if resp.status != 403:
            continue

        bypass_resp, technique = try_403_bypass(client, url, soft404)
        if bypass_resp:
            ctx.add_finding(Finding(
                title=f"403 bypass via {technique}",
                severity="high",
                category="API5:2023 Broken Function Level Authorization",
                method="GET",
                path=ep.path,
                host=ep.host,
                status=bypass_resp.status,
                evidence=f"Bypassed 403 using {technique}, "
                         f"got {bypass_resp.status}",
                remediation="Fix authorization at the application layer, "
                            "not just at proxy/reverse-proxy.",
                attack_phase="bfla"))
            found += 1

    # Test 3: Method-based BFLA (GET allowed but DELETE/PUT also work)
    if ctx.auth2:
        for ep in sensitive[:20]:
            url = ep.base_url()
            for method in ("DELETE", "PUT", "PATCH"):
                resp = client.request(method, url, headers=headers_low)
                if 200 <= resp.status < 300:
                    ctx.add_finding(Finding(
                        title=f"BFLA: low-priv {method} accepted on {ep.path}",
                        severity="critical",
                        category="API5:2023 Broken Function Level Authorization",
                        method=method,
                        path=ep.path,
                        host=ep.host,
                        status=resp.status,
                        evidence=f"Low-priv {method} got {resp.status}",
                        remediation="Enforce authorization per HTTP method, "
                                    "not just per path.",
                        attack_phase="bfla"))
                    found += 1

    _log(f"BFLA findings: {found}")
