"""Attack 9: Improper Inventory Management — version/shadow API discovery."""
import re
import sys

from ..config import VERSION_VARIANTS
from ..http_client import HTTPClient
from ..models import Endpoint, Finding, ScanContext
from ..utils.soft404 import Soft404Detector


def _log(msg):
    print(f"[*] Attack 9 (inventory): {msg}", file=sys.stderr)


VERSION_RE = re.compile(r"/v(\d+)/")


def _generate_version_variants(path):
    """For a path like /api/v2/users, generate /api/v1/users, /api/v3/users, etc."""
    variants = []
    match = VERSION_RE.search(path)
    if match:
        current = int(match.group(1))
        for v in range(1, 6):
            if v != current:
                new_path = path[:match.start(1)] + str(v) + path[match.end(1):]
                variants.append((new_path, f"v{v} (current v{current})"))
    else:
        # No version in path — try inserting version prefixes
        for variant in VERSION_VARIANTS:
            if variant not in path:
                new_path = variant + path.lstrip("/")
                variants.append((new_path, f"prefix {variant.strip('/')}"))
    return variants


def run_inventory(ctx: ScanContext):
    """Test for deprecated/shadow API versions."""
    endpoints = ctx.api_endpoints()
    if not endpoints:
        endpoints = ctx.endpoints[:50]
    _log(f"Testing version variants on {len(endpoints)} endpoints")

    client = HTTPClient(timeout=ctx.timeout)
    headers_high = {}
    headers_low = {}
    if ctx.auth:
        headers_high["Authorization"] = ctx.auth
    if ctx.auth2:
        headers_low["Authorization"] = ctx.auth2

    soft404 = Soft404Detector()
    found = 0
    tested = set()

    for ep in endpoints:
        base = ep.base_url()
        parsed_host = ep.url.split(ep.path)[0] if ep.path in ep.url else ""
        if not parsed_host:
            continue

        if ep.host not in tested:
            soft404.fingerprint(client, parsed_host)
            tested.add(ep.host)

        variants = _generate_version_variants(ep.path)

        for new_path, desc in variants:
            new_url = parsed_host + new_path
            if new_url in tested:
                continue
            tested.add(new_url)

            resp = client.request("GET", new_url, headers=headers_high or None)
            if resp.status == 0 or resp.status >= 404:
                continue
            if soft404.is_soft_404(resp):
                continue

            # Found a responding version variant
            ctx.add_finding(Finding(
                title=f"Shadow/deprecated API version: {new_path} ({desc})",
                severity="medium",
                category="API9:2023 Improper Inventory Management",
                method="GET",
                path=new_path,
                host=ep.host,
                status=resp.status,
                evidence=f"Alternate version {desc} responds with "
                         f"{resp.status} ({resp.length}B)",
                remediation="Deprecate and remove old API versions. "
                            "Maintain an API inventory.",
                attack_phase="inventory"))
            found += 1

            # Check if older version has weaker auth
            if ctx.auth2:
                resp_low = client.request("GET", new_url, headers=headers_low)
                resp_none = client.request("GET", new_url)

                if resp_none.status == 200 and resp.status in (401, 403):
                    ctx.add_finding(Finding(
                        title=f"Old API version {desc} has no auth "
                              f"(current requires auth)",
                        severity="high",
                        category="API9:2023 Improper Inventory Management",
                        method="GET",
                        path=new_path,
                        host=ep.host,
                        status=resp_none.status,
                        evidence=f"Current: {resp.status}, "
                                 f"old version no-auth: {resp_none.status}",
                        remediation="Apply consistent auth across all API "
                                    "versions. Remove deprecated endpoints.",
                        attack_phase="inventory"))
                    found += 1

            # Add to endpoint list for further testing
            new_ep = Endpoint(url=new_url, status_code=resp.status,
                              is_api=True, source="inventory")
            ctx.endpoints.append(new_ep)

    _log(f"Inventory findings: {found}")
