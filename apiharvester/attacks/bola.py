"""Attack 1: BOLA / IDOR — Broken Object-Level Authorization."""
import re
import sys

from ..config import ID_SEGMENT_RE
from ..http_client import HTTPClient
from ..models import Finding, ScanContext


def _log(msg):
    print(f"[*] Attack 1 (BOLA): {msg}", file=sys.stderr)


ID_VALUE_RE = re.compile(
    r"(?:^|[/=])(\d{1,10}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|"
    r"[0-9a-fA-F]{24})(?:$|[/&?])")

SWAP_IDS = {
    "1": "2", "2": "1", "100": "101", "0": "1",
}


def _swap_id(value):
    """Generate an alternate ID to test access control."""
    if value in SWAP_IDS:
        return SWAP_IDS[value]
    if value.isdigit():
        n = int(value)
        return str(n + 1 if n > 0 else 1)
    if len(value) == 36 and value.count("-") == 4:
        parts = value.split("-")
        last = parts[-1]
        swapped = last[:-1] + ("0" if last[-1] != "0" else "1")
        parts[-1] = swapped
        return "-".join(parts)
    if len(value) >= 24 and all(c in "0123456789abcdef" for c in value.lower()):
        return value[:-1] + ("0" if value[-1] != "0" else "1")
    return None


def _replace_id_in_url(url, old_id, new_id):
    """Replace an ID value in the URL."""
    return url.replace(old_id, new_id, 1)


def run_bola(ctx: ScanContext):
    """Test for BOLA/IDOR on endpoints with ID parameters."""
    candidates = [e for e in ctx.endpoints if e.has_id_param]
    _log(f"Testing {len(candidates)} endpoints with ID params")

    client = HTTPClient(timeout=ctx.timeout)
    headers = {}
    if ctx.auth:
        headers["Authorization"] = ctx.auth

    found = 0
    for ep in candidates:
        ids = ID_VALUE_RE.findall(ep.url)
        if not ids:
            continue

        for original_id in ids:
            alt_id = _swap_id(original_id)
            if not alt_id:
                continue

            # Original request
            resp1 = client.request("GET", ep.url, headers=headers)
            if resp1.status != 200:
                continue

            # Swapped ID request
            alt_url = _replace_id_in_url(ep.url, original_id, alt_id)
            resp2 = client.request("GET", alt_url, headers=headers)

            if resp2.status == 200 and resp2.length > 50:
                # Check it's not the same response (soft-404)
                if resp1.body != resp2.body:
                    ctx.add_finding(Finding(
                        title=f"BOLA: accessible with swapped ID ({original_id}->{alt_id})",
                        severity="high",
                        category="API1:2023 BOLA",
                        method="GET",
                        path=ep.path,
                        host=ep.host,
                        status=resp2.status,
                        evidence=f"Original ID {original_id} swapped to {alt_id}, "
                                 f"got {resp2.status} with {resp2.length}B "
                                 f"(original {resp1.length}B)",
                        remediation="Enforce object-level authorization checks; "
                                    "verify the requesting user owns the resource.",
                        attack_phase="bola"))
                    found += 1

        # Differential auth test: if auth2 provided, check cross-account
        if ctx.auth2:
            headers2 = {"Authorization": ctx.auth2}
            resp_low = client.request("GET", ep.url, headers=headers2)
            if resp_low.status == 200 and resp_low.length > 50:
                if resp_low.body == resp1.body if resp1.status == 200 else True:
                    ctx.add_finding(Finding(
                        title="BOLA: cross-account access (auth2 can read auth1 object)",
                        severity="critical",
                        category="API1:2023 BOLA",
                        method="GET",
                        path=ep.path,
                        host=ep.host,
                        status=resp_low.status,
                        evidence=f"Low-priv token accessed same object, "
                                 f"got {resp_low.status} {resp_low.length}B",
                        remediation="Implement per-user object ownership checks.",
                        attack_phase="bola"))
                    found += 1

    _log(f"BOLA findings: {found}")
