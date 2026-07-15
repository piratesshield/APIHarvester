"""Attack 1: BOLA / IDOR — Broken Object-Level Authorization.

Strategy:
1. Passive: flag any object-ID endpoint that returns 200+ *in this attack phase*
   with authenticated access. Low cost, high recall — if you can read your own
   object, you have an object-ID endpoint worth testing further.
2. Active ID fuzzing: for endpoints that return 200, try common alternate IDs
   (1, 2, 0, 99, 100, "admin", "test", "guest", UUID variants, etc.).
   Compare responses for access to a different object.
3. Differential auth: with two tokens (--auth and --auth2), same URL request —
   if both get 200, cross-account access confirmed.
"""
import hashlib
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


def _generate_id_candidates(extracted_id):
    """Generate multiple ID candidates to test, not just the original.
    Returns a list of (label, value) tuples to fuzz."""
    candidates = []

    # Numeric IDs: try common low-priv IDs and adjacent values
    if extracted_id.isdigit():
        n = int(extracted_id)
        candidates.extend([
            ("0", "0"),
            ("1", "1"),
            ("2", "2"),
            ("99", "99"),
            ("100", "100"),
            (f"+1", str(n + 1) if n < 1000000 else extracted_id),
            (f"-1", str(max(0, n - 1))),
            ("admin_id=1", "1"),  # sometimes ID is a query param
        ])

    # UUID: mutate the last segment slightly
    elif len(extracted_id) == 36 and extracted_id.count("-") == 4:
        parts = extracted_id.split("-")
        last = parts[-1]
        for suffix in ["00000000", "11111111", "ffffffff", "12345678"]:
            new_last = suffix
            new_parts = parts[:-1] + [new_last]
            candidates.append((f"uuid_variant_{suffix[:4]}", "-".join(new_parts)))

    # Hex/Mongo ObjectId: try common values and variants
    elif len(extracted_id) >= 24 and all(c in "0123456789abcdefABCDEF" for c in extracted_id):
        for v in ["0" * len(extracted_id),
                  "1" * len(extracted_id),
                  "f" * len(extracted_id),
                  "deadbeefdeadbeefdeadbeef"[:len(extracted_id)]]:
            candidates.append((f"hex_{v[:4]}", v))

    # String/alphanumeric IDs: try common weak values
    if extracted_id.lower() in ("admin", "root", "test", "guest", "user"):
        return [(extracted_id, extracted_id)]  # already common
    candidates.extend([
        ("admin", "admin"),
        ("test", "test"),
        ("guest", "guest"),
        ("user", "user"),
        ("null", "null"),
    ])

    return candidates


def _replace_id_in_url(url, old_id, new_id):
    """Replace an ID value in the URL (first occurrence only)."""
    return url.replace(old_id, new_id, 1)


def _response_info_disclosure(resp_baseline, resp_alt):
    """Check if the alternate response discloses information about a
    different object (compared to baseline). Returns a reason if true."""
    # Different status suggests different object/access level
    if resp_baseline.status != resp_alt.status:
        return f"status changed from {resp_baseline.status} to {resp_alt.status}"

    # Different body suggests different object
    if resp_baseline.body != resp_alt.body:
        # But not if it's just length (could be formatting)
        if abs(resp_baseline.length - resp_alt.length) > 100:
            return f"body changed significantly ({resp_baseline.length}B → {resp_alt.length}B)"

    return None


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
        # Baseline: request the endpoint with primary auth. If this doesn't
        # return 200+, there's nothing to BOLA test (you don't have access
        # to your own object, so you can't test accessing someone else's).
        resp1 = client.request("GET", ep.url, headers=headers)
        if not (200 <= resp1.status < 300):
            continue

        # Passive check: if you can read it at all with auth, it's a possible
        # BOLA (no ownership check visible during recon).
        if not ep.is_auth_endpoint:
            ctx.add_finding(Finding(
                title="Possible BOLA/IDOR: object-ID endpoint accessible",
                severity="medium",
                category="API1:2023 BOLA",
                method="GET",
                path=ep.path,
                host=ep.host,
                status=resp1.status,
                evidence=f"Authenticated request to {ep.path} returned "
                         f"{resp1.status}; ID-carrying endpoints should enforce "
                         f"per-object access control",
                remediation="Enforce object-level authorization checks; "
                            "verify the requesting user owns the resource.",
                attack_phase="bola"))
            found += 1

        # Active ID fuzzing: extract IDs from the URL, generate candidates,
        # and try them to see if we can access a different object.
        ids = ID_VALUE_RE.findall(ep.url)
        for original_id in ids:
            candidates_to_try = _generate_id_candidates(original_id)
            for label, alt_id in candidates_to_try[:5]:  # cap requests
                if alt_id == original_id:
                    continue

                alt_url = _replace_id_in_url(ep.url, original_id, alt_id)
                resp2 = client.request("GET", alt_url, headers=headers)

                if 200 <= resp2.status < 300:
                    # Check if this is a different object or same soft-404
                    reason = _response_info_disclosure(resp1, resp2)
                    if reason:
                        ctx.add_finding(Finding(
                            title=f"BOLA: accessed different object with ID swap "
                                  f"({original_id}→{label}={alt_id})",
                            severity="high",
                            category="API1:2023 BOLA",
                            method="GET",
                            path=ep.path,
                            host=ep.host,
                            status=resp2.status,
                            evidence=f"Original ID: {original_id}, "
                                     f"alternate ID: {alt_id} ({label}); "
                                     f"reason: {reason}",
                            remediation="Enforce object-level authorization checks; "
                                        "verify the requesting user owns the resource.",
                            attack_phase="bola"))
                        found += 1
                        break  # one confirmed BOLA per endpoint is enough signal

        # Differential auth test: same URL with two different tokens.
        # If both get 200, cross-account access = confirmed IDOR.
        if ctx.auth2:
            headers2 = {"Authorization": ctx.auth2}
            resp_low = client.request("GET", ep.url, headers=headers2)
            if 200 <= resp_low.status < 300:
                ctx.add_finding(Finding(
                    title="BOLA: confirmed cross-account access (differential auth)",
                    severity="critical",
                    category="API1:2023 BOLA",
                    method="GET",
                    path=ep.path,
                    host=ep.host,
                    status=resp_low.status,
                    evidence=f"Same URL returned {resp1.status} for --auth "
                             f"(high-priv) and {resp_low.status} for --auth2 "
                             f"(low-priv); if these are different identities, "
                             f"this is a confirmed IDOR",
                    remediation="Implement per-user/per-object authorization checks; "
                                "verify caller owns the requested resource on every request.",
                    attack_phase="bola"))
                found += 1

    _log(f"BOLA findings: {found}")
