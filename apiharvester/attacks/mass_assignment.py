"""Attack 3: Mass Assignment / Excessive Data Exposure.

Hardened per REAL_WORLD_RESEARCH.md §3 (GitHub/Homakov). A mass-assignment
finding is only trustworthy when the injected privilege field *persists* — i.e.
it is still present when we re-read the object — not merely echoed back in the
write response (many frameworks reflect the request body without saving it).
"""
import json
import sys

from ..config import MASS_ASSIGNMENT_FIELDS
from ..http_client import HTTPClient
from ..models import Finding, ScanContext
from ..utils.json_shape import extract_fields as _extract_fields
from ..utils.validation import looks_like_real_secret


def _log(msg):
    print(f"[*] Attack 3 (mass-assignment): {msg}", file=sys.stderr)


def _has_sensitive_fields(fields):
    """Check if response exposes sensitive internal fields."""
    sensitive = {"password", "password_hash", "hash", "secret", "token",
                 "api_key", "apikey", "ssn", "credit_card", "internal_id",
                 "private_key", "salt", "session_token"}
    return fields & sensitive


def run_mass_assignment(ctx: ScanContext):
    """Test for mass assignment and excessive data exposure."""
    writable = [e for e in ctx.endpoints
                if any(m in e.methods for m in ("PUT", "PATCH", "POST"))]
    if not writable:
        writable = ctx.api_endpoints()[:30]
    _log(f"Testing {len(writable)} endpoints")

    client = HTTPClient(timeout=ctx.timeout)
    headers = {}
    if ctx.auth:
        headers["Authorization"] = ctx.auth

    found = 0

    for ep in writable:
        url = ep.base_url()

        # Step 1: GET to learn the object shape
        get_resp = client.request("GET", url, headers=headers)
        if get_resp.status != 200:
            continue

        fields = _extract_fields(get_resp.body)
        if not fields:
            continue
        ep.object_fields = sorted(fields)

        # Check excessive data exposure
        exposed = _has_sensitive_fields(fields)
        if exposed:
            ctx.add_finding(Finding(
                title=f"Excessive data exposure: {', '.join(sorted(exposed))}",
                severity="medium",
                category="API3:2023 Broken Object Property Level Authorization",
                method="GET",
                path=ep.path,
                host=ep.host,
                status=get_resp.status,
                evidence=f"Response contains sensitive fields: "
                         f"{sorted(exposed)}",
                remediation="Filter sensitive fields from API responses. "
                            "Use response DTOs.",
                attack_phase="mass_assignment"))
            found += 1

        # Step 2: Try mass assignment with privilege escalation fields
        for method in ("PATCH", "PUT", "POST"):
            if method not in ep.methods and method != "PATCH":
                continue

            payload = {}
            for field, value in MASS_ASSIGNMENT_FIELDS.items():
                if field not in fields:
                    payload[field] = value

            if not payload:
                continue

            req_headers = dict(headers)
            req_headers["Content-Type"] = "application/json"
            body = json.dumps(payload)

            resp = client.request(method, url, body=body, headers=req_headers)

            if not (200 <= resp.status < 300):
                continue

            echoed = set(payload.keys()) & _extract_fields(resp.body)
            if not echoed:
                continue

            # VALIDATION: an echo is not proof. Re-read the object and confirm
            # the injected privilege field actually PERSISTED with our value.
            verify = client.request("GET", url, headers=headers)
            persisted = set()
            if verify.status == 200:
                try:
                    obj = json.loads(verify.body)
                    obj = obj.get("data", obj) if isinstance(obj, dict) else obj
                except (ValueError, TypeError):
                    obj = None
                if isinstance(obj, dict):
                    for f in echoed:
                        if f in obj and str(obj[f]) == str(payload[f]):
                            persisted.add(f)

            if persisted:
                ctx.add_finding(Finding(
                    title=f"Mass assignment CONFIRMED: {', '.join(sorted(persisted))} "
                          f"persisted via {method}",
                    severity="high",
                    category="API3:2023 Broken Object Property Level Authorization",
                    method=method,
                    path=ep.path,
                    host=ep.host,
                    status=resp.status,
                    evidence=f"Injected {sorted(persisted)} via {method} and "
                             f"confirmed persisted on re-read (GET). "
                             f"Privilege fields are mass-assignable.",
                    remediation="Whitelist allowed fields per endpoint. "
                                "Never bind request body directly to models.",
                    attack_phase="mass_assignment"))
                found += 1
                break
            else:
                # Echoed but not persisted — report low-confidence only.
                ctx.add_finding(Finding(
                    title=f"Possible mass assignment: {', '.join(sorted(echoed))} "
                          f"echoed via {method} (persistence unconfirmed)",
                    severity="low",
                    category="API3:2023 Broken Object Property Level Authorization",
                    method=method,
                    path=ep.path,
                    host=ep.host,
                    status=resp.status,
                    evidence=f"Fields {sorted(echoed)} reflected in {method} "
                             f"response but not confirmed on re-read; may be "
                             f"harmless echo. Manual review advised.",
                    remediation="Whitelist allowed fields per endpoint.",
                    attack_phase="mass_assignment"))
                found += 1
                break

    _log(f"Mass assignment findings: {found}")
