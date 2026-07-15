"""Attack 3: Mass Assignment / Excessive Data Exposure."""
import json
import sys

from ..config import MASS_ASSIGNMENT_FIELDS
from ..http_client import HTTPClient
from ..models import Finding, ScanContext


def _log(msg):
    print(f"[*] Attack 3 (mass assign): {msg}", file=sys.stderr)


def _extract_fields(body):
    """Extract field names from a JSON response body."""
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            return set(data.keys())
        if isinstance(data, list) and data and isinstance(data[0], dict):
            return set(data[0].keys())
    except (json.JSONDecodeError, TypeError):
        pass
    return set()


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

            if 200 <= resp.status < 300:
                resp_fields = _extract_fields(resp.body)
                injected = set(payload.keys()) & resp_fields
                if injected:
                    ctx.add_finding(Finding(
                        title=f"Mass assignment: {', '.join(sorted(injected))} "
                              f"accepted via {method}",
                        severity="high",
                        category="API3:2023 Broken Object Property Level Authorization",
                        method=method,
                        path=ep.path,
                        host=ep.host,
                        status=resp.status,
                        evidence=f"Injected fields {sorted(injected)} accepted, "
                                 f"response {resp.status}",
                        remediation="Whitelist allowed fields for each endpoint. "
                                    "Never bind request body directly to models.",
                        attack_phase="mass_assignment"))
                    found += 1
                    break

    _log(f"Mass assignment findings: {found}")
