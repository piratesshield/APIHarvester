"""Attack 6: Business Logic Flaws — price/qty/status manipulation."""
import json
import sys

from ..config import BUSINESS_PARAM_NAMES
from ..http_client import HTTPClient
from ..models import Finding, ScanContext


def _log(msg):
    print(f"[*] Attack 6 (business logic): {msg}", file=sys.stderr)


MANIPULATIONS = [
    ("zero", "0"),
    ("negative", "-1"),
    ("large", "99999999"),
    ("decimal_abuse", "0.001"),
    ("string", "free"),
]

STATUS_ESCALATIONS = {
    "status": ["approved", "verified", "active", "completed", "admin"],
    "state": ["approved", "verified", "active", "completed"],
    "approved": ["true", "1"],
    "verified": ["true", "1"],
}


def run_business_logic(ctx: ScanContext):
    """Test for business logic flaws in API parameters."""
    candidates = ctx.endpoints_with_params()
    _log(f"Testing {len(candidates)} endpoints with params")

    client = HTTPClient(timeout=ctx.timeout)
    headers = {}
    if ctx.auth:
        headers["Authorization"] = ctx.auth
    headers["Content-Type"] = "application/json"

    found = 0

    for ep in candidates:
        url = ep.base_url()

        # Test 1: Price/quantity/amount manipulation
        business_params = {
            k: v for k, v in ep.params.items()
            if k.lower() in BUSINESS_PARAM_NAMES
        }

        for param, original in business_params.items():
            for label, evil_value in MANIPULATIONS:
                # GET-based manipulation
                test_url = f"{url}?{param}={evil_value}"
                resp = client.request("GET", test_url, headers=headers)
                if 200 <= resp.status < 300:
                    try:
                        data = json.loads(resp.body)
                        # Check if the manipulated value appears in response
                        body_str = resp.body.lower()
                        if evil_value in body_str or label == "zero":
                            ctx.add_finding(Finding(
                                title=f"Business logic: {param}={evil_value} "
                                      f"({label}) accepted",
                                severity="high" if label in ("zero", "negative")
                                         else "medium",
                                category="API6:2023 Unrestricted Access to "
                                         "Sensitive Business Flows",
                                method="GET",
                                path=ep.path,
                                host=ep.host,
                                status=resp.status,
                                evidence=f"{param}={evil_value} accepted, "
                                         f"response {resp.status} {resp.length}B",
                                remediation="Validate business parameters "
                                            "server-side (min/max/type checks). "
                                            "Reject negative prices/quantities.",
                                attack_phase="business_logic"))
                            found += 1
                            break
                    except (json.JSONDecodeError, TypeError):
                        pass

                # POST-based manipulation
                payload = {param: evil_value}
                resp = client.request("POST", url, body=json.dumps(payload),
                                      headers=headers)
                if 200 <= resp.status < 300 and resp.length > 20:
                    ctx.add_finding(Finding(
                        title=f"Business logic: POST {param}={evil_value} "
                              f"({label}) accepted",
                        severity="high",
                        category="API6:2023 Unrestricted Access to "
                                 "Sensitive Business Flows",
                        method="POST",
                        path=ep.path,
                        host=ep.host,
                        status=resp.status,
                        evidence=f"POST {param}={evil_value} accepted",
                        remediation="Validate all business-critical parameters.",
                        attack_phase="business_logic"))
                    found += 1
                    break

        # Test 2: Status/state escalation
        for param, escalations in STATUS_ESCALATIONS.items():
            if param in ep.params:
                for value in escalations:
                    payload = {param: value}
                    resp = client.request(
                        "PATCH", url, body=json.dumps(payload),
                        headers=headers)
                    if 200 <= resp.status < 300:
                        ctx.add_finding(Finding(
                            title=f"Status escalation: {param}={value} accepted",
                            severity="high",
                            category="API6:2023 Unrestricted Access to "
                                     "Sensitive Business Flows",
                            method="PATCH",
                            path=ep.path,
                            host=ep.host,
                            status=resp.status,
                            evidence=f"PATCH {param}={value} accepted",
                            remediation="Enforce state machine transitions. "
                                        "Don't allow arbitrary status changes.",
                            attack_phase="business_logic"))
                        found += 1
                        break

    _log(f"Business logic findings: {found}")
