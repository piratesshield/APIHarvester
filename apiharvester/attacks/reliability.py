"""RESTler-equivalent: boundary/malformed-input fuzzing to find crashes,
500s, and reliability bugs. This is a different bug class from the OWASP
API Top 10 attacks elsewhere in this pipeline (bola.py, mass_assignment.py,
etc.) — like RESTler, it doesn't classify by OWASP category, it flags any
input that makes the server return a 5xx or otherwise misbehave."""
import json
import sys
import urllib.parse

from ..http_client import HTTPClient
from ..models import Finding, ScanContext


def _log(msg):
    print(f"[*] Attack: Reliability (crash/500 fuzz): {msg}", file=sys.stderr)


# Boundary/malformed query values — mirrors RESTler's default checkers plus
# common property-based edge cases (Schemathesis-style): type confusion,
# huge/negative numbers, oversized strings, null bytes, path traversal.
FUZZ_VALUES = [
    ("empty_string", ""),
    ("null_literal", "null"),
    ("negative_huge", "-99999999999999999999999999999999"),
    ("huge_int", "99999999999999999999999999999999"),
    ("float_where_int", "1.5"),
    ("long_string", "A" * 10000),
    ("null_byte", "test\x00value"),
    ("array_injection", "[1,2,3]"),
    ("nested_json", '{"a":{"a":{"a":{"a":1}}}}'),
    ("format_string", "%s%s%s%s%s%n"),
]

# Malformed JSON bodies for write methods — schema-violation testing in
# RESTler/Schemathesis's spirit: wrong types, deeply nested/huge payloads
# that can crash a naive parser or handler.
FUZZ_BODIES = [
    ("empty_object", "{}"),
    ("null_body", "null"),
    ("wrong_top_level_type", '"just a string, not an object"'),
    ("deeply_nested", json.dumps(
        {"a": {"a": {"a": {"a": {"a": {"a": "x"}}}}}})),
    ("huge_array", json.dumps(list(range(5000)))),
    ("malformed_json", '{"a": '),
]

_SERVER_ERROR_STATUSES = {500, 502, 503, 504}


def run_reliability(ctx: ScanContext):
    """Fuzz endpoints with boundary/malformed inputs to find crashes, 500s,
    and reliability bugs — distinct from the OWASP API Top 10 findings
    elsewhere. A finding here means a bad input crashed or errored the
    server (a robustness/DoS-class bug), not an access-control violation."""
    candidates = ctx.endpoints_with_params()[:60]  # cap requests, black-box budget
    _log(f"Fuzzing {len(candidates)} param'd endpoints "
         f"({len(FUZZ_VALUES)} boundary values/param)")

    client = HTTPClient(timeout=ctx.timeout)
    headers = {}
    if ctx.auth:
        headers["Authorization"] = ctx.auth

    found = 0

    for ep in candidates:
        base_url = ep.base_url()
        for param in ep.params:
            for label, value in FUZZ_VALUES:
                test_url = f"{base_url}?{param}={urllib.parse.quote(str(value), safe='')}"
                resp = client.request("GET", test_url, headers=headers)

                if resp.status in _SERVER_ERROR_STATUSES:
                    ctx.add_finding(Finding(
                        title=f"Reliability: {param}={label!r} causes "
                              f"HTTP {resp.status}",
                        severity="medium",
                        category="Reliability",
                        method="GET",
                        path=ep.path,
                        host=ep.host,
                        status=resp.status,
                        evidence=f"Query param {param!r} set to {label} "
                                 f"({str(value)[:60]!r}) triggered {resp.status}",
                        remediation="Validate and sanitize all input "
                                    "server-side; return 4xx (not 5xx) for "
                                    "malformed input. Never let unhandled "
                                    "exceptions surface as 500s.",
                        attack_phase="reliability"))
                    found += 1
                    break  # one confirmed crash per param is enough signal

    # Malformed-body fuzzing on writable endpoints (POST/PUT/PATCH)
    writable = [e for e in ctx.endpoints
                if any(m in e.methods for m in ("POST", "PUT", "PATCH"))][:30]
    for ep in writable:
        url = ep.base_url()
        for method in ("POST", "PUT", "PATCH"):
            if method not in ep.methods:
                continue
            for label, body in FUZZ_BODIES:
                req_headers = dict(headers)
                req_headers["Content-Type"] = "application/json"
                resp = client.request(method, url, body=body, headers=req_headers)

                if resp.status in _SERVER_ERROR_STATUSES:
                    ctx.add_finding(Finding(
                        title=f"Reliability: malformed body ({label}) "
                              f"causes HTTP {resp.status} via {method}",
                        severity="medium",
                        category="Reliability",
                        method=method,
                        path=ep.path,
                        host=ep.host,
                        status=resp.status,
                        evidence=f"Body {label} ({body[:60]!r}) sent via "
                                 f"{method} triggered {resp.status}",
                        remediation="Validate request bodies against the "
                                    "expected schema before processing; "
                                    "reject malformed JSON/types with 4xx.",
                        attack_phase="reliability"))
                    found += 1
                    break  # one confirmed crash per method is enough signal

    _log(f"Reliability findings: {found}")
