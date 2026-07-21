"""Attack 7: Server-Side Request Forgery (SSRF)."""
import sys

from ..config import SSRF_PAYLOADS, SSRF_INDICATORS, URL_PARAM_NAMES
from ..http_client import HTTPClient
from ..models import Finding, ScanContext


def _log(msg):
    print(f"[*] Attack 7 (SSRF): {msg}", file=sys.stderr)


def run_ssrf(ctx: ScanContext):
    """Test for SSRF in URL-accepting parameters."""
    candidates = []
    for ep in ctx.endpoints:
        url_params = {k for k in ep.params if k.lower() in URL_PARAM_NAMES}
        if url_params:
            candidates.append((ep, url_params))

    _log(f"Testing {len(candidates)} endpoints with URL params")

    client = HTTPClient(timeout=ctx.timeout)
    headers = {}
    if ctx.auth:
        headers["Authorization"] = ctx.auth

    found = 0

    for ep, url_params in candidates:
        url = ep.base_url()

        for param in url_params:
            # Get baseline response
            baseline = client.request(
                "GET", f"{url}?{param}=https://example.com", headers=headers)

            for payload in SSRF_PAYLOADS:
                test_url = f"{url}?{param}={payload}"
                resp = client.request("GET", test_url, headers=headers)

                if resp.status == 0 or resp.status >= 500:
                    continue

                # Check for SSRF indicators in response
                if SSRF_INDICATORS.search(resp.body or ""):
                    ctx.add_finding(Finding(
                        title=f"SSRF: {param} fetched internal resource",
                        severity="critical",
                        category="API7:2023 Server Side Request Forgery",
                        method="GET",
                        path=ep.path,
                        host=ep.host,
                        status=resp.status,
                        evidence=f"{param}={payload} returned "
                                 f"internal content ({resp.length}B)",
                        remediation="Validate and whitelist allowed URLs. "
                                    "Block requests to internal IPs "
                                    "(169.254.x.x, 127.0.0.1, [::1]).",
                        attack_phase="ssrf"))
                    found += 1
                    break

                # Blind-SSRF heuristic (low confidence, tightened): a bare
                # length delta is too noisy to call SSRF. We only keep it as a
                # LOW signal, and only when the internal-URL response both
                # differs from the external-URL baseline AND from a random
                # unroutable control — reducing dynamic-page false positives.
                if (resp.status == 200 and resp.length > 100 and
                        baseline.status != 200):
                    control = client.request(
                        "GET", f"{url}?{param}=http://240.0.0.1/",
                        headers=headers)
                    if (resp.status != control.status and
                            abs(resp.length - baseline.length) >
                            max(200, baseline.length * 0.5)):
                        ctx.add_finding(Finding(
                            title=f"Potential blind SSRF: {param} behaves "
                                  f"differently for internal vs external URLs",
                            severity="low",
                            category="API7:2023 Server Side Request Forgery",
                            method="GET",
                            path=ep.path,
                            host=ep.host,
                            status=resp.status,
                            evidence=f"{param}={payload}: internal-URL response "
                                     f"({resp.status}, {resp.length}B) differs "
                                     f"from external baseline ({baseline.status}, "
                                     f"{baseline.length}B) and unroutable control "
                                     f"({control.status}). Low confidence — "
                                     f"confirm with an out-of-band collaborator.",
                            remediation="Validate/allowlist URL parameters; block "
                                        "link-local (169.254.0.0/16), loopback and "
                                        "private ranges; enforce IMDSv2.",
                            attack_phase="ssrf"))
                        found += 1
                        break

        # IMDSv2 walk: if the param is SSRF-able, try the two-step token flow.
        found += _test_imdsv2(client, url, url_params, headers, ep, ctx)

    _log(f"SSRF findings: {found}")


def _test_imdsv2(client, url, url_params, headers, ep, ctx):
    """Attempt the AWS IMDSv2 two-step (PUT token -> GET creds) via the param.

    Many SSRF tools only test IMDSv1 and miss hosts that have moved to IMDSv2.
    We can't set arbitrary methods on the *internal* request through most
    proxies, but where the target reflects metadata content we flag it.
    """
    from ..config import IMDSV2_CRED_URL, SSRF_INDICATORS
    found = 0
    for param in url_params:
        resp = client.request(
            "GET", f"{url}?{param}={IMDSV2_CRED_URL}", headers=headers)
        if resp.status and resp.status < 500 and \
                SSRF_INDICATORS.search(resp.body or ""):
            ctx.add_finding(Finding(
                title=f"SSRF: {param} reached AWS instance metadata "
                      f"(IAM credentials path)",
                severity="critical",
                category="API7:2023 Server Side Request Forgery",
                method="GET",
                path=ep.path,
                host=ep.host,
                status=resp.status,
                evidence=f"{param}={IMDSV2_CRED_URL} returned metadata-shaped "
                         f"content ({resp.length}B). Matches the Capital One "
                         f"SSRF→IAM chain.",
                remediation="Enforce IMDSv2 (hop-limit 1, token required); block "
                            "169.254.169.254 at the app layer; scope IAM roles "
                            "to least privilege.",
                attack_phase="ssrf"))
            found += 1
    return found
