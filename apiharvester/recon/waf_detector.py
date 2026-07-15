"""Phase 4: WAF detection + baseline calibration — from easm-pipeline.sh."""
import json
import secrets
import sys

from ..config import WAF_SIGNATURES, JS_CHALLENGE_RE
from ..http_client import HTTPClient
from ..models import ScanContext
from ..utils.tool_runner import run_tool, tool_available


def _log(msg):
    print(f"[*] Phase 4 (WAF): {msg}", file=sys.stderr)


def _detect_catchall(client, base_url):
    """Check if the host returns the same page for any path (catchall)."""
    real = client.request("GET", base_url + "/")
    junk = client.request("GET",
                          base_url + "/__zr_" + secrets.token_hex(6))
    if real.status == 0 or junk.status == 0:
        return False
    if real.status == junk.status and real.length > 0 and junk.length > 0:
        diff = abs(real.length - junk.length)
        threshold = max(64, real.length * 0.05)
        if diff < threshold:
            return True
    return False


def _header_waf_detect(headers_str):
    """Match WAF vendor from combined header string."""
    for vendor, patterns in WAF_SIGNATURES.items():
        for pat in patterns:
            if pat.search(headers_str):
                return vendor
    return ""


def _detect_js_challenge(body):
    """Check if the page presents a JS challenge / CAPTCHA."""
    return bool(JS_CHALLENGE_RE.search(body or ""))


def _wafw00f_scan(domains):
    """Use wafw00f for WAF detection. Returns dict[domain] -> vendor."""
    if not tool_available("wafw00f"):
        return {}
    results = {}
    for domain in domains:
        url = "https://" + domain
        result = run_tool("wafw00f", [url, "-a", "-f", "json"], timeout=30)
        if result is None:
            continue
        stdout, _, _ = result
        try:
            data = json.loads(stdout)
            for entry in data:
                waf = entry.get("firewall", "")
                if waf and waf.lower() not in ("none", "unknown", "generic"):
                    results[domain] = waf
        except (json.JSONDecodeError, TypeError):
            continue
    return results


def detect_waf(ctx: ScanContext):
    """Detect WAF/catchall/JS-challenge per live host."""
    live = ctx.active_hosts()
    _log(f"Checking {len(live)} live hosts for WAF/catchall")

    client = HTTPClient(timeout=ctx.timeout)

    wafw00f_results = _wafw00f_scan([h.domain for h in live])

    waf_count = 0
    catchall_count = 0
    js_count = 0

    for host in live:
        if host.domain in wafw00f_results:
            host.waf_vendor = wafw00f_results[host.domain]
            host.skip_bruteforce = True
            waf_count += 1
            ctx.waf_hosts.add(host.domain)
            continue

        resp = client.request("GET", host.url + "/")
        headers_combined = " ".join(
            f"{k}: {v}" for k, v in resp.headers.items())

        vendor = _header_waf_detect(headers_combined)
        if vendor:
            host.waf_vendor = vendor
            host.skip_bruteforce = True
            waf_count += 1
            ctx.waf_hosts.add(host.domain)
            continue

        if _detect_js_challenge(resp.body):
            host.js_challenge = True
            host.skip_bruteforce = True
            js_count += 1
            ctx.waf_hosts.add(host.domain)
            continue

        if _detect_catchall(client, host.url):
            host.catchall = True
            host.skip_bruteforce = True
            catchall_count += 1

    _log(f"WAF: {waf_count}, Catchall: {catchall_count}, "
         f"JS-challenge: {js_count}, "
         f"Scannable: {len(ctx.scannable_hosts())}")
