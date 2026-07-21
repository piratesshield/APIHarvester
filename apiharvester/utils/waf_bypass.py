"""Optional WAF / User-Agent bypass engine.

DISABLED BY DEFAULT. Enable with the CLI flag `--waf-bypass`. When enabled the
shared HTTPClient (a) rotates a realistic browser User-Agent instead of the
default bot UA, and (b) on a WAF-blocked response (403/406/429/503 or a JS
challenge / vendor signature) retries the request with a sequence of
UA + spoofed-origin-header variants, returning the first that gets through.

Why optional: rotating UAs and spoofing origin headers is evasion. It is
appropriate only for *authorized* testing where the engagement permits it, and
it changes traffic fingerprints, so it must be a deliberate opt-in — never the
default. The engine is intentionally low-volume (a bounded variant list, one
pass) so it probes rather than floods.

Techniques implemented (see REAL_WORLD_RESEARCH.md §5/§11):
  * User-Agent rotation across current desktop/mobile browsers + benign bots.
  * Full browser header set (Accept, Accept-Language, Sec-* hints) — many WAFs
    block requests that lack them.
  * Spoofed client-origin headers (X-Forwarded-For, X-Real-IP,
    X-Originating-IP, etc.) set to loopback/RFC1918 to impersonate an internal
    caller past a naive edge rule.
"""
import itertools
import re

from ..config import JS_CHALLENGE_RE, WAF_SIGNATURES

# Explicit block-page text. Some WAFs return a denial as HTTP 200/404 with a
# body like "Access Denied" / "Reference #...", so status codes alone miss them.
# NOTE: we deliberately do NOT treat a vendor header (Server: AkamaiGHost,
# cf-ray, etc.) as a block — those appear on EVERY response from a CDN-fronted
# site, including normal 200s/404s, and using them would false-positive the
# block detector on all traffic (and trigger needless retry amplification).
_BLOCK_PAGE_RE = re.compile(
    r"(access denied|you don.?t have permission to access|request blocked|"
    r"blocked by .{0,20}(security|firewall|waf)|attention required|"
    r"reference\s*#[0-9a-f.]+|has been blocked|unusual traffic|"
    r"automated (access|request)s? (is|are) )", re.I)

# Realistic, current browser/bot User-Agent strings for rotation.
BROWSER_USER_AGENTS = [
    # Chrome / Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    # Safari / macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    # Firefox / Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    # Chrome / Android (mobile)
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    # Safari / iPhone
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 "
    "Safari/604.1",
    # Edge / Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    # Benign, allow-listed crawler UA (some WAFs allow-list Googlebot)
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]

# Full browser-like header set. WAFs frequently block requests missing these.
BROWSER_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
              "application/json,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Upgrade-Insecure-Requests": "1",
}

# Spoofed client-origin headers — impersonate an internal/allow-listed caller.
ORIGIN_SPOOF_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Forwarded-For": "10.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {},  # UA/header change only, no origin spoof
]

# Statuses that commonly indicate a WAF/edge block (vs a normal app response).
BLOCK_STATUSES = {403, 406, 429, 503}


def is_waf_blocked(resp):
    """Heuristic: does this response look like a WAF/edge *block*?

    A block is signalled by a block status code, a JS/CAPTCHA challenge body, or
    explicit block-page text. Crucially this does NOT fire on the mere presence
    of a CDN/WAF vendor header — those ride along on every response from a
    fronted site, so using them would flag normal 200/404 traffic as blocked
    and trigger pointless (and abusive) retry amplification.
    """
    if resp is None or resp.status == 0:
        return False
    if resp.status in BLOCK_STATUSES:
        return True
    body = resp.body or ""
    if JS_CHALLENGE_RE.search(body):
        return True
    if _BLOCK_PAGE_RE.search(body[:2000]):
        return True
    return False


def detect_waf_vendor(resp):
    """Return the matched WAF vendor name, or '' if none."""
    if resp is None:
        return ""
    blob = " ".join(f"{k}: {v}" for k, v in resp.headers.items())
    blob += " " + (resp.body or "")[:512]
    for vendor, patterns in WAF_SIGNATURES.items():
        for pat in patterns:
            if pat.search(blob):
                return vendor
    return ""


def bypass_variants(max_variants=14):
    """Yield (user_agent, extra_headers, label) bypass attempts, bounded.

    Pairs rotating UAs with origin-spoof header sets, always including the full
    browser header block. Bounded so the engine probes rather than floods.
    """
    count = 0
    for ua, origin in itertools.product(BROWSER_USER_AGENTS,
                                        ORIGIN_SPOOF_HEADERS):
        if count >= max_variants:
            return
        headers = dict(BROWSER_HEADERS)
        headers.update(origin)
        origin_label = ",".join(origin.keys()) if origin else "no-spoof"
        ua_label = ua.split(")")[0].split("(")[-1][:24]
        yield ua, headers, f"UA[{ua_label}]+{origin_label}"
        count += 1


def attempt_bypass(client, method, url, base_headers=None, max_variants=14):
    """Retry a WAF-blocked request with UA/header variants.

    Returns (response, technique_label) for the first variant that is NOT
    blocked, or (None, None) if every variant is still blocked. `client` must
    be a plain client (bypass disabled) to avoid recursion.
    """
    base_headers = dict(base_headers or {})
    for ua, headers, label in bypass_variants(max_variants):
        merged = dict(headers)
        merged.update(base_headers)          # caller headers (e.g. Authorization) win
        merged["User-Agent"] = ua            # but force the rotating UA
        resp = client.request(method, url, headers=merged)
        if resp.status != 0 and not is_waf_blocked(resp):
            return resp, label
    return None, None
