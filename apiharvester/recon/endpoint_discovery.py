"""Phase 7: Endpoint brute-force — kiterunner/ffuf logic + pure-Python fallback."""
import os
import sys
import concurrent.futures as futures

from ..config import (PATH_WORDS, ACTION_WORDS, EXTENSIONS,
                      KITERUNNER_ROUTES_FILE, DIR_WORDLIST_FILE)
from ..http_client import HTTPClient
from ..models import Endpoint, ScanContext
from ..utils.soft404 import Soft404Detector
from ..utils.tool_runner import run_tool_lines, tool_available


def _log(msg):
    print(f"[*] Phase 7 (endpoints): {msg}", file=sys.stderr)


class _Quarantine:
    """Per-host fail counter — halt brute-force when WAF/rate-limit kicks in."""

    def __init__(self, threshold=15):
        self.threshold = threshold
        self.consecutive_fails = 0
        self.tripped = False

    def record(self, status):
        if status in (429, 503, 0):
            self.consecutive_fails += 1
            if self.consecutive_fails >= self.threshold:
                self.tripped = True
        else:
            self.consecutive_fails = 0

    def is_tripped(self):
        return self.tripped


def _build_wordlist():
    """Combine PATH_WORDS and ACTION_WORDS into full probe list."""
    words = set(PATH_WORDS)
    for action in ACTION_WORDS:
        words.add(action)
        words.add("api/" + action)
        words.add("api/v1/" + action)
    return sorted(words)


def _extend_with_extensions(paths):
    """For each path, also probe with common extensions."""
    extended = list(paths)
    for p in paths:
        if p and not any(p.endswith(ext) for ext in EXTENSIONS):
            for ext in EXTENSIONS[:3]:
                extended.append(p + ext)
    return extended


def _kiterunner_scan(url):
    """Try kiterunner for route scanning. Needs the routes-large.kite wordlist
    on disk — see scripts/install_requirements.sh (downloads to
    payloads/kiterunner/routes-large.kite)."""
    if not os.path.exists(KITERUNNER_ROUTES_FILE):
        _log(f"  kiterunner: skipped, no wordlist at {KITERUNNER_ROUTES_FILE} "
             f"(run scripts/install_requirements.sh)")
        return []
    lines = run_tool_lines(
        "kr", ["scan", url, "-w", KITERUNNER_ROUTES_FILE, "--fail-status-codes",
               "404,400", "-q"], timeout=300)
    results = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 2 and parts[1].startswith("/"):
            results.append(parts[1])
    return results


def _ffuf_scan(url):
    """Try ffuf for directory fuzzing. Needs the directories.txt wordlist on
    disk — see scripts/install_requirements.sh (downloads to
    payloads/directories.txt)."""
    if not os.path.exists(DIR_WORDLIST_FILE):
        _log(f"  ffuf: skipped, no wordlist at {DIR_WORDLIST_FILE} "
             f"(run scripts/install_requirements.sh)")
        return []
    lines = run_tool_lines(
        "ffuf", ["-u", url + "/FUZZ", "-w", DIR_WORDLIST_FILE,
                 "-mc", "200,201,204,301,302,401,403,405",
                 "-s"], timeout=300)
    return [l.strip() for l in lines if l.strip().startswith("/")]


def _probe_paths(client, base_url, paths, soft404, quarantine):
    """Pure-Python parallel path probing."""
    found = []

    def probe(path):
        if quarantine.is_tripped():
            return None
        url = base_url.rstrip("/") + "/" + path.lstrip("/")
        resp = client.request("GET", url)
        quarantine.record(resp.status)
        if resp.status == 0 or resp.status >= 404:
            return None
        if soft404.is_soft_404(resp):
            return None
        return (url, resp)

    with futures.ThreadPoolExecutor(max_workers=10) as ex:
        for result in ex.map(probe, paths):
            if result:
                found.append(result)
            if quarantine.is_tripped():
                break

    return found


def discover_endpoints(ctx: ScanContext):
    """Brute-force endpoints on scannable hosts."""
    hosts = ctx.scannable_hosts()
    _log(f"Brute-forcing endpoints on {len(hosts)} hosts "
         f"(skipping {len(ctx.waf_hosts)} WAF hosts)")

    client = HTTPClient(timeout=ctx.timeout)
    wordlist = _build_wordlist()
    extended = _extend_with_extensions(wordlist)
    total_new = 0

    for host in hosts:
        base = host.url.rstrip("/")
        _log(f"  {host.domain}: {len(extended)} paths")

        soft404 = Soft404Detector()
        soft404.fingerprint(client, base)
        quarantine = _Quarantine()

        existing_urls = {e.url for e in ctx.endpoints_for_host(host.domain)}

        if tool_available("kr"):
            kr_paths = _kiterunner_scan(base)
            for path in kr_paths:
                url = base + path
                if url not in existing_urls:
                    ep = Endpoint(url=url, is_api=host.is_api,
                                  source="kiterunner")
                    ctx.endpoints.append(ep)
                    existing_urls.add(url)
                    total_new += 1
        elif tool_available("ffuf"):
            ffuf_paths = _ffuf_scan(base)
            for path in ffuf_paths:
                url = base + path
                if url not in existing_urls:
                    ep = Endpoint(url=url, is_api=host.is_api,
                                  source="ffuf")
                    ctx.endpoints.append(ep)
                    existing_urls.add(url)
                    total_new += 1

        results = _probe_paths(client, base, extended, soft404, quarantine)

        if quarantine.is_tripped():
            _log(f"  {host.domain}: quarantined (rate-limit/WAF)")

        for url, resp in results:
            if url not in existing_urls:
                ep = Endpoint(
                    url=url, status_code=resp.status,
                    content_type=resp.ctype,
                    response_length=resp.length,
                    is_api=host.is_api,
                    source="bruteforce")
                ctx.endpoints.append(ep)
                existing_urls.add(url)
                total_new += 1

    _log(f"New endpoints discovered: {total_new}, "
         f"total: {len(ctx.endpoints)}")
