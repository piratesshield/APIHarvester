"""Phase 8: Hidden parameter discovery — Arjun algorithm reimplemented."""
import concurrent.futures
import hashlib
import os
import sys

from ..config import PARAM_WORDLIST, PARAM_WORDLIST_FILE
from ..http_client import HTTPClient
from ..models import ScanContext
from ..utils.tool_runner import run_tool_lines, tool_available


def _log(msg):
    print(f"[*] Phase 8 (params): {msg}", file=sys.stderr)


class _Fingerprint:
    """Response fingerprint for anomaly comparison."""

    def __init__(self, resp):
        self.status = resp.status
        self.length = resp.length
        self.ctype = resp.ctype
        self.body_hash = hashlib.md5(
            (resp.body or "").encode()).hexdigest()
        self.line_count = (resp.body or "").count("\n")
        self.headers_keys = sorted(resp.headers.keys())
        redirect = resp.headers.get("location", "")
        self.redirect = redirect

    def differs_from(self, other):
        """Return True if fingerprints differ significantly."""
        if self.status != other.status:
            return True
        if self.redirect != other.redirect:
            return True
        if abs(self.length - other.length) > max(32, other.length * 0.1):
            return True
        if abs(self.line_count - other.line_count) > 5:
            return True
        if self.body_hash != other.body_hash:
            length_diff = abs(self.length - other.length)
            if length_diff > 16:
                return True
        return False


def _establish_baseline(client, url, method="GET"):
    """Send 2 identical requests and return stable fingerprint."""
    r1 = client.request(method, url)
    r2 = client.request(method, url)
    fp1 = _Fingerprint(r1)
    fp2 = _Fingerprint(r2)
    if fp1.differs_from(fp2):
        return None
    return fp1


def _chunk_list(lst, size):
    for i in range(0, len(lst), size):
        yield lst[i:i + size]


def _build_query(url, params):
    """Append params to URL as query string."""
    sep = "&" if "?" in url else "?"
    pairs = "&".join(f"{p}=1" for p in params)
    return url + sep + pairs


def _binary_search(client, url, params, baseline, method="GET"):
    """Bisect a chunk to find which individual param causes anomaly."""
    if len(params) <= 1:
        return params

    mid = len(params) // 2
    left = params[:mid]
    right = params[mid:]

    found = []
    for half in (left, right):
        test_url = _build_query(url, half)
        resp = client.request(method, test_url)
        fp = _Fingerprint(resp)
        if fp.differs_from(baseline):
            found.extend(_binary_search(client, url, half, baseline, method))

    return found


def _verify_param(client, url, param, baseline, method="GET"):
    """Confirm a single param causes a real difference."""
    test_url = _build_query(url, [param])
    resp = client.request(method, test_url)
    fp = _Fingerprint(resp)
    return fp.differs_from(baseline)


def _arjun_discover(client, url, method="GET", chunk_size=25):
    """Arjun-style parameter discovery: baseline, chunk, bisect, verify."""
    baseline = _establish_baseline(client, url, method)
    if baseline is None:
        return []

    # Check if a garbage parameter causes an anomaly. If so, the page is dynamic/unstable.
    garbage_url = _build_query(url, ["apiharvester_garbage_detect"])
    garbage_resp = client.request(method, garbage_url)
    garbage_fp = _Fingerprint(garbage_resp)
    if garbage_fp.differs_from(baseline):
        return []


    found = []
    for chunk in _chunk_list(list(PARAM_WORDLIST), chunk_size):
        test_url = _build_query(url, chunk)
        resp = client.request(method, test_url)
        fp = _Fingerprint(resp)

        if not fp.differs_from(baseline):
            continue

        candidates = _binary_search(client, url, chunk, baseline, method)
        for param in candidates:
            if _verify_param(client, url, param, baseline, method):
                if param not in found:
                    found.append(param)

    return found


def _arjun_tool(url):
    """Try external arjun tool for cross-validation. Uses the downloaded
    params.txt wordlist (see scripts/install_requirements.sh) if present,
    else falls back to arjun's own bundled default wordlist."""
    if not tool_available("arjun"):
        return []
    args = ["-u", url, "-m", "GET", "-q"]
    if os.path.exists(PARAM_WORDLIST_FILE):
        args += ["-w", PARAM_WORDLIST_FILE]
    else:
        _log(f"  arjun: no wordlist at {PARAM_WORDLIST_FILE} "
             f"(run scripts/install_requirements.sh), using arjun's default")
    lines = run_tool_lines("arjun", args, timeout=120)
    params = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith("["):
            params.append(line)
    return params


def discover_params(ctx: ScanContext):
    """Discover hidden parameters on all API endpoints."""
    endpoints = ctx.api_endpoints()
    if not endpoints:
        endpoints = [e for e in ctx.endpoints if e.status_code
                     and e.status_code < 400]
    _log(f"Discovering params on {len(endpoints)} endpoints (concurrently with {ctx.threads} threads)")

    def scan_endpoint(ep):
        thread_client = HTTPClient(timeout=ctx.timeout)
        url = ep.base_url()
        found = _arjun_discover(thread_client, url)

        ext_params = _arjun_tool(url)
        for p in ext_params:
            if p not in found:
                found.append(p)
        return ep, found

    total_params = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=ctx.threads) as executor:
        futures = {executor.submit(scan_endpoint, ep): ep for ep in endpoints}
        for future in concurrent.futures.as_completed(futures):
            ep, found = future.result()
            if found:
                for p in found:
                    # "1" is the literal probe value _build_query used to
                    # confirm this param, so record it as the observed value.
                    ep.params.setdefault(p, "1")
                total_params += len(found)
                _log(f"  {ep.path}: {found}")

    spec_params = _extract_params_from_specs(ctx)
    total_params += spec_params

    _log(f"Total params discovered: {total_params}")


def _extract_params_from_specs(ctx):
    """Pull param names from swagger specs and apply to matching endpoints."""
    count = 0
    for domain, spec in ctx.swagger_specs.items():
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method_key, op in methods.items():
                if not isinstance(op, dict):
                    continue
                for param in op.get("parameters", []):
                    if isinstance(param, dict) and param.get("in") == "query":
                        name = param.get("name", "")
                        if not name:
                            continue
                        value = str(param.get("example",
                                               param.get("default", "1")))
                        for ep in ctx.endpoints_for_host(domain):
                            if path.rstrip("/") in ep.path:
                                ep.params.setdefault(name, value)
                                count += 1
    return count
