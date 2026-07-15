"""Phase 3: HTTP probing — httpx wrapper + pure-Python fallback."""
import json
import re
import sys
import concurrent.futures as futures

from ..http_client import HTTPClient
from ..models import ScanContext
from ..utils.tool_runner import run_tool, tool_available

TITLE_RE = re.compile(r"<title[^>]*>([^<]{1,200})</title>", re.I | re.S)


def _log(msg):
    print(f"[*] Phase 3 (prober): {msg}", file=sys.stderr)


def _probe_with_httpx(domains):
    """Use httpx for bulk probing. Returns dict[domain] -> probe_info."""
    if not tool_available("httpx"):
        return {}

    stdin = "\n".join(domains)
    result = run_tool("httpx",
                      ["-silent", "-json", "-timeout", "10",
                       "-follow-redirects", "-status-code",
                       "-title", "-server", "-content-type",
                       "-tech-detect"],
                      timeout=300, stdin_data=stdin)
    if result is None:
        return {}

    stdout, _, _ = result
    results = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            domain = obj.get("input", "").lower()
            results[domain] = {
                "url": obj.get("url", ""),
                "status": obj.get("status_code", 0),
                "title": obj.get("title", ""),
                "server": obj.get("webserver", ""),
                "content_type": obj.get("content_type", ""),
                "tech": obj.get("tech", []),
            }
        except (json.JSONDecodeError, KeyError):
            continue
    return results


def _probe_single(client, domain):
    """Probe a single domain with HTTPS then HTTP."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/"
        resp = client.request("GET", url)
        if resp.status > 0:
            title = ""
            m = TITLE_RE.search(resp.body or "")
            if m:
                title = m.group(1).strip()
            return {
                "url": url,
                "status": resp.status,
                "title": title,
                "server": resp.headers.get("server", ""),
                "content_type": resp.ctype,
                "body": resp.body,
                "headers": resp.headers,
            }
    return None


def _probe_fallback(domains, timeout=10, threads=20):
    """Pure-Python HTTP probing via urllib."""
    _log(f"Fallback: probing {len(domains)} domains...")
    client = HTTPClient(timeout=timeout)
    results = {}

    def probe(domain):
        info = _probe_single(client, domain)
        if info:
            return domain, info
        return domain, None

    with futures.ThreadPoolExecutor(max_workers=threads) as ex:
        for domain, info in ex.map(probe, domains):
            if info:
                results[domain] = info

    return results


def probe_hosts(ctx: ScanContext):
    """HTTP-probe all resolved hosts, mark live ones."""
    domains = [h.domain for h in ctx.hosts]
    _log(f"Probing {len(domains)} hosts")

    probed = _probe_with_httpx(domains)
    if not probed:
        probed = _probe_fallback(domains, timeout=ctx.timeout,
                                 threads=ctx.threads)

    live = 0
    for host in ctx.hosts:
        info = probed.get(host.domain)
        if info and info.get("status", 0) > 0:
            host.is_live = True
            host.status_code = info["status"]
            host.server = info.get("server", "")
            host.content_type = info.get("content_type", "")
            host.title = info.get("title", "")
            host.url = info.get("url", host.url)
            live += 1

    _log(f"Live hosts: {live}/{len(domains)}")
    return probed
