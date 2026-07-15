"""Phase 2: DNS resolution — dnsx wrapper + pure-Python fallback."""
import socket
import sys
import concurrent.futures as futures
import ipaddress

from ..models import ScanContext
from ..utils.tool_runner import run_tool_lines

CDN_RANGES = [
    ("13.32.0.0/15", "CloudFront"),
    ("13.35.0.0/16", "CloudFront"),
    ("13.224.0.0/14", "CloudFront"),
    ("52.84.0.0/15", "CloudFront"),
    ("54.182.0.0/16", "CloudFront"),
    ("54.192.0.0/16", "CloudFront"),
    ("54.230.0.0/16", "CloudFront"),
    ("54.239.128.0/18", "CloudFront"),
    ("99.84.0.0/16", "CloudFront"),
    ("104.16.0.0/13", "Cloudflare"),
    ("104.24.0.0/14", "Cloudflare"),
    ("172.64.0.0/13", "Cloudflare"),
    ("173.245.48.0/20", "Cloudflare"),
    ("188.114.96.0/20", "Cloudflare"),
    ("190.93.240.0/20", "Cloudflare"),
    ("197.234.240.0/22", "Cloudflare"),
    ("198.41.128.0/17", "Cloudflare"),
    ("23.0.0.0/12", "Akamai"),
    ("104.64.0.0/10", "Akamai"),
    ("184.24.0.0/13", "Akamai"),
    ("151.101.0.0/16", "Fastly"),
    ("199.232.0.0/16", "Fastly"),
]

_CDN_NETS = [(ipaddress.ip_network(cidr), name) for cidr, name in CDN_RANGES]


def _log(msg):
    print(f"[*] Phase 2 (resolver): {msg}", file=sys.stderr)


def _identify_cdn(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
        for net, name in _CDN_NETS:
            if addr in net:
                return name
    except ValueError:
        pass
    return ""


def _resolve_with_dnsx(domains):
    """Use dnsx for bulk resolution. Returns dict[domain] -> [ips]."""
    stdin = "\n".join(domains)
    lines = run_tool_lines("dnsx", ["-a", "-resp", "-silent"],
                           timeout=120)
    results = {}
    for line in lines:
        parts = line.split()
        if len(parts) >= 2:
            domain = parts[0].lower().rstrip(".")
            ips = [p.strip("[]") for p in parts[1:] if _is_ip(p.strip("[]"))]
            if ips:
                results[domain] = ips
    return results


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _resolve_fallback(domains, threads=20):
    """Pure-Python DNS resolution with socket.gethostbyname."""
    _log(f"Fallback: resolving {len(domains)} domains...")
    results = {}

    def resolve_one(domain):
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            return domain, ips
        except socket.gaierror:
            return domain, []

    with futures.ThreadPoolExecutor(max_workers=threads) as ex:
        for domain, ips in ex.map(resolve_one, domains):
            if ips:
                results[domain] = ips

    return results


def resolve_hosts(ctx: ScanContext):
    """Resolve all discovered hosts to IP addresses, tag CDN."""
    domains = [h.domain for h in ctx.hosts]
    _log(f"Resolving {len(domains)} domains")

    resolved = _resolve_with_dnsx(domains)
    if not resolved:
        resolved = _resolve_fallback(domains, threads=ctx.threads)

    alive = 0
    cdn_count = 0
    for host in ctx.hosts:
        ips = resolved.get(host.domain, [])
        host.ips = ips
        if ips:
            alive += 1
            cdn = _identify_cdn(ips[0])
            if cdn:
                host.is_cdn = True
                cdn_count += 1

    dead = [h for h in ctx.hosts if not h.ips]
    ctx.hosts = [h for h in ctx.hosts if h.ips]

    _log(f"Resolved: {alive}, unresolvable: {len(dead)}, CDN: {cdn_count}")
    return resolved
