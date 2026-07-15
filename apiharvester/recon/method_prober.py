"""Phase 10: HTTP method enumeration per endpoint."""
import sys

from ..config import METHODS
from ..http_client import HTTPClient
from ..models import ScanContext


def _log(msg):
    print(f"[*] Phase 10 (methods): {msg}", file=sys.stderr)


def _parse_allow_header(value):
    """Parse an Allow header into a list of methods."""
    if not value:
        return []
    return [m.strip().upper() for m in value.split(",") if m.strip()]


def probe_methods(ctx: ScanContext):
    """Enumerate accepted HTTP methods for each endpoint."""
    endpoints = ctx.api_endpoints()
    if not endpoints:
        endpoints = ctx.endpoints[:200]
    _log(f"Probing methods on {len(endpoints)} endpoints")

    client = HTTPClient(timeout=ctx.timeout)
    probed = 0

    for ep in endpoints:
        url = ep.base_url()

        options = client.request("OPTIONS", url)
        allow = options.headers.get("allow", "")
        if allow and options.status < 400:
            ep.methods = _parse_allow_header(allow)
            probed += 1
            continue

        accepted = []
        for method in METHODS:
            if method == "OPTIONS":
                continue
            resp = client.request(method, url)
            if resp.status > 0 and resp.status != 405:
                accepted.append(method)

        if accepted:
            ep.methods = accepted
        probed += 1

    _log(f"Probed {probed} endpoints")
