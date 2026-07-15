"""Phase 11: Response object shape discovery — GET each endpoint and
record its JSON field names, so objectshape.txt is populated during
recon rather than depending on the mass_assignment attack running."""
import concurrent.futures
import sys

from ..http_client import HTTPClient
from ..models import ScanContext
from ..utils.json_shape import extract_fields


def _log(msg):
    print(f"[*] Phase 11 (shape): {msg}", file=sys.stderr)


def discover_object_shapes(ctx: ScanContext):
    """GET each API endpoint and record its response's top-level fields."""
    endpoints = ctx.api_endpoints()
    if not endpoints:
        endpoints = [e for e in ctx.endpoints if e.status_code
                     and e.status_code < 400]
    _log(f"Probing object shape on {len(endpoints)} endpoints "
         f"(concurrently with {ctx.threads} threads)")

    headers = {}
    if ctx.auth:
        headers["Authorization"] = ctx.auth

    def probe(ep):
        client = HTTPClient(timeout=ctx.timeout)
        resp = client.request("GET", ep.base_url(), headers=headers)
        if resp.status != 200:
            return ep, []
        return ep, sorted(extract_fields(resp.body))

    shaped = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=ctx.threads) as executor:
        futures = [executor.submit(probe, ep) for ep in endpoints]
        for future in concurrent.futures.as_completed(futures):
            ep, fields = future.result()
            if fields:
                ep.object_fields = fields
                shaped += 1

    _log(f"Object shapes discovered: {shaped}")
