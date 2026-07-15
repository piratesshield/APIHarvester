"""Phase 5: API URL detection — smart heuristic classification."""
import sys

from ..config import (API_CONTENT_TYPES, API_HEADER_CLUES, API_SERVER_CLUES,
                      API_ERROR_BODY_RE, API_PATH_RE)
from ..http_client import HTTPClient
from ..models import Endpoint, ScanContext


def _log(msg):
    print(f"[*] Phase 5 (API detect): {msg}", file=sys.stderr)


API_PROBE_PATHS = ["/", "/api", "/api/v1", "/api/v2", "/v1", "/v2",
                   "/graphql", "/rest", "/health", "/status"]


def _is_json_body(body):
    """Check if body looks like JSON (starts with { or [)."""
    stripped = (body or "").lstrip()
    return stripped.startswith("{") or stripped.startswith("[")


def _score_api_signals(url, resp):
    """Score how likely a response is from an API endpoint.
    Returns (score, reasons) where score >= 3 means high confidence API."""
    score = 0
    reasons = []

    if API_CONTENT_TYPES.search(resp.ctype or ""):
        score += 3
        reasons.append("api_content_type")

    if _is_json_body(resp.body):
        score += 2
        reasons.append("json_body")

    headers_str = " ".join(f"{k}: {v}" for k, v in resp.headers.items())
    if API_HEADER_CLUES.search(headers_str):
        score += 2
        reasons.append("api_headers")

    if API_PATH_RE.search(url):
        score += 1
        reasons.append("api_path")

    server = resp.headers.get("server", "")
    if API_SERVER_CLUES.search(server):
        score += 1
        reasons.append("api_server")

    if API_ERROR_BODY_RE.search(resp.body or ""):
        score += 2
        reasons.append("api_error_format")

    cors = resp.headers.get("access-control-allow-origin", "")
    if cors:
        score += 1
        reasons.append("cors_header")

    www_auth = resp.headers.get("www-authenticate", "")
    if "bearer" in www_auth.lower():
        score += 2
        reasons.append("bearer_auth")

    return score, reasons


def detect_api_urls(ctx: ScanContext):
    """Probe live hosts to identify API endpoints and classify them."""
    live = ctx.active_hosts()
    _log(f"Detecting API URLs on {len(live)} hosts")

    client = HTTPClient(timeout=ctx.timeout)
    api_count = 0
    endpoint_count = 0

    for host in live:
        best_score = 0
        host_is_api = False

        for path in API_PROBE_PATHS:
            url = host.url.rstrip("/") + path
            resp = client.request("GET", url)

            if resp.status == 0 or resp.status >= 500:
                continue

            score, reasons = _score_api_signals(url, resp)

            if score >= 3:
                host_is_api = True

            if score >= best_score:
                best_score = score

            if resp.status < 404 and score >= 2:
                ep = Endpoint(
                    url=url, status_code=resp.status,
                    content_type=resp.ctype,
                    response_length=resp.length,
                    is_api=score >= 3,
                    source="api_detect")
                ctx.endpoints.append(ep)
                endpoint_count += 1

            options = client.request("OPTIONS", url)
            allow = options.headers.get("allow", "")
            if allow and options.status < 400:
                cors_origin = options.headers.get(
                    "access-control-allow-origin", "")
                if cors_origin or allow:
                    if score < 3:
                        score += 2
                        host_is_api = True

        if host_is_api:
            host.is_api = True
            api_count += 1

    _log(f"API hosts: {api_count}, endpoints found: {endpoint_count}")
