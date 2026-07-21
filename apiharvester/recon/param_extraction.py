"""Extract parameters from endpoint paths and URLs.

Many endpoints come from Swagger/crawl with templated paths like:
  /api/v2/score/league/{slug}/meeting/{meetingId}

These should be recognized as path parameters immediately, not during
query-parameter probing.
"""
import re
import sys
from urllib.parse import urlparse, parse_qs

from ..models import ScanContext


def _log(msg):
    print(f"[*] Path params: {msg}", file=sys.stderr)


def _extract_path_params(path: str) -> dict:
    """Extract {param} placeholders from a path.

    Returns dict of param_name → "1" (default value for testing).
    """
    params = {}
    # Match {identifier} or {identifier:pattern}
    for match in re.finditer(r"\{([a-zA-Z0-9_]+)(?::[^}]*)?\}", path):
        param_name = match.group(1)
        params[param_name] = "1"  # placeholder test value
    return params


def _extract_query_params(url: str) -> dict:
    """Extract query string parameters from a URL."""
    params = {}
    parsed = urlparse(url)
    if parsed.query:
        for key, values in parse_qs(parsed.query, keep_blank_values=True).items():
            # parse_qs returns lists; take first value
            params[key] = values[0] if values else "1"
    return params


def extract_endpoint_params(ctx: ScanContext):
    """Scan all endpoints and extract path/query parameters.

    This runs before param_discovery (Phase 7.5) to identify parameters
    that are already visible in the endpoint URL or path.
    """
    count = 0
    for ep in ctx.endpoints:
        # Extract path parameters (e.g., {id}, {slug})
        path_params = _extract_path_params(ep.path)
        for name, value in path_params.items():
            ep.params.setdefault(name, value)
            count += 1

        # Extract query string parameters from discovered URL
        query_params = _extract_query_params(ep.url)
        for name, value in query_params.items():
            ep.params.setdefault(name, value)
            count += 1

    _log(f"Extracted {count} path/query params from {len(ctx.endpoints)} endpoints")
    return count
