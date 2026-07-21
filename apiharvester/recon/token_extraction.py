"""Extract authentication tokens from responses during recon.

Tokens can appear in:
  - Auth endpoint responses: /login, /auth, /oauth, /token
  - Headers: Set-Cookie, X-Auth-Token, X-Access-Token, Authorization
  - JSON body: access_token, token, jwt, bearer, api_key, auth_token
  - Cookies: session_id, auth_token, jwt, etc.
"""
import json
import re
import sys
from typing import List

from ..models import Response


def _log(msg):
    print(f"[*] Token extraction: {msg}", file=sys.stderr)


# Regex patterns for token-like strings
TOKEN_PATTERNS = [
    # JWT: eyJhbGc...
    (r"eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}", "JWT"),
    # Bearer/OAuth token (alphanumeric + underscore/dash, 20+ chars)
    (r"[a-zA-Z0-9_-]{30,}", "Bearer"),
    # AWS access key (AKIA...)
    (r"AKIA[0-9A-Z]{16}", "AWS"),
    # Google API key (AIza...)
    (r"AIza[0-9A-Za-z\-_]{35}", "Google"),
]


def _extract_tokens_from_json(body: str) -> List[str]:
    """Extract token-like values from JSON response body."""
    tokens = []
    try:
        data = json.loads(body)
        if not isinstance(data, dict):
            return tokens

        # Check common token field names
        token_fields = [
            "access_token", "token", "jwt", "bearer", "auth_token",
            "api_key", "apiKey", "authentication", "credentials",
            "session", "session_id", "sessionId", "refresh_token",
            "oauth_token", "X-Auth-Token", "authorization"
        ]
        for field in token_fields:
            if field in data:
                val = data[field]
                if isinstance(val, str) and len(val) > 8:
                    tokens.append(val)

        # Recursive search in nested dicts
        def search_nested(obj, depth=0):
            if depth > 3:  # limit recursion
                return
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, str) and len(v) > 16:
                        if any(re.match(pat, v) for pat, _ in TOKEN_PATTERNS):
                            tokens.append(v)
                    elif isinstance(v, dict):
                        search_nested(v, depth + 1)
            elif isinstance(obj, list):
                for item in obj[:10]:  # limit list depth
                    search_nested(item, depth + 1)

        search_nested(data)
    except (json.JSONDecodeError, TypeError):
        pass

    return list(set(tokens))  # deduplicate


def _extract_tokens_from_headers(headers: dict) -> List[str]:
    """Extract tokens from response headers."""
    tokens = []
    token_header_names = [
        "Authorization", "X-Auth-Token", "X-Access-Token", "X-Token",
        "X-API-Key", "Set-Cookie", "WWW-Authenticate", "Proxy-Authenticate"
    ]
    for header in token_header_names:
        value = headers.get(header, "")
        if not value:
            continue

        # Parse "Bearer <token>" format
        if "Bearer" in value:
            parts = value.split()
            if len(parts) >= 2:
                tokens.append(parts[-1])
        # Parse cookies
        elif header == "Set-Cookie":
            for part in value.split(";"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    if len(v) > 8:
                        tokens.append(v.strip())
        else:
            # Take the whole value if it looks like a token
            if len(value) > 8 and not any(c in value for c in [" ", "\n", "<", ">"]):
                tokens.append(value)

    return list(set(tokens))


def _extract_tokens_from_body(body: str) -> List[str]:
    """Extract token-like patterns from response body (HTML or plain text)."""
    tokens = []
    if not body or len(body) > 100000:  # skip huge bodies
        return tokens

    for pattern, token_type in TOKEN_PATTERNS:
        for match in re.finditer(pattern, body):
            token = match.group(0)
            # Filter out false positives
            if len(token) > 8 and token not in [
                "localhost", "example.com", "test.com", "api.example.com"
            ]:
                tokens.append(token)

    return list(set(tokens))


def extract_tokens_from_response(resp: Response) -> List[str]:
    """Extract all tokens from a single response."""
    if not resp or resp.status == 0:
        return []

    tokens = []

    # Headers
    tokens.extend(_extract_tokens_from_headers(resp.headers))

    # Body
    body = resp.body or ""
    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8", errors="replace")
        except:
            body = ""

    # JSON parsing (for APIs)
    tokens.extend(_extract_tokens_from_json(body))

    # Pattern matching (for HTML or plain text)
    tokens.extend(_extract_tokens_from_body(body))

    return list(set(tokens))  # final dedup


def extract_tokens_from_auth_endpoints(ctx):
    """Scan auth-related endpoints for tokens in responses.

    Auth endpoints are likely to return tokens in login/refresh responses.
    """
    from ..models import Endpoint

    auth_keywords = ["auth", "login", "token", "oauth", "refresh", "signin"]
    auth_endpoints = [
        e for e in ctx.endpoints
        if any(kw in e.path.lower() for kw in auth_keywords)
        and e.status_code and e.status_code < 400
    ]

    _log(f"Scanning {len(auth_endpoints)} auth endpoints for tokens")

    from ..http_client import HTTPClient
    client = HTTPClient(timeout=ctx.timeout)

    for ep in auth_endpoints:
        try:
            # Try GET first (usually safe for token endpoints)
            resp = client.request("GET", ep.url)
            tokens = extract_tokens_from_response(resp)
            for token in tokens:
                if token not in ctx.tokens:
                    ctx.tokens.append(token)
                    _log(f"  Found token in {ep.path}: {token[:20]}...")
        except Exception as e:
            pass

    return len(ctx.tokens)
