"""Pre-flight API capability & signature detection.

Before running attacks, probe the target to understand:
  - Supported HTTP versions (1.0, 1.1, 2, 3)
  - Required/preferred headers
  - Content-Type negotiation
  - Authentication scheme(s)
  - API type classification (REST, GraphQL, gRPC, RPC)
  - Response shape and error patterns

Builds a "genuine request profile" used by attacks to craft native-looking requests
that minimize WAF false-positives and maximize test legitimacy.
"""
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import json

from ..http_client import HTTPClient
from ..models import Response


class APIProfile:
    """Signature of a target API — what it accepts and returns."""

    def __init__(self):
        self.http_versions: List[str] = []  # ["1.1", "2", ...] in order of preference
        self.preferred_headers: Dict[str, str] = {}  # {"Accept": "application/json", ...}
        self.required_headers: set = set()  # headers that must be present
        self.content_types: List[str] = []  # supported: ["application/json", "application/xml", ...]
        self.auth_schemes: List[str] = []  # ["Bearer", "OAuth2", "API-Key", ...]
        self.auth_header_name: str = ""  # where auth goes: "Authorization", "X-API-Key", etc.
        self.api_type: str = ""  # "REST", "GraphQL", "gRPC", "RPC", "Custom"
        self.server_header: str = ""  # "nginx/1.20", "Akamai", etc.
        self.waf_vendor: str = ""  # "Akamai", "Cloudflare", "AWS", ...
        self.typical_errors: Dict[int, str] = {}  # {401: "Unauthorized", 403: "Forbidden", ...}
        self.user_agent_pattern: str = ""  # regex/hint for accepted UAs ("Mozilla", ".*", etc.)
        self.is_binary_api: bool = False  # protobuf, msgpack, binary?
        self.supports_compression: bool = False  # gzip, br, deflate?
        self.has_rate_limiting: bool = False  # X-RateLimit-* or similar?
        self.tls_required: bool = False  # HTTPS enforced?

    def to_dict(self) -> dict:
        return {
            "http_versions": self.http_versions,
            "preferred_headers": self.preferred_headers,
            "required_headers": list(self.required_headers),
            "content_types": self.content_types,
            "auth_schemes": self.auth_schemes,
            "auth_header_name": self.auth_header_name,
            "api_type": self.api_type,
            "server_header": self.server_header,
            "waf_vendor": self.waf_vendor,
            "typical_errors": self.typical_errors,
            "user_agent_pattern": self.user_agent_pattern,
            "is_binary_api": self.is_binary_api,
            "supports_compression": self.supports_compression,
            "has_rate_limiting": self.has_rate_limiting,
            "tls_required": self.tls_required,
        }


def _extract_server_header(resp: Response) -> str:
    """Return Server header value or empty."""
    return resp.headers.get("Server", "")


def _extract_waf_vendor(resp: Response) -> str:
    """Detect WAF vendor from response headers."""
    from ..utils.waf_bypass import detect_waf_vendor
    return detect_waf_vendor(resp)


def _detect_api_type(resp: Response, url: str) -> str:
    """Infer API type from response body, Content-Type, and URL hints."""
    ctype = resp.headers.get("Content-Type", "").lower()
    body = resp.body or ""

    # Ensure body is a string for startswith checks
    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8", errors="replace")
        except:
            body = ""

    # GraphQL
    if "graphql" in url.lower() or ("data" in body and "errors" in body):
        try:
            data = json.loads(body)
            if "data" in data or "errors" in data:
                return "GraphQL"
        except:
            pass

    # gRPC (proto binary or grpc-web)
    if "application/grpc" in ctype:
        return "gRPC"

    # REST JSON (most common)
    if "application/json" in ctype or body.startswith("{") or body.startswith("["):
        return "REST-JSON"

    # REST XML
    if "application/xml" in ctype or "text/xml" in ctype or body.startswith("<"):
        return "REST-XML"

    # RPC (JSON-RPC, XML-RPC)
    if "jsonrpc" in body.lower() or "methodCall" in body:
        return "RPC"

    return "REST"  # default


def _detect_auth_scheme(url: str) -> Tuple[List[str], str]:
    """Guess auth schemes and header name from URL path and common patterns.

    Returns (schemes, header_name) where schemes is ["Bearer", "OAuth2", ...]
    and header_name is "Authorization", "X-API-Key", etc.
    """
    schemes = []
    header_name = "Authorization"

    path = urlparse(url).path.lower()

    # Endpoint hints
    if "auth" in path or "login" in path or "token" in path:
        schemes.extend(["Bearer", "OAuth2", "Basic"])
    if "api-key" in path or "apikey" in path or "key" in path:
        schemes.append("API-Key")
        header_name = "X-API-Key"

    # URL structure hints
    if "/oauth" in path or "/oidc" in path:
        schemes = ["OAuth2", "Bearer"]
    elif "/jwt" in path or "/bearer" in path:
        schemes = ["Bearer", "JWT"]

    return schemes or ["Bearer"], header_name


def profile_api(ctx, target_url: str, timeout: int = 10) -> APIProfile:
    """Probe an API endpoint to build its capability profile.

    Makes ~10-15 low-volume requests to detect:
      - HTTP version support
      - Required/preferred headers
      - Content-Type negotiation
      - Auth scheme and location
      - API type
      - Server/WAF info

    Returns an APIProfile object used by attacks to craft native-looking requests.
    """
    prof = APIProfile()
    client = HTTPClient(timeout=timeout)

    print(f"[*] Profiling API: {target_url}")

    # 1) Baseline: plain GET, minimal headers (what breaks first?)
    try:
        r = client.request("GET", target_url)
        prof.server_header = _extract_server_header(r)
        prof.waf_vendor = _extract_waf_vendor(r)
        prof.api_type = _detect_api_type(r, target_url)
        prof.tls_required = target_url.startswith("https")

        print(f"  server: {prof.server_header or '(unknown)'}")
        print(f"  waf: {prof.waf_vendor or 'none'}")
        print(f"  api_type: {prof.api_type}")
    except Exception as e:
        print(f"  [!] baseline probe failed: {e}")
        return prof

    # 2) Content-Type negotiation: try common types, see which is accepted
    for ctype in ["application/json", "application/xml", "text/html", "application/protobuf"]:
        try:
            r = client.request("GET", target_url, headers={"Accept": ctype})
            if r.status < 400:
                prof.content_types.append(ctype)
        except:
            pass

    # 3) Auth scheme detection
    schemes, auth_hdr = _detect_auth_scheme(target_url)
    prof.auth_schemes = schemes
    prof.auth_header_name = auth_hdr

    # 4) User-Agent: test browser vs bot
    bot_ua = "apiharvester/1.0 (security test)"
    browser_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    try:
        r_bot = client.request("GET", target_url, headers={"User-Agent": bot_ua})
        r_br = client.request("GET", target_url, headers={"User-Agent": browser_ua})
        # If browser UA gets better status, prefer it
        if r_br.status < 400 and r_bot.status >= 400:
            prof.user_agent_pattern = "Mozilla"
        elif r_bot.status < 400:
            prof.user_agent_pattern = ".*"  # accepts any
    except:
        pass

    # 5) Compression support
    try:
        r = client.request("GET", target_url, headers={"Accept-Encoding": "gzip, deflate"})
        if "Content-Encoding" in r.headers:
            prof.supports_compression = True
    except:
        pass

    # 6) Rate limiting detection (X-RateLimit-*, X-Rate-*, etc.)
    for key in r.headers:
        if "ratelimit" in key.lower() or "rate-limit" in key.lower():
            prof.has_rate_limiting = True
            break

    # 7) Error pattern detection: test with invalid path to see error shape
    try:
        r_err = client.request("GET", target_url.rstrip("/") + "/nonexistent-9999xyz")
        if r_err.status >= 400:
            prof.typical_errors[r_err.status] = r_err.body[:200] if r_err.body else ""
    except:
        pass

    # 8) HTTP version preference: record in order of success
    # (Note: HTTPClient currently uses urllib3 which handles version negotiation,
    #  but we can record what succeeded. HTTP/2 is default on HTTPS, fall back to 1.1.)
    prof.http_versions = ["2", "1.1"]  # typical modern priority
    if not target_url.startswith("https"):
        prof.http_versions = ["1.1"]  # HTTP/1 only for non-TLS

    # Heuristic: if Akamai WAF detected, strongly prefer HTTP/1.1
    # (many edge WAFs have stream handling issues with HTTP/2)
    if "Akamai" in prof.waf_vendor or "CloudFlare" in prof.waf_vendor:
        prof.http_versions = ["1.1", "2"]  # flip priority for Akamai/CF

    # 9) Build preferred header set for genuine requests
    prof.preferred_headers = {
        "Accept": prof.content_types[0] if prof.content_types else "application/json",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br" if prof.supports_compression else "identity",
        "User-Agent": browser_ua,
    }

    if prof.api_type == "REST-JSON":
        prof.preferred_headers["Content-Type"] = "application/json"

    print(f"  content_types: {prof.content_types}")
    print(f"  auth_scheme: {prof.auth_schemes[0] if prof.auth_schemes else 'none'} "
          f"@ {prof.auth_header_name}")
    print(f"  ua_pattern: {prof.user_agent_pattern or 'any'}")
    print(f"  compression: {prof.supports_compression}")
    print(f"  rate_limiting: {prof.has_rate_limiting}")

    return prof


def apply_profile(client_headers: Dict[str, str], profile: APIProfile) -> Dict[str, str]:
    """Merge attack-caller headers with profile-derived genuine headers.

    Profile headers become defaults; caller headers (e.g., Authorization) win.
    """
    merged = dict(profile.preferred_headers)
    merged.update(client_headers)
    return merged
