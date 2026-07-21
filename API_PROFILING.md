# API Capability Profiling — Pre-Flight Detection

Before running attacks, APIHarvester now profiles discovered APIs to understand what they accept and how they respond. This prevents false-positives and makes attacks look more "genuine" to WAF/edge filtering.

## Why Profile?

Real-world APIs have specific requirements:

- **HTTP version negotiation**: Akamai requires HTTP/1.1; the tool was auto-negotiating HTTP/2 and failing
- **Header requirements**: Some APIs block requests missing `Accept`, `User-Agent`, or `Accept-Language`
- **Content-Type negotiation**: Not all APIs accept `application/json`; some want specific media types
- **Auth location**: Auth can be in `Authorization`, `X-API-Key`, custom headers, or query params
- **Binary protocols**: Some APIs use Protobuf, gRPC, or binary serialization

## How It Works

**Phase 5b** of recon (new) profiles each discovered API host with ~10-15 low-volume probes:

```
[*] Profiling API: https://api.myntra.com
  server: (unknown)
  waf: Akamai
  api_type: REST-JSON
  content_types: []
  auth_scheme: Bearer @ Authorization
  ua_pattern: any
  compression: False
  rate_limiting: False

[+] Profiled api.myntra.com: REST-JSON, WAF=Akamai, auth=Bearer
```

Results are stored in `ctx.api_profiles[base_url]` and used by attacks to craft native-looking requests.

## API Profile Format

Each profile captures:

```python
{
  "http_versions": ["1.1", "2"],        # in preferred order
  "preferred_headers": {
    "Accept": "application/json",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...",
    "Content-Type": "application/json"
  },
  "required_headers": ["Authorization"],
  "content_types": ["application/json"],
  "auth_schemes": ["Bearer", "OAuth2", "Basic"],
  "auth_header_name": "Authorization",
  "api_type": "REST-JSON|REST-XML|GraphQL|gRPC|RPC|Custom",
  "server_header": "nginx/1.20",
  "waf_vendor": "Akamai|Cloudflare|AWS|...",
  "typical_errors": {
    "403": "Forbidden",
    "503": "Service Unavailable"
  },
  "user_agent_pattern": "Mozilla",
  "is_binary_api": false,
  "supports_compression": false,
  "has_rate_limiting": false,
  "tls_required": true
}
```

## Using Profiles in Attacks

When attacks run, they call `apply_profile()` to merge their request headers with the API's genuine-request profile:

```python
from apiharvester.recon.api_profiler import apply_profile

# Get the profile for this API
profile = ctx.api_profiles.get(endpoint.host, {})

# Merge: profile headers become defaults, attack headers win
headers = apply_profile(
    {"Authorization": "Bearer ATTACKER_TOKEN"},
    profile
)

# Result: headers now includes genuine User-Agent, Accept, etc.
# + the attacker's Authorization
```

This makes requests look legitimate to WAF/IDS systems.

## Detection Heuristics

### HTTP Version

- Default: HTTP/2 for HTTPS, HTTP/1 for HTTP
- **Akamai/Cloudflare WAF detected** → flip to HTTP/1.1 first (known stream handling issues)

### Auth Scheme

Inferred from URL path:
- `/auth`, `/login`, `/token` → `Bearer`, `OAuth2`, `Basic`
- `/api-key`, `/apikey` → `API-Key` @ `X-API-Key`
- `/oauth`, `/oidc` → `OAuth2`, `Bearer`

### Content-Type

Tested against common types; recorded in order of success.

### API Type

Detected from:
- URL hints (`/graphql` → GraphQL)
- Response body (JSON vs XML vs Protobuf)
- Content-Type header
- Response structure (GraphQL has `data` + `errors`)

### WAF Vendor

Uses existing `detect_waf_vendor()` from `waf_bypass.py`.

## Example: Debugging Myntra

```bash
# Stand-alone profile script (no attack)
python3 scratch/profile_api.py https://api.myntra.com/auth/v1/refresh

# Output shows:
# - api_type: REST-JSON
# - waf_vendor: Akamai
# - http_versions: ["1.1", "2"]  # 1.1 prioritized for Akamai
# - auth: Bearer @ Authorization
# - User-Agent: Mozilla/5.0 (browsers preferred)
```

## Future: HTTP/1.1 Enforcement

Currently, profiles *recommend* HTTP/1.1 order, but `HTTPClient` doesn't enforce it (urllib3 auto-negotiates). To fully lock HTTP/1.1:

```python
# Planned: add to HTTPClient
class HTTPClient:
    FORCE_HTTP_VERSION = None  # "1.1", "2", or None (auto)

    def request(self, ...):
        # Pass force_http to underlying adapter
        pool.http_version = self.FORCE_HTTP_VERSION or 'auto'
```

Then:

```python
from .recon.api_profiler import profile_api
profile = profile_api(ctx, target)
if profile.http_versions[0] == "1.1":
    HTTPClient.FORCE_HTTP_VERSION = "1.1"
```

## Files

- **`apiharvester/recon/api_profiler.py`** — Core profiling engine
- **`scratch/profile_api.py`** — Stand-alone debug script
- **`apiharvester/__main__.py`** — Integrated as Phase 5b in recon pipeline
- **`apiharvester/models.py`** — `ScanContext.api_profiles` dict

## Integration Points

### For Attacks

Attacks can now request the profile:

```python
def run_bola(ctx, endpoints):
    for ep in endpoints:
        profile = ctx.api_profiles.get(ep.host, {})
        # Use profile["preferred_headers"] when crafting requests
```

### For WAF Bypass

The profiler identifies WAF vendors and HTTP version issues, which inform:

```python
# If Akamai, use HTTP/1.1 + browser UA + origin spoofing
# If Cloudflare, expect JS challenges (already handled)
```

### For Output

Profiles written to recon output:

```
output/example.com_YYYYMMDD_HHMMSS/api_profiles.jsonl
# Each line: {"url": "https://...", "profile": {...}}
```
