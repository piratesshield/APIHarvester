# API Security — Real-World Case Research & Detection Mapping

**Purpose**: Map the API security taxonomy to *verified* real-world breaches, then derive concrete scanner detection logic from each.
**Companion to**: [SKILL.md](SKILL.md)
**Research date**: 2026-07-16
**Sources**: KrebsOnSecurity, PortSwigger Research, Pen Test Partners, PortSwigger Web Security Academy, BleepingComputer, TechCrunch, vendor post-mortems, arXiv/NSA MCP papers, + 1,173 curated writeups in [extracted_urls.txt](extracted_urls.txt)

---

## Executive Mapping: Taxonomy → Verified Case → Impact

| Taxonomy Category | Verified Real-World Case | Root Cause | Impact |
|---|---|---|---|
| **BOLA / IDOR** | USPS Informed Visibility (2018) | Wildcard params + no object-level auth | 60M users exposed |
| **BOLA / IDOR (unauth)** | Peloton API (2021) | Unauthenticated API returned private profiles | All users' private data |
| **Broken Auth (unauth API)** | Optus (2022) | Public API, no auth + sequential IDs | 9.8M customers, AU$ regulatory action |
| **BPOA / Mass Assignment** | GitHub / Homakov (2012) | Rails `update_attributes` no whitelist | Write access to rails/rails repo |
| **SSRF** | Capital One (2019) | WAF SSRF → AWS metadata → IAM keys | 106M records, ~$190M costs+fines |
| **Broken Account Enumeration** | Twitter API (2022) | Phone/email→userID despite privacy setting | 5.4M accounts scraped, sold |
| **Web Cache Deception** | PayPal (Omer Gil, 2017) | CDN caches `page.php/x.css` as static | Session/CSRF token theft → ATO |
| **HTTP Request Smuggling** | Amazon `/b/` (Kettle, 2019) | CL/TE parser desync front vs back-end | Captured live user requests+tokens |
| **JWT Validation Flaws** | Hono/HarbourJwt CVEs (2026) | Trusts `alg` header (RS256→HS256) | Forge tokens for any user |
| **Multi-Step Race Conditions** | Coupon/gift-card reuse (2023+) | TOCTOU + HTTP/2 single-packet | Financial loss, limit bypass |
| **API Key Theft** | 3Commas → FTX/Binance (2022) | Phished keys, no IP allowlist/scoping | $14.8M+ across 44 victims |
| **Agentic AI / MCP** | MCP Tool Poisoning CVE-2025-54136 | Client trusts server tool metadata | Silent redefinition → key exfil |

---

## 1. Broken Object Level Authorization (BOLA / IDOR)

### Verified Case A — USPS "Informed Visibility" API (Nov 2018)
- **What**: Any logged-in usps.com user could query account details of **any** of ~60M other users — email, username, user ID, account #, address, phone, mailing-campaign data — *and modify some fields*.
- **Root cause**: API accepted **wildcard search parameters**, returning *all* records for a dataset with no object-level authorization check. No special tooling needed — just browser dev tools.
- **Aggravating factor**: Researcher reported it **over a year earlier**; USPS ignored until Krebs made contact.
- **Source**: [KrebsOnSecurity](https://krebsonsecurity.com/2018/11/usps-site-exposed-data-on-60-million-users/), [Salt Security](https://salt.security/blog/lessons-learned-usps-api-vulnerability-and-60-million-exposed-users)

### Verified Case B — Peloton API (May 2021)
- **What**: Unauthenticated requests returned private profile data (user IDs, age, gender, city, weight, workout stats) **even when profiles set to private**.
- **Root cause**: Unauthenticated/over-permissive API; auth check missing on the resource endpoints.
- **Disclosure lesson**: Peloton silently "fixed" one issue but the fix didn't work; full resolution only after journalist pressure at day 90.
- **Discoverer**: Jan Masters, Pen Test Partners.
- **Source**: [Pen Test Partners](https://www.pentestpartners.com/security-blog/tour-de-peloton-exposed-user-data/), [TechCrunch](https://techcrunch.com/2021/05/05/peloton-bug-account-data-leak/)

### Scanner Detection Logic
```python
def detect_bola(endpoints, token_a, token_b):
    """
    Two-identity differential + wildcard probing.
    Derived from USPS (wildcard) + Peloton (unauth) cases.
    """
    findings = []
    for ep in endpoints:
        obj_id = extract_object_id(ep)          # numeric, UUID, hash, slug
        if not obj_id:
            continue

        # (1) Cross-user access — user A requests user B's object
        r_a = request(ep.with_id(user_b_object), token=token_a)
        if r_a.status == 200 and contains_foreign_data(r_a, owner="B"):
            findings.append(("BOLA", ep, "cross-user read"))

        # (2) Unauthenticated access (Peloton)
        r_anon = request(ep, token=None)
        if r_anon.status == 200 and contains_pii(r_anon):
            findings.append(("BOLA-unauth", ep, "no-auth resource read"))

        # (3) Wildcard / mass-return (USPS)
        for wc in ["*", "%", "%25", "_", "[]", "all"]:
            r_wc = request(ep.set_param(id_param, wc), token=token_a)
            if is_bulk_response(r_wc):          # many records, not one
                findings.append(("BOLA-wildcard", ep, f"wildcard={wc}"))
    return findings
```
**Key signal**: response contains an object the *authenticated identity does not own*, OR a single-ID endpoint returns a collection when fed a wildcard.

---

## 2. Broken Authentication & Session Management

### Verified Case — Optus (Sep 2022)
- **What**: ~9.8M current+former customers. Names, DOB, phone, email, addresses; ~2.1M had driver-license/passport/Medicare numbers.
- **Root cause chain**:
  1. **Unauthenticated public API** (`api.www.optus.com.au`-style customer endpoint) — no auth required at all.
  2. **Sequential identifiers**: `contactID` incremented by exactly 1 → attacker scripted enumeration of the entire DB.
  3. **Shadow/legacy domain**: a coding error from 2018 was patched on the main domain (2021) but **persisted on a redundant, internet-facing API domain** since 2017.
- **Source**: [UpGuard](https://www.upguard.com/blog/how-did-the-optus-data-breach-happen), [Wikipedia](https://en.wikipedia.org/wiki/2022_Optus_data_breach)

### Scanner Detection Logic
```python
def detect_broken_auth(endpoints):
    findings = []
    for ep in endpoints:
        # (1) No-auth reachability of sensitive endpoints
        if request(ep, token=None).status < 400 and is_sensitive(ep):
            findings.append(("NO_AUTH", ep))

        # (2) Sequential/predictable ID enumeration (Optus)
        ids = harvest_ids(ep)                 # e.g. contactID=5567
        if is_monotonic(ids):                 # +1 pattern
            findings.append(("SEQUENTIAL_ID_ENUM", ep))

        # (3) Invalid/expired token still accepted
        if request(ep, token="Bearer INVALID.eyJ.x").status < 400:
            findings.append(("WEAK_TOKEN_VALIDATION", ep))

        # (4) Shadow-domain check — same path on api./legacy./v1. hosts
        for shadow in shadow_variants(ep.host):   # api2., legacy., internal.
            if request(ep.on_host(shadow), token=None).status < 400:
                findings.append(("SHADOW_API_UNAUTH", shadow))
    return findings
```
**Cross-ref taxonomy**: *Version Downgrading/Hopping* and *Finding Shadow & Undocumented APIs* — the Optus redundant domain is exactly a shadow-API failure.

---

## 3. Broken Object Property Level Authorization (Mass Assignment / Excessive Data Exposure)

### Verified Case — GitHub / Egor Homakov (Mar 2012)
- **What**: Added a hidden field `public_key[user_id]=4223` (the rails org ID) to the SSH-key form. Rails' `update_attributes(params[:public_key])` blindly bound it → Homakov's key attached to the **rails/rails** org → commit access.
- **Root cause**: No attribute whitelist (`attr_accessible` / strong params). Fixed on GitHub in **1 hour**, in Rails in **5 hours**. Became the canonical mass-assignment lesson.
- **Source**: [The Hacker News](https://thehackernews.com/2012/03/github-hacked-with-ruby-on-rails-public.html), [Homakov's writeup](http://homakov.blogspot.com/2012/03/how-to.html)

### Scanner Detection Logic (Schema-Mirroring, per taxonomy)
```python
INJECT_FIELDS = {
    "role":"admin", "is_admin":True, "isAdmin":True, "admin":True,
    "user_id":1, "owner_id":1, "account_id":1,          # Homakov-style
    "verified":True, "is_verified":True, "email_verified":True,
    "balance":999999, "credit":999999, "price":0, "status":"approved",
    "permissions":["*"], "plan":"premium", "tenant_id":"victim-org",
}

def detect_mass_assignment(write_endpoints):
    findings = []
    for ep in write_endpoints:          # POST/PUT/PATCH
        # SCHEMA MIRRORING: learn fields the GET response exposes,
        # then reflect them back into the write body (taxonomy: BPOA).
        exposed = keys_of(request("GET", ep.read_view()).json)
        candidates = set(INJECT_FIELDS) | (exposed - baseline_writable(ep))

        for field in candidates:
            body = baseline_body(ep) | {field: INJECT_FIELDS.get(field, "x")}
            r = request(ep.method, ep, json=body)
            if privilege_changed(r, field):      # re-read + verify persisted
                findings.append(("MASS_ASSIGNMENT", ep, field))
    return findings
```
**Excessive Data Exposure companion**: diff admin-vs-user responses for the same object; flag fields present only for higher privilege, and scan every response body for `password|secret|token|ssn|card|internal_id`.

---

## 4. Server-Side Request Forgery (SSRF)

### Verified Case — Capital One (2019) — the definitive API-SSRF breach
- **Chain** (all verified):
  1. **Misconfigured ModSecurity WAF** on an EC2 instance was SSRF-able.
  2. Attacker (Paige Thompson, ex-AWS) forced the app to call the **link-local metadata service**: `http://169.254.169.254/latest/meta-data/iam/security-credentials/` → returned the **IAM role name**, then the temporary **AccessKey/SecretKey/Token**.
  3. **Over-privileged IAM role** could `ListBuckets`/`GetObject` → **700+ S3 buckets**.
  4. Exfiltrated **106M records** (100M US + 6M Canada): names, DOB, SSNs, bank account numbers, credit scores.
- **Detection lag**: exfil on **Mar 22–23, 2019**; discovered **Jul 19, 2019** via external tip. IMDSv1 (no token requirement) was the enabler; IMDSv2 mitigates.
- **Source**: [KrebsOnSecurity](https://krebsonsecurity.com/2019/08/what-we-can-learn-from-the-capital-one-hack/), [Appsecco](https://blog.appsecco.com/an-ssrf-privileged-aws-keys-and-the-capital-one-breach-4c3c2cded3af)

### Scanner Detection Logic
```python
SSRF_TARGETS = [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",  # AWS IMDSv1
    "http://169.254.169.254/latest/api/token",                            # IMDSv2 probe
    "http://metadata.google.internal/computeMetadata/v1/",                # GCP
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",    # Azure
    "http://100.100.100.200/latest/meta-data/",                           # Alibaba
    "http://127.0.0.1/", "http://[::1]/", "http://localhost/",
    "gopher://127.0.0.1:6379/_INFO",                                      # internal Redis
]
def detect_ssrf(url_accepting_params):
    findings = []
    for ep, param in url_accepting_params:    # url,uri,callback,webhook,image,fetch...
        oob = new_collaborator_domain()       # OOB canary for blind SSRF
        for payload in SSRF_TARGETS + [f"http://{oob}/"]:
            r = request(ep.set_param(param, payload))
            if metadata_leaked(r) or oob_hit(oob):
                findings.append(("SSRF", ep, param, payload))
    return findings
```
**Also test**: IMDSv2 enforcement (does the app forward `X-aws-ec2-metadata-token`?), DNS-rebinding, and redirect-based bypass (`http://allowed.com@169.254.169.254`).

---

## 5. Recon, Shadow APIs & Version Hopping

### Real-world anchor — Optus redundant domain (see §2) + curated corpus
The corpus ([extracted_urls.txt](extracted_urls.txt)) contains dozens of shadow/undocumented-API writeups (e.g. lines 957 "unused API endpoint", 1049 "hidden API endpoints in IDOR", 305 "WSDL endpoint discovery", 214 "Swagger API"). Version hopping recurs (line 856 "API versioning → stored XSS bypassing CSP").

### Scanner Detection Logic
```python
def recon_shadow_and_versions(ctx):
    # (1) Version hopping — try older versions of every discovered path
    for ep in ctx.endpoints:
        for v in ["v1","v2","v3","beta","internal","legacy","old","mobile"]:
            alt = swap_version_segment(ep, v)
            r = request(alt)
            if r.status < 400 and lacks_controls(r, baseline=ep):
                report("VERSION_HOP", alt)     # legacy code missing checks

    # (2) Shadow endpoints from JS bundles + specs + GraphQL introspection
    resources = (extract_from_js_bundles(ctx)
                 | extract_from_openapi(ctx)
                 | graphql_introspect(ctx))
    for r in resources: enqueue_probe(r)

    # (3) Content-Type switching + HTTP method override (taxonomy)
    for ep in blocked_methods(ctx):
        for hdr in [{"X-HTTP-Method-Override":"PUT"},
                    {"X-HTTP-Method-Override":"DELETE"}]:
            if request(ep, method="POST", headers=hdr).status < 400:
                report("METHOD_OVERRIDE_BYPASS", ep, hdr)
```

---

## 6. Broken Account Enumeration & Privacy-Setting Bypass

### Verified Case — Twitter API (2022)
- **What**: A bug (introduced Jun 2021, patched Jan 2022) let **anyone, unauthenticated**, submit a phone number or email and receive the associated Twitter **user ID** — *even if the user disabled "let others find me"* in privacy settings. Chained with public data → **5.4M profiles** compiled, sold ~$30k, later leaked free.
- **Bounty**: researcher paid **$5,040**.
- **Source**: [BleepingComputer](https://www.bleepingcomputer.com/news/security/twitter-confirms-zero-day-used-to-expose-data-of-54-million-accounts/), [TechCrunch](https://techcrunch.com/2022/08/05/twitter-zero-day-vulnerability-millions/)

### Scanner Detection Logic
```python
def detect_enumeration(auth_endpoints):
    # Registration/login/forgot-password/identity-lookup oracles
    known   = request(lookup_ep, {"email":"known@target.com"})
    unknown = request(lookup_ep, {"email":"noexist_9f2@target.com"})
    if differs(known, unknown, on=("status","length","timing","message")):
        report("USER_ENUMERATION", lookup_ep)
    # Privacy-setting bypass (Twitter): does the API honor the user's
    # discoverability flag? Compare API result vs UI-visible state.
```
**Signals**: differential status/length/latency/error text between known vs unknown identifiers; API returning data the UI hides.

---

## 7. Edge & Caching Layer Anomalies

### Verified Case A — Web Cache Deception, PayPal (Omer Gil, BlackHat 2017)
- **Mechanic**: Request `https://paypal.com/myaccount/settings/x.css`. Origin ignores the extra path segment and serves the **authenticated** `settings` page; the CDN sees `.css` and **caches it as a public static file** for ~5 hours. Attacker then fetches the cached copy → victim's PII/CSRF tokens/session data.
- **Surface**: 40+ static extensions accepted (`.css .js .jpg .ico .txt …`).
- **Source**: [Omer Gil whitepaper](https://blackhat.com/docs/us-17/wednesday/us-17-Gil-Web-Cache-Deception-Attack-wp.pdf)

### Verified Case B — HTTP Request Smuggling, Amazon (James Kettle, 2019)
- **Mechanic**: Front-end and back-end disagree on `Content-Length` vs `Transfer-Encoding` (CL.TE / TE.CL / TE.TE). Amazon's `/b/` browse endpoint ignored `Content-Length`; Kettle captured **live users' full requests including auth tokens** into his own shopping list. HTTP/2 downgrade variants (H2.CL/H2.TE) still paid **$350k+** in 2025 across Akamai/Cloudflare/Netlify.
- **Source**: [PortSwigger Research — HTTP Desync Attacks](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)

### Scanner Detection Logic
```python
def detect_web_cache_deception(authed_pages):
    for page in authed_pages:                     # pages returning user PII
        for ext in [".css",".js",".jpg",".png",".ico",".txt",".svg"]:
            u = page.rstrip("/") + "/wcd_probe" + ext
            r1 = request(u, token=victim_token)   # authed → PII served
            r2 = request(u, token=None)           # anon → is it cached?
            if contains_pii(r2) and cache_hit(r2.headers):
                report("WEB_CACHE_DECEPTION", u, ext)

def detect_request_smuggling(host):
    # Timing-based CL.TE / TE.CL differential (safe, non-destructive)
    for variant in ["CL.TE","TE.CL","TE.TE","H2.CL"]:
        if desync_timing_anomaly(host, variant):
            report("REQUEST_SMUGGLING", host, variant)
```
**Cache headers to inspect**: `X-Cache: HIT`, `CF-Cache-Status: HIT`, `Age:`, `Cache-Control: public`.

---

## 8. State & Session Management — JWT & CORS

### Verified Case — JWT Algorithm Confusion (ongoing, fresh CVEs 2026)
- **Two live 2026 CVEs**: **Hono** JWT middleware `<4.11.4` (CVSS 8.2) and **HarbourJwt** — both **trusted the `alg` header** to pick the verification path.
- **RS256→HS256 attack**: server publishes RSA public key (JWKS/TLS cert). Attacker sets `"alg":"HS256"` and HMAC-signs the forged token **using the public key as the shared secret**. Vulnerable server verifies with HMAC path → **valid forgery for any user**.
- **`alg:none`**: original 2015 bypass — still reappears.
- **Source**: [PortSwigger Academy — Algorithm Confusion](https://portswigger.net/web-security/jwt/algorithm-confusion)

### Scanner Detection Logic
```python
def detect_jwt_flaws(token, endpoint):
    hdr, claims = decode_jwt(token)
    # (1) alg:none
    if accepts(endpoint, jwt_with_alg_none(claims)): report("JWT_ALG_NONE")
    # (2) RS256 -> HS256 confusion using discovered public key
    pub = fetch_jwks_or_cert(endpoint)
    forged = sign_hs256(claims_as_admin(claims), key=pub)
    if accepts(endpoint, forged): report("JWT_ALG_CONFUSION")
    # (3) Weak HMAC secret
    for secret in JWT_WEAK_SECRETS:
        if verifies(token, secret): report("JWT_WEAK_SECRET", secret)
    # (4) Claim checks: exp/nbf ignored, tenant_id swappable
    if accepts(endpoint, tamper_claim(claims, "exp", past())):
        report("JWT_NO_EXP_CHECK")
    if accepts(endpoint, tamper_claim(claims, "tenant_id", "victim-org")):
        report("JWT_TENANT_SWAP")   # → multitenancy leak, §11
```
**CORS companion**: reflect arbitrary `Origin`; if response echoes it with `Access-Control-Allow-Credentials: true`, cross-origin theft is possible.

---

## 9. Business Logic & Race Conditions

### Verified pattern — TOCTOU + Single-Packet Attack (PortSwigger, 2023)
- **Mechanic**: Between *check* (coupon unused / balance sufficient) and *act* (mark used / debit), fire N concurrent requests. **HTTP/2 single-packet attack** puts many requests in one TCP packet → sub-millisecond arrival, eliminating network jitter and maximizing the race window (Burp Turbo Intruder).
- **Real payouts**: gift-card/coupon reuse, double-spend, and **race-condition auth-bypass → full ATO** are recurring high-severity bug-bounty findings.
- **Source**: [YesWeHack race-condition guide](https://www.yeswehack.com/learn-bug-bounty/ultimate-guide-race-condition-vulnerabilities), [APIsec](https://www.apisec.ai/blog/race-condition-vulnerabilities-in-apis)

### Scanner Detection Logic
```python
def detect_race_condition(state_changing_eps):
    for ep in state_changing_eps:      # redeem, transfer, apply-coupon, vote
        baseline = get_state()
        # Single-packet style burst — 20-50 parallel identical requests
        results = fire_parallel(ep, n=30, same_tcp_packet=True)
        successes = [r for r in results if r.ok]
        if len(successes) > expected_max(ep):   # e.g. coupon used >1x
            report("RACE_CONDITION", ep, len(successes))
```
**Also (taxonomy)**: *Step Bypassing* — call a late-stage endpoint (e.g. `/checkout/confirm`) directly without prerequisites; *User Context Switching* — User A token + User B object id; read-only key on a write endpoint; *State-Machine Invalidation* — reuse an `Idempotency-Key` across different transactions.

---

## 10. API Key & Secret Theft

### Verified Case — 3Commas → FTX/Binance/Coinbase (2022)
- **What**: Phishing sites cloned the 3Commas UI, captured users' **exchange API keys**, then placed unauthorized trades (pump-and-dump on illiquid pairs like DMG). **44 verified victims, $14.8M** total; one user lost $1.6M across 5,000+ forced trades. 3Commas later confirmed the leaked key files were genuine.
- **Root cause on the API side**: keys had **trading permission without IP allowlisting or withdrawal restriction**, so a stolen key = full trading control.
- **Source**: [CoinDesk](https://www.coindesk.com/tech/2022/11/23/alameda-backed-crypto-trading-firm-3commas-says-its-pretty-sure-it-wasnt-breached), [Crypto Times](https://www.cryptotimes.io/2022/12/29/3commas-confirms-the-api-key-leak-after-denying-their-involvement/)

### Corpus scale
Secret-leak writeups dominate the curated corpus — Google Maps keys (lines 320, 372, 837, 1074), Firebase (488, 870), Stripe (1022), Twitter keys in 3,200+ Android apps (538), Postman workspaces leaking 30k keys (1168). This is the **single most common real-world API finding**.

### Scanner Detection Logic
```python
def detect_secret_leakage(responses, js_bundles):
    for blob in responses + js_bundles + source_maps():
        for name, rx in SECRET_PATTERNS:      # AWS AKIA, AIza, sk_live_, gh[pousr]_, JWT...
            for m in rx.finditer(blob):
                # Validate liveness where safe (e.g. Google Maps key → Staticmap probe)
                report("SECRET_LEAK", name, m.group(), live=validate(name, m.group()))
```
**Sources to scan**: JS bundles + `.map` source maps, error bodies, `/.env` `/.git/config`, mobile APK strings, GitHub, Postman public workspaces.

---

## 11. Multitenancy, Microservice Bypass & Advanced Parser Exploits

### Anchors
- **Tenant cross-pollination**: swap `X-Tenant-ID` / `tenant_id` JWT claim while acting on an object → cross-tenant leak (directly chains from JWT tamper, §8).
- **Internal header spoofing**: strip the edge token and inject `X-User-Id` / `X-Internal-Auth` straight at a microservice that trusts gateway-set headers.
- **Path-normalization**: `..%2f`, `;/`, `/./`, double-encoding to bypass the API gateway's routing/authz before the origin re-normalizes.
- **Parser differentials**: duplicate JSON keys interpreted differently by Go (last wins) vs Python (last) vs others; oversized ints causing overflow/type confusion. These map to the corpus's parser/interop writeups.

### Scanner Detection Logic
```python
def detect_tenant_and_gateway_bypass(ep, token):
    # Cross-tenant
    for h in [{"X-Tenant-ID":"victim"}, {"X-Org-Id":"victim"}]:
        if returns_foreign_tenant(request(ep, token=token, headers=h)):
            report("CROSS_TENANT_LEAK", ep, h)
    # Internal identity spoof (skip gateway)
    for h in [{"X-User-Id":"1"}, {"X-Internal-Auth":"true"},
              {"X-Forwarded-User":"admin"}]:
        if request(ep, token=None, headers=h).status < 400:
            report("INTERNAL_HEADER_SPOOF", ep, h)
    # Path normalization gateway bypass
    for p in ["/admin/..%2fadmin", "/%2e/admin", "/admin;/", "/admin/./"]:
        if request(ep.host + p, token=token).status < 400:
            report("PATH_NORMALIZATION_BYPASS", p)
    # JSON duplicate-key differential
    raw = '{"role":"user","role":"admin"}'
    if privilege_granted(request(ep, raw_body=raw, ctype="application/json")):
        report("JSON_DUPLICATE_KEY_DIFF", ep)
```

---

## 12. Protocol Mechanics — GraphQL, gRPC, WebSocket, Webhooks

### GraphQL (corpus: lines 226, 442, 728, 847, 1063, 911)
```python
def audit_graphql(gql_ep):
    if introspection_enabled(gql_ep):  report("GRAPHQL_INTROSPECTION", gql_ep)
    if depth_unbounded(gql_ep):        report("GRAPHQL_DEPTH_DoS", gql_ep)   # nested cycles
    if batching_allowed(gql_ep):       report("GRAPHQL_BATCH_BRUTE", gql_ep) # alias/array multiplex
    # IDOR still applies to node(id:) resolvers — corpus lines 442,453,455
```

### WebSocket / CSWSH
```python
def audit_websocket(ws_ep):
    # Cross-Site WebSocket Hijacking: is Origin validated at handshake AND
    # is authorization re-checked on each message post-connection?
    if handshake_accepts_foreign_origin(ws_ep):
        report("CSWSH", ws_ep)
    if not authz_revalidated_per_message(ws_ep):
        report("WS_POSTCONNECT_AUTHZ", ws_ep)
```

### Webhooks
```python
def audit_webhook_receiver(hook_ep):
    if accepts_unsigned_payload(hook_ep):        report("WEBHOOK_NO_HMAC", hook_ep)
    if not timestamp_validated(hook_ep):         report("WEBHOOK_REPLAY", hook_ep)
    # Async task status endpoints — /api/tasks/{id} authorization (taxonomy)
    if request(f"/api/tasks/{other_task_id}", token=low_priv).status == 200:
        report("ASYNC_TASK_BOLA", hook_ep)
```

---

## 13. Agentic AI & MCP Security (Emerging — 2025/2026)

### Verified Case — MCP Tool Poisoning (CVE-2025-54136 "MCPoison", CVE-2025-54135)
- **Mechanic**: MCP clients accept **server-provided tool metadata** (descriptions/params) with no validation. Malicious instructions embedded in tool descriptions = **indirect prompt injection**. The **"Rug Pull: Silent Redefinition"** — an approved, safe-looking tool **mutates its own definition after install** to reroute actions (e.g., exfiltrate API keys). Closer to a **supply-chain attack on the agent's context** than user-side jailbreaking. NSA/CISA published MCP security guidance.
- **Evidence**: 5 of 7 evaluated MCP clients did no static validation (Nov 2025 study).
- **Source**: [Simon Willison](https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/), [arXiv threat model](https://arxiv.org/pdf/2603.22489), [NSA CSI](https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf)

### Scanner Detection Logic
```python
def audit_mcp_and_agentic(mcp_server, agent_api):
    # (1) Tool metadata integrity — hash tool defs, detect post-approval mutation
    baseline = hash_tool_definitions(mcp_server)
    if hash_tool_definitions(mcp_server) != baseline:
        report("MCP_RUG_PULL", mcp_server)          # silent redefinition
    # (2) Injection markers in tool descriptions/params
    for tool in list_tools(mcp_server):
        if injection_markers(tool.description):      # "ignore previous", hidden unicode
            report("MCP_TOOL_POISONING", tool.name)
    # (3) Capability guardrails — does the server over-expose tools/scopes?
    if exposes_unscoped_capabilities(mcp_server):
        report("MCP_OVER_EXPOSURE", mcp_server)
    # (4) Agent processes untrusted API data as instructions
    if agent_acts_on_injected_api_content(agent_api):
        report("AGENTIC_PROMPT_INJECTION", agent_api)
```

---

## 14. Defense-Side Controls the Scanner Should *Verify Are Present*

Derived from the taxonomy's governance/identity/zero-trust rows — the scanner should flag their **absence**:

| Control | What to verify | Taxonomy row |
|---|---|---|
| **Strict schema validation** | `additionalProperties:false` at edge → blocks mass assignment (§3) | Governance |
| **Sender-constrained tokens** | mTLS binding (RFC 8705) / DPoP (RFC 9449) → stops stolen-token replay (§10) | Sender-Constrained |
| **Token exchange (RFC 8693)** | Edge token ≠ internal token; short-lived scoped downstream | Identity Propagation |
| **Workload identity (SPIFFE/SPIRE)** | mTLS X.509 svc-to-svc → blocks internal header spoof (§11) | Cryptographic Attestation |
| **Policy-as-code (OPA/Cedar)** | Centralized authz decisions, not per-service ad-hoc | Policy-as-Code |
| **Cost-based throttling** | Throttle by backend compute cost, not raw count | Behavioral Observability |
| **IMDSv2 enforced** | Metadata requires session token → blocks Capital One SSRF (§4) | (Cloud hardening) |
| **Fuzzing in CI/CD** | RESTler / Schemathesis property-based tests | Contract Enforcement |

---

## 15. Prioritized Scanner Build Order (evidence-weighted)

Ranked by **real-world frequency × impact** from the research + corpus:

1. **Secret/API-key leakage** — most common finding in the corpus; 3Commas shows direct financial impact.
2. **BOLA/IDOR + wildcard + cross-user** — USPS/Peloton; OWASP API #1.
3. **Broken auth / unauth shadow APIs / sequential IDs** — Optus.
4. **Mass assignment (schema mirroring)** — GitHub/Homakov.
5. **SSRF → cloud metadata** — Capital One; test IMDSv2.
6. **JWT alg confusion + weak secret + claim tampering** — fresh 2026 CVEs.
7. **Rate-limit / race conditions** — single-packet attack.
8. **Excessive data exposure** — differential response analysis.
9. **Web cache deception + request smuggling** — high skill, high impact.
10. **GraphQL/WebSocket/webhook** protocol audits.
11. **Multitenancy + gateway/parser bypass** — advanced.
12. **Agentic/MCP** — emerging, forward-looking.

---

## Consolidated Sources

- Capital One: [Krebs](https://krebsonsecurity.com/2019/08/what-we-can-learn-from-the-capital-one-hack/) · [Appsecco](https://blog.appsecco.com/an-ssrf-privileged-aws-keys-and-the-capital-one-breach-4c3c2cded3af)
- USPS: [Krebs](https://krebsonsecurity.com/2018/11/usps-site-exposed-data-on-60-million-users/) · [Salt](https://salt.security/blog/lessons-learned-usps-api-vulnerability-and-60-million-exposed-users)
- Optus: [UpGuard](https://www.upguard.com/blog/how-did-the-optus-data-breach-happen) · [Wikipedia](https://en.wikipedia.org/wiki/2022_Optus_data_breach)
- GitHub/Homakov: [The Hacker News](https://thehackernews.com/2012/03/github-hacked-with-ruby-on-rails-public.html) · [Homakov](http://homakov.blogspot.com/2012/03/how-to.html)
- Peloton: [Pen Test Partners](https://www.pentestpartners.com/security-blog/tour-de-peloton-exposed-user-data/) · [TechCrunch](https://techcrunch.com/2021/05/05/peloton-bug-account-data-leak/)
- Twitter: [BleepingComputer](https://www.bleepingcomputer.com/news/security/twitter-confirms-zero-day-used-to-expose-data-of-54-million-accounts/) · [TechCrunch](https://techcrunch.com/2022/08/05/twitter-zero-day-vulnerability-millions/)
- Web Cache Deception: [Omer Gil whitepaper](https://blackhat.com/docs/us-17/wednesday/us-17-Gil-Web-Cache-Deception-Attack-wp.pdf)
- Request Smuggling: [PortSwigger Research](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
- JWT confusion: [PortSwigger Academy](https://portswigger.net/web-security/jwt/algorithm-confusion)
- Race conditions: [YesWeHack](https://www.yeswehack.com/learn-bug-bounty/ultimate-guide-race-condition-vulnerabilities) · [APIsec](https://www.apisec.ai/blog/race-condition-vulnerabilities-in-apis)
- 3Commas: [CoinDesk](https://www.coindesk.com/tech/2022/11/23/alameda-backed-crypto-trading-firm-3commas-says-its-pretty-sure-it-wasnt-breached) · [Crypto Times](https://www.cryptotimes.io/2022/12/29/3commas-confirms-the-api-key-leak-after-denying-their-involvement/)
- MCP: [Simon Willison](https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/) · [arXiv](https://arxiv.org/pdf/2603.22489) · [NSA CSI](https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf)

---

**Next step**: fold each §Scanner Detection Logic block into APIHarvester as a discrete attack module, gated behind `--attacks` flags, reusing the existing `ScanContext` two-identity model (`ctx.auth` / `ctx.auth2`) that the BOLA/BFLA modules already rely on.
