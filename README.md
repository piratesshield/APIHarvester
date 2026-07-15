<img width="1983" height="793" alt="ChatGPT Image Jul 15, 2026, 10_14_08 AM" src="https://github.com/user-attachments/assets/c8850fd3-d2e8-43f5-b7e3-f0562ec9c49b" />

# ApiHarvester

A full-pipeline black-box API security scanner written in Python. It enumerates endpoints, identifies parameters, probes HTTP methods, tests authentication/authorization logic, and runs standard OWASP API Top 10 attack simulations (BOLA, Broken Auth, BFLA, Mass Assignment, Rate Limiting, SSRF, Security Misconfiguration, etc.), plus a RESTler-style reliability fuzzer that hunts crashes/500s independent of any OWASP category.

All core scripts are designed to be **stdlib-only (standard library only)**. If external tools or libraries are not present on the system, `apiharvester` automatically falls back to pure-Python implementations to guarantee out-of-the-box execution.

---

## Repository Structure

* `apiharvester/` — The main python package directory. Run as `python3 -m apiharvester`.
* `scripts/check_requirements.sh` — Verifies binary + payload prerequisites.
* `scripts/install_requirements.sh` — Downloads required SecLists payload files and optionally installs binaries (via `go install` and `pip`).
* `apiharvester.py` — A standalone, single-file distribution of the scanner.
* `api_deep_discovery.py` — Dynamic crawler using Katana headless browser code for dynamic SPA/XHR endpoints discovery.
* `api_intelligence_engine.py` — Pipeline aggregator and passive vulnerability classifier.
* `apisec.py` — Alternate single-file security scanner version.
* `requirements.txt` — Python dependencies list (primarily for optional Python-based accelerators).
* `payloads/` — Wordlist and payload files for reconnaissance:
  - `params.txt` — 25,889 parameter name candidates for API endpoint testing
  - `directories.txt` — 62,281 common API path patterns and directory names
  - `subdomains.txt` — 5,000 subdomain variants for API discovery
  - `kiterunner/` — Kiterunner route schema files for accelerated endpoint enumeration

---

## Installation & Setup

1. **Verify Requirements:**
   Run the read-only script to check if core tools/payloads are available:
   ```bash
   ./scripts/check_requirements.sh
   ```

2. **Install Optional Tools & Payload Files:**
   Run the install script to automatically fetch SecLists top wordlists, Kiterunner route schemas, and install tool accelerators:
   ```bash
   ./scripts/install_requirements.sh
   ```

3. **Install Python Packages:**
   ```bash
   pip3 install -r requirements.txt
   ```

---

## Usage

Run the scanner directly against a target domain:
```bash
python3 -m apiharvester example.com \
    --auth "Bearer eyJ..." \
    --auth2 "Bearer eyJ_lowpriv..." \
    --threads 20 \
    --html report.html \
    --json findings.jsonl
```

### Command-line Options:
* `target` (positional): FQDN domain to scan.
* `--auth`: High-privilege access token for authenticated checks (e.g., valid user session).
* `--auth2`: Low-privilege access token for BOLA / BFLA / cross-account privilege-escalation testing.
* `--threads`: Threadpool size (default: 20).
* `--timeout`: HTTP request timeout in seconds (default: 10).
* `--burst`: Rapid request count for rate-limiting verification (default: 20).
* `--json`: Save JSONL format report (line-delimited JSON findings).
* `--html`: Save interactive HTML dashboard report.
* `--output-dir`: Override default output directory path (e.g., `./scans/example.com`).
* `--skip-recon`: Skip recon phases, use existing output files from a prior run.
* `--recon-dir`: Load pre-existing recon output directory and run only attack phases.
* `--attacks-only`: Run only attack phases (implies `--skip-recon`).
* `--attacks`: Comma-separated attack list to run. Default: all. Available:
  ```
  bola,broken_auth,mass_assignment,rate_limit,bfla,business_logic,
  ssrf,misconfiguration,inventory,sspp,injection,reliability,secrets
  ```

### Attack Modules

**OWASP API Top 10 (API1–API10:2023):**
- **API1: BOLA/IDOR** (`bola`) — Broken Object-Level Authorization. Tests object-ID endpoints with ID fuzzing (0, 1, 2, 99, "admin", "test", UUID variants, etc.) and differential auth tokens.
- **API2: Broken Auth** (`broken_auth`) — Unauthenticated endpoint discovery, JWT weak-secret cracking, alg=none bypass, claim tampering, kid injection, plus OPTIONS/HEAD method bypasses.
- **API3: Mass Assignment** (`mass_assignment`) — Privilege-escalation field injection into PUT/PATCH bodies (role, is_admin, verified, balance, etc.).
- **API4: Rate Limiting** (`rate_limit`) — Sends 20+ rapid requests; flags endpoints returning 200 instead of 429 Retry-After.
- **API5: BFLA** (`bfla`) — Broken Function-Level Authorization. Tests sensitive paths (/admin, /roles, /impersonate, etc.) with and without low-priv token.
- **API6: Business Logic** (`business_logic`) — Workflow/state-machine violations (e.g., updating an order after payment).
- **API7: SSRF** (`ssrf`) — Tests for server-side request forgery via URL parameters and request bodies.
- **API8: Misconfiguration** (`misconfiguration`) — CORS (active: sends untrusted Origin), missing security headers, verbose errors, server banner leaks.
- **API9: Inventory** (`inventory`) — Undocumented endpoints, abandoned endpoints, exposed admin interfaces.
- **API10: SSPP** (`sspp`) — Unsafe Server-Side Post Processing (template injection, XPath injection, etc.).

**Bonus Attacks:**
- **Injection** (`injection`) — SQL injection, XSS, command injection (error-based + time-based blind).
- **Reliability** (`reliability`) — RESTler-style fuzzing: boundary/malformed-input testing to find 5xx crashes and server reliability bugs (independent of OWASP categories).
- **Secrets** (`secrets`) — Pattern matching for leaked credentials in response bodies: AWS Access Keys, Google API Keys, Slack Tokens, Stripe Keys, GitHub Tokens, Private Key Blocks, JWTs, and generic secret assignments (api_key=..., password=..., etc.).

### Example Scans

**Full scan with authenticated + low-priv token (best for BOLA/BFLA):**
```bash
python3 -m apiharvester api.example.com \
    --auth "Bearer high_priv_token_here" \
    --auth2 "Bearer low_priv_token_here" \
    --html report.html \
    --json findings.jsonl
```

**Quick recon-only (discover endpoints, no attacks):**
```bash
python3 -m apiharvester example.com --skip-recon --attacks ""
```
(Or just don't provide `--auth` to skip some attack phases.)

**Re-run only attacks against saved recon data (fast iteration):**
```bash
python3 -m apiharvester example.com --recon-dir output/example.com_20260715_140233 --attacks-only
```

**Run only specific attacks (e.g., BOLA + Secrets):**
```bash
python3 -m apiharvester example.com --attacks bola,secrets
```

**Bypass TLS certificate errors (corporate proxy, staging environment):**
```bash
# apiharvester uses a permissive TLS context by default — no extra flags needed
# All HTTPS endpoints work even with self-signed/intercepted certs
python3 -m apiharvester https://staging-api.example.com
```

---

## Output Directory

Every scan writes its recon artifacts to a structured output directory before the attack phase runs. By default this is:

```
output/{target}_{YYYYMMDD_HHMMSS}/
```

e.g. `output/example.com_20260715_140233/`. Override the location with `--output-dir /path/to/dir` if you want a fixed, predictable path (useful for scripting/CI).

### Files written

| File | Contents |
|---|---|
| `fqdn.txt` | All discovered subdomains (one per line) |
| `fqdn_resolved.txt` | Subdomains with resolved IPs — `domain\tip1,ip2` |
| `fqdn_active.txt` | Live HTTP(S) hosts (full URLs) |
| `fqdnwithendpoint.txt` | All discovered endpoint URLs |
| `withparam.txt` | Endpoints with discovered query parameters, as full URLs |
| `paramvalue.txt` | Endpoints with observed parameter *values* (from live probing) |
| `withtoken.txt` | Auth tokens/JWTs supplied via `--auth`/`--auth2` plus any harvested from responses |
| `objectshape.txt` | Response JSON field names per endpoint — `url\tfield1,field2` |
| `waf_results.jsonl` | One JSON object per host with a detected WAF/catch-all/JS challenge |
| `endpoint_methods.jsonl` | One JSON object per endpoint listing allowed HTTP methods |
| `swagger_specs/*.json` | Any OpenAPI/Swagger specs discovered, one file per host |

Everything is plain text (one entry per line) or JSONL, so it greps, `jq`s, and pipes cleanly.

### Reusing an output directory

**Re-run only the attack phase against existing recon data**, skipping subdomain discovery/crawling/etc:
```bash
python3 -m apiharvester example.com --recon-dir output/example.com_20260715_140233 --attacks-only
```
`--attacks-only` implies `--skip-recon` and loads `fqdn_active.txt`, `fqdnwithendpoint.txt`, `withparam.txt`, `withtoken.txt`, `swagger_specs/`, and `waf_results.jsonl` back into the scan context.

**Feed the recon files into other tools:**
```bash
# httpx re-probe
httpx -l output/example.com_*/fqdn_active.txt

# nuclei against discovered endpoints
nuclei -l output/example.com_*/fqdnwithendpoint.txt

# ffuf using discovered params as a wordlist seed
cut -d'?' -f2 output/example.com_*/withparam.txt | tr '&' '\n' | cut -d= -f1 | sort -u

# jq over per-host WAF results
jq -r 'select(.waf_vendor != "none") | .domain' output/example.com_*/waf_results.jsonl
```

Because every file is line-delimited plain text or JSONL, the output directory doubles as a portable recon dataset you can hand to grep, jq, httpx, nuclei, ffuf, or any other tool in your pipeline — no apiharvester-specific parser required.

---

## Payload Files

apiharvester uses high-quality wordlists and route schemas from SecLists and Kiterunner for comprehensive API discovery and testing:

* **params.txt** (25,889 entries) — Common API parameter names (e.g., `api_key`, `user_id`, `token`). Used during parameter discovery phase to identify potential input points.

* **directories.txt** (62,281 entries) — API endpoint paths and directory patterns (e.g., `/api/v1/`, `/admin/`, `/internal/`). Used for path enumeration and Soft-404 detection.

* **subdomains.txt** (5,000 entries) — Subdomain prefixes and variants (e.g., `api`, `api-v2`, `staging-api`). Used for identifying additional API surface across subdomains.

* **kiterunner/** — Kiterunner-format OpenAPI route schemas for rapid route discovery and validation. Enables accelerated endpoint mapping when external schemas are available.

These payloads are sourced from SecLists (https://github.com/danielmiessler/SecLists) and enable apiharvester to efficiently identify hidden or undocumented API endpoints, parameters, and services.

---

## Improvements Over Prior Versions

### BOLA/IDOR Detection
**Before:** Only tried predictable ID swaps (ID±1, UUID last-segment flip). Missed real-world IDORs with weak IDs (1, 2, "admin", "test").  
**Now:** `_generate_id_candidates()` generates 5-13 ID variants per endpoint:
- Numeric: 0, 1, 2, 99, 100, ID±1
- UUID: last-segment variants (00000000, 11111111, ffffffff, 12345678)
- Hex/Mongo: common patterns
- String: "admin", "test", "guest", "user", "null"

### Broken Authentication
**Before:** Only tested GET without auth. Missed OPTIONS/HEAD method bypasses (common misconfiguration).  
**Now:** Also probes OPTIONS/HEAD on sensitive paths; many servers apply auth only to GET/POST.

### Secrets Detection
**Before:** No credential/API key detection in responses.  
**Now:** New `secrets` attack module (8 patterns):
- AWS Access Keys (AKIA pattern)
- Google API Keys (AIza pattern)
- Slack Tokens (xox pattern)
- Stripe Live Keys, GitHub Tokens, Private Key Blocks, JWTs, Generic secrets

### RESTler-Equivalent Reliability Fuzzing
**Before:** No crash/reliability testing.  
**Now:** New `reliability` attack module fuzzes with:
- Boundary query values: huge numbers, null bytes, oversized strings, path traversal
- Malformed JSON bodies: null, wrong top-level type, deeply nested, huge arrays
- Flags any 5xx response as a reliability bug (independent of OWASP categories)

---

## Performance & Tuning

| Metric | Default | Notes |
|--------|---------|-------|
| Threads | 20 | Increase for faster discovery (e.g., `--threads 50`). Decrease for noisy/rate-limited targets. |
| Timeout | 10s | Increase for slow/distant targets (`--timeout 30`). |
| Output | `output/{domain}_{timestamp}/` | All recon files are plain text/JSONL; portable to other tools. |
| Rate limit test | 20 requests | Adjust with `--burst 50` for more aggressive rate-limit detection. |
| Scope | Full domain | Limit to specific subdomain: `python3 -m apiharvester api.example.com` |

### Rough Timing (unoptimized cloud environment)
- Subdomain discovery: 10–30s (passive OSINT)
- HTTP probing + endpoint discovery: 2–10 min (depends on target size)
- Parameter discovery: 2–5 min (Arjun-style probing)
- All attacks: 5–15 min (depends on endpoint count + auth testing)
- **Total**: 15–60 minutes for a mid-size target

---

## Integration with Other Tools

apiharvester's output directory contains plain-text/JSONL files that feed directly into other scanners:

```bash
# Run apiharvester, then pass results to httpx (re-probe)
python3 -m apiharvester example.com --json findings.jsonl
httpx -l output/example.com_*/fqdnwithendpoint.txt -H "Authorization: Bearer $TOKEN"

# Feed discovered endpoints to Nuclei
nuclei -l output/example.com_*/fqdnwithendpoint.txt -t cves/ -t misconfiguration/

# Use param discovery as a seed for ffuf
cat output/example.com_*/withparam.txt | ffuf -u http://target/api/users/FUZZ -w -

# Export findings to SIEM/ticketing via JSONL
jq -r '.title, .severity, .evidence' output/example.com_*/findings.jsonl | xargs -I {} echo {} >> tickets.txt
```
