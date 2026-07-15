# apiharvester

A full-pipeline black-box API security scanner written in Python. It enumerates endpoints, identifies parameters, probes HTTP methods, tests authentication/authorization logic, and runs standard OWASP API Top 10 attack simulations (BOLA, Broken Auth, BFLA, Mass Assignment, Rate Limiting, SSRF, Security Misconfiguration, etc.).

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

### Options:
* `target` (positional): FQDN domain to scan.
* `--auth`: High-privilege access token for authenticated checks.
* `--auth2`: Low-privilege access token for BOLA / BFLA privilege-escalation testing.
* `--threads`: Threadpool size (default: 20).
* `--timeout`: HTTP request timeout in seconds.
* `--burst`: Request count limit for rate-limiting verification.
* `--json`: Save JSONL format report.
* `--html`: Save interactive HTML dashboard report.

---

## Payload Files

apiharvester uses high-quality wordlists and route schemas from SecLists and Kiterunner for comprehensive API discovery and testing:

* **params.txt** (25,889 entries) — Common API parameter names (e.g., `api_key`, `user_id`, `token`). Used during parameter discovery phase to identify potential input points.

* **directories.txt** (62,281 entries) — API endpoint paths and directory patterns (e.g., `/api/v1/`, `/admin/`, `/internal/`). Used for path enumeration and Soft-404 detection.

* **subdomains.txt** (5,000 entries) — Subdomain prefixes and variants (e.g., `api`, `api-v2`, `staging-api`). Used for identifying additional API surface across subdomains.

* **kiterunner/** — Kiterunner-format OpenAPI route schemas for rapid route discovery and validation. Enables accelerated endpoint mapping when external schemas are available.

These payloads are sourced from SecLists (https://github.com/danielmiessler/SecLists) and enable apiharvester to efficiently identify hidden or undocumented API endpoints, parameters, and services.
