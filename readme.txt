================================================================================
apiharvester - Full-Pipeline API Security Scanner
================================================================================

OVERVIEW
--------
apiharvester is a comprehensive black-box API security scanner written in Python.
It enumerates endpoints, identifies parameters, probes HTTP methods, tests
authentication/authorization logic, and runs standard OWASP API Top 10 attack
simulations (BOLA, Broken Auth, BFLA, Mass Assignment, Rate Limiting, SSRF,
Security Misconfiguration, etc.).

All core scripts are designed to be stdlib-only (standard library only). If
external tools are not available, apiharvester automatically falls back to
pure-Python implementations.


QUICK START
-----------
1. Check requirements:
   ./scripts/check_requirements.sh

2. Install optional tools and payloads:
   ./scripts/install_requirements.sh

3. Install Python dependencies:
   pip3 install -r requirements.txt

4. Run the scanner:
   python3 -m apiharvester example.com \
       --auth "Bearer eyJ..." \
       --threads 20 \
       --html report.html


COMMAND-LINE OPTIONS
--------------------
target                  FQDN domain to scan (positional argument)
--auth TEXT            High-privilege access token for authenticated checks
--auth2 TEXT           Low-privilege access token for BOLA/BFLA testing
--threads INT          Threadpool size (default: 20)
--timeout INT          HTTP request timeout in seconds
--burst INT            Request count limit for rate-limiting verification
--json FILE            Save JSONL format report
--html FILE            Save interactive HTML dashboard report
--version              Display version information


PAYLOAD FILES
=============

apiharvester uses multiple high-quality wordlists and route schemas for
comprehensive API discovery and security testing. All payloads are located
in the payloads/ directory.

1. params.txt (25,889 entries)
   ----
   Common API parameter names extracted from real-world APIs and industry
   standards. Includes:
   - Standard API parameters: api_key, token, auth, session
   - User-related: user_id, user_name, email, password
   - Query parameters: limit, offset, filter, sort, search
   - API-specific: subscription_id, api_version, client_id

   Usage: Parameter discovery phase to identify potential input points and
   injection surfaces

2. directories.txt (62,281 entries)
   ----
   Common API endpoint paths, directory structures, and route patterns. Includes:
   - Base paths: /api/, /api/v1/, /api/v2/, /rest/
   - Resource patterns: /users/, /admin/, /internal/, /debug/
   - Common endpoints: /auth/, /login/, /config/, /status/
   - Vendor-specific paths: /oauth/, /graphql/, /webhooks/

   Usage: Endpoint path enumeration, Soft-404 detection, and route mapping

3. subdomains.txt (5,000 entries)
   ----
   Subdomain prefixes and variants for API surface discovery:
   - Generic API subdomains: api, api-v1, api-v2, apidev
   - Environment variants: staging-api, test-api, prod-api
   - Regional variants: api-eu, api-us, api-asia
   - Service-specific: admin-api, internal-api, public-api

   Usage: Identifying additional API endpoints across organization subdomains

4. kiterunner/ (directory)
   ----
   OpenAPI and Swagger route schemas in Kiterunner format. Enables rapid
   endpoint discovery when OpenAPI specifications are available.

   Usage: Accelerated route enumeration and schema validation


PAYLOAD STATISTICS
------------------
Total wordlist entries: 93,170
  - Parameters: 25,889 unique names
  - Directories: 62,281 unique paths
  - Subdomains: 5,000 unique variants

Source: SecLists (https://github.com/danielmiessler/SecLists)
Industry-standard for API and web application security testing

RECOMMENDATION
--------------
For best results, keep payloads regularly updated by running:
  ./scripts/install_requirements.sh

This ensures apiharvester uses the latest community-maintained wordlists and
API schemas for maximum coverage during security assessments.


SECURITY NOTICE
---------------
apiharvester is designed for authorized security testing and penetration
testing only. Unauthorized access to computer systems is illegal.
Only run against systems you own or have explicit written permission to test.


PROJECT STRUCTURE
-----------------
apiharvester/              Main package directory
scripts/                   Installation and verification scripts
payloads/                  Wordlist files and route schemas
api_deep_discovery.py      Dynamic SPA/XHR endpoint discovery
api_intelligence_engine.py Pipeline aggregator and vulnerability classifier
requirements.txt           Python package dependencies

================================================================================
