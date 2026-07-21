#!/usr/bin/env python3
"""
ARISE Module 20: API Deep Discovery
====================================
Headless browser interception + form/page classification + HTTP method enumeration.

Consumes: naabu output (open ports), httpx hosts, crawled URLs
Produces: classified injectable URLs for SQLi/XSS/SSRF modules

Strategy:
  1. Katana headless crawl → intercept XHR/Fetch/WebSocket API calls
  2. DOM parsing → detect login forms, search pages, admin panels, etc.
  3. HTTP method probing → OPTIONS/HEAD/POST/PUT/DELETE on API endpoints
  4. Output → injectable URLs classified by type, ready for attack modules
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


# ─── Page Classification Patterns ────────────────────────────────────────────

LOGIN_PATTERNS = [
    re.compile(r'(login|signin|sign-in|auth|authenticate|sso)', re.I),
    re.compile(r'(type=["\']password["\'])', re.I),
    re.compile(r'(name=["\'](?:username|email|user|login|passwd|password)["\'])', re.I),
]

SEARCH_PATTERNS = [
    re.compile(r'(type=["\']search["\'])', re.I),
    re.compile(r'(name=["\'](?:q|query|search|keyword|s|term|find)["\'])', re.I),
    re.compile(r'(action=["\'][^"\']*search[^"\']*["\'])', re.I),
    re.compile(r'(placeholder=["\'][^"\']*search[^"\']*["\'])', re.I),
]

REGISTRATION_PATTERNS = [
    re.compile(r'(register|signup|sign-up|create.?account|join)', re.I),
    re.compile(r'(name=["\'](?:confirm.?password|password_confirm|re.?password)["\'])', re.I),
]

PASSWORD_RESET_PATTERNS = [
    re.compile(r'(forgot.?password|reset.?password|recover|password.?recovery)', re.I),
]

PROFILE_UPDATE_PATTERNS = [
    re.compile(r'(profile|account.?settings|update.?profile|edit.?profile|my.?account)', re.I),
    re.compile(r'(name=["\'](?:bio|avatar|display.?name|phone|address)["\'])', re.I),
]

ADMIN_PATTERNS = [
    re.compile(r'/admin[/\?]|/dashboard|/manage|/cms|/panel|/backend|/cp/', re.I),
    re.compile(r'/wp-admin|/administrator|/phpmyadmin|/adminer', re.I),
]

FILE_DOWNLOAD_PATTERNS = [
    re.compile(r'(download|export|attachment|file|document)', re.I),
    re.compile(r'\.(pdf|csv|xlsx|docx|zip|tar|gz)(\?|$)', re.I),
    re.compile(r'[?&](file|path|doc|name|id|attachment)=', re.I),
]

FILTER_ANALYTICS_PATTERNS = [
    re.compile(r'[?&](date|from|to|start|end|filter|sort|order|group.?by|metric|period|range)=', re.I),
    re.compile(r'(report|analytics|statistics|chart|graph|dashboard)', re.I),
]

API_ENDPOINT_PATTERNS = [
    re.compile(r'/api/|/v[0-9]+/|/graphql|/rest/|/ws/|/rpc/', re.I),
    re.compile(r'/oauth/|/token|/webhook|/callback', re.I),
    re.compile(r'\.(json|xml)(\?|$)', re.I),
]

CONTACT_FORM_PATTERNS = [
    re.compile(r'(contact|feedback|support|inquiry|message.?us|get.?in.?touch)', re.I),
    re.compile(r'(name=["\'](?:message|subject|body|inquiry|feedback)["\'])', re.I),
]

# Parameters that suggest injectable points for SQLi
SQLI_PARAM_NAMES = {
    'id', 'user', 'item', 'cat', 'category', 'order', 'sort', 'page', 'dir',
    'file', 'report', 'type', 'name', 'query', 'field', 'row', 'table', 'from',
    'sel', 'results', 'search', 'lang', 'keyword', 'year', 'view', 'val',
    'token', 'num', 'key', 'pid', 'uid', 'gid', 'no', 'doc', 'article',
    'thread', 'post', 'product', 'productid', 'ref', 'date', 'month',
}


def run_katana_headless(http_hosts_file, output_dir, max_depth=3, concurrency=10, rate=50):
    """Run katana in headless mode to intercept JS-triggered API calls."""
    katana_output = os.path.join(output_dir, "katana_headless_urls.txt")
    katana_json = os.path.join(output_dir, "katana_headless.jsonl")

    cmd = [
        "katana",
        "-list", http_hosts_file,
        "-headless",
        "-d", str(max_depth),
        "-c", str(concurrency),
        "-rl", str(rate),
        "-jc",                # JS crawling
        "-xhr",               # capture XHR/fetch requests
        "-silent",
        "-nc",                # no color
        "-jsonl",
        "-o", katana_json,
    ]

    print(f"[*] Running katana headless crawl: {' '.join(cmd[:8])}...")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode != 0 and result.stderr:
            print(f"[!] katana stderr: {result.stderr[:500]}")
    except FileNotFoundError:
        print("[!] katana not found - install with: go install github.com/projectdiscovery/katana/cmd/katana@latest")
        return [], []
    except subprocess.TimeoutExpired:
        print("[!] katana timed out after 600s")

    all_urls = []
    xhr_urls = []

    if os.path.exists(katana_json):
        with open(katana_json, errors='ignore') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    url = entry.get("request", {}).get("endpoint", "") or entry.get("endpoint", "")
                    if not url:
                        url = entry.get("url", "")
                    if url:
                        all_urls.append(url)
                        source = entry.get("source", "")
                        if entry.get("xhr", False) or "xhr" in source.lower() or "fetch" in source.lower():
                            xhr_urls.append(url)
                except (json.JSONDecodeError, KeyError):
                    continue

    # Also extract plain URLs
    with open(katana_output, "w") as f:
        for url in sorted(set(all_urls)):
            f.write(url + "\n")

    print(f"[+] Katana headless: {len(all_urls)} total URLs, {len(xhr_urls)} XHR/Fetch intercepted")
    return all_urls, xhr_urls


def classify_url(url, page_content=None):
    """Classify a URL by its likely function (login, search, API, etc.)."""
    classifications = []
    combined = url + (page_content or "")

    checks = [
        ("login", LOGIN_PATTERNS),
        ("search", SEARCH_PATTERNS),
        ("registration", REGISTRATION_PATTERNS),
        ("password_reset", PASSWORD_RESET_PATTERNS),
        ("profile_update", PROFILE_UPDATE_PATTERNS),
        ("admin_panel", ADMIN_PATTERNS),
        ("file_download", FILE_DOWNLOAD_PATTERNS),
        ("filter_analytics", FILTER_ANALYTICS_PATTERNS),
        ("api_endpoint", API_ENDPOINT_PATTERNS),
        ("contact_form", CONTACT_FORM_PATTERNS),
    ]

    for label, patterns in checks:
        for pat in patterns:
            if pat.search(combined):
                classifications.append(label)
                break

    return list(set(classifications)) if classifications else ["generic"]


def extract_forms_from_html(html_content, base_url):
    """Extract form actions and input fields from HTML content."""
    forms = []
    form_re = re.compile(r'<form[^>]*>(.*?)</form>', re.I | re.S)
    action_re = re.compile(r'action=["\']([^"\']*)["\']', re.I)
    method_re = re.compile(r'method=["\']([^"\']*)["\']', re.I)
    input_re = re.compile(r'<input[^>]*>', re.I)
    name_re = re.compile(r'name=["\']([^"\']*)["\']', re.I)
    type_re = re.compile(r'type=["\']([^"\']*)["\']', re.I)

    for form_match in form_re.finditer(html_content):
        form_html = form_match.group(0)
        form_body = form_match.group(1)

        action = ""
        action_m = action_re.search(form_html)
        if action_m:
            action = action_m.group(1)
            if action and not action.startswith(('http://', 'https://')):
                parsed = urlparse(base_url)
                if action.startswith('/'):
                    action = f"{parsed.scheme}://{parsed.netloc}{action}"
                else:
                    action = f"{parsed.scheme}://{parsed.netloc}/{action}"

        method = "GET"
        method_m = method_re.search(form_html)
        if method_m:
            method = method_m.group(1).upper()

        inputs = []
        for inp in input_re.finditer(form_body):
            inp_html = inp.group(0)
            name_m = name_re.search(inp_html)
            type_m = type_re.search(inp_html)
            if name_m:
                inputs.append({
                    "name": name_m.group(1),
                    "type": type_m.group(1).lower() if type_m else "text",
                })

        if action or inputs:
            forms.append({
                "action": action or base_url,
                "method": method,
                "inputs": inputs,
                "classification": classify_url(action or base_url, form_html),
            })

    return forms


def probe_http_methods(url, timeout=10):
    """Probe which HTTP methods an endpoint supports via OPTIONS and direct probing."""
    supported = []
    parsed = urlparse(url)
    base = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))

    # Try OPTIONS first
    try:
        result = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "-X", "OPTIONS", "--max-time", str(timeout), "-k", base],
            capture_output=True, text=True, timeout=timeout + 5
        )
        code = result.stdout.strip()
        if code and int(code) < 400:
            # Check Allow header
            result2 = subprocess.run(
                ["curl", "-s", "-I", "-X", "OPTIONS", "--max-time", str(timeout), "-k", base],
                capture_output=True, text=True, timeout=timeout + 5
            )
            for line in result2.stdout.splitlines():
                if line.lower().startswith("allow:"):
                    methods = [m.strip().upper() for m in line.split(":", 1)[1].split(",")]
                    return methods
    except (subprocess.TimeoutExpired, ValueError, OSError):
        pass

    # Fallback: probe common methods directly
    for method in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
        try:
            result = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "-X", method, "--max-time", str(timeout), "-k", base],
                capture_output=True, text=True, timeout=timeout + 5
            )
            code = result.stdout.strip()
            if code and int(code) < 405:
                supported.append(method)
        except (subprocess.TimeoutExpired, OSError):
            continue

    return supported if supported else ["GET"]


def fetch_page_content(url, timeout=15):
    """Fetch page HTML for form extraction."""
    try:
        result = subprocess.run(
            ["curl", "-s", "-L", "--max-time", str(timeout), "-k",
             "-H", "User-Agent: Mozilla/5.0 (compatible; ARISE/2.1)",
             url],
            capture_output=True, text=True, timeout=timeout + 5
        )
        return result.stdout if result.returncode == 0 else ""
    except (subprocess.TimeoutExpired, OSError):
        return ""


def run_gospider(hosts, output_dir):
    """Run gospider on target hosts."""
    gospider_urls = []
    gospider_bin = "/Users/apple/go/bin/gospider"
    if not os.path.isfile(gospider_bin):
        try:
            result = subprocess.run(["which", "gospider"], capture_output=True, text=True)
            if result.returncode == 0:
                gospider_bin = result.stdout.strip()
            else:
                return []
        except Exception:
            return []

    print(f"[*] Running gospider crawl on {len(hosts)} hosts...")
    temp_dir = os.path.join(output_dir, "gospider_raw")
    os.makedirs(temp_dir, exist_ok=True)

    for host in hosts:
        site = host
        if not site.startswith(('http://', 'https://')):
            site = f"https://{site}"
        
        cmd = [
            gospider_bin,
            "-s", site,
            "-o", temp_dir,
            "-c", "10",
            "-d", "3",
            "--quiet",
            "--subs",
            "--js",
            "--sitemap",
            "--robots"
        ]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except Exception as e:
            print(f"[!] Error running gospider on {site}: {e}")

    for root, dirs, files in os.walk(temp_dir):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if " - " in line:
                            parts = line.split(" - ", 1)
                            url = parts[1].strip()
                        else:
                            url = line
                        if url.startswith("http"):
                            gospider_urls.append(url)
            except Exception as e:
                print(f"[!] Error reading gospider output file {file_path}: {e}")

    try:
        shutil.rmtree(temp_dir)
    except Exception:
        pass

    print(f"[+] gospider found {len(set(gospider_urls))} unique URLs")
    return list(set(gospider_urls))


def run_gau(hosts):
    """Run gau on domains from target hosts."""
    gau_urls = []
    gau_bin = "/Users/apple/go/bin/gau"
    if not os.path.isfile(gau_bin):
        try:
            result = subprocess.run(["which", "gau"], capture_output=True, text=True)
            if result.returncode == 0:
                gau_bin = result.stdout.strip()
            else:
                return []
        except Exception:
            return []

    domains = set()
    for host in hosts:
        parsed = urlparse(host)
        domain = parsed.netloc or host
        if ":" in domain:
            domain = domain.split(":")[0]
        if domain:
            domains.add(domain)

    print(f"[*] Running gau crawl on {len(domains)} domains...")
    for domain in domains:
        cmd = [gau_bin, domain, "--threads", "10"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.startswith("http"):
                        gau_urls.append(line)
        except Exception as e:
            print(f"[!] Error running gau on {domain}: {e}")

    print(f"[+] gau found {len(set(gau_urls))} unique URLs")
    return list(set(gau_urls))


def build_injectable_urls(all_urls, xhr_urls, forms, base_hosts):
    """Build the final list of injectable URLs with classifications, splitting endpoints and queries."""
    injectable = []
    seen = set()

    # URLs with query parameters from headless/web crawl
    for url in set(all_urls + xhr_urls):
        parsed = urlparse(url)
        if not parsed.query:
            continue
        if url in seen:
            continue
        seen.add(url)

        # Split endpoint and query parameters
        endpoint_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        query_string = parsed.query

        params = parse_qs(query_string, keep_blank_values=True)
        param_names = set(p.lower() for p in params.keys())
        is_sqli_candidate = bool(param_names & SQLI_PARAM_NAMES)

        entry = {
            "url": url,
            "endpoint": endpoint_url,
            "query": query_string,
            "source": "xhr_intercept" if url in set(xhr_urls) else "web_crawl",
            "classifications": classify_url(url),
            "params": list(params.keys()),
            "sqli_candidate": is_sqli_candidate,
            "has_query": True,
        }
        injectable.append(entry)

    # URLs without query but with path params (REST-style /api/users/123)
    rest_param_re = re.compile(r'/(\d+)(?:/|$|\?)')
    for url in set(all_urls + xhr_urls):
        parsed = urlparse(url)
        if parsed.query:
            continue
        if not API_ENDPOINT_PATTERNS[0].search(url):
            continue
        if rest_param_re.search(parsed.path):
            if url not in seen:
                seen.add(url)
                endpoint_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                injectable.append({
                    "url": url,
                    "endpoint": endpoint_url,
                    "query": "",
                    "source": "rest_path_param",
                    "classifications": ["api_endpoint"],
                    "params": ["path_id"],
                    "sqli_candidate": True,
                    "has_query": False,
                })

    # Form-based targets
    for form in forms:
        action = form["action"]
        if action in seen:
            continue
        seen.add(action)
        parsed = urlparse(action)
        endpoint_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        injectable.append({
            "url": action,
            "endpoint": endpoint_url,
            "query": parsed.query or "",
            "source": "form_discovery",
            "method": form["method"],
            "classifications": form["classification"],
            "params": [i["name"] for i in form["inputs"]],
            "input_types": {i["name"]: i["type"] for i in form["inputs"]},
            "sqli_candidate": any(
                i["name"].lower() in SQLI_PARAM_NAMES for i in form["inputs"]
            ),
            "has_query": form["method"] == "GET",
        })

    return injectable


def main():
    parser = argparse.ArgumentParser(description="ARISE API Deep Discovery Module")
    parser.add_argument("--http-hosts", required=True, help="File with HTTP hosts (from httpx)")
    parser.add_argument("--output-dir", required=True, help="Output directory for results")
    parser.add_argument("--crawled-urls", help="Existing crawled URLs file (all_urls.txt)")
    parser.add_argument("--manifest", help="Path to manifest.json")
    parser.add_argument("--depth", type=int, default=3, help="Crawl depth (default: 3)")
    parser.add_argument("--concurrency", type=int, default=10, help="Concurrent crawlers")
    parser.add_argument("--rate", type=int, default=50, help="Requests per second limit")
    parser.add_argument("--method-probe", action="store_true", help="Probe HTTP methods on API endpoints")
    parser.add_argument("--method-probe-max", type=int, default=50, help="Max endpoints to method-probe")
    parser.add_argument("--form-fetch-max", type=int, default=30, help="Max pages to fetch for form extraction")
    args = parser.parse_args()

    output_dir = args.output_dir
    os.makedirs(output_dir, exist_ok=True)

    # Load HTTP hosts
    if not os.path.isfile(args.http_hosts):
        print(f"[!] HTTP hosts file not found: {args.http_hosts}")
        sys.exit(1)

    with open(args.http_hosts) as f:
        base_hosts = [line.strip() for line in f if line.strip()]

    # Parse manifest.json if provided
    if args.manifest and os.path.isfile(args.manifest):
        try:
            with open(args.manifest) as f:
                manifest = json.load(f)
            manifest_hosts = []
            for host, data in manifest.get("hosts", {}).items():
                url = data.get("url")
                if url:
                    manifest_hosts.append(url)
                elif data.get("is_api"):
                    manifest_hosts.append(f"https://{host}")
            if manifest_hosts:
                base_hosts = list(sorted(set(base_hosts + manifest_hosts)))
                print(f"[+] Loaded {len(manifest_hosts)} hosts from manifest.json. Total base hosts: {len(base_hosts)}")
        except Exception as e:
            print(f"[!] Error loading manifest: {e}")

    print(f"[*] API Deep Discovery starting with {len(base_hosts)} HTTP hosts")

    # Write a temporary hosts file for Katana list input
    temp_hosts_file = os.path.join(output_dir, "temp_crawling_hosts.txt")
    with open(temp_hosts_file, "w") as f:
        for host in base_hosts:
            f.write(host + "\n")

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 1: Headless Browser Interception (katana --headless --xhr)
    # ═══════════════════════════════════════════════════════════════════════════
    print("\n[*] PHASE 1: Headless browser interception...")
    all_urls, xhr_urls = run_katana_headless(
        temp_hosts_file, output_dir,
        max_depth=args.depth,
        concurrency=args.concurrency,
        rate=args.rate
    )

    try:
        os.unlink(temp_hosts_file)
    except Exception:
        pass

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 2: Additional Web Crawling (Gospider & GAU)
    # ═══════════════════════════════════════════════════════════════════════════
    print("\n[*] PHASE 2: Running auxiliary web crawls (gospider & gau)...")
    gospider_urls = run_gospider(base_hosts, output_dir)
    gau_urls = run_gau(base_hosts)
    all_urls = list(sorted(set(all_urls + gospider_urls + gau_urls)))

    # Merge with existing crawled URLs if available
    if args.crawled_urls and os.path.isfile(args.crawled_urls):
        with open(args.crawled_urls) as f:
            existing = [line.strip() for line in f if line.strip()]
        print(f"[+] Merged {len(existing)} existing crawled URLs")
        all_urls = list(set(all_urls + existing))

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 3: Page Classification & Form Discovery
    # ═══════════════════════════════════════════════════════════════════════════
    print("\n[*] PHASE 3: Page classification & form discovery...")
    all_forms = []
    pages_fetched = 0

    # Prioritize pages likely to have forms
    form_candidates = []
    for url in all_urls:
        classifications = classify_url(url)
        if any(c in classifications for c in [
            "login", "search", "registration", "password_reset",
            "profile_update", "contact_form", "admin_panel"
        ]):
            form_candidates.append(url)

    # Also check base hosts (homepage often has search/login)
    for host in base_hosts[:20]:
        if not host.startswith(('http://', 'https://')):
            host = f"https://{host}"
        if host not in form_candidates:
            form_candidates.insert(0, host)

    # Deduplicate by netloc+path to avoid fetching same page multiple times
    seen_pages = set()
    unique_candidates = []
    for url in form_candidates:
        parsed = urlparse(url)
        key = f"{parsed.netloc}{parsed.path}"
        if key not in seen_pages:
            seen_pages.add(key)
            unique_candidates.append(url)

    print(f"[+] {len(unique_candidates)} unique form candidate pages to fetch")

    for url in unique_candidates[:args.form_fetch_max]:
        html = fetch_page_content(url)
        if html:
            forms = extract_forms_from_html(html, url)
            all_forms.extend(forms)
            pages_fetched += 1

    print(f"[+] Fetched {pages_fetched} pages, found {len(all_forms)} forms")

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 4: Build Injectable URL List
    # ═══════════════════════════════════════════════════════════════════════════
    print("\n[*] PHASE 4: Building injectable URL inventory...")
    injectable = build_injectable_urls(all_urls, xhr_urls, all_forms, base_hosts)
    print(f"[+] Total injectable targets: {len(injectable)}")

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 5: HTTP Method Enumeration (on API endpoints only)
    # ═══════════════════════════════════════════════════════════════════════════
    if args.method_probe:
        print("\n[*] PHASE 5: HTTP method probing on API endpoints...")
        api_targets = [
            entry for entry in injectable
            if "api_endpoint" in entry.get("classifications", [])
        ][:args.method_probe_max]

        print(f"[+] Probing {len(api_targets)} API endpoints for supported methods...")
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(probe_http_methods, entry["url"]): i
                for i, entry in enumerate(api_targets)
            }
            for future in as_completed(futures):
                idx = futures[future]
                try:
                    methods = future.result()
                    api_targets[idx]["http_methods"] = methods
                except Exception:
                    api_targets[idx]["http_methods"] = ["GET"]

        # Update main injectable list
        api_url_set = {e["url"] for e in api_targets}
        for entry in injectable:
            if entry["url"] in api_url_set:
                match = next((a for a in api_targets if a["url"] == entry["url"]), None)
                if match and "http_methods" in match:
                    entry["http_methods"] = match["http_methods"]

        methods_found = sum(1 for e in injectable if "http_methods" in e)
        print(f"[+] Method probing complete: {methods_found} endpoints enumerated")

    # ═══════════════════════════════════════════════════════════════════════════
    # OUTPUT: Write results
    # ═══════════════════════════════════════════════════════════════════════════
    print("\n[*] Writing outputs...")

    # Full results (JSONL)
    results_file = os.path.join(output_dir, "api_deep_discovery.jsonl")
    with open(results_file, "w") as f:
        for entry in injectable:
            f.write(json.dumps(entry) + "\n")

    # SQLi-ready URLs (plain text, one per line)
    sqli_file = os.path.join(output_dir, "sqli_targets.txt")
    with open(sqli_file, "w") as f:
        for entry in injectable:
            if entry.get("sqli_candidate"):
                f.write(entry["url"] + "\n")

    # XSS/injection candidate URLs (all with query params)
    injection_file = os.path.join(output_dir, "injection_targets.txt")
    with open(injection_file, "w") as f:
        for entry in injectable:
            if entry.get("has_query") or entry.get("params"):
                f.write(entry["url"] + "\n")

    # API endpoints with methods
    api_file = os.path.join(output_dir, "api_endpoints.jsonl")
    with open(api_file, "w") as f:
        for entry in injectable:
            if "api_endpoint" in entry.get("classifications", []):
                f.write(json.dumps(entry) + "\n")

    # Forms discovered
    forms_file = os.path.join(output_dir, "forms_discovered.json")
    with open(forms_file, "w") as f:
        json.dump(all_forms, f, indent=2)

    # Page classifications summary
    classification_summary = {}
    for entry in injectable:
        for cls in entry.get("classifications", ["generic"]):
            classification_summary.setdefault(cls, []).append(entry["url"])

    summary_file = os.path.join(output_dir, "classifications.json")
    with open(summary_file, "w") as f:
        json.dump({k: {"count": len(v), "urls": v[:20]} for k, v in classification_summary.items()}, f, indent=2)

    # XHR/Fetch intercepted (these are the high-value API calls from headless)
    xhr_file = os.path.join(output_dir, "xhr_intercepted.txt")
    with open(xhr_file, "w") as f:
        for url in sorted(set(xhr_urls)):
            f.write(url + "\n")

    # ═══════════════════════════════════════════════════════════════════════════
    # FEEDBACK LOOP: Append findings back to all_urls.txt
    # ═══════════════════════════════════════════════════════════════════════════
    loop_file = args.crawled_urls
    if not loop_file:
        loop_file = os.path.abspath(os.path.join(output_dir, "..", "09_crawling", "all_urls.txt"))
    
    loop_urls = []
    for entry in injectable:
        if entry.get("sqli_candidate") or entry.get("has_query") or entry.get("params"):
            loop_urls.append(entry["url"])
            
    if loop_urls:
        try:
            loop_dir = os.path.dirname(loop_file)
            if loop_dir:
                os.makedirs(loop_dir, exist_ok=True)
            existing_all = []
            if os.path.exists(loop_file):
                with open(loop_file, "r", errors="ignore") as f:
                    existing_all = [l.strip() for l in f if l.strip()]
            merged_all = list(sorted(set(existing_all + loop_urls)))
            with open(loop_file, "w") as f:
                for u in merged_all:
                    f.write(u + "\n")
            print(f"[+] Feedback loop: Appended {len(loop_urls)} targets to {loop_file} (Total URLs: {len(merged_all)})")
        except Exception as e:
            print(f"[!] Warning: Feedback loop write failed: {e}")

    # Module result summary
    result_summary = {
        "module": "api_deep_discovery",
        "total_urls_discovered": len(all_urls),
        "xhr_intercepted": len(set(xhr_urls)),
        "forms_discovered": len(all_forms),
        "js_api_paths": 0,
        "total_injectable": len(injectable),
        "sqli_candidates": sum(1 for e in injectable if e.get("sqli_candidate")),
        "api_endpoints": sum(1 for e in injectable if "api_endpoint" in e.get("classifications", [])),
        "login_pages": sum(1 for e in injectable if "login" in e.get("classifications", [])),
        "search_pages": sum(1 for e in injectable if "search" in e.get("classifications", [])),
        "admin_panels": sum(1 for e in injectable if "admin_panel" in e.get("classifications", [])),
        "file_downloads": sum(1 for e in injectable if "file_download" in e.get("classifications", [])),
        "classifications": {k: len(v) for k, v in classification_summary.items()},
    }

    result_file = os.path.join(output_dir, "results.json")
    with open(result_file, "w") as f:
        json.dump(result_summary, f, indent=2)

    # Print summary
    print("\n" + "=" * 60)
    print("  API DEEP DISCOVERY — RESULTS")
    print("=" * 60)
    print(f"  Total URLs from crawls         : {len(all_urls)}")
    print(f"  XHR/Fetch intercepted          : {len(set(xhr_urls))}")
    print(f"  Forms discovered               : {len(all_forms)}")
    print(f"  Total injectable targets       : {len(injectable)}")
    print(f"  SQLi candidates                : {result_summary['sqli_candidates']}")
    print(f"  API endpoints                  : {result_summary['api_endpoints']}")
    print(f"  Login pages                    : {result_summary['login_pages']}")
    print(f"  Search pages                   : {result_summary['search_pages']}")
    print(f"  Admin panels                   : {result_summary['admin_panels']}")
    print("=" * 60)
    print(f"\n[+] Outputs written to: {output_dir}/")
    print(f"    - api_deep_discovery.jsonl  (full classified results)")
    print(f"    - sqli_targets.txt          (ready for sqlmap)")
    print(f"    - injection_targets.txt     (all injectable URLs)")
    print(f"    - api_endpoints.jsonl       (APIs with methods)")
    print(f"    - xhr_intercepted.txt       (headless-caught API calls)")
    print(f"    - forms_discovered.json     (forms with fields)")
    print(f"    - classifications.json      (page type summary)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
