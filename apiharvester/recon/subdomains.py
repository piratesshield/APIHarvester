"""Phase 1: Subdomain discovery — tool wrappers + pure-Python fallback."""
import json
import os
import socket
import sys
import concurrent.futures as futures
import urllib.request
import urllib.error

from ..config import SUBDOMAIN_WORDS, SUBDOMAIN_WORDLIST_FILE
from ..models import Host, ScanContext
from ..utils.tool_runner import run_tool_lines, tool_available


def _log(msg):
    print(f"[*] Phase 1 (subdomains): {msg}", file=sys.stderr)


def _passive_crtsh(domain):
    """Query crt.sh certificate transparency logs."""
    _log("Passive: crt.sh...")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "apiharvester"})
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        subs = set()
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lstrip("*.").lower()
                if name.endswith("." + domain) or name == domain:
                    subs.add(name)
        _log(f"  crt.sh: {len(subs)} subdomains")
        return subs
    except Exception as e:
        _log(f"  crt.sh failed: {e}")
        return set()


def _passive_subfinder(domain):
    """Run subfinder if installed."""
    lines = run_tool_lines("subfinder", ["-d", domain, "-silent"], timeout=120)
    if lines:
        _log(f"  subfinder: {len(lines)} subdomains")
    return set(l.lower() for l in lines if l.endswith("." + domain) or l == domain)


def _passive_haktrails(domain):
    """Run haktrails if installed."""
    if not tool_available("haktrails"):
        return set()
    from ..utils.tool_runner import run_tool
    result = run_tool("haktrails", ["subdomains"], timeout=60, stdin_data=domain)
    if result is None:
        return set()
    stdout, _, _ = result
    lines = [l.strip().lower() for l in stdout.splitlines() if l.strip()]
    if lines:
        _log(f"  haktrails: {len(lines)} subdomains")
    return set(l for l in lines if l.endswith("." + domain) or l == domain)


def _active_puredns(domain):
    """Run puredns brute-force if installed. Needs a wordlist file on disk —
    see scripts/install_requirements.sh (downloads to payloads/subdomains.txt)."""
    if not os.path.exists(SUBDOMAIN_WORDLIST_FILE):
        _log(f"  puredns: skipped, no wordlist at {SUBDOMAIN_WORDLIST_FILE} "
             f"(run scripts/install_requirements.sh)")
        return set()
    lines = run_tool_lines(
        "puredns", ["bruteforce", SUBDOMAIN_WORDLIST_FILE, domain, "--quiet"],
        timeout=300)
    if lines:
        _log(f"  puredns: {len(lines)} subdomains")
    return set(l.lower() for l in lines if l.endswith("." + domain) or l == domain)


def _fallback_dns_bruteforce(domain, threads=20):
    """Pure-Python DNS brute-force against built-in wordlist."""
    _log(f"Fallback: DNS brute-force ({len(SUBDOMAIN_WORDS)} words)...")
    found = set()

    def check(word):
        fqdn = f"{word}.{domain}"
        try:
            socket.gethostbyname(fqdn)
            return fqdn
        except socket.gaierror:
            return None

    with futures.ThreadPoolExecutor(max_workers=threads) as ex:
        for result in ex.map(check, SUBDOMAIN_WORDS):
            if result:
                found.add(result)

    _log(f"  DNS brute-force: {len(found)} subdomains")
    return found


def discover_subdomains(ctx: ScanContext):
    """Run all subdomain discovery sources, populate ctx.hosts."""
    domain = ctx.target
    _log(f"Target: {domain}")

    all_subs = {domain}

    all_subs |= _passive_crtsh(domain)
    all_subs |= _passive_subfinder(domain)
    all_subs |= _passive_haktrails(domain)

    if tool_available("puredns"):
        all_subs |= _active_puredns(domain)
    else:
        all_subs |= _fallback_dns_bruteforce(domain, threads=ctx.threads)

    # Filter to in-scope
    all_subs = {s for s in all_subs
                if s == domain or s.endswith("." + domain)}

    _log(f"Total unique subdomains: {len(all_subs)}")

    for sub in sorted(all_subs):
        ctx.hosts.append(Host(domain=sub))

    return all_subs
