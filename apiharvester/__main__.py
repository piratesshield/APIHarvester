"""CLI entry point — python -m apiharvester anan.com"""
import argparse
import os
import sys
import time

from . import VERSION
from .models import ScanContext

# Phase imports
from .recon.subdomains import discover_subdomains
from .recon.resolver import resolve_hosts
from .recon.prober import probe_hosts
from .recon.waf_detector import detect_waf
from .recon.api_detector import detect_api_urls
from .recon.swagger_finder import find_swagger_specs
from .recon.endpoint_discovery import discover_endpoints
from .recon.param_discovery import discover_params
from .recon.crawler import crawl_and_extract
from .recon.method_prober import probe_methods

# Attack imports
from .attacks.bola import run_bola
from .attacks.broken_auth import run_broken_auth
from .attacks.mass_assignment import run_mass_assignment
from .attacks.rate_limit import run_rate_limit
from .attacks.bfla import run_bfla
from .attacks.business_logic import run_business_logic
from .attacks.ssrf import run_ssrf
from .attacks.misconfiguration import run_misconfiguration
from .attacks.inventory import run_inventory
from .attacks.sspp import run_sspp
from .attacks.injection import run_injection

# Output imports
from .output.file_writer import write_recon_files
from .output.reporter import report_console, report_jsonl, report_html


BANNER = f"""
  ___  ____  ___ ____            ____
 / _ \\|  _ \\|_ _/ ___|  ___  __|___ \\
| |_| | |_) || |\\___ \\ / _ \\/ __|__) |
|  _  |  __/ | | ___) |  __/ (__ / __/
|_| |_|_|   |___|____/ \\___|\\___||_____|  v{VERSION}
     API Security Scanner — OWASP Top 10
"""

ALL_ATTACKS = {
    "bola": ("API1:2023 BOLA", run_bola),
    "broken_auth": ("API2:2023 Broken Auth", run_broken_auth),
    "mass_assignment": ("API3:2023 Mass Assignment", run_mass_assignment),
    "rate_limit": ("API4:2023 Rate Limit", run_rate_limit),
    "bfla": ("API5:2023 BFLA", run_bfla),
    "business_logic": ("API6:2023 Business Logic", run_business_logic),
    "ssrf": ("API7:2023 SSRF", run_ssrf),
    "misconfiguration": ("API8:2023 Misconfiguration", run_misconfiguration),
    "inventory": ("API9:2023 Inventory", run_inventory),
    "sspp": ("API10:2023 SSPP", run_sspp),
    "injection": ("Bonus: Injection", run_injection),
}


def build_parser():
    p = argparse.ArgumentParser(
        prog="apiharvester",
        description="API Security Scanner — OWASP Top 10 attack automation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n"
               "  python -m apiharvester example.com\n"
               "  python -m apiharvester example.com --auth 'Bearer eyJ...'\n"
               "  python -m apiharvester example.com --attacks bola,ssrf,bfla\n")

    p.add_argument("target", help="Root domain to scan (e.g., example.com)")
    p.add_argument("--auth", default="",
                   help="Primary auth token (e.g., 'Bearer eyJ...')")
    p.add_argument("--auth2", default="",
                   help="Low-priv auth token for differential testing")
    p.add_argument("--skip-recon", action="store_true",
                   help="Skip recon phases, use existing output files")
    p.add_argument("--recon-dir",
                   help="Use pre-existing recon output directory")
    p.add_argument("--attacks-only", action="store_true",
                   help="Run only attack phases (implies --skip-recon)")
    p.add_argument("--attacks", default="",
                   help="Comma-separated attack list (default: all). "
                        f"Available: {','.join(ALL_ATTACKS.keys())}")
    p.add_argument("--threads", type=int, default=20,
                   help="Thread pool size (default: 20)")
    p.add_argument("--timeout", type=int, default=10,
                   help="HTTP timeout in seconds (default: 10)")
    p.add_argument("--burst", type=int, default=20,
                   help="Burst request count for rate-limit tests (default: 20)")
    p.add_argument("--json", dest="json_out", metavar="FILE",
                   help="Write JSONL report to FILE")
    p.add_argument("--html", dest="html_out", metavar="FILE",
                   help="Write HTML report to FILE")
    p.add_argument("--output-dir", dest="output_dir",
                   help="Scan output directory (default: ./output/{domain})")
    p.add_argument("--version", action="version", version=f"apiharvester {VERSION}")
    return p


def _phase(label, fn, *args):
    """Run a pipeline phase with timing."""
    t0 = time.time()
    print(f"\n{'='*60}", file=sys.stderr)
    print(f"  {label}", file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)
    try:
        fn(*args)
    except KeyboardInterrupt:
        print(f"\n[!] {label} interrupted by user", file=sys.stderr)
        raise
    except Exception as e:
        print(f"[!] {label} failed: {e}", file=sys.stderr)
    elapsed = time.time() - t0
    print(f"[*] {label} completed in {elapsed:.1f}s", file=sys.stderr)


def main():
    parser = build_parser()
    args = parser.parse_args()

    print(BANNER, file=sys.stderr)

    # Build output directory
    if args.output_dir:
        output_dir = args.output_dir
    else:
        ts = time.strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join("output", f"{args.target}_{ts}")

    ctx = ScanContext(
        target=args.target,
        output_dir=output_dir,
        auth=args.auth,
        auth2=args.auth2,
        threads=args.threads,
        timeout=args.timeout,
        burst=args.burst,
    )

    # Extract tokens from auth headers
    if ctx.auth:
        from .utils.jwt import extract_jwt_from_auth
        jwt = extract_jwt_from_auth(ctx.auth)
        if jwt:
            ctx.tokens.append(jwt)
    if ctx.auth2:
        from .utils.jwt import extract_jwt_from_auth
        jwt = extract_jwt_from_auth(ctx.auth2)
        if jwt:
            ctx.tokens.append(jwt)

    t_start = time.time()
    skip_recon = args.skip_recon or args.attacks_only

    # ===== RECON PHASE =====
    if not skip_recon:
        print(f"\n{'#'*60}", file=sys.stderr)
        print(f"  RECON PHASE — {ctx.target}", file=sys.stderr)
        print(f"{'#'*60}", file=sys.stderr)

        _phase("Phase 1:  Subdomain Discovery", discover_subdomains, ctx)
        _phase("Phase 2:  DNS Resolution", resolve_hosts, ctx)
        _phase("Phase 3:  HTTP Probing", probe_hosts, ctx)
        _phase("Phase 4:  WAF Detection", detect_waf, ctx)
        _phase("Phase 5:  API URL Detection", detect_api_urls, ctx)
        _phase("Phase 6:  Swagger/OpenAPI Discovery", find_swagger_specs, ctx)
        _phase("Phase 7:  Endpoint Brute-Force", discover_endpoints, ctx)
        _phase("Phase 8:  Parameter Discovery", discover_params, ctx)
        _phase("Phase 9:  Crawling + JS Extraction", crawl_and_extract, ctx)
        _phase("Phase 10: HTTP Method Probing", probe_methods, ctx)

        # Write recon files
        _phase("Writing recon files", write_recon_files, ctx)

        print(f"\n[*] Recon summary:", file=sys.stderr)
        print(f"    Hosts:     {len(ctx.hosts)}", file=sys.stderr)
        print(f"    Live:      {len(ctx.active_hosts())}", file=sys.stderr)
        print(f"    API hosts: {len(ctx.api_hosts())}", file=sys.stderr)
        print(f"    Endpoints: {len(ctx.endpoints)}", file=sys.stderr)
        print(f"    WAF:       {len(ctx.waf_hosts)}", file=sys.stderr)
        print(f"    Swagger:   {len(ctx.swagger_specs)}", file=sys.stderr)
    else:
        print(f"\n[*] Skipping recon (--skip-recon)", file=sys.stderr)
        if args.recon_dir:
            _load_recon_from_dir(ctx, args.recon_dir)

    # ===== ATTACK PHASE =====
    selected = ALL_ATTACKS
    if args.attacks:
        keys = [k.strip() for k in args.attacks.split(",")]
        selected = {k: v for k, v in ALL_ATTACKS.items() if k in keys}
        unknown = set(keys) - set(ALL_ATTACKS.keys())
        if unknown:
            print(f"[!] Unknown attacks: {unknown}", file=sys.stderr)

    if ctx.endpoints or ctx.active_hosts():
        print(f"\n{'#'*60}", file=sys.stderr)
        print(f"  ATTACK PHASE — {len(selected)} attacks", file=sys.stderr)
        print(f"{'#'*60}", file=sys.stderr)

        for key, (label, fn) in selected.items():
            _phase(f"Attack: {label}", fn, ctx)
    else:
        print("\n[!] No endpoints or hosts found — skipping attacks.",
              file=sys.stderr)

    # ===== REPORTING =====
    print(f"\n{'#'*60}", file=sys.stderr)
    print(f"  REPORTING", file=sys.stderr)
    print(f"{'#'*60}", file=sys.stderr)

    report_console(ctx)

    if args.json_out:
        report_jsonl(ctx, args.json_out)

    if args.html_out:
        report_html(ctx, args.html_out)

    elapsed = time.time() - t_start
    print(f"\n[*] Scan completed in {elapsed:.1f}s", file=sys.stderr)
    print(f"[*] Total findings: {len(ctx.findings)}", file=sys.stderr)
    print(f"[*] Output directory: {ctx.output_dir}", file=sys.stderr)


def _load_recon_from_dir(ctx, recon_dir):
    """Load previously generated recon files into context."""
    from .models import Host, Endpoint
    import json

    print(f"[*] Loading recon from {recon_dir}", file=sys.stderr)

    # fqdn_active.txt
    active_path = os.path.join(recon_dir, "fqdn_active.txt")
    if os.path.exists(active_path):
        with open(active_path) as f:
            for line in f:
                url = line.strip()
                if url:
                    from urllib.parse import urlparse
                    domain = urlparse(url).netloc
                    host = Host(domain=domain, url=url, is_live=True)
                    ctx.hosts.append(host)

    # fqdnwithendpoint.txt
    ep_path = os.path.join(recon_dir, "fqdnwithendpoint.txt")
    if os.path.exists(ep_path):
        with open(ep_path) as f:
            for line in f:
                url = line.strip()
                if url:
                    ctx.endpoints.append(Endpoint(url=url, source="file"))

    # withparam.txt
    param_path = os.path.join(recon_dir, "withparam.txt")
    if os.path.exists(param_path):
        with open(param_path) as f:
            for line in f:
                url = line.strip()
                if url:
                    ctx.endpoints.append(Endpoint(url=url, source="file"))

    # withtoken.txt
    token_path = os.path.join(recon_dir, "withtoken.txt")
    if os.path.exists(token_path):
        with open(token_path) as f:
            for line in f:
                token = line.strip()
                if token:
                    ctx.tokens.append(token)

    # swagger_specs
    specs_dir = os.path.join(recon_dir, "swagger_specs")
    if os.path.isdir(specs_dir):
        for fname in os.listdir(specs_dir):
            if fname.endswith(".json"):
                fpath = os.path.join(specs_dir, fname)
                try:
                    with open(fpath) as f:
                        spec = json.load(f)
                    domain = fname.replace(".json", "").replace("_", ":")
                    ctx.swagger_specs[domain] = spec
                except (json.JSONDecodeError, OSError):
                    pass

    # waf_results.jsonl
    waf_path = os.path.join(recon_dir, "waf_results.jsonl")
    if os.path.exists(waf_path):
        with open(waf_path) as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    ctx.waf_hosts.add(entry["domain"])
                except (json.JSONDecodeError, KeyError):
                    pass

    print(f"[*] Loaded: {len(ctx.hosts)} hosts, "
          f"{len(ctx.endpoints)} endpoints, "
          f"{len(ctx.tokens)} tokens, "
          f"{len(ctx.swagger_specs)} specs", file=sys.stderr)


if __name__ == "__main__":
    main()
