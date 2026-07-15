"""Write categorised recon files consumed by attack modules."""
import json
import os
import sys

from ..models import ScanContext


def _log(msg):
    print(f"[*] Output: {msg}", file=sys.stderr)


def _write(path, lines):
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n" if lines else "")
    _log(f"  {os.path.basename(path)}: {len(lines)} entries")


def write_recon_files(ctx: ScanContext):
    """Generate all recon output files from accumulated context."""
    d = ctx.output_dir
    os.makedirs(d, exist_ok=True)

    # fqdn.txt — all subdomains
    _write(os.path.join(d, "fqdn.txt"),
           sorted(h.domain for h in ctx.hosts))

    # fqdn_resolved.txt — domains with IPs
    resolved = []
    for h in ctx.hosts:
        if h.ips:
            resolved.append(f"{h.domain}\t{','.join(h.ips)}")
    _write(os.path.join(d, "fqdn_resolved.txt"), sorted(resolved))

    # fqdn_active.txt — live HTTP hosts
    _write(os.path.join(d, "fqdn_active.txt"),
           sorted(h.url for h in ctx.active_hosts()))

    # fqdnwithendpoint.txt — all discovered endpoints
    _write(os.path.join(d, "fqdnwithendpoint.txt"),
           sorted(set(e.url for e in ctx.endpoints)))

    # withparam.txt — endpoints with discovered params
    param_lines = []
    for e in ctx.endpoints:
        if e.params:
            qs = "&".join(f"{k}={v}" for k, v in e.params.items())
            base = e.base_url()
            param_lines.append(f"{base}?{qs}")
    _write(os.path.join(d, "withparam.txt"), sorted(set(param_lines)))

    # paramvalue.txt — endpoints with param values (from probing)
    value_lines = []
    for e in ctx.endpoints:
        if any(v for v in e.params.values()):
            qs = "&".join(f"{k}={v}" for k, v in e.params.items() if v)
            value_lines.append(f"{e.base_url()}?{qs}")
    _write(os.path.join(d, "paramvalue.txt"), sorted(set(value_lines)))

    # withtoken.txt — auth tokens
    token_lines = list(set(ctx.tokens))
    if ctx.auth:
        token_lines.insert(0, ctx.auth)
    if ctx.auth2:
        token_lines.append(ctx.auth2)
    _write(os.path.join(d, "withtoken.txt"), token_lines)

    # objectshape.txt — response object fields per endpoint
    shape_lines = []
    for e in ctx.endpoints:
        if e.object_fields:
            shape_lines.append(
                f"{e.url}\t{','.join(e.object_fields)}")
    _write(os.path.join(d, "objectshape.txt"), sorted(shape_lines))

    # waf_results.jsonl — WAF detection per host
    waf_path = os.path.join(d, "waf_results.jsonl")
    with open(waf_path, "w") as f:
        for h in ctx.hosts:
            if h.waf_vendor != "none" or h.catchall or h.js_challenge:
                entry = {
                    "domain": h.domain,
                    "waf_vendor": h.waf_vendor,
                    "catchall": h.catchall,
                    "js_challenge": h.js_challenge,
                    "skip_bruteforce": h.skip_bruteforce,
                }
                f.write(json.dumps(entry) + "\n")

    # endpoint_methods.jsonl — HTTP methods per endpoint
    methods_path = os.path.join(d, "endpoint_methods.jsonl")
    with open(methods_path, "w") as f:
        for e in ctx.endpoints:
            if e.methods:
                entry = {"url": e.url, "methods": e.methods}
                f.write(json.dumps(entry) + "\n")

    # swagger_specs/*.json
    specs_dir = os.path.join(d, "swagger_specs")
    os.makedirs(specs_dir, exist_ok=True)
    for domain, spec in ctx.swagger_specs.items():
        safe = domain.replace("/", "_").replace(":", "_")
        spec_path = os.path.join(specs_dir, f"{safe}.json")
        with open(spec_path, "w") as f:
            json.dump(spec, f, indent=2)

    _log(f"All recon files written to {d}")
