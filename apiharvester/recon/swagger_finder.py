"""Phase 6: OpenAPI / Swagger spec discovery and parsing."""
import json
import sys
import urllib.parse

from ..config import SPEC_PATHS
from ..http_client import HTTPClient
from ..models import Endpoint, ScanContext
from ..utils.soft404 import Soft404Detector
from .swagger_parser import analyze_spec


def _log(msg):
    print(f"[*] Phase 6 (swagger): {msg}", file=sys.stderr)


def _is_valid_spec(body):
    """Check if body looks like a valid OpenAPI/Swagger spec."""
    if not body:
        return False
    stripped = body.lstrip()
    if stripped.startswith("{"):
        try:
            data = json.loads(body)
            return any(k in data for k in
                       ("swagger", "openapi", "paths", "info", "basePath"))
        except json.JSONDecodeError:
            return False
    if "openapi:" in body[:200] or "swagger:" in body[:200]:
        return True
    return False


def _parse_spec_paths(body, base_url):
    """Extract endpoints from an OpenAPI/Swagger spec."""
    endpoints = []
    try:
        spec = json.loads(body)
    except json.JSONDecodeError:
        return endpoints

    base_path = spec.get("basePath", "")
    parsed_base = urllib.parse.urlparse(base_url)
    scheme_host = f"{parsed_base.scheme}://{parsed_base.netloc}"

    servers = spec.get("servers", [])
    if servers and isinstance(servers, list):
        srv_url = servers[0].get("url", "")
        if srv_url.startswith("/"):
            base_path = srv_url
        elif srv_url.startswith("http"):
            scheme_host = srv_url.rstrip("/")
            base_path = ""

    paths = spec.get("paths", {})
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        full_path = base_path.rstrip("/") + "/" + path.lstrip("/")
        url = scheme_host.rstrip("/") + "/" + full_path.lstrip("/")

        method_list = []
        params = {}
        for method in ("get", "post", "put", "patch", "delete",
                       "options", "head"):
            if method in methods:
                method_list.append(method.upper())
                op = methods[method]
                if isinstance(op, dict):
                    for p in op.get("parameters", []):
                        if isinstance(p, dict) and p.get("in") == "query":
                            params[p.get("name", "")] = ""

        if method_list:
            ep = Endpoint(
                url=url, methods=method_list, params=params,
                is_api=True, source="swagger")
            endpoints.append(ep)

    return endpoints


def _walk_up_paths(existing_paths, base_url):
    """Generate spec probe paths by walking up from discovered API paths."""
    extra = set()
    for ep_path in existing_paths:
        parts = ep_path.rstrip("/").split("/")
        for i in range(len(parts), 0, -1):
            prefix = "/".join(parts[:i])
            if prefix:
                for spec in ("swagger.json", "openapi.json", "api-docs"):
                    extra.add(prefix.rstrip("/") + "/" + spec)
    return list(extra)


def find_swagger_specs(ctx: ScanContext):
    """Discover and parse OpenAPI/Swagger specs for all API hosts."""
    api_hosts = ctx.api_hosts()
    if not api_hosts:
        api_hosts = ctx.active_hosts()
    _log(f"Searching for specs on {len(api_hosts)} hosts")

    client = HTTPClient(timeout=ctx.timeout)
    soft404 = Soft404Detector()

    found_specs = 0
    added_endpoints = 0

    for host in api_hosts:
        base = host.url.rstrip("/")
        soft404.fingerprint(client, base)

        existing_paths = [e.path for e in ctx.endpoints_for_host(host.domain)]
        probe_paths = list(SPEC_PATHS) + _walk_up_paths(existing_paths, base)
        seen = set()

        for spec_path in probe_paths:
            url = base + "/" + spec_path.lstrip("/")
            if url in seen:
                continue
            seen.add(url)

            resp = client.request("GET", url)
            if resp.status == 0 or resp.status >= 400:
                continue
            if soft404.is_soft_404(resp):
                continue
            if not _is_valid_spec(resp.body):
                continue

            _log(f"  Found spec: {url}")
            found_specs += 1

            try:
                spec_dict = json.loads(resp.body)
                ctx.swagger_specs[host.domain] = spec_dict

                # Advanced analysis: extract security schemes, enums, schemas, constraints
                analysis = analyze_spec(spec_dict)
                ctx.swagger_analysis[host.domain] = analysis

                # Log what we found
                if analysis.get("security_schemes"):
                    _log(f"    Auth: {', '.join(analysis['security_schemes'].keys())}")
                if analysis.get("parameter_enums"):
                    _log(f"    Enums: {len(analysis['parameter_enums'])} param(s) with enum values")
                if analysis.get("request_body_schemas"):
                    _log(f"    Request bodies: {len(analysis['request_body_schemas'])} endpoint(s)")

            except json.JSONDecodeError:
                continue

            new_eps = _parse_spec_paths(resp.body, base)
            for ep in new_eps:
                if not any(e.url == ep.url for e in ctx.endpoints):
                    ctx.endpoints.append(ep)
                    added_endpoints += 1

            break

    _log(f"Specs found: {found_specs}, "
         f"endpoints from specs: {added_endpoints}")
