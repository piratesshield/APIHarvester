"""Mock vulnerable+safe API to validate APIHarvester's hardened detection.

Endpoints are split into VULNERABLE (findings SHOULD fire) and SAFE (findings
should NOT fire — these are the false-positive traps). Run:

    python3 scratch/mock_api.py 8099      # in one shell
    python3 scratch/selftest.py 8099      # in another

Design maps to REAL_WORLD_RESEARCH.md cases.
"""
import base64
import hashlib
import hmac
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECRET = b"secret"  # deliberately weak HMAC secret (JWT_WEAK_SECRETS)

# A fixed "user 1 profile" object served for BOLA tests.
USER1 = {"id": 1, "name": "Alice", "email": "alice@corp.test", "role": "user"}
USER2 = {"id": 2, "name": "Bob", "email": "bob@corp.test", "role": "user"}

# In-memory object whose 'role' can be mass-assigned (vuln) — persisted.
VULN_PROFILE = {"id": 10, "name": "Carol", "role": "user"}
# Safe profile: echoes body but never persists 'role'.
SAFE_PROFILE = {"id": 11, "name": "Dave", "role": "user"}


def _b64u(d):
    if isinstance(d, str):
        d = d.encode()
    return base64.urlsafe_b64encode(d).rstrip(b"=")


def make_jwt(payload, alg="HS256", secret=SECRET):
    header = {"alg": alg, "typ": "JWT"}
    h = _b64u(json.dumps(header))
    p = _b64u(json.dumps(payload))
    signing = h + b"." + p
    if alg == "none":
        return (signing + b".").decode()
    sig = _b64u(hmac.new(secret, signing, hashlib.sha256).digest())
    return (signing + b"." + sig).decode()


def verify_jwt_strict(token):
    """SAFE verifier: pins HS256 + real secret, rejects alg=none."""
    try:
        h_b64, p_b64, s_b64 = token.split(".")
        header = json.loads(base64.urlsafe_b64decode(h_b64 + "=="))
        if header.get("alg") != "HS256":
            return None
        signing = (h_b64 + "." + p_b64).encode()
        expected = _b64u(hmac.new(SECRET, signing, hashlib.sha256).digest())
        if not hmac.compare_digest(expected.decode(), s_b64):
            return None
        return json.loads(base64.urlsafe_b64decode(p_b64 + "=="))
    except Exception:
        return None


def verify_jwt_broken(token):
    """VULNERABLE verifier: trusts alg header, accepts alg=none, no sig check."""
    try:
        h_b64, p_b64, s_b64 = token.split(".")
        header = json.loads(base64.urlsafe_b64decode(h_b64 + "=="))
        payload = json.loads(base64.urlsafe_b64decode(p_b64 + "=="))
        if header.get("alg") == "none":
            return payload  # BUG: accepts unsigned
        # BUG: does not actually verify the signature at all
        return payload
    except Exception:
        return None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass  # quiet

    def _send(self, code, obj, ctype="application/json"):
        body = obj if isinstance(obj, (bytes, str)) else json.dumps(obj)
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _auth(self):
        return self.headers.get("Authorization", "")

    def do_GET(self):
        p = self.path.split("?")[0]
        q = self.path.split("?", 1)[1] if "?" in self.path else ""
        auth = self._auth()

        # ---- BOLA: fixed object, NO ownership check (VULNERABLE) ----
        # Any valid-looking bearer returns user1's object → two identities get
        # the SAME object. Hardened BOLA should flag critical.
        if p == "/api/vuln/users/1":
            if auth.startswith("Bearer "):
                return self._send(200, USER1)
            return self._send(401, {"error": "unauthorized"})

        # ---- BOLA-safe: per-caller object (FALSE-POSITIVE TRAP) ----
        # Returns a different object per identity (decoded from JWT sub) → NOT
        # a BOLA. Hardened BOLA should NOT flag critical (info at most).
        if p == "/api/safe/me":
            if not auth.startswith("Bearer "):
                return self._send(401, {"error": "unauthorized"})
            payload = verify_jwt_strict(auth.replace("Bearer ", "")) or {}
            sub = str(payload.get("sub", ""))
            return self._send(200, USER2 if sub == "2" else USER1)

        # ---- BOLA id-fuzz: distinct objects per id (VULNERABLE) ----
        if p.startswith("/api/vuln/doc/"):
            doc_id = p.rsplit("/", 1)[-1]
            if auth.startswith("Bearer "):
                # every id returns a genuinely different object
                return self._send(200, {"doc": doc_id, "owner": f"user{doc_id}",
                                        "content": "X" * (100 + int(doc_id or 0) % 7 * 40)
                                        if doc_id.isdigit() else "Y" * 300})
            return self._send(401, {"error": "unauthorized"})

        # ---- id-fuzz SAFE: soft-404 for other ids (FALSE-POSITIVE TRAP) ----
        if p.startswith("/api/safe/doc/"):
            doc_id = p.rsplit("/", 1)[-1]
            if not auth.startswith("Bearer "):
                return self._send(401, {"error": "unauthorized"})
            if doc_id == "500":  # only the owner's id is valid
                return self._send(200, {"doc": "500", "owner": "me",
                                        "content": "Z" * 300})
            return self._send(200, {"error": "not found", "doc": doc_id})  # soft-404

        # ---- JWT-protected endpoint, BROKEN verifier (VULNERABLE) ----
        if p == "/api/vuln/jwt/profile":
            payload = verify_jwt_broken(auth.replace("Bearer ", "")) if auth else None
            if payload is None:
                return self._send(401, {"error": "invalid token"})
            return self._send(200, {"profile": payload})

        # ---- JWT-protected endpoint, STRICT verifier (FALSE-POSITIVE TRAP) ----
        # Rejects garbage/alg=none/tamper. Hardened auth should flag NOTHING
        # (except offline weak-secret crack, which is legitimate).
        if p == "/api/safe/jwt/profile":
            payload = verify_jwt_strict(auth.replace("Bearer ", "")) if auth else None
            if payload is None:
                return self._send(401, {"error": "invalid token"})
            return self._send(200, {"profile": payload})

        # ---- SSRF: reflects fetched "internal" content (VULNERABLE) ----
        if p == "/api/vuln/fetch":
            params = dict(kv.split("=", 1) for kv in q.split("&") if "=" in kv)
            url = params.get("url", "")
            if "169.254.169.254" in url and "security-credentials" in url:
                # simulate metadata response
                return self._send(200, {"ami-id": "ami-0abc",
                                        "iam": {"security-credentials":
                                                {"role": "s3-read"}}})
            if "169.254.169.254" in url:
                return self._send(200, {"instance-id": "i-0abc",
                                        "local-ipv4": "10.0.0.5"})
            return self._send(200, {"fetched": url, "bytes": 12})

        # ---- Mass-assignment read views (needed to learn object shape) ----
        if p == "/api/vuln/profile":
            return self._send(200, dict(VULN_PROFILE))
        if p == "/api/safe/profile":
            return self._send(200, dict(SAFE_PROFILE))

        # ---- Secret leak (VULNERABLE) + placeholder (FALSE-POSITIVE TRAP) ----
        if p == "/api/vuln/config":
            # Realistic high-entropy secrets (no 'example'/'123456' substrings).
            return self._send(200, {"aws_key": "AKIA2E0QF7B4TC9DKW8Z",
                                    "google": "AIzaSyB7xQ9zK4mNpRvwT8cLdH6jYqEbGoaK1bM"})
        if p == "/api/safe/config":
            # docs placeholders only — hardened secrets should NOT flag
            return self._send(200, {"api_key": "your-api-key-here",
                                    "token": "example_token_xxxxxxxxxxxx"})

        # ---- WAF simulation: blocks non-browser UAs, bypassable by rotation --
        # Mimics an edge rule that 403s bot/default UAs (no 'Mozilla') but lets
        # real browsers through. The bypass engine forces browser UAs, so it
        # should get past this on the first variant.
        if p == "/api/vuln/wafblock":
            ua = self.headers.get("User-Agent", "")
            xff = self.headers.get("X-Forwarded-For", "")
            # Simulated WAF: requires a real browser UA AND an allow-listed
            # internal client IP. UA rotation alone is not enough — the engine
            # must also add a spoofed origin header, so the retry loop engages.
            if "Mozilla" not in ua or not xff.startswith(("127.", "10.")):
                return self._send(
                    403, "<html><body>Access Denied. Reference #18.abc</body>"
                         "</html>", ctype="text/html")
            return self._send(200, {"ok": True, "secret_data": "protected"})

        # ---- JWKS for algorithm-confusion (not exploitable here; HS256 mock) ----
        if p == "/.well-known/jwks.json":
            return self._send(200, {"keys": []})

        return self._send(404, {"error": "not found"})

    def do_PATCH(self):
        self._write()

    def do_PUT(self):
        self._write()

    def do_POST(self):
        self._write()

    def _write(self):
        p = self.path.split("?")[0]
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw)
        except ValueError:
            body = {}

        # ---- Mass assignment: PERSISTS injected role (VULNERABLE) ----
        if p == "/api/vuln/profile":
            for k, v in body.items():
                VULN_PROFILE[k] = v  # BUG: binds whole body
            return self._send(200, dict(VULN_PROFILE))

        # ---- Mass assignment SAFE: echoes but never persists role (TRAP) ----
        if p == "/api/safe/profile":
            echo = dict(SAFE_PROFILE)
            echo.update({k: v for k, v in body.items() if k == "name"})  # whitelist
            resp = dict(echo)
            resp.update(body)  # echoes everything back (but didn't persist role)
            return self._send(200, resp)

        return self._send(404, {"error": "not found"})


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"mock API on http://127.0.0.1:{port}")
    srv.serve_forever()
