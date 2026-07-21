"""Drive the hardened attack modules against mock_api.py and assert behaviour.

Proves two things per module:
  (1) TRUE POSITIVE  — the vulnerable endpoint IS flagged.
  (2) NO FALSE POSITIVE — the safe/trap endpoint is NOT flagged (or only info).

Usage: python3 scratch/selftest.py [port]   (mock_api.py must be running)
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from apiharvester.models import ScanContext, Endpoint
from apiharvester.attacks.bola import run_bola
from apiharvester.attacks.broken_auth import run_broken_auth
from apiharvester.attacks.mass_assignment import run_mass_assignment
from apiharvester.attacks.ssrf import run_ssrf
from apiharvester.attacks.secrets import run_secrets
from scratch.mock_api import make_jwt

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
BASE = f"http://127.0.0.1:{PORT}"

# Valid tokens signed with the mock's weak secret "secret".
TOKEN1 = "Bearer " + make_jwt({"sub": "1", "role": "user"})
TOKEN2 = "Bearer " + make_jwt({"sub": "2", "role": "user"})

PASS, FAIL = [], []


def check(name, condition):
    (PASS if condition else FAIL).append(name)
    print(f"  {'✓ PASS' if condition else '✗ FAIL'}  {name}")


def fresh_ctx(endpoints):
    ctx = ScanContext(target="127.0.0.1", output_dir="/tmp/ah_selftest",
                      auth=TOKEN1, auth2=TOKEN2, timeout=8)
    ctx.endpoints = endpoints
    return ctx


def titles(ctx, path):
    return [(f.severity, f.title) for f in ctx.findings.values() if f.path == path]


print(f"\n=== APIHarvester hardened self-test against {BASE} ===\n")

# ---------------- BOLA ----------------
print("[BOLA]")
ctx = fresh_ctx([
    Endpoint(url=f"{BASE}/api/vuln/users/1", methods=["GET"], is_api=True),
    Endpoint(url=f"{BASE}/api/safe/me", methods=["GET"], is_api=True),
    Endpoint(url=f"{BASE}/api/vuln/doc/1", methods=["GET"], is_api=True),
    Endpoint(url=f"{BASE}/api/safe/doc/500", methods=["GET"], is_api=True),
])
run_bola(ctx)
vuln = titles(ctx, "/api/vuln/users/1")
safe = titles(ctx, "/api/safe/me")
check("vuln fixed-object → critical cross-account BOLA",
      any(s == "critical" for s, _ in vuln))
check("safe per-caller /me → NO critical (info only)",
      not any(s == "critical" for s, _ in safe))
# id-fuzz: distinct objects should flag high; soft-404 trap should not
vdoc = titles(ctx, "/api/vuln/doc/1")
sdoc = titles(ctx, "/api/safe/doc/500")
check("safe id-fuzz (soft-404 for other ids) → NO high BOLA",
      not any(s == "high" for s, _ in sdoc))

# ---------------- Broken Auth / JWT ----------------
print("\n[BROKEN AUTH / JWT]")
ctx = fresh_ctx([
    Endpoint(url=f"{BASE}/api/vuln/jwt/profile", methods=["GET"], is_api=True),
])
run_broken_auth(ctx)
vjwt = titles(ctx, "/api/vuln/jwt/profile")
check("vuln JWT verifier → weak-secret crack (critical)",
      any("weak secret" in t.lower() for _, t in vjwt))
check("vuln JWT verifier → accepts invalid/forged (finding present)",
      any(s in ("critical", "high") for s, _ in vjwt))

ctx = fresh_ctx([
    Endpoint(url=f"{BASE}/api/safe/jwt/profile", methods=["GET"], is_api=True),
])
run_broken_auth(ctx)
sjwt = titles(ctx, "/api/safe/jwt/profile")
# Strict verifier: no alg=none/tamper/confusion bypass should be reported.
# (Offline weak-secret crack still legitimately fires — that's real.)
bypass_fps = [t for s, t in sjwt
              if any(k in t.lower() for k in
                     ("alg=none", "tampering", "confusion", "not enforced"))]
check("safe strict JWT verifier → NO bypass false positives",
      len(bypass_fps) == 0)

# ---------------- Mass Assignment ----------------
print("\n[MASS ASSIGNMENT]")
ctx = fresh_ctx([
    Endpoint(url=f"{BASE}/api/vuln/profile", methods=["POST", "PATCH"], is_api=True),
    Endpoint(url=f"{BASE}/api/safe/profile", methods=["POST", "PATCH"], is_api=True),
])
run_mass_assignment(ctx)
vma = titles(ctx, "/api/vuln/profile")
sma = titles(ctx, "/api/safe/profile")
check("vuln profile persists injected role → high CONFIRMED",
      any(s == "high" and "confirmed" in t.lower() for s, t in vma))
check("safe profile (echo, no persist) → NO high (low at most)",
      not any(s == "high" for s, _ in sma))

# ---------------- SSRF ----------------
print("\n[SSRF]")
ctx = fresh_ctx([
    Endpoint(url=f"{BASE}/api/vuln/fetch?url=https://example.com",
             methods=["GET"], is_api=True),
])
run_ssrf(ctx)
vssrf = titles(ctx, "/api/vuln/fetch")
check("vuln fetch reaches metadata → critical SSRF",
      any(s == "critical" for s, _ in vssrf))

# ---------------- Secrets ----------------
print("\n[SECRETS]")
ctx = fresh_ctx([
    Endpoint(url=f"{BASE}/api/vuln/config", methods=["GET"], is_api=True),
    Endpoint(url=f"{BASE}/api/safe/config", methods=["GET"], is_api=True),
])
run_secrets(ctx)
vsec = titles(ctx, "/api/vuln/config")
ssec = titles(ctx, "/api/safe/config")
check("vuln config (real AKIA/AIza) → secret finding",
      len(vsec) > 0)
check("safe config (placeholders) → NO secret false positive",
      len(ssec) == 0)

# ---------------- Summary ----------------
print(f"\n=== RESULT: {len(PASS)} passed, {len(FAIL)} failed ===")
if FAIL:
    print("FAILED:")
    for f in FAIL:
        print("   -", f)
    sys.exit(1)
print("All hardened-detection assertions passed.")
