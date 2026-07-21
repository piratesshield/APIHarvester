"""Deterministic test of the WAF-bypass engine against the local mock.

Proves the full block->bypass->success path AND the no-false-positive path,
without touching any third-party host. Requires mock_api.py running.

Usage: python3 scratch/waf_selftest.py [port]
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from apiharvester.http_client import HTTPClient
from apiharvester.utils import waf_bypass as w

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
BASE = f"http://127.0.0.1:{PORT}"
PASS, FAIL = [], []


def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(f"  {'✓ PASS' if cond else '✗ FAIL'}  {name}")


print(f"\n=== WAF-bypass engine self-test against {BASE} ===\n")

# 1) Default bot UA is blocked (403 Access Denied) by the mock WAF rule.
plain = HTTPClient(timeout=6)
blocked = plain.request("GET", f"{BASE}/api/vuln/wafblock")
check("bot UA is blocked (403)", blocked.status == 403)
check("is_waf_blocked() detects the 403 block", w.is_waf_blocked(blocked))

# 2) attempt_bypass rotates to a browser UA and gets through.
resp, tech = w.attempt_bypass(plain, "GET", f"{BASE}/api/vuln/wafblock")
check("bypass engine gets past the WAF (200)", resp is not None and resp.status == 200)
check("bypassed response contains protected data",
      resp is not None and "protected" in (resp.body or ""))
print(f"     technique that worked: {tech}")

# 3) A normal 200/404 must NOT be seen as blocked (the Akamai-header bug).
ok = plain.request("GET", f"{BASE}/api/safe/config")  # 200 JSON
check("normal 200 is NOT flagged blocked (no amplification)",
      not w.is_waf_blocked(ok))
missing = plain.request("GET", f"{BASE}/api/does-not-exist")  # 404
check("plain 404 is NOT flagged blocked", not w.is_waf_blocked(missing))

# 4) Global --waf-bypass path: enabling it makes a normal request transparently
#    succeed on the blocked endpoint, and does NOT retry on already-good ones.
HTTPClient.enable_waf_bypass()
c2 = HTTPClient(timeout=6)
auto = c2.request("GET", f"{BASE}/api/vuln/wafblock")
check("--waf-bypass path auto-clears the block (200)", auto.status == 200)
check("--waf-bypass marks response.bypassed=True",
      getattr(auto, "bypassed", False) is True)
HTTPClient.ROTATE_UA = False
HTTPClient.BYPASS_ON_BLOCK = False

print(f"\n=== RESULT: {len(PASS)} passed, {len(FAIL)} failed ===")
if FAIL:
    for f in FAIL:
        print("   -", f)
    sys.exit(1)
print("WAF-bypass engine verified.")
