"""Low-volume debug of the WAF-bypass engine against a real host.

Read-only GETs, single-digit request count. Purpose: exercise the bypass code
paths against a real WAF to surface bugs in OUR implementation.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from apiharvester.http_client import HTTPClient
from apiharvester.utils import waf_bypass as w

TARGET = sys.argv[1] if len(sys.argv) > 1 else "https://api.myntra.com/"

print(f"\n=== WAF-bypass debug against {TARGET} ===\n")

# 1) Baseline with the default bot UA (bypass OFF).
plain = HTTPClient(timeout=12)
base = plain.request("GET", TARGET)
print(f"[baseline / bot-UA] status={base.status} len={base.length} "
      f"err={base.error!r}")
print(f"   server={base.headers.get('server','')!r} "
      f"waf_vendor={w.detect_waf_vendor(base)!r} "
      f"blocked={w.is_waf_blocked(base)}")

# 2) Single request with a browser UA (still bypass OFF, manual header).
br = plain.request("GET", TARGET,
                   headers={"User-Agent": w.BROWSER_USER_AGENTS[0],
                            **w.BROWSER_HEADERS})
print(f"\n[browser-UA]        status={br.status} len={br.length} "
      f"blocked={w.is_waf_blocked(br)}")

# 3) If baseline looked blocked, run the bounded bypass engine.
if w.is_waf_blocked(base):
    print("\n[bypass engine] baseline blocked — trying bounded variants...")
    resp, tech = w.attempt_bypass(plain, "GET", TARGET, max_variants=6)
    if resp is not None:
        print(f"   ✓ BYPASS WORKED via {tech}: status={resp.status} "
              f"len={resp.length}")
    else:
        print("   ✗ all variants still blocked (WAF held)")
else:
    print("\n[bypass engine] baseline not blocked — engine would no-op (correct)")

# 4) End-to-end: enable the global flag and confirm the wrapper path runs
#    without raising (the integration surface used by --waf-bypass).
print("\n[integration] enabling global --waf-bypass path...")
HTTPClient.enable_waf_bypass()
c2 = HTTPClient(timeout=12)
r2 = c2.request("GET", TARGET)
print(f"   status={r2.status} len={r2.length} "
      f"bypassed={getattr(r2, 'bypassed', False)} "
      f"technique={getattr(r2, 'bypass_technique', '')!r}")
print("\n=== debug complete ===")
