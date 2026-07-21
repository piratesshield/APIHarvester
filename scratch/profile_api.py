"""Debug script: probe an API endpoint and print its profile.

Usage: python3 scratch/profile_api.py <url>
Example: python3 scratch/profile_api.py https://api.myntra.com/auth/v1/refresh
"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from apiharvester.recon.api_profiler import profile_api
from apiharvester.models import ScanContext

TARGET = sys.argv[1] if len(sys.argv) > 1 else "https://api.myntra.com/auth/v1/refresh"

print(f"\n=== API Profile: {TARGET} ===\n")

ctx = ScanContext(target="debug", output_dir="/tmp/debug")
profile = profile_api(ctx, TARGET, timeout=8)

print("\n=== Profile Summary ===")
print(json.dumps(profile.to_dict(), indent=2))

print("\n=== Genuine Request Example ===")
print(f"Headers to use for requests to this API:")
for k, v in profile.preferred_headers.items():
    print(f"  {k}: {v}")

if profile.auth_schemes:
    print(f"\nAuth hint: {profile.auth_schemes[0]} @ {profile.auth_header_name}")

print(f"\nHTTP versions (prefer in order): {profile.http_versions}")
print(f"API Type: {profile.api_type}")
