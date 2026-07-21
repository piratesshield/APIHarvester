"""Test path parameter extraction and Phase 7b integration."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from apiharvester.models import ScanContext, Endpoint
from apiharvester.recon.param_extraction import extract_endpoint_params

# Create mock context with templated endpoints
ctx = ScanContext(target="test", output_dir="/tmp/test")

# Add endpoints with path parameters (like from Swagger spec)
endpoints_with_params = [
    Endpoint(url="https://api.example.com/api/v2/score/league/{slug}/meeting/{meetingId}"),
    Endpoint(url="https://api.example.com/api/v2/user/{userId}/profile"),
    Endpoint(url="https://api.example.com/api/search?q=test&limit=10"),
    Endpoint(url="https://api.example.com/api/simple"),  # no params
]

for ep in endpoints_with_params:
    ctx.endpoints.append(ep)

print("Before extraction:")
for ep in ctx.endpoints:
    print(f"  {ep.url}: params={ep.params}")

# Run extraction
count = extract_endpoint_params(ctx)

print(f"\nAfter extraction ({count} params found):")
for ep in ctx.endpoints:
    if ep.params:
        print(f"  {ep.url}: params={ep.params}")

# Verify
assert "slug" in ctx.endpoints[0].params, "slug not extracted"
assert "meetingId" in ctx.endpoints[0].params, "meetingId not extracted"
assert "userId" in ctx.endpoints[1].params, "userId not extracted"
assert "q" in ctx.endpoints[2].params, "query param q not extracted"
assert "limit" in ctx.endpoints[2].params, "query param limit not extracted"
assert len(ctx.endpoints[3].params) == 0, "endpoint with no params should have none"

print("\n✓ All assertions passed")
print("✓ Path parameter extraction working correctly")
