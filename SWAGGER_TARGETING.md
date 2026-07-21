# Swagger/OpenAPI Spec Targeting

API Harvester now performs **deep analysis of OpenAPI/Swagger specs** to inform attack design. Instead of treating specs as just an endpoint source, they're used to understand what the API *should* accept and do — then test whether the actual implementation deviates.

## What's Extracted from Specs

### 1. Security Schemes

Auth methods defined in `securityDefinitions` (Swagger 2.0) or `components.securitySchemes` (OpenAPI 3.0):

```json
"components": {
  "securitySchemes": {
    "bearerAuth": {"type": "http", "scheme": "bearer"},
    "apiKey": {"type": "apiKey", "name": "X-API-Key", "in": "header"},
    "oauth2": {"type": "oauth2", "flows": {...}}
  }
}
```

**Used for:** Auth bypass testing — if the spec says only Bearer tokens are allowed, test what happens when you omit it, use wrong scheme, or try API-Key.

### 2. Parameter Enums

All enum values for parameters across endpoints:

```json
"parameters": [
  {"name": "status", "in": "query", "schema": {"enum": ["active", "inactive", "pending"]}}
]
```

Extracted as: `{"status": ["active", "inactive", "pending"], "role": ["admin", "user", "guest"]}`

**Used for:** Business logic testing — test state transitions (e.g., can you set a status to an invalid value? Can you transition from inactive → active?). All enum values are probed.

### 3. Request Body Schemas

Fields the API says it accepts in POST/PUT/PATCH bodies:

```json
"requestBody": {
  "content": {
    "application/json": {
      "schema": {
        "type": "object",
        "properties": {
          "name": {"type": "string"},
          "email": {"type": "string"},
          "role": {"type": "string", "enum": ["user", "admin"]},
          "isVerified": {"type": "boolean"},
          "tier": {"type": "integer"}
        }
      }
    }
  }
}
```

**Used for:** Mass Assignment testing — inject all these fields into a PUT body and see which ones the server actually accepts and persists. Privilege escalation: can a regular user set `role: "admin"` or `tier: 999`?

### 4. Response Schemas

Object fields returned by endpoints:

```json
"responses": {
  "200": {
    "schema": {
      "type": "object",
      "properties": {
        "id": {"type": "integer"},
        "name": {"type": "string"},
        "email": {"type": "string"},
        "role": {"type": "string"},
        "passwordHash": {"type": "string"}
      }
    }
  }
}
```

**Used for:** BOLA/IDOR testing — response schemas tell us what fields to expect, so we can detect when we've successfully read another user's data. Secrets detection — if a field like `passwordHash` or `apiKey` is in the response schema, flag it as sensitive data leakage.

### 5. Field Constraints

Min/max values, string patterns, formats:

```json
"schema": {
  "type": "object",
  "properties": {
    "age": {"type": "integer", "minimum": 0, "maximum": 150},
    "email": {"type": "string", "pattern": "^[^@]+@[^@]+$", "format": "email"},
    "name": {"type": "string", "minLength": 1, "maxLength": 100}
  }
}
```

**Used for:** Reliability/boundary testing — test values outside the spec's constraints (age: -1, age: 9999, email: "invalid", name: "" or oversized string). Find validation bugs and edge cases.

## Example: Using Spec Data in Attacks

### Mass Assignment (Injecting Spec-Defined Fields)

```python
from apiharvester.recon.swagger_targeting import get_writable_fields

def run_mass_assignment(ctx, endpoints):
    for ep in endpoints:
        if "PUT" not in ep.methods:
            continue

        # Get fields the spec says are writable
        writable = get_writable_fields(ctx, ep)
        if not writable:
            continue

        # Try injecting all of them + privilege fields
        payload = {**writable, "role": "admin", "is_verified": True, "tier": 999}
        resp = client.request("PUT", ep.url, json=payload)
        
        # Check if privilege fields were accepted
        if "role" in resp.body and "admin" in resp.body:
            # Mass assignment vulnerability confirmed
```

### Enum Value Business Logic Testing

```python
from apiharvester.recon.swagger_targeting import get_enum_values

def run_business_logic(ctx, endpoints):
    for ep in endpoints:
        # Get all enum values for "status" parameter
        status_values = get_enum_values(ctx, "status", ep.host)
        
        for status in status_values:
            # Test state transition: can we set any status directly?
            resp = client.request("PUT", ep.url, json={"status": status})
            # Validate the response matches expected state
```

### Boundary/Constraint Testing

```python
from apiharvester.recon.swagger_targeting import get_field_constraints

def run_reliability(ctx, endpoints):
    for ep in endpoints:
        for field_name in ep.params:
            cons = get_field_constraints(ctx, field_name)
            if not cons:
                continue

            # Test boundary violations
            if "minimum" in cons:
                # Test below minimum
                test_val = cons["minimum"] - 1
                resp = client.request("GET", f"{ep.url}?{field_name}={test_val}")
                if resp.status == 500:
                    # Boundary bug found
            
            if "maximum" in cons:
                # Test above maximum
                test_val = cons["maximum"] + 1000
                resp = client.request("GET", f"{ep.url}?{field_name}={test_val}")
```

## How It Integrates into the Pipeline

**Phase 6: Swagger/OpenAPI Discovery**

1. Probes common spec paths (`/swagger.json`, `/openapi.json`, `/v1/api-docs`)
2. Fetches and validates specs
3. **NEW**: Analyzes each spec with `analyze_spec()` → extracts security, enums, schemas, constraints
4. Stores analysis in `ctx.swagger_analysis[domain]` for all attack modules to access
5. Adds endpoints from spec to discovery list

**Attack Modules (Phase 9+)**

Attacks now call helper functions to get spec-informed test data:

```python
from apiharvester.recon.swagger_targeting import (
    get_enum_values, get_writable_fields, get_response_fields,
    get_field_constraints, get_auth_schemes
)

# Test enum values for BOLA
status_values = get_enum_values(ctx, "status", endpoint.host)

# Test writable fields for mass assignment
writable = get_writable_fields(ctx, endpoint)

# Validate response against schema
response_fields = get_response_fields(ctx, endpoint)

# Test boundary violations
constraints = get_field_constraints(ctx, "age")

# Check auth methods
auth = get_auth_schemes(ctx, endpoint.host)
```

## Files

- **`apiharvester/recon/swagger_parser.py`** — Analyzers for specs (security, enums, schemas, constraints)
- **`apiharvester/recon/swagger_finder.py`** — Modified to call `analyze_spec()` and store results
- **`apiharvester/recon/swagger_targeting.py`** — Helper functions for attacks to access spec data
- **`apiharvester/models.py`** — Added `ScanContext.swagger_analysis` field

## Example Output

When a spec is discovered:

```
[*] Phase 6 (swagger):   Found spec: https://api.example.com/openapi.json
[*] Phase 6 (swagger):     Auth: bearer, apiKey
[*] Phase 6 (swagger):     Enums: 8 param(s) with enum values
[*] Phase 6 (swagger):     Request bodies: 12 endpoint(s)
[*] Phase 6 (swagger): Specs found: 1, endpoints from specs: 47
```

Attacks access this data transparently:

```python
# In mass_assignment.py
writable_fields = get_writable_fields(ctx, endpoint)
if writable_fields:
    # Test these specific fields, not generic ones
```

## Benefits

1. **Spec-Driven Testing** — Test what the API *says* it should do, detect deviations
2. **Reduced False Positives** — Enums from specs are real values the API expects
3. **Smarter Payloads** — Mass assignment tests actual writable fields, not guesses
4. **Boundary Bug Hunting** — Field constraints reveal edge cases to test
5. **Auth Testing** — Security schemes from spec inform what to bypass
6. **Business Logic Coverage** — Enum values expose state transitions to test
