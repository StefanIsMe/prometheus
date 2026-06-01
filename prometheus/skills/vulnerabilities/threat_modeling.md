---
name: threat_modeling
description: Threat modeling and insecure design analysis covering abuse case enumeration, architectural flaws, trust boundary analysis, and design-level vulnerabilities
---

# Threat Modeling and Insecure Design Analysis

This skill covers OWASP A06:2021 - Vulnerable and Outdated Components / insecure design patterns. Focus on identifying design-level flaws that cannot be fixed by patching code alone — they require architectural changes.

## Threat Modeling Methodology

### STRIDE Framework

Apply STRIDE to each component and data flow discovered during scanning:

| Threat | Description | What to Look For |
|--------|-------------|------------------|
| **Spoofing** | Impersonating a user or system | Weak auth, missing token validation, predictable session IDs |
| **Tampering** | Modifying data in transit or at rest | No integrity checks, unsigned requests, missing HMAC |
| **Repudiation** | Denying an action was performed | Missing audit logs, no request signing |
| **Information Disclosure** | Leaking sensitive data | Verbose errors, exposed internal IDs, debug endpoints |
| **Denial of Service** | Making system unavailable | No rate limiting, unbounded queries, resource exhaustion |
| **Elevation of Privilege** | Gaining unauthorized access | Missing authz checks, IDOR, mass assignment |

### DREAD Risk Scoring

Score each finding 1-10 for prioritization:

- **Damage**: How bad if exploited? (data breach vs. info leak)
- **Reproducibility**: How easy to reproduce? (always vs. depends on state)
- **Exploitability**: How much skill/effort needed? (browser vs. custom exploit)
- **Affected Users**: How many impacted? (all users vs. one account)
- **Discoverability**: How easy to find? (obvious URL vs. buried parameter)

DREAD Score = (D + R + E + A + D) / 5. Prioritize scores > 7.

### Attack Trees

Build attack trees for high-value targets during scanning:

```
Goal: Access Admin Panel
├── Guess/Brute-force credentials
│   └── No rate limiting → brute force viable
├── Bypass authentication
│   └── Direct access to /admin without session check
├── Session hijacking
│   └── Session cookie missing HttpOnly/Secure flags
└── Privilege escalation
    └── Mass assignment to set role=admin
```

### Applying During a Scan

1. **Map the application**: Discover all endpoints, parameters, and functionality
2. **Identify assets**: What data/actions are valuable? (admin panels, PII, payments)
3. **Enumerate entry points**: Every URL, parameter, header, cookie is an entry point
4. **Apply STRIDE per entry point**: Systematically check each threat category
5. **Score with DREAD**: Prioritize which threats to test first
6. **Build attack trees**: For the top 3-5 high-value targets

## Trust Boundary Analysis

### Identifying Trust Boundaries

Map these boundaries in the target application:

- **Client ↔ Server**: Browser is untrusted, server should validate everything
- **Frontend API ↔ Backend Services**: API gateway vs. internal services
- **Service ↔ Service**: Microservice-to-microservice communication
- **Internal ↔ External**: Corporate network vs. public internet
- **Authenticated ↔ Unauthenticated**: Logged-in vs. anonymous zones
- **User ↔ Admin**: Regular user vs. privileged user zones

### Testing Boundary Crossings

```
# Test 1: Can unauthenticated user reach authenticated endpoints?
# Remove auth headers/cookies and replay requests to protected endpoints
# Expected: 401/403
# Vulnerable: 200 with data

# Test 2: Can regular user reach admin endpoints?
# Use a regular user session and access /admin/*, /api/admin/* paths
# Expected: 403
# Vulnerable: 200 with admin functionality

# Test 3: Can frontend bypass API gateway to reach internal services?
# Check for direct service URLs leaked in JS, error messages, or headers
# Look for: internal hostnames, direct IP addresses, service mesh endpoints

# Test 4: Do internal services trust each other without verification?
# Replay requests with modified origin or without auth tokens
# Expected: Rejected
# Vulnerable: Accepted (implicit trust)
```

### Authentication Boundary Testing

- Test if password reset flow trusts client-provided email/userID
- Test if MFA can be skipped by navigating directly to post-auth endpoints
- Test if session tokens from one app work on another (SSO misconfig)
- Test if account lockout applies across all auth boundaries (API, web, mobile)

### Authorization Boundary Testing

- Test horizontal privilege escalation (access other users' data)
- Test vertical privilege escalation (access admin functions)
- Test if authorization is enforced at API gateway AND at service level
- Test if changing HTTP method (GET→DELETE) bypasses authorization

## Abuse Case Enumeration

### Thinking Like an Attacker

For each feature, ask:

1. **What is the happy path?** → What does the feature expect?
2. **What if I skip steps?** → Can I jump to step 3 from step 1?
3. **What if I repeat steps?** → Can I submit payment twice?
4. **What if I reverse steps?** → Can I cancel after receiving goods?
5. **What if I modify state between steps?** → Change cart total during checkout?
6. **What if I use extreme values?** → Negative quantity, zero price, MAX_INT?

### Business Logic Abuse Patterns

| Pattern | Example | Detection |
|---------|---------|-----------|
| **Price manipulation** | Modify item price in client-side request | Compare client-submitted price vs. server-stored price |
| **Coupon reuse** | Apply same discount code multiple times | Replay coupon application request |
| **Race conditions** | Transfer funds twice before balance updates | Send concurrent identical requests |
| **Workflow bypass** | Skip email verification to access features | Directly access post-verification endpoints |
| **Quantity abuse** | Order -1 items to credit account | Send negative/decimal quantities |
| **Referral abuse** | Self-refer for bonuses | Create accounts with predictable patterns |

### Workflow Bypass Testing

```
# Multi-step process testing (e.g., checkout):
# 1. Identify all steps: cart → shipping → payment → confirmation
# 2. Try accessing step 4 directly: GET /checkout/confirm
# 3. Try skipping payment: POST /checkout/confirm without payment step
# 4. Try modifying cart after payment: POST /checkout/cart after confirm
# 5. Try replaying confirmation: POST /checkout/confirm twice
```

### Edge Case Abuse

- **Negative values**: Negative quantities, prices, offsets
- **Zero values**: Zero-price items, zero-quantity orders
- **Null/empty**: Missing required fields, empty arrays
- **Overflow**: Integer overflow on quantities, buffer sizes
- **Boundary values**: MAX_INT, MIN_INT, 0, -1, empty string
- **Type confusion**: String where number expected, array where object expected

## Architectural Flaws

### Single Points of Failure

- Single authentication server with no fallback
- Single database with no replication
- Single API key for all external integrations
- Hardcoded dependency on specific service instance

### Missing Defense in Depth

- Authentication only at gateway, not at service level
- Input validation only on client side
- Encryption only at transport layer, not at rest
- Logging only at application level, not at infrastructure level

### Insecure Defaults

- Default credentials on admin panels, databases, or services
- Overly permissive CORS policies (`Access-Control-Allow-Origin: *`)
- Debug/development mode enabled in production
- Verbose error messages exposing stack traces
- Default API keys or tokens in configuration

### Missing Security Controls at Architecture Level

- No centralized authentication/authorization service
- No API gateway for rate limiting and request validation
- No secrets management (hardcoded credentials)
- No network segmentation between services
- No centralized logging and monitoring

### Microservice Trust Issues

- Services trusting requests from other services without authentication
- Shared secrets between all services (no per-service credentials)
- No mTLS between services
- Service mesh not enforcing policies
- Cascading failures when one service is compromised

## Design-Level Vulnerabilities

### Mass Assignment

**Design flaw**: Application accepts and processes all fields from client input.

```
# Detection: Send extra fields in requests
POST /api/user/profile
{"name": "John", "role": "admin", "is_verified": true, "credits": 99999}

# Look for: API endpoints that bind request body directly to model objects
# Frameworks affected: Rails (strong parameters bypass), Django, Express, Laravel
```

### Missing Rate Limiting

**Design flaw**: No abuse prevention mechanism on sensitive operations.

```
# Test endpoints that should have rate limiting:
# - Login/registration (brute force)
# - Password reset (enumeration)
# - OTP/MFA verification (bypass via brute force)
# - API keys/tokens (theft via brute force)
# - Payment processing (fraud)
# - File upload (storage exhaustion)

# Detection: Send 100+ rapid requests to sensitive endpoints
# Expected: 429 Too Many Requests after threshold
# Vulnerable: All requests processed
```

### Insecure Direct Object References (IDOR)

**Design flaw**: Exposing internal identifiers that users can manipulate.

```
# Detection patterns:
# - Sequential IDs: /api/users/1, /api/users/2, /api/users/3
# - Predictable UUIDs: /api/documents/550e8400-e29b-41d4-a716-446655440000
# - Internal paths: /api/files/home/app/uploads/user123/report.pdf

# Test: Change ID to another user's ID, access their data
# Better design: Use non-sequential, non-guessable resource identifiers
```

### Missing Encryption

**Design flaw**: Sensitive data transmitted or stored without encryption.

```
# Transit encryption checks:
# - HTTP instead of HTTPS for login/payment endpoints
# - Mixed content (HTTPS page loading HTTP resources)
# - Weak TLS versions (TLS 1.0/1.1)
# - Missing HSTS headers

# At-rest encryption checks:
# - Sensitive fields stored in plaintext (passwords, tokens, PII)
# - Database backups not encrypted
# - Logs containing sensitive data
```

### Verbose Errors

**Design flaw**: Error responses leak implementation details.

```
# Look for in error responses:
# - Stack traces with file paths and line numbers
# - Database error messages (table names, column names, query syntax)
# - Internal IP addresses or hostnames
# - Software version numbers
# - Configuration file contents
# - Memory addresses or internal state

# Test: Trigger errors by sending malformed input to every endpoint
# - Invalid JSON in POST body
# - Invalid Content-Type header
# - Non-existent resource IDs
# - SQL metacharacters in parameters
```

## Testing Methodology

### Performing Threat Modeling During a Scan

1. **Discovery Phase** (first 20% of scan):
   - Crawl/spider the application to map all endpoints
   - Identify technology stack from headers, error pages, file extensions
   - Catalog all input points (URLs, parameters, headers, cookies, body)
   - Identify authentication mechanisms (cookies, JWT, API keys, OAuth)
   - Map data flows (where does user input go?)

2. **Analysis Phase** (next 30% of scan):
   - Classify endpoints by sensitivity (public, authenticated, admin)
   - Identify trust boundaries (auth zones, service boundaries)
   - Build threat model for top 5 high-value targets
   - Prioritize test cases based on DREAD scores

3. **Testing Phase** (remaining 50% of scan):
   - Execute tests based on threat model priority
   - Test boundary crossings first (highest impact)
   - Test design flaws second (mass assignment, missing rate limits)
   - Test edge cases and abuse patterns

### Mapping Attack Surface

Create a mental model of the attack surface:

```
Attack Surface Map:
├── Public Endpoints (no auth required)
│   ├── Login, Registration, Password Reset
│   ├── Public API endpoints
│   └── Static files, robots.txt, sitemap.xml
├── Authenticated Endpoints
│   ├── User profile, settings
│   ├── User-generated content
│   └── API endpoints with user tokens
├── Admin Endpoints
│   ├── Admin panel
│   ├── User management
│   └── System configuration
├── Service Endpoints
│   ├── Internal APIs
│   ├── Webhooks
│   └── Message queues
└── Infrastructure
    ├── DNS, CDN, Load Balancer
    ├── Database, Cache, Storage
    └── Third-party integrations
```

### Identifying High-Value Targets

Prioritize testing on:

1. **Authentication systems** — login, registration, password reset, MFA
2. **Payment/financial endpoints** — checkout, refunds, credits
3. **Admin functionality** — user management, system config
4. **Data export/import** — file upload, bulk operations, reports
5. **API endpoints with sensitive data** — PII, credentials, tokens
6. **State-changing operations** — delete, transfer, modify permissions

## Key Vulnerability Patterns

### Pattern: Implicit Trust in Client Data

```
# Vulnerable: Server trusts client-sent role
POST /api/register
{"username": "attacker", "role": "admin"}

# Vulnerable: Server trusts client-calculated total
POST /api/checkout
{"items": [...], "total": 0.01}

# Vulnerable: Server trusts client-sent redirect URL
GET /login?redirect=https://evil.com
```

### Pattern: Missing Security Boundaries

```
# Vulnerable: Internal API accessible from external network
# No network segmentation — attacker reaches internal service directly

# Vulnerable: Service trusts all requests from internal IP
# Attacker exploits SSRF to make requests from internal IP

# Vulnerable: Single auth check at gateway
# Attacker bypasses gateway via direct service access
```

### Pattern: Security Through Obscurity

```
# Vulnerable: Hiding admin panel at /admin_x8f2k instead of proper auth
# Vulnerable: Using non-standard ports instead of proper firewall rules
# Vulnerable: Obfuscating JavaScript instead of server-side validation
```

## Validation

For each finding, validate by:

1. **Reproducing the issue** — Can you trigger it reliably?
2. **Assessing impact** — What data/actions can be accessed?
3. **Determining scope** — Does it affect all users or specific conditions?
4. **Checking exploitability** — What skill/tools are needed?
5. **Confirming it's a design flaw** — Not just a code bug, but a missing control

## Remediation

### For Design-Level Issues

| Issue | Remediation |
|-------|-------------|
| Mass assignment | Use explicit allowlists for accepted fields (strong parameters) |
| Missing rate limiting | Implement rate limiting on all sensitive endpoints |
| IDOR | Use indirect references or enforce ownership checks |
| Missing encryption | Enforce TLS everywhere, encrypt sensitive data at rest |
| Verbose errors | Return generic errors, log details server-side |
| Missing auth boundaries | Enforce auth at every service, not just gateway |
| Implicit trust | Validate and authorize all input at every trust boundary |
| No audit logging | Log all state-changing operations with user context |

### For Architectural Issues

- Implement defense in depth: auth at gateway AND service level
- Use secrets management (Vault, AWS Secrets Manager)
- Implement network segmentation between services
- Use mTLS for service-to-service communication
- Deploy centralized logging and monitoring
- Implement circuit breakers for service dependencies
- Use parameterized queries and input validation at every layer
