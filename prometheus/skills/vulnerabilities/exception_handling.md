---
name: exception_handling
description: Exception handling failure testing covering stack trace leakage, verbose error messages, fail-secure behavior, and error-based information disclosure
---

# Exception Handling Failures

OWASP A10 — Improper exception handling reveals implementation details, internal paths, technology versions, and system architecture to attackers. Stack traces, verbose error messages, and fail-unsafe behavior provide reconnaissance data that accelerates exploitation of other vulnerabilities.

## Attack Surface

**Error Response Content**
- Stack traces in HTML/JSON/XML error responses
- Internal file paths and directory structures
- Database connection strings and query fragments
- Technology versions and framework identifiers
- Internal IP addresses and hostnames

**Error Behavior Patterns**
- Fail-open vs fail-secure authentication/authorization
- Unhandled exception paths bypassing security controls
- Different error responses for valid vs invalid inputs (oracle)
- Timeout behavior revealing internal processing

**Information Disclosure Vectors**
- Custom error pages not configured for all HTTP methods
- Debug endpoints and development tools in production
- API error responses with excessive detail
- Client-side error handling exposing server details

## Key Vulnerabilities

### Stack Trace Leakage

**Detection Patterns**
```bash
# Java stack traces
curl -s "https://target.com/api/invalid" | grep -i "at com\.\|java\.lang\.\|Exception\|Caused by\|\.java:"
curl -s "https://target.com/api/invalid" | grep -i "org\.springframework\|org\.hibernate\|java\.sql\."

# Python stack traces
curl -s "https://target.com/api/invalid" | grep -i "Traceback\|File \"\|\.py\", line\|NameError\|TypeError\|AttributeError"
curl -s "https://target.com/api/invalid" | grep -i "Django\|Flask\|FastAPI\|werkzeug"

# .NET stack traces
curl -s "https://target.com/api/invalid" | grep -i "Server Error\|Stack Trace:\|at System\.\|at Microsoft\.\|\.cs:line"
curl -s "https://target.com/api/invalid" | grep -i "ASP\.NET\|IIS\|Unhandled exception"

# PHP stack traces
curl -s "https://target.com/api/invalid" | grep -i "Fatal error\|Parse error\|Warning:\|Notice:\|on line\|in /var/www"
curl -s "https://target.com/api/invalid" | grep -i "Symfony\\Component\|Laravel\|vendor/"

# Ruby stack traces
curl -s "https://target.com/api/invalid" | grep -i "NoMethodError\|ActiveRecord\|Rails\|\.rb:in\|\.rb:\d"

# Node.js stack traces
curl -s "https://target.com/api/invalid" | grep -i "Error:\|at Object\.\|at Module\.\|node_modules\|\.js:\d"
```

**Triggering Stack Traces**
```bash
# Type confusion / invalid types
curl -s "https://target.com/api/users?id[]=1&id[]=2"
curl -s "https://target.com/api/users?id=abc"  # Expect integer
curl -s -X POST "https://target.com/api/data" \
  -H "Content-Type: application/json" \
  -d '{"data": [1, "two", null, {}, []]}'

# Boundary conditions
curl -s "https://target.com/api/users?id=99999999999999999999"
curl -s "https://target.com/api/search?q=$(python3 -c 'print("A"*10000)')"

# Invalid content types
curl -s -X POST "https://target.com/api/data" \
  -H "Content-Type: application/xml" \
  -d '<invalid>xml'

# Missing required fields
curl -s -X POST "https://target.com/api/users" \
  -H "Content-Type: application/json" \
  -d '{}'

# Null/empty values
curl -s "https://target.com/api/users?id="
curl -s "https://target.com/api/users?id=null"

# Special characters
curl -s "https://target.com/api/search?q=%00"  # Null byte
curl -s "https://target.com/api/search?q=\\\\"  # Escape sequence
curl -s "https://target.com/api/search?q=\${jndi:ldap://test}"  # Log4Shell probe
```

### Verbose Error Messages

**Information Extraction**
```bash
# Database error messages
# SQL syntax errors revealing table/column names
curl -s "https://target.com/api/search?q='" | grep -i "syntax error\|column\|table\|SQL\|query"
curl -s "https://target.com/api/search?q=1 UNION SELECT 1" | grep -i "error\|columns\|select"

# Internal paths
curl -s "https://target.com/nonexistent" | grep -oP '/[a-zA-Z/]+\.(py|java|rb|js|php|cs|conf|yml)'

# Technology versions
curl -s "https://target.com/" -I | grep -i "server:\|x-powered-by:\|x-aspnet-version:"
curl -s "https://target.com/api/error" | grep -iE "version|v[0-9]+\.[0-9]+"

# Configuration leaks
curl -s "https://target.com/api/error" | grep -i "connection string\|password\|secret\|key\|token\|config"

# Internal IP addresses
curl -s "https://target.com/api/error" | grep -oP '\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b'
```

**Different Error Responses (Oracle)**
```bash
# Username enumeration via different errors
curl -s -X POST "https://target.com/api/login" -d "username=admin&password=wrong"
curl -s -X POST "https://target.com/api/login" -d "username=nonexistent&password=wrong"
# If responses differ → username enumeration

# IDOR verification via error differences
curl -s "https://target.com/api/users/1" -H "Authorization: Bearer *** other-user-token"
# "Access denied" vs "Not found" reveals existence

# SQL injection oracle
curl -s "https://target.com/api/search?q=test'" | grep -i "SQL\|syntax\|query"
curl -s "https://target.com/api/search?q=test\"" | grep -i "SQL\|syntax\|query"
```

### Fail-Open vs Fail-Secure

**Authentication Bypass Testing**
```bash
# Test behavior when auth service is unavailable
# Block auth endpoint and retry (may require network manipulation)
# Some applications fail-open and allow access

# Test with expired/malformed tokens
curl -s "https://target.com/api/protected" \
  -H "Authorization: Bearer expired.token.here"
curl -s "https://target.com/api/protected" \
  -H "Authorization: Bearer malformed"
curl -s "https://target.com/api/protected" \
  -H "Authorization: "

# Test with missing auth headers
curl -s "https://target.com/api/protected"
curl -s "https://target.com/api/protected" -H "Authorization:"

# Test with null session
curl -s "https://target.com/api/protected" \
  -H "Cookie: session=null"
curl -s "https://target.com/api/protected" \
  -H "Cookie: session=undefined"

# Race condition on auth check
# Send many requests simultaneously — some may bypass auth during error handling
for i in $(seq 1 100); do
  curl -s "https://target.com/api/protected" &
done
wait
```

**Authorization Bypass via Errors**
```bash
# Test role-based access with error conditions
# Send request that might cause authorization check to error
curl -s -X PUT "https://target.com/api/admin/settings" \
  -H "Authorization: Bearer *** user-token" \
  -d '{"setting": null}'

# Test with malformed role claims
# If JWT parsing fails, does the app default to authorized or unauthorized?
```

### Unhandled Exception Paths

```bash
# Test HTTP methods not expected by application
curl -s -X PATCH "https://target.com/api/users/1"
curl -s -X DELETE "https://target.com/api/health"
curl -s -X OPTIONS "https://target.com/api/users"
curl -s -X TRACE "https://target.com/"
curl -s -X TRACK "https://target.com/"

# Test with unexpected content types
curl -s -X POST "https://target.com/api/data" \
  -H "Content-Type: multipart/form-data" \
  -d 'test'
curl -s -X POST "https://target.com/api/data" \
  -H "Content-Type: text/plain" \
  -d 'test'

# Test with very large payloads
python3 -c "print('A'*1000000)" | curl -s -X POST "https://target.com/api/data" -d @-

# Test with chunked encoding
curl -s -X POST "https://target.com/api/data" \
  -H "Transfer-Encoding: chunked" \
  --data-binary "FFFFFFFF\r\n$(python3 -c "print('A'*(2**32-1))")\r\n0\r\n"
```

## Automated Error Discovery

**ffuf Error Pattern Detection**
```bash
# Find endpoints that return detailed errors
ffuf -u https://target.com/FUZZ \
  -w /path/to/endpoints.txt \
  -mc 500 \
  -fr "An error occurred"  # Filter generic errors

# Test different input types across endpoints
ffuf -u https://target.com/api/FUZZ \
  -w /path/to/endpoints.txt \
  -X POST \
  -d '{"test": "FUZZ"}' \
  -H "Content-Type: application/json" \
  -mc 500,400 \
  -fw 1  # Filter by response size
```

**Custom Error Enumeration Script**
```bash
#!/bin/bash
# Test various error conditions across endpoints
ENDPOINTS=("/api/users" "/api/data" "/api/search" "/api/auth")

for endpoint in "${ENDPOINTS[@]}"; do
  echo "=== Testing $endpoint ==="

  # Missing parameters
  curl -s "https://target.com$endpoint" | grep -i "error\|exception\|trace"

  # Invalid types
  curl -s "https://target.com$endpoint?id=abc" | grep -i "error\|exception\|trace"

  # Boundary values
  curl -s "https://target.com$endpoint?id=999999999999" | grep -i "error\|exception\|trace"

  # Special characters
  curl -s "https://target.com$endpoint?id=%00" | grep -i "error\|exception\|trace"
done
```

## Error Response Analysis

**Content-Type Specific Analysis**
```bash
# JSON API errors
curl -s "https://target.com/api/error" | jq '.'
# Look for: stack, trace, message, details, debug, error.code

# HTML error pages
curl -s "https://target.com/error" | grep -oP '<pre>.*?</pre>'
curl -s "https://target.com/error" | grep -oP '<code>.*?</code>'

# XML error responses
curl -s "https://target.com/api/error" | xmllint --format -
```

**Error Response Headers**
```bash
# Check for debugging headers
curl -sI "https://target.com/error" | grep -i "x-debug\|x-error\|x-trace\|x-request-id"

# Check for framework-specific headers
curl -sI "https://target.com/error" | grep -i "x-powered-by\|x-aspnet\|x-rails"
```

## Testing Methodology

1. **Error trigger mapping** — Identify all input points that can trigger application errors
2. **Stack trace detection** — Test each endpoint for verbose error responses
3. **Information extraction** — Analyze error content for internal paths, versions, configs
4. **Oracle identification** — Compare error responses to find information disclosure oracles
5. **Fail behavior testing** — Verify fail-secure behavior for auth and authorization
6. **Unhandled paths** — Test unexpected HTTP methods, content types, and edge cases
7. **Error response headers** — Check for debug headers and framework disclosure
8. **Client-side errors** — Verify JavaScript error handling doesn't expose server details

## Validation

1. Show stack trace or verbose error revealing internal implementation details
2. Demonstrate error-based oracle enabling username enumeration or data inference
3. Prove fail-open behavior allowing authentication/authorization bypass
4. Identify unhandled exception path that bypasses security controls
5. Extract sensitive configuration or credential data from error messages

## Remediation

- Implement custom error pages for all HTTP error codes (400, 401, 403, 404, 500, etc.)
- Never return stack traces or internal details to clients in production
- Use generic error messages ("An error occurred") without implementation details
- Log detailed errors server-side for debugging without exposing to users
- Implement fail-secure defaults — deny access on authentication/authorization errors
- Remove debug headers (X-Debug, X-Powered-By) from production responses
- Configure framework-specific error handling (DEBUG=False in Django, customErrors in .NET)
- Implement error monitoring (Sentry, Bugsnag) that captures details without exposing them
- Regular error response review as part of security testing

## Pro Tips

1. Test both authenticated and unauthenticated error responses — behavior often differs
2. Check API vs web UI error responses — APIs often have more verbose errors
3. Error messages may change between staging and production — test both if accessible
4. Some frameworks only show stack traces for specific IP ranges (10.x, 172.x, 192.168.x)
5. Check WebSocket and gRPC error handling — often less hardened than HTTP
6. Rate limiting can be an oracle — different errors for rate-limited vs invalid input
7. Monitor error rates during testing — spikes may indicate security weaknesses

## Summary

Exception handling failures are a rich source of reconnaissance data and potential bypass vectors. Stack traces reveal implementation details, verbose errors create oracles for further attacks, and fail-open behavior directly enables unauthorized access. Every error path in the application must be tested for information leakage and secure failure behavior.
