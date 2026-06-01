---
name: js_bundle_analysis
description: Extract API endpoints, secrets, hidden parameters, and internal routes from frontend JavaScript bundles
---

# JS Bundle Analysis

Modern SPAs (React, Vue, Angular, Next.js, Nuxt) compile application logic, API routes, environment variables, and internal configuration into client-side JavaScript bundles. These bundles are a reconnaissance goldmine: API endpoints, authentication flows, hidden parameters, internal service URLs, environment secrets, and logic that reveals authorization bypass vectors. Treat every `.js` bundle as a potential source disclosure.

## Attack Surface

**Scope**
- Webpack/Vite/Rollup/Parcel bundles: `main.*.js`, `vendor.*.js`, `chunk-*.js`, `app.*.js`
- Next.js bundles: `_next/static/chunks/*.js`, `_next/static/webpack/*.js`
- Nuxt.js bundles: `_nuxt/*.js`
- Angular bundles: `main.*.js`, `polyfills.*.js`, `runtime.*.js`, `*.chunk.js`
- Vue CLI: `js/app.*.js`, `js/chunk-vendors.*.js`
- CRA (Create React App): `static/js/main.*.js`, `static/js/2.*.chunk.js`
- Source maps: `*.js.map`, `*.css.map` — often deployed to production accidentally

**Common Bundle Locations**
- `/static/js/`, `/assets/js/`, `/dist/js/`, `/build/static/js/`
- `/_next/static/`, `/_nuxt/`, `/wp-content/themes/*/js/`
- CDN subdomains: `cdn.target.com/static/js/`, `assets.target.com/`

**Discovery**

```bash
# Extract all JS bundle URLs from a page
curl -s https://TARGET/ | grep -oP '(src|href)="[^"]*\.js(\.map)?"' | sort -u

# With more context — find script tags and link preloads
curl -s https://TARGET/ | grep -oP '(?:src|href)="[^"]*\.js[^"]*"' | sed 's/.*"\(.*\)"/\1/' | sort -u

# Recursive crawl for JS files
hakrawler -url https://TARGET -depth 3 -plain | grep '\.js' | sort -u

# gau + httpx for historical JS files
gau TARGET | grep '\.js$' | sort -u | httpx -mc 200 -silent

# Check for source maps in common locations
for js in $(curl -s https://TARGET/ | grep -oP '[^"]+\.js' | head -20); do
  curl -sI "https://TARGET/${js}.map" | head -1
done
```

## High-Value Targets

- API keys, tokens, and secrets embedded in client code (Firebase, AWS, Stripe, SendGrid)
- Internal API endpoints not exposed in public documentation
- Hidden/admin routes and parameters
- Authentication and authorization logic (JWT flows, token refresh, role checks)
- Environment-specific URLs (staging, development, internal services)
- Feature flags and A/B testing configurations
- WebSocket/GraphQL endpoints and subscriptions
- Debug/development endpoints left in production bundles

## Key Techniques

### Source Map Recovery

Source maps (`.js.map` files) contain the original source code before minification/bundling — full variable names, comments, file structure, and even API keys left in comments.

```bash
# Download and extract source map
curl -s https://TARGET/static/js/main.abc123.js.map -o main.js.map

# Use shuji to reconstruct original files from source map
npx shuji main.js.map -o extracted_sources/

# Use reverse-sourcemap
npx reverse-sourcemap -d ./maps -o ./sources https://TARGET/static/js/main.abc123.js.map

# Manual extraction with jq
cat main.js.map | jq -r '.sourcesContent[]' > recovered_sources.txt

# List original file paths from source map
cat main.js.map | jq -r '.sources[]' | head -50

# Automated source map discovery
python3 -c "
import re, requests
html = requests.get('https://TARGET/').text
for js in re.findall(r'src=[\"\\']([^\"\\']+\.js)[\"\\']', html):
    url = f'https://TARGET{js}' if js.startswith('/') else js
    map_url = url + '.map'
    r = requests.get(map_url)
    if r.status_code == 200:
        print(f'[!] Source map found: {map_url}')
"
```

### API Endpoint Extraction

```bash
# Extract API endpoints from bundled JS
curl -s https://TARGET/static/js/main.abc123.js | \
  grep -oP '["'"'"']/api/v\d/[^"'"'"'\s]+["'"'"']' | sort -u

# Broader pattern — any path-like string
curl -s https://TARGET/static/js/main.abc123.js | \
  grep -oP '["'"'"']/[a-zA-Z0-9_/-]{5,}["'"'"']' | sort -u

# Extract fetch/axios/XMLHttpRequest calls
curl -s https://TARGET/static/js/main.abc123.js | \
  grep -oP '(?:fetch|axios|get|post|put|delete|patch)\s*\(\s*["`'"'"'][^"`'"'"']+["`'"'"']' | sort -u

# GraphQL operations
curl -s https://TARGET/static/js/main.abc123.js | \
  grep -oP '(?:query|mutation|subscription)\s+\w+' | sort -u

# Using linkfinder for comprehensive extraction
python3 linkfinder.py -i https://TARGET/static/js/main.abc123.js -o cli

# EndpointFinder — bulk JS analysis
cat js_urls.txt | xargs -I{} python3 linkfinder.py -i {} -o cli 2>/dev/null | sort -u
```

### Secret & Credential Extraction

```bash
# Regex patterns for common secrets in JS bundles
curl -s https://TARGET/static/js/main.abc123.js | grep -oP \
  '(?:api[_-]?key|apikey|secret|token|password|auth|credential|private[_-]?key)\s*[:=]\s*["'"'"'][A-Za-z0-9+/=_-]{16,}["'"'"']' -i

# AWS keys
curl -s https://TARGET/static/js/main.abc123.js | grep -oP 'AKIA[0-9A-Z]{16}'

# Firebase config (common leak)
curl -s https://TARGET/static/js/main.abc123.js | grep -oP 'apiKey["'"'"']?\s*[:=]\s*["'"'"'][^"'"'"']+["'"'"']'

# Stripe keys
curl -s https://TARGET/static/js/main.abc123.js | grep -oP '(pk|sk)_(test|live)_[A-Za-z0-9]{20,}'

# JWT tokens in code
curl -s https://TARGET/static/js/main.abc123.js | grep -oP 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'

# Generic base64 secrets
curl -s https://TARGET/static/js/main.abc123.js | grep -oP 'btoa\(["'"'"'][^"'"'"']+["'"'"']\)' | head -20

# Trufflehog-style entropy scanning on extracted strings
cat bundle.txt | python3 -c "
import sys, re, math
from collections import Counter
for line in sys.stdin:
    for match in re.findall(r'[\"'"'"']([A-Za-z0-9+/=_-]{20,})[\"'"'"']', line):
        s = match
        entropy = -sum((c/len(s))*math.log2(c/len(s)) for c in Counter(s).values()) if len(s)>0 else 0
        if entropy > 3.5 and len(s) > 20:
            print(f'[HIGH ENTROPY] {s[:60]}... (entropy={entropy:.2f})')
"
```

### Hidden Parameters & Feature Flags

```bash
# Extract parameter names from JS bundles
curl -s https://TARGET/static/js/main.abc123.js | \
  grep -oP '(?:params|query|body|data|payload|input)\s*[=:]\s*\{[^}]+\}' | \
  grep -oP '\b[a-zA-Z_][a-zA-Z0-9_]*\s*(?=:|,)'

# Feature flags and config objects
curl -s https://TARGET/static/js/main.abc123.js | \
  grep -oP '(?:FEATURE_|FLAG_|ENABLE_|DISABLE_|CONFIG_)[A-Z_]+' | sort -u

# Environment variables in config objects
curl -s https://TARGET/static/js/main.abc123.js | \
  grep -oP 'process\.env\.[A-Z_]+' | sort -u

# React/Redux state shape (reveals data model)
curl -s https://TARGET/static/js/main.abc123.js | \
  grep -oP '(?:initialState|defaultState|rootReducer)\s*[=:]\s*\{[^}]{0,500}' | head -10
```

### Route & Authorization Logic

```bash
# Extract route definitions (React Router, Vue Router, Angular)
# React Router v6
curl -s https://TARGET/static/js/main.abc123.js | \
  grep -oP '(?:path|Route)\s*:\s*["'"'"']/[^"'"'"']+["'"'"']' | sort -u

# Vue Router
curl -s https://TARGET/static/js/main.abc123.js | \
  grep -oP 'path:\s*["'"'"']/[^"'"'"']+["'"'"']' | sort -u

# Angular routes
curl -s https://TARGET/static/js/main.abc123.js | \
  grep -oP 'path:\s*["'"'"'][^"'"'"']+["'"'"']' | sort -u

# Role/permission checks in code
curl -s https://TARGET/static/js/main.abc123.js | \
  grep -oP '(?:isAdmin|isSuperAdmin|role|permission|canAccess|authorize)\s*[(:]' | sort -u

# Conditional rendering based on roles (reveals admin UI paths)
curl -s https://TARGET/static/js/main.abc123.js | \
  grep -oP '(?:admin|staff|superuser|moderator).*?(?:path|route|redirect)' -i | head -20
```

### Structured Analysis Tools

```bash
# nuclei — JS exposure templates
nuclei -u https://TARGET -t exposures/ -tags js -silent

# retire.js — find vulnerable JS libraries
retire --js https://TARGET/static/js/main.abc123.js

# secretfinder — automated secret detection in JS
python3 secretfinder.py -i https://TARGET/static/js/main.abc123.js -o cli

# JSScanner — bulk JS analysis
python3 jsscanner.py -l js_urls.txt

# Manually review bundle with prettify
curl -s https://TARGET/static/js/main.abc123.js | js-beautify | less

# Download all chunks and search
mkdir bundles && cd bundles
curl -s https://TARGET/ | grep -oP '[^"]+\.js' | while read f; do
  wget -q "https://TARGET/$f" 2>/dev/null
done
grep -rn 'api_key\|secret\|token\|password\|internal\|staging\|dev\.' bundles/ --include='*.js' -i
```

## Bypass Techniques

**Bundle Splitting Detection**
- SPAs split code into chunks — enumerate all chunks, not just the main bundle
- Check webpack chunk manifest: `/static/js/webpack-manifest.json`, `asset-manifest.json`
- For Next.js: check `/_next/static/*/buildManifest.js` for all chunk names

**Minification Bypass**
- Use source maps when available (`.js.map` files)
- Use `js-beautify` or `prettier` to reformat minified code
- Use AST tools (babel, acorn) for structured parsing of minified JS

**Obfuscation Bypass**
- String array rotation patterns: look for `function _0x...` and large string arrays
- Use `de4js` or `synchrony` deobfuscation tools
- Dynamic `eval()` — use `node --inspect` with Chrome DevTools to step through
- WebAssembly obfuscation — check `.wasm` files for hardcoded URLs/tokens

**Authentication Token Recovery**
- Look for `Bearer` token concatenation patterns in request interceptors
- Find refresh token logic: endpoints and conditions for token rotation
- Extract JWT structure: `header.payload.signature` patterns reveal algorithm and claims

## Chaining Attacks

- JS bundle analysis → API endpoint discovery → undocumented API testing → IDOR/privilege escalation
- Source map recovery → full source code → hardcoded credentials → account takeover
- Hidden parameter discovery → mass assignment → admin account creation
- Feature flag extraction → enable disabled features → access beta/admin functionality
- Internal URL discovery → SSRF via server-side fetch to dev/staging environments
- Firebase config extraction → insecure Firestore rules → read/write all documents
- Stripe key extraction → payment manipulation, subscription bypass

## Testing Methodology

1. **Discover bundles** — Crawl target page, extract all JS/script URLs; check `robots.txt`, sitemap for additional JS paths
2. **Download all bundles** — Main bundle + all chunks; check for source maps (`.map` extension)
3. **Extract endpoints** — Regex for URL patterns, fetch/axios calls, GraphQL operations, WebSocket connections
4. **Scan for secrets** — API keys, tokens, passwords, internal URLs, environment variables; use entropy analysis
5. **Analyze routes** — Router definitions, permission checks, role-based conditional rendering, admin paths
6. **Extract parameters** — Request payload shapes, query parameters, hidden form fields, feature flags
7. **Test discovered assets** — Hit undocumented endpoints with different auth levels; try hidden parameters on known endpoints
8. **Check source maps** — If `.map` files exist, reconstruct original source and repeat analysis with full context

## Validation

1. Prove endpoint discovery: hit a non-documented API endpoint and receive valid response (not 404/403)
2. Demonstrate secret validity: use extracted API key/token against the service (Firebase, Stripe, AWS)
3. Show hidden parameter impact: submit extracted parameter and observe behavior change
4. Confirm route access: navigate to discovered admin/hidden route and verify it loads
5. Provide evidence: URL of bundle, line/column of finding, curl command demonstrating the discovery

## False Positives

- Example/template code in bundles (e.g., React boilerplate comments, documentation links)
- CDN/cloud provider default keys that are intentionally public (Firebase `measurementId`, Google Maps public keys)
- Dead code paths referencing removed endpoints (check if endpoint returns 404)
- Type definitions revealing structure but no actual endpoints (`interface User { id: string }`)
- Environment variable references that are replaced at build time (`process.env.NODE_ENV` → `"production"`)
- Obfuscated strings that are actually UI labels, not secrets

## Impact

- Full API surface disclosure enabling systematic attack planning
- Credential/token exposure enabling unauthorized API access
- Internal infrastructure discovery (staging, dev, internal services)
- Hidden admin functionality accessible through discovered routes/parameters
- Business logic disclosure revealing authorization checks, payment flows, data models
- Third-party service compromise via leaked API keys (AWS, GCP, Firebase, Stripe, SendGrid)

## CVSS Scoring

| Scenario | CVSS 3.1 | Vector |
|----------|----------|--------|
| Source map deployed → full source code disclosure | 5.3 | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N |
| Hardcoded API key (read-only, scoped) | 5.3 | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N |
| Hardcoded admin API key or AWS secret | 7.5 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N |
| Hidden admin route with no auth check | 8.1 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
| Firebase config with open read/write rules | 8.2 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L |
| Internal staging URL disclosure → SSRF chain | 6.5 | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N |

## Pro Tips

1. Always check for source maps first — they give you the entire codebase for free
2. Download ALL chunks, not just the main bundle — secrets are often in smaller feature-specific chunks
3. Use `grep -rn` across all bundles at once — patterns may only appear in one chunk
4. Next.js `_next/static/chunks/pages/` reveals the entire page routing structure
5. Firebase config in bundles is extremely common — always check `firebaseConfig` and `initializeApp`
6. Look for `process.env.` references — even if replaced at build time, source maps may contain originals
7. GraphQL queries in bundles reveal the exact schema structure even without introspection
8. The `webpack://` source root in source maps often reveals the full project directory structure
9. Use `linkfinder` in CI/CD pipeline — new endpoints appear with every deploy
10. Check for `.env` files at common paths: `/.env`, `/env.js`, `/config.js`, `/runtime-config.js`
11. Angular apps often expose `environment.ts` and `environment.prod.ts` — check for both in bundles
12. JWT tokens in bundles may be refresh tokens or service-to-service tokens with elevated privileges

## Summary

JavaScript bundles are the source code of client-side applications — they contain API routes, authentication logic, secrets, and the full data model. Source maps make the problem worse by exposing original code. Always enumerate and analyze every bundle chunk, scan for secrets with entropy analysis, and test every discovered endpoint and parameter for authorization and injection flaws.
