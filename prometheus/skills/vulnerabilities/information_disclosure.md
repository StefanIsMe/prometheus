---
name: information-disclosure
description: Information disclosure testing covering error messages, debug endpoints, metadata leakage, and source exposure
---

# Information Disclosure

Information leaks accelerate exploitation by revealing code, configuration, identifiers, and trust boundaries. Treat every response byte, artifact, and header as potential intelligence. Minimize, normalize, and scope disclosure across all channels.

## Attack Surface

- Errors and exception pages: stack traces, file paths, SQL, framework versions
- Debug/dev tooling reachable in prod: debuggers, profilers, feature flags
- DVCS/build artifacts and temp/backup files: .git, .svn, .hg, .bak, .swp, archives
- Configuration and secrets: .env, phpinfo, appsettings.json, Docker/K8s manifests
- API schemas and introspection: OpenAPI/Swagger, GraphQL introspection, gRPC reflection
- Client bundles and source maps: webpack/Vite maps, embedded env, `__NEXT_DATA__`, static JSON
- Headers and response metadata: Server/X-Powered-By, tracing, ETag, Accept-Ranges, Server-Timing
- Storage/export surfaces: public buckets, signed URLs, export/download endpoints
- Observability/admin: /metrics, /actuator, /health, tracing UIs (Jaeger, Zipkin), Kibana, Admin UIs
- Directory listings and indexing: autoindex, sitemap/robots revealing hidden routes

## High-Value Surfaces

### Errors and Exceptions

- SQL/ORM errors: reveal table/column names, DBMS, query fragments
- Stack traces: absolute paths, class/method names, framework versions, developer emails
- Template engine probes: `{{7*7}}`, `${7*7}` identify templating stack
- JSON/XML parsers: type mismatches leak internal model names

### Debug and Env Modes

- Debug pages: Django DEBUG, Laravel Telescope, Rails error pages, Flask/Werkzeug debugger, ASP.NET customErrors Off
- Profiler endpoints: `/debug/pprof`, `/actuator`, `/_profiler`, custom `/debug` APIs
- Feature/config toggles exposed in JS or headers

### DVCS and Backups

- DVCS: `/.git/` (HEAD, config, index, objects), `.svn/entries`, `.hg/store` → reconstruct source and secrets
- Backups/temp: `.bak`/`.old`/`~`/`.swp`/`.swo`/`.tmp`/`.orig`, db dumps, zipped deployments
- Build artifacts: dist artifacts containing `.map`, env prints, internal URLs

### Configs and Secrets

- Classic: web.config, appsettings.json, settings.py, config.php, phpinfo.php
- Containers/cloud: Dockerfile, docker-compose.yml, Kubernetes manifests, service account tokens
- Credentials and connection strings; internal hosts and ports; JWT secrets

### API Schemas and Introspection

- OpenAPI/Swagger: `/swagger`, `/api-docs`, `/openapi.json` — enumerate hidden/privileged operations
- GraphQL: introspection enabled; field suggestions; error disclosure via invalid fields
- gRPC: server reflection exposing services/messages

### Client Bundles and Maps

- Source maps (`.map`) reveal original sources, comments, and internal logic
- Client env leakage: `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_` variables; embedded secrets
- `__NEXT_DATA__` and pre-fetched JSON can include internal IDs, flags, or PII

### JavaScript Bundle Analysis (for SPAs — REPORTABLE)

This is a mandatory step for any SPA (React, Vue, Angular, Svelte). Do NOT skip.

**Step 1: Extract bundle URLs from the page**
```bash
curl -s https://target.com/ | grep -oE 'src="[^"]*\.js[^"]*"' | head -20
# Also check for CSS bundles that may contain font URLs
curl -s https://target.com/ | grep -oE 'href="[^"]*\.css[^"]*"' | head -10
```

**Step 2: Download and scan each bundle for secrets**
```bash
# Download bundle
curl -s "$BUNDLE_URL" -o /tmp/bundle.js

# Scan for secrets
grep -oiE '(api[_-]?key|secret|token|password|credential|private)[=:]["'"'"'][^"'"'"']*' /tmp/bundle.js
grep -oE 'sk-[a-zA-Z0-9]{20,}' /tmp/bundle.js          # OpenAI
grep -oE 'AIza[a-zA-Z0-9_-]{35}' /tmp/bundle.js         # Google
grep -oE 'ghp_[a-zA-Z0-9]{36}' /tmp/bundle.js           # GitHub
grep -oE 'xoxb-[0-9]+-[a-zA-Z0-9]+' /tmp/bundle.js      # Slack
grep -oE 'SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43}' /tmp/bundle.js  # SendGrid
grep -oE 'v1\\.0-[a-zA-Z0-9]{2}-[a-zA-Z0-9_-]{20,}' /tmp/bundle.js    # Cloudflare API Token
grep -oE 'CLOUDFLARE_API_TOKEN[=:]["'"'"'][^"'"'"']+' /tmp/bundle.js   # CF token in env
grep -oE 'CF_API_TOKEN[=:]["'"'"'][^"'"'"']+' /tmp/bundle.js           # CF token shorthand
grep -oE 'CF_API_KEY[=:]["'"'"'][^"'"'"']+' /tmp/bundle.js             # CF global key
# Supabase
grep -oE 'SUPABASE_SERVICE_ROLE_KEY[=:]["'"'"'][^"'"'"']+' /tmp/bundle.js  # Supabase service_role (SECRET)
grep -oE 'https://[a-z0-9]+\.supabase\.co' /tmp/bundle.js                  # Supabase project URL
# Firebase
grep -oE '"private_key":\s*"-----BEGIN' /tmp/bundle.js                     # Firebase SA private key (SECRET)
grep -oE '"client_email":\s*"[^"]+@[^"]+\.iam\.gserviceaccount\.com"' /tmp/bundle.js  # GCP SA email
# Azure
grep -oE 'AccountKey=[a-zA-Z0-9+/]{80,}==' /tmp/bundle.js                 # Azure storage account key
grep -oE 'sig=[a-zA-Z0-9%/+]+=*' /tmp/bundle.js                           # Azure SAS token signature
grep -oE 'DefaultEndpointsProtocol=[^;]+;AccountName=[^;]+;AccountKey=[^;]+' /tmp/bundle.js  # Azure connection string
# GCP
grep -oE '"private_key":\s*"-----BEGIN' /tmp/bundle.js                     # GCP service account key
```

**When you find cloud credentials**: Classify FIRST. Public-by-design keys (Firebase apiKey, Supabase anon key, OAuth client IDs) are NOT findings by themselves. Actual secrets (service account JSON, service_role key, SAS tokens, storage account keys) must be validated, scoped, and exploited. See the `cloud_credential_exploitation` skill for the full methodology across Firebase, Supabase, GCP, and Azure.

**Step 3: Check for source map exposure**
```bash
# Source maps contain original source code — HIGH severity if exposed
curl -s "$BUNDLE_URL" | grep -oE '//# sourceMappingURL=[^ ]+'
# If found, download the .map file
MAP_URL=$(curl -s "$BUNDLE_URL" | grep -oE '//# sourceMappingURL=[^ ]+' | sed 's/.*mappingSourceURL=//')
curl -s "$MAP_URL" -o /tmp/bundle.map && echo "SOURCE MAP EXPOSED"
# .map files contain: original filenames, comments, internal URLs, sometimes secrets
```

**Step 4: Extract hardcoded URLs**
```bash
# Find internal URLs, staging domains, API endpoints
curl -s "$BUNDLE_URL" | grep -oE 'https?://[a-zA-Z0-9._/-]+' | sort -u
# Flag: staging domains, internal IPs, localhost references, debug endpoints
```

**Step 5: Check for environment variable leakage**
```bash
# Vite prefixes: VITE_, React prefixes: REACT_APP_, Next prefixes: NEXT_PUBLIC_
grep -oE '(VITE_|REACT_APP_|NEXT_PUBLIC_)[A-Z_]+=[^ ]+' /tmp/bundle.js
# These are embedded at build time and visible to anyone
```

**Reporting:**
- Hardcoded API keys/secrets in bundles: CVSS 7.3 (high) — anyone can extract them
- Source map exposure in production: CVSS 5.3 (medium) — reveals original source
- Internal URL/domain disclosure: CVSS 3.1 (low) — aids reconnaissance
- Environment variable leakage: CVSS 3.1-7.3 depending on what's exposed

### Headers and Response Metadata

- Fingerprinting: Server, X-Powered-By, X-AspNet-Version
- Tracing: X-Request-Id, traceparent, Server-Timing, debug headers
- Caching oracles: ETag/If-None-Match, Last-Modified/If-Modified-Since, Accept-Ranges/Range

### Storage and Exports

- Public object storage: S3/GCS/Azure blobs with world-readable ACLs or guessable keys
- Signed URLs: long-lived, weakly scoped, re-usable across tenants
- Export/report endpoints returning foreign data sets or unfiltered fields

### Observability and Admin

- Metrics: Prometheus `/metrics` exposing internal hostnames, process args
- Health/config: `/actuator/health`, `/actuator/env`, Spring Boot info endpoints
- Tracing UIs: Jaeger/Zipkin/Kibana/Grafana exposed without auth

### Cross-Origin Signals

- Referrer leakage: missing/weak referrer policy leading to path/query/token leaks to third parties
- CORS: overly permissive Access-Control-Allow-Origin/Expose-Headers revealing data cross-origin; preflight error shapes

### File Metadata

- EXIF, PDF/Office properties: authors, paths, software versions, timestamps, embedded objects

### Cloud Storage

- S3/GCS/Azure: anonymous listing disabled but object reads allowed; metadata headers leak owner/project identifiers
- Pre-signed URLs: audience not bound; observe key scope and lifetime in URL params

## Key Vulnerabilities

### Differential Oracles

- Compare owner vs non-owner vs anonymous for the same resource
- Track: status, length, ETag, Last-Modified, Cache-Control
- HEAD vs GET: header-only differences can confirm existence
- Conditional requests: 304 vs 200 behaviors leak existence/state

### CDN and Cache Keys

- Identity-agnostic caches: CDN/proxy keys missing Authorization/tenant headers
- Vary misconfiguration: user-agent/language vary without auth vary leaks content
- 206 partial content + stale caches leak object fragments

### Cross-Channel Mirroring

- Inconsistent hardening between REST, GraphQL, WebSocket, and gRPC
- SSR vs CSR: server-rendered pages omit fields while JSON API includes them

## Triage Rubric

- **Critical**: Credentials/keys WITH demonstrated unauthorized access; signed URL secrets used to access cross-tenant data; config dumps that chain to RCE/LFI/auth bypass; unrestricted admin panels with demonstrated data access
- **NOT reportable alone**: Credentials/keys found in responses without using them; config dumps without exploitation; internal paths/names without a chain to unauthorized action
- **High**: Versions with reachable CVEs; cross-tenant data; caches serving cross-user content
- **Medium**: Internal paths/hosts enabling LFI/SSRF pivots; source maps revealing hidden endpoints
- **Low**: Generic headers, marketing versions, intended documentation without exploit path

## Exploitation Chains

### Credential Extraction
- DVCS/config dumps exposing secrets (DB, SMTP, JWT, cloud)
- Keys → cloud control plane access

### Version to CVE
1. Derive precise component versions from headers/errors/bundles
2. Map to known CVEs and confirm reachability
3. Execute minimal proof targeting disclosed component

### Path Disclosure to LFI
1. Paths from stack traces/templates reveal filesystem layout
2. Use LFI/traversal to fetch config/keys

### Schema to Auth Bypass
1. Schema reveals hidden fields/endpoints
2. Attempt requests with those fields; confirm missing authorization

## Testing Methodology

1. **Build channel map** - Web, API, GraphQL, WebSocket, gRPC, mobile, background jobs, exports, CDN
2. **Establish diff harness** - Compare owner vs non-owner vs anonymous; normalize on status/body length/ETag/headers
3. **Trigger controlled failures** - Malformed types, boundary values, missing params, alternate content-types
4. **Enumerate artifacts** - DVCS folders, backups, config endpoints, source maps, client bundles, API docs
5. **Correlate to impact** - Versions→CVE, paths→LFI/RCE, keys→cloud access, schemas→auth bypass

## Validation

1. Provide raw evidence (headers/body/artifact) and explain exact data revealed
2. Determine intent: cross-check docs/UX; classify per triage rubric
3. Attempt minimal, reversible exploitation or present a concrete step-by-step chain
4. Show reproducibility and minimal request set
5. Bound scope (user, tenant, environment) and data sensitivity classification
6. CREDENTIAL CHAINING RULE: When you find credentials (API keys, tokens, client IDs), your job is NOT done. Use the credential against its service. If the Firebase key lets you read Firestore — that's the finding. If the OAuth client ID enables a CSRF token theft — that's the finding. The credential extraction is recon; the unauthorized access is the vulnerability. If you cannot demonstrate unauthorized access with the credential, do NOT report it as a vulnerability.

## False Positives

- Intentional public docs or non-sensitive metadata with no exploit path
- Generic errors with no actionable details
- Redacted fields that do not change differential oracles
- Version banners with no exposed vulnerable surface and no chain
- Owner-visible-only details that do not cross identity/tenant boundaries

## Impact

- Accelerated exploitation of RCE/LFI/SSRF via precise versions and paths
- Credential/secret exposure leading to persistent external compromise
- Cross-tenant data disclosure through exports, caches, or mis-scoped signed URLs
- Privacy/regulatory violations and business intelligence leakage

## Pro Tips

1. Start with artifacts (DVCS, backups, maps) before payloads; artifacts yield the fastest wins
2. Normalize responses and diff by digest to reduce noise when comparing roles
3. Hunt source maps and client data JSON; they often carry internal IDs and flags
4. Probe caches/CDNs for identity-unaware keys; verify Vary includes Authorization/tenant
5. Treat introspection and reflection as configuration findings across GraphQL/gRPC
6. Mine observability endpoints last; they are noisy but high-yield in misconfigured setups
7. Chain quickly to a concrete risk and stop—proof should be minimal and reversible

## Summary

Information disclosure is an amplifier. Convert leaks into precise, minimal exploits or clear architectural risks.

## SSR Internal Hostname/IP Disclosure (INFORMATIONAL — Do NOT Report)

**This is a critical section — read it carefully before reporting any SSR finding.**

### What SSR Internal Hostname Leaks Are

Server-Side Rendering (SSR) frameworks like Nuxt.js, Next.js, and Angular often expose internal infrastructure details in their response data. This includes:

- Internal hostnames (e.g., `willmlmxxx.railway.internal`, `app-abc123.internal`)
- Private IP addresses (e.g., `10.x.x.x`, `172.16.x.x`, `192.168.x.x`)
- Cloud platform identifiers (e.g., Railway, Vercel, Heroku, AWS ECS task IDs)
- Internal port numbers and service names

### Why This Is NOT a Vulnerability

1. **Expected behavior**: SSR frameworks serialize server-side state into responses by design. The `__NUXT_DATA__`, `__NEXT_DATA__`, and similar payloads are meant to hydrate client-side state.

2. **No security impact**: Knowing an internal hostname like `willmlmxxx.railway.internal` does NOT allow an attacker to:
   - Access the internal service (it's behind a private network)
   - Exfiltrate data (the hostname is just a label, not an access credential)
   - Escalate privileges (the hostname doesn't grant any permissions)
   - Execute code (the hostname is just a string, not an executable)

3. **Cloud platform normality**: Railway, Vercel, Heroku, and other platforms assign internal hostnames to all services. This is infrastructure, not a security flaw.

4. **Bugcrowd/HackerOne classification**: Both platforms classify this as P5 (Informational) under:
   - Bugcrowd VRT: "Sensitive Data Exposure > Internal IP Disclosure" (P5)
   - HackerOne: "Version disclosure/banner grabbing without exploitable vulnerability is Informational"

### When SSR Leaks ARE Reportable

The ONLY time an SSR leak becomes a real vulnerability is when you can CHAIN it to exploitation:

1. **SSRF via internal hostname**: If you can use the leaked hostname to make the server request internal resources (e.g., `http://willmlmxxx.railway.internal/admin` returns admin data)
2. **Data exfiltration via internal service**: If the internal hostname hosts a service that returns sensitive data when accessed
3. **Authentication bypass via internal routing**: If the internal hostname bypasses authentication checks

### The Rule

**"I found an internal hostname" = reconnaissance (do NOT report)**
**"I used the internal hostname to access an internal service and extract data" = vulnerability (DO report)**

### What To Do Instead

1. **Log it in agent notes** as reconnaissance for further testing
2. **Attempt SSRF**: Try to make the server request the internal hostname and return data
3. **Test internal access**: Try to access the internal hostname directly (usually fails)
4. **Chain with other findings**: Combine with SSRF, LFI, or auth bypass to create a real exploit chain
5. **If you cannot exploit it**: Move on to other attack surfaces. Do NOT file a report.

### Example: OSL.com Finding

In the OSL.com scan, prometheus found `willmlmxxx.railway.internal` in SSR response data. This was classified as a "Medium" severity finding, but it's actually P5 (Informational) because:

- The hostname was discovered in `__NUXT_DATA__` response (expected SSR behavior)
- No attempt was made to access the internal service
- No data was exfiltrated using the hostname
- No SSRF or other exploitation was demonstrated

The correct approach would have been:
1. Log the hostname in agent notes
2. Attempt SSRF: `curl -H "Host: willmlmxxx.railway.internal" https://www.osl.com/`
3. Test internal access: `curl https://willmlmxxx.railway.internal/` (usually fails)
4. If no exploitation possible, move on to other attack surfaces
