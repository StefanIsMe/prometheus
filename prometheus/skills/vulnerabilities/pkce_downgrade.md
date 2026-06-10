---
name: pkce-downgrade
description: PKCE downgrade attack detection and validation — OAuth/OIDC PKCE bypass via plain method
triggers:
  - pkce downgrade
  - plain pkce
  - code_challenge_method plain
  - oauth pkce bypass
  - pkce validation
  - oidc discovery plain
---

# PKCE Downgrade Attack

## What It Is

PKCE (Proof Key for Code Exchange) protects OAuth authorization code flows against code interception. A PKCE downgrade occurs when:

1. The authorization server's discovery document advertises `code_challenge_methods_supported: ["S256", "plain"]`
2. The server accepts `code_challenge_method=plain` at the /authorize endpoint
3. The token endpoint accepts a plain `code_verifier` (which equals the `code_challenge`)

With **plain**: `code_challenge = code_verifier` (no transformation)
With **S256**: `code_challenge = BASE64URL(SHA256(code_verifier))`

If an attacker intercepts the authorization code AND the authorization request URL (which contains the code_challenge in cleartext), they can exchange the code for tokens using the known verifier — only with plain, not S256.

## Detection Steps

### Step 1: Fetch OIDC Discovery Document
```bash
curl -s https://TARGET/.well-known/openid-configuration | python3 -c "
import json, sys
d = json.load(sys.stdin)
print('code_challenge_methods_supported:', d.get('code_challenge_methods_supported', 'NOT PRESENT'))
print('issuer:', d.get('issuer'))
print('authorization_endpoint:', d.get('authorization_endpoint'))
print('token_endpoint:', d.get('token_endpoint'))
"
```

### Step 2: Test /authorize Endpoint
Generate PKCE values:
```bash
CODE_VERIFIER=$(python3 -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode())")
# For plain: code_challenge = code_verifier
```

Test with plain:
```
https://TARGET/authorize?client_id=CLIENT_ID&response_type=code&redirect_uri=REDIRECT&scope=openid+profile+email&code_challenge=$CODE_VERIFIER&code_challenge_method=plain&state=test
```

Test without PKCE:
```
https://TARGET/authorize?client_id=CLIENT_ID&response_type=code&redirect_uri=REDIRECT&scope=openid+profile+email&state=test
```

Both should be REJECTED (error). If login page is shown = accepted.

### Step 3: Test Token Endpoint
```bash
# With code_verifier
curl -s -X POST https://TARGET/oauth/token \
  -d "grant_type=authorization_code&code=FAKE&redirect_uri=REDIRECT&client_id=CLIENT_ID&code_verifier=$CODE_VERIFIER"

# Without code_verifier
curl -s -X POST https://TARGET/oauth/token \
  -d "grant_type=authorization_code&code=FAKE&redirect_uri=REDIRECT&client_id=CLIENT_ID"
```

If both return the same error (e.g., "token_expired" for fake code), the proxy may not check PKCE at all.

### Step 4: Automated Validation
```bash
python3 -m prometheus.core.oauth_validation https://TARGET CLIENT_ID REDIRECT_URI
```

## Validation Criteria

### Validated (reportable)
- Discovery document advertises `plain` in code_challenge_methods_supported
- AND token endpoint accepts plain code_verifier (proven via full OAuth flow)
- OR discovery advertises only plain (not S256) — high severity

### Speculative (needs more evidence)
- Discovery document advertises `plain` but token endpoint behavior unconfirmed
- Authorize endpoint accepts plain (could be UI-only, validation at token stage)
- Missing PKCE enforcement (no code_challenge required)

### False Positive
- Server only advertises S256
- Server rejects plain at token endpoint
- Server returns `invalid_request` for missing code_challenge

## AUTO-REPORT BLOCKER (MANDATORY)

**DO NOT auto-report PKCE plain findings.** This finding class is almost always rejected by bug bounty programs as theoretical/informational.

Reason: Showing the server advertises or accepts `code_challenge_method=plain` at the /authorize endpoint is NOT exploitation. The /authorize endpoint is a UI redirect — it shows a login page for any valid-looking request. Real PKCE validation happens at the token exchange endpoint, which requires a valid authorization code (obtained after user authentication). Without completing the full OAuth flow and demonstrating that the token endpoint accepts a plain code_verifier, the finding is unproven.

**To report this finding, ALL of these must be true:**
1. Discovery document advertises `plain` — confirmed via curl
2. Token endpoint tested with a REAL authorization code (not a fake code)
3. Token endpoint accepted the plain code_verifier and returned tokens
4. Full chain documented: authorize → user login → code capture → token exchange with plain verifier

If you cannot complete step 2-4, this is INFORMATIONAL ONLY. Do not submit.

**2026-06-02 lesson learned:** auth.openai.com finding (ID 53) rejected by Bugcrowd — "theoretical with no actual valid PoC/impact." Deducted 1 point. The PoC only showed /authorize accepts plain (step 2 of detection), never tested token exchange with a real code.

## Scoring

- **Medium** (CVSS ~4.2): Plain advertised, S256 also advertised, token behavior unconfirmed
- **High** (CVSS ~6.5): Only plain advertised (no S256), or token confirmed accepting plain
- **Critical** (CVSS ~8.0): PKCE completely bypassable (no verifier check at all)

## CVE References

- CVE-2025-4144: Cloudflare Workers OAuth PKCE bypass via downgrade
- CVE-2024-23647: Authentik PKCE downgrade
- CVE-2024-22258: Spring Authorization Server PKCE downgrade for confidential clients

## RFC References

- RFC 7636: Proof Key for Code Exchange (PKCE)
- RFC 9700: OAuth 2.0 Security Best Current Practice (Jan 2025)
  - Section 2.1.2: "Currently, S256 is the only such method"
- OAuth 2.1 Draft: Mandates PKCE for all authorization code flows

## Common Targets

- Auth0 tenants: `https://TENANT.auth0.com/.well-known/openid-configuration`
- Keycloak: `https://KEYCLOAK/realms/REALM/.well-known/openid-configuration`
- Okta: `https://TENANT.okta.com/.well-known/openid-configuration`
- Azure AD: `https://login.microsoftonline.com/TENANT/v2.0/.well-known/openid-configuration`

## Pitfalls

1. **Authorize endpoint != Token endpoint**: The /authorize accepting plain doesn't mean the token endpoint does. Auth0's Universal Login shows the login page for any request. Real PKCE validation happens at token exchange.

2. **Proxy layers**: Some providers (like OpenAI) proxy the token endpoint. The proxy may validate auth codes before PKCE, returning generic errors that mask PKCE behavior.

3. **Discovery doc vs actual behavior**: Auth0 docs say "only S256 supported" but the discovery doc may still advertise plain. Test the actual token exchange, not just the metadata.

4. **Client ID validation**: Some endpoints accept any client_id at /authorize but reject at token exchange. Use a known-valid client_id.

5. **Full chain required**: To prove exploitability, you need: valid client_id + valid redirect_uri + user authentication + authorization code capture + token exchange with plain verifier. Metadata-only findings are weaker.
