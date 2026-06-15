# Hunt Playbook: CORS Misconfiguration

> Adapted from CBH `hunt-cors` to Prometheus' 12-section structure.
> CORS alone is **always rejected**; the value is in the chain.

## 1. Crown Jewel Targets

- Endpoints that return user-scoped data (`/api/me`,
  `/api/users/{id}`, `/api/orders/...`).
- Endpoints that *change* state with credentials (the `Cookie` is
  sent on a cross-origin request).
- Admin endpoints: `/api/admin/...`, `/internal/...`.

## 2. OOB (Out-of-Band) Gate

- A preflight that returns the **attacker origin reflected** in
  `Access-Control-Allow-Origin` *and* `Access-Control-Allow-Credentials:
  true` *and* the actual request returns the victim's data when
  sent with the victim's cookie. STOP and report.
- A CORS misconfig on a static asset — informational only.

## 3. Attack Surface Signals

- The endpoint returns `Access-Control-Allow-Origin: <attacker>`
  for a request with `Origin: <attacker>`.
- The endpoint returns `Access-Control-Allow-Origin: null` and
  accepts an iframe with a `data:` / `null` origin.
- The endpoint returns `Access-Control-Allow-Origin: *` (this
  alone is not a vuln — the browser blocks credentialed
  cross-origin reads with `*`).
- The endpoint reflects the request `Origin` header verbatim
  (origin reflection).
- The endpoint uses a regex allowlist (e.g., `*.example.com`) but
  the regex is anchored wrong (`example.com` is matched as a
  suffix, so `evilexample.com` is also allowed).

## 4. Methodology

1. Send a request with `Origin: https://attacker.example`. Inspect
   the `Access-Control-Allow-Origin` response header.
2. If reflected, send a preflight (`OPTIONS`) and confirm
   `Access-Control-Allow-Credentials: true`.
3. Send the actual request from a page you control with
   `credentials: 'include'` and the victim's cookie. Confirm the
   response is readable cross-origin.
4. If the response carries user data, escalate per the chain
   `cors_origin_reflect`.

## 5. Payloads

| Probe | Request | Expected (vulnerable) |
|-------|---------|------------------------|
| Reflect | `Origin: https://attacker.example` | `Access-Control-Allow-Origin: https://attacker.example` |
| Reflect + creds | `OPTIONS` preflight from attacker | `Access-Control-Allow-Credentials: true` |
| Null origin | `Origin: null` (via iframe sandbox) | `Access-Control-Allow-Origin: null` |
| Suffix confusion | `Origin: https://evilexample.com` | `Access-Control-Allow-Origin: https://evilexample.com` |
| Regexy | `Origin: https://foo.example.com.evil.com` | `Access-Control-Allow-Origin: https://foo.example.com.evil.com` |

## 6. Root Causes

- Reflecting the request `Origin` header without an allowlist.
- Using a regex allowlist that is anchored at the suffix
  (`example.com$`) without escaping the dot.
- Returning `Access-Control-Allow-Origin: null` for sandboxed
  iframes.
- Setting `Access-Control-Allow-Credentials: true` together with
  an attacker-controlled origin.

## 7. Bypasses

- Use `Origin: null` via a `sandbox="allow-scripts"` iframe.
- Use a subdomain takeover (if the allowlist is `*.example.com`
  and there is a dangling CNAME).
- Use a path-based origin mismatch: some servers compare the
  origin *string* rather than the parsed hostname.

## 8. Gate 0 (Pre-Reporting)

- The cross-origin request actually returns the victim's data
  (not just the headers).
- The `Content-Type` is on the simple-request allowlist or the
  preflight succeeds.
- The victim is logged in (a fresh session proves the
  reproducibility).

## 9. Real Impact

- Reflected origin + creds + sensitive data → P1
  (`cors_origin_reflect`).
- Reflected origin + creds + state-changing endpoint → P0.
- Wildcard without creds → rejected (`cors_wildcard_alone`).

## 10. Chains

- **CORS reflection + state-changing** (`cors_origin_reflect`, P1).
- **CORS reflection + IDOR** (read other users' data cross-origin,
  P1).
- **CORS reflection + admin endpoint** (admin actions from a
  cross-origin attacker page, P0).

## 11. Related Skills

- `prometheus/skills/vulnerabilities/cors_misconfiguration.md`
- `prometheus/skills/data/conditionally_valid.json`
- `prometheus/core/always_rejected.py` (the `cors_wildcard_alone`
  rule rejects the no-creds wildcard case).

## 12. Validation Heuristics

- A CORS misconfig without `Access-Control-Allow-Credentials: true`
  is rejected (`cors_wildcard_alone`).
- A CORS misconfig on a non-sensitive endpoint is rejected.
- A CORS misconfig that requires a network position the victim
  does not have (e.g., same-LAN) is informational.
