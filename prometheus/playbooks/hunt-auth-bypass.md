# Hunt Playbook: Authentication Bypass

> Adapted from CBH `hunt-auth-bypass` to Prometheus' 12-section
> structure. Covers header manipulation, token confusion, role
> escalation, and the 2FA/MFA-bypass class.

## 1. Crown Jewel Targets

- Admin endpoints: `/admin`, `/api/internal/admin`, `/admin/...`
- Tenant/admin APIs: `/api/tenants/{id}/admin`, `/api/v1/admin/...`
- Privileged user endpoints: `PUT /api/users/{id}/role`,
  `POST /api/users/{id}/permissions`, `POST /api/auth/2fa/disable`
- Password reset / recovery: `/api/auth/reset`,
  `/api/auth/recover`, `/api/auth/forgot`
- Account merge / transfer ownership:
  `POST /api/users/{id}/merge`, `POST /api/transfer-ownership`

## 2. OOB (Out-of-Band) Gate

- 500 with a stack trace exposing auth-internal symbols (e.g.,
  `JwtVerifier`, `bcrypt`).
- 200 on `/api/admin/...` without an admin token.
- 200 on a 2FA-required endpoint with the 2FA factor missing.
- 200 on a "forgot password" flow that returns a reset token in the
  response (information disclosure, not bypass).

## 3. Attack Surface Signals

- Endpoints that accept an `X-User-Id` / `X-Role` / `X-Is-Admin`
  header.
- Endpoints that accept an `Authorization: Bearer <jwt>` AND a
  `Cookie: session=...` — token confusion.
- Endpoints that don't require the `Authorization` header at all
  (unauthenticated) but are mounted under `/api/`.
- Endpoints that allow a `?role=admin` or `?as_admin=true` query.
- GraphQL mutations that take a `role: Role` argument and don't
  validate server-side.
- Password reset flows that take a `user_id` (not a token) and reset
  the password for that user.

## 4. Methodology

1. **Map the auth model**: collect all paths that touch
   authentication, session, JWT, OAuth, API key, or 2FA.
2. **For each privileged endpoint**, send:
   - No `Authorization` header.
   - An expired token.
   - A token belonging to a different (lower-privileged) user.
   - A token signed with a *different* secret (algorithm confusion).
   - A header-only bypass: `X-User-Id: admin`, `X-Role: admin`.
3. **For each 2FA endpoint**, send the post-2FA request *without*
   completing the 2FA step (some apps check the cookie but not the
   `mfa_passed` claim).
4. **For each role escalation endpoint**, send the role-change
   request as a non-admin.

## 5. Payloads

| Bypass class | Payload | Expected (vulnerable) |
|--------------|---------|------------------------|
| Header-based | `X-User-Id: <admin-id>` (no token) | 200 + admin data |
| Algorithm confusion | JWT `alg: none` token signed empty | 200 + admin data |
| Token confusion | `Cookie: session=<admin-cookie>` (no JWT) | 200 + admin data |
| Mass-assignment | `POST /api/users/{id}` body `{"role":"admin"}` | 200 + role changed |
| 2FA skip | `POST /api/transfers` after login, no TOTP | 200 + transfer succeeded |
| Password reset by user_id | `POST /reset {"user_id":<victim>}` | 200 + reset link returned |

## 6. Root Causes

- Authorization middleware that trusts client-supplied identity
  headers.
- JWT verification that accepts `alg: none` or that uses the *public*
  key as the HMAC secret (RS256 → HS256 confusion).
- Missing function-level checks on top of the auth middleware.
- 2FA enforced only at login, not on every privileged action.
- Password reset endpoint that takes a `user_id` instead of (or in
  addition to) a one-time token.

## 7. Bypasses

- Try the bypass with the **referer** header set to an in-scope
  domain.
- Try with the bypass in a **case-variant** header (`X-User-ID`).
- Try with the bypass in a **secondary** auth scheme (e.g., the
  endpoint accepts an API key as a query param even though the spec
  says header-only).
- Try **path normalization**: `/admin/./`, `/Admin/`, `/%61dmin/`.
- Try **HTTP method override**: `POST /api/foo` with
  `X-HTTP-Method-Override: PUT`.

## 8. Gate 0 (Pre-Reporting)

- The bypass succeeds against a fresh request (no stale session
  cookies).
- The response body contains data that the bypassed user would not
  normally see (admin-only fields, other users' PII).
- A token replay shows the same bypassed response (not a one-off
  race).

## 9. Real Impact

- Header-based bypass → P0 (full account takeover of any user).
- 2FA skip → P1 (financial or account-takeover chain).
- Role escalation → P0 if the role change persists.
- Password reset by user_id → P0 (account takeover).

## 10. Chains

- **Auth bypass + admin endpoint** (`auth_bypass_admin`, P1): the
  bypass reaches an admin-only path.
- **Auth bypass + IDOR** (write-IDOR after bypass, P0): the agent
  edits other users' data via the bypassed endpoint.
- **2FA skip + financial** (race condition on transfer, P0): chained
  with `race_condition_balance`.

## 11. Related Skills

- `prometheus/skills/vulnerabilities/authentication_jwt.md`
- `prometheus/skills/data/conditionally_valid.json`
- `prometheus/core/openapi_sweep.py` (declared-security vs. enforced)

## 12. Validation Heuristics

- A "missing auth" finding must show a 200 with admin data, not
  just a 401 → 200 path mismatch.
- A 2FA-skip finding must show the post-2FA action actually
  succeeded (not a 200 with `{status: "pending_2fa"}`).
- A role-escalation finding must show the role *persisted* in a
  follow-up request.
