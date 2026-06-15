# Hunt Playbook: Account Enumeration

> Adapted from CBH `hunt-account-enumeration` to Prometheus' 12-section
> structure. The agent should not stop at "the response differs"; it
> must demonstrate that the difference is *enumerable at scale* and
> chain the leak to a credential-stuffing or password-reset
> poisoning flow.

## 1. Crown Jewel Targets

- Login form: `POST /login`, `POST /api/auth/login`
- Forgot password: `POST /api/auth/forgot`, `POST /reset`
- Signup / "already registered" check: `POST /api/auth/signup`
- User search / directory: `GET /api/users?email=...`,
  `GET /api/directory?q=...`
- 2FA enrollment: `POST /api/auth/2fa/enroll`
- Account recovery via phone/SMS: `POST /api/auth/recover`

## 2. OOB (Out-of-Band) Gate

- A response body that returns the *full* user record for a known
  email (this is a different class of vuln: PII exposure).
- A response that *triggers* an actual email/SMS to the victim
  (the agent must suppress — never send production emails).
- A response timing oracle that varies by *seconds* rather than
  milliseconds (often a different bug — slow hash leak, not
  enumeration).

## 3. Attack Surface Signals

- The login response is asymmetric: "user not found" vs "wrong
  password".
- The forgot-password response is asymmetric: "if the email
  exists, ..." with a different status code per branch.
- The signup response is asymmetric: "email already in use" with
  a 409 vs "user created" with a 201.
- The 2FA enrollment response is asymmetric: "no 2FA enrolled"
  vs "2FA already enrolled".
- The directory endpoint has no rate limit + no captcha.

## 4. Methodology

1. Build a corpus of known-existing and known-not-existing emails
   (use the engagement's own test accounts; do not enumerate
   real users).
2. For each auth-relevant endpoint, send the same request with
   both corpora.
3. Capture: status code, response body length, response body
   content, headers, and request time (≥ 100 samples per email
   for timing oracles).
4. Diff the responses. Any systematic, per-email difference is
   the enumeration oracle.

## 5. Payloads

| Endpoint | Request | Expected (vulnerable) |
|----------|---------|------------------------|
| `/login` | `{email, password}` | 401 "user not found" vs 401 "wrong password" |
| `/forgot` | `{email}` | 200 with "email sent" vs 404 "no such user" |
| `/signup` | `{email}` | 201 with "verification sent" vs 409 "email exists" |
| `/api/users?email=...` | GET | 200 with user object vs 404 |
| `/api/auth/2fa/enroll` | POST | 200 with QR vs 400 "2FA already enabled" |

## 6. Root Causes

- Login responses include the failure reason ("user not found" vs
  "wrong password") instead of a generic "invalid credentials".
- Forgot-password returns a different status for known vs unknown
  emails.
- Signup is reachable and returns "email exists" for registered
  emails.
- The user-search endpoint is not rate-limited and not captcha'd.

## 7. Bypasses

- Try with the victim's email in **uppercase / lowercase** — some
  endpoints short-circuit on the canonical form.
- Try with **plus-aliasing** (`victim+1@example.com`).
- Try with **unicode normalization** (`vıctim@example.com`).
- Try with **leading/trailing whitespace**.

## 8. Gate 0 (Pre-Reporting)

- The oracle is reproducible across at least 5 distinct emails per
  branch.
- The oracle is reachable without authentication (or with a low-
  privilege user).
- The response difference is not an HTTP/2 push-promise artifact or
  CDN variance (test from two different IPs if possible).

## 9. Real Impact

- A standalone enumeration is **informational** (no chain).
- Chained to credential stuffing (no rate limit, no captcha) →
  P2 (`rate_limit_credential_stuffing`).
- Chained to password reset poisoning → P2
  (`account_enum_password_reset`).
- Chained to phishing at scale → P3 (the attack is real but
  off-platform).

## 10. Chains

- **Account enum + password reset flow** (`account_enum_password_reset`,
  P2): the forgot-password response differs per known email AND
  the response (or follow-up) includes a reset token / link.
- **Account enum + credential stuffing** (`rate_limit_credential_stuffing`,
  P2): the login endpoint has no rate limit and the enumeration
  provides the user list.
- **Account enum + 2FA enrollment** (no chain, P3): the 2FA
  endpoint leaks whether the user has 2FA.

## 11. Related Skills

- `prometheus/skills/vulnerabilities/authentication_jwt.md`
- `prometheus/skills/data/conditionally_valid.json`

## 12. Validation Heuristics

- A single email with a single probe is **not** an oracle — must
  be reproducible across the corpus.
- Timing oracles require ≥ 100 samples and a t-test or median diff
  ≥ 50ms to count.
- The 5-step Q1 template (request/response/impact/cost/setup) must
  be filled in 5 minutes; if it takes longer the gate KILL_Q1s.
