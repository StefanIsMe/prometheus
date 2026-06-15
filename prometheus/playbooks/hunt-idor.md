# Hunt Playbook: IDOR (Insecure Direct Object Reference)

> Adapted from CBH `hunt-idor` to Prometheus' 12-section structure.
> The deep-dive agent loads this playbook when the threat model or the
> current candidate stream points at IDOR.

## 1. Crown Jewel Targets

Endpoints that return or mutate **per-user** state with an ID/UUID in
the path, query, or body:

- `/api/users/{id}`, `/api/v1/accounts/{id}`, `/api/orders/{id}`,
  `/api/invoices/{id}`, `/api/messages/{id}`
- File/download routes: `/files/{id}`, `/api/documents/{id}`,
  `/api/avatars/{id}`, `/api/attachments/{id}`
- Multi-tenant resources keyed by tenant ID: `/api/tenants/{id}/...`
- Webhook / API key endpoints: `/api/webhooks/{id}`,
  `/api/keys/{id}`

The asset is crown-jewel when the response contains PII, payment
data, secrets, tokens, or causes a state change for a user other than
the caller.

## 2. OOB (Out-of-Band) Gate

Stop hunting the moment you observe **any** of:

- 500 with a stack trace that includes internal-only hostnames or
  schema names.
- 200 with data belonging to a *different* user/tenant.
- 200 with a 200 OK body that, when the ID is replaced with the
  attacker's own ID, returns a 403/404 (an existence oracle).

The OOB gate forbids: editing other users' data without consent,
replaying destructive actions more than twice, generating any
production data (real PII, real charges, real emails).

## 3. Attack Surface Signals

The agent should bias its search toward endpoints matching:

- Path parameters that look like sequential integers or short
  hex/UUIDs (`/items/12345`, `/items/abc123`).
- Pagination cursors that include a `user_id` or `account_id` field.
- Bulk export endpoints that iterate over IDs.
- Search/filter endpoints that accept a `user_id` or `owner_id` field.
- GraphQL nodes with `id: ID!` arguments.
- Mobile API variants under `/m/`, `/mobile/`, or `/api/mobile/`.

## 4. Methodology

1. **Build a corpus** of attacker-IDs and victim-IDs from
   authenticated probes. Note: do not touch other tenants' IDs unless
   scope explicitly allows multi-tenant testing.
2. **Enumerate** endpoints that take a path / query / body ID. Use
   `arsenal.md` from the recon stage to find candidates.
3. **Probe systematically**:
   - Logged in as attacker-A: `GET /api/users/attacker-A-id` → 200.
   - Replace path ID with `victim-B-id` (a second account the agent
     controls): `GET /api/users/victim-B-id` → 200? = IDOR.
   - Repeat for `PUT`, `PATCH`, `DELETE`.
4. **Chase the chain** (see §10): an IDOR returning PII escalates to
   `P1` per `idor_sensitive_data`.

## 5. Payloads

| Verb | Request | Expected (vulnerable) | Expected (safe) |
|------|---------|------------------------|-----------------|
| GET  | `/api/users/{victim_id}` | 200 with victim's data | 403 / 404 |
| PUT  | `/api/users/{victim_id}` (body: `{"email":"x@evil"}`) | 200 + email changed | 403 / 404 |
| DELETE | `/api/users/{victim_id}` | 204 | 403 / 404 |
| GET  | `/api/orders/{victim_order_id}` | 200 with order details | 403 / 404 |
| POST | `/api/transfer` (body: `{"to":"victim", "amount":1}`) | 200 | 403 / 400 |

## 6. Root Causes

- Missing or broken function-level authorization (OWASP API1:2023).
- Authorization checks that compare `user_id` from JWT but use
  `account_id` from the URL — claim/parameter confusion.
- Internal admin endpoints exposed at `/api/internal/...` without
  role checks.
- Mass-assignment: a request body field like `owner_id` overrides the
  authoritative server-side value.
- Cursor pagination that includes a `user_id` not in the JWT.

## 7. Bypasses

- Try with **leading zeros**, hex variants, UUID braces, base64 of
  the ID, and the email / username in place of the numeric ID.
- Try `HEAD` instead of `GET` (some frameworks only authorize GET).
- Try `Content-Type: application/json` vs
  `application/x-www-form-urlencoded` — some routers only inspect one.
- Try with the attacker's auth header but the victim's cookie (or
  vice versa). Some code paths authorize on the wrong one.
- Try IDOR via the **search endpoint** (`?owner_id={victim_id}`).

## 8. Gate 0 (Pre-Reporting)

Before you report, confirm:

- The response **actually** belongs to the victim (compare to a
  victim-controlled screenshot or to a sentinel value you changed on
  the victim account first).
- The ID is server-issued (not user-controlled free text).
- The endpoint is in-scope per `engagement/scope.py`.

## 9. Real Impact

The chain escalates severity based on the *response*, not the request:

- Returns email/phone/address → `idor_sensitive_data` chain → P1
- Allows editing → write-IDOR → P1 (account takeover if the edit
  changes the email — the attacker resets the password).
- Allows deletion → P0 (data loss).
- Reveals existence of a resource → informational.

## 10. Chains

- **IDOR + sensitive data** (`idor_sensitive_data`, P1): the response
  contains PII, payment info, or secrets. Always try this chain.
- **IDOR + password reset** (write-IDOR + email change → ATO, P1).
- **IDOR + GraphQL** (one node ID, multiple sibling nodes visible,
  P1): a single IDOR leaks a parent's children.
- **IDOR + file path** (e.g., `/files/{id}` returns
  `../../../etc/passwd`): chain with `path_traversal` to P1.

## 11. Related Skills

- `prometheus/skills/vulnerabilities/broken_function_level_authorization.md`
- `prometheus/skills/data/conditionally_valid.json` (the chain table)
- `prometheus/core/seven_question_gate.py` (Q1 template + Q6 victim data)
- `prometheus/core/recon.py` (find candidate endpoints from JS bundles)

## 12. Validation Heuristics

- A "no PII returned" finding is rejected as `idor_no_pii`; the
  agent must demonstrate at least one piece of data that is
  victim-specific.
- A finding that shows only the attacker's own data is rejected as
  `self_idor`.
- A finding with status 200 + an empty body and a successful status
  is not enough — there must be a diff between the victim's body
  and the attacker's.
