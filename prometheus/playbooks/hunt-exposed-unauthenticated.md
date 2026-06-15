# Hunt Playbook: Exposed Unauthenticated Endpoint

> Adapted from CBH `hunt-exposed-unauthenticated` to Prometheus'
> 12-section structure. The vuln is not "the endpoint exists" — it
> is "the endpoint returns or mutates data without authentication
> and that data matters".

## 1. Crown Jewel Targets

- Internal admin endpoints exposed at `/api/internal/...`,
  `/admin/...`, `/_debug/...`, `/actuator/...`, `/swagger-ui/...`
- Unauthenticated user-data endpoints: `/api/users`,
  `/api/orders`, `/api/internal/users/{id}`
- Unauthenticated file/object routes: `/files/{id}`,
  `/api/documents/{id}`, `/uploads/{name}`
- Unauthenticated control endpoints: `/api/seed`, `/api/migrate`,
  `/api/admin/reset`
- Healthcheck/info endpoints that leak env vars, internal IPs,
  or version info that *also* contain secrets (`/env`,
  `/debug/vars`, `/actuator/env`)

## 2. OOB (Out-of-Band) Gate

- The endpoint returns production data (real user PII, real
  customer records, real orders). STOP and report.
- The endpoint accepts a write (POST/PUT/DELETE) without auth and
  the write persists. STOP and report.
- The endpoint returns an env var dump with a real secret (API
  key, DB password). STOP and report.

## 3. Attack Surface Signals

- Endpoints that are documented for *internal* use but exposed
  externally (e.g., `/.well-known/`, `/api/internal/health`).
- Endpoints that were protected by an API gateway in staging but
  are exposed directly in prod.
- Spring Boot Actuator endpoints: `/actuator/env`, `/actuator/heapdump`,
  `/actuator/configprops`, `/actuator/mappings`.
- Express.js debug routes: `/debug/vars`, `/_debugbar/...`.
- Server-status / server-info: `/server-status`, `/server-info`.

## 4. Methodology

1. **Crawl the JS bundles** (the recon stage already does this).
   Mine for `/api/`, `/v1/`, `/v2/`, `/graphql/`, `/internal/`.
2. **For each candidate endpoint**, send `GET` with no auth
   header. 200 + sensitive data = exposed.
3. **For each candidate POST/PUT/DELETE**, send the request with
   no auth. 200/204 = write-without-auth (often a P0).
4. **For actuator / debug endpoints**, send a single probe; the
   response body is the smoking gun.
5. **Chase the chain** (see §10).

## 5. Payloads

| Endpoint | Request | Expected (vulnerable) |
|----------|---------|------------------------|
| `/api/users` | `GET` (no auth) | 200 + user list |
| `/api/admin/users` | `GET` (no auth) | 200 + admin data |
| `/actuator/env` | `GET` (no auth) | 200 + env var dump |
| `/actuator/heapdump` | `GET` (no auth) | 200 + heap dump (binary) |
| `/api/internal/seed` | `POST` (no auth) | 200 + seed action ran |
| `/api/documents/{id}` | `GET` (no auth) | 200 + document content |

## 6. Root Causes

- Missing auth middleware on internal admin routes.
- Auth middleware that whitelists `/api/internal/*` for
  "monitoring" but doesn't restrict the methods.
- Actuator / debug routes left enabled in production.
- Routes that *were* behind a VPN but are now exposed on the
  public ingress.

## 7. Bypasses

- Try with `X-Forwarded-For: 127.0.0.1` (some apps skip auth for
  loopback).
- Try with `X-Original-URL: /admin/...` (some proxies route the
  inner path after a path match).
- Try with HTTP verb override: `POST` with
  `X-HTTP-Method-Override: GET`.
- Try the path with a trailing slash, `.html`, or `.json` —
  sometimes the auth middleware matches a regex that misses
  variants.

## 8. Gate 0 (Pre-Reporting)

- The endpoint is reachable from the public internet (not just
  from inside the engagement's network).
- The response body contains data the unauth caller should not
  see (PII, secrets, admin-only data).
- For write endpoints, the action persists (re-fetch and
  confirm).

## 9. Real Impact

- Read of admin data → P1 (`exposed_unauthenticated`).
- Read of customer PII → P0.
- Write of admin data → P0.
- Read of env var dump with secrets → P0.

## 10. Chains

- **Exposed unauth + admin endpoint** (`exposed_unauthenticated`,
  P1).
- **Exposed unauth + IDOR** (the unauth endpoint returns other
  users' data by ID, P1).
- **Exposed unauth + write** (unauth POST/PUT/DELETE persists,
  P0).

## 11. Related Skills

- `prometheus/core/recon.py` (find candidate endpoints from
  recon).
- `prometheus/core/openapi_sweep.py` (declared-security vs.
  enforced-security).
- `prometheus/core/seven_question_gate.py` (Q1 template + Q6
  victim data).

## 12. Validation Heuristics

- An endpoint that returns 401 (not 200) is *not* exposed.
- An endpoint that returns 200 with `{"error":"forbidden"}` is
  *not* exposed.
- An endpoint that returns 200 with a generic 404-style body is
  not exposed.
- An endpoint that requires an API key in the URL query is
  `exposed_with_static_key` — different class, different chain.
