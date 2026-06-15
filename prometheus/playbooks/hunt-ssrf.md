# Hunt Playbook: SSRF (Server-Side Request Forgery)

> Adapted from CBH `hunt-ssrf` to Prometheus' 12-section structure.
> The single most important chain is **SSRF + cloud metadata service**
> (`ssrf_imds_creds`, P1) — that single chain is what makes a
> "boring" SSRF a critical finding.

## 1. Crown Jewel Targets

- URL-bearing parameters on user-facing endpoints:
  - `?url=`, `?image_url=`, `?avatar_url=`, `?callback=`, `?feed=`
  - `?webhook=`, `?next=`, `?return_url=`, `?dest=`
  - File converters: PDF render, image proxy, avatar fetch, link
    preview.
- Webhook configuration: `POST /api/webhooks` with a `target_url`
  field.
- OAuth/OpenID `redirect_uri` and `post_logout_redirect_uri`.
- Import-from-URL flows: `POST /api/import` with `source_url`.
- RSS / Atom / sitemap fetchers.

## 2. OOB (Out-of-Band) Gate

- 200 with the contents of `http://169.254.169.254/...` in the
  response — IAM credential leak. STOP and report.
- 200 with the contents of `http://localhost:6379/` or
  `http://127.0.0.1:8080/internal/...` — internal service exposed.
  STOP and report.
- 200 with a body that includes `root:x:0:0:...` — path traversal
  leak on top of SSRF. Chain to `path_traversal`.
- 200 with the contents of an attacker's OOB listener (e.g.,
  `burpcollaborator.net` or your own server) — the SSRF is
  confirmed; the response can be empty.

## 3. Attack Surface Signals

- The endpoint accepts a URL and either fetches it server-side
  (proxy / image fetch) or stores it for later fetch (webhook /
  import).
- The endpoint normalizes the URL but does not validate the
  resolved IP (DNS rebinding candidate).
- The endpoint follows redirects (an internal redirect can pivot
  to a metadata IP).
- The endpoint returns the body of the fetched URL (full SSRF,
  not blind).

## 4. Methodology

1. **Find URL-bearing parameters** (use `arsenal.md` from the recon
   stage).
2. **Probe with an external canary** you control. Confirm the
   server-side fetch happens (look at your listener).
3. **Probe with a metadata IP** (169.254.169.254 for AWS,
   `metadata.google.internal` for GCP, etc.). The response body
   is the smoking gun.
4. **Probe with internal loopback** (`http://127.0.0.1:PORT/path`)
   to reach admin panels (Grafana, Kibana, internal admin).
5. **Probe with DNS rebinding**: a domain whose A record flips
   between a public IP and `169.254.169.254` between the
   validator's lookup and the server's fetch.

## 5. Payloads

| Target | Payload | Expected (vulnerable) |
|--------|---------|------------------------|
| AWS IMDSv1 | `http://169.254.169.254/latest/meta-data/` | 200 + role-name list |
| AWS IMDSv1 (creds) | `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` | 200 + AccessKeyId/SecretAccessKey/Token |
| GCP metadata | `http://metadata.google.internal/computeMetadata/v1/` (header `Metadata-Flavor: Google`) | 200 + project-id |
| Azure metadata | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (header `Metadata: true`) | 200 + subscriptionId |
| Internal Grafana | `http://127.0.0.1:3000/api/dashboards/home` | 200 + dashboard JSON |
| DNS rebind | `http://rebind.<your-domain>/...` | first lookup passes validation, second hits internal IP |

## 6. Root Causes

- The endpoint builds a request from a user-supplied URL without
  validating the resolved IP.
- The endpoint allows `file://`, `gopher://`, or other schemes
  beyond `http(s)://`.
- The endpoint follows redirects without re-validating the
  redirect target.
- The endpoint uses a library that resolves hostnames *after* the
  IP allowlist check (DNS rebinding).

## 7. Bypasses

- Use **decimal** IPs (`http://2130706433/` = `127.0.0.1`).
- Use **hex / octal** IP encodings.
- Use **`0.0.0.0`** (often accepted as loopback).
- Use **`[::]`** or **`[::1]`** for IPv6 loopback.
- Use a **shortened URL** that 30x-redirects to a metadata IP.
- Use **alternate case** of the scheme (`HTTP://`).
- Use **URL credentials** (`http://allowed@169.254.169.254/`).

## 8. Gate 0 (Pre-Reporting)

- The SSRF reaches the target (the response body is from the
  target, not a generic 200).
- The target is *not* on the engagement's allowlist (an SSRF that
  only hits the agent's own infrastructure is rejected as
  `ssrf_internal_only`).
- The metadata endpoint returns a *non-empty* response (some
  endpoints return 200 with an empty body — that is not a chain,
  just a filtered SSRF).

## 9. Real Impact

- SSRF → metadata → IAM creds → P0.
- SSRF → internal admin (Grafana, Kibana) → P0.
- SSRF → internal service with creds in env vars → P0.
- SSRF that only reaches a public allowlist → P3 (chain to
  bypass).

## 10. Chains

- **SSRF + IMDS** (`ssrf_imds_creds`, P1).
- **SSRF + internal admin** (`ssrf_internal_admin`, P1).
- **SSRF + bypass-of-allowlist** (chained with a path-traversal
  finding on the internal service, P0).

## 11. Related Skills

- `prometheus/skills/vulnerabilities/cloud_credential_exploitation.md`
- `prometheus/skills/data/conditionally_valid.json`

## 12. Validation Heuristics

- A SSRF that only returns 200 with the attacker's own canary is
  a `blind_ssrf` — severity is reduced by one tier (P2 → P3,
  P1 → P2).
- A SSRF that *requires* an authenticated session is
  `auth_required_ssrf` — chain with `auth_bypass` for full
  credit.
- A SSRF on a webhook URL that triggers an action (e.g., a
  payment webhook) is `ssrf_with_side_effect` — P0 regardless
  of the target.
