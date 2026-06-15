# Hunt Playbook: Source Map / Build Artifact Exposure

> Adapted from CBH `hunt-source-map` to Prometheus' 12-section
> structure. Source maps alone are **always rejected**; the chain
> is to *what the source map reveals*.

## 1. Crown Jewel Targets

- Production bundle `.js.map` files that map back to the original
  TypeScript / JSX / Vue source.
- `.env`, `.env.local`, `.env.production` files served from the
  app root.
- `webpack.stats.json`, `manifest.json`, `stats.html` files.
- The `.git` directory (when the build server's CWD is the
  repo root).
- Docker layer tarballs / image registry credentials left in
  `/var/lib/...` or in env-var dump endpoints.

## 2. OOB (Out-of-Band) Gate

- A source map that maps a minified bundle to a real source file
  that contains API endpoints not present in the public docs.
- A source map that contains unredacted API keys, OAuth client
  secrets, or DB credentials inline.
- A source map that reveals an unpatched vulnerability class
  (e.g., the original source uses `eval()` on user input).

## 3. Attack Surface Signals

- Bundle paths under `/_next/`, `/static/`, `/assets/`, `/build/`
  with a sibling `.map` file.
- Webpack build artifacts served from a CDN without stripping the
  `.map` files.
- `.env` files referenced in the public docs as a "config example"
  but with real values.

## 4. Methodology

1. Find all `.js` files served by the app (the recon stage).
2. For each `.js` file, request the sibling `.js.map`. 200 + a
   valid sourcemap JSON = exposed.
3. For each exposed map, parse the `sources` field and the
   `sourcesContent` field. Look for hardcoded secrets, internal
   endpoints, unstripped comments, and unpatched code.
4. Cross-reference the source paths with the agent's JS-bundle
   list to confirm the bundle is production (not a dev artifact).

## 5. Payloads

| Probe | Request | Expected (vulnerable) |
|-------|---------|------------------------|
| Sibling map | `GET /assets/app.js.map` | 200 + valid sourcemap JSON |
| `.env` | `GET /.env` | 200 + env vars |
| Webpack stats | `GET /webpack.stats.json` | 200 + module list |
| `.git` | `GET /.git/HEAD` | 200 + `ref: refs/heads/main` |

## 6. Root Causes

- The build pipeline does not strip `.map` files in production.
- The web server's static file handler does not block `.env` /
  `.git` paths.
- The CDN cache serves the build output without filtering.

## 7. Bypasses

- Try path traversal: `/assets/../.env`, `/static/..%2F.env`.
- Try the file under different extensions: `app.js.MAP`,
  `app.js?map`.
- Try the index file: `/assets/.env` vs `/assets/.env/`.

## 8. Gate 0 (Pre-Reporting)

- The file is reachable on the production domain (not a
  dev/staging URL).
- The contents reveal something an attacker would not otherwise
  know (an internal endpoint, a secret, an unpatched code path).
- The file is not a publicly documented artifact (e.g., the
  OpenAPI doc itself is not a finding).

## 9. Real Impact

- Standalone `.map` exposure → rejected (`source_map_alone`).
- `.map` + unredacted API key → P0.
- `.map` + internal-only endpoint → P1 (chains to IDOR /
  unauthenticated on the revealed endpoint).
- `.git` exposure → P0 (full source disclosure).

## 10. Chains

- **Source map + unredacted secret** (chained to the secret
  class, P0).
- **Source map + internal endpoint** (chained to
  `exposed_unauthenticated` once the agent confirms the
  endpoint, P1).
- **`.env` + cloud creds** (P0).

## 11. Related Skills

- `prometheus/core/recon.py` (mine the JS bundle list).
- `prometheus/core/always_rejected.py` (the `source_map_alone`
  rule).
- `prometheus/skills/data/conditionally_valid.json`.

## 12. Validation Heuristics

- A source map that maps to a *minified* source is informational
  (no real disclosure).
- A `.env` file that contains only public-safe values (e.g.,
  `NODE_ENV=production`) is informational.
- A `webpack.stats.json` that contains no secrets and no
  internal endpoints is informational.
