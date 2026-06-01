---
name: supply_chain
description: Software supply chain attack testing covering dependency confusion, typosquatting, compromised packages, CI/CD poisoning, and lock file tampering
---

# Supply Chain Attacks

Software supply chain failures allow attackers to compromise the development pipeline itself — poisoning dependencies, build systems, and deployment mechanisms. Focus on dependency resolution flaws, package provenance gaps, CI/CD pipeline weaknesses, and transitive dependency risks that bypass traditional application security controls.

## Attack Surface

**Package Registries**
- npm (JavaScript), PyPI (Python), RubyGems, Maven Central, crates.io (Rust), Go modules
- Private/internal registries (Artifactory, Nexus, GitHub Packages, Verdaccio)
- Package scopes and namespace confusion (`@company/internal` vs `internal`)

**Dependency Resolution**
- Lock files: `package-lock.json`, `yarn.lock`, `Pipfile.lock`, `poetry.lock`, `Gemfile.lock`, `go.sum`
- Dependency ranges: `^1.0.0`, `>=2.0`, `latest` — resolve differently over time
- Transitive dependencies: packages you never explicitly install but inherit

**Build & CI/CD**
- GitHub Actions workflows, GitLab CI, Jenkins pipelines, CircleCI
- Build scripts: `postinstall`, `preinstall`, `prepare` hooks in npm
- Container base images, layer caching, multi-stage builds
- Code signing, artifact signing, SLSA provenance

**Distribution Channels**
- CDN-hosted libraries (cdnjs, unpkg, jsDelivr)
- Docker Hub images, Helm charts, Terraform modules
- Auto-update mechanisms, extension marketplaces

## Key Vulnerabilities

### Dependency Confusion

Attackers publish public packages matching internal package names with higher version numbers. Package managers resolve the public package instead of the private one.

**Reconnaissance**
```bash
# Find internal package names from error messages, lock files, source code
grep -r "require\|import\|from" --include="*.js" --include="*.py" --include="*.rb" .

# Check package.json for private registry config
cat .npmrc
cat .yarnrc

# Look for internal scope declarations
cat package.json | jq '.dependencies | keys'
cat package.json | jq '.publishConfig'

# Examine lock files for registry URLs
grep "resolved" package-lock.json | grep -v "registry.npmjs.org"
grep "source" Pipfile.lock | grep -v "pypi.org"
```

**Testing**
```bash
# Check if internal names exist on public registries
npm view @company-internal/auth 2>/dev/null
pip index versions company-auth 2>/dev/null
gem search company-auth

# Compare version resolution
npm info <package> versions --json
# Look for suspiciously high version numbers

# Test namespace confusion
# If internal uses "company-auth" (no scope), publish "company-auth" on npm with higher version
# If internal uses "@company/auth", check if "company/auth" exists unscoped
```

**Validation**
- Install in isolated environment and check if public package is resolved
- Verify `registry` field in lock files points to private registry
- Test with `--registry` flag to force private registry resolution

### Typosquatting

Malicious packages with names similar to popular ones.

**Common Patterns**
```bash
# One-off character swaps
requests vs requets vs reqeusts
lodash vs lodesh vs lodahs

# Plural/singular confusion
express vs expresss
flask vs flasks

# Prefix/suffix additions
request vs requests-plus
chalk vs chalk-js

# Check for typosquatting in your dependencies
npm ls --all | awk -F@ '{print $1}' | sort -u
pip list | awk '{print $1}' | while read pkg; do
  # Check Levenshtein distance to popular packages
  echo "$pkg"
done
```

**Automated Detection**
```bash
# Use socket.dev to analyze dependency risk
# https://socket.dev/npm/package/<name>

# Check download counts (low = suspicious)
npm view <package> --json | jq '.time'
pip show <package>

# Examine package metadata age
npm view <package> time.created
npm view <package> maintainers
```

### Compromised Packages

Legitimate packages taken over by malicious actors via:
- Maintainer account compromise
- Abandoned package adoption
- Malicious PR merge to dependency

**Detection**
```bash
# Check for suspicious recent changes
npm view <package> time --json
# Compare latest publish date with previous version

# Analyze package contents before install
npm pack <package> --dry-run
npm pack <package> && tar -tf <package>-*.tgz

# Look for obfuscated code
find node_modules/<package> -name "*.js" -exec grep -l "eval\|Function(" {} \;
find node_modules/<package> -name "*.js" -exec grep -l "atob\|btoa\|fromCharCode" {} \;

# Check for network calls in packages that shouldn't need them
grep -r "http\|https\|fetch\|axios\|request" node_modules/<package>/ --include="*.js" -l
grep -r "dns\|socket\|net\." node_modules/<package>/ --include="*.js" -l
```

### Lock File Tampering

Attackers modify lock files to redirect dependencies to malicious sources.

**Inspection**
```bash
# Verify lock file integrity
git diff HEAD~1 -- package-lock.json
git diff HEAD~1 -- yarn.lock
git diff HEAD~1 -- Pipfile.lock

# Check for unexpected registry URLs
grep "resolved" package-lock.json | grep -v "registry.npmjs.org"
grep "resolved" yarn.lock | grep -v "registry.yarnpkg.com"

# Verify integrity hashes
node -e "
const lock = require('./package-lock.json');
Object.entries(lock.packages || {}).forEach(([name, pkg]) => {
  if (pkg.resolved && !pkg.resolved.includes('registry.npmjs.org')) {
    console.log('SUSPICIOUS:', name, pkg.resolved);
  }
});
"

# Compare resolved versions with expected
npm ls --json | jq '.dependencies | to_entries[] | {name: .key, version: .value.version}'
```

### CI/CD Pipeline Poisoning

**GitHub Actions**
```bash
# Review workflow files for injection points
cat .github/workflows/*.yml

# Dangerous patterns:
# - pull_request_target with checkout of PR head
# - Uses of ${{ github.event.pull_request.title }} in run steps
# - Third-party actions pinned to mutable refs (branch, not SHA)
# - Excessive permissions

# Check action references
grep -r "uses:" .github/workflows/
# Look for: uses: owner/action@main (mutable, can be poisoned)
# Safe: uses: owner/action@abc123def (pinned to SHA)

# Verify action integrity
# Compare pinned SHA with latest commit on action repo
git ls-remote https://github.com/owner/action.git HEAD
```

**Build Script Hooks**
```bash
# npm lifecycle scripts that execute arbitrary code
cat node_modules/<package>/package.json | jq '.scripts'
# Dangerous: preinstall, postinstall, prepare, preuninstall

# Examine what postinstall scripts actually do
find node_modules -name "package.json" -maxdepth 2 -exec \
  sh -c 'jq -r ".scripts.postinstall // empty" "$1"' _ {} \;

# Python setup.py hooks
find . -name "setup.py" -exec grep -l "cmdclass\|install_requires" {} \;
find . -name "pyproject.toml" -exec grep -l "build-system" {} \;
```

### CDN Dependency Hijacking

```bash
# Check CDN-hosted dependencies for integrity
# Missing SRI (Subresource Integrity) = tamperable
grep -r "integrity=" index.html
grep -r "<script src.*cdn" index.html

# Verify SRI hashes match actual content
curl -s https://cdn.example.com/lib.js | openssl dgst -sha384 -binary | openssl base64

# Check for deprecated/abandoned CDN libraries
# Libraries with no updates in 2+ years may have takeover risks
```

## Tools

**Dependency Analysis**
```bash
# npm audit — built-in vulnerability scanner
npm audit
npm audit --json | jq '.vulnerabilities | to_entries[] | {name: .key, severity: .value.severity}'

# pip-audit — Python dependency vulnerability scanner
pip-audit
pip-audit --format json --desc

# Trivy filesystem scan
trivy fs --scanners vuln .
trivy fs --scanners vuln --format json .

# OSV-Scanner (Google)
osv-scanner .

# Socket.dev CLI
npx socket optimize --dry-run
```

**Secret Detection in Dependencies**
```bash
# TruffleHog
trufflehog git file://. --only-verified
trufflehog npm --package <package>

# Gitleaks
gitleaks detect --source .

# Check for embedded credentials in node_modules
grep -r "password\|secret\|api_key\|token" node_modules/ --include="*.js" -l | head -20
```

**Package Provenance**
```bash
# npm provenance (SLSA)
npm audit signatures
# Verify attestations on published packages

# Check package integrity
npm integrity <package>

# Python package verification
pip hash <wheel-file>
twine check dist/*
```

## Bypass Techniques

**Namespace Confusion**
- Publish to public registry with higher version than private package
- Exploit missing `--registry` enforcement in CI
- Abuse scope confusion: `@company/pkg` vs `company-pkg`

**Typosquatting Evasion**
- Use Unicode homoglyphs in package names
- Register packages with very similar names to popular transitive deps
- Wait for natural adoption through copy-paste errors

**Lock File Manipulation**
- Modify integrity hashes in lock files during PR review
- Add extra resolved URLs pointing to attacker-controlled registry
- Exploit lock file format differences across tools (npm vs yarn)

**CI/CD Injection**
- Exploit `pull_request_target` workflows that checkout untrusted PR code
- Inject payloads through PR titles, branch names, or commit messages used in `run:` steps
- Abuse GitHub Actions cache poisoning to inject malicious artifacts
- Use artifact poisoning to swap build outputs between jobs

## Testing Methodology

1. **Dependency inventory** — Map all direct and transitive dependencies with versions and sources
2. **Lock file audit** — Verify lock files exist, are committed, and contain expected registry URLs
3. **Registry configuration** — Check `.npmrc`, `.pypirc`, `.gemrc` for registry pinning and auth
4. **Version pinning** — Identify range specifiers that allow uncontrolled upgrades
5. **Build script review** — Audit all lifecycle scripts and CI/CD configurations
6. **Provenance verification** — Check for SLSA attestations, package signatures, integrity hashes
7. **Internal package exposure** — Test if internal package names exist on public registries
8. **Transitive analysis** — Map full dependency tree and identify high-risk transitive deps
9. **Update mechanism testing** — Verify auto-update channels use signature verification

## Validation

1. Demonstrate dependency confusion resolving public package in isolated test environment
2. Show typosquatting package with suspicious code behavior (network calls, file access)
3. Prove lock file tampering goes undetected in CI pipeline
4. Identify CI/CD workflow with exploitable injection point (with PoC PR/commit)
5. Show missing integrity verification on CDN dependencies or auto-update mechanism

## Remediation

- Pin all dependencies to exact versions with integrity hashes
- Use private registry with namespace reservation and scope enforcement
- Enable `--frozen-lockfile` in CI (`npm ci` instead of `npm install`)
- Pin GitHub Actions to commit SHAs, not branch names
- Implement dependency review in PR checks
- Use tools like Socket.dev or Snyk for continuous monitoring
- Restrict npm lifecycle scripts with `--ignore-scripts` where possible
- Enable npm provenance and SLSA attestations for published packages
- Regularly audit transitive dependencies and remove unused ones

## Summary

Supply chain attacks target the trust relationships between developers and their tooling. A single compromised dependency can cascade through thousands of downstream projects. Focus on dependency resolution logic, build pipeline integrity, and provenance verification — the weakest link in the chain determines overall security.
