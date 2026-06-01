---
name: threat_intelligence
description: Pre-scan threat intelligence gathering from CISA KEV, NVD, GHSA, OSV.dev, and Exploit-DB
---

# Threat Intelligence

## Overview
Before performing vulnerability scanning, always gather threat intelligence to identify known exploited vulnerabilities (KEVs) and actively targeted CVEs for the technologies in scope. This ensures scanning is prioritized around real-world threats rather than theoretical weaknesses.

**IMPORTANT**: Use the `query_threat_feeds` tool FIRST. It queries 4 sources in parallel:
- CISA KEV (actively exploited vulnerabilities)
- NVD (National Vulnerability Database)
- OSV.dev (open source vulnerabilities)
- GHSA (GitHub Security Advisories)

The tool takes a list of `{technology, version}` fingerprints and returns prioritized CVEs with scores. Feed data is pre-cached daily at 06:00 ICT via systemd timer.

## Pre-Scan Intelligence Gathering

### 1. Update Nuclei Templates First
Before any scanning session, always update nuclei templates to ensure the latest CVE checks are available:
```bash
exec_command('nuclei -update-templates')
```
This pulls the latest community templates including CVE-specific checks.

### 2. Fingerprint Technology Stack
After reconnaissance, fingerprint all discovered technologies and their exact versions:
- Web server and version (Apache, Nginx, IIS)
- Framework and version (WordPress, Django, Laravel, Express, etc.)
- Language runtime and version (PHP, Python, Node.js, Java, .NET)
- Database and version (MySQL, PostgreSQL, MongoDB, Redis)
- CMS and plugins/extensions with versions
- JavaScript libraries and versions
- SSL/TLS versions and cipher suites

### 3. CVE Research
For each discovered technology and version, research known vulnerabilities:

**CISA Known Exploited Vulnerabilities (KEV) Catalog:**
- URL: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Check if any discovered technology/version has CVEs listed in KEV
- KEV-listed CVEs are ACTIVELY EXPLOITED in the wild - prioritize these
- Use web_search to query: `site:cisa.gov known exploited vulnerabilities [technology]`

**NVD (National Vulnerability Database) API:**
- URL: https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=
- Search by technology name and version
- Focus on CVEs with CVSS 7.0+ (High/Critical)
- Check published dates - recent CVEs are more likely relevant

**Exploit-DB:**
- URL: https://www.exploit-db.com/
- Search for public exploits for discovered CVEs
- Verify if exploit code is available and functional
- Available exploits dramatically increase testing priority

**GitHub Security Advisories (GHSA):**
- URL: https://github.com/advisories
- Search by technology/ecosystem: `query=type:reviewed+ecosystem:pip+severity:high`
- API: `https://api.github.com/advisories?ecosystem=pip&severity=high,critical&per_page=100`
- Ecosystems: pip, npm, maven, nuget, go, rubygems, cargo, composer, erlang, swift
- Focus on advisories from last 90 days with known exploits
- Use web_search: `site:github.com/advisories [technology] [version]`

**OSV.dev (Open Source Vulnerabilities):**
- URL: https://osv.dev/
- API: `https://api.osv.dev/v1/query` (POST with package name + version)
- Aggregates GHSA, NVD, Go vulns, RustSec, PyPI advisories, and more
- Use for dependency/library version matching
- curl example: `curl -X POST https://api.osv.dev/v1/query -d '{"package":{"name":"[pkg]","ecosystem":"PyPI"},"version":"[ver]"}'`

**Vendor Security Advisories:**
- Check vendor-specific security pages for discovered technologies
- Cloudflare: https://www.cloudflare.com/trust-hub/security-updates/
- AWS: https://aws.amazon.com/security/security-bulletins/
- Google Cloud: https://cloud.google.com/chronicle/docs/reference/security-advisory
- Microsoft: https://msrc.microsoft.com/update-guide
- Use web_search: `[vendor] security advisory [technology] [year]`

**General Research:**
- Search for `CVE [year] [technology] vulnerability` using web_search
- Focus on 2024-2026 CVEs for current relevance
- Check vendor security advisories and changelogs
- Look for recent security blog posts about the technology

### 4. Map CVEs to Nuclei Templates
For each identified CVE, check if a nuclei template exists:
```bash
exec_command('nuclei -tags [cve-id] -u [target]')
# Example:
exec_command('nuclei -tags cve-2024-1234 -u https://target.com')
```

Use vulnx (cvemap) for quick CVE-to-template mapping:
```bash
exec_command('vulnx search [technology]')
```

### 5. Prioritization Matrix
Rank discovered CVEs by exploitation priority:

| Priority | Criteria |
|----------|----------|
| **P0 - Critical** | In CISA KEV + public exploit available |
| **P1 - High** | In CISA KEV OR public exploit available |
| **P2 - Medium** | CVSS 7.0+ with no public exploit |
| **P3 - Low** | CVSS 4.0-6.9, theoretical |

**Always prioritize CVEs with known exploits over theoretical vulnerabilities.**

## Workflow Integration

```
Reconnaissance
    ↓
Technology Fingerprinting
    ↓
CVE Research (CISA KEV → NVD → Exploit-DB)
    ↓
Map CVEs to Nuclei Templates
    ↓
Run Targeted Nuclei Scans with CVE Tags
    ↓
Validate Findings with PoCs
    ↓
Report
```

## Key Principles
- **Anonymization first** — verify Tor is active before any scanning
- Threat intelligence DRIVES scanning priority, not the other way around
- A CVE in CISA KEV means it's being exploited RIGHT NOW - test it first
- **Reputation protection** — do NOT file findings that will be closed as "Not Applicable". Missing headers, version disclosure, deprecated ciphers without exploitation, and theoretical reports from automated scanners are rejected by most programs and damage your HackerOne reputation. Always check the target program's "Out of Scope" section before filing.
- **Common out-of-scope findings** (most HackerOne programs reject these):
  - Missing security headers without demonstrated exploitation
  - Deprecated TLS/SSL configurations without demonstrated exploitation
  - Version disclosure / banner grabbing
  - Self-XSS
  - Clickjacking on non-sensitive actions
  - Rate limiting on non-authenticated endpoints
  - Missing HttpOnly/Secure cookie flags (some programs)
  - Theoretical reports from automated scanners without working PoC
- Focus on findings that get PAID: auth bypass, RCE, SQLi with data access, SSRF, account takeover, privilege escalation, IDOR, sensitive data exposure
- Always verify tool/template freshness (update before scanning)
- Cross-reference multiple sources (CISA, NVD, Exploit-DB, OSV.dev, GitHub Advisories) for completeness
- Document the threat intelligence source for each CVE tested in reports
- Run `/workspace/.prometheus-threat-feeds/update_threat_feeds.sh` before scanning for fresh data
