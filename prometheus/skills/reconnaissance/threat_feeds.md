---
name: threat_feeds
description: Automated threat intelligence gathering from CISA KEV, NVD, OSV.dev, and GitHub Security Advisories
---

# Threat Feeds Reconnaissance Skill

## Overview

Query multiple threat intelligence sources at scan start to identify actively exploited vulnerabilities, map them to detected technologies, and prioritize exploitation paths.

## Supported Feeds

| Feed | API Endpoint | Auth Required |
|------|-------------|---------------|
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | No |
| NVD | `https://services.nvd.nist.gov/rest/json/cves/2.0` | Optional API key |
| OSV.dev | `https://api.osv.dev/v1/query` | No |
| GitHub Advisory | `https://api.github.com/graphql` | Token recommended |
| Exploit-DB | `https://www.exploit-db.com/` | No |

## Workflow

1. **Fingerprint technologies** — Use wappalyzer, whatweb, or httpx tech detection on targets
2. **Query threat feeds** — Search each feed for CVEs matching discovered tech
3. **Map CVEs to nuclei templates** — Cross-reference with local nuclei templates
4. **Prioritize by exploitation status** — KEV entries first, then known exploits, then all CVEs

## Query Commands

### CISA KEV Catalog

```bash
# Download full KEV catalog
curl -s "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" \
  -o /tmp/prometheus-threat-intel/cisa-kev.json

# Search KEV for a specific product
jq '.vulnerabilities[] | select(.product | test("apache"; "i"))' /tmp/prometheus-threat-intel/cisa-kev.json

# List all KEV CVEs
jq -r '.vulnerabilities[].cveID' /tmp/prometheus-threat-intel/cisa-kev.json
```

### NVD API (CVE Search)

```bash
# Search NVD by keyword
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=apache+httpd"

# Search by CPE (Common Platform Enumeration)
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:a:apache:http_server:2.4.49"

# With API key for higher rate limits
curl -s -H "apiKey: YOUR_KEY" \
  "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=nginx"

# Extract CVE IDs from NVD response
jq -r '.vulnerabilities[].cve.id' response.json
```

### OSV.dev (Open Source Vulnerabilities)

```bash
# Query by package name and version
curl -s -X POST "https://api.osv.dev/v1/query" \
  -H "Content-Type: application/json" \
  -d '{"package":{"name":"log4j","ecosystem":"Maven"},"version":"2.14.1"}'

# Query by commit
curl -s -X POST "https://api.osv.dev/v1/query" \
  -d '{"commit":"6879efc2c1596d11a6a6ad296f80063b558d4e07"}'

# Bulk query
curl -s -X POST "https://api.osv.dev/v1/querybatch" \
  -H "Content-Type: application/json" \
  -d '{"queries":[{"package":{"name":"lodash","ecosystem":"npm"}},{"package":{"name":"express","ecosystem":"npm"}}]}'

# Get full vulnerability details
curl -s "https://api.osv.dev/v1/vulns/CVE-2021-44228"
```

### GitHub Security Advisories (GraphQL)

```bash
# Search advisories for a package
curl -s -X POST "https://api.github.com/graphql" \
  -H "Authorization: bearer $GITHUB_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ securityAdvisories(first: 100, orderBy: {field: PUBLISHED_AT, direction: DESC}) { nodes { ghsaId summary severity publishedAt vulnerabilities(first: 10, ecosystem: NPM, package: \"lodash\") { nodes { advisory { ghsaId } vulnerableVersionRange firstPatchedVersion { identifier } } } } } }"
  }'

# REST API: list advisories for a repo
curl -s "https://api.github.com/repos/owner/repo/security-advisories" \
  -H "Authorization: bearer $GITHUB_TOKEN"

# Search GHSA by ecosystem
curl -s "https://api.github.com/advisories?ecosystem=npm&severity=critical&per_page=100" \
  -H "Accept: application/vnd.github+json"
```

### Exploit-DB (via searchsploit)

```bash
# Search by software name
searchsploit apache 2.4.49

# Search by CVE
searchsploit --cve 2021-41773

# JSON output for parsing
searchsploit --json apache 2.4.49

# Search nuclei templates for a CVE
find ~/nuclei-templates -name "*.yaml" -exec grep -l "CVE-2021-44228" {} \;
```

## Prioritization Logic

```
priority_score = 0

if CVE in CISA_KEV:
    priority_score += 100   # Actively exploited in the wild
if CVE has public_exploit:
    priority_score += 50    # Exploit available
if severity == "CRITICAL":
    priority_score += 30
elif severity == "HIGH":
    priority_score += 20
if CVSS >= 9.0:
    priority_score += 10
if has_nuclei_template:
    priority_score += 25    # Automated exploitation possible

# Sort targets by priority_score descending
```

## Integration with prometheus Scan

Run `scripts/update_threat_feeds.sh` before scan to refresh local caches. Then:

```bash
# Load KEV catalog into memory
CISA_CVES=$(jq -r '.vulnerabilities[].cveID' /tmp/prometheus-threat-intel/cisa-kev.json)

# For each discovered tech component, check if it has a KEV entry
for cve in $CISA_CVES; do
    # Match against nuclei templates
    TEMPLATE=$(find ~/nuclei-templates -name "*.yaml" -exec grep -l "$cve" {} \; 2>/dev/null | head -1)
    if [[ -n "$TEMPLATE" ]]; then
        echo "HIGH PRIORITY: $cve -> $TEMPLATE"
    fi
done
```

## Notes

- NVD rate limit: 5 requests/30s without API key, 50/30s with key
- OSV.dev has no documented rate limit but be respectful
- GitHub GraphQL API: 5,000 points/hour with token
- CISA KEV catalog updates daily; re-download at scan start
- Always combine feed data with active verification (nuclei) before reporting
