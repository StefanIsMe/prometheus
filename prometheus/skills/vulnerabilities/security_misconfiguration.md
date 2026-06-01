---
name: security_misconfiguration
description: Security misconfiguration testing covering exposed panels, default credentials, missing headers, permissive CORS, cloud IAM issues, and metadata endpoint access
---

# Security Misconfiguration

OWASP A02 — Security misconfiguration is the most commonly seen issue. This includes insecure default configurations, incomplete or ad-hoc configurations, open cloud storage, misconfigured HTTP headers, and verbose error messages containing sensitive information.

## Attack Surface

**Web Server & Application**
- Default pages and configurations (Apache, Nginx, IIS)
- Exposed admin panels, management consoles, debug endpoints
- Missing or misconfigured security headers
- Verbose error pages and debug modes
- Directory listing and path-based information disclosure

**Cloud Infrastructure**
- IAM policies and role configurations
- Storage bucket permissions (S3, GCS, Azure Blob)
- Metadata endpoint access (169.254.169.254)
- Security group and network ACL configurations
- Serverless function permissions

**Network Services**
- Unnecessary open ports and services
- Default credentials on management interfaces
- Unencrypted protocols (HTTP, FTP, Telnet)
- SNMP with default community strings

**Application Configuration**
- CORS policy permissiveness
- Session management configuration
- Rate limiting and brute force protection

## Key Vulnerabilities

### Exposed Admin Panels & Debug Endpoints

**Discovery**
```bash
# Common admin paths
/admin /administrator /admin-panel /dashboard
/wp-admin /wp-login.php (WordPress)
/phpmyadmin /adminer (Database admin)
/actuator /actuator/env /actuator/health (Spring Boot)
/_debug /debug /debug/vars /debug/pprof (Go)
/console /rails/info /rails/mailers (Ruby on Rails)
/server-status /server-info (Apache)
/nginx_status (Nginx)
/solr/admin /admin/collections (Solr)
/elasticsearch /_cat /_cluster (Elasticsearch)
/grafana /kibana /prometheus (Monitoring)
/jenkins /blue (Jenkins)
/manager /host-manager (Tomcat)
/airflow (Apache Airflow)

# Automated discovery
ffuf -u https://target.com/FUZZ -w /path/to/admin-paths.txt -mc 200,301,302,403
nuclei -u https://target.com -t technologies/
```

**Testing Default Credentials**
```bash
# Common default credentials
admin:admin, admin:password, root:root, root:toor
administrator:administrator, guest:guest
test:test, demo:demo, user:user

# Service-specific defaults
# Tomcat: tomcat:tomcat, admin:admin
# Jenkins: admin:admin (initial setup)
# MongoDB: no auth by default (pre-4.0)
# Elasticsearch: no auth by default (pre-8.0)
# Redis: no auth by default
# MySQL: root with no password (default install)

# Automated testing
hydra -l admin -P /path/to/passwords.txt target.com http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"
medusa -h target.com -u admin -P /path/to/passwords.txt -M http
```

### Security Headers — DO NOT INVESTIGATE

**SKIP THIS ENTIRELY.** Header analysis wastes time and produces findings that are universally rejected on HackerOne. Do NOT run `curl -sI` to check headers. Do NOT analyze CSP policies. Do NOT check for missing or deprecated headers.

Focus instead on: default credentials, exposed panels, verbose errors, directory listing, source maps, cookie misconfigurations on session cookies, CORS misconfigurations that allow credential theft.

### CORS Misconfiguration — THIS IS REPORTABLE

CORS misconfigurations that allow credential theft ARE real vulnerabilities. Focus here instead of headers.

### Static Site Data API Audit

For sites serving static JSON/XML data files (SPAs, headless CMS, JAMstack):

**Step 1: Discover data endpoints**
```bash
# Check robots.txt for hidden paths
curl -s https://target.com/robots.txt

# Check sitemap.xml for all URLs
curl -s https://target.com/sitemap.xml | grep -oE '<loc>[^<]+</loc>'

# Common data paths
for path in /data/ /api/ /content/ /assets/ /static/ /feeds/ /json/; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com$path")
  [ "$code" != "404" ] && echo "FOUND: $path ($code)"
done
```

**Step 2: Sample data files for sensitive content**
```bash
# Download a sample of data files
curl -s https://target.com/data/articles/ | head -50

# Check for:
# - Unpublished/draft content (draft flags, unpublished dates)
# - Internal metadata (author emails, user IDs, internal tags)
# - Injection vectors in HTML fields (dangerouslySetInnerHTML sinks)
# - Overly permissive data (more fields than UI shows — PII in API)
```

**Step 3: Check volume and rate limiting**
```bash
# Large data APIs (100+ files) — check for:
# - Rate limiting: rapid-fire requests to see if throttled
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code} " "https://target.com/data/articles/$i.json"
done
echo ""

# - Pagination: can an attacker dump all data?
curl -s "https://target.com/api/articles?limit=10000" | wc -c

# - CORS on data endpoints
curl -sI -H "Origin: https://evil.com" "https://target.com/data/articles/1.json" | grep -i "access-control"
```

**Step 4: Check for hidden/unlisted content**
```bash
# Sequential ID enumeration
for i in $(seq 1 100); do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/data/articles/$i.json")
  [ "$code" = "200" ] && echo "FOUND: article $i"
done

# Check for backup/draft files
curl -s "https://target.com/data/articles/draft.json" | head -5
curl -s "https://target.com/data/articles/backup.json" | head -5
```

**Reporting:**
- Unpublished content accessible: CVSS 5.3 (medium) — information disclosure
- PII in public API responses: CVSS 7.3 (high) — privacy violation
- No rate limiting on data API: CVSS 3.1 (low) — scraping/enumeration
- Draft content accessible: CVSS 4.3 (medium) — business logic flaw

### Permissive CORS

```bash
# Test CORS with arbitrary origin
curl -sI -H "Origin: https://evil.com" https://target.com/api/data | grep -i "access-control"

# Test with null origin
curl -sI -H "Origin: null" https://target.com/api/data | grep -i "access-control"

# Test with subdomain
curl -sI -H "Origin: https://sub.target.com" https://target.com/api/data | grep -i "access-control"

# Vulnerable patterns:
# Access-Control-Allow-Origin: *
# Access-Control-Allow-Origin: https://evil.com (reflected)
# Access-Control-Allow-Origin: null
# Access-Control-Allow-Credentials: true with wildcard or reflected origin

# Test with credentials
curl -sI -H "Origin: https://evil.com" -H "Cookie: session=abc" https://target.com/api/data | grep -i "access-control"
```

### Directory Listing

```bash
# Check common directories
curl -s https://target.com/uploads/ | grep -i "index of"
curl -s https://target.com/assets/ | grep -i "directory listing"
curl -s https://target.com/static/ | grep -i "parent directory"

# Nginx autoindex
curl -s https://target.com/files/ | grep -i "autoindex"

# Apache Options +Indexes
curl -s https://target.com/images/ | grep -i "index of /"

# Check for sensitive files in listed directories
curl -s https://target.com/.git/config
curl -s https://target.com/.env
curl -s https://target.com/wp-config.php.bak
```

### Verbose Error Pages

```bash
# Trigger errors to reveal information
curl -s "https://target.com/nonexistent" -o /dev/null -w "%{http_code}"
curl -s "https://target.com/api/data'OR'1'='1" # SQL error
curl -s "https://target.com/page?debug=true" # Debug mode

# Common error triggers
# Invalid input: ' " < > {{ }} ${} %00
# Boundary conditions: very long strings, special characters
# Missing parameters: send request without required fields
# Invalid content type: send XML to JSON endpoint

# Stack trace indicators
# Java: "at com.company.package.Class.method(File.java:42)"
# Python: "Traceback (most recent call last):"
# .NET: "Server Error in '/' Application."
# PHP: "Fatal error: Uncaught exception"
# Node.js: "Error: Cannot find module"
# Ruby: "NoMethodError in Controller#action"
```

### Cloud Metadata Endpoint Access

**AWS**
```bash
# IMDSv1 (vulnerable to SSRF)
curl -s http://169.254.169.254/latest/meta-data/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://169.254.169.254/latest/user-data

# IMDSv2 (requires token)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/

# Check if IMDSv2 is enforced
curl -s -H "X-aws-ec2-metadata-token: invalid" \
  http://169.254.169.254/latest/meta-data/
# If still returns data, IMDSv1 is not disabled
```

**GCP**
```bash
# Requires Metadata-Flavor header
curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/
curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Project metadata
curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/project/project-id
```

**Azure**
```bash
# Requires Metadata header
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

### S3 Bucket Exposure

```bash
# List bucket contents (if public)
curl -s https://bucket-name.s3.amazonaws.com/
curl -s https://s3.amazonaws.com/bucket-name/

# Check bucket permissions
aws s3api get-bucket-acl --bucket bucket-name
aws s3api get-bucket-policy --bucket bucket-name

# Check for public access
aws s3api get-public-access-block --bucket bucket-name

# Try common bucket name variations
for name in target target-backup target-assets target-logs target-internal target-staging; do
  curl -s -o /dev/null -w "%{http_code}" https://$name.s3.amazonaws.com/
done

# Check for anonymous listing
aws s3 ls s3://bucket-name --no-sign-request
```

### Unnecessary Services & Ports

```bash
# Port scan for unnecessary services
nmap -sV -p 1-65535 target.com --top-ports 1000

# Services that should not be exposed:
# SSH (22), Telnet (23), FTP (21), SMTP (25)
# SNMP (161), RDP (3389), VNC (5900)
# Databases: MySQL (3306), PostgreSQL (5432), MongoDB (27017), Redis (6379)
# Message queues: RabbitMQ (5672, 15672), Kafka (9092)
# Debug: remote debugging ports

# Check for exposed internal services
nuclei -u target.com -t network/
```

## Tools

**Automated Scanners**
```bash
# Nuclei — misconfiguration templates
nuclei -u https://target.com -t http/misconfiguration/
nuclei -u https://target.com -t http/exposures/
nuclei -u https://target.com -t http/default-logins/

# Nikto — web server scanner
nikto -h https://target.com
nikto -h https://target.com -Tuning 123  # Misconfigurations only

# httpx — probe for headers and tech
httpx -l urls.txt -sc -title -tech-detect -follow-redirects

# WAFW00F — WAF detection
wafw00f https://target.com
```

**Cloud Security**
```bash
# ScoutSuite — multi-cloud security auditing
scout aws
scout gcp
scout azure

# Prowler — AWS security assessment
prowler aws --checks-directory checks/

# CloudSploit — cloud security scanning
node index.js --config config.js
```

## Bypass Techniques

**Header Bypass**
- `X-Forwarded-Host: admin.internal` to bypass host-based restrictions
- `X-Forwarded-For: 127.0.0.1` to bypass IP-based access controls
- `X-Original-URL: /admin` to bypass URL-based restrictions
- `X-Rewrite-URL: /admin` for IIS URL rewrite bypass

**CORS Bypass**
- Subdomain takeover → trusted origin → CORS abuse
- `null` origin via sandboxed iframe
- Regex bypass in origin validation: `target.com.evil.com`

**Cloud Metadata Bypass**
- IMDSv1 via SSRF when IMDSv2 is not enforced
- DNS rebinding to bypass IP-based restrictions
- Container escape to host network for metadata access

## Testing Methodology

1. **Service enumeration** — Port scan, technology fingerprint, version detection
2. **Header audit** — Check all security headers with recommended values
3. **Default credential test** — Attempt default credentials on all management interfaces
4. **Error handling** — Trigger errors to check for information leakage
5. **CORS testing** — Verify origin validation logic
6. **Cloud metadata** — Test IMDS access from application context
7. **Storage permissions** — Check S3/GCS/Azure Blob public access
8. **Directory listing** — Probe for accessible directories and sensitive files
9. **Debug endpoints** — Check for exposed debug, metrics, and admin endpoints

## Validation

1. Missing security header: RECONNAISSANCE ONLY — do NOT file as standalone. Use to identify attack surface, then demonstrate the concrete attack (e.g., iframe clickjack, script injection, cookie theft). The curl output is NOT a PoC — it's recon data.
2. Deprecated header value: show the curl command with the wrong value, demonstrate the actual bypass technique that exploits it
3. Weak CSP policy: parse the policy, find an actual injection point, execute a payload that the weak CSP fails to block
4. Default credentials: show access to management interface
5. Permissive CORS: show cross-origin data theft (actual data exfiltrated, not just header analysis)
6. Sensitive data from cloud metadata or exposed storage
7. Static data API: show unpublished content, PII, or enumeration without rate limiting
8. Cookie misconfiguration: show the Set-Cookie header with missing flags AND demonstrate session theft or CSRF

## Remediation

- Implement security header baseline (CSP, HSTS, X-Content-Type-Options, etc.)
- Remove default credentials and enforce strong password policy
- Restrict CORS to specific trusted origins
- Disable directory listing and unnecessary services
- Enforce IMDSv2 and disable IMDSv1 on cloud instances
- Apply principle of least privilege to IAM roles and network access
- Disable debug mode and verbose error pages in production
- Regular security configuration audits with automated scanning

## Pro Tips

1. Security headers vary by endpoint — check API, admin, and static file paths separately
2. Cloud metadata access often depends on network position — test from application context
3. Default credentials change between versions — check version-specific defaults
4. CORS policies may differ between authenticated and unauthenticated endpoints
5. Error pages may leak different information based on content type (HTML vs JSON)
6. Check both IPv4 and IPv6 — firewall rules may differ
7. Internal services may be exposed via reverse proxy misconfigurations

## Summary

Security misconfiguration is a broad category that encompasses the gap between intended security posture and actual deployment. Attackers systematically probe for defaults, missing controls, and permissive configurations. Every layer — from cloud infrastructure to application headers — must be hardened against common misconfiguration patterns.
