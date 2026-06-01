---
name: cryptographic_failures
description: Cryptographic failure testing covering weak TLS, expired certs, insecure hashing, hardcoded secrets, weak RNG, and missing encryption
---

# Cryptographic Failures

OWASP A04 — Failures related to cryptography which often lead to data exposure, authentication bypass, or credential compromise. Focus on transport security, data-at-rest encryption, password storage, secret management, and cryptographic implementation weaknesses.

## Attack Surface

**Transport Layer**
- TLS/SSL configurations on HTTPS, SMTPS, IMAPS, FTPS, WebSocket Secure
- Certificate validity, chain, and trust store configuration
- Protocol and cipher suite negotiation
- HSTS, certificate pinning, and downgrade protection

**Data at Rest**
- Database encryption (TDE, column-level, application-level)
- File system encryption, backup encryption
- Key storage and management (HSM, KMS, environment variables)
- Secrets in code, config files, CI/CD variables, containers

**Password & Credential Storage**
- Hashing algorithm selection and configuration
- Salt generation and application
- Iteration/work factor settings
- Legacy migration from weak algorithms

**Cryptographic Implementation**
- Random number generation quality
- IV/nonce reuse, padding oracle vulnerabilities
- Algorithm selection and parameter choices
- Custom cryptographic implementations

## Key Vulnerabilities

### Weak TLS Configuration

**Testing with testssl.sh**
```bash
# Full assessment
testssl.sh https://target.com

# Quick cipher suite check
testssl.sh -E https://target.com

# Test specific protocol versions
testssl.sh -p https://target.com

# Check for specific vulnerabilities
testssl.sh --vulnerable https://target.com

# Test for BEAST, POODLE, Heartbleed, ROBOT
testssl.sh -W https://target.com
```

**Testing with sslyze**
```bash
# Full scan
sslyze --regular target.com:443

# Certificate analysis
sslyze --certinfo target.com:443

# Check for weak ciphers
sslyze --tlsv1 --tlsv1_1 target.com:443

# Session resumption testing
sslyze --session_renewal target.com:443

# JSON output for automation
sslyze --json_out=- --regular target.com:443
```

**Testing with nmap**
```bash
# Enumerate cipher suites
nmap --script ssl-enum-ciphers -p 443 target.com

# Check for specific vulnerabilities
nmap --script ssl-heartbleed -p 443 target.com
nmap --script ssl-poodle -p 443 target.com
nmap --script ssl-ccs-injection -p 443 target.com

# Certificate information
nmap --script ssl-cert -p 443 target.com
```

**Weak Cipher Indicators**
```
# Insecure protocols
SSLv2, SSLv3, TLSv1.0, TLSv1.1

# Weak cipher suites
RC4, DES, 3DES, MD5-based MACs, NULL ciphers, EXPORT ciphers
CBC-mode ciphers (vulnerable to BEAST/POODLE)
RSA key exchange (no forward secrecy)

# Secure minimum
TLSv1.2+ with AEAD ciphers (GCM, ChaCha20)
ECDHE or DHE key exchange (forward secrecy)
```

### Missing HSTS

```bash
# Check HSTS header
curl -sI https://target.com | grep -i strict-transport-security

# Missing HSTS = vulnerable to SSL stripping
# Weak HSTS = missing includeSubDomains or insufficient max-age

# Check preload readiness
curl -sI https://target.com | grep -i "strict-transport-security"
# Good: max-age=31536000; includeSubDomains; preload
# Bad: max-age=86400 (too short), missing includeSubDomains

# Test HTTP to HTTPS redirect (required for HSTS)
curl -sI http://target.com | head -5
```

### Expired or Invalid Certificates

```bash
# Check certificate expiration
echo | openssl s_client -connect target.com:443 -servername target.com 2>/dev/null | \
  openssl x509 -noout -dates

# Check certificate chain
echo | openssl s_client -connect target.com:443 -servername target.com -showcerts 2>/dev/null

# Verify certificate matches hostname
echo | openssl s_client -connect target.com:443 -servername target.com 2>/dev/null | \
  openssl x509 -noout -text | grep -A1 "Subject Alternative Name"

# Check for self-signed certificates
echo | openssl s_client -connect target.com:443 2>&1 | grep "self-signed\|verify return"
```

### Weak Password Hashing

**Identify Algorithm**
```bash
# From database dump or hash format
# MD5 (32 hex): 5f4dcc3b5aa765d61d8327deb882cf99
# SHA1 (40 hex): 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
# SHA256 (64 hex): 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
# bcrypt ($2a$/$2b$): $2a$10$N9qo8uLOickgx2ZMRZoMye...
# PBKDF2: pbkdf2_sha256$...
# Argon2: $argon2id$...

# Check for MD5/SHA1/unsalted hashes
grep -r "md5\|sha1\|hashlib.md5\|hashlib.sha1" --include="*.py" --include="*.js" --include="*.php" .
grep -r "MD5\|SHA1\|MessageDigest" --include="*.java" .
```

**Weak Hashing Patterns**
```python
# Python - VULNERABLE
import hashlib
hash = hashlib.md5(password.encode()).hexdigest()
hash = hashlib.sha1(password.encode()).hexdigest()
hash = hashlib.sha256(password.encode()).hexdigest()

# Python - SECURE
import bcrypt
hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
# Or argon2
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
hash = ph.hash(password)
```

### Hardcoded Secrets

**TruffleHog**
```bash
# Scan repository
trufflehog git file://. --only-verified

# Scan specific files
trufflehog file://./config/database.yml

# Scan with custom rules
trufflehog git file://. --include-detectors aws,gcp,github,slack
```

**Gitleaks**
```bash
# Scan repository
gitleaks detect --source .

# Scan with report
gitleaks detect --source . --report-path gitleaks-report.json

# Scan staged changes
gitleaks protect --staged

# Scan specific paths
gitleaks detect --source . --path ".env,.env.production,config/"
```

**Manual Patterns**
```bash
# Common secret locations
grep -rn "password\|secret\|api_key\|apikey\|token\|private_key" \
  --include="*.py" --include="*.js" --include="*.yml" --include="*.yaml" \
  --include="*.json" --include="*.env" --include="*.conf" \
  --include="*.ini" --include="*.toml" .

# Environment files
cat .env .env.local .env.production .env.development 2>/dev/null
cat config/secrets.yml config/database.yml 2>/dev/null

# Docker and Kubernetes secrets
grep -rn "password\|secret" Dockerfile docker-compose.yml 2>/dev/null
grep -rn "password\|secret" k8s/*.yml k8s/*.yaml 2>/dev/null

# Client-side exposure
grep -rn "api_key\|apiKey\|token" static/ public/ dist/ --include="*.js" 2>/dev/null
```

**Bandit (Python)**
```bash
# Scan for hardcoded passwords
bandit -r . -t B105,B106,B107,B108

# Scan for weak crypto
bandit -r . -t B301,B302,B303,B304,B305

# Full scan with confidence/severity filtering
bandit -r . -i -ii --severity-level medium
```

### Insecure Random Number Generation

```bash
# Python - VULNERABLE
# random module is not cryptographically secure
import random
token = ''.join(random.choices(string.ascii_letters, k=32))

# JavaScript - VULNERABLE
# Math.random() is not cryptographically secure
token = Math.random().toString(36).substring(2);

# Java - VULNERABLE
# java.util.Random is not cryptographically secure
Random rand = new Random();

# Look for insecure RNG usage
grep -rn "Math.random\|random\.random\|random\.randint\|new Random()" \
  --include="*.py" --include="*.js" --include="*.java" .

# Python - SECURE
import secrets
token = secrets.token_urlsafe(32)

# JavaScript - SECURE
crypto.getRandomValues(new Uint8Array(32));
crypto.randomUUID();

# Java - SECURE
SecureRandom secureRandom = new SecureRandom();
```

### Missing Encryption at Rest

```bash
# Check database encryption
# PostgreSQL
psql -c "SHOW ssl;" # Transport encryption
# Check if TDE is enabled (enterprise feature)

# MySQL
mysql -e "SHOW VARIABLES LIKE '%ssl%';"
mysql -e "SHOW VARIABLES LIKE '%encrypt%';"

# MongoDB
mongosh --eval "db.adminCommand({getParameter: 1, encryptionAtRest: 1})"

# Check for unencrypted sensitive fields
# PII, payment data, health records should be encrypted at field level
# Search for plaintext storage of sensitive data
grep -rn "credit_card\|ssn\|social_security\|passport" \
  --include="*.py" --include="*.js" --include="*.java" .
```

## Algorithm Downgrade Attacks

**SSL/TLS Downgrade**
```bash
# Test if server allows protocol downgrade
openssl s_client -connect target.com:443 -tls1
openssl s_client -connect target.com:443 -tls1_1

# Check for downgrade protection (SCSV)
nmap --script ssl-enum-ciphers -p 443 target.com | grep "TLS_FALLBACK_SCSV"
```

**SSH Downgrade**
```bash
# Check SSH configuration
ssh -vv target.com 2>&1 | grep "kex:\|cipher:\|mac:"

# Weak algorithms to flag
# Ciphers: arcfour, blowfish-cbc, 3des-cbc, cast128-cbc
# MACs: hmac-md5, hmac-sha1-96, hmac-md5-96
# KEX: diffie-hellman-group1-sha1, diffie-hellman-group14-sha1
```

## Testing Methodology

1. **Transport security** — TLS version, cipher suites, certificate validity, HSTS, certificate pinning
2. **Secret scanning** — Repository history, config files, environment variables, client-side bundles
3. **Password storage** — Hashing algorithm, salt configuration, iteration count
4. **Encryption at rest** — Database, file system, backup, field-level encryption
5. **Key management** — Key storage location, rotation policy, access controls
6. **RNG quality** — Identify cryptographically insecure random sources
7. **Algorithm analysis** — Check for deprecated/weak algorithms in use
8. **Configuration review** — TLS configs, SSH configs, application crypto settings

## Validation

1. Demonstrate TLS downgrade or weak cipher suite acceptance
2. Extract hardcoded secrets from repository or configuration
3. Show weak password hashing algorithm in use with example hash format
4. Prove insecure RNG produces predictable output
5. Identify missing encryption for sensitive data at rest or in transit

## Remediation

- Enforce TLSv1.2+ with AEAD cipher suites and forward secrecy
- Implement HSTS with long max-age, includeSubDomains, and preload
- Use bcrypt, scrypt, or Argon2 for password hashing with appropriate work factors
- Store secrets in dedicated secret management (HashiCorp Vault, AWS Secrets Manager, K8s secrets)
- Use `secrets` module (Python), `crypto` module (Node.js), `SecureRandom` (Java) for all security-sensitive randomness
- Enable encryption at rest for databases and file storage
- Implement automated secret scanning in CI/CD pipeline
- Regular certificate rotation and monitoring for expiration

## Pro Tips

1. Certificate transparency logs reveal subdomains: `crt.sh/?q=%.target.com`
2. Test both IPv4 and IPv6 endpoints — TLS configs often differ
3. Check mail servers (SMTPS/IMAPS) for weak TLS — often overlooked
4. Scan git history for secrets, not just current files
5. Many APIs accept HTTP despite HTTPS being available — test both
6. Check if the application falls back to HTTP when HTTPS fails
7. Look for encryption in transit between internal services, not just external

## Summary

Cryptographic failures are pervasive — from expired certificates and weak cipher suites to hardcoded secrets and insecure password storage. Every layer of the stack needs cryptographic review: transport, storage, authentication, and random number generation. The absence of encryption is as dangerous as the presence of weak encryption.
