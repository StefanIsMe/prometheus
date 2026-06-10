---
name: browser_harness
description: browser-harness for CDP browser control via Python. Connects to in-container Chromium for JavaScript-heavy target analysis, SPA interaction, and browser-based vulnerability testing. Pre-mounted at /opt/browser-harness; invoke via exec_command with Python scripts.
---

# browser-harness — CDP browser control for scanning

browser-harness is a thin CDP bridge that connects to Chromium via a single
WebSocket. The sandbox has Chromium running with CDP on port 9222 and
browser-harness mounted at `/opt/browser-harness`.

## Setup (automatic)

The sandbox auto-starts Chromium with `--remote-debugging-port=9222` and
installs browser-harness deps. The env var `BU_CDP_URL=http://127.0.0.1:9222`
is pre-set. PYTHONPATH includes `/opt/browser-harness/src`.

**Verify CDP is up:**
```bash
curl -s http://127.0.0.1:9222/json/version
```

## Quick start — Python scripts via exec_command

Write a Python script, then run it via `exec_command`:

```python
import sys
sys.path.insert(0, "/opt/browser-harness/src")
import browser_harness.helpers as h

h.goto_url("https://target.com")
h.wait_for_load(timeout=15)
info = h.page_info()
print(f"Page: {info['url']} — {info['title']}")

# Extract content
content = h.js("document.querySelector('body').innerText[:5000]")
print(content)

# Find API endpoints in page source
apis = h.js(r"""
(function(){
    var links = Array.from(document.querySelectorAll('a[href], script[src]'));
    return links.map(l => l.href || l.src).filter(u => u.includes('/api/')).join('\n');
})()
""")
print("API endpoints found:", apis)
```

Save to `/tmp/scan_browser.py` and run:
```bash
python3 /tmp/scan_browser.py
```

## Core helpers

### Navigation
- `goto_url(url)` — navigate current tab
- `new_tab(url)` — create and navigate new tab
- `wait_for_load(timeout=15)` — wait for page load
- `wait_for_element(selector, timeout=10)` — wait for DOM element
- `page_info()` — `{url, title, w, h}`

### Content extraction
- `js(expression)` — run JavaScript, return result
- `cdp(method, **params)` — raw CDP call

### Interaction
- `click(x, y)` — coordinate click via CDP Input.dispatchMouseEvent
- `type_text(text)` — type via Input.insertText
- `fill_input(selector, text)` — fill form input
- `press_key(key)` — press Enter, Tab, etc.
- `scroll(x, y, dy=-300)` — scroll page

### Tabs
- `list_tabs()` — list all tabs
- `current_tab()` — get active tab
- `switch_tab(target)` — switch to tab
- `close_tab(target)` — close tab

## Security scanning patterns

### Discover hidden API endpoints
```python
apis = h.js("""
(function(){
    var results = new Set();
    // Check performance entries (XHR/fetch calls)
    performance.getEntriesByType('resource').forEach(r => {
        if (r.initiatorType === 'xmlhttprequest' || r.initiatorType === 'fetch')
            results.add(r.name);
    });
    // Check inline scripts for API URLs
    document.querySelectorAll('script').forEach(s => {
        var matches = s.textContent.match(/https?:\\/\\/[^'"\\s]+\\/api\\/[^'"\\s]+/g);
        if (matches) matches.forEach(m => results.add(m));
    });
    return Array.from(results).join('\\n');
})()
""")
```

### Intercept network requests (CDP Network domain)
```python
# Enable network capture
h.cdp("Network.enable")
# Navigate to trigger requests
h.goto_url("https://target.com/api/endpoint")
# Read captured requests from CDP events
```

### Test for XSS reflection
```python
import random
payload = f"test{random.randint(1000,9999)}"
h.goto_url(f"https://target.com/search?q={payload}")
h.wait_for_load()
reflected = h.js(f"document.body.innerText.includes('{payload}')")
if reflected:
    print(f"XSS REFLECTION DETECTED: {payload}")
```

### Extract auth tokens and cookies
```python
cookies = h.js("document.cookie")
print("Cookies:", cookies)

# Check localStorage
storage = h.js("""
(function(){
    var items = {};
    for(var i = 0; i < localStorage.length; i++){
        var key = localStorage.key(i);
        items[key] = localStorage.getItem(key);
    }
    return JSON.stringify(items);
})()
""")
```

### SPA route discovery
```python
# Discover client-side routes from JS bundles
routes = h.js("""
(function(){
    var scripts = Array.from(document.querySelectorAll('script[src]'));
    var urls = scripts.map(s => s.src);
    // Also check for route definitions in inline scripts
    var inlineRoutes = [];
    document.querySelectorAll('script:not([src])').forEach(s => {
        var matches = s.textContent.match(/['"]\\/([a-z][a-z0-9_\\/-]*)['"]/g);
        if (matches) matches.forEach(m => inlineRoutes.push(m.replace(/['"]/g,'')));
    });
    return JSON.stringify({external: urls, routes: inlineRoutes});
})()
""")
```

## browser-harness CLI mode (one-liners)

For quick reconnaissance, use `browser-harness -c`:
```bash
cd /opt/browser-harness && BU_CDP_URL=http://127.0.0.1:9222 \
  /app/.venv/bin/python3 -m browser_harness.run -c "
goto_url('https://target.com')
wait_for_load()
print(page_info())
print(js('document.title'))
"
```

## Pitfalls

- **Always use `/app/.venv/bin/python3`** — the sandbox venv has the deps
- **PYTHONPATH is pre-set** — `import browser_harness.helpers` works from any script
- **BU_CDP_URL is pre-set** — no need to configure CDP connection
- **Chromium runs headless** — no visible window, CDP only
- **Port 9222 is localhost only** — not exposed outside the container
- **`nohup` won't work** — use `background=true` if you need long-running browser processes
- **JS string escaping** — write complex JS to `.py` files, not inline strings
- **`js()` does NOT accept `timeout=` kwarg** — use `wait(N)` after for async operations
- **For async JS returning values** — use `cdp('Runtime.evaluate', expression=..., awaitPromise=True, returnByValue=True)`
