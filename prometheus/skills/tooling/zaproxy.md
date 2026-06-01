---
name: zaproxy
description: OWASP ZAP automation via zap-cli and Docker for active/passive scanning, spidering, and fuzzing.
---

# OWASP ZAP CLI Playbook

Official docs:
- https://www.zaproxy.org/docs/docker/
- https://github.com/zaproxy/zaproxy
- https://github.com/Grunny/zap-cli

Canonical syntax:
`zap-cli [command] [options]`

High-signal flags (zap-cli):
- `--zap-url <url>` ZAP instance URL (default http://127.0.0.1:8080)
- `--api-key <key>` ZAP API key
- `quick-scan -s <target>` quick active scan
- `quick-scan -s -r <target>` quick scan with report output
- `active-scan -r <target>` full active scan
- `spider -r <target>` spider a target
- `passive-scan -r` run passive scan on current session
- `open-url <url>` open URL in ZAP session
- `alert -l <level>` list alerts at severity level (Low, Medium, High, Informational)
- `report -o <file> -f <html|xml|json|md>` generate report
- `session -n -s <name>` start new named session
- `shutdown` stop ZAP daemon

Docker mode (recommended):
`docker run -u zap -p 8080:8080 -i ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true`

Docker one-shot scan:
`docker run -u zap -i ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py -t https://target.tld -r report.html`

Agent-safe baseline for automation:
```
# Start ZAP daemon
docker run -d --name zap -u zap -p 8080:8080 ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true
# Wait for startup
sleep 10
# Quick scan
zap-cli --zap-url http://127.0.0.1:8080 quick-scan -s -r https://target.tld
# Generate report
zap-cli --zap-url http://127.0.0.1:8080 report -o zap_report.html -f html
```

Common patterns:
- Quick active scan with openapi spec:
  `zap-cli quick-scan -s -t openapi https://target.tld/openapi.json`
- Spider then active scan:
  `zap-cli spider https://target.tld && zap-cli active-scan -r https://target.tld && zap-cli report -o zap.json -f json`
- Passive scan only (no active attacks):
  `zap-cli open-url https://target.tld && zap-cli passive-scan && zap-cli alert -l Medium`
- API security scan with context:
  `zap-cli context new "api" && zap-cli context include "api" "https://api.target.tld/.*" && zap-cli active-scan -r -c "api" https://api.target.tld/v1/users`
- Docker automated full scan:
  `docker run -u zap -v $(pwd):/zap/wrk/:rw -i ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py -t https://target.tld -r report.html -J report.json`

Python API (zaproxy library):
```python
from zapv2 import ZAPv2
zap = ZAPv2(apikey='your-key', proxies={'http': 'http://127.0.0.1:8080'})
zap.urlopen('https://target.tld')
scan_id = zap.ascan.scan('https://target.tld')
while int(zap.ascan.status(scan_id)) < 100:
    time.sleep(5)
print(zap.core.alerts(baseurl='https://target.tld'))
```

Critical correctness rules:
- Always start ZAP daemon and wait for readiness before sending commands.
- Use `-config api.disablekey=true` in Docker for local automation or pass `--api-key`.
- Use `quick-scan` for fast one-off checks; `active-scan` for thorough testing.
- Save structured output (`-f json` or `-f html`) for parsing.

Usage rules:
- Check WAF with wafw00f before active scanning to inform rate limiting.
- Spider before active scanning to build URL tree.
- Use context/include patterns to scope scans and reduce noise.
- Stop ZAP daemon after use: `zap-cli shutdown` or `docker stop zap`.

Failure recovery:
- If ZAP fails to start, check port conflicts: `lsof -i :8080`.
- If scans timeout, increase `-m <minutes>` timeout or reduce scope.
- If blocked by WAF, reduce thread count via `-config scanner.threadPerHost=2`.

If uncertain, query web_search with:
`site:zaproxy.org/docs zap-cli automation`
