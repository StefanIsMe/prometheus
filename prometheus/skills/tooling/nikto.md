---
name: nikto
description: Nikto web server scanner for vulnerability detection, misconfiguration checks, and outdated software identification.
---

# Nikto CLI Playbook

Official docs:
- https://cirt.net/Nikto2
- https://github.com/sullo/nikto

Canonical syntax:
`nikto -h <host> [options]`

High-signal flags:
- `-h <host>` target host (IP or hostname), required
- `-p <port>` target port(s), comma-separated or range (e.g., 80,443,8000-8100)
- `-ssl` force SSL/TLS mode
- `-nossl` disable SSL
- `-Tuning <types>` scan tuning for specific vulnerability categories
- `-output <file>` output file path
- `-Format <fmt>` output format: csv, htm, txt, xml, json, nbe, sql, xml (default txt)
- `-Display <opts>` control output verbosity (1=show redirects, 2=show cookies, 3=all)
- `-timeout <seconds>` timeout per request (default 10)
- `-Pause <seconds>` pause between tests
- `-maxtime <seconds>` total maximum scan time
- `-id <user:pass>` basic auth credentials
- `-useproxy <proxy>` use HTTP proxy
- `-vhost <hostname>` virtual host header
- `-root <path>` prepend root path to all requests
- `-mutate <opts>` mutation techniques (1=filenames, 2=dirs, 3=subdomains, 4=usernames, 5=outfile)
- `-evasion <opts>` IDS evasion techniques
- `-C all` check all CGI directories
- `-404code <code>` override 404 detection
- `-ask no` disable interactive prompts (automation)

Tuning options (-Tuning):
- `0` file upload
- `1` interesting file / seen in logs
- `2` misconfiguration / default file
- `3` information disclosure
- `4` injection (XSS/Script/HTML)
- `5` remote file retrieval (inside webroot)
- `6` denial of service
- `7` remote file retrieval (server-wide)
- `8` command execution / remote shell
- `9` SQL injection
- `a` authentication bypass
- `b` software identification
- `c` remote source inclusion
- `x` reverse tuning (exclude categories)

Agent-safe baseline for automation:
`nikto -h https://target.tld -ssl -Tuning xb -Format json -output nikto.json -timeout 10 -maxtime 600 -ask no`

Common patterns:
- Basic scan:
  `nikto -h target.tld -p 80,443 -ssl -output nikto.txt -Format txt -ask no`
- SSL-only scan:
  `nikto -h target.tld -ssl -p 443 -output nikto_ssl.json -Format json -ask no`
- Targeted vuln scan (SQLi + XSS):
  `nikto -h target.tld -ssl -Tuning 94 -ask no -output nikto_injection.json -Format json`
- Full scan with mutations:
  `nikto -h target.tld -ssl -Tuning x -mutate 123 -ask no -maxtime 1200 -output nikto_full.txt`
- Multi-port scan:
  `nikto -h target.tld -p 80,443,8080,8443 -ssl -ask no -output nikto_multi.xml -Format xml`
- Authenticated scan:
  `nikto -h target.tld -ssl -id admin:password -ask no -output nikto_auth.txt`
- Docker scan:
  `docker run --rm sullo/nikto -h https://target.tld -ssl -Format json -output /dev/stdout -ask no`

Critical correctness rules:
- Always include `-ask no` to avoid interactive prompts.
- Use `-ssl` when targeting HTTPS endpoints.
- Use `-maxtime` to bound scan duration and prevent runaway scans.
- Tune with `-Tuning` to reduce noise; `xb` excludes software ID and checks everything else.
- Use `-Format json` or `-Format xml` for structured parsing.

Usage rules:
- Run wafw00f first to identify WAF; adjust `-Pause` or IDS evasion if needed.
- Combine with nmap to identify open ports before scanning.
- Use `-Tuning` to focus on specific vuln types rather than scanning everything.
- Parse JSON output: each finding has `OSVDB` id, `method`, `url`, `msg` fields.

Failure recovery:
- If scan times out, increase `-maxtime` or reduce `-Tuning` scope.
- If 404 detection fails, use `-404code` to override false positive detection.
- If rate limited, add `-Pause 2` between requests.
- If target has redirects, use `-Display 1` to track them.

If uncertain, query web_search with:
`site:cirt.net nikto tuning options`
