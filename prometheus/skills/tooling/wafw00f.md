---
name: wafw00f
description: WAF detection and fingerprinting to identify Web Application Firewalls before running active scans.
---

# wafw00f CLI Playbook

Official docs:
- https://github.com/EnableSecurity/wafw00f
- https://wafw00f.readthedocs.io

Canonical syntax:
`wafw00f <url> [options]`

High-signal flags:
- `<url>` target URL (positional argument)
- `-a, --findall` find all matching WAFs (not just first match)
- `-r, --redirects` follow redirects
- `-t, --test <test>` test for specific WAF
- `-l, --list` list all WAFs that can be detected
- `-p, --proxy <url>` use proxy (http/https/socks)
- `-H, --header <header>` custom header (repeatable)
- `-o, --output <file>` output file
- `-f, --format <fmt>` output format: json, csv, text (default text)
- `-i, --input <file>` read targets from file (one per line)
- `-v, --verbose` verbose output
- `--no-color` disable colored output

Agent-safe baseline for automation:
`wafw00f https://target.tld -a -f json -o waf_results.json`

Common patterns:
- Basic WAF detection:
  `wafw00f https://target.tld`
- Find all possible WAF matches:
  `wafw00f https://target.tld -a -f json -o waf.json`
- Scan multiple targets:
  `wafw00f -i targets.txt -a -f json -o waf_multi.json`
- With custom headers (authenticated detection):
  `wafw00f https://target.tld -H 'Cookie: session=abc123' -a -f json`
- Through proxy:
  `wafw00f https://target.tld -p http://127.0.0.1:8080 -a`
- Test specific WAF:
  `wafw00f https://target.tld -t 'Cloudflare'`
- List all detectable WAFs:
  `wafw00f -l`

Output parsing:
- JSON output structure: array of objects with fields:
  - `url`: target URL
  `detected`: boolean
  - `firewall`: WAF name (e.g., "Cloudflare (Cloudflare Inc.)")
  - `manufacturer`: WAF vendor
- Text output format: "is behind [WAF Name] ([Vendor])" or "No WAF detected"
- Exit code 0 = WAF detected, non-zero = check errors

Integration with other tools:
- Always run wafw00f BEFORE active scans (nuclei, nikto, sqlmap, zaproxy)
- If WAF detected:
  - Use WAF bypass payloads in nuclei/sqlmap
  - Reduce scan rate (`-rl`, `-rate`, `-Pause`)
  - Consider IDS evasion flags in nikto (`-evasion`)
  - Use tamper scripts in sqlmap (`--tamper`)
  - Rotate User-Agents and add random delays
- Feed WAF name to nuclei: use WAF-specific templates (`-tags waf-bypass`)
- If no WAF: proceed with standard scan parameters

Critical correctness rules:
- Use `-a` (findall) to avoid missing multi-layered WAF setups.
- Always use `-f json` for structured output parsing.
- Follow redirects with `-r` if target uses 302-based WAF challenges.
- Provide authenticated context via `-H` if WAF is behind login.

Usage rules:
- Run this as the first step in any active scanning workflow.
- Log the WAF name for each target to inform scan strategy.
- Retest if scans later fail with 403/429 responses.

Failure recovery:
- If "No WAF detected" but getting blocked, try `-a` with `-r`.
- If detection fails, add valid cookies/headers via `-H`.
- If proxy needed, use `-p` to route through intercepting proxy.

If uncertain, query web_search with:
`site:github.com/EnableSecurity/wafw00f wafw00f usage`
