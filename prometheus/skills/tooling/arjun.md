---
name: arjun
description: Hidden HTTP parameter discovery tool for finding undocumented query, body, and header parameters.
---

# Arjun CLI Playbook

Official docs:
- https://github.com/s0md3v/Arjun
- https://github.com/s0md3v/Arjun/wiki

Canonical syntax:
`arjun -u <url> [options]`

High-signal flags:
- `-u, --url <url>` target URL
- `-o, --output <file>` output JSON file
- `-m, --method <method>` HTTP method: GET, POST, JSON, HEADER (default GET)
- `-d, --data <data>` POST data with placeholder for fuzzing
- `-w, --wordlist <path>` custom wordlist path
- `-t, --threads <n>` number of threads (default 2)
- `--timeout <seconds>` request timeout (default 15)
- `--headers` test hidden headers instead of query/body params
- `--include <status>` include specific status codes in detection
- `--stable` use stable mode (reduces false positives)
- `--disable-redirects` don't follow redirects
- `-c, --chunk <n>` chunk size for parameter testing batch
- `--passive <string>` extract parameters from passive sources (burp file, wayback)
- `--skip-heuristics` skip heuristic parameter detection
- `--no-redirects` disable following redirects

Default wordlist:
- Built-in: ships with a default parameter wordlist (~25k entries)
- Custom: `/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt`

Agent-safe baseline for automation:
`arjun -u https://target.tld -m GET -t 2 --timeout 15 -o arjun_params.json`

Common patterns:
- GET parameter discovery:
  `arjun -u https://target.tld -m GET -t 2 -o arjun_get.json`
- POST body parameter discovery:
  `arjun -u https://target.tld -m POST -t 2 -o arjun_post.json`
- JSON body parameter discovery:
  `arjun -u https://target.tld -m JSON -t 2 -o arjun_json.json`
- Hidden header discovery:
  `arjun -u https://target.tld --headers -t 2 -o arjun_headers.json`
- Custom wordlist:
  `arjun -u https://target.tld -m GET -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -o arjun_custom.json`
- Multiple methods in sequence:
  ```bash
  arjun -u https://target.tld -m GET -o arjun_get.json
  arjun -u https://target.tld -m POST -o arjun_post.json
  arjun -u https://target.tld -m JSON -o arjun_json.json
  arjun -u https://target.tld --headers -o arjun_hdr.json
  ```
- Stable mode for noisy targets:
  `arjun -u https://target.tld -m GET --stable -t 1 -o arjun_stable.json`
- With custom POST data template:
  `arjun -u https://target.tld -m POST -d 'user=admin&pass=test' -o arjun_postdata.json`

Output parsing (JSON):
- Output is a JSON object with discovered parameters
- Structure: `{"name": "param_name", "type": "GET|POST|JSON|HEADER"}`
- Each parameter includes: name, method, confidence level
- Parse and feed into subsequent fuzzing/scanning tools

Integration with other tools:
- Feed discovered parameters to ffuf for value fuzzing:
  `ffuf -w values.txt -u 'https://target.tld/page?FUZZ=value' -mc 200 -ac`
- Feed to sqlmap for injection testing:
  `sqlmap -u 'https://target.tld/page?param=1' -p param --batch`
- Feed to nuclei with parameter-specific templates:
  `nuclei -u 'https://target.tld/page?param=test' -t http/vulnerabilities/`
- Use with httpx to verify parameter behavior changes:
  ```bash
  httpx -u 'https://target.tld/page' -fc 200
  httpx -u 'https://target.tld/page?param=test' -mc 200
  ```

Critical correctness rules:
- Use `-m` to match the HTTP method; don't rely on defaults for POST/JSON endpoints.
- Keep `-t` low (2-5) to avoid rate limiting and false positives.
- Use `--stable` when results are noisy or inconsistent.
- Test all methods (GET, POST, JSON, HEADERS) for comprehensive coverage.

Usage rules:
- Run after initial recon (httpx, katana) to have confirmed-alive URLs.
- Run before sqlmap/nuclei to maximize parameter coverage.
- Use built-in wordlist first; switch to custom only if needed.
- Save output as JSON for pipeline integration.

Failure recovery:
- If too many false positives, use `--stable` and reduce `-t` to 1.
- If blocked, add `--timeout 30` and reduce threads.
- If missing expected params, try different methods (GET vs POST vs JSON).
- If heuristic detection fails, use `--skip-heuristics` and rely on wordlist.

If uncertain, query web_search with:
`site:github.com/s0md3v/Arjun arjun parameter discovery usage`
