---
name: dirsearch
description: Directory and file brute-forcing tool for web content discovery with recursive scanning and status code filtering.
---

# dirsearch CLI Playbook

Official docs:
- https://github.com/maurosoria/dirsearch
- https://dirsearch.readthedocs.io

Canonical syntax:
`dirsearch -u <url> [options]`

High-signal flags:
- `-u, --url <url>` target URL
- `-l, --url-list <file>` list of target URLs
- `-w, --wordlist <path>` custom wordlist path
- `-e, --extensions <exts>` file extensions to try (comma-separated: php,html,js,json)
- `-t, --threads <n>` number of threads (default 30)
- `-r, --recursive` enable recursive brute-forcing
- `-R, --recursion-depth <n>` max recursion depth
- `--subdirs` brute-force subdirectories found
- `--exclude-subdirs <dirs>` exclude subdirectories from recursion
- `-x, --exclude-status <codes>` exclude status codes (e.g., 404,500)
- `--include-status <codes>` include only these status codes
- `-s, --follow-redirects` follow redirects
- `--no-follow-redirects` disable redirect following
- `-b, --request-by-hostname` use hostname in request header
- `--user-agent <ua>` custom user agent
- `--header <header>` custom header (repeatable)
- `--cookie <cookie>` custom cookie
- `--timeout <seconds>` request timeout (default 10)
- `--delay <seconds>` delay between requests
- `--proxy <proxy>` proxy URL (http/https/socks)
- `--auth <user:pass>` basic authentication
- `--full-url` print full URL in output
- `--suppress-empty` suppress empty responses
- `-o, --output <file>` output file
- `--format <fmt>` output format: plain, json, csv, xml, md, html (default plain)
- `--force-extensions` force extensions for every wordlist entry
- `--no-extensions` don't append extensions
- `--crawl` crawl for URLs before brute-forcing
- `-q, --quiet-mode` quiet mode (minimal output)

Default wordlist locations:
- `/usr/share/wordlists/dirb/common.txt`
- `/usr/share/dirsearch/wordlists/common.txt`
- `/usr/share/seclists/Discovery/Web-Content/common.txt`
- `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt`

Agent-safe baseline for automation:
`dirsearch -u https://target.tld -e php,html,js,json -t 30 --timeout 10 -x 404,500 --format json -o dirsearch.json -q`

Common patterns:
- Basic directory scan:
  `dirsearch -u https://target.tld -e php,html,js -t 30 -x 404`
- Recursive scan with medium wordlist:
  `dirsearch -u https://target.tld -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -e php,html,js,txt,bak -r -R 2 -x 404,403 --format json -o dirsearch_recursive.json`
- API endpoint discovery:
  `dirsearch -u https://api.target.tld -e json,yaml,xml,txt -t 20 --format json -o api_endpoints.json -q`
- Extension-focused backup file scan:
  `dirsearch -u https://target.tld -e bak,old,orig,swp,zip,tar.gz,sql -t 20 -x 404 --suppress-empty --format json -o backups.json`
- Multi-target scan:
  `dirsearch -l targets.txt -e php,html,js,json -t 20 -x 404 --format json -o dirsearch_multi.json`
- With custom headers and auth:
  `dirsearch -u https://target.tld -e php,html --header 'Authorization: Bearer TOKEN' -x 404 --format json -o dirsearch_auth.json`
- Crawl then brute-force:
  `dirsearch -u https://target.tld -e php,html,js --crawl -r -R 2 -x 404 --format json -o dirsearch_crawl.json`

Critical correctness rules:
- Always use `-x 404` (or broader filter) to suppress noise.
- Use `-q` for automation to reduce console output overhead.
- Use `--format json` for structured output parsing.
- Use `-t` conservatively; 20-30 is usually safe, 50+ may trigger WAF.
- Provide `-e` with relevant extensions; don't rely on extensionless wordlist alone.

Usage rules:
- Run wafw00f first; if WAF detected, lower `-t` and add `--delay`.
- Start with `common.txt` for fast results; escalate to `directory-list-2.3-medium.txt`.
- Use `--recursive` with `-R 2` depth limit to prevent explosion.
- Combine with ffuf for surgical fuzzing of discovered endpoints.

Integration with other tools:
- Feed discovered paths to nuclei: extract URLs from JSON, pass to `nuclei -l`
- Feed to httpx for alive-checking: pipe to `httpx -l`
- Feed discovered endpoints to sqlmap for injection testing
- Feed to katana for deeper crawling: use discovered dirs as seeds

Output parsing (JSON):
- Each result has: `url`, `status`, `content-length`, `content-type`, `redirect`
- Filter high-value: status 200, 301, 302, 401, 403 with non-zero content-length
- Status 401/403 = interesting authenticated resources
- Status 301/302 = redirects, check Location header

Failure recovery:
- If too many false positives, add more status codes to `-x` (e.g., 404,500,502).
- If WAF blocking, reduce `-t` and add `--delay 1`.
- If memory issues, disable `--recursive` or reduce `-R`.
- If no results, try different wordlists or add more extensions.

If uncertain, query web_search with:
`site:github.com/maurosoria/dirsearch dirsearch flags usage`
