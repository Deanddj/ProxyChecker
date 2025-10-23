# ProxyChecker

Fast proxy scanner with a two-stage flow:

1) Fast probe: TCP connect + HTTP CONNECT check to quickly filter proxies.
2) Optional full HTTP scan with configurable URL, method, headers, body, matching, and retries.

Supports HTTP and SOCKS proxies (prefix SOCKS proxies with a scheme, e.g., `socks5://...`).

## Install

```powershell
pip install -r requirements.txt
```

Python 3.8+ recommended.

## Quick start

Put proxies in `proxies.txt` (one per line). Then:

```powershell
# Fast probe only (saves results.txt by default)
python .\proxy.py -p .\proxies.txt --timeout 8

# Full HTTP scan against a URL, save JSON
python .\proxy.py -p .\proxies.txt --url "https://example.com/" --expect-text "Welcome" --output-file json
```

Results are always written as one of: `results.txt`, `results.json`, or `results.csv` depending on `--output-file` (default: plain -> results.txt). Use `--no-save` to skip writing files.

## Options (summary)

- `-p, --proxies <path>`: Path to proxies file (lines starting with `#` are ignored). Supports scheme-prefixed (`socks5://`, `http://`) and shorthand formats.
- `-w, --workers <n>`: Worker threads. If omitted, a safe recommendation is used (~2.5% of proxies, min 10, max 300).
- `-t, --timeout <sec>`: Overall timeout used for both fast and full HTTP requests.
- `-c, --connect-target <host[:port]>`: Target used by the fast probe when issuing HTTP CONNECT.
- `-S, --no-save`: Do not write results files; only print progress and summary.
- `-o, --output-file {plain,json,csv}`: Choose results format: plain -> `results.txt` (working proxies one per line), json -> `results.json` (JSON array), csv -> `results.csv`.
- `-s, --save-snippet <N>`: Include first N characters of response in JSON/CSV outputs.
- `-k, --require-connect`: Keep only proxies that returned HTTP 200 to CONNECT in the fast probe (also affects fast-only save).

Full-scan (provide any of these to trigger a full HTTP scan in addition to the fast probe):

- `-u, --url <URL>`: Target URL for the full HTTP test. In PowerShell, quote URLs with `&`.
- `-U, --ua <string>` / `--no-ua`: Custom User-Agent string or omit the header entirely.
- `-m, --method <VERB>`: HTTP method (e.g., GET, POST, HEAD, PUT).
- `-H, --header 'Key: Value'` (repeatable): Add custom headers.
- `-d, --data <body>`: Raw request body (set Content-Type via `--header` as needed).
- `-A, --accept-statuses 200,204,302`: Comma-separated acceptable status codes (default is 200 if not provided).
- `-e, --expect-text <text>`: Case-insensitive substring after normalization (handles smart quotes/whitespace). Use `--strict-expect` to disable the loose fallback.
- `-E, --expect-regex <pattern>`: Case-insensitive regex (tested on raw body, then on normalized body). Good for matching tokens or text split by tags.
- `-R, --no-redirects`: Do not follow redirects in the full HTTP test.
- `-r, --retries <n>`: Retries on request errors (total attempts = `n` + 1).
- `-x, --strict-expect`: Only strict expect-text matching (no loose punctuation-stripped fallback).

## Proxy formats

Supported per-line formats:

- Scheme-prefixed (recommended for SOCKS):
  - `socks5://user:pass@1.2.3.4:1080`
  - `socks4://1.2.3.4:1080`
  - `http://1.2.3.4:8080`
- Shorthand (normalized automatically):
  - `username:password@ip:port`
  - `username:password:ip:port`
  - `ip:port:username:password`
  - `ip:port@username:password`
  - `ip:port`

## Regex tips (PowerShell)

- Prefer single quotes in PowerShell to avoid expansions: `'\bx1ga7v0g\b'`.
- Examples:
  - Match a class token anywhere: `--expect-regex '\\bxexx8yu\\b'`
  - Match "Log in" even through HTML tags: `--expect-regex 'log(?:\\s|<[^>]*>)*in'`

## Notes

- Ctrl+C gracefully cancels work and exits.
- For SOCKS support, `pysocks` is already listed in `requirements.txt`.

## License
This project is licensed under the [GNU GPLv3 License](LICENSE).