# ProxyChecker

A simple, fast proxy testing utility that performs a two-stage scan:

1. Fast TCP + CONNECT probe to quickly filter reachable proxies.
2. Optional full HTTP probe (custom URL, headers, method, and flexible content checks).

The script supports HTTP and SOCKS proxies (provide scheme for SOCKS: `socks5://...`).

## Features

- Fast TCP and optional CONNECT probe for quick filtering.
- Full HTTP tests with customizable method, headers, body, redirects and retries.
- Flexible content checks: substring (`--expect-text`) or regex (`--expect-regex`).
- Per-worker connection reuse via requests.Session.
- Graceful Ctrl+C handling and progress output.

## Install

1. Clone the repository:

```bash
git clone https://github.com/deanddj/ProxyChecker.git
cd ProxyChecker
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

(Requires Python 3.8+)

## Usage

Basic usage with the default `proxies.txt` file:

```powershell
python .\\proxy.py --url "https://example.com/" --expect-text "Welcome" --timeout 10
```

Common flags

- `-p, --proxies <path>` — path to your proxies file (default: `./proxies.txt`).
- `--timeout <n>` — global timeout in seconds (used for both fast and full scans).
- `--workers <n>` — number of worker threads (default: recommended based on proxy count).
- `--no-save` — do not write output files.

Full-scan options

- `--url` — target URL for the full HTTP scan.
- `--ua` / `--no-ua` — provide or disable User-Agent header.
- `--method` — HTTP method (GET/POST/...)
- `--header` — repeatable header `--header "Key: Value"`.
- `--data` — request body for POST/PUT.
- `--accept-statuses` — comma-separated acceptable status codes (default 200).
- `--expect-text` — case-insensitive substring match after normalization.
- `--expect-regex` — case-insensitive regex match (recommended for class tokens or tag-split text).
- `--no-redirects` — do not follow redirects.
- `--retries` — retry count for full HTTP requests.

### Proxy file formats

One proxy per line. Supported forms:

- Scheme-prefixed (recommended for SOCKS):
  - `socks5://user:pass@1.2.3.4:1080`
  - `socks4://1.2.3.4:1080`
  - `http://1.2.3.4:8080`

- Legacy shorthand (normalized by script):
  - `username:password@ip:port`
  - `username:password:ip:port`
  - `ip:port:username:password`
  - `ip:port@username:password`
  - `ip:port`

## Regex tips (PowerShell)

- Use single quotes in PowerShell to avoid variable expansion: `'\\bx1ga7v0g\\b'`.
- Examples:
  - Match a class token anywhere: `--expect-regex '\\bxexx8yu\\b'`
  - Match 'Log in' even if split by tags: `--expect-regex 'log(?:\\s|<[^>]*>)*in'`
  - Combine class + inner text: `--expect-regex '(?s)<div[^>]*class="[^"]*\\bxexx8yu\\b[^"]*"[^>]*>.*?log(?:\\s|<[^>]*>)*in.*?</div>'`

## Safety and tuning

- The default worker recommendation is conservative but depends on your machine. Monitor CPU, memory, open files (ulimit -n on Linux), and TIME_WAIT sockets when running large scans.
- For SOCKS support install `pysocks` (in `requirements.txt`).

## Examples

- Fast-only (no URL):
```powershell
python .\\proxy.py -p .\\proxies.txt --timeout 5 --no-save
```

- Full HTTP scan with regex matching:
```powershell
python .\\proxy.py -p .\\proxies.txt --url "https://www.example.com/" --expect-regex '\\blogin\\b' --timeout 8
```

## License

This project is provided under the GNU GPLv3 license (see LICENSE file).