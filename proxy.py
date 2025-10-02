"""
ProxyChecker

Notes:
- SOCKS proxy support: provide proxies with a scheme, e.g. socks5://user:pass@1.2.3.4:1080 or socks4://1.2.3.4:1080
- This requires PySocks to be installed (the project requirements include PySocks). Requests will use it automatically when a socks:// URL is passed.
"""

import requests
import time
import socket
import os
import sys
import argparse
import threading
from queue import Queue, Empty
from urllib.parse import urlparse
import re
import unicodedata

def detect_proxy_format(proxy):
    """Detect common proxy string formats.

    Returns one of the format keys used elsewhere, or 'url_with_scheme' when the
    proxy contains an explicit scheme (http://, https://, socks5://, socks4://).
    Falls back to 'Unknown format' when it can't be parsed.
    """
    proxy = (proxy or '').strip()
    if not proxy:
        return 'Unknown format'

    # Scheme-prefixed proxies (e.g. socks5://..., http://...)
    if '://' in proxy:
        return 'url_with_scheme'

    # username:password@host:port  or host:port@username:password
    if '@' in proxy:
        left, right = proxy.split('@', 1)
        # left looks like user:pass and right like ip:port
        if left.count(':') >= 1 and right.count(':') == 1:
            return 'username:password@ip:port'
        # left looks like ip:port and right like user:pass
        if left.count(':') == 1 and right.count(':') >= 1:
            return 'ip:port@username:password'

    # bracketed IPv6 with port e.g. [2001:db8::1]:8080
    if proxy.startswith('[') and ']:' in proxy:
        return 'ip:port'

    parts = proxy.split(':')
    # username:password:ip:port or ip:port:username:password
    if len(parts) == 4:
        # heuristic: if first part looks like an IP, assume ip:port:username:password
        if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', parts[0]):
            return 'ip:port:username:password'
        return 'username:password:ip:port'

    # simple ip:port
    if len(parts) == 2:
        return 'ip:port'

    return 'Unknown format'

# Function to format the proxy string for requests
def format_proxy(proxy, format_name):
    # If the proxy string already contains a scheme (e.g. socks5://, http://), return it as-is.
    # This enables SOCKS support when users provide proxies like: socks5://user:pass@ip:port
    if '://' in proxy:
        return proxy
    try:
        if format_name == 'username:password@ip:port':
            proxy_auth, proxy_ip_port = proxy.split('@')
        elif format_name == 'username:password:ip:port':
            parts = proxy.split(':')
            proxy_auth = f"{parts[0]}:{parts[1]}"
            proxy_ip_port = f"{parts[2]}:{parts[3]}"
        elif format_name == 'ip:port:username:password':
            parts = proxy.split(':')
            proxy_ip_port = f"{parts[0]}:{parts[1]}"
            proxy_auth = f"{parts[2]}:{parts[3]}"
        elif format_name == 'ip:port@username:password':
            proxy_ip_port, proxy_auth = proxy.split('@')
        elif format_name == 'ip:port':
            proxy_ip_port = proxy
            proxy_auth = ''
        else:
            raise ValueError("Invalid format name")

        return f'http://{proxy_auth}@{proxy_ip_port}' if proxy_auth else f'http://{proxy_ip_port}'
    except (ValueError, IndexError) as e:
        return {
            'error': str(e),
            'proxy': proxy
        }

def _parse_connect_target(target_str, default_port=443):
    """Parse a connect target which may be 'host' or 'host:port'.

    Returns (host, port_int). If port is missing or invalid, uses default_port.
    """
    try:
        if not target_str:
            return 'example.com', int(default_port)
        if ':' in target_str and not target_str.startswith('['):
            host, port_str = target_str.rsplit(':', 1)
            try:
                return host.strip(), int(port_str)
            except Exception:
                return host.strip(), int(default_port)
        # bracketed IPv6 with optional :port
        if target_str.startswith('['):
            if ']:' in target_str:
                host = target_str.split(']:', 1)[0] + ']'
                port_str = target_str.split(']:', 1)[1]
                try:
                    return host, int(port_str)
                except Exception:
                    return host, int(default_port)
            return target_str, int(default_port)
        return target_str.strip(), int(default_port)
    except Exception:
        return 'example.com', int(default_port)

def _read_http_status_line(sock, max_bytes=1024):
    """Read until CRLF for the status line and parse HTTP status code.

    Returns integer status code or None on failure.
    """
    try:
        buf = b''
        while b'\r\n' not in buf and len(buf) < max_bytes:
            chunk = sock.recv(64)
            if not chunk:
                break
            buf += chunk
        # split first line
        if b'\r\n' in buf:
            line = buf.split(b'\r\n', 1)[0]
        else:
            # fallback: take entire buffer as line
            line = buf
        try:
            line_str = line.decode('iso-8859-1', errors='replace')
        except Exception:
            return None
        parts = line_str.strip().split()
        if len(parts) >= 2 and parts[0].startswith('HTTP/'):
            try:
                return int(parts[1])
            except Exception:
                return None
        return None
    except Exception:
        return None

# Function to visit the webpage with a specified proxy
def visit_webpage(
    url,
    proxy,
    format_name,
    user_agent,
    timeout,
    session=None,
    initial_tcp_ok=None,
    fast_timeout=5.0,
    method='GET',
    extra_headers=None,
    data=None,
    allow_redirects=True,
    accept_statuses=None,
    expect_text=None,
    expect_regex=None,
    retries=0,
):
    """Visit a webpage using the provided proxy.

    user_agent: None -> no UA header, or string -> set as User-Agent header.
    """
    proxies = {
        'http': format_proxy(proxy, format_name),
        'https': format_proxy(proxy, format_name),
    }

    if isinstance(proxies['http'], dict):  # Check if proxy formatting failed
        return {
            'error': f"Proxy formatting error: {proxies['http']['error']} for proxy {proxies['http']['proxy']}",
            'time_taken': float('inf'),
            'proxy': proxy
        }

    headers = {'User-Agent': user_agent} if user_agent else {}
    if extra_headers:
        try:
            # merge/override
            headers.update(extra_headers)
        except Exception:
            pass

    try:
        # If an initial tcp check result from the fast pass is provided, use it
        # instead of performing another quick TCP connect here. This keeps the
        # final summary consistent with the fast pass filtering.
        if initial_tcp_ok is not None:
            tcp_ok = bool(initial_tcp_ok)
        else:
            # quick TCP-level reachability check (timeout controlled by fast_timeout)
            tcp_ok = False
            try:
                parsed = urlparse(proxies['http'])
                host = parsed.hostname
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                conn_timeout = min(fast_timeout if fast_timeout is not None else 5.0, timeout)
                socket.create_connection((host, port), timeout=conn_timeout)
                tcp_ok = True
            except Exception:
                tcp_ok = False

        # perform the HTTP request with optional retries
        attempts = int(retries) + 1
        last_exc = None
        response = None
        start_time = time.time()
        for _ in range(max(1, attempts)):
            try:
                if session is not None:
                    response = session.request(method.upper(), url, proxies=proxies, headers=headers, timeout=timeout, data=data, allow_redirects=allow_redirects)
                else:
                    response = requests.request(method.upper(), url, proxies=proxies, headers=headers, timeout=timeout, data=data, allow_redirects=allow_redirects)
                break
            except requests.exceptions.RequestException as e:
                last_exc = e
                response = None
                # if more attempts remain, continue; else fall through to error handling
                continue
        time_taken = time.time() - start_time

        if response is None:
            raise last_exc if last_exc else requests.exceptions.RequestException("Unknown request failure")

        if response.status_code == 407:
            return {
                'error': f"Proxy requires credentials to be used: {proxy}",
                'time_taken': time_taken,
                'proxy': proxy,
                'tcp_ok': tcp_ok
            }

        # success criteria
        accepted = set(accept_statuses) if accept_statuses else {200}
        status_ok = response.status_code in accepted
        content_ok = True
        # If an expect_regex is provided, try it first (case-insensitive).
        if expect_regex:
            try:
                # Try raw response first
                if re.search(expect_regex, response.text or '', flags=re.IGNORECASE):
                    content_ok = True
                else:
                    # fallback: try on normalized text as well
                    normalized_resp = _normalize_for_match(response.text or '')
                    if re.search(expect_regex, normalized_resp, flags=re.IGNORECASE):
                        content_ok = True
                    else:
                        content_ok = False
            except re.error:
                # Invalid regex -> treat as non-matching
                content_ok = False
            except Exception:
                content_ok = False
        elif expect_text:
            try:
                # Normalize both expected text and response body to improve matching.
                # This handles curly quotes, replacement characters, and odd Unicode
                # punctuation that may appear due to site encoding differences.
                def _normalize_for_match(s: str) -> str:
                    if s is None:
                        return ''
                    try:
                        ns = unicodedata.normalize('NFKC', s)
                    except Exception:
                        ns = s
                    # map common smart quotes to ASCII equivalents
                    ns = ns.replace('\u2019', "'").replace('\u2018', "'")
                    ns = ns.replace('\u201c', '"').replace('\u201d', '"')
                    # replace replacement char with apostrophe (common when encoding mismatches occur)
                    ns = ns.replace('\ufffd', "'")
                    # collapse whitespace
                    ns = re.sub(r'\s+', ' ', ns)
                    return ns.strip().lower()

                normalized_resp = _normalize_for_match(response.text or '')
                normalized_expect = _normalize_for_match(expect_text)
                # Also try a loose match that strips punctuation (but keeps hyphens)
                def _loose_strip(s: str) -> str:
                    return re.sub(r"[^\w\s-]", '', s)

                normalized_resp_loose = _loose_strip(normalized_resp)
                normalized_expect_loose = _loose_strip(normalized_expect)

                content_ok = (
                    (normalized_expect in normalized_resp) or
                    (normalized_expect_loose and normalized_expect_loose in normalized_resp_loose)
                )
            except Exception:
                content_ok = False
        ok = bool(status_ok and content_ok)

        return {
            'status_code': response.status_code,
            'time_taken': time_taken,
            'proxy': proxy,
            'tcp_ok': tcp_ok,
            'ok': ok
        }

    except requests.exceptions.RequestException as e:
        return {
            'error': str(e),
            'time_taken': float('inf'),
            'proxy': proxy,
            'tcp_ok': tcp_ok if 'tcp_ok' in locals() else False
        }


# Global event used to signal threads to stop when the user requests cancellation
shutdown_event = threading.Event()


def print_progress(processed, total, bar_len=40):
    """Print a simple progress bar to the console."""
    # don't print progress anymore once shutdown has been requested
    if shutdown_event.is_set():
        return
    if total <= 0:
        return
    percent = processed / total
    filled_len = int(round(bar_len * percent))
    bar = '=' * filled_len + '-' * (bar_len - filled_len)
    print(f"\rProgress: |{bar}| {processed}/{total} ({percent*100:.0f}%)", end='', flush=True)


def fast_pass(proxies_list, timeout, num_workers, connect_target='example.com', fast_timeout=5.0):
    """Fast probe: TCP connect + optional CONNECT probe to detect CONNECT-capable proxies.

    Returns list of dicts: {'proxy': proxy, 'tcp_ok': bool, 'connect_ok': bool}
    """
    results = []
    q = Queue()
    for p in proxies_list:
        q.put(p)

    def worker_fast(q, results, timeout, connect_target, progress, lock, total):
        try:
            while not shutdown_event.is_set():
                try:
                    proxy = q.get(timeout=0.5)
                except Empty:
                    continue
                if proxy is None:
                    q.task_done()
                    break
                formatted = format_proxy(proxy, detect_proxy_format(proxy))
                tcp_ok = False
                connect_ok = False
                try:
                    if isinstance(formatted, dict):
                        raise ValueError("Bad proxy format")
                    parsed = urlparse(formatted)
                    host = parsed.hostname
                    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                    # Single socket: establish once
                    # fast_timeout controls how long the fast probe waits (seconds)
                    conn_timeout = min(fast_timeout, timeout)
                    s = socket.create_connection((host, port), timeout=conn_timeout)
                    s.settimeout(conn_timeout)
                    tcp_ok = True
                    # Build CONNECT request using provided connect_target (may include :port)
                    tgt_host, tgt_port = _parse_connect_target(connect_target, default_port=443)
                    connect_req = f"CONNECT {tgt_host}:{tgt_port} HTTP/1.1\r\nHost: {tgt_host}:{tgt_port}\r\n\r\n"
                    s.sendall(connect_req.encode('utf-8'))
                    status = _read_http_status_line(s)
                    if status == 200:
                        connect_ok = True
                    try:
                        s.close()
                    except Exception:
                        pass
                except Exception:
                    tcp_ok = False

                results.append({'proxy': proxy, 'tcp_ok': tcp_ok, 'connect_ok': connect_ok})

                # progress update
                if progress is not None and lock is not None:
                    with lock:
                        progress['count'] += 1
                        print_progress(progress['count'], total)

                q.task_done()
        finally:
            pass

    # start threads
    progress = {'count': 0}
    lock = threading.Lock()
    threads = []
    worker_count = max(1, num_workers)
    for _ in range(worker_count):
        t = threading.Thread(target=worker_fast, args=(q, results, timeout, connect_target, progress, lock, len(proxies_list)))
        t.daemon = True
        threads.append(t)
        t.start()

    # Push sentinel None items so workers can exit cleanly after queue drains
    for _ in range(worker_count):
        q.put(None)

    try:
        while any(t.is_alive() for t in threads):
            # main loop will break when threads finish or shutdown requested
            if shutdown_event.is_set():
                break
            time.sleep(0.1)
    except KeyboardInterrupt:
        shutdown_event.set()
        # re-raise so the top-level handler can perform an immediate exit
        raise

    # If shutdown was requested, drain the queue so q.join won't block forever
    if shutdown_event.is_set():
        try:
            while True:
                item = q.get_nowait()
                try:
                    q.task_done()
                except Exception:
                    pass
        except Empty:
            pass

    # ensure queue is drained to let threads exit
    try:
        q.join()
    except Exception:
        pass

    print()
    return results

# Worker function for threading
def worker(url, user_agent, timeout, results, queue, progress=None, lock=None, total_proxies=0, initial_tcp_map=None, fast_timeout=5.0,
           method='GET', extra_headers=None, data=None, allow_redirects=True, accept_statuses=None, expect_text=None, expect_regex=None, retries=0):
    # create a Session per worker for connection reuse
    session = requests.Session()
    try:
        while not shutdown_event.is_set():
            try:
                proxy = queue.get(timeout=0.5)
            except Empty:
                continue
            if proxy is None:
                queue.task_done()
                break
            format_name = detect_proxy_format(proxy)
            # pass along any initial TCP check result from the fast pass to keep counts consistent
            initial_tcp_ok = None
            if initial_tcp_map is not None:
                initial_tcp_ok = initial_tcp_map.get(proxy)
            result = visit_webpage(
                url, proxy, format_name, user_agent, timeout,
                session=session, initial_tcp_ok=initial_tcp_ok, fast_timeout=fast_timeout,
                method=method, extra_headers=extra_headers, data=data, allow_redirects=allow_redirects,
                accept_statuses=accept_statuses, expect_text=expect_text, expect_regex=expect_regex, retries=retries
            )
            results.append(result)
            # update progress
            if progress is not None and lock is not None:
                with lock:
                    progress['count'] += 1
                    print_progress(progress['count'], total_proxies)
            queue.task_done()
    finally:
        try:
            session.close()
        except Exception:
            pass

# Main function to test all proxies and sort results
def test_proxies(url, user_agent, timeout, num_workers, save_file, proxies_list=None, initial_tcp_map=None, fast_timeout=5.0,
                 method='GET', extra_headers=None, data=None, allow_redirects=True, accept_statuses=None, expect_text=None, expect_regex=None, retries=0):
    results = []
    current_dir = os.path.dirname(os.path.abspath(__file__))
    proxies_file = os.path.join(current_dir, 'proxies.txt')

    if proxies_list is None:
        with open(proxies_file, 'r') as file:
            proxies_list = file.read().splitlines()
            proxies_list = [line.strip() for line in proxies_list if line.strip() and not line.startswith("#")]

        if not proxies_list:
             print("\nThe proxies.txt file doesn't contain any valid proxies. Please add proxies and try again.")
             return

    queue = Queue()
    for proxy in proxies_list:
        queue.put(proxy)

    threads = []

    # prepare progress tracking
    progress = {'count': 0}
    lock = threading.Lock()

    # show initial progress (0%) so user sees the progress bar immediately
    print_progress(0, len(proxies_list))

    for _ in range(num_workers):
        thread = threading.Thread(
            target=worker,
            args=(url, user_agent, timeout, results, queue, progress, lock, len(proxies_list), initial_tcp_map, fast_timeout,
                  method, extra_headers, data, allow_redirects, accept_statuses, expect_text, expect_regex, retries)
        )
        thread.daemon = True
        threads.append(thread)
        thread.start()

    # send sentinel values so workers exit after processing
    for _ in range(num_workers):
        queue.put(None)

    try:
        while any(t.is_alive() for t in threads):
            if shutdown_event.is_set():
                break
            time.sleep(0.1)
    except KeyboardInterrupt:
        shutdown_event.set()
        # re-raise to let top-level handler exit the process
        raise

    # If shutdown was requested, drain the queue so q.join won't block forever
    if shutdown_event.is_set():
        try:
            while True:
                item = queue.get_nowait()
                try:
                    queue.task_done()
                except Exception:
                    pass
        except Empty:
            pass

    # attempt graceful shutdown
    try:
        queue.join()
    except Exception:
        pass

    # finish progress line
    print()

    results.sort(key=lambda x: x.get('time_taken', float('inf')))

    print(f"\nUser Agent: {user_agent if user_agent else 'None'}")
    print(f"URL: {url}")

    total = len(results)
    # mark working by 'ok' only (this takes into account accept_statuses and expect_text)
    working = sum(1 for r in results if r.get('ok', False))
    tcp_reachable = sum(1 for r in results if r.get('tcp_ok'))
    failed = total - working

    print(f"Summary: {working}/{total} proxies matching criteria, {failed} failed")
    print(f"TCP reachable (fast check): {tcp_reachable}/{total}")

    # Anonymity features removed

    if save_file:
        # Export working proxies (based on status/criteria) to a separate file only
        working_file = os.path.join(current_dir, 'working_proxies.txt')
        # collect proxies that actually matched the acceptance criteria and sort fastest->slowest
        working = [r for r in results if r.get('ok', False)]
        # Anonymity-based filtering removed
        working_sorted = sorted(working, key=lambda x: x.get('time_taken', float('inf')))
        working_proxies = [r['proxy'] for r in working_sorted]

        try:
            # write plain proxies file
            with open(working_file, 'w', encoding='utf-8') as wf:
                for p in working_proxies:
                    wf.write(f"{p}\n")

            print(f"\nSaved {len(working_proxies)} working proxies to: {working_file}")
        except OSError as e:
            print(f"\nFailed to write working proxies file: {e}")

# Function to check if proxies.txt file exists, create if not
def check_and_create_proxies_file():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    proxies_file = os.path.join(current_dir, 'proxies.txt')

    if not os.path.exists(proxies_file):
        print("\nNo proxies file found. Creating a template 'proxies.txt' in this directory.")
        template = (
            "# Add one proxy per line. Lines starting with '#' are ignored.\n"
            "# Supported formats (examples):\n"
            "#  - Scheme-prefixed (recommended for SOCKS):\n"
            "#      socks5://user:pass@1.2.3.4:1080\n"
            "#      socks4://1.2.3.4:1080\n"
            "#      http://1.2.3.4:8080\n"
            "#  - Legacy/shorthand (the script normalizes these):\n"
            "#      username:password@ip:port\n"
            "#      username:password:ip:port\n"
            "#      ip:port:username:password\n"
            "#      ip:port@username:password\n"
            "#      ip:port\n"
            "# Examples (uncomment to use):\n"
            "# socks5://user:pass@185.221.160.134:1080\n"
            "# http://185.221.160.134:80\n"
            "# 185.221.160.134:8080\n"
            "# username:password@185.221.160.134:8080\n"
            "# IPv6 example (with port):\n"
            "# [2001:db8::1]:8080\n"
            "# After editing this file, re-run the script.\n"
        )
        with open(proxies_file, 'w', encoding='utf-8') as file:
            file.write(template)
        return False
    return True



def recommend_workers(total_proxies):
    """Recommend a worker count based on total proxies.

    Heuristic: recommend ~2.5% of total proxies, clamped between 10 and 300.
    This is a conservative default for typical desktops.
    """
    if total_proxies <= 0:
        return 10
    rec = max(10, int(total_proxies * 0.025))
    return min(rec, 300)


# Anonymity parsing removed


def load_proxies_from_file(path):
    """Load proxies from a file, ignoring blank lines and comments."""
    with open(path, 'r', encoding='utf-8') as f:
        return [l.strip() for l in f.read().splitlines() if l.strip() and not l.strip().startswith('#')]


def parse_header_items(header_items):
    """Parse repeated --header 'Key: Value' items into a dict. Ignores malformed items."""
    headers = {}
    if not header_items:
        return headers
    for item in header_items:
        if not item:
            continue
        # Split only on first ':' to allow values that contain ':'
        if ':' in item:
            key, value = item.split(':', 1)
            headers[key.strip()] = value.strip()
    return headers


def parse_accept_statuses(status_str):
    """Parse a comma-separated list of status codes into a set of ints."""
    if not status_str:
        return None
    parts = [p.strip() for p in status_str.split(',') if p.strip()]
    out = set()
    for p in parts:
        try:
            out.add(int(p))
        except ValueError:
            # ignore bad entries
            pass
    return out if out else None


def run_cli(args):
    """Run non-interactive CLI flow using defaults unless overridden by flags."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    default_proxies_path = os.path.join(current_dir, 'proxies.txt')
    proxies_path = args.proxies or default_proxies_path

    # Proxies file handling
    if not os.path.exists(proxies_path):
        if proxies_path == default_proxies_path:
            # Create a template and exit with message
            check_and_create_proxies_file()
            print("No proxies found. A template 'proxies.txt' was created. Please add proxies and rerun.")
            return
        else:
            print(f"Proxies file not found: {proxies_path}")
            return

    proxies_list = load_proxies_from_file(proxies_path)
    if not proxies_list:
        print("The proxies file doesn't contain any valid proxies.")
        return

    # Defaults
    timeout = args.timeout or 10
    # User-Agent behavior:
    # - If --no-ua is passed, don't send a User-Agent header.
    # - If --ua is passed, use that exact string.
    # - Otherwise use a sensible default UA string.
    if getattr(args, 'no_ua', False):
        user_agent = None
    else:
        ua_arg = getattr(args, 'ua', None)
        if ua_arg is not None:
            user_agent = ua_arg
        else:
            # sensible default UA for reliability
            user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36'
    save_file = not bool(args.no_save)
    # Determine whether to run the full scan. Previously this was an explicit --full flag.
    # Now we auto-enable full scan when any full-scan specific option is provided (url, ua, method, header, data, accept-statuses, expect-text, no-redirects, retries).
    full_scan_options = any(getattr(args, name, None) for name in ('url', 'ua', 'method', 'header', 'data', 'accept_statuses', 'expect_text', 'no_redirects', 'retries'))
    fast_only = not full_scan_options

    # Workers: use recommended unless explicitly provided
    workers = args.workers or recommend_workers(len(proxies_list))

    # Determine connect target (for CONNECT probe)
    if args.connect_target:
        connect_target = args.connect_target
    else:
        if fast_only:
            connect_target = 'example.com'
        else:
            url = args.url or 'https://google.com'
            try:
                parsed = urlparse(url)
                connect_target = parsed.hostname or 'example.com'
            except Exception:
                connect_target = 'example.com'

    print("\nRunning fast probe (TCP + CONNECT) on proxies...")
    _to = getattr(args, 'timeout', None)
    fast_timeout = float(_to) if _to is not None else 5.0
    fast_results = fast_pass(proxies_list, timeout, workers, connect_target=connect_target, fast_timeout=fast_timeout)
    total_fast = len(fast_results)
    tcp_ok_count = sum(1 for r in fast_results if r.get('tcp_ok'))
    connect_ok_count = sum(1 for r in fast_results if r.get('connect_ok'))
    print(f"\nFast probe summary: TCP reachable: {tcp_ok_count}/{total_fast}, CONNECT OK: {connect_ok_count}/{total_fast}")

    if fast_only:
        # Save fast-only results (TCP reachable)
        passed = [r['proxy'] for r in fast_results if r.get('tcp_ok')]
        if save_file:
            fast_file = os.path.join(current_dir, 'fast_probes.txt')
            try:
                with open(fast_file, 'w', encoding='utf-8') as cf:
                    for p in passed:
                        cf.write(f"{p}\n")
                print(f"Saved {len(passed)} fast-probe proxies to: {fast_file}")
            except OSError as e:
                print(f"Failed to write fast probe results: {e}")
        return

    # Full HTTP tests on candidates
    candidates = [r['proxy'] for r in fast_results if r.get('tcp_ok')]
    print(f"\n{len(candidates)} candidates remain after fast pass. Running full HTTP tests on candidates...")
    initial_tcp_map = {r['proxy']: r.get('tcp_ok', False) for r in fast_results}
    url = args.url or 'https://google.com'
    _to = getattr(args, 'timeout', None)
    call_fast_timeout = float(_to) if _to is not None else 5.0
    # Build precise HTTP options
    method = (args.method or 'GET').upper()
    extra_headers = parse_header_items(args.header) if getattr(args, 'header', None) else None
    data = args.data
    allow_redirects = not bool(args.no_redirects)
    accept_statuses = parse_accept_statuses(args.accept_statuses) if getattr(args, 'accept_statuses', None) else None
    expect_text = args.expect_text
    expect_regex = getattr(args, 'expect_regex', None)
    retries = int(args.retries or 0)
    test_proxies(
        url,
        user_agent,
        timeout,
        workers,
        save_file,
        proxies_list=candidates,
        initial_tcp_map=initial_tcp_map,
        fast_timeout=call_fast_timeout,
        method=method,
        extra_headers=extra_headers,
        data=data,
        allow_redirects=allow_redirects,
        accept_statuses=accept_statuses,
        expect_text=expect_text,
        expect_regex=expect_regex,
        retries=retries,
    )

if __name__ == "__main__":
    # CLI-first: parse arguments to decide interactive vs non-interactive
    parser = argparse.ArgumentParser(description="Proxy Checker")

    # Group: fast probe & common options
    fast_group = parser.add_argument_group('Fast-probe / common options')
    fast_group.add_argument('-p', '--proxies', help='Path to proxies file (default: ./proxies.txt)')
    fast_group.add_argument('--workers', type=int, help='Number of worker threads (default: recommend based on proxy count)')
    fast_group.add_argument('--timeout', type=int, help='Request timeout in seconds (default: 10)')
    fast_group.add_argument('--connect-target', help='Host or host:port to use for the HTTP CONNECT probe in fast mode (default: example.com:443)')

    # Group: full-scan specific options
    full_group = parser.add_argument_group('Full-scan options')
    full_group.add_argument('--url', help='Target URL for full HTTP GET scan (default: https://google.com). If using PowerShell and the URL contains & characters, wrap it in quotes.')
    # User can override the default User-Agent; use --no-ua to disable sending a UA header
    full_group.add_argument('--ua', help='Custom User-Agent string to use for full-scan requests (default: sensible browser UA)')
    full_group.add_argument('--no-ua', action='store_true', help='Do not send a User-Agent header (overrides --ua)')
    # Note: fast probe timeout is derived from --timeout (single timeout option)
    # Anonymity flag removed
    full_group.add_argument('--method', help='HTTP method for full test (default: GET)')
    full_group.add_argument('--header', action='append', help="Additional HTTP header, e.g. --header 'Authorization: Bearer X' (can repeat) (default: none)")
    full_group.add_argument('--data', help='Request body for methods like POST/PUT (sent as raw body) (default: none)')
    full_group.add_argument('--accept-statuses', help='Comma-separated list of acceptable HTTP status codes (default: 200)')
    full_group.add_argument('--expect-text', help='Substring that must appear in the response body to be considered working (default: none)')
    full_group.add_argument('--expect-regex', help='Regex that must match the response body to be considered working (case-insensitive). Example: "\\bx1ga7v0g\\b" or "log(?:\\s|<[^>]*>)*in"')
    full_group.add_argument('--no-redirects', action='store_true', help='Disable following redirects for full HTTP tests (default: follow redirects)')
    full_group.add_argument('--retries', type=int, help='Number of retry attempts for the full HTTP request on failure (default: 0)')

    # Non-interactive mode only: parse args and run
    parser.add_argument('--no-save', action='store_true', help='Do not save outputs to files (default: save)')
    args = parser.parse_args()

    # Help Windows PowerShell users: if they forgot to quote a URL with '&' in it,
    # PowerShell will split the URL into multiple argv tokens. Attempt to
    # reconstruct the URL from subsequent tokens until the next option (token
    # that starts with '-'). This makes the CLI more forgiving when users run
    # commands like:
    #   python .\proxy.py --url https://.../?a=1&b=2 --expect-text "..."
    # in PowerShell without quoting the URL.
    try:
        if args.url:
            import sys as _sys
            argv = _sys.argv
            # find the position of '--url' in the raw argv (if present)
            if '--url' in argv:
                idx = argv.index('--url')
            else:
                idx = None
            if idx is not None and idx + 1 < len(argv):
                # collect tokens after the --url argument until the next option
                parts = []
                for tok in argv[idx+1:]:
                    if tok.startswith('-'):
                        break
                    parts.append(tok)
                if len(parts) > 1:
                    # join: first part as-is, subsequent parts prefixed with '&'
                    reconstructed = parts[0] + ''.join(t if t.startswith('&') else ('&' + t) for t in parts[1:])
                    # only overwrite if the reconstructed differs meaningfully
                    if reconstructed != args.url:
                        args.url = reconstructed
    except Exception:
        # best-effort reconstruction; if anything goes wrong, continue normally
        pass

    try:
        run_cli(args)
    except KeyboardInterrupt:
        shutdown_event.set()
        print("\nOperation cancelled by user. Exiting...")
        sys.exit(1)