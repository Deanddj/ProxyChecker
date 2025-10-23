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


def _write_results_file(results, out_path, out_fmt):
    """Write results to out_path using out_fmt in {'txt','json','csv'}.

    results may be a list of proxy strings or a list of dicts.
    For 'txt' we write one proxy per line (for dicts we write proxies where ok==True).
    For 'json' we write JSON Lines of the dicts. For 'csv' we write a CSV with all keys.
    """
    try:
        if out_fmt == 'json':
            # Write a single valid JSON array to make the file parseable by JSON parsers.
            import json
            out_list = []
            for r in results:
                if isinstance(r, str):
                    out_list.append({'proxy': r})
                else:
                    out_list.append(r)
            with open(out_path, 'w', encoding='utf-8') as jf:
                json.dump(out_list, jf, ensure_ascii=False, indent=2)
        elif out_fmt == 'csv':
            import csv
            # Collect keys from dict results
            keys = set()
            for r in results:
                if isinstance(r, dict):
                    keys.update(r.keys())
            keys = list(sorted(keys))
            with open(out_path, 'w', encoding='utf-8', newline='') as cf:
                writer = csv.DictWriter(cf, fieldnames=keys or ['proxy'])
                writer.writeheader()
                for r in results:
                    if isinstance(r, str):
                        writer.writerow({'proxy': r})
                    else:
                        writer.writerow({k: r.get(k, '') for k in keys})
        else:
            # plain text: write proxies one-per-line
            with open(out_path, 'w', encoding='utf-8') as tf:
                for r in results:
                    if isinstance(r, str):
                        tf.write(f"{r}\n")
                    else:
                        if r.get('ok'):
                            tf.write(f"{r.get('proxy')}\n")
        return True, None
    except Exception as e:
        return False, str(e)

def detect_proxy_format(proxy):
    """Detect common proxy string formats.

    Returns one of the format keys used elsewhere, or 'url_with_scheme' when the
    proxy contains an explicit scheme. Falls back to 'Unknown format'.
    """
    proxy = (proxy or '').strip()
    if not proxy:
        return 'Unknown format'

    # Scheme-prefixed proxies
    if '://' in proxy:
        return 'url_with_scheme'

    # username:password@host:port  or host:port@username:password
    if '@' in proxy:
        left, right = proxy.split('@', 1)
        if left.count(':') >= 1 and right.count(':') == 1:
            return 'username:password@ip:port'
        if left.count(':') == 1 and right.count(':') >= 1:
            return 'ip:port@username:password'

    # bracketed IPv6 with port
    if proxy.startswith('[') and ']:' in proxy:
        return 'ip:port'

    parts = proxy.split(':')
    # username:password:ip:port or ip:port:username:password
    if len(parts) == 4:
        if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', parts[0]):
            return 'ip:port:username:password'
        return 'username:password:ip:port'

    # simple ip:port
    if len(parts) == 2:
        return 'ip:port'

    return 'Unknown format'

# Function to format the proxy string for requests
def format_proxy(proxy, format_name):
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
    """Parse a connect target which may be 'host' or 'host:port'."""
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
    """Read until CRLF for the status line and parse HTTP status code."""
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
    save_snippet_size=0,
    strict_expect=False,
    retries=0,
):
    """Visit a webpage using the provided proxy.

    user_agent: None means do not send a User-Agent header.
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
            headers.update(extra_headers)
        except Exception:
            pass
    try:
        if initial_tcp_ok is not None:
            tcp_ok = bool(initial_tcp_ok)
        else:
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

        accepted = set(accept_statuses) if accept_statuses else {200}
        status_ok = response.status_code in accepted
        content_ok = True

        if expect_regex:
            try:
                if re.search(expect_regex, response.text or '', flags=re.IGNORECASE):
                    content_ok = True
                else:
                    normalized_resp = _normalize_for_match(response.text or '')
                    if re.search(expect_regex, normalized_resp, flags=re.IGNORECASE):
                        content_ok = True
                    else:
                        content_ok = False
            except re.error:
                content_ok = False
            except Exception:
                content_ok = False
        elif expect_text:
            try:
                def _normalize_for_match(s: str) -> str:
                    if s is None:
                        return ''
                    try:
                        ns = unicodedata.normalize('NFKC', s)
                    except Exception:
                        ns = s
                    ns = ns.replace('\u2019', "'").replace('\u2018', "'")
                    ns = ns.replace('\u201c', '"').replace('\u201d', '"')
                    ns = ns.replace('\ufffd', "'")
                    ns = re.sub(r'\s+', ' ', ns)
                    return ns.strip().lower()

                normalized_resp = _normalize_for_match(response.text or '')
                normalized_expect = _normalize_for_match(expect_text)

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

        out = {
            'status_code': response.status_code,
            'time_taken': time_taken,
            'proxy': proxy,
            'tcp_ok': tcp_ok,
            'ok': ok,
        }
        try:
            if save_snippet_size and isinstance(save_snippet_size, int) and save_snippet_size > 0:
                snippet = (response.text or '')[:int(save_snippet_size)]
                out['snippet'] = snippet
        except Exception:
            pass

        return out
    except requests.exceptions.RequestException as e:
        return {
            'error': str(e),
            'time_taken': float('inf'),
            'proxy': proxy,
            'tcp_ok': tcp_ok if 'tcp_ok' in locals() else False
        }


# Stop threads when the user requests cancellation
shutdown_event = threading.Event()

def print_progress(processed, total, bar_len=40):
    """Print a simple progress bar to the console."""
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
                    conn_timeout = min(fast_timeout, timeout)
                    s = socket.create_connection((host, port), timeout=conn_timeout)
                    s.settimeout(conn_timeout)
                    tcp_ok = True
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

                if progress is not None and lock is not None:
                    with lock:
                        progress['count'] += 1
                        print_progress(progress['count'], total)

                q.task_done()
        finally:
            pass

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

    try:
        q.join()
    except Exception:
        pass

    print()
    return results

# Worker function for threading
def worker(url, user_agent, timeout, results, queue, progress=None, lock=None, total_proxies=0, initial_tcp_map=None, fast_timeout=5.0,
           method='GET', extra_headers=None, data=None, allow_redirects=True, accept_statuses=None, expect_text=None, expect_regex=None, save_snippet_size=0, strict_expect=False, retries=0):
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
            initial_tcp_ok = None
            if initial_tcp_map is not None:
                initial_tcp_ok = initial_tcp_map.get(proxy)
            result = visit_webpage(
                url, proxy, format_name, user_agent, timeout,
                session=session, initial_tcp_ok=initial_tcp_ok, fast_timeout=fast_timeout,
                method=method, extra_headers=extra_headers, data=data, allow_redirects=allow_redirects,
                accept_statuses=accept_statuses, expect_text=expect_text, expect_regex=expect_regex, save_snippet_size=save_snippet_size, strict_expect=strict_expect, retries=retries
            )
            results.append(result)
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
                 method='GET', extra_headers=None, data=None, allow_redirects=True, accept_statuses=None, expect_text=None, expect_regex=None, save_snippet_size=0, strict_expect=False, require_connect=False, retries=0):
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

    progress = {'count': 0}
    lock = threading.Lock()

    print_progress(0, len(proxies_list))

    for _ in range(num_workers):
        thread = threading.Thread(
            target=worker,
            args=(url, user_agent, timeout, results, queue, progress, lock, len(proxies_list), initial_tcp_map, fast_timeout,
                  method, extra_headers, data, allow_redirects, accept_statuses, expect_text, expect_regex, save_snippet_size, strict_expect, retries)
        )
        thread.daemon = True
        threads.append(thread)
        thread.start()

    for _ in range(num_workers):
        queue.put(None)

    try:
        while any(t.is_alive() for t in threads):
            if shutdown_event.is_set():
                break
            time.sleep(0.1)
    except KeyboardInterrupt:
        shutdown_event.set()
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

    try:
        queue.join()
    except Exception:
        pass

    print()

    results.sort(key=lambda x: x.get('time_taken', float('inf')))

    print(f"\nUser Agent: {user_agent if user_agent else 'None'}")
    print(f"URL: {url}")

    # Optionally filter by connect capability
    if require_connect:
        pre_filter_len = len(results)
        results = [r for r in results if r.get('connect_ok')]
        print(f"\nFiltered by CONNECT capability: {len(results)}/{pre_filter_len} remain")

    total = len(results)
    # mark working by 'ok' only (this takes into account accept_statuses and expect_text/regex)
    working = sum(1 for r in results if r.get('ok', False))
    tcp_reachable = sum(1 for r in results if r.get('tcp_ok'))
    failed = total - working

    print(f"Summary: {working}/{total} proxies matching criteria, {failed} failed")
    print(f"TCP reachable (fast check): {tcp_reachable}/{total}")

    # Return results for further processing (e.g. JSON/CSV export)
    return results

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
    if getattr(args, 'no_ua', False):
        user_agent = None
    else:
        ua_arg = getattr(args, 'ua', None)
        if ua_arg is not None:
            user_agent = ua_arg
        else:
            # default UA for reliability
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
        # Save fast-only results: either TCP reachable or CONNECT-capable depending on --require-connect
        require_connect_flag = bool(getattr(args, 'require_connect', False))
        if require_connect_flag:
            passed = [r['proxy'] for r in fast_results if r.get('connect_ok')]
        else:
            passed = [r['proxy'] for r in fast_results if r.get('tcp_ok')]
        if save_file:
            chosen = getattr(args, 'output_file', 'plain') or 'plain'
            if chosen == 'json':
                out_path = os.path.join(current_dir, 'results.json')
                ok, err = _write_results_file(passed, out_path, 'json')
            elif chosen == 'csv':
                out_path = os.path.join(current_dir, 'results.csv')
                ok, err = _write_results_file(passed, out_path, 'csv')
            else:
                out_path = os.path.join(current_dir, 'results.txt')
                ok, err = _write_results_file(passed, out_path, 'txt')

            if ok:
                print(f"Saved {len(passed)} fast-probe proxies to: {out_path}")
            else:
                print(f"Failed to write fast probe results: {err}")
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
    save_snippet_size = int(getattr(args, 'save_snippet', 0) or 0)
    output_choice = getattr(args, 'output_file', 'plain') or 'plain'
    strict_expect = bool(getattr(args, 'strict_expect', False))
    require_connect = bool(getattr(args, 'require_connect', False))

    results = test_proxies(
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
        save_snippet_size=save_snippet_size,
        strict_expect=strict_expect,
        require_connect=require_connect,
        retries=retries,
    )

    if results is not None and save_file:
        try:
            if output_choice == 'json':
                out_path = os.path.join(current_dir, 'results.json')
                ok, err = _write_results_file(results, out_path, 'json')
            elif output_choice == 'csv':
                out_path = os.path.join(current_dir, 'results.csv')
                ok, err = _write_results_file(results, out_path, 'csv')
            else:
                out_path = os.path.join(current_dir, 'results.txt')
                ok, err = _write_results_file(results, out_path, 'txt')

            if ok:
                print(f"\nWrote {len(results)} results to: {out_path}")
            else:
                print(f"\nFailed to write output file: {err}")
        except OSError as e:
            print(f"\nFailed to write output file: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Fast proxy scanner with optional full HTTP checks and flexible output",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Group: fast probe & common options
    fast_group = parser.add_argument_group('Fast-probe / common options')
    fast_group.add_argument('-p', '--proxies', help='Path to proxies file. Lines starting with # are ignored. Supports scheme-prefixed (socks5://, http://) and shorthand formats.')
    fast_group.add_argument('-w', '--workers', type=int, help='Number of worker threads. If omitted, a safe recommendation is used (~2.5%% of proxy count, min 10, max 300).')
    fast_group.add_argument('-t', '--timeout', type=int, help='Overall timeout (seconds) used for both fast and full HTTP requests.')
    fast_group.add_argument('-c', '--connect-target', help='Host or host:port used by the fast probe when issuing HTTP CONNECT.')

    # Group: full-scan specific options
    full_group = parser.add_argument_group('Full-scan options')
    full_group.add_argument('-u', '--url', help='Target URL for the full HTTP scan. In PowerShell, quote URLs with &.')
    full_group.add_argument('-U', '--ua', help='Custom User-Agent for full-scan requests. Use --no-ua to omit the header entirely.')
    full_group.add_argument('--no-ua', action='store_true', help='Do not send a User-Agent header (overrides --ua).')
    full_group.add_argument('-m', '--method', help='HTTP method for full test (e.g., GET, POST, HEAD, PUT).')
    full_group.add_argument('-H', '--header', action='append', help="Additional HTTP header; can repeat. Example: --header 'Authorization: Bearer X'.")
    full_group.add_argument('-d', '--data', help='Raw request body for methods like POST/PUT. Set Content-Type via --header when needed.')
    full_group.add_argument('-A', '--accept-statuses', help='Comma-separated list of acceptable HTTP status codes (e.g., 200,204,302).')
    full_group.add_argument('-e', '--expect-text', help='Case-insensitive substring after normalization (smart quotes, whitespace). Use --strict-expect to disable loose fallback.')
    full_group.add_argument('-E', '--expect-regex', help='Case-insensitive regex tested first on raw body, then on normalized body. Example: "\\bx1ga7v0g\\b" or "log(?:\\s|<[^>]*>)*in"')
    full_group.add_argument('-R', '--no-redirects', action='store_true', help='Do not follow redirects during the full HTTP test.')
    full_group.add_argument('-r', '--retries', type=int, help='Retry attempts on request errors (total attempts = retries + 1).')

    parser.add_argument('-S', '--no-save', action='store_true', help='Do not write results.* files; show progress and summary only.')
    parser.add_argument('-s', '--save-snippet', type=int, help='Include a small response snippet (first N characters) in results (JSON/CSV).')
    parser.add_argument('-o', '--output-file', choices=['plain', 'json', 'csv'], default='plain',
                        help='Results output format: plain -> results.txt (working proxies one-per-line), json -> results.json (array), csv -> results.csv.')
    parser.add_argument('-x', '--strict-expect', action='store_true', help='Only use strict expect-text (disable loose punctuation-stripped fallback).')
    parser.add_argument('-k', '--require-connect', action='store_true', help='Keep only proxies that returned HTTP 200 to CONNECT in fast probe; fast-only saves only these.')
    args = parser.parse_args()

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
                parts = []
                for tok in argv[idx+1:]:
                    if tok.startswith('-'):
                        break
                    parts.append(tok)
                if len(parts) > 1:
                    reconstructed = parts[0] + ''.join(t if t.startswith('&') else ('&' + t) for t in parts[1:])
                    if reconstructed != args.url:
                        args.url = reconstructed
    except Exception:
        pass

    try:
        run_cli(args)
    except KeyboardInterrupt:
        shutdown_event.set()
        print("\nOperation cancelled by user. Exiting...")
        sys.exit(1)