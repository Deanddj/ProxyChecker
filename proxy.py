import requests
import time
import os
import threading
from queue import Queue
from urllib.parse import urlparse

# Function to format the proxy string for requests
def format_proxy(proxy, format_type):
    try:
        if format_type == 1:
            proxy_auth, proxy_ip_port = proxy.split('@')
        elif format_type == 2:
            parts = proxy.split(':')
            proxy_auth = f"{parts[0]}:{parts[1]}"
            proxy_ip_port = f"{parts[2]}:{parts[3]}"
        elif format_type == 3:
            parts = proxy.split(':')
            if len(parts) != 4:
                raise ValueError("Invalid format for type 3: ip:port:username:password")
            proxy_ip_port = f"{parts[0]}:{parts[1]}"
            proxy_auth = f"{parts[2]}:{parts[3]}"
        elif format_type == 4:
            proxy_ip_port, proxy_auth = proxy.split('@')
        elif format_type == 5:
            proxy_ip_port = proxy
            proxy_auth = ''
        else:
            raise ValueError("Invalid format type")

        return f'http://{proxy_auth}@{proxy_ip_port}' if proxy_auth else f'http://{proxy_ip_port}'
    except (ValueError, IndexError) as e:
        return {
            'error': str(e),
            'proxy': proxy
        }

# Function to visit the webpage with a specified proxy
def visit_webpage(url, proxy, format_type, use_user_agent, timeout):
    proxies = {
        'http': format_proxy(proxy, format_type),
        'https': format_proxy(proxy, format_type),
    }

    if isinstance(proxies['http'], dict):  # Check if proxy formatting failed
        return {
            'error': f"Proxy formatting error: {proxies['http']['error']} for proxy {proxies['http']['proxy']}",
            'time_taken': float('inf'),
            'proxy': proxy
        }


    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'} if use_user_agent else {}

    try:
        start_time = time.time()
        response = requests.get(url, proxies=proxies, headers=headers, timeout=timeout)
        time_taken = time.time() - start_time

        if response.status_code == 407:
            return {
                'error': f"Proxy requires credentials to be used: {proxy}",
                'time_taken': time_taken,
                'proxy': proxy
            }

        return {
            'status_code': response.status_code,
            'time_taken': time_taken,
            'proxy': proxy
        }


    except requests.exceptions.RequestException as e:
        return {
            'error': str(e),
            'time_taken': float('inf'),
            'proxy': proxy
        }

# Worker function for threading
def worker(url, format_type, use_user_agent, timeout, results, queue):
    while True:
        proxy = queue.get()
        if proxy is None:
            break
        result = visit_webpage(url, proxy, format_type, use_user_agent, timeout)
        results.append(result)
        queue.task_done()

# Main function to test all proxies and sort results
def test_proxies(url, format_type, use_user_agent, timeout, num_workers, save_file):
    results = []
    current_dir = os.path.dirname(os.path.abspath(__file__))
    proxies_file = os.path.join(current_dir, 'proxies.txt')

    with open(proxies_file, 'r') as file:
        proxies_list = file.read().splitlines()
        proxies_list = [line.strip() for line in proxies_list if line.strip() and not line.startswith("#")]

        if not proxies_list:
             print("\nThe proxies.txt file doesn't contain any valid proxies. Please add proxies and try again.")
             return

    if format_type < 1 or format_type > 5:
        print("\nInvalid format type. Please enter a number between 1 and 5.")
        return

    queue = Queue()
    for proxy in proxies_list:
        queue.put(proxy)

    threads = []
    for _ in range(num_workers):
        thread = threading.Thread(target=worker, args=(url, format_type, use_user_agent, timeout, results, queue))
        thread.daemon = True
        threads.append(thread)
        thread.start()

    queue.join()

    results.sort(key=lambda x: x.get('time_taken', float('inf')))

    print(f"\nUser Agent: {'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36' if use_user_agent else 'None'}")
    print(f"URL: {url}")
    print("Results (fastest to slowest):")
    for result in results:
        if 'status_code' in result:
            print(f"Status Code: {result['status_code']}, Time Taken: {result['time_taken']:.2f} seconds, Proxy: {result['proxy']}")
        else:
            print(f"An error occurred with proxy {result['proxy']}: {result['error']}")

    if save_file:
        result_file = os.path.join(current_dir, 'result.txt')
        with open(result_file, "w") as file:
            file.write(f"Proxy timeout: {timeout}")
            file.write(f"\nURL: {url}")
            file.write(f"\nUser Agent: {'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36' if use_user_agent else 'None'}")
            file.write("\nResults (fastest to slowest):\n")
            for result in results:
                if 'status_code' in result:
                    file.write(f"\nStatus Code: {result['status_code']}, Time Taken: {result['time_taken']:.2f} seconds, Proxy: {result['proxy']}")
                else:
                    file.write(f"\nAn error occurred with proxy {result['proxy']}: {result['error']}")

# Function to check if proxies.txt file exists, create if not
def check_and_create_proxies_file():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    proxies_file = os.path.join(current_dir, 'proxies.txt')

    if not os.path.exists(proxies_file):
        print("\nThe proxies.txt file couldn't be found. A new proxies file has been created in this directory.\nPlease provide the proxies in the proxies.txt file and try again.")
        with open(proxies_file, 'w') as file:
            file.write(
    "# Please add your proxies in the following accepted formats without the comment symbol (#):\n"
    "# 1. username:password@ip:port\n"
    "# 2. username:password:ip:port\n"
    "# 3. ip:port:username:password\n"
    "# 4. ip:port@username:password\n"
    "# 5. ip:port\n"
    "# Example proxy:\n"
    "# nrmabx99:uixx9xdoszu9@99.999.99.999:9999\n"
            )
        return False
    return True

def is_valid_url(url):
    parsed_url = urlparse(url)
    return bool(parsed_url.scheme and parsed_url.netloc)

def prompt_for_url():
    while True:
        url = input("What URL do you want to test your proxies on? (default is http://example.com): ") or 'http://example.com'
        if is_valid_url(url):
            return url
        else:
            print("\nInvalid URL. Please enter a valid URL.")

def prompt_for_int(prompt, default):
    while True:
        try:
            value = input(prompt) or default
            value = int(value)
            if value > 0:
                return value
            else:
                print("\nInvalid input. Please enter an integer greater than 0.")
        except ValueError:
            print("\nInvalid input. Please enter a valid number.")

def prompt_for_yes_no(prompt):
    while True:
        response = input(prompt).strip().lower()
        if response in {'y', 'n', ''}:
            return response != 'n'
        else:
            print("\nInvalid input. Please enter 'Y' or 'N' (leave blank for default).")

if __name__ == "__main__":
    if not check_and_create_proxies_file():
        pass
    else:
        print("Select the format of the proxy list:")
        print("1. username:password@ip:port")
        print("2. username:password:ip:port")
        print("3. ip:port:username:password")
        print("4. ip:port@username:password")
        print("5. ip:port\n")

        while True:
            try:
                format_type = int(input("Enter the number corresponding to the proxy list format: "))
                if format_type < 1 or format_type > 5:
                    print("\nInvalid format type. Please enter a number between 1 and 5.")
                else:
                    break
            except ValueError:
                print("\nInvalid input. Please enter a valid number.")

        url = prompt_for_url()
        use_user_agent = prompt_for_yes_no("Would you like to use a User-Agent? (Y/n) ")
        timeout = prompt_for_int("Enter the timeout for proxy requests (default is 10 seconds): ", 10)
        num_workers = prompt_for_int("Enter the number of worker threads (default is 10): ", 10)
        save_file = prompt_for_yes_no("Would you like to save the results in a file? (Y/n) ")

        test_proxies(url, format_type, use_user_agent, timeout, num_workers, save_file)

    input("\nPress enter to continue...")
