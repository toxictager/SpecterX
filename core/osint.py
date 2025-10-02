# core/osint.py

import requests
import re
from phonenumbers import geocoder, carrier, parse
from phonenumbers.phonenumberutil import NumberParseException
import time
import hashlib
import socket
import dns.resolver
import whois
from datetime import datetime
from random import uniform
from utils.reporter import write_html_section

# Enhanced platform list with more targets
platforms = {
    "GitHub": "https://github.com/{}",
    "Reddit": "https://www.reddit.com/user/{}",
    "Telegram": "https://t.me/{}",
    "Instagram": "https://www.instagram.com/{}/",
    "Twitter (X)": "https://x.com/{}",
    "Pinterest": "https://www.pinterest.com/{}/",
    "Steam": "https://steamcommunity.com/id/{}",
    "Twitch": "https://www.twitch.tv/{}",
    "SoundCloud": "https://soundcloud.com/{}",
    "TikTok": "https://www.tiktok.com/@{}",
    "DEV.to": "https://dev.to/{}",
    "HackerNews": "https://news.ycombinator.com/user?id={}",
    "Keybase": "https://keybase.io/{}",
    "GitLab": "https://gitlab.com/{}",
    "Flickr": "https://www.flickr.com/people/{}",
    "YouTube": "https://www.youtube.com/@{}",
    "LinkedIn": "https://www.linkedin.com/in/{}",
    "Medium": "https://medium.com/@{}",
    "Behance": "https://www.behance.net/{}",
    "Dribbble": "https://dribbble.com/{}",
    "Discord": "https://discord.com/users/{}",
    "Spotify": "https://open.spotify.com/user/{}",
    "Snapchat": "https://www.snapchat.com/add/{}",
    "Vimeo": "https://vimeo.com/{}",
    "Patreon": "https://www.patreon.com/{}",
}


def make_request_with_retry(url, max_retries=3):
    """Make HTTP request with retry logic and random delays"""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    
    for attempt in range(max_retries):
        try:
            # Random delay to avoid detection (1-3 seconds)
            time.sleep(uniform(1, 3))
            response = requests.get(url, headers=headers, timeout=10)
            
            # Don't retry on rate limits immediately
            if response.status_code != 429:
                return response
            elif attempt < max_retries - 1:
                # Longer wait for rate limits
                time.sleep(uniform(5, 10))
                
        except requests.exceptions.RequestException as e:
            if attempt == max_retries - 1:
                return None
            time.sleep(uniform(2, 4))
    return None

def check_username(username):
    print(f"\n[🔎] Searching for '{username}' across platforms:\n")
    headers = {"User-Agent": "Mozilla/5.0"}
    results = []

    for site, url in platforms.items():
        full_url = url.format(username)
        try:
            resp = requests.get(full_url, headers=headers, timeout=6)

            if resp.status_code == 200:
                if site == "Reddit":
                    if "Sorry, nobody on Reddit goes by that name" in resp.text or "suspended" in resp.text:
                        status = f"{site}: Page exists, but user is missing/banned"
                    else:
                        status = f"{site}: Found → {full_url}"
                elif site == "Telegram":
                    if "If you have Telegram" not in resp.text:
                        status = f"{site}: Not found"
                    else:
                        status = f"{site}: Found → {full_url}"
                elif site == "GitLab":
                    if "Not Found" in resp.text:
                        status = f"{site}: Not found (text check)"
                    else:
                        status = f"{site}: Found → {full_url}"
                elif site == "Keybase":
                    if "We couldn’t find any" in resp.text:
                        status = f"{site}: Not found (text check)"
                    else:
                        status = f"{site}: Found → {full_url}"
                elif site == "Flicker":
                    if "Oops! We can't find that page" in resp.text:
                        status = f"{site}: Not found"
                    else:
                        status = f"{site}: Found → {full_url}"
                elif site == "HackerNews":
                    if "user not found" in resp.text:
                        status = f"{site}: Not found"
                    else:
                        status = f"{site}: Found → {full_url}"
                elif site == "TikTok":
                    if "Couldn't find this account" in resp.text or "Page Not Found" in resp.text:
                        status = f"{site}: Not found"
                    else:
                        status = f"{site}: Found → {full_url}"
                else:
                    status = f"{site}: Found → {full_url}"
            elif resp.status_code in [403, 429]:
                status = f"{site}: Rate-limited or blocked (status {resp.status_code})"
            elif resp.status_code == 404:
                status = f"{site}: Not found"
            elif resp.status_code == 400:
                status = f"{site}: Invalid username or bad request"
            else:
                status = f"{site}: Unhandled status {resp.status_code}"
        except requests.exceptions.RequestException as e:
            status = f"{site}: Connection failed - {e}"

        print(f"[{status}]")
        results.append(status)

    write_html_section("Username OSINT", [f"Username: {username}"] + results)
    input("\nPress Enter to return...")


# Phone Number OSINT Module
def is_valid_phone_number(phone):
    """Basic phone number validation"""
    # Remove common formatting characters
    cleaned = re.sub(r'[\s\-\(\)\+\.]', '', phone)
    # Check if it's mostly digits and reasonable length
    return re.match(r'^\+?[\d]{7,15}$', cleaned) is not None

def format_phone_number(phone):
    """Clean and format phone number"""
    # Remove all non-digit characters except +
    cleaned = re.sub(r'[^\d\+]', '', phone)
    return cleaned

def get_country_from_phone(phone):
    """Identify country from phone number prefix"""
    country_codes = {
        "+1": "United States/Canada",
        "+7": "Russia/Kazakhstan", 
        "+33": "France",
        "+34": "Spain",
        "+39": "Italy",
        "+44": "United Kingdom",
        "+49": "Germany",
        "+55": "Brazil",
        "+81": "Japan",
        "+86": "China",
        "+91": "India",
        "+92": "Pakistan",
        "+93": "Afghanistan",
        "+94": "Sri Lanka",
        "+95": "Myanmar",
        "+98": "Iran",
        "+212": "Morocco",
        "+213": "Algeria",
        "+216": "Tunisia",
        "+218": "Libya",
        "+220": "Gambia",
        "+221": "Senegal",
        "+222": "Mauritania",
        "+223": "Mali",
        "+224": "Guinea",
        "+225": "Ivory Coast",
        "+226": "Burkina Faso",
        "+227": "Niger",
        "+228": "Togo",
        "+229": "Benin",
        "+230": "Mauritius",
        "+231": "Liberia",
        "+232": "Sierra Leone",
        "+233": "Ghana",
        "+234": "Nigeria",
        "+235": "Chad",
        "+236": "Central African Republic",
        "+237": "Cameroon",
        "+238": "Cape Verde",
        "+239": "São Tomé and Príncipe",
        "+240": "Equatorial Guinea",
        "+241": "Gabon",
        "+242": "Republic of the Congo",
        "+243": "Democratic Republic of the Congo",
        "+244": "Angola",
        "+245": "Guinea-Bissau",
        "+246": "British Indian Ocean Territory",
        "+248": "Seychelles",
        "+249": "Sudan",
        "+250": "Rwanda",
        "+251": "Ethiopia",
        "+252": "Somalia",
        "+253": "Djibouti",
        "+254": "Kenya",
        "+255": "Tanzania",
        "+256": "Uganda",
        "+257": "Burundi",
        "+258": "Mozambique",
        "+260": "Zambia",
        "+261": "Madagascar",
        "+262": "Mayotte/Réunion",
        "+263": "Zimbabwe",
        "+264": "Namibia",
        "+265": "Malawi",
        "+266": "Lesotho",
        "+267": "Botswana",
        "+268": "Eswatini",
        "+269": "Comoros",
        "+290": "Saint Helena",
        "+291": "Eritrea",
        "+297": "Aruba",
        "+298": "Faroe Islands",
        "+299": "Greenland",
        "+350": "Gibraltar",
        "+351": "Portugal",
        "+352": "Luxembourg",
        "+353": "Ireland",
        "+354": "Iceland",
        "+355": "Albania",
        "+356": "Malta",
        "+357": "Cyprus",
        "+358": "Finland",
        "+359": "Bulgaria",
        "+370": "Lithuania",
        "+371": "Latvia",
        "+372": "Estonia",
        "+373": "Moldova",
        "+374": "Armenia",
        "+375": "Belarus",
        "+376": "Andorra",
        "+377": "Monaco",
        "+378": "San Marino",
        "+380": "Ukraine",
        "+381": "Serbia",
        "+382": "Montenegro",
        "+383": "Kosovo",
        "+385": "Croatia",
        "+386": "Slovenia",
        "+387": "Bosnia and Herzegovina",
        "+389": "North Macedonia",
        "+420": "Czech Republic",
        "+421": "Slovakia",
        "+423": "Liechtenstein",
        "+43": "Austria",
        "+45": "Denmark",
        "+46": "Sweden",
        "+47": "Norway",
        "+48": "Poland",
        "+90": "Turkey",
        "+960": "Maldives",
        "+961": "Lebanon",
        "+962": "Jordan",
        "+963": "Syria",
        "+964": "Iraq",
        "+965": "Kuwait",
        "+966": "Saudi Arabia",
        "+967": "Yemen",
        "+968": "Oman",
        "+970": "Palestine",
        "+971": "United Arab Emirates",
        "+972": "Israel",
        "+973": "Bahrain",
        "+974": "Qatar",
        "+975": "Bhutan",
        "+976": "Mongolia",
        "+977": "Nepal",
        "+992": "Tajikistan",
        "+993": "Turkmenistan",
        "+994": "Azerbaijan",
        "+995": "Georgia",
        "+996": "Kyrgyzstan",
        "+998": "Uzbekistan"
    }
    
    # Try to match country codes (longest first)
    for code in sorted(country_codes.keys(), key=len, reverse=True):
        if phone.startswith(code):
            return country_codes[code], code
    
    return "Unknown", "Unknown"
def get_carrier_info(phone):
    """
    Identifies the carrier of a phone number using the phonenumbers library.
    This works for international numbers.
    """
    try:
        # Parse the phone number, 'None' indicates the region is unknown
        # and should be inferred from the country code.
        parsed_number = parse(phone, None)

        # Get the carrier name in English
        carrier_name = carrier.name_for_number(parsed_number, "en")

        if carrier_name:
            return carrier_name
        else:
            return "Carrier could not be identified."
    except NumberParseException:
        # This handles cases where the number format is invalid
        return "Invalid number format for carrier lookup."
    
def check_phone_social_media(phone):
    """Check if phone number is associated with social media accounts (more robust)"""
    results = []
    
    # Note: This is for educational purposes only
    # In reality, most platforms have privacy protections
    
    social_checks = {
        "WhatsApp": f"https://wa.me/{phone.replace('+', '')}",
        "Telegram": f"https://t.me/{phone.replace('+', '')}"
    }
    
    for platform, url in social_checks.items():
        try:
            response = make_request_with_retry(url)
            if response and response.status_code == 200:
                content = response.text.lower() # Convert to lowercase for case-insensitive check
                
                if platform == "WhatsApp":
                    # Look for the error message shown for invalid numbers.
                    # If this message is NOT present, the number is likely valid.
                    if "phone number shared via url is invalid" in content:
                        results.append(f"{platform}: ❌ Number not found")
                    else:
                        results.append(f"{platform}: ✅ Number is likely registered")

                elif platform == "Telegram":
                    # Telegram's check remains fairly reliable for now
                    if "if you have telegram" in content:
                        results.append(f"{platform}: ✅ Number may be registered")
                    else:
                        results.append(f"{platform}: ❌ Number not found/private")
            else:
                results.append(f"{platform}: ❓ Could not verify")
        except Exception as e:
            results.append(f"{platform}: ❌ Check failed with error: {e}")
    
    return results

def run_phone_osint():
    """Main phone number OSINT function"""
    print("\n📞 [PHONE NUMBER OSINT]")
    phone = input("Enter a phone number (with country code): ").strip()
    
    if not is_valid_phone_number(phone):
        print("[❌] Invalid phone number format.")
        print("Expected format: +1234567890 or +1-234-567-8900")
        input("Press Enter to return...")
        return
    
    formatted_phone = format_phone_number(phone)
    print(f"\n[🔍] Analyzing phone number: {formatted_phone}\n")
    
    # Country identification
    country, country_code = get_country_from_phone(formatted_phone)
    print(f"🌍 Country: {country}")
    print(f"📍 Country Code: {country_code}")
    
    # Carrier information
    carrier = get_carrier_info(formatted_phone)
    print(f"📡 Carrier: {carrier}")
    
    # Phone number type analysis
    phone_type = "Unknown"
    if len(formatted_phone.replace('+', '')) == 11 and formatted_phone.startswith('+1'):
        phone_type = "Mobile/Landline (US/Canada format)"
    elif len(formatted_phone.replace('+', '')) >= 10:
        phone_type = "International format"
    print(f"📱 Type: {phone_type}")
    
    # Social media checks
    print(f"\n🔍 Checking social media associations...")
    social_results = check_phone_social_media(formatted_phone)
    for result in social_results:
        print(f"  {result}")
    
    # Reverse lookup simulation (educational)
    print(f"\n📋 Additional Analysis:")
    print(f"  • Phone validation: Valid format ✅")
    print(f"  • Length check: {len(formatted_phone.replace('+', ''))} digits")
    
    # Timezone estimation based on country
    timezone_map = {
        "United States/Canada": "Multiple (UTC-5 to UTC-8)",
        "United Kingdom": "UTC+0 (GMT)",
        "Germany": "UTC+1 (CET)",
        "India": "UTC+5:30 (IST)",
        "China": "UTC+8 (CST)",
        "Japan": "UTC+9 (JST)",
        "Australia": "Multiple (UTC+8 to UTC+11)"
    }
    
    estimated_timezone = timezone_map.get(country, "Unknown")
    print(f"  • Estimated timezone: {estimated_timezone}")
    
    # Compile results for report
    report_data = [
        f"Phone Number: {formatted_phone}",
        f"Original Input: {phone}",
        f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Country: {country}",
        f"Country Code: {country_code}",
        f"Carrier: {carrier}",
        f"Type: {phone_type}",
        f"Timezone: {estimated_timezone}",
        "=" * 40,
        "Social Media Checks:"
    ] + social_results + [
        "=" * 40,
        "⚠️  DISCLAIMER: This tool is for educational purposes only.",
        "   Respect privacy laws and obtain proper authorization before",
        "   conducting investigations on phone numbers you don't own."
    ]
    
    write_html_section("Phone Number OSINT", report_data)
    print("\n[💾] Results saved to report.html")
    
    input("\nPress Enter to return...")

# Domain OSINT (unchanged from original)
def run_domain_osint():
    print("\n🌐 [DOMAIN OSINT] Scan")
    domain = input("Enter a domain (e.g. example.com): ").strip()
    if not domain:
        print("No domain provided.")
        return

    print(f"\n[🔍] Scanning: {domain}\n")

    try:
        # WHOIS Info
        print("📄 WHOIS Info:")
        w = whois.whois(domain)
        print(f"  Registrar     : {w.registrar}")
        print(f"  Creation Date : {w.creation_date}")
        print(f"  Expiration    : {w.expiration_date}")
        print(f"  Emails        : {w.emails}")
    except Exception as e:
        print(f"  [!] WHOIS lookup failed: {e}")

    # DNS Records
    try:
        print("\n📡 DNS Records:")
        for record_type in ["A", "MX", "NS", "TXT"]:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                print(f"  {record_type} Records:")
                for r in answers:
                    print(f"    → {str(r)}")
            except dns.resolver.NoAnswer:
                print(f"  {record_type}: No records found")
            except dns.resolver.NXDOMAIN:
                print(f"  {record_type}: Domain not found")
            except Exception as e:
                print(f"  {record_type}: Error - {e}")
    except Exception as e:
        print(f"  [!] DNS resolution failed: {e}")

    lines = [f"Domain: {domain}"]
    try:
        w = whois.whois(domain)
        lines.append(f"Registrar: {w.registrar}")
        lines.append(f"Created: {w.creation_date}")
        lines.append(f"Expires: {w.expiration_date}")
        lines.append(f"Emails: {w.emails}")
    except Exception as e:
        lines.append(f"WHOIS failed: {e}")

    lines.append("DNS Records:")
    for record_type in ["A", "MX", "NS", "TXT"]:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            for r in answers:
                lines.append(f"{record_type}: {r}")
        except Exception as e:
            lines.append(f"{record_type}: Error - {e}")

    write_html_section("Domain OSINT", lines)
    print("[💾] Appended to report.html")

    input("\nPress Enter to return...")

# Email OSINT (fixed from original)
def is_valid_email(email):
    """Simple email regex validation"""
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w{2,}$'
    return re.match(pattern, email)

def get_gravatar_url(email):
    """Generate Gravatar URL from email MD5 hash"""
    email_clean = email.strip().lower()
    email_hash = hashlib.md5(email_clean.encode()).hexdigest()
    return f"https://www.gravatar.com/avatar/{email_hash}?d=404"

def run_email_osint():
    """Email OSINT with bug fixes"""
    print("\n📧 [EMAIL OSINT]")
    email = input("Enter an email: ").strip()

    if not is_valid_email(email):
        print("[❌] Invalid email format.")
        input("Press Enter to return...")
        return

    print(f"\n[🔍] Scanning email: {email}\n")

    # Gravatar Check
    gravatar_url = get_gravatar_url(email)
    gravatar_status = "Unknown"
    
    try:
        resp = requests.get(gravatar_url, timeout=5)
        if resp.status_code == 200:
            print(f"[🧑‍🎨] Gravatar profile exists → {gravatar_url}")
            gravatar_status = f"Found (Status: {resp.status_code})"
        elif resp.status_code == 404:
            print("[❌] No Gravatar profile found")
            gravatar_status = f"Not found (Status: {resp.status_code})"
        else:
            print(f"[⚠️ ] Unexpected Gravatar response: {resp.status_code}")
            gravatar_status = f"Unexpected response: {resp.status_code}"
    except Exception as e:
        print(f"[🔥] Gravatar check failed: {e}")
        gravatar_status = f"Check failed: {e}"

    # MX Records
    domain = email.split('@')[-1]
    print(f"\n📡 MX Records for domain: {domain}")
    mx_records = []
    
    try:
        mx_answers = dns.resolver.resolve(domain, "MX")
        for r in mx_answers:
            print(f"  → {str(r)}")
            mx_records.append(str(r))
    except Exception as e:
        print(f"  [!] Failed to get MX records: {e}")
        mx_records.append(f"Failed: {e}")

    lines = [
        f"Email: {email}",
        f"Gravatar URL: {gravatar_url}",
        f"Gravatar Status: {gravatar_status}",
        f"MX Records for {domain}:"
    ] + [f"→ {record}" for record in mx_records]

    write_html_section("Email OSINT", lines)
    print("[💾] Appended to report.html")

    input("\nPress Enter to return...")

def run():
    """Main OSINT menu with enhanced options"""
    print("\n[🕵️ Enhanced OSINT Toolkit]")
    print("[1] Enhanced Username Lookup")
    print("[2] Phone Number OSINT")
    print("[3] Domain OSINT") 
    print("[4] Email OSINT")
    print("[5] Back to Main Menu")

    choice = input("Select an option: ").strip()

    if choice == '1':
        username = input("Enter a username: ").strip()
        if username:
            check_username(username)
    elif choice == '2':
        run_phone_osint()
    elif choice == '3':
        run_domain_osint()
    elif choice == '4':
        run_email_osint()
    else:
        return