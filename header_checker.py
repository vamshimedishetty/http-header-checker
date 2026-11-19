"""
HTTP Security Header Checker - learning project
Fetches a website's HTTP response headers and checks for common
security headers that protect a site. Reports which are present/missing.

Usage:
    python header_checker.py https://example.com

LEGAL: Checking response headers is passive (same as a browser visit).
Only test further on systems you own or have permission to test.
"""
import sys
import urllib.request
import urllib.error

SECURITY_HEADERS = {
    "Content-Security-Policy": "Controls what the browser is allowed to load. Helps stop XSS.",
    "X-Frame-Options": "Stops the site being put inside a frame on another site (clickjacking).",
    "X-Content-Type-Options": "Stops the browser guessing file types (should be: nosniff).",
    "Strict-Transport-Security": "Forces HTTPS (HSTS) so the connection cannot be downgraded.",
    "Referrer-Policy": "Controls how much URL info is leaked to other sites.",
    "Permissions-Policy": "Controls browser features like camera/microphone for the site.",
}

def fetch_headers(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    req = urllib.request.Request(url, headers={"User-Agent": "HeaderChecker/1.0 (learning project)"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status, resp.geturl(), dict(resp.headers)

def main():
    if len(sys.argv) != 2:
        print("Usage: python header_checker.py https://example.com")
        sys.exit(1)
    url = sys.argv[1]
    try:
        status, final_url, headers = fetch_headers(url)
    except urllib.error.URLError as e:
        print(f"[!] Could not reach {url} : {e}")
        sys.exit(1)

    # Header names are case-insensitive - normalise them
    lower = {k.lower(): v for k, v in headers.items()}

    print(f"[*] URL    : {final_url}")
    print(f"[*] Status : {status}")
    print(f"[*] Server : {headers.get('Server', 'not disclosed')}")
    print("-" * 60)

    present = 0
    for name, why in SECURITY_HEADERS.items():
        value = lower.get(name.lower())
        if value:
            present += 1
            print(f"[+] PRESENT  {name}: {value[:70]}")
        else:
            print(f"[-] MISSING  {name}")
            print(f"             Why it matters: {why}")
    print("-" * 60)
    print(f"[*] Result: {present}/{len(SECURITY_HEADERS)} security headers present.")
    print("[*] Note: Missing a header is a hardening gap, not proof a site is hackable.")

if __name__ == "__main__":
    main()
