"""
Web version of the HTTP Security Header Checker (Vercel serverless function).
Same checks as header_checker.py: fetches a site's response headers and
reports which of the 6 common security headers are present or missing.

Safety: only public http/https sites can be checked. Private / loopback
addresses are refused, so the service cannot be used to probe internal
networks. Checking headers is passive - the same as a browser visit.
"""
import ipaddress
import json
import socket
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

SECURITY_HEADERS = {
    "Content-Security-Policy": "Controls what the browser is allowed to load. Helps stop XSS.",
    "X-Frame-Options": "Stops the site being put inside a frame on another site (clickjacking).",
    "X-Content-Type-Options": "Stops the browser guessing file types (should be: nosniff).",
    "Strict-Transport-Security": "Forces HTTPS (HSTS) so the connection cannot be downgraded.",
    "Referrer-Policy": "Controls how much URL info is leaked to other sites.",
    "Permissions-Policy": "Controls browser features like camera/microphone for the site.",
}


def is_public_host(hostname):
    """True only if every IP the hostname points to is a public address."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False
    return True


def check(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    host = urlparse(url).hostname or ""
    if not host or not is_public_host(host):
        return {"error": "That address is not a public website, so it cannot be checked."}
    req = urllib.request.Request(url, headers={"User-Agent": "HeaderChecker/1.0 (learning project)"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status, final_url, headers = resp.status, resp.geturl(), dict(resp.headers)
    except urllib.error.URLError as e:
        return {"error": f"Could not reach {url} : {e}"}
    lower = {k.lower(): v for k, v in headers.items()}
    results = []
    present = 0
    for name, why in SECURITY_HEADERS.items():
        value = lower.get(name.lower())
        if value:
            present += 1
            results.append({"name": name, "present": True, "value": value[:200], "why": why})
        else:
            results.append({"name": name, "present": False, "value": None, "why": why})
    return {
        "url": final_url,
        "status": status,
        "server": headers.get("Server", "not disclosed"),
        "results": results,
        "present": present,
        "total": len(SECURITY_HEADERS),
        "note": "Missing a header is a hardening gap, not proof a site is hackable.",
    }


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        qs = parse_qs(urlparse(self.path).query)
        target = (qs.get("url") or [""])[0].strip()
        if not target:
            body, code = {"error": "No website given."}, 400
        else:
            body, code = check(target), 200
        payload = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass
