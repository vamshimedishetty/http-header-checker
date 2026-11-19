# HTTP Security Header Checker

A small Python tool built as a **learning project** for web application security basics.
Give it a website URL and it checks whether the site sends the common **security headers**
that browsers use for protection — and explains, in plain words, why each missing one matters.

## What I learnt
- How HTTP requests and responses work (headers, status codes)
- What the main security headers do: CSP, X-Frame-Options, HSTS, and others
- The difference between a *hardening gap* (missing header) and a real vulnerability
- Making HTTP requests in Python with the standard library (`urllib`)

## How to run
```bash
python header_checker.py https://example.com
```

## Sample output
```
[*] URL    : https://example.com/
[*] Status : 200
[*] Server : cloudflare
------------------------------------------------------------
[+] PRESENT  Content-Security-Policy: ...
[-] MISSING  X-Frame-Options
             Why it matters: Stops the site being put inside a frame...
------------------------------------------------------------
[*] Result: 4/6 security headers present.
```

## Tech
Python 3 — standard library only. No installation needed.
