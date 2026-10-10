#!/usr/bin/env python3
"""Send bounded, same-origin SSRF probes to explicitly authorized targets."""

import argparse
import ipaddress
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

MAX_PARAMS = 20
MAX_THREADS = 5
MAX_TIMEOUT = 10.0
MAX_BODY_BYTES = 4096
HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


def _normalized_host(host: str) -> str:
    """Normalize DNS names and IP literals for exact scope comparisons."""
    try:
        return ipaddress.ip_address(host).compressed.lower()
    except ValueError:
        try:
            normalized = host.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("URL contains an invalid hostname") from exc
        labels = normalized.split(".")
        if (
            len(normalized) > 253
            or any(
                not label
                or len(label) > 63
                or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
                for label in labels
            )
            or (all(char in "0123456789." for char in normalized) and len(labels) == 4)
        ):
            raise ValueError("URL contains an invalid hostname")
        return normalized


def validate_http_url(value: str, label: str) -> urllib.parse.SplitResult:
    """Accept only unambiguous absolute HTTP(S) URLs without credentials/fragments."""
    if not value or any(ord(char) < 0x20 or char.isspace() for char in value):
        raise ValueError(f"{label} must not be empty or contain whitespace/control characters")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{label} is not a valid URL: {exc}") from exc
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError(f"{label} must be an absolute HTTP or HTTPS URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"{label} must not contain user information")
    if parsed.fragment:
        raise ValueError(f"{label} must not contain a fragment")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError(f"{label} has an invalid port")
    _normalized_host(parsed.hostname)
    return parsed


def _origin(parsed: urllib.parse.SplitResult) -> tuple[str, str, int]:
    scheme = parsed.scheme.lower()
    port = parsed.port or (443 if scheme == "https" else 80)
    return scheme, _normalized_host(parsed.hostname), port


def validate_scope(target_url: str, probe_url: str, allowed_host: str) -> None:
    target = validate_http_url(target_url, "Target URL")
    probe = validate_http_url(probe_url, "Probe URL")
    if not allowed_host or any(char in allowed_host for char in "/@?#"):
        raise ValueError("--allow-host must contain only a hostname or IP address")
    try:
        allowed = _normalized_host(allowed_host.strip("[]"))
    except ValueError as exc:
        raise ValueError(f"--allow-host is invalid: {exc}") from exc
    if _normalized_host(target.hostname) != allowed:
        raise ValueError("Target hostname does not exactly match --allow-host")
    if _origin(target) != _origin(probe):
        raise ValueError("Probe URL must have the same scheme, hostname, and port as the target")


def inject_probe(target_url: str, param: str, probe_url: str) -> str:
    """Replace all values for one parameter, preserving unrelated query parameters."""
    parsed = urllib.parse.urlsplit(target_url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    updated = []
    for key, value in query:
        if key == param:
            if not replaced:
                updated.append((key, probe_url))
                replaced = True
        else:
            updated.append((key, value))
    if not replaced:
        updated.append((param, probe_url))
    return urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(updated)))


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def test_ssrf(
    target_url: str,
    param: str,
    probe_url: str,
    timeout: float = 5.0,
    headers: dict[str, str] | None = None,
) -> dict:
    """Send one scoped GET; response reflection is heuristic, never confirmation."""
    target = validate_http_url(target_url, "Target URL")
    validate_scope(target_url, probe_url, target.hostname)
    if not 0 < timeout <= MAX_TIMEOUT:
        raise ValueError(f"timeout must be greater than 0 and at most {MAX_TIMEOUT}")
    for name, value in (headers or {}).items():
        if (
            not HEADER_NAME.fullmatch(name)
            or name.lower() in ("host", "connection", "transfer-encoding", "upgrade")
            or any(char in value for char in "\r\n")
        ):
            raise ValueError(f"invalid or disallowed request header: {name!r}")
    request_url = inject_probe(target_url, param, probe_url)
    result = {
        "param": param,
        "classification": "inconclusive",
        "evidence": "",
    }
    request = urllib.request.Request(request_url)
    for name, value in (headers or {}).items():
        request.add_header(name, value)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirectHandler(),
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(MAX_BODY_BYTES).decode("utf-8", errors="replace")
            result["status"] = response.status
    except urllib.error.HTTPError as exc:
        result["status"] = exc.code
        try:
            body = exc.read(MAX_BODY_BYTES).decode("utf-8", errors="replace")
        finally:
            exc.close()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        result["error"] = str(exc)
        return result

    if probe_url in body:
        result["classification"] = "heuristic_indication"
        result["evidence"] = "probe URL is reflected in the response; reflection does not confirm SSRF"
    return result


def discover_url_params(url: str) -> list[str]:
    parsed = urllib.parse.urlsplit(url)
    return list(dict.fromkeys(key for key, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)))


def _parse_headers(values: list[str], parser: argparse.ArgumentParser) -> dict[str, str]:
    headers = {}
    for item in values:
        if ":" not in item:
            parser.error(f"Invalid --header {item!r}; expected 'Name: Value'")
        name, value = item.split(":", 1)
        name, value = name.strip(), value.strip()
        if not HEADER_NAME.fullmatch(name) or any(char in value for char in "\r\n"):
            parser.error(f"Invalid --header {item!r}")
        if name.lower() in ("host", "connection", "transfer-encoding", "upgrade"):
            parser.error(f"--header may not override the transport header {name!r}")
        headers[name] = value
    return headers


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Send bounded same-origin SSRF probes to an authorized target."
    )
    parser.add_argument("url", help="Authorized target endpoint URL")
    parser.add_argument("--probe-url", required=True, help="Harmless HTTP(S) URL on the target's exact origin")
    parser.add_argument("--allow-host", required=True, help="Exact target hostname/IP authorized for testing")
    parser.add_argument("--authorized", action="store_true", help="Confirm you are authorized to test this target")
    parser.add_argument("--params", nargs="*", help="Query parameters to test (auto-detected by default)")
    parser.add_argument("--threads", type=int, default=2, help=f"Concurrent requests (1-{MAX_THREADS}; default: 2)")
    parser.add_argument("--timeout", type=float, default=5.0, help=f"Per-request timeout in seconds (0-{MAX_TIMEOUT}]")
    parser.add_argument("--out", help="Write results as JSON")
    parser.add_argument("--header", action="append", default=[], metavar="NAME: VALUE", help="Request header; may be repeated")
    args = parser.parse_args()

    if not args.authorized:
        parser.error("explicit consent required; pass --authorized only for a target you may test")
    try:
        validate_scope(args.url, args.probe_url, args.allow_host)
    except ValueError as exc:
        parser.error(str(exc))
    if not 1 <= args.threads <= MAX_THREADS:
        parser.error(f"--threads must be between 1 and {MAX_THREADS}")
    if not 0 < args.timeout <= MAX_TIMEOUT:
        parser.error(f"--timeout must be greater than 0 and at most {MAX_TIMEOUT}")

    params = args.params if args.params is not None else discover_url_params(args.url)
    if not params:
        parser.error("No query parameters found. Specify them with --params.")
    if len(params) > MAX_PARAMS:
        parser.error(f"At most {MAX_PARAMS} parameters may be tested per run")
    if any(not param or len(param) > 128 for param in params):
        parser.error("Parameter names must be between 1 and 128 characters")
    headers = _parse_headers(args.header, parser)

    print(f"[*] Sending {len(params)} same-origin probe(s) to {_normalized_host(validate_http_url(args.url, 'Target URL').hostname)}")
    print("[!] Authorized use only; redirects are not followed.")
    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(test_ssrf, args.url, param, args.probe_url, args.timeout, headers): param
            for param in params
        }
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            status = result.get("status", "request failed")
            print(f"  [{result['classification']}] param={result['param']} | status={status}")
            if result["evidence"]:
                print(f"        {result['evidence']}")

    heuristic_count = sum(result["classification"] == "heuristic_indication" for result in results)
    print(
        f"\n[*] {heuristic_count} heuristic indication(s); "
        "no result confirms SSRF. Verify suspected behavior using authorized server-side logs."
    )
    if args.out:
        with open(args.out, "w", encoding="utf-8") as output:
            json.dump(results, output, indent=2)
        print(f"[*] Results written to {args.out}")


if __name__ == "__main__":
    main()
