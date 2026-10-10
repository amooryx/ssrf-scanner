import threading
import subprocess
import sys
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import ssrf_scanner


class _FixtureHandler(BaseHTTPRequestHandler):
    followed_redirect = False
    request_count = 0

    def do_GET(self):
        type(self).request_count += 1
        parsed = urlsplit(self.path)
        if parsed.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/followed")
            self.end_headers()
            return
        if parsed.path == "/followed":
            type(self).followed_redirect = True
        value = parse_qs(parsed.query).get("url", [""])[0]
        body = value.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class ScannerSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _FixtureHandler.followed_redirect = False
        _FixtureHandler.request_count = 0
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.origin = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_scoped_probe_is_heuristic_not_confirmation(self):
        target = f"{self.origin}/proxy?url=original&keep=yes"
        probe = f"{self.origin}/safe-fixture"
        ssrf_scanner.validate_scope(target, probe, "127.0.0.1")

        result = ssrf_scanner.test_ssrf(target, "url", probe, timeout=1)

        self.assertEqual(result["classification"], "heuristic_indication")
        self.assertIn("does not confirm SSRF", result["evidence"])

    def test_redirect_is_not_followed(self):
        target = f"{self.origin}/redirect?url=original"
        probe = f"{self.origin}/safe-fixture"
        result = ssrf_scanner.test_ssrf(target, "url", probe, timeout=1)

        self.assertEqual(result["status"], 302)
        self.assertEqual(result["classification"], "inconclusive")
        self.assertFalse(_FixtureHandler.followed_redirect)

    def test_foreign_origin_and_allow_host_are_rejected(self):
        target = f"{self.origin}/proxy?url=original"
        with self.assertRaisesRegex(ValueError, "same scheme, hostname, and port"):
            ssrf_scanner.validate_scope(target, "http://example.invalid/", "127.0.0.1")
        with self.assertRaisesRegex(ValueError, "does not exactly match"):
            ssrf_scanner.validate_scope(target, f"{self.origin}/safe", "example.invalid")

    def test_non_http_and_credential_urls_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "HTTP or HTTPS"):
            ssrf_scanner.validate_http_url("file:///etc/passwd", "Probe URL")
        with self.assertRaisesRegex(ValueError, "user information"):
            ssrf_scanner.validate_http_url("http://user@127.0.0.1/", "Target URL")

    def test_cli_requires_explicit_consent_before_sending_requests(self):
        initial_requests = _FixtureHandler.request_count
        completed = subprocess.run(
            [
                sys.executable,
                "ssrf_scanner.py",
                f"{self.origin}/proxy?url=original",
                "--probe-url",
                f"{self.origin}/safe-fixture",
                "--allow-host",
                "127.0.0.1",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("explicit consent required", completed.stderr)
        self.assertEqual(_FixtureHandler.request_count, initial_requests)

    def test_cli_runs_against_local_fixture_when_scoped_and_authorized(self):
        completed = subprocess.run(
            [
                sys.executable,
                "ssrf_scanner.py",
                f"{self.origin}/proxy?url=original",
                "--probe-url",
                f"{self.origin}/safe-fixture",
                "--allow-host",
                "127.0.0.1",
                "--authorized",
                "--threads",
                "1",
                "--timeout",
                "1",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("[heuristic_indication]", completed.stdout)
        self.assertIn("no result confirms SSRF", completed.stdout)

    def test_request_api_enforces_timeout_and_header_limits(self):
        target = f"{self.origin}/proxy?url=original"
        probe = f"{self.origin}/safe-fixture"
        with self.assertRaisesRegex(ValueError, "timeout"):
            ssrf_scanner.test_ssrf(target, "url", probe, timeout=ssrf_scanner.MAX_TIMEOUT + 1)
        with self.assertRaisesRegex(ValueError, "header"):
            ssrf_scanner.test_ssrf(target, "url", probe, headers={"Host": "elsewhere"})

    def test_probe_replacement_preserves_other_query_parameters(self):
        target = f"{self.origin}/proxy?url=old&keep=unchanged&url=duplicate"
        probe = f"{self.origin}/safe-fixture"
        injected = ssrf_scanner.inject_probe(target, "url", probe)
        self.assertEqual(
            parse_qs(urlsplit(injected).query),
            {"url": [probe], "keep": ["unchanged"]},
        )


if __name__ == "__main__":
    unittest.main()
