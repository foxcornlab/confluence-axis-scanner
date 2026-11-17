#!/usr/bin/env python3
"""Tests for confluence_axis_scanner.py. Run: python3 -m pytest tests/ -q
or: python3 tests/test_confluence_axis_scanner.py (runs unittest)."""

import io
import json
import os
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import confluence_axis_scanner as s


class TestParseVersion(unittest.TestCase):
    def test_bare_version(self):
        self.assertEqual(s.parse_version("9.2.28"), ((9, 2, 28), None))

    def test_bare_two_part(self):
        self.assertEqual(s.parse_version("9.2"), ((9, 2), None))

    def test_jar_filename(self):
        self.assertEqual(
            s.parse_version("confluence-9.2.27.jar"), ((9, 2, 27), None))

    def test_install_dir_name(self):
        self.assertEqual(
            s.parse_version("atlassian-confluence-9.2.28"),
            ((9, 2, 28), None))

    def test_powered_by_footer(self):
        self.assertEqual(
            s.parse_version("Powered by Atlassian Confluence 9.2.28, "
                            "the Enterprise Wiki."),
            ((9, 2, 28), None))

    def test_meta_tags(self):
        html = ('<meta name="ajs-version-number" content="9.2.27">\n'
                '<meta name="ajs-build-number" content="9117">')
        self.assertEqual(s.parse_version(html), ((9, 2, 27), 9117))

    def test_meta_tags_patched(self):
        html = ('<meta name="ajs-version-number" content="9.2.28">\n'
                '<meta name="ajs-build-number" content="9117">')
        self.assertEqual(s.parse_version(html), ((9, 2, 28), 9117))

    def test_log_line(self):
        self.assertEqual(
            s.parse_version("2026-11-01 INFO Starting Confluence 9.2.28"),
            ((9, 2, 28), None))

    def test_buildnumber_confversion(self):
        self.assertEqual(
            s.parse_version("SELECT BUILDNUMBER FROM CONFVERSION\n9117"),
            (None, 9117))

    def test_no_version(self):
        self.assertEqual(s.parse_version("nothing here"), (None, None))

    def test_empty(self):
        self.assertEqual(s.parse_version(""), (None, None))

    def test_garbage_numbers_not_a_version(self):
        # A bare port number or date must not parse as a version.
        self.assertEqual(s.parse_version("listening on port 8090"),
                         (None, None))


class TestGradeVersion(unittest.TestCase):
    def test_fixed_release_patched(self):
        self.assertEqual(s.grade_version((9, 2, 28))[0], "PATCHED")

    def test_later_92_patch_patched(self):
        self.assertEqual(s.grade_version((9, 2, 29))[0], "PATCHED")

    def test_92_27_vulnerable(self):
        # The one-patch-behind trap: 9.2.27 is a day older than the fix.
        verdict, reason = s.grade_version((9, 2, 27))
        self.assertEqual(verdict, "VULNERABLE")
        self.assertIn("9.2.28", reason)

    def test_92_0_vulnerable(self):
        self.assertEqual(s.grade_version((9, 2, 0))[0], "VULNERABLE")

    def test_no_fix_lines_vulnerable(self):
        for version in ((9, 0, 3), (9, 1, 1), (9, 3, 2), (9, 4, 1),
                        (9, 5, 4)):
            verdict, reason = s.grade_version(version)
            self.assertEqual(verdict, "VULNERABLE", version)
            self.assertIn("no fix", reason.lower())

    def test_old_lines_vulnerable(self):
        for version in ((8, 5, 31), (8, 9, 8), (7, 20, 3), (6, 15, 1),
                        (1, 0, 0)):
            self.assertEqual(s.grade_version(version)[0], "VULNERABLE",
                             version)

    def test_10x_not_affected(self):
        for version in ((10, 0, 0), (10, 2, 20), (11, 0, 1)):
            verdict, reason = s.grade_version(version)
            self.assertEqual(verdict, "NOT-AFFECTED", version)
            self.assertIn("10.0", reason)

    def test_bare_92_unknown(self):
        verdict, reason = s.grade_version((9, 2))
        self.assertEqual(verdict, "UNKNOWN")
        self.assertIn("9.2.28", reason)

    def test_bare_9_unknown(self):
        self.assertEqual(s.grade_version((9,))[0], "UNKNOWN")

    def test_bare_10_not_affected(self):
        self.assertEqual(s.grade_version((10,))[0], "NOT-AFFECTED")
        self.assertEqual(s.grade_version((10, 2))[0], "NOT-AFFECTED")

    def test_future_9x_unknown(self):
        # A 9.6 line is not in the advisory table; never call it clean.
        self.assertEqual(s.grade_version((9, 6, 0))[0], "UNKNOWN")

    def test_no_version(self):
        self.assertEqual(s.grade_version(None)[0], "UNKNOWN")


class TestGradeBuild(unittest.TestCase):
    def test_ambiguous_build_9117_unknown(self):
        # The build-number trap: 9117 spans 9.2.24 (vulnerable) to
        # 9.2.28 (fixed). Build alone cannot tell them apart.
        verdict, reason = s.grade_build(9117)
        self.assertEqual(verdict, "UNKNOWN")
        self.assertIn("9.2.24", reason)

    def test_older_9x_builds_vulnerable(self):
        for build in (9116, 9114, 9111, 9109, 9104, 9202, 9203, 9204,
                      9012, 9002, 8901):
            self.assertEqual(s.grade_build(build)[0], "VULNERABLE", build)

    def test_10x_builds_not_affected(self):
        for build in (9304, 9403, 9425, 9526):
            self.assertEqual(s.grade_build(build)[0], "NOT-AFFECTED",
                             build)

    def test_no_build(self):
        self.assertEqual(s.grade_build(None)[0], "UNKNOWN")

    def test_nonsense_build(self):
        self.assertEqual(s.grade_build(0)[0], "UNKNOWN")
        self.assertEqual(s.grade_build(-5)[0], "UNKNOWN")


class TestTriage(unittest.TestCase):
    def test_vulnerable_version_alone(self):
        result = s.triage((9, 2, 27), None)
        self.assertEqual(result["verdict"], "VULNERABLE")

    def test_build_used_when_no_version(self):
        result = s.triage(None, 9116)
        self.assertEqual(result["verdict"], "VULNERABLE")
        result = s.triage(None, 9117)
        self.assertEqual(result["verdict"], "UNKNOWN")
        result = s.triage(None, 9403)
        self.assertEqual(result["verdict"], "NOT-AFFECTED")

    def test_version_beats_build(self):
        # 9.2.28 at build 9117 is patched even though the build alone
        # is ambiguous.
        result = s.triage((9, 2, 28), 9117)
        self.assertEqual(result["verdict"], "PATCHED")

    def test_remote_api_off_makes_vulnerable_not_exposed(self):
        result = s.triage((9, 2, 27), None, remote_api="off")
        self.assertEqual(result["verdict"], "NOT-EXPOSED")
        self.assertIn("mitigation", result["reason"])

    def test_no_remote_api_flag(self):
        result = s.triage((9, 5, 4), None, remote_api_off=True)
        self.assertEqual(result["verdict"], "NOT-EXPOSED")

    def test_remote_api_off_does_not_clean_patched(self):
        result = s.triage((9, 2, 28), None, remote_api="off")
        self.assertEqual(result["verdict"], "PATCHED")

    def test_exposed_endpoint_warns_but_keeps_verdict(self):
        result = s.triage((9, 2, 27), None, remote_api="exposed")
        self.assertEqual(result["verdict"], "VULNERABLE")
        self.assertEqual(len(result["warnings"]), 1)
        self.assertIn("reachable", result["warnings"][0])

    def test_exposed_endpoint_with_unknown_version_is_vulnerable(self):
        # The endpoint only answers on pre-10.0 with the feature on,
        # and every such version is affected.
        result = s.triage(None, None, remote_api="exposed")
        self.assertEqual(result["verdict"], "VULNERABLE")

    def test_unknown_version_api_off_stays_unknown(self):
        result = s.triage(None, None, remote_api="off")
        self.assertEqual(result["verdict"], "UNKNOWN")
        self.assertEqual(len(result["warnings"]), 1)

    def test_cloud_not_affected(self):
        result = s.triage(None, None, cloud=True)
        self.assertEqual(result["verdict"], "NOT-AFFECTED")

    def test_nothing_at_all_unknown(self):
        result = s.triage(None, None)
        self.assertEqual(result["verdict"], "UNKNOWN")


# --- mock Confluence for --url tests ---------------------------------------

def make_handler(pages):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            page = pages.get(self.path)
            if page is None:
                self.send_response(404)
                self.end_headers()
                return
            status, body = page
            self.send_response(status)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))
    return Handler


LOGIN_VULN = ('<html><head>'
              '<meta name="ajs-version-number" content="9.2.27">'
              '<meta name="ajs-build-number" content="9117">'
              '</head><body>login</body></html>')

LOGIN_PATCHED = ('<html><head>'
                 '<meta name="ajs-version-number" content="9.2.28">'
                 '<meta name="ajs-build-number" content="9117">'
                 '</head><body>login</body></html>')

LOGIN_NO_VERSION = '<html><head></head><body>login</body></html>'

SOAP_EXPOSED = ('<html><body>AXIS service: confluenceservice-v2 '
                '(wsdl)</body></html>')


class MockServerTestCase(unittest.TestCase):
    def _serve(self, pages):
        server = HTTPServer(("127.0.0.1", 0), make_handler(pages))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        return "http://127.0.0.1:%d" % server.server_address[1]

    def test_url_vulnerable_api_on(self):
        base = self._serve({
            "/": (200, LOGIN_VULN),
            s.SOAP_PATH: (200, SOAP_EXPOSED),
        })
        result = s.probe_url(base)
        self.assertEqual(result["verdict"], "VULNERABLE")
        self.assertIn("exposed", result["remote_api"])
        self.assertEqual(len(result["warnings"]), 1)

    def test_url_vulnerable_api_off(self):
        base = self._serve({
            "/": (200, LOGIN_VULN),
            s.SOAP_PATH: (403, "HTTP Status 403 - Forbidden"),
        })
        result = s.probe_url(base)
        self.assertEqual(result["verdict"], "NOT-EXPOSED")
        self.assertIn("off", result["remote_api"])

    def test_url_patched_api_on(self):
        base = self._serve({
            "/": (200, LOGIN_PATCHED),
            s.SOAP_PATH: (200, SOAP_EXPOSED),
        })
        result = s.probe_url(base)
        self.assertEqual(result["verdict"], "PATCHED")
        self.assertEqual(len(result["warnings"]), 1)

    def test_url_no_version_exposed_endpoint_is_vulnerable(self):
        base = self._serve({
            "/": (200, LOGIN_NO_VERSION),
            "/login.action": (200, LOGIN_NO_VERSION),
            s.SOAP_PATH: (200, SOAP_EXPOSED),
        })
        result = s.probe_url(base)
        self.assertEqual(result["verdict"], "VULNERABLE")

    def test_url_version_on_login_page_only(self):
        base = self._serve({
            "/": (200, LOGIN_NO_VERSION),
            "/login.action": (200, LOGIN_VULN),
            s.SOAP_PATH: (403, "forbidden"),
        })
        result = s.probe_url(base)
        self.assertEqual(result["verdict"], "NOT-EXPOSED")
        self.assertEqual(result["version"], (9, 2, 27))

    def test_url_unreachable(self):
        with self.assertRaises(RuntimeError):
            s.probe_url("http://127.0.0.1:1/")

    def test_cloud_host(self):
        self.assertTrue(s.is_cloud_host("https://foo.atlassian.net/"))
        self.assertTrue(s.is_cloud_host("https://foo.jira.com/wiki"))
        self.assertFalse(s.is_cloud_host("https://wiki.example.com/"))


class TestLocal(unittest.TestCase):
    def _fake_install(self, version):
        root = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(root, True))
        lib = os.path.join(root, "confluence", "WEB-INF", "lib")
        os.makedirs(lib)
        open(os.path.join(lib, "confluence-%s.jar" % version), "w").close()
        return root

    def test_local_reads_jar(self):
        root = self._fake_install("9.2.27")
        version, build, source = s.find_local_version(
            install_dir=root, home_dir="/tmp/no-such-home")
        self.assertEqual(version, (9, 2, 27))
        self.assertIn("confluence-9.2.27.jar", source)

    def test_local_reads_install_dir_name(self):
        root = tempfile.mkdtemp(prefix="atlassian-confluence-9.2.28-")
        self.addCleanup(lambda: __import__("shutil").rmtree(root, True))
        version, _, _ = s.find_local_version(
            install_dir=root, home_dir="/tmp/no-such-home")
        self.assertEqual(version, (9, 2, 28))

    def test_local_reads_log_last_line(self):
        home = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(home, True))
        os.makedirs(os.path.join(home, "logs"))
        with open(os.path.join(home, "logs",
                               "atlassian-confluence.log"), "w") as fh:
            fh.write("2025-01-01 Starting Confluence 9.2.0\n")
            fh.write("2026-11-10 Starting Confluence 9.2.28\n")
        version, _, source = s.find_local_version(
            install_dir="/tmp/no-such-install", home_dir=home)
        self.assertEqual(version, (9, 2, 28))
        self.assertIn("log", source)

    def test_local_nothing_found(self):
        version, build, _ = s.find_local_version(
            install_dir="/tmp/no-such-install",
            home_dir="/tmp/no-such-home")
        self.assertIsNone(version)
        self.assertIsNone(build)


class TestCLI(unittest.TestCase):
    def test_list(self):
        self.assertEqual(s.main(["--list"]), 0)

    def test_version_patched_exit_0(self):
        self.assertEqual(s.main(["--version", "9.2.28"]), 0)

    def test_version_vulnerable_exit_1(self):
        self.assertEqual(s.main(["--version", "9.2.27"]), 1)

    def test_version_unknown_exit_2(self):
        self.assertEqual(s.main(["--version", "9.2"]), 2)

    def test_build_ambiguous_exit_2(self):
        self.assertEqual(s.main(["--build-number", "9117"]), 2)

    def test_build_vulnerable_exit_1(self):
        self.assertEqual(s.main(["--build-number", "9116"]), 1)

    def test_no_args_exit_3(self):
        self.assertEqual(s.main([]), 3)

    def test_no_remote_api_flag(self):
        self.assertEqual(
            s.main(["--version", "9.2.27", "--no-remote-api"]), 0)

    def test_json_output(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = s.main(["--version", "9.2.28", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["verdict"], "PATCHED")

    def test_inventory_json(self):
        entries = [
            {"host": "wiki-a", "version": "9.2.28"},
            {"host": "wiki-b", "version": "9.2.27"},
            {"host": "wiki-c", "version": "10.2.20"},
            {"host": "wiki-d", "version": "9.5.4", "remote_api_off": True},
            {"host": "wiki-e", "build": 9117},
        ]
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                        delete=False) as fh:
            json.dump(entries, fh)
            path = fh.name
        self.addCleanup(os.unlink, path)
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = s.main(["--inventory-json", path, "--json"])
        # Worst exit code wins, and UNKNOWN (2) outranks VULNERABLE (1)
        # under the same max() convention as the checkpoint scanner:
        # wiki-e (build 9117) is UNKNOWN, wiki-b is VULNERABLE.
        self.assertEqual(code, 2)
        data = json.loads(buf.getvalue())
        verdicts = {d["host"]: d["verdict"] for d in data}
        self.assertEqual(verdicts, {
            "wiki-a": "PATCHED",
            "wiki-b": "VULNERABLE",
            "wiki-c": "NOT-AFFECTED",
            "wiki-d": "NOT-EXPOSED",
            "wiki-e": "UNKNOWN",
        })

    def test_version_file_html(self):
        with tempfile.NamedTemporaryFile("w", suffix=".html",
                                        delete=False) as fh:
            fh.write(LOGIN_VULN)
            path = fh.name
        self.addCleanup(os.unlink, path)
        self.assertEqual(s.main(["--version-file", path]), 1)

    def test_version_file_missing_exit_3(self):
        self.assertEqual(s.main(["--version-file", "/tmp/no-such-file-xyz"]),
                         3)


if __name__ == "__main__":
    unittest.main()
