import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("redirect_audit_tool", ROOT / "tool.py")
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

class AuditTests(unittest.TestCase):
    def run_audit(self, start="https://example.com/start", responses=None, **extra):
        return tool.audit({"start_url": start, "responses": responses if responses is not None else [{"status": 200}], **extra})
    def codes(self, result):
        return [item["code"] for item in result["findings"]]
    def test_terminal(self):
        r = self.run_audit()
        self.assertEqual(r["status"], "pass")
        self.assertTrue(r["complete"])
        self.assertEqual(r["redirect_count"], 0)
    def test_relative_chain(self):
        r = self.run_audit(responses=[{"status": 302, "location": "next"}, {"status": 200}])
        self.assertEqual(r["status"], "pass")
        self.assertTrue(r["trace"][0]["location_is_relative"])
    def test_all_supported_redirect_codes(self):
        for status in [301, 302, 303, 307, 308]:
            self.assertEqual(self.run_audit(responses=[{"status": status, "location": "/next"}, {"status": 200}])["status"], "pass")
    def test_cross_origin_and_downgrade(self):
        r = self.run_audit(responses=[{"status": 301, "location": "http://other.example"}, {"status": 200}])
        self.assertEqual(self.codes(r), ["cross_origin_redirect", "https_downgrade"])
        self.assertTrue(r["complete"])
    def test_default_port_and_case_equivalence(self):
        r = self.run_audit(responses=[{"status": 302, "location": "https://EXAMPLE.COM:443/next"}, {"status": 200}])
        self.assertEqual(r["status"], "pass")
    def test_nondefault_port_cross_origin(self):
        r = self.run_audit(responses=[{"status": 302, "location": "https://example.com:8443/next"}, {"status": 200}])
        self.assertIn("cross_origin_redirect", self.codes(r))
    def test_ipv6_compression_loop(self):
        r = self.run_audit("https://[2001:0db8::1]/", [{"status": 302, "location": "https://[2001:db8::1]:443/"}])
        self.assertIn("redirect_loop", self.codes(r))
    def test_direct_loop(self):
        r = self.run_audit(responses=[{"status": 302, "location": "/start"}])
        self.assertEqual(r["stopped_reason"], "redirect_loop")
    def test_multi_hop_loop(self):
        r = self.run_audit(responses=[{"status": 302, "location": "/next"}, {"status": 301, "location": "/start"}])
        self.assertEqual(r["redirect_count"], 2)
        self.assertEqual(r["findings"][-1]["first_request_index"], 0)
    def test_fragment_only_loop(self):
        r = self.run_audit(responses=[{"status": 302, "location": "#new"}])
        self.assertIn("redirect_loop", self.codes(r))
    def test_empty_location_is_reference(self):
        self.assertIn("redirect_loop", self.codes(self.run_audit(responses=[{"status": 302, "location": ""}])))
    def test_empty_query_is_not_inherited(self):
        r = self.run_audit("https://example.com/start?secret", [{"status": 302, "location": "?"}, {"status": 200}])
        self.assertEqual(r["status"], "pass")
        self.assertTrue(r["trace"][0]["target_query_present"])
        target, _ = tool.resolve("https://example.com/start?secret", "?")
        self.assertEqual(target, "https://example.com/start?")
    def test_query_changed_not_loop(self):
        self.assertEqual(self.run_audit(responses=[{"status": 302, "location": "?q=2"}, {"status": 200}])["status"], "pass")
    def test_fragment_inheritance(self):
        target, inherited = tool.resolve("https://example.com/start#private", "/next")
        self.assertEqual(target, "https://example.com/next#private")
        self.assertTrue(inherited)
        target, inherited = tool.resolve("https://example.com/start#private", "/next#")
        self.assertEqual(target, "https://example.com/next#")
        self.assertFalse(inherited)
    def test_rfc3986_resolution_examples(self):
        base = "http://a/b/c/d;p?q"
        examples = {"g": "http://a/b/c/g", "./g": "http://a/b/c/g", "g/": "http://a/b/c/g/",
                    "/g": "http://a/g", "//g": "http://g", "?y": "http://a/b/c/d;p?y",
                    "g?y": "http://a/b/c/g?y", "#s": "http://a/b/c/d;p?q#s",
                    "": "http://a/b/c/d;p?q", ".": "http://a/b/c/", "..": "http://a/b/",
                    "../g": "http://a/b/g", "../../g": "http://a/g", "../../../g": "http://a/g",
                    "/./g": "http://a/g", "/../g": "http://a/g", "g/./h": "http://a/b/c/g/h",
                    "g/../h": "http://a/b/c/h", "g?y/./x": "http://a/b/c/g?y/./x"}
        for ref, expected in examples.items():
            with self.subTest(ref=ref):
                self.assertEqual(tool.resolve(base, ref)[0], expected)
    def test_repeated_slashes_preserved(self):
        self.assertEqual(tool.resolve("https://example.com/a/", "b//c")[0], "https://example.com/a/b//c")
    def test_dot_segment_absolute_target(self):
        self.assertEqual(tool.resolve("https://example.com/", "https://other.example/a/../b")[0], "https://other.example/b")
        self.assertEqual(tool.remove_dot_segments("a/../b"), "/b")
    def test_budget_zero_and_exact(self):
        self.assertEqual(self.run_audit(max_redirects=0)["status"], "pass")
        r = self.run_audit(responses=[{"status": 302, "location": "/next"}, {"status": 200}], max_redirects=0)
        self.assertEqual(r["stopped_reason"], "redirect_budget_exceeded")
        self.assertEqual(r["consumed_response_count"], 1)
        self.assertEqual(self.run_audit(responses=[{"status": 302, "location": "/next"}, {"status": 200}], max_redirects=1)["status"], "pass")
    def test_missing_location(self):
        self.assertIn("missing_location", self.codes(self.run_audit(responses=[{"status": 302}])))
    def test_incomplete_trace(self):
        r = self.run_audit(responses=[{"status": 302, "location": "/next"}])
        self.assertIn("incomplete_trace", self.codes(r))
        self.assertFalse(r["complete"])
    def test_responses_after_terminal(self):
        r = self.run_audit(responses=[{"status": 200}, {"status": 302, "location": "/next"}])
        self.assertIn("responses_after_terminal", self.codes(r))
    def test_non_redirect_location(self):
        r = self.run_audit(responses=[{"status": 201, "location": "/created"}])
        self.assertEqual(r["status"], "pass")
        self.assertTrue(r["trace"][0]["location_not_followed"])
    def test_300_305_306(self):
        for status in (300, 305, 306):
            self.assertIn("unmodeled_redirect_status", self.codes(self.run_audit(responses=[{"status": status}])))
    def test_invalid_start(self):
        for start in ["/relative", "ftp://example.com", "https://[broken", "https://127.1", "https://example.com\\@other.example"]:
            r = self.run_audit(start)
            self.assertEqual(r["stopped_reason"], "invalid_start_url")
            self.assertFalse(r["complete"])
    def test_invalid_target(self):
        for location in ["https:relative", "javascript:alert(1)", "///path", "//?q", "https://[broken", " /next", "/a\nb", "\\next", "https://127.1"]:
            with self.subTest(location=location):
                r = self.run_audit(responses=[{"status": 302, "location": location}])
                self.assertEqual(r["stopped_reason"], "invalid_redirect_target")
    def test_redaction(self):
        r = self.run_audit("https://secret-user:secret-pass@example.com/secret-path?secret-query#secret-fragment",
                           [{"status": 302, "location": "https://other.example/new?second-secret"}, {"status": 200}])
        output = json.dumps(r)
        self.assertNotIn("secret", output)
        self.assertIn("userinfo_present", self.codes(r))
    def test_resolved_length_limit(self):
        start = "https://example.com/" + "a" * 8170
        r = self.run_audit(start, [{"status": 302, "location": "?" + "q" * 100}])
        self.assertIn("resolved_url_size_limit", self.codes(r))
    def test_schema_errors(self):
        base = {"start_url": "https://example.com", "responses": [{"status": 200}]}
        for change in [{"responses": []}, {"responses": [{"status": True}]}, {"responses": [{"status": 199}]},
                       {"responses": [{"status": 600}]}, {"responses": [{"status": 302, "location": None}]},
                       {"responses": [{"status": 200, "extra": 1}]}, {"max_redirects": -1},
                       {"max_redirects": 257}, {"max_redirects": True}, {"start_url": 1},
                       {"start_url": "a" * 8193}, {"responses": [{"status": 200}] * 257}]:
            self.assertEqual(tool.audit(dict(base, **change))["status"], "error")
    def test_max_responses(self):
        responses = [{"status": 302, "location": "/p" + str(i)} for i in range(255)] + [{"status": 200}]
        r = self.run_audit(responses=responses, max_redirects=255)
        self.assertEqual(r["status"], "pass")
        self.assertEqual(r["consumed_response_count"], 256)
    def test_stable(self):
        self.assertEqual(self.run_audit(), self.run_audit())
    def cli(self, raw, *args):
        return subprocess.run([sys.executable, str(ROOT / "tool.py"), *args], input=raw, text=True, capture_output=True)
    def test_cli_examples_and_exits(self):
        for name, code in [("good", 0), ("bad", 1)]:
            r = self.cli("", "--input", str(ROOT / "examples" / (name + ".json")))
            self.assertEqual(r.returncode, code, r.stderr)
            json.loads(r.stdout)
        self.assertEqual(self.cli("{}").returncode, 2)
    def test_cli_error_privacy(self):
        r = self.cli("", "--bad", "secret-query")
        self.assertEqual(r.returncode, 2)
        self.assertNotIn("secret-query", r.stdout + r.stderr)
        for raw in ['{"start_url":1,"start_url":2}', '{"start_url":NaN}', '{', ' ' * (tool.MAX_BYTES + 1)]:
            self.assertEqual(self.cli(raw).returncode, 2)

    def test_cli_exact_byte_boundary(self):
        valid = '{"start_url":"https://example.com","responses":[{"status":200}]}'
        self.assertEqual(self.cli(valid + " " * (tool.MAX_BYTES - len(valid))).returncode, 0)
    def test_cli_invalid_utf8_and_deep_json(self):
        result = subprocess.run([sys.executable, str(ROOT / "tool.py")], input=b"\xff", capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(b"Traceback", result.stderr)
        self.assertEqual(self.cli("[" * 1500 + "]" * 1500).returncode, 2)
    def test_nonregular_input_file(self):
        result = self.cli("", "--input", str(ROOT))
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(str(ROOT), result.stdout + result.stderr)

if __name__ == "__main__":
    unittest.main()
