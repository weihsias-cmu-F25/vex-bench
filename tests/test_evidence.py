import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from pydantic import ValidationError

from evaluate.result_parser import parse_category, to_binary
from evidence.verifier import verify

SHA = "a" * 40
SOURCE = "from pkg import parser\n# parser.run(user_input)\nparser.run(user_input)\n"


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "app.py").write_text(SOURCE)
        self.payload = {
            "schema_version": 1,
            "task_id": "demo",
            "cve_id": "CVE-2024-12345",
            "snapshot_sha": SHA,
            "category": "uncertain",
            "reasoning": "Review needed",
            "citations": [
                {
                    "id": "c1",
                    "path": "app.py",
                    "start_line": 3,
                    "end_line": 3,
                    "quote": "parser.run(user_input)",
                    "file_sha256": hashlib.sha256(SOURCE.encode()).hexdigest(),
                }
            ],
            "claims": [
                {
                    "id": "fact1",
                    "statement": "A parser.run call expression occurs here",
                    "predicate": {"kind": "python_call", "target": "parser.run"},
                    "citation_ids": ["c1"],
                }
            ],
        }

    def check_payload(self):
        return verify(self.payload, self.root, SHA)

    def test_real_call_is_local_fact_only(self):
        result = self.check_payload()
        self.assertEqual(result["claims"][0]["status"], "verified_local_predicate")
        self.assertEqual(result["decision"], "needs_review")
        self.assertFalse(result["exploitability_verified"])

    def test_quote_tampering(self):
        self.payload["citations"][0]["quote"] = "safe_parser.run(user_input)"
        self.assertEqual(self.check_payload()["decision"], "unsupported")

    def test_stale_file_hash(self):
        (self.root / "app.py").write_text(SOURCE + "# changed\n")
        self.assertIn("file_hash_mismatch", self.check_payload()["citations"][0]["errors"])

    def test_wrong_line_range(self):
        self.payload["citations"][0]["end_line"] = 100
        self.assertEqual(self.check_payload()["decision"], "unsupported")

    def test_missing_file(self):
        self.payload["citations"][0]["path"] = "missing.py"
        self.assertEqual(self.check_payload()["decision"], "unsupported")

    def test_parent_traversal(self):
        self.payload["citations"][0]["path"] = "../outside.py"
        self.assertEqual(self.check_payload()["decision"], "unsupported")

    def test_absolute_path(self):
        self.payload["citations"][0]["path"] = str(self.root / "app.py")
        self.assertEqual(self.check_payload()["decision"], "unsupported")

    def test_symlink_escape(self):
        with tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / "outside.py"
            target.write_text(SOURCE)
            (self.root / "link.py").symlink_to(target)
            self.payload["citations"][0]["path"] = "link.py"
            self.assertEqual(self.check_payload()["decision"], "unsupported")

    def test_comments_are_not_calls(self):
        self.payload["citations"][0].update(
            start_line=2, end_line=2, quote="# parser.run(user_input)"
        )
        self.assertEqual(self.check_payload()["claims"][0]["status"], "unsupported")

    def test_call_elsewhere_does_not_support_citation(self):
        self.payload["citations"][0].update(
            start_line=1, end_line=1, quote="from pkg import parser"
        )
        self.assertEqual(self.check_payload()["claims"][0]["status"], "unsupported")

    def test_import_predicate(self):
        self.payload["citations"][0].update(
            start_line=1, end_line=1, quote="from pkg import parser"
        )
        self.payload["claims"][0]["predicate"] = {"kind": "python_import", "target": "pkg.parser"}
        self.assertEqual(self.check_payload()["claims"][0]["status"], "verified_local_predicate")

    def test_false_local_predicate(self):
        self.payload["claims"][0]["predicate"]["target"] = "missing.call"
        self.assertEqual(self.check_payload()["decision"], "unsupported")

    def test_semantic_overclaim_abstains_even_with_real_quote(self):
        self.payload["category"] = "code_not_reachable"
        self.payload["claims"][0]["predicate"] = {"kind": "semantic", "target": "Unreachable"}
        self.assertEqual(self.check_payload()["claims"][0]["status"], "requires_review")

    def test_valid_predicate_does_not_validate_misleading_statement(self):
        self.payload["claims"][0]["statement"] = "This application is definitely safe"
        result = self.check_payload()
        self.assertEqual(result["claims"][0]["statement_entailment"], "not_checked")
        self.assertFalse(result["exploitability_verified"])

    def test_labels_are_rejected(self):
        self.payload["ground_truth"] = "not_exploitable"
        with self.assertRaises(ValidationError):
            self.check_payload()

    def test_nested_labels_are_rejected(self):
        self.payload["claims"][0]["ground_truth"] = "safe"
        with self.assertRaises(ValidationError):
            self.check_payload()

    def test_unknown_category(self):
        self.payload["category"] = "safe"
        with self.assertRaises(ValidationError):
            self.check_payload()

    def test_unknown_citation_reference(self):
        self.payload["claims"][0]["citation_ids"] = ["missing"]
        with self.assertRaises(ValidationError):
            self.check_payload()

    def test_duplicate_ids(self):
        self.payload["citations"].append(copy.deepcopy(self.payload["citations"][0]))
        with self.assertRaises(ValidationError):
            self.check_payload()

    def test_empty_evidence(self):
        self.payload["citations"] = []
        with self.assertRaises(ValidationError):
            self.check_payload()

    def test_line_zero(self):
        self.payload["citations"][0]["start_line"] = 0
        with self.assertRaises(ValidationError):
            self.check_payload()

    def test_boolean_line_number(self):
        self.payload["citations"][0]["start_line"] = True
        with self.assertRaises(ValidationError):
            self.check_payload()

    def test_wrong_snapshot(self):
        self.payload["snapshot_sha"] = "b" * 40
        self.assertEqual(self.check_payload()["decision"], "unsupported")

    def test_non_utf8_file(self):
        (self.root / "app.py").write_bytes(b"\xff\xfe")
        self.assertEqual(self.check_payload()["decision"], "unsupported")

    def test_crlf_quote_normalization_and_raw_hash(self):
        raw = SOURCE.replace("\n", "\r\n").encode()
        (self.root / "app.py").write_bytes(raw)
        self.payload["citations"][0]["file_sha256"] = hashlib.sha256(raw).hexdigest()
        self.assertTrue(self.check_payload()["citation_integrity"])

    def test_upstream_parser_remains_compatible(self):
        self.assertEqual(parse_category(json.dumps(self.payload))[0], "uncertain")
        self.assertIsNone(to_binary("uncertain"))
        self.assertIsNone(to_binary("requires_dependency"))
        self.assertEqual(self.check_payload()["decision"], "needs_review")

    def test_cli_reports_failure_with_exit_one(self):
        self.payload["citations"][0]["quote"] = "fabricated"
        input_path = self.root / "input.json"
        input_path.write_text(json.dumps(self.payload))
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "from cli import main; main()",
                "verify",
                "--repo",
                str(self.root),
                "--input",
                str(input_path),
                "--snapshot-sha",
                SHA,
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout)["decision"], "unsupported")


if __name__ == "__main__":
    unittest.main()
