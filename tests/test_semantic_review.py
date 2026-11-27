import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from evidence.schema import Explanation
from evidence.semantic_review import annotation_template, make_review_packet, score_review
from evidence.verifier import verify

SHA = "a" * 40


class SemanticReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        raw = b"import pkg\npkg.run(value)\n"
        (self.root / "app.py").write_bytes(raw)
        self.payload = {
            "schema_version": 1,
            "task_id": "example-task",
            "cve_id": "CVE-2024-12345",
            "snapshot_sha": SHA,
            "category": "code_not_reachable",
            "reasoning": "The call exists; reachability needs expert assessment.",
            "citations": [
                {
                    "id": "c1",
                    "path": "app.py",
                    "start_line": 2,
                    "end_line": 2,
                    "quote": "pkg.run(value)",
                    "file_sha256": hashlib.sha256(raw).hexdigest(),
                }
            ],
            "claims": [
                {
                    "id": "claim1",
                    "statement": "The cited span has a pkg.run call",
                    "predicate": {"kind": "python_call", "target": "pkg.run"},
                    "citation_ids": ["c1"],
                }
            ],
        }
        self.report = verify(self.payload, self.root, SHA)
        self.packet = make_review_packet(Explanation.model_validate(self.payload), self.report)

    def filled_annotation(self):
        annotation = annotation_template(self.packet)
        annotation["reviewer_id"] = "reviewer-1"
        for item in annotation["judgments"]:
            item["rationale"] = "The available material does not settle this obligation."
        return annotation

    def test_packet_is_label_free_and_requires_reachability_review(self):
        self.assertNotIn("ground_truth", json.dumps(self.packet))
        self.assertEqual(self.packet["verifier_decision"], "needs_review")
        self.assertEqual(self.packet["claims"][0]["local_status"], "verified_local_predicate")
        self.assertEqual(
            {item["id"] for item in self.packet["obligations"]},
            {"advisory_scope", "affected_version", "affected_operation", "no_reachable_path"},
        )

    def test_false_positive_checks_mapping_without_requiring_an_affected_operation(self):
        payload = {**self.payload, "category": "false_positive"}
        report = verify(payload, self.root, SHA)
        packet = make_review_packet(Explanation.model_validate(payload), report)
        self.assertEqual(
            {item["id"] for item in packet["obligations"]},
            {"vulnerability_record", "mapping"},
        )

    def test_insufficient_review_is_human_judgment_not_automatic_verification(self):
        result = score_review(self.packet, self.filled_annotation())
        self.assertEqual(result["evidence_support"], "insufficient")
        self.assertTrue(result["annotation_validated"])
        self.assertFalse(result["automated_exploitability_verified"])

    def test_judgment_aggregation_uses_human_entries_only(self):
        annotation = self.filled_annotation()
        for item in annotation["judgments"]:
            item.update(verdict="supported", source_refs=["c1", "https://example.com/advisory"])
        result = score_review(self.packet, annotation)
        self.assertEqual(result["evidence_support"], "supported")
        self.assertFalse(result["automated_exploitability_verified"])
        annotation["judgments"][0]["verdict"] = "contradicted"
        self.assertEqual(score_review(self.packet, annotation)["evidence_support"], "contradicted")

    def test_packet_tampering_is_rejected(self):
        self.packet["reasoning"] = "Changed after review"
        with self.assertRaisesRegex(ValueError, "hash"):
            score_review(self.packet, self.filled_annotation())

    def test_missing_obligation_and_unknown_reference_are_rejected(self):
        annotation = self.filled_annotation()
        annotation["judgments"].pop()
        with self.assertRaisesRegex(ValueError, "exactly once"):
            score_review(self.packet, annotation)
        annotation = self.filled_annotation()
        annotation["judgments"][0].update(verdict="supported", source_refs=["missing-id"])
        with self.assertRaisesRegex(ValueError, "Unknown source reference"):
            score_review(self.packet, annotation)
        annotation = self.filled_annotation()
        annotation["judgments"][0]["verdict"] = "supported"
        with self.assertRaisesRegex(ValueError, "needs source references"):
            score_review(self.packet, annotation)

    def test_invalid_citation_cannot_enter_semantic_review(self):
        self.payload["citations"][0]["quote"] = "invented"
        report = verify(self.payload, self.root, SHA)
        with self.assertRaisesRegex(ValueError, "intact citations"):
            make_review_packet(Explanation.model_validate(self.payload), report)

    def test_cli_prepares_and_scores_review_packet(self):
        input_path = self.root / "explanation.json"
        input_path.write_text(json.dumps(self.payload))
        packet_path = self.root / "packet.json"
        prepared = subprocess.run(
            [
                sys.executable,
                "-c",
                "from cli import main; main()",
                "review",
                "prepare",
                "--repo",
                str(self.root),
                "--input",
                str(input_path),
                "--snapshot-sha",
                SHA,
                "--output",
                str(packet_path),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(prepared.returncode, 0, prepared.stderr)
        self.assertTrue(packet_path.is_file())
        template_path = self.root / "packet.annotation.template.json"
        self.assertTrue(template_path.is_file())
        annotation = json.loads(template_path.read_text())
        annotation["reviewer_id"] = "reviewer-1"
        for item in annotation["judgments"]:
            item["rationale"] = "Insufficient source evidence."
        annotation_path = self.root / "annotation.json"
        annotation_path.write_text(json.dumps(annotation))
        scored = subprocess.run(
            [
                sys.executable,
                "-c",
                "from cli import main; main()",
                "review",
                "score",
                "--packet",
                str(packet_path),
                "--annotation",
                str(annotation_path),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(scored.returncode, 0, scored.stderr)
        self.assertEqual(json.loads(scored.stdout)["evidence_support"], "insufficient")


if __name__ == "__main__":
    unittest.main()
