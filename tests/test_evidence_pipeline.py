import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from evaluate.agents.base import AgentResult
from evaluate.agents.opencode import OpenCodeAgent
from evaluate.common import BENCHMARKS, ExperimentConfig
from evaluate.metrics import compute_metrics, metrics
from evaluate.parse import _parse_run, parse
from evaluate.run import _run_one
from evidence.pipeline import parse_explanation, verify_agent_answer

SHA = "a" * 40


class EvidencePipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.task = {
            "task_id": "example-repo-aaaaaaa-CVE-2024-12345",
            "repo_url": "https://github.com/example/repo",
            "commit_sha": SHA,
            "cve_id": "CVE-2024-12345",
            "ground_truth": "not_exploitable",
            "ground_truth_category": "code_not_reachable",
            "metadata": {"language": "python"},
        }
        self.config = ExperimentConfig(
            model="kimi-k2.6",
            agent="opencode",
            benchmark="milestone_demo",
            prompt="evidence_v1",
            repos_dir=self.root / "repos",
            output_dir=self.root / "results",
        )
        self.source = self.config.repos_dir / "example" / "repo" / SHA
        self.source.mkdir(parents=True)
        raw = b"import pkg\npkg.run(value)\n"
        (self.source / "app.py").write_bytes(raw)
        self.payload = {
            "schema_version": 1,
            "task_id": self.task["task_id"],
            "cve_id": self.task["cve_id"],
            "snapshot_sha": SHA,
            "category": "code_not_reachable",
            "reasoning": "A call is visible; reachability needs review.",
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
                    "statement": "The cited span contains a pkg.run call",
                    "predicate": {"kind": "python_call", "target": "pkg.run"},
                    "citation_ids": ["c1"],
                }
            ],
        }
        self.agent = OpenCodeAgent("kimi-k2.6")

    def export(self, answer):
        return json.dumps(
            {
                "messages": [
                    {
                        "info": {"role": "assistant"},
                        "parts": [
                            {"type": "text", "text": answer},
                            {"type": "step-finish", "tokens": {"input": 30, "output": 20}},
                        ],
                    }
                ]
            }
        )

    def result_path(self):
        path = self.config.run_dir / self.task["task_id"] / "run_001" / "result.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def test_opencode_export_is_verified_and_scored_separately(self):
        self.result_path().write_text(self.export(json.dumps(self.payload)))
        row = _parse_run(self.agent, self.task, self.config, 1)
        self.assertEqual(row["predicted"], "not_exploitable")
        self.assertEqual(row["evidence_decision"], "needs_review")
        self.assertEqual(row["evidence_citations_valid"], 1)
        report = json.loads(Path(row["evidence_report"]).read_text())
        self.assertEqual(report["claims"][0]["status"], "verified_local_predicate")
        self.assertFalse(report["feedback"]["revision_requested"])
        self.assertTrue(report["feedback"]["human_review_required"])
        self.assertIn("entry point", report["feedback"]["review_questions"][0])
        scores = compute_metrics([row])
        self.assertEqual(scores["evidence"]["decision_counts"], {"needs_review": 1})
        self.assertEqual(scores["evidence"]["citation_validity"]["rate"], 1.0)

    def test_parse_and_metrics_write_end_to_end_artifacts(self):
        self.result_path().write_text(self.export(json.dumps(self.payload)))
        task_file = self.root / "tasks.jsonl"
        task_file.write_text(json.dumps(self.task) + "\n")
        with patch.dict(BENCHMARKS, {"milestone_demo": task_file}):
            parse(self.config)
            metrics(self.config)
        parsed = json.loads((self.config.benchmark_dir / "parsed.jsonl").read_text())
        scores = json.loads((self.config.benchmark_dir / "metrics.json").read_text())
        self.assertEqual(parsed["evidence_decision"], "needs_review")
        self.assertEqual(scores["evidence"]["decision_counts"], {"needs_review": 1})
        self.assertEqual(scores["binary"]["accuracy"]["mean"], 1.0)

    def test_fabricated_quote_is_reported_without_changing_raw_prediction(self):
        self.payload["citations"][0]["quote"] = "fabricated"
        self.result_path().write_text(self.export(json.dumps(self.payload)))
        row = _parse_run(self.agent, self.task, self.config, 1)
        self.assertEqual(row["predicted_category"], "code_not_reachable")
        self.assertEqual(row["evidence_decision"], "unsupported")
        self.assertEqual(row["evidence_citations_valid"], 0)
        report = json.loads(Path(row["evidence_report"]).read_text())
        self.assertTrue(report["feedback"]["revision_requested"])
        self.assertIn(
            "invalid_citation", {repair["code"] for repair in report["feedback"]["repairs"]}
        )

    def test_category_only_answer_is_invalid_evidence(self):
        self.result_path().write_text(
            self.export('{"category":"code_not_reachable","reasoning":"unsupported"}')
        )
        row = _parse_run(self.agent, self.task, self.config, 1)
        self.assertEqual(row["predicted_category"], "code_not_reachable")
        self.assertEqual(row["evidence_decision"], "invalid_input")
        report = json.loads(Path(row["evidence_report"]).read_text())
        self.assertTrue(report["feedback"]["revision_requested"])

    def test_task_identity_mismatch_is_rejected(self):
        self.payload["task_id"] = "another-task"
        report = verify_agent_answer(json.dumps(self.payload), self.task, self.config.repos_dir)
        self.assertEqual(report["decision"], "invalid_input")
        self.assertIn("task_id", report["error"])

    def test_source_unavailable_is_distinct_from_bad_evidence(self):
        (self.source / "app.py").unlink()
        self.source.rmdir()
        report = verify_agent_answer(json.dumps(self.payload), self.task, self.config.repos_dir)
        self.assertEqual(report["decision"], "source_unavailable")
        self.assertFalse(report["feedback"]["revision_requested"])
        self.assertEqual(report["feedback"]["repairs"][0]["code"], "source_unavailable")

    def test_semantic_overclaim_remains_for_human_review(self):
        self.payload["claims"][0]["statement"] = "The entire application is safe"
        self.payload["claims"][0]["predicate"] = {
            "kind": "semantic",
            "target": "Repository-wide unreachability",
        }
        report = verify_agent_answer(json.dumps(self.payload), self.task, self.config.repos_dir)
        self.assertEqual(report["decision"], "needs_review")
        self.assertTrue(report["feedback"]["human_review_required"])
        self.assertFalse(report["feedback"]["revision_requested"])
        self.assertEqual(report["feedback"]["review_claim_ids"], ["claim1"])

    def test_absent_local_predicate_produces_claim_repair(self):
        self.payload["claims"][0]["predicate"]["target"] = "pkg.missing"
        report = verify_agent_answer(json.dumps(self.payload), self.task, self.config.repos_dir)
        self.assertEqual(report["decision"], "unsupported")
        self.assertEqual(report["feedback"]["repairs"][0]["code"], "unsupported_claim")
        self.assertEqual(report["feedback"]["repairs"][0]["claim_id"], "claim1")

    def test_valid_structured_answer_is_required_for_cache(self):
        self.result_path().write_text(
            self.export('{"category":"code_not_reachable","reasoning":"old"}')
        )
        replacement = self.export(json.dumps(self.payload))
        self.agent.run = Mock(return_value=AgentResult(raw_output=replacement))
        _run_one(self.task, 1, config=self.config, agent=self.agent)
        self.agent.run.assert_called_once()
        cached = self.agent.load_result(self.result_path().parent)
        self.assertEqual(parse_explanation(cached.text, self.task).task_id, self.task["task_id"])
        _run_one(self.task, 1, config=self.config, agent=self.agent)
        self.agent.run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
