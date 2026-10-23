"""Deterministic, authored demonstrations against real pinned source snapshots.

These are controlled evidence mutations, not model outputs or classification
accuracy measurements. Ground-truth files are not read by this script.
"""

import copy
import hashlib
import json
from collections import Counter
from pathlib import Path

from evidence.verifier import verify

ROOT = Path(__file__).resolve().parents[1]
RECIPES = [
    {
        "name": "FastAPI",
        "owner": "fastapi",
        "repo": "fastapi",
        "sha": "febf6b6a52e36e0d64920fb54670ad7fc29b2eaa",
        "cve": "CVE-2024-47874",
        "path": "fastapi/routing.py",
        "needle": "body = await request.form()",
        "kind": "python_call",
        "target": "request.form",
        "fact": "The cited span contains a request.form call expression",
        "question": "Does attacker input reach an affected Starlette multipart parser?",
    },
    {
        "name": "RAGFlow",
        "owner": "infiniflow",
        "repo": "ragflow",
        "sha": "c68767acdde0bbe521fad7f202f01130d7aa4ce3",
        "cve": "CVE-2024-36039",
        "path": "api/db/db_models.py",
        "needle": "from playhouse.pool import PooledMySQLDatabase",
        "kind": "python_import",
        "target": "playhouse.pool.PooledMySQLDatabase",
        "fact": "The cited span imports the pooled MySQL database class",
        "question": "Can attacker-controlled dictionary keys reach PyMySQL's vulnerable API?",
    },
    {
        "name": "Minikube",
        "owner": "kubernetes",
        "repo": "minikube",
        "sha": "e7bf515c48f32d7ef63c81fcdba92cccef619016",
        "cve": "CVE-2019-5736",
        "path": "go.mod",
        "needle": "github.com/opencontainers/runc v1.1.14",
        "kind": "text_contains",
        "target": "github.com/opencontainers/runc v1.1.14",
        "fact": "The cited manifest line declares runc v1.1.14",
        "question": "Which runc binary actually runs in each supported deployment?",
    },
]


def main():
    out = ROOT / "results/evidence_demo"
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for recipe in RECIPES:
        repo = ROOT / "benchmark/repos" / recipe["owner"] / recipe["repo"] / recipe["sha"]
        source_path = repo / recipe["path"]
        raw = source_path.read_bytes()
        lines = raw.decode().splitlines()
        matches = [i for i, line in enumerate(lines, 1) if recipe["needle"] in line]
        if len(matches) != 1:
            raise ValueError(f"Expected one source anchor in {source_path}, got {matches}")
        line = matches[0]
        task_id = f"{recipe['owner']}-{recipe['repo']}-{recipe['sha'][:7]}-{recipe['cve']}"
        payload = {
            "schema_version": 1,
            "task_id": task_id,
            "cve_id": recipe["cve"],
            "snapshot_sha": recipe["sha"],
            "category": "uncertain",
            "reasoning": "Authored evidence demonstration. " + recipe["question"],
            "citations": [
                {
                    "id": "source1",
                    "path": recipe["path"],
                    "start_line": line,
                    "end_line": line,
                    "quote": lines[line - 1],
                    "file_sha256": hashlib.sha256(raw).hexdigest(),
                }
            ],
            "claims": [
                {
                    "id": "fact1",
                    "statement": recipe["fact"],
                    "citation_ids": ["source1"],
                    "predicate": {"kind": recipe["kind"], "target": recipe["target"]},
                }
            ],
        }
        variants = {"valid_local_fact": copy.deepcopy(payload)}
        variants["fabricated_quote"] = copy.deepcopy(payload)
        variants["fabricated_quote"]["citations"][0]["quote"] += " # fabricated"
        variants["missing_file"] = copy.deepcopy(payload)
        variants["missing_file"]["citations"][0]["path"] = "missing/fabricated.file"
        variants["unsupported_local_predicate"] = copy.deepcopy(payload)
        variants["unsupported_local_predicate"]["claims"][0]["predicate"]["target"] = (
            "invented.safe_api"
        )
        variants["semantic_overclaim"] = copy.deepcopy(payload)
        variants["semantic_overclaim"]["category"] = "code_not_reachable"
        variants["semantic_overclaim"]["claims"][0].update(
            statement="This entire application cannot be exploited",
            predicate={"kind": "semantic", "target": "Repository-wide unreachability"},
        )
        for variant, item in variants.items():
            report = verify(item, repo, recipe["sha"])
            expected = (
                "unsupported"
                if variant in {"fabricated_quote", "missing_file", "unsupported_local_predicate"}
                else "needs_review"
            )
            if report["decision"] != expected:
                raise AssertionError((recipe["name"], variant, report))
            stem = f"{recipe['name'].lower()}-{variant}"
            (out / f"{stem}.input.json").write_text(json.dumps(item, indent=2) + "\n")
            (out / f"{stem}.report.json").write_text(json.dumps(report, indent=2) + "\n")
            rows.append(
                {
                    "project": recipe["name"],
                    "task_id": task_id,
                    "variant": variant,
                    "decision": report["decision"],
                    "expected_for_demo": expected,
                    "citation": f"{recipe['path']}:{line}",
                    "source_url": f"https://github.com/{recipe['owner']}/{recipe['repo']}/blob/"
                    f"{recipe['sha']}/{recipe['path']}#L{line}",
                }
            )
    summary = {
        "experiment_type": "authored_evidence_mutations_on_real_pinned_source",
        "model_calls": 0,
        "baseline_run": False,
        "ground_truth_used_by_verifier": False,
        "cases": 3,
        "examples": len(rows),
        "decisions": dict(Counter(row["decision"] for row in rows)),
        "rows": rows,
        "warning": "These counts are not exploitability accuracy or F1",
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "rows"}, indent=2))
    for row in rows:
        print(f"{row['project']:9} {row['variant']:28} {row['decision']}")


if __name__ == "__main__":
    main()
