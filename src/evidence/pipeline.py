"""Connect an agent's final answer to the evidence verifier."""

import json
from pathlib import Path

from pydantic import ValidationError

from evidence.feedback import build_feedback
from evidence.schema import Explanation
from evidence.verifier import verify
from utils.repo import parse_owner_repo


def parse_explanation(text: str, task: dict) -> Explanation:
    """Require one complete structured answer for the given benchmark task."""
    answer = text.strip()
    if answer.startswith("```json\n") and answer.endswith("```"):
        answer = answer[len("```json\n") : -3].strip()
    elif answer.startswith("```\n") and answer.endswith("```"):
        answer = answer[len("```\n") : -3].strip()
    payload = json.loads(answer)
    explanation = Explanation.model_validate(payload)
    for field, expected in (
        ("task_id", task["task_id"]),
        ("cve_id", task["cve_id"]),
        ("snapshot_sha", task["commit_sha"]),
    ):
        if getattr(explanation, field) != expected:
            raise ValueError(f"{field} does not match the benchmark task")
    return explanation


def verify_agent_answer(text: str, task: dict, repos_dir: Path) -> dict:
    """Return a report even when the answer or local source is unavailable."""
    try:
        explanation = parse_explanation(text, task)
    except (ValueError, ValidationError) as exc:
        report = {"decision": "invalid_input", "error": str(exc)}
        report["feedback"] = build_feedback(report)
        return report

    owner, repo = parse_owner_repo(task["repo_url"])
    source = repos_dir / owner / repo / task["commit_sha"]
    if not source.is_dir():
        report = {"decision": "source_unavailable", "error": f"Source dir not found: {source}"}
        report["feedback"] = build_feedback(report)
        return report
    try:
        return verify(explanation.model_dump(), source, task["commit_sha"])
    except (ValueError, OSError) as exc:
        report = {"decision": "source_unavailable", "error": str(exc)}
        report["feedback"] = build_feedback(report)
        return report
