"""Try one live repair of a saved model answer that failed evidence verification.

The saved answer can come from a different prompt. This is an engineering
demonstration of the feedback loop, not a controlled baseline comparison.
"""

import argparse
import hashlib
import json
from pathlib import Path

from evaluate.common import ExperimentConfig, load_tasks, make_agent
from evaluate.feedback_run import run_with_feedback
from evidence.pipeline import verify_agent_answer
from utils.repo import parse_owner_repo


def run_seeded_repair(config: ExperimentConfig, task_id: str, seed_result: Path) -> dict:
    task = next((item for item in load_tasks(config) if item["task_id"] == task_id), None)
    if task is None:
        raise ValueError(f"Unknown task ID: {task_id}")
    agent = make_agent(config)
    raw = seed_result.read_bytes()
    answer = agent.extract_text(raw.decode("utf-8"))
    initial = verify_agent_answer(answer, task, config.repos_dir)
    if not initial["feedback"]["revision_requested"]:
        raise ValueError("Saved answer does not trigger verifier feedback")

    owner, repo = parse_owner_repo(task["repo_url"])
    source = config.repos_dir / owner / repo / task["commit_sha"]
    if not source.is_dir():
        raise ValueError(f"Missing source snapshot: {source}")
    prompt = (
        config.prompt_text.replace("{cve_id}", task["cve_id"])
        .replace("{task_id}", task_id)
        .replace("{snapshot_sha}", task["commit_sha"])
    )
    target = config.run_dir / task_id / "run_001"
    attempt = target / "attempt_000"
    seed_hash = hashlib.sha256(raw).hexdigest()
    manifest_path = target / "seed_manifest.json"
    manifest = {
        "schema_version": 1,
        "seed_raw_sha256": seed_hash,
        "seed_origin": str(seed_result),
        "initial_decision": initial["decision"],
        "initial_prompt_matches_repair_prompt": False,
        "experiment_type": "seeded_repair_demonstration_not_controlled_comparison",
    }
    if manifest_path.exists():
        if json.loads(manifest_path.read_text(encoding="utf-8")) != manifest:
            raise ValueError(f"Seed manifest differs from existing run: {manifest_path}")
    else:
        if target.exists():
            raise ValueError(f"Destination already exists: {target}")
        attempt.mkdir(parents=True)
        (attempt / agent.result_filename()).write_bytes(raw)
        (attempt / "prompt.txt").write_text(prompt, encoding="utf-8")
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    run_with_feedback(
        agent,
        task,
        prompt,
        source,
        config.repos_dir,
        target,
        config.timeout,
        f"[{task_id}/run_001]",
    )
    summary_path = target / "feedback_summary.json"
    if not summary_path.exists():
        raise RuntimeError(f"Repair attempt did not complete: {target / 'error.txt'}")
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    return {"seed_sha256": seed_hash, "run_dir": str(target), **summary}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--seed-result", type=Path, required=True)
    parser.add_argument("--model", default="gpt-6.2-sol")
    parser.add_argument("--output-dir", type=Path, default=Path("results/seeded_repair"))
    parser.add_argument("--repos-dir", type=Path, default=Path("benchmark/repos"))
    parser.add_argument("--timeout", type=int, default=240)
    args = parser.parse_args()
    config = ExperimentConfig(
        agent="opencode_host",
        model=args.model,
        benchmark="milestone_demo",
        prompt="evidence_v1",
        feedback_rounds=1,
        output_dir=args.output_dir,
        repos_dir=args.repos_dir,
        timeout=args.timeout,
    )
    print(json.dumps(run_seeded_repair(config, args.task_id, args.seed_result), indent=2))


if __name__ == "__main__":
    main()
