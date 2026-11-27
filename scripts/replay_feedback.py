"""Replay valid baseline outputs through feedback policy without model calls.

Only cases whose existing verifier report is ``needs_review`` may be replayed.
This is a paired policy evaluation, not an independent agent run.
"""

import argparse
import json
from pathlib import Path
from unittest.mock import patch

from evaluate.common import ExperimentConfig, load_tasks, make_agent
from evaluate.feedback_run import run_with_feedback
from evidence.pipeline import verify_agent_answer
from utils.repo import parse_owner_repo


def replay(config: ExperimentConfig) -> int:
    if config.prompt != "evidence_v1" or config.feedback_rounds:
        raise ValueError("Replay requires evidence_v1 and feedback_rounds=0")
    feedback = config.model_copy(update={"feedback_rounds": 1})
    agent = make_agent(config)
    prepared = []
    for task in load_tasks(config):
        for rep in range(1, config.repeats + 1):
            run_id = f"run_{rep:03d}"
            baseline_dir = config.run_dir / task["task_id"] / run_id
            parsed = agent.load_result(baseline_dir)
            if parsed is None:
                raise ValueError(f"Missing parseable baseline output: {baseline_dir}")
            report = verify_agent_answer(parsed.text, task, config.repos_dir)
            if report["decision"] != "needs_review" or report["feedback"]["revision_requested"]:
                raise ValueError(f"Baseline answer cannot be replayed for {task['task_id']}")
            target = feedback.run_dir / task["task_id"] / run_id
            if target.exists():
                raise ValueError(
                    f"Feedback directory already exists; preserve or move it: {target}"
                )
            owner, repo = parse_owner_repo(task["repo_url"])
            source = config.repos_dir / owner / repo / task["commit_sha"]
            if not source.is_dir():
                raise ValueError(f"Missing source snapshot: {source}")
            prompt = (
                config.prompt_text.replace("{cve_id}", task["cve_id"])
                .replace("{task_id}", task["task_id"])
                .replace("{snapshot_sha}", task["commit_sha"])
            )
            prepared.append((task, run_id, parsed.raw, target, source, prompt))

    # Never permit a model call, even if a future feedback policy changes.
    with patch.object(agent, "run", side_effect=RuntimeError("Offline replay forbids model calls")):
        for task, run_id, raw, target, source, prompt in prepared:
            attempt = target / "attempt_000"
            attempt.mkdir(parents=True)
            (attempt / agent.result_filename()).write_text(raw, encoding="utf-8")
            (attempt / "prompt.txt").write_text(prompt, encoding="utf-8")
            run_with_feedback(
                agent,
                task,
                prompt,
                source,
                config.repos_dir,
                target,
                config.timeout,
                f"[{task['task_id']}/{run_id}]",
            )
            summary_path = target / "feedback_summary.json"
            if not summary_path.is_file():
                raise RuntimeError(f"Offline replay did not complete: {target}")
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            if summary["revised"] or len(summary["attempts"]) != 1:
                raise RuntimeError(f"Offline replay unexpectedly requested a revision: {target}")
    return len(prepared)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True)
    parser.add_argument("--agent", default="opencode_host")
    parser.add_argument("--benchmark", default="milestone_demo")
    parser.add_argument("--output-dir", type=Path, default=Path("results"))
    parser.add_argument("--repos-dir", type=Path, default=Path("benchmark/repos"))
    parser.add_argument("--repeats", type=int, default=1)
    args = parser.parse_args()
    config = ExperimentConfig(
        model=args.model,
        agent=args.agent,
        benchmark=args.benchmark,
        prompt="evidence_v1",
        output_dir=args.output_dir,
        repos_dir=args.repos_dir,
        repeats=args.repeats,
    )
    print(json.dumps({"replayed_cases": replay(config), "model_calls": 0}))


if __name__ == "__main__":
    main()
