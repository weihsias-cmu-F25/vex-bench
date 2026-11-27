import json
import logging
from pathlib import Path

from evaluate.agents import Agent, RunStats
from evaluate.common import (
    ExperimentConfig,
    add_experiment_args,
    config_from_args,
    load_tasks,
    make_agent,
)
from evaluate.pricing import cost_usd
from evaluate.result_parser import normalize_ground_truth, to_binary
from evidence.pipeline import parse_explanation, verify_agent_answer
from evidence.semantic_review import annotation_template, make_review_packet

logger = logging.getLogger(__name__)


def parse(config: ExperimentConfig) -> None:
    """Parse runs matching ``config`` into ``<benchmark_dir>/parsed.jsonl``.

    Driven by the benchmark's tasks, so the run dir can be reused across
    benchmark variants. Any (task, run) that can't yield a category becomes a
    row with ``predicted=None`` and a ``status`` of ``parse_fail`` /
    ``no_result`` / ``no_dir`` (``ok`` otherwise) — metrics counts these as
    failures, not skips. The only hard error is the run dir not existing.
    """
    agent = make_agent(config)
    tasks = load_tasks(config)

    if not config.run_dir.exists():
        raise FileNotFoundError(f"Run dir not found: {config.run_dir}")

    logger.info(
        "Parsing benchmark=%s tasks=%d repeats=%d under %s",
        config.benchmark,
        len(tasks),
        config.repeats,
        config.run_dir,
    )

    rows = [
        _parse_run(agent, task, config, rep)
        for task in tasks
        for rep in range(1, config.repeats + 1)
    ]

    config.benchmark_dir.mkdir(parents=True, exist_ok=True)
    parsed_path = config.benchmark_dir / "parsed.jsonl"
    with parsed_path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    logger.info("Wrote %d rows to %s", len(rows), parsed_path)


def _parse_run(agent: Agent, task: dict, config: ExperimentConfig, rep: int) -> dict:
    task_id = task["task_id"]
    run_id = f"run_{rep:03d}"
    gt_raw = task["ground_truth"]
    row = {
        "task_id": task_id,
        "run_id": run_id,
        "cve_id": task["cve_id"],
        "ground_truth": normalize_ground_truth(gt_raw) if gt_raw is not None else None,
        "ground_truth_category": task.get("ground_truth_category"),
        "predicted": None,
        "predicted_category": None,
        "reasoning": None,
        "status": "ok",
        **RunStats().model_dump(),
        "cost_usd": None,
    }

    run_dir_per_rep = config.run_dir / task_id / run_id
    evidence_mode = config.prompt == "evidence_v1"
    if evidence_mode:
        row["evidence_decision"] = "not_checked"
    if config.feedback_rounds:
        stats, attempts = _attempt_stats(agent, run_dir_per_rep)
        row["feedback_attempts"] = attempts
        initial = agent.load_result(run_dir_per_rep / "attempt_000")
        row["initial_predicted_category"] = initial.category if initial else None
        row["initial_predicted"] = to_binary(initial.category) if initial else None
        summary_path = run_dir_per_rep / "feedback_summary.json"
        row["feedback_status"] = "complete" if summary_path.is_file() else "incomplete"
        if summary_path.is_file():
            try:
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
                row["feedback_initial_decision"] = summary["initial_decision"]
                row["feedback_final_decision"] = summary["final_decision"]
                if len(summary["attempts"]) != attempts:
                    row["feedback_status"] = "incomplete"
            except (ValueError, KeyError, TypeError):
                row["feedback_status"] = "incomplete"
        if stats is not None:
            row.update(stats.model_dump())
            row["cost_usd"] = cost_usd(stats, config.model)
    report_path = run_dir_per_rep / "evidence_report.json"
    if evidence_mode:
        report_path.unlink(missing_ok=True)
    parsed = agent.load_result(run_dir_per_rep)
    if parsed is None:
        status = "no_dir" if not (config.run_dir / task_id).exists() else "no_result"
        if agent.has_result(run_dir_per_rep):
            status = "parse_fail"
            if evidence_mode:
                result_path = run_dir_per_rep / agent.result_filename()
                try:
                    raw = result_path.read_text(encoding="utf-8")
                    answer = agent.extract_text(raw)
                except Exception:
                    answer = ""
                _attach_evidence(row, answer, task, config, report_path)
        logger.warning("[%s] %s/%s", status.upper().replace("_", "-"), task_id, run_id)
        return {**row, "status": status}

    if not config.feedback_rounds:
        row.update(parsed.stats.model_dump())
        row["cost_usd"] = cost_usd(parsed.stats, config.model)

    if evidence_mode:
        _attach_evidence(row, parsed.text, task, config, report_path)
        if (
            config.feedback_rounds
            and row.get("feedback_final_decision") != row["evidence_decision"]
        ):
            row["feedback_status"] = "incomplete"

    result = {
        **row,
        "predicted": to_binary(parsed.category),
        "predicted_category": parsed.category,
        "reasoning": parsed.reasoning,
    }
    if config.feedback_rounds and row["feedback_status"] != "complete":
        result.update(
            status="revision_incomplete",
            incomplete_category=parsed.category,
            predicted=None,
            predicted_category=None,
        )
    return result


def _attach_evidence(
    row: dict, answer: str, task: dict, config: ExperimentConfig, path: Path
) -> None:
    report = verify_agent_answer(answer, task, config.repos_dir)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    packet_path = path.with_name("review_packet.json")
    template_path = path.with_name("review_annotation.template.json")
    packet_path.unlink(missing_ok=True)
    template_path.unlink(missing_ok=True)
    row["evidence_decision"] = report["decision"]
    row["evidence_report"] = str(path)
    row["evidence_citations_valid"] = sum(c["valid"] for c in report.get("citations", []))
    row["evidence_citations_total"] = len(report.get("citations", []))
    row["evidence_claim_statuses"] = [c["status"] for c in report.get("claims", [])]
    if report["decision"] == "needs_review":
        packet = make_review_packet(parse_explanation(answer, task), report)
        packet_path.write_text(
            json.dumps(packet, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        template_path.write_text(
            json.dumps(annotation_template(packet), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        row["review_packet"] = str(packet_path)


def _attempt_stats(agent: Agent, run_dir: Path) -> tuple[RunStats | None, int]:
    files = [
        path
        for index in (0, 1)
        if (path := run_dir / f"attempt_{index:03d}" / agent.result_filename()).is_file()
    ]
    if not files:
        return None, 0
    stats = []
    for path in files:
        try:
            stats.append(agent.extract_stats(path.read_text(encoding="utf-8")))
        except Exception:
            stats.append(RunStats())

    def total(field: str) -> int | None:
        values = [getattr(item, field) for item in stats]
        return (
            sum(value for value in values if value is not None)
            if any(value is not None for value in values)
            else None
        )

    return RunStats(
        steps=total("steps"),
        completed=stats[-1].completed,
        input_tokens=total("input_tokens"),
        cached_input_tokens=total("cached_input_tokens"),
        cache_write_tokens=total("cache_write_tokens"),
        output_tokens=total("output_tokens"),
        reasoning_tokens=total("reasoning_tokens"),
    ), len(files)


def register_parser(subparsers) -> None:
    p = subparsers.add_parser("parse", help="Parse recorded agent results into parsed.jsonl")
    add_experiment_args(p)
    p.set_defaults(func=lambda args: parse(config_from_args(args)))
