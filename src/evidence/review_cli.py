"""Prepare and score label-free human semantic-review packets."""

import json
from pathlib import Path

from pydantic import ValidationError

from evidence.schema import Explanation
from evidence.semantic_review import annotation_template, make_review_packet, score_review
from evidence.verifier import verify


def register_parser(subparsers) -> None:
    review = subparsers.add_parser("review", help="Prepare and score human evidence review")
    actions = review.add_subparsers(dest="review_action", required=True)
    prepare = actions.add_parser("prepare", help="Build a review packet from a valid explanation")
    prepare.add_argument("--repo", type=Path, required=True)
    prepare.add_argument("--input", type=Path, required=True)
    prepare.add_argument("--snapshot-sha", required=True)
    prepare.add_argument("--output", type=Path, required=True)
    prepare.set_defaults(func=_prepare)

    score = actions.add_parser("score", help="Validate and summarize a human annotation")
    score.add_argument("--packet", type=Path, required=True)
    score.add_argument("--annotation", type=Path, required=True)
    score.add_argument("--output", type=Path)
    score.set_defaults(func=_score)


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _prepare(args) -> None:
    try:
        explanation = Explanation.model_validate_json(args.input.read_text(encoding="utf-8"))
        report = verify(explanation.model_dump(), args.repo, args.snapshot_sha)
        if report["decision"] != "needs_review":
            print(json.dumps(report, indent=2, ensure_ascii=False))
            raise SystemExit(1)
        packet = make_review_packet(explanation, report)
    except (ValidationError, ValueError, OSError) as exc:
        print(json.dumps({"error": str(exc)}, indent=2))
        raise SystemExit(2) from exc
    _write(args.output, packet)
    template_path = args.output.with_name(args.output.stem + ".annotation.template.json")
    _write(template_path, annotation_template(packet))
    print(json.dumps({"packet": str(args.output), "annotation_template": str(template_path)}))


def _score(args) -> None:
    try:
        packet = json.loads(args.packet.read_text(encoding="utf-8"))
        annotation = json.loads(args.annotation.read_text(encoding="utf-8"))
        result = score_review(packet, annotation)
    except (ValidationError, ValueError, OSError, KeyError) as exc:
        print(json.dumps({"error": str(exc)}, indent=2))
        raise SystemExit(2) from exc
    if args.output:
        _write(args.output, result)
    print(json.dumps(result, indent=2, ensure_ascii=False))
