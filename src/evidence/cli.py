import json
from pathlib import Path

from pydantic import ValidationError

from evidence.feedback import build_feedback
from evidence.verifier import verify


def register_parser(subparsers):
    parser = subparsers.add_parser("verify", help="Check evidence in a structured explanation")
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--snapshot-sha", required=True)
    parser.add_argument("--output", type=Path)
    parser.set_defaults(func=_run)


def _run(args):
    try:
        payload = json.loads(args.input.read_text(encoding="utf-8"))
        report = verify(payload, args.repo, args.snapshot_sha)
    except (ValidationError, ValueError, OSError) as exc:
        report = {"decision": "invalid_input", "error": str(exc)}
        report["feedback"] = build_feedback(report)
        print(json.dumps(report, indent=2))
        raise SystemExit(2) from exc
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if report["decision"] == "unsupported":
        raise SystemExit(1)
