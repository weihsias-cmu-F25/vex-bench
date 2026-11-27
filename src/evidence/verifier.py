"""Check citation integrity and narrow local predicates, without claiming exploitability.

AST checks confirm syntax in the cited lines only. A call expression does not
prove execution, reachability, binding identity, or attacker control.
"""

import ast
import hashlib
from pathlib import Path, PurePosixPath

from evidence.feedback import build_feedback
from evidence.schema import Explanation

MAX_FILE_BYTES = 4 * 1024 * 1024


def _source(root: Path, relative: str) -> bytes:
    path = PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts or "\\" in relative or "\x00" in relative:
        raise ValueError("unsafe_path")
    resolved = (root / relative).resolve()
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise ValueError("missing_or_escaping_path")
    if resolved.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("file_too_large")
    return resolved.read_bytes()


def verify(payload: dict, repo: Path, expected_snapshot_sha: str) -> dict:
    explanation = Explanation.model_validate(payload)
    root = repo.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Repository must be a directory")
    snapshot_matches = explanation.snapshot_sha == expected_snapshot_sha
    checked = []
    sources = {}
    for citation in explanation.citations:
        errors = []
        try:
            raw = _source(root, citation.path)
            digest = hashlib.sha256(raw).hexdigest()
            text = raw.decode("utf-8")
            lines = text.splitlines()
            if digest != citation.file_sha256:
                errors.append("file_hash_mismatch")
            if citation.end_line > len(lines):
                errors.append("line_range_out_of_bounds")
            else:
                actual = "\n".join(lines[citation.start_line - 1 : citation.end_line])
                if actual != citation.quote:
                    errors.append("quote_mismatch")
            sources[citation.id] = (text, citation)
        except (ValueError, OSError) as exc:
            errors.append(str(exc))
        checked.append({"id": citation.id, "valid": not errors, "errors": errors})

    validity = {item["id"]: item["valid"] for item in checked}
    claims = []
    for claim in explanation.claims:
        state, detail = "requires_review", "Semantic entailment requires human review"
        if not all(validity[ref] for ref in claim.citation_ids):
            state, detail = "unsupported", "Claim cites invalid evidence"
        elif claim.predicate.kind != "semantic":
            found = False
            parse_error = False
            for ref in claim.citation_ids:
                text, citation = sources[ref]
                if claim.predicate.kind == "text_contains":
                    found |= claim.predicate.target in citation.quote
                    continue
                if not citation.path.endswith(".py"):
                    parse_error = True
                    continue
                try:
                    tree = ast.parse(text)
                except (SyntaxError, ValueError, RecursionError):
                    parse_error = True
                    continue
                for node in ast.walk(tree):
                    if not (
                        citation.start_line <= getattr(node, "lineno", 0)
                        and getattr(node, "end_lineno", 0) <= citation.end_line
                    ):
                        continue
                    if claim.predicate.kind == "python_call" and isinstance(node, ast.Call):
                        found |= ast.unparse(node.func) == claim.predicate.target
                    if claim.predicate.kind == "python_import":
                        if isinstance(node, ast.Import):
                            found |= any(a.name == claim.predicate.target for a in node.names)
                        if isinstance(node, ast.ImportFrom) and node.module:
                            found |= any(
                                f"{'.' * node.level}{node.module}.{a.name}"
                                == claim.predicate.target
                                for a in node.names
                            )
            if found:
                state, detail = "verified_local_predicate", "Exact local predicate found"
            elif parse_error:
                detail = "Unsupported file language or Python syntax needs review"
            else:
                state, detail = "unsupported", "Predicate absent from cited source spans"
        claims.append(
            {
                "id": claim.id,
                "status": state,
                "detail": detail,
                "statement_entailment": "not_checked",
            }
        )

    integrity = snapshot_matches and all(c["valid"] for c in checked)
    unsupported = not integrity or any(c["status"] == "unsupported" for c in claims)
    report = {
        "schema_version": 1,
        "task_id": explanation.task_id,
        "cve_id": explanation.cve_id,
        "snapshot_sha": explanation.snapshot_sha,
        "snapshot_matches_expected": snapshot_matches,
        "proposed_category": explanation.category,
        "decision": "unsupported" if unsupported else "needs_review",
        "citation_integrity": integrity,
        "citations": checked,
        "claims": claims,
        "exploitability_verified": False,
        "limitations": [
            "Snapshot SHA comparison uses caller-supplied provenance, not Git attestation",
            "File hashes bind citations to current bytes, not a complete pristine tree",
            "Local predicates do not establish the truth of free-text claims or reasoning",
            "Calls and imports do not prove execution or end-to-end reachability",
            "Absence of a match does not prove repository-wide absence or safety",
            "Affected-version resolution and effective mitigations require further analysis",
        ],
    }
    report["feedback"] = build_feedback(report)
    return report
