"""Actionable verifier feedback without claiming semantic certainty."""

REVIEW_QUESTIONS = {
    "false_positive": ["What advisory evidence shows the CVE-to-package mapping is wrong?"],
    "code_not_present": [
        "Which manifests, lockfiles, and vendored locations were checked for the vulnerable code?"
    ],
    "code_not_reachable": [
        "What evidence rules out a path from an application entry point "
        "to the vulnerable operation?"
    ],
    "requires_configuration": [
        "Which configuration value is required, and what source shows it is disabled by default?"
    ],
    "requires_dependency": [
        "Which additional dependency is required, and what shows it is absent "
        "from the resolved build?"
    ],
    "requires_environment": [
        "Which environment precondition is required, and what establishes the deployed environment?"
    ],
    "compiler_protected": [
        "Which build setting is active, and how does it block this exploit primitive?"
    ],
    "runtime_protected": [
        "Which runtime control is active on the affected path, and how does it block the exploit?"
    ],
    "perimeter_protected": [
        "Which perimeter control covers the attacker entry point in the deployed configuration?"
    ],
    "mitigating_control_protected": [
        "Which mitigation is active before the vulnerable operation, and why is it effective?"
    ],
    "uncertain": [
        "Which exploitability precondition remains unresolved after inspecting the evidence?"
    ],
    "vulnerable": [
        "What establishes an affected dependency version and a path from attacker-controlled input "
        "to the vulnerable operation?",
        "What evidence rules out effective configuration, runtime, and perimeter mitigations?",
    ],
}


def build_feedback(report: dict) -> dict:
    """Describe repairs and review work supported by the verifier's own findings."""
    decision = report["decision"]
    repairs = []
    if decision == "invalid_input":
        repairs.append(
            {
                "code": "invalid_input",
                "instruction": (
                    "Return one complete JSON explanation matching the required schema "
                    "and task identifiers."
                ),
                "detail": report.get("error", ""),
            }
        )
    elif decision == "unsupported":
        if not report.get("snapshot_matches_expected", True):
            repairs.append(
                {
                    "code": "snapshot_mismatch",
                    "instruction": "Use the task's exact repository snapshot SHA.",
                }
            )
        for citation in report.get("citations", []):
            if not citation["valid"]:
                repairs.append(
                    {
                        "code": "invalid_citation",
                        "citation_id": citation["id"],
                        "errors": citation["errors"],
                        "instruction": (
                            "Recheck the source path, inclusive line range, exact quote, "
                            "and raw-file SHA-256."
                        ),
                    }
                )
        for claim in report.get("claims", []):
            if claim["status"] == "unsupported":
                repairs.append(
                    {
                        "code": "unsupported_claim",
                        "claim_id": claim["id"],
                        "detail": claim["detail"],
                        "instruction": (
                            "Replace or remove this claim, or cite a span containing "
                            "its local predicate."
                        ),
                    }
                )
    elif decision == "source_unavailable":
        repairs.append(
            {
                "code": "source_unavailable",
                "instruction": (
                    "Download the task's pinned repository snapshot before verifying evidence."
                ),
            }
        )

    questions = REVIEW_QUESTIONS.get(report.get("proposed_category"), [])
    return {
        "revision_requested": decision in {"invalid_input", "unsupported"},
        "repairs": repairs,
        "human_review_required": True,
        "review_claim_ids": [
            claim["id"]
            for claim in report.get("claims", [])
            if claim["status"] == "requires_review"
        ],
        "review_questions": questions,
        "scope": (
            "Citation and local predicate checks do not verify free-text reasoning "
            "or exploitability."
        ),
    }
