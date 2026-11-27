"""Label-free human review of semantic support for an exploitability explanation.

The code validates packet provenance and annotation completeness. It does not
decide whether a call path is feasible or a mitigation is effective.
"""

import hashlib
import json
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator

from evidence.schema import Explanation

OBLIGATIONS: dict[str, tuple[tuple[str, str], ...]] = {
    "false_positive": (
        ("mapping", "Does the advisory identify a different package or a withdrawn CVE?"),
    ),
    "code_not_present": (
        ("affected_component", "What exact package or module contains the vulnerable operation?"),
        (
            "dependency_absence",
            "Do resolved dependencies, vendored code, and build paths exclude it?",
        ),
    ),
    "code_not_reachable": (
        (
            "affected_operation",
            "What exact affected operation is identified by the advisory or fix?",
        ),
        (
            "no_reachable_path",
            "What evidence rules out a path from an application entry point to that operation, "
            "including dynamic calls and configuration?",
        ),
    ),
    "requires_configuration": (
        ("required_setting", "Which setting is necessary to trigger the vulnerable behavior?"),
        ("default_and_override", "Is it disabled by default and never enabled by a relevant path?"),
    ),
    "requires_dependency": (
        ("required_dependency", "Which additional dependency is necessary for the exploit?"),
        ("dependency_absence", "Is it absent from the resolved and vendored dependency graph?"),
    ),
    "requires_environment": (
        ("required_environment", "Which environment property is necessary for the exploit?"),
        ("deployed_environment", "What establishes that supported deployments lack it?"),
    ),
    "compiler_protected": (
        ("build_control", "Which build hardening setting is active in the shipped artifact?"),
        ("control_effect", "How does that setting prevent this exploit primitive?"),
    ),
    "runtime_protected": (
        ("runtime_control", "Which runtime control is active along the affected path?"),
        ("control_effect", "How does that control prevent this exploit primitive?"),
    ),
    "perimeter_protected": (
        ("entry_control", "Which perimeter control covers the attacker entry point?"),
        ("control_effect", "How does the deployed control block the relevant input?"),
    ),
    "mitigating_control_protected": (
        ("mitigation", "Which mitigation runs before the vulnerable operation?"),
        ("control_effect", "How does it block the vulnerable behavior for all relevant inputs?"),
    ),
    "uncertain": (
        ("unresolved_precondition", "Which exact exploitability precondition remains unresolved?"),
    ),
    "vulnerable": (
        ("attacker_path", "Can attacker-controlled input reach the vulnerable operation?"),
        ("mitigation_check", "Are relevant mitigations absent or ineffective on that path?"),
    ),
}
ADVISORY_OBLIGATION = (
    "advisory_scope",
    "Which advisory source identifies the affected component, versions, operation, and trigger?",
)
VULNERABILITY_RECORD_OBLIGATION = (
    "vulnerability_record",
    "Which authoritative record establishes the CVE status and actual affected package?",
)
VERSION_OBLIGATION = (
    "affected_version",
    "Does the resolved dependency version fall inside the advisory's affected range?",
)
VERSION_CATEGORIES = frozenset(
    {
        "code_not_reachable",
        "requires_configuration",
        "requires_dependency",
        "requires_environment",
        "compiler_protected",
        "runtime_protected",
        "perimeter_protected",
        "mitigating_control_protected",
        "vulnerable",
    }
)


def _digest(data: dict) -> str:
    encoded = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def make_review_packet(explanation: Explanation, report: dict) -> dict:
    """Package a structurally valid explanation without benchmark labels."""
    if report["decision"] != "needs_review" or not report.get("citation_integrity"):
        raise ValueError("Only evidence with intact citations can enter semantic review")
    if (
        report["task_id"] != explanation.task_id
        or report["cve_id"] != explanation.cve_id
        or report["snapshot_sha"] != explanation.snapshot_sha
        or report["proposed_category"] != explanation.category
    ):
        raise ValueError("Verifier report does not match explanation")
    citation_status = {item["id"]: item for item in report["citations"]}
    claim_status = {item["id"]: item for item in report["claims"]}
    obligations = [
        VULNERABILITY_RECORD_OBLIGATION
        if explanation.category == "false_positive"
        else ADVISORY_OBLIGATION
    ]
    if explanation.category in VERSION_CATEGORIES:
        obligations.append(VERSION_OBLIGATION)
    obligations.extend(OBLIGATIONS[explanation.category])
    packet = {
        "schema_version": 1,
        "task_id": explanation.task_id,
        "cve_id": explanation.cve_id,
        "snapshot_sha": explanation.snapshot_sha,
        "proposed_category": explanation.category,
        "reasoning": explanation.reasoning,
        "verifier_decision": report["decision"],
        "obligations": [
            {"id": obligation_id, "question": question} for obligation_id, question in obligations
        ],
        "citations": [
            {**citation.model_dump(), "integrity_valid": citation_status[citation.id]["valid"]}
            for citation in explanation.citations
        ],
        "claims": [
            {**claim.model_dump(), "local_status": claim_status[claim.id]["status"]}
            for claim in explanation.claims
        ],
        "review_scope": (
            "A human must assess whether the reasoning and cited evidence support each obligation. "
            "External advisory URLs may be added in the annotation; this tool does not verify them."
        ),
    }
    packet["packet_sha256"] = _digest(packet)
    return packet


def annotation_template(packet: dict) -> dict:
    return {
        "schema_version": 1,
        "packet_sha256": packet["packet_sha256"],
        "reviewer_id": "",
        "judgments": [
            {
                "obligation_id": item["id"],
                "verdict": "insufficient",
                "rationale": "",
                "source_refs": [],
            }
            for item in packet["obligations"]
        ],
    }


class Judgment(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    obligation_id: str = Field(min_length=1)
    verdict: Literal["supported", "contradicted", "insufficient"]
    rationale: str = Field(min_length=1)
    source_refs: list[str] = Field(default_factory=list)

    @field_validator("rationale")
    @classmethod
    def nonblank_rationale(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("rationale must not be blank")
        return value


class Annotation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal[1]
    packet_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewer_id: str = Field(min_length=1)
    judgments: list[Judgment] = Field(min_length=1)

    @field_validator("reviewer_id")
    @classmethod
    def nonblank_reviewer(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("reviewer_id must not be blank")
        return value


def score_review(packet: dict, annotation: dict) -> dict:
    """Validate and summarize a human judgment; never auto-verify exploitability."""
    model = Annotation.model_validate(annotation)
    if packet.get("schema_version") != 1 or packet.get("verifier_decision") != "needs_review":
        raise ValueError("Only verified review packets with schema version 1 can be scored")
    content = {key: value for key, value in packet.items() if key != "packet_sha256"}
    if packet.get("packet_sha256") != _digest(content):
        raise ValueError("Review packet content does not match its hash")
    if model.packet_sha256 != packet["packet_sha256"]:
        raise ValueError("Annotation refers to a different review packet")
    expected = {item["id"] for item in packet["obligations"]}
    actual = [item.obligation_id for item in model.judgments]
    if len(actual) != len(set(actual)) or set(actual) != expected:
        raise ValueError("Annotation must judge each obligation exactly once")
    citation_ids = {item["id"] for item in packet["citations"]}
    for judgment in model.judgments:
        if judgment.verdict != "insufficient" and not judgment.source_refs:
            raise ValueError(f"{judgment.obligation_id} needs source references")
        for ref in judgment.source_refs:
            url = urlparse(ref)
            if ref not in citation_ids and not (url.scheme == "https" and url.netloc):
                raise ValueError(f"Unknown source reference: {ref}")
    verdicts = [item.verdict for item in model.judgments]
    overall = (
        "contradicted"
        if "contradicted" in verdicts
        else "supported"
        if all(item == "supported" for item in verdicts)
        else "insufficient"
    )
    return {
        "schema_version": 1,
        "task_id": packet["task_id"],
        "packet_sha256": packet["packet_sha256"],
        "reviewer_id": model.reviewer_id,
        "evidence_support": overall,
        "judgment_counts": {status: verdicts.count(status) for status in sorted(set(verdicts))},
        "annotation_validated": True,
        "automated_exploitability_verified": False,
    }
