"""Strict, label-free input contract for the initial verifier."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from evaluate.result_parser import VALID_CATEGORIES


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Citation(StrictModel):
    id: str = Field(min_length=1)
    path: str = Field(min_length=1)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    quote: str = Field(min_length=1)
    file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def bounded_span(self):
        if self.end_line < self.start_line or self.end_line - self.start_line >= 200:
            raise ValueError("Citations must span between 1 and 200 lines")
        return self


class Predicate(StrictModel):
    kind: Literal["text_contains", "python_import", "python_call", "semantic"]
    target: str = Field(min_length=1)


class Claim(StrictModel):
    id: str = Field(min_length=1)
    statement: str = Field(min_length=1)
    predicate: Predicate
    citation_ids: list[str] = Field(min_length=1)


class Explanation(StrictModel):
    schema_version: Literal[1]
    task_id: str = Field(min_length=1)
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    snapshot_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    category: str
    reasoning: str = Field(min_length=1)
    citations: list[Citation] = Field(min_length=1, max_length=100)
    claims: list[Claim] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def consistent_ids(self):
        if self.category not in VALID_CATEGORIES:
            raise ValueError("Unknown upstream VEX category")
        citation_ids = [c.id for c in self.citations]
        claim_ids = [c.id for c in self.claims]
        if len(set(citation_ids)) != len(citation_ids):
            raise ValueError("Duplicate citation IDs")
        if len(set(claim_ids)) != len(claim_ids):
            raise ValueError("Duplicate claim IDs")
        referenced = {ref for claim in self.claims for ref in claim.citation_ids}
        if referenced != set(citation_ids):
            raise ValueError("Unknown references or unused citations")
        return self
