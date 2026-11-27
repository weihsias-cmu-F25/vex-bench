# Web-enabled three-case comparison

Run date: November 27, 2026. This corrects the earlier [offline pilot](OFFLINE_EVALUATION.md),
which disabled advisory lookup after a headless OpenCode run could not answer its
first-use search-provider prompt. OpenCode CLI 2.4.2 now selects Exa in its
configuration and allows `websearch` and `webfetch`; a direct probe and the
recorded task transcripts confirm successful advisory retrieval. The host
adapter still uses disposable source copies and denies general shell commands,
editing, external-directory access, subagents, and interactive questions.

We ran the same three pinned `milestone_demo` tasks once each with
`openai/gpt-6.2-sol`, a 300-second timeout, and sequential execution. The
comparison uses the original `vuln` prompt and the `evidence_v1` prompt that
adds structured source citations and claims. Both had the same model, source
snapshots, and web permissions. The runs are independent, with no feedback
round; they do not isolate a verifier-feedback effect.

| Case | Benchmark label | Original prompt | Evidence prompt | Valid evidence citations |
| --- | --- | --- | --- | ---: |
| FastAPI / CVE-2024-47874 | `vulnerable` | `uncertain` | `uncertain` | 6/6 |
| RAGFlow / CVE-2024-36039 | `code_not_reachable` | `vulnerable` | `vulnerable` | 12/12 |
| Minikube / CVE-2019-5736 | `code_not_present` | `code_not_present` | `uncertain` | 5/5 |

Under the [paper's five-label scoring rule](https://arxiv.org/html/2609.08040v1),
predictions outside the five annotated categories count as failed. The original
prompt scored **1/3** and the evidence prompt **0/3** in both binary and exact
category accuracy. All six outputs were parseable. The evidence prompt produced
23/23 mechanically valid repository citations, but all three verifier decisions
were `needs_review` because their nine claims require semantic review. The
original prompt has no structured citation contract, so 23/23 is an absolute
validity count, not a comparative evidence-quality score.

### What the cases show

- **FastAPI:** Both prompts found the [Starlette maintainer advisory](https://github.com/Kludex/starlette/security/advisories/GHSA-f96h-pmfr-66vw)
  and the `request.form()` path. The snapshot's Starlette range permits both
  affected and fixed versions and does not resolve an installed version. Both
  abstained for that reason, despite the benchmark's `vulnerable` label.
- **RAGFlow:** Both prompts found the [PyMySQL advisory](https://github.com/advisories/GHSA-v9hf-5j83-6xpp)
  and the pinned 1.1.0 dependency, then asserted a path from authenticated JSON
  input through Peewee to the vulnerable driver operation. They proposed
  *different* application routes. The benchmark labels this case
  `code_not_reachable`. Mechanically correct citations do not establish the
  cross-library data flow or exploitability; this is a targeted semantic-review
  question, not a confirmed vulnerability finding.
- **Minikube:** Both found the [runc advisory](https://github.com/advisories/GHSA-gxmr-w5mj-v8hh).
  The original prompt treated the explicitly selected runc versions as proof
  that affected code is absent. The evidence prompt also found an unpinned
  `containerd.io` install in a build path and abstained because the resulting
  runtime version was not established. The benchmark label agrees with the
  original prompt; the unresolved build-path question remains for review.

The evidence run recorded 597,593 total tokens across the five recorded token
buckets, versus 417,663 for the original prompt (about 43% more). These are
OpenCode's usage counters, not a USD cost estimate; this model is absent from
the repository's API pricing table and was accessed through a plan login.

### Interpretation and next experiment

This small run does **not** support an accuracy improvement from the evidence
format. It demonstrates that the format enables mechanical source-citation
checks while leaving the decisive version, reachability, and mitigation claims
to semantic review. The old Gemini judge's six `insufficient` annotations
apply to the earlier no-web answers and must not be treated as judgments of
these new answers. The current schema records local file citations but has no
structured field for advisory excerpts or third-party library source, so its
review packets still need an external-source audit.

The next useful experiment is to adjudicate the three new review packets,
especially RAGFlow's claimed Peewee-to-PyMySQL path, against the pinned source
and upstream library code. Then add explicit, checkable advisory provenance and
test a larger set with resolvable dependency versions and varied labels. A
verifier feedback comparison should be run only when the initial answers
actually trigger revisions; none of these three `needs_review` results does.

Selected answers, evidence reports, review packets, metrics, prompt hashes,
web-tool counts, and raw-transcript hashes are in the
[comparison receipt](reports/web_enabled_comparison/README.md). Full JSONL
transcripts remain local under `results/web_enabled_baseline/` and
`results/web_enabled_pilot/`, which are ignored by Git.
