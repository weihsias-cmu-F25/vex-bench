# 14-795 Progress Milestone Report

**Evidence Grounded Exploitability Explanations for VEX Bench**

Team: Miles Chiang (imingc), Wei-Hsiang Shao (weihsias)

Evidence cutoff: October 18, 2026, America/Los_Angeles. Individual attribution remains unconfirmed.

## Implementation progress achieved

### Actual upstream and extension point

The implementation extends [steven1518/vex-bench](https://github.com/steven1518/vex-bench)
at commit `80cddeac3132826bfd47227ad59b2e6618a681bd`, on the local `evidence-verifier` branch.
The inspected benchmark file contains 75 tasks. `src/evaluate/result_parser.py` validates a
12-category JSON answer and extracts reasoning. That parser does not check cited source content.
The new verifier adds evidence postprocessing while preserving the original category parser.

The original binary mapping assigns only `vulnerable` to `exploitable` and maps `uncertain`
to `not_exploitable`. This extension keeps that upstream scoring behavior unchanged and
separately reports `needs_review` rather than treating uncertainty as evidence of safety.

### Completed implementation

- Added `vex-bench verify` with strict JSON input and machine-readable reports.
- Defined task, CVE, snapshot, category, reasoning, citations and claim fields in a JSON Schema.
- Bound each citation to a relative source path, inclusive line range, exact line quote and SHA-256.
- Rejected escaping paths, missing files, altered bytes, fabricated quotes and malformed references.
- Added narrow Python AST predicates for import and call syntax inside cited spans.
- Added literal text predicates for non-Python manifests, including Go.
- Kept reachability, mitigation efficacy, absence and exploitability claims subject to review.
- Registered `milestone_demo` and the `evidence_v1` prompt, with task and snapshot placeholders.
- Added 27 unit/integration tests and a deterministic demonstration script.

The verifier never executes target code. It does not automatically extract reliable claims from
unstructured prose. The new prompt requests structured evidence, but automatic raw-agent-result
extraction, verifier invocation and model revision remain future integration work.

### Representative source cases

| Project / CVE | Exact snapshot | Observed evidence | Remaining question |
| --- | --- | --- | --- |
| FastAPI / CVE-2024-47874 | `febf6b6a52e36e0d64920fb54670ad7fc29b2eaa` | `fastapi/routing.py:247` calls `request.form()` | Which affected dependency version and attacker path apply? |
| RAGFlow / CVE-2024-36039 | `c68767acdde0bbe521fad7f202f01130d7aa4ce3` | `api/db/db_models.py:30` imports `PooledMySQLDatabase` | Can untrusted dictionary keys reach the vulnerable PyMySQL operation? |
| Minikube / CVE-2019-5736 | `e7bf515c48f32d7ef63c81fcdba92cccef619016` | `go.mod:52` declares `github.com/opencontainers/runc v1.1.14` | Which runtime binary and deployment path actually apply? |

The downloaded sources are real pinned snapshots. The demonstration inputs are authored,
not predictions from OpenCode or another baseline model. These three cases provide varied
source evidence, not a representative statistical sample of all 75 tasks.

### Obtained results

27 tests passed. Tests exercise citation tampering, stale hashes, incorrect bounds, traversal,
symlink escapes, comment-versus-call distinctions, wrong source spans, schema and label rejection,
uncertainty handling, CRLF content, upstream-parser compatibility and CLI exit behavior.

| Authored variant | Inputs | Actual verifier result |
| --- | ---: | --- |
| Real local fact | 3 | 3 needs_review, with verified local predicates |
| Fabricated quotation | 3 | 3 unsupported |
| Missing cited file | 3 | 3 unsupported |
| Predicate absent from cited span | 3 | 3 unsupported |
| Semantic overclaim using a real citation | 3 | 3 needs_review |
| Total | 15 | 9 unsupported, 6 needs_review |

These counts describe controlled evidence checks. They are not exploitability accuracy,
precision, recall or F1. No baseline model was run, so there is no measured improvement over
VEX Bench, no token comparison and no provider-cost estimate. No model calls occurred in this demo.
Test code verifies only the stated checks, not general semantic correctness.

Source and result receipts: `results/evidence_demo/summary.json`, `tests.txt`, `demo.txt`,
individual input/report JSON files and `baseline_preflight.json`. Structured example inputs
also live under `examples/evidence/`.

## Difficulties encountered

| Difficulty | Status required by rubric | Evidence and response |
| --- | --- | --- |
| Lockfile inconsistent with project metadata | Overcome for this environment | Retained the prior uv.lock refresh. Locked synchronization now succeeds. |
| Editable installation cannot import cli | Overcome with workaround | Python verbose startup showed it skipping UF_HIDDEN .pth files. Non-editable install avoids that mechanism. A targeted flag-repair helper is included. |
| Complete baseline execution unavailable | Will keep working | Docker daemon is unavailable and OpenCode configuration files are absent. Recorded preflight results without reading credential values. |
| True citation does not establish semantic entailment | Will keep working | AST and literal facts cannot establish whole-program reachability, affected runtime versions or safety. Verifier abstains. |
| Individual contribution attribution missing | Will keep working | Both names come from the proposal. The available record does not identify which student performed each action. |

No difficulty has been classified as impossible within the semester. Whether larger evaluation
fits available time and provider budget remains unmeasured.

## Refinements to the rest-of-semester plan

**Refinement: reorder implementation and narrow the milestone claim.** The proposal scheduled
baseline runs before basic verification, and targeted an end-to-end demonstration on 3-5 cases
by October 23. The current milestone demonstrates evidence checking on three real source
snapshots. The paid-agent baseline and complete semantic verifier remain outstanding.

The following is a proposed schedule, not a record of completed work:

| Planned period | Work | Acceptance criterion |
| --- | --- | --- |
| Oct 19-20 | Start Docker, configure provider, build Python/Go images, run baseline | Three real model outputs plus recorded run settings and failures |
| Oct 21-22 | Extract structured agent evidence, invoke verifier, add advisory/version checks | Traceable source and advisory evidence, invalid claims rejected |
| Oct 23 | Prepare live milestone demonstration and confirm contribution attribution | Reproducible three-case demo and verified team contribution page |
| Remainder of semester | Add semantic review and feedback, broaden evaluation | Compare matched baseline and verified outputs with explicit abstention |

End-of-semester goals: improve semantic support checks, allow agent revision of unsupported
claims, and compare evidence quality and exploitability judgments on an expanded case set.
Select additional cases using an explicit language/category sampling plan. Do not promise all
75 cases before measuring run time, failures and provider cost on the initial subset.

Planned evaluation distinguishes binary/category metrics from evidence quality. Report completion
rate, invalid citations, expert-rated claim support, review/abstention rate, token use and cost.
Use the same cases, model and run settings for matched comparisons. Keep benchmark labels and
reference PR metadata outside agent-visible source containers. The developer has already seen
labels during setup, so current authored demonstrations are not a blind evaluation.

## Individual contributions up to this point

- **Miles Chiang (imingc):** Individual contribution attribution has not been confirmed. The team
  must provide actual completed tasks before submitting this section as a final contribution record.
- **Wei-Hsiang Shao (weihsias):** Individual contribution attribution has not been confirmed.
  No implementation task has been assigned to this person in the available record.

Observed human activity: the user cloned upstream, created the branch, installed the environment,
inspected the parser and selected tasks using guided commands. The user's identity cannot be
matched to a named student from the supplied record alone.

AI assistance in this session: repository inspection, environment diagnosis, initial verifier
implementation, test and demo construction, and milestone artifact drafting. Students should
review and understand this material and disclose assistance according to course policy.

## Reproduction and limitations

See `WALKTHROUGH.zh-TW.md` for step-by-step commands and explanations. A quick local rerun is:

```bash
uv sync --locked --no-editable
uv run --no-editable python -m unittest discover -s tests -v
uv run --no-editable python scripts/demo_evidence.py
```

The verifier compares snapshot SHA metadata to a caller-supplied expected SHA. It does not
cryptographically attest the entire downloaded repository. Citation hashes check the current
file bytes. Source checkout provenance and an immutable whole-tree manifest need stronger
enforcement before any unattended evaluation. Free-text reasoning entailment is explicitly
unchecked. A valid local predicate can coexist with a misleading statement, and the verifier
still refuses to certify exploitability.

## Sources

1. Supplied `Project proposal slides.pptx (1).pdf`, pages 1-7. Names, goals, selected cases and original schedule.
2. Supplied `Progress milestone slides.pptx.pdf`, pages 1-5. Required milestone sections and difficulty status options.
3. [VEX Bench upstream](https://github.com/steven1518/vex-bench/tree/80cddeac3132826bfd47227ad59b2e6618a681bd), especially README, src/evaluate, src/builder and benchmark/tasks.
4. [FastAPI source at line 247](https://github.com/fastapi/fastapi/blob/febf6b6a52e36e0d64920fb54670ad7fc29b2eaa/fastapi/routing.py#L247).
5. [RAGFlow source at line 30](https://github.com/infiniflow/ragflow/blob/c68767acdde0bbe521fad7f202f01130d7aa4ce3/api/db/db_models.py#L30).
6. [Minikube manifest at line 52](https://github.com/kubernetes/minikube/blob/e7bf515c48f32d7ef63c81fcdba92cccef619016/go.mod#L52).
7. [Starlette advisory](https://github.com/encode/starlette/security/advisories/GHSA-f96h-pmfr-66vw), [PyMySQL advisory](https://github.com/advisories/GHSA-v9hf-5j83-6xpp), [runc advisory](https://github.com/advisories/GHSA-gxmr-w5mj-v8hh). Context only, not automatically verified inputs in version 1.

This report and its slides are an evidence-based milestone draft. The contribution section
requires human confirmation before submission.
