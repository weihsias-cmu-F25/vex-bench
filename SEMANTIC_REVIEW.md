# Semantic evidence review protocol

The verifier confirms citation bytes and narrow local syntax. It does not
establish whether an affected dependency is reachable by an attacker or whether
a defense blocks the exploit. VEX Bench itself notes that call graphs and
reachability do not establish exploitability by themselves
([paper](https://arxiv.org/html/2609.08040v1)). This protocol records the
remaining judgments as **human evidence review**, separate from the benchmark
label and the agent's raw prediction.

## Prepare and score

`evaluate parse --prompt evidence_v1` automatically creates `review_packet.json`
and `review_annotation.template.json` next to each result whose verifier
decision is `needs_review`. For a standalone explanation:

```bash
uv run vex-bench review prepare \
  --repo benchmark/repos/fastapi/fastapi/febf6b6a52e36e0d64920fb54670ad7fc29b2eaa \
  --input examples/evidence/fastapi-semantic_overclaim.input.json \
  --snapshot-sha febf6b6a52e36e0d64920fb54670ad7fc29b2eaa \
  --output results/semantic_review_demo/fastapi.packet.json
```

Copy the generated `*.annotation.template.json` to a new file. Fill in a
reviewer ID and one judgment for every obligation. Use:

- `supported` only when the cited source and advisory evidence jointly answer
  the obligation;
- `contradicted` when evidence shows the proposed explanation is wrong; or
- `insufficient` when a necessary fact remains unestablished.

Every judgment needs a nonblank rationale. `supported` and `contradicted` also
need `source_refs`: citation IDs from the packet or HTTPS advisory URLs. The
scorer checks the packet hash, all obligation IDs, and reference syntax. It does
**not** read external URLs or decide whether the reviewer's reasoning is true.

```bash
uv run vex-bench review score \
  --packet results/semantic_review_demo/fastapi.packet.json \
  --annotation results/semantic_review_demo/fastapi.annotation.json \
  --output results/semantic_review_demo/fastapi.review.json
```

The packet omits benchmark `ground_truth` and `pr_url`. Reviewers should record
their judgment before consulting the benchmark label or reference PR. The hash
detects a changed packet during scoring; it is not a signature or an attestation
of the source checkout. The reviewer ID is self-reported; the scorer cannot
attest who wrote an annotation. A final `supported` value means the annotation
marks every evidence obligation supported. It is not an automated
exploitability certificate. Use independent reviewers and resolve disagreements
before reporting evidence-support rates.

## What reviewers must establish

The `false_positive` category requires an authoritative vulnerability record
establishing CVE status and the actual affected package. Other categories
require a public advisory identifying the affected component, versions,
operation, and trigger. For categories that assume vulnerable code is present,
reviewers must also establish the resolved dependency version. The packet then
asks category-specific questions:

| Proposed conclusion | Key review obligation |
| --- | --- |
| `vulnerable` | Trace attacker-controlled input to the vulnerable operation and assess relevant mitigations. |
| `code_not_reachable` | Identify the vulnerable operation and rule out a relevant path from first-party entry points, including dynamic calls and configuration. |
| Protected categories | Show that the proposed control is active on the affected path and effective against the advisory's trigger. |
| `code_not_present` | Check resolved dependencies, vendored copies, and build paths for the affected component. |
| `uncertain` | Name the unresolved precondition instead of implying that uncertainty means safety. |

A single import, call, or manifest line cannot discharge a whole-program
obligation. A negative reachability conclusion needs particular care because
searching one symbol or file does not rule out dynamic dispatch, aliases, or
configuration-dependent paths.

## Three selected cases

These are review prompts for the pinned snapshots, not new exploitability
judgments:

| Case | Verified local fact | Semantic question to investigate |
| --- | --- | --- |
| FastAPI / CVE-2024-47874 | `fastapi/routing.py:247` has `request.form()`. | Does the resolved Starlette version fall in the [multipart advisory's affected range](https://github.com/Kludex/starlette/security/advisories/GHSA-f96h-pmfr-66vw), and can attacker-supplied form data reach this parser in the relevant deployment? |
| RAGFlow / CVE-2024-36039 | `api/db/db_models.py:30` imports `PooledMySQLDatabase`. | Does untrusted input reach PyMySQL's `escape_dict` key handling described in the [PyMySQL advisory](https://github.com/advisories/GHSA-v9hf-5j83-6xpp)? The import alone does not show this. |
| Minikube / CVE-2019-5736 | `go.mod:52` declares `runc v1.1.14`. | Which runc binary is actually used by supported deployments, and do the [runc advisory's execution preconditions](https://github.com/advisories/GHSA-gxmr-w5mj-v8hh) apply? The manifest line is not a runtime inventory. |

The authored examples in `examples/evidence/` demonstrate verifier behavior.
They are not model outputs or blinded human annotations. Actual evidence
quality comparisons require real agent runs and completed review files.
