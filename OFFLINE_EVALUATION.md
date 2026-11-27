# Three-case evaluation status

Evidence cutoff: November 26, 2026. This page separates authored verifier
examples, one live agent baseline, and an offline feedback-policy replay.

## Completed authored checks

The pinned FastAPI, RAGFlow, and Minikube source snapshots are present.
`python scripts/demo_evidence.py` produces 15 manually authored examples:
nine `unsupported` (fabricated quote, missing file, or absent local predicate)
and six `needs_review` (real local fact or semantic overclaim). These examples
demonstrate verifier behavior; they do not measure agent accuracy. The verifier
checks citation bytes and narrow local syntax but does not prove security
conclusions. The full unit suite passes 54 tests.

## Live OpenCode baseline

On November 26, 2026, the `milestone_demo` benchmark ran once on each of its
three cases with OpenCode CLI 2.4.2, `openai/gpt-6.2-sol` through an authorized
ChatGPT login, `evidence_v1` prompt hash `c048a5f709e8`, a 240-second per-case
timeout, and sequential execution. The `opencode_host` adapter copied each
pinned source snapshot into a disposable directory, denied editing, general
shell commands, external-directory access, subagents, and interactive web tools,
and allowed SHA-256 calculation. These are OpenCode tool restrictions, not an
operating-system sandbox. The three cases therefore had no live advisory
retrieval. The login database and CLI install stayed outside this repository.

| Case | Ground-truth category | Raw agent category | Verifier decision | Valid citations |
| --- | --- | --- | --- | ---: |
| FastAPI / CVE-2024-47874 | `vulnerable` | `uncertain` | `needs_review` | 4/4 |
| RAGFlow / CVE-2024-36039 | `code_not_reachable` | `uncertain` | `needs_review` | 4/4 |
| Minikube / CVE-2019-5736 | `code_not_present` | `uncertain` | `needs_review` | 5/5 |

All three outputs were parseable. Thirteen of thirteen citations passed the
mechanical path, line, quote, and file-hash checks. Five claims require semantic
review; six have verified local predicates. All three verifier reports abstain
at `needs_review`, and three label-free review packets were generated. No human
review annotations have been collected.

The upstream binary scorer maps `uncertain` to `not_exploitable`, yielding
2/3 binary accuracy (two true negatives and one false negative). This is a
scoring artifact of that mapping, not evidence that two cases are safe.
Fine-grained category accuracy is 0/3. The recorded token totals are 46,825
input, 111,872 cached input, 4,937 output, and 195 reasoning, for a combined
163,829. The model has no entry in the repository's API pricing table, so the
local metrics cannot give a USD cost. Subscription quota use is not a dollar
cost estimate.

Raw baseline outputs, parsed rows, metrics, evidence reports, and review packets
are under `results/chatgpt_pilot/c048a5f709e8/opencode_host/gpt-6.2-sol/`.
`results/` is intentionally ignored by Git. A selected, credential-free
[pilot receipt](reports/three_case_pilot/README.md) containing the final
answers, reports, review packets, metrics, and raw-output hashes is committed
for team review. Keep the local raw artifacts for a full audit.

## Feedback-policy replay and quota limit

An attempted independent `--feedback-rounds 1` run received OpenCode's
`provider.chatgpt-limit` response (`subscription_sharing_usage_limit_exceeded`)
before producing agent answers. Its error artifacts are preserved under the
local `feedback_1_quota_failed/` directory. We did not retry the model.

`scripts/replay_feedback.py` then reused the three saved baseline outputs as
attempt 0, while making model calls impossible. The verifier policy requested
zero revisions because all three decisions were `needs_review`; the replay has
one attempt per case, zero new model calls, and exactly the baseline predictions,
evidence decisions, and token counts. Its parsed rows and metrics are in
`feedback_1/milestone_demo/`. This verifies the feedback decision for these
answers. It is **not** an independent verifier-assisted agent comparison or
evidence of an accuracy improvement.

## Reproduce or extend

The pinned source snapshots must be downloaded first. Install OpenCode CLI
2.4.2 in a private directory outside the repository and authenticate there:

```bash
npm install --prefix /private/tmp/vex-bench-opencode @opencode/cli@2.4.2
export XDG_DATA_HOME=/private/tmp/vex-bench-opencode/data
export XDG_CONFIG_HOME=/private/tmp/vex-bench-opencode/config
export XDG_CACHE_HOME=/private/tmp/vex-bench-opencode/cache
/private/tmp/vex-bench-opencode/node_modules/.bin/opencode auth login openai --standalone
```

With a usable model quota, run the baseline with:

```bash
VEX_OPENCODE_HOME=/private/tmp/vex-bench-opencode uv run --no-editable vex-bench evaluate run \
  --benchmark milestone_demo --agent opencode_host --model gpt-6.2-sol \
  --prompt evidence_v1 --timeout 240 --repeats 1 --parallel 1 \
  --output-dir results/chatgpt_pilot
uv run --no-editable vex-bench evaluate parse --benchmark milestone_demo \
  --agent opencode_host --model gpt-6.2-sol --prompt evidence_v1 \
  --output-dir results/chatgpt_pilot
uv run --no-editable vex-bench evaluate metrics --benchmark milestone_demo \
  --agent opencode_host --model gpt-6.2-sol --prompt evidence_v1 \
  --output-dir results/chatgpt_pilot
```

`python scripts/replay_feedback.py --model gpt-6.2-sol
--output-dir results/chatgpt_pilot` creates the offline policy replay only when
the destination is empty and each baseline answer requires no revision. Pass
`--feedback-rounds 1` to parse and metrics to inspect it. The script rejects a
case that would actually need another model call.

## Remaining work

1. Have independent reviewers judge the three generated review packets against
   the advisories and source snapshots, then score their annotations using
   [the review protocol](SEMANTIC_REVIEW.md). This is the missing evidence-quality
   measurement.
2. After model quota resets, run an independent assisted experiment on cases
   that actually trigger `invalid_input` or `unsupported`. The current three
   answers do not trigger the repair prompt, so they cannot measure its effect.
3. Expand beyond three selected cases and compare the same model, task set,
   source access, and prompt settings before making general accuracy claims.
   Supplying vetted advisory context would also let the agent assess more than
   local source facts.

The Docker OpenCode path still cannot build its runner images on this Mac
because Docker image storage returned `read-only file system`. The host adapter
allows this limited pilot to proceed without those images or an Azure API key.
