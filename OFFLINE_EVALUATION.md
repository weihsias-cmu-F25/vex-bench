# Three-case evaluation status

This is the reproducible result available without a model provider. It is not
an OpenCode baseline or a measurement of exploitability classification accuracy.

## Completed offline checks

The pinned FastAPI, RAGFlow, and Minikube source snapshots are present. Running
`python scripts/demo_evidence.py` against those snapshots produces 15 authored
evidence examples: nine `unsupported` (fabricated quote, missing file, or absent
local predicate) and six `needs_review` (real local fact or semantic overclaim).
The verifier checks local evidence but abstains on the security conclusion.
The three semantic-overclaim examples can each produce a label-free review
packet with `vex-bench review prepare`. No human annotations have been collected.

The test suite passes 51 tests. No model was called in the authored demo, so
there are no baseline predictions, accuracy scores, token counts, or model costs.

## Live-run prerequisites checked

`python scripts/check_baseline.py` writes a machine-readable readiness record to
`results/evidence_demo/baseline_preflight.json` without inspecting credentials.
On this Mac, Docker Desktop started and its engine reported version 23.0.5.
The Python base image built, but both required OpenCode runner images are absent.
The Python OpenCode image build failed while committing a layer with `read-only
file system`; a legacy-builder retry failed while creating a build directory
with the same error. This indicates Docker's image storage needs repair before
the runner images can be built. The three source snapshots are ready.

The local OpenCode provider files `env/opencode/opencode.env` and
`env/opencode/opencode.json` are absent. There is no available Azure model key
for this experiment. GitHub access does not supply model-provider credentials.

## Smallest remaining experiment

After Docker storage works and a supported model provider is configured, build
`vex-bench-python-opencode:latest` and `vex-bench-go-opencode:latest`. Run
`milestone_demo` once with `evidence_v1`, then once with `--feedback-rounds 1`
using the same OpenCode model and settings. Parse and score both runs with the
existing `evaluate parse` and `evaluate metrics` commands in the README.
Report the three raw predictions, verifier decisions, citation validity,
revision transitions, total tokens, and estimated cost. Treat semantic support
as unmeasured until independent reviewers complete the review packets.
