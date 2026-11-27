# Independent three-case feedback run

OpenCode CLI 2.4.2 produced three fresh answers on November 26, 2026 with the
same `evidence_v1` prompt, model, source snapshots, and sequential 240-second
settings as the [baseline](../three_case_pilot/README.md). This run used
`--feedback-rounds 1` and a separate output directory.

All three initial answers were `uncertain` with `needs_review` verifier
decisions. The feedback policy correctly requested no revisions, so each run
contains only attempt 0. The three final answers and mechanical verifier
reports are in `answers/` and `evidence_reports/`; `review_packets/` contains
label-free material and `review_annotation_templates/` has blank forms for
independent semantic review. `metrics.json` records
the aggregate results, and `manifest.json` includes the raw JSONL hashes and
per-case feedback summaries. The full raw tool transcripts remain local under
`results/chatgpt_assisted/`.

This is an independent model run, but it does **not** measure whether a repair
prompt improves an invalid answer because none of these answers triggered it.
The separate saved-answer repair demonstration is described in
[`OFFLINE_EVALUATION.md`](../../OFFLINE_EVALUATION.md).
