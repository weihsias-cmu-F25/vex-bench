# Three-case OpenCode pilot receipt

This directory contains selected outputs from the November 26, 2026 live
baseline. The [`manifest.json`](manifest.json) identifies the model, prompt,
and SHA-256 hashes of the original raw JSONL files kept locally under
`results/chatgpt_pilot/`.

- `answers/`: the three final structured JSON answers extracted from OpenCode.
- `evidence_reports/`: mechanical verifier results for those answers.
- `review_packets/` and `review_annotation_templates/`: label-free materials
  for independent semantic review. Reviewers should use these before viewing
  benchmark labels or aggregate accuracy.
- `baseline_metrics.json`: metrics from the live baseline.
- `feedback_replay_metrics.json`: metrics from reusing those same answers in an
  offline feedback-policy replay with **zero new model calls**. This does not
  measure an independent assisted run.

The original tool transcripts and local OpenCode session database are omitted.
The verifier's valid citations establish only source integrity and narrow local
facts; every case still needs semantic review. See
[`OFFLINE_EVALUATION.md`](../../OFFLINE_EVALUATION.md) for interpretation and
remaining work.

[`AI_PRELIMINARY_REVIEW.md`](AI_PRELIMINARY_REVIEW.md) links the relevant
maintainer advisories and records the unresolved security questions. It is not
an independent human annotation.
