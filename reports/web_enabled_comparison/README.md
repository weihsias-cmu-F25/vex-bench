# Web-enabled comparison receipt

This directory preserves the November 27, 2026 three-case comparison described
in [`WEB_ENABLED_EVALUATION.md`](../../WEB_ENABLED_EVALUATION.md). The
`baseline_answers/` and `evidence_answers/` directories hold the final JSON
answers. `evidence_reports/` contains mechanical verification results;
`review_packets/` and `review_annotation_templates/` contain label-free
semantic-review material. The two metrics files use the corrected five-label
scorer. `manifest.json` records the prompt hashes, tool-use counts, benchmark
labels, predicted categories, and SHA-256 hashes of the local raw JSONL files.

The review packets omit benchmark labels; keep `manifest.json` and this report
away from a reviewer until after annotation. The full tool transcripts are
ignored by Git and remain in `results/web_enabled_baseline/` and
`results/web_enabled_pilot/` on the runner machine.
