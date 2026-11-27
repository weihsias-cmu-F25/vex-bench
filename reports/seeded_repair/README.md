# Saved-answer repair demonstration

This one-case engineering demonstration begins with a **real earlier OpenCode
FastAPI answer**. That answer was generated under an older prompt and failed
the evidence schema because it supplied no citations. It was reused as attempt
0; the current `evidence_v1` prompt and verifier feedback were then sent to
OpenCode for one live repair attempt. Because the first and repair prompts
differ, this is **not a controlled before/after model comparison**.

| Attempt | Verifier decision | Valid citations | Raw category |
| --- | --- | ---: | --- |
| Saved answer | `invalid_input` | 0 | `uncertain` |
| Live repair | `needs_review` | 7/7 | `uncertain` |

The repair supplied valid source citations and corrected the schema. It did
not establish the exploitability conclusion, which still needs semantic
review. `initial_answer.json`, `revised_answer.json`, and their verifier reports
allow inspection of the change. Temporary checkout paths in the committed
initial answer were replaced with `<temporary-source>/`; its original raw
JSONL SHA-256 is retained in the manifest. The revised answer's label-free review
packet and blank annotation template are also included. `manifest.json`
records raw-output hashes, token usage, and the prompt-provenance limitation;
full JSONL transcripts remain under the ignored local `results/` directory.

Re-run the demonstration with `scripts/run_seeded_repair.py` using the saved
JSONL seed, if it is still available locally. The script checks that the seed
actually requests revision and supports resuming a failed repair attempt.
