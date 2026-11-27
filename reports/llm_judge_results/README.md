# External LLM-judge annotations

On November 27, 2026, six annotations were received in a ZIP and matched to
the six blinded packets in [`llm_judge_bundle`](../llm_judge_bundle/README.md).
All six passed the project's `score_review` structure, packet-hash, obligation,
and source-reference syntax checks. The ZIP SHA-256 and full per-case mapping
are in [`summary.json`](summary.json). The original annotations and generated
scores are preserved in `annotations/` and `scores/`.

The self-reported reviewer ID in every annotation is `llm-judge/gemini/2.5`.
These are **one AI judge's assessments**, not independent human or expert
review. The scoring code does not check whether a URL is reachable, whether a
rationale is true, or whether a security conclusion follows from the cited
source.

| Case | Project | Model run | Advisory scope | Unresolved precondition | Overall |
| --- | --- | --- | --- | --- | --- |
| 01 | FastAPI | Baseline | insufficient | insufficient | insufficient |
| 02 | RAGFlow | Independent feedback run | insufficient | insufficient | insufficient |
| 03 | Minikube | Baseline | insufficient | insufficient | insufficient |
| 04 | FastAPI | Independent feedback run | insufficient | supported | insufficient |
| 05 | RAGFlow | Baseline | insufficient | insufficient | insufficient |
| 06 | Minikube | Independent feedback run | insufficient | insufficient | insufficient |

Thus the judge marked all six answers `insufficient`: 0/6 advisory-scope
obligations and 1/6 unresolved-precondition obligations were `supported`. In
several rationales, `insufficient` reflects that the judge or original model
could not retrieve an advisory, not that the cited local facts were false.
For example, case 01 says the reviewer could not open the Starlette advisory,
while case 04 uses a GitHub advisory for the same CVE. The single supported
judgment in case 04 also relies on an external advisory and an unpinned-version
inference beyond the cited snippets. A human should inspect that rationale
before treating it as evidence quality.

All six model answers proposed `uncertain`, so these annotations concern the
quality of the explanations for uncertainty. They do not supply ground-truth
exploitability labels. Neither three-case model run triggered a feedback
revision, so differences between their answers cannot be attributed to the
repair loop. Do not report 0/6 as a general explanation-quality rate from a
representative sample or as an improvement estimate.
