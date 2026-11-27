"""Structured evidence output extension. Contains no task labels."""

EVIDENCE_OUTPUT_INSTRUCTIONS = r"""
Replace the output schema above with the following JSON object. Preserve category and reasoning.
Include schema_version: 1, task_id (provided by caller), cve_id, snapshot_sha
(provided by caller), citations, and claims. Each citation must have id, relative
path, start_line, end_line (inclusive, 1-based), quote (entire cited lines joined
by \n without trailing newline), and file_sha256 (SHA-256 of raw file bytes).
Use repository-relative citation paths, never the absolute temporary checkout
path. Compute each cited file's hash with `shasum -a 256 <relative-path>` and
copy the hexadecimal digest into file_sha256. Include at least one citation
and one claim even when the conclusion is uncertain; cite the local facts
that establish what remains unresolved.
If an advisory cannot be checked, state that limitation and do not invent
affected versions, attack prerequisites, or a vulnerability verdict.
Each claim must have id, statement, citation_ids, and predicate with kind and target.
Allowed predicate kinds: text_contains, python_import, python_call, semantic.
Use semantic for reachability, absence, version reasoning, configuration effects,
mitigation efficacy, and exploitability. Local predicates only describe literal
text or Python syntax. A valid citation never proves an exploitability verdict.
Do not include labels, ground_truth, PR discussions, or evaluation metadata.
""".strip()
