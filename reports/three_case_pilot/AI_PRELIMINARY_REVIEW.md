# Preliminary semantic review of the live answers

Prepared November 26, 2026 by an AI assistant after the three model runs. This
is source research for a later reviewer, **not an independent human annotation
or an evidence-support score**. Benchmark labels were visible during project
setup. The agent itself had no web access in the pilot; the advisory sources
below were checked afterward. The three agent answers all chose `uncertain`.

## FastAPI / CVE-2024-47874

The [Starlette maintainer advisory](https://github.com/Kludex/starlette/security/advisories/GHSA-f96h-pmfr-66vw)
describes unbounded buffering of multipart text fields without a filename and
lists 0.40.0 as patched. Its affected-version field says `<0.39.2`, leaving a
gap before 0.40.0; the [GitHub advisory database record](https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2024/10/GHSA-f96h-pmfr-66vw/GHSA-f96h-pmfr-66vw.json)
records the affected range as `<0.40.0`. This discrepancy should be checked by
a reviewer before claiming a precise boundary.

The pinned FastAPI snapshot declares `starlette>=0.37.2,<0.41.0`
([answer citation c1](review_packets/fastapi-fastapi-febf6b6-CVE-2024-47874.json))
and calls `request.form()` for form-body routes (c3). The declared range permits
both versions before 0.40.0 and version 0.40.0. No exact resolved Starlette
version or particular deployed application is established by those citations.
The answer's uncertainty about the resolved version is therefore supported by
its cited local facts. The cited route code supports a potential form-parsing
path, but a reviewer must still establish an affected installation and an
attacker-accessible form endpoint before affirming exploitability.

## RAGFlow / CVE-2024-36039

The [PyMySQL maintainer's 1.1.1 release](https://github.com/PyMySQL/PyMySQL/releases/tag/v1.1.1)
says the 2024 fix prohibits dict parameters to `Cursor.execute()`, because an
untrusted dict was the attack vector. The [GitHub reviewed advisory](https://github.com/advisories/GHSA-v9hf-5j83-6xpp)
identifies versions before 1.1.1 as affected.

The snapshot pins PyMySQL 1.1.0 in `requirements.txt` (c1), and the cited
Dockerfile installs that requirements file (c2). This supports presence of an
affected declared version for that build path. The cited first-party database
call passes a tuple of lock parameters (c4); it does not establish a dict
parameter with untrusted keys. We searched the snapshot's `api/` and `rag/`
trees for `escape_dict`, PyMySQL calls, and direct `execute_sql` calls, but a
text search alone cannot exclude dynamic calls through Peewee. The exact
unresolved question is whether any entry point can cause an untrusted dict to
reach the vulnerable PyMySQL operation. The answer's `uncertain` category is a
cautious statement of that missing proof, not proof of non-reachability.

## Minikube / CVE-2019-5736

[JPCERT/CC's advisory](https://www.jpcert.or.jp/english/at/2019/at190007.html)
identifies runc 1.0-rc6 and earlier as affected and describes the malicious
container execution prerequisite. The pinned Go manifest declares runc v1.1.14
(c1), and the ISO recipe selects v1.1.15 (c2); these declared versions are
newer than the affected range. The old `go.sum` entry in c3 hashes a `go.mod`
file and does not by itself select a runtime binary.

The cited KIC Dockerfile installs `containerd.io` without an exact version
(c5); another branch in that Dockerfile can install `cri-o-runc`. The cited
files do not inventory the runc binary in every built image or deployed
driver. They support rejecting an inference from the old `go.sum` line, but
they do not fully establish the agent's unresolved runtime-version question.
The answer's uncertainty is defensible for that broader deployment question;
it should not be reported as evidence that the two explicitly selected runc
versions are vulnerable.

## What remains for independent review

The [review packets](review_packets/) contain each model answer's citations
and obligations without benchmark labels. A human reviewer should inspect
them and the sources independently, record one judgment and rationale per
obligation in the matching annotation template, and run `vex-bench review
score`. The scorer validates the annotation format and packet hash; it does
not verify the reviewer's security reasoning. This preliminary note must not
be counted as a human-reviewed evidence-quality result.
