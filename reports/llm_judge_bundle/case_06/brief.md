# CVE-2019-5736 review case

Repository snapshot: https://github.com/kubernetes/minikube/tree/e7bf515c48f32d7ef63c81fcdba92cccef619016

Vulnerability sources for independent checking:
- https://www.jpcert.or.jp/english/at/2019/at190007.html

## Model answer

Proposed category: `uncertain`

Minikube's none-driver documentation references CVE-2019-5736 as a container-escape risk, but does not identify affected versions. The Go manifest requires github.com/opencontainers/runc v1.1.14, and the ISO build pins runc v1.1.15. The January 2019 runc entry in go.sum is a go.mod checksum, not evidence that the corresponding source is selected. Separately, the kicbase Dockerfile installs containerd.io and cri-o-runc without pinning their package versions in those instructions. External advisory lookups were blocked, so the affected range could not be verified. The repository evidence establishes runc declarations but does not establish whether an affected implementation is present.

## Questions to judge

- **advisory_scope**: Which advisory source identifies the affected component, versions, operation, and trigger?
- **unresolved_precondition**: Which exact exploitability precondition remains unresolved?

## Cited source lines

### c1: `site/content/en/docs/drivers/none.md:31-31`

Source at pinned commit: https://github.com/kubernetes/minikube/blob/e7bf515c48f32d7ef63c81fcdba92cccef619016/site/content/en/docs/drivers/none.md#L31-L31

```text
* Containers may be able to execute arbitrary code on your host, by using container escape vulnerabilities such as [CVE-2019-5736](https://access.redhat.com/security/vulnerabilities/runcescape). Please keep your release of minikube up to date.
```

### c2: `go.mod:52-52`

Source at pinned commit: https://github.com/kubernetes/minikube/blob/e7bf515c48f32d7ef63c81fcdba92cccef619016/go.mod#L52-L52

```text
	github.com/opencontainers/runc v1.1.14
```

### c3: `go.sum:1332-1332`

Source at pinned commit: https://github.com/kubernetes/minikube/blob/e7bf515c48f32d7ef63c81fcdba92cccef619016/go.sum#L1332-L1332

```text
github.com/opencontainers/runc v0.0.0-20190115041553-12f6a991201f/go.mod h1:qT5XzbpPznkRYVz/mWwUaVBUv2rmF59PVA73FjuZG0U=
```

### c4: `deploy/iso/minikube-iso/package/runc-master/runc-master.mk:7-10`

Source at pinned commit: https://github.com/kubernetes/minikube/blob/e7bf515c48f32d7ef63c81fcdba92cccef619016/deploy/iso/minikube-iso/package/runc-master/runc-master.mk#L7-L10

```text
RUNC_MASTER_VERSION = v1.1.15
RUNC_MASTER_COMMIT = bc20cb4497af9af01bea4a8044f1678ffca2745c
RUNC_MASTER_SITE = https://github.com/opencontainers/runc/archive
RUNC_MASTER_SOURCE = $(RUNC_MASTER_VERSION).tar.gz
```

### c5: `deploy/kicbase/Dockerfile:159-159`

Source at pinned commit: https://github.com/kubernetes/minikube/blob/e7bf515c48f32d7ef63c81fcdba92cccef619016/deploy/kicbase/Dockerfile#L159-L159

```text
    clean-install docker-ce docker-ce-cli containerd.io docker-buildx-plugin
```

### c6: `deploy/kicbase/Dockerfile:213-213`

Source at pinned commit: https://github.com/kubernetes/minikube/blob/e7bf515c48f32d7ef63c81fcdba92cccef619016/deploy/kicbase/Dockerfile#L213-L213

```text
    clean-install cri-o cri-o-runc; fi
```

## Model claims

- **cl1** (c1; local check: `verified_local_predicate`): The none-driver documentation cites CVE-2019-5736 in a container-escape warning.

- **cl2** (c2, c3; local check: `requires_review`): The Go manifest declares runc v1.1.14; the older go.mod checksum alone does not establish selection of that older source.

- **cl3** (c4; local check: `requires_review`): The ISO build recipe selects the upstream runc v1.1.15 archive.

- **cl4** (c5, c6; local check: `requires_review`): The kicbase install instructions name containerd.io and cri-o-runc without exact package versions, so those lines do not establish the resolved runtime versions.

The exact packet is `packet.json`. `integrity_valid` checks quoted bytes,
not whether a source supports the security conclusion. Return one filled
`annotation.json` based on `annotation.template.json`.
