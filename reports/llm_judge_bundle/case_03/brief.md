# CVE-2019-5736 review case

Repository snapshot: https://github.com/kubernetes/minikube/tree/e7bf515c48f32d7ef63c81fcdba92cccef619016

Vulnerability sources for independent checking:
- https://www.jpcert.or.jp/english/at/2019/at190007.html

## Model answer

Proposed category: `uncertain`

The repository links CVE-2019-5736 as a container-escape example, but the public advisory could not be retrieved to verify the affected version range. The Go manifest selects github.com/opencontainers/runc v1.1.14, and the ISO build selects upstream runc v1.1.15. The older January 2019 entry in go.sum is a go.mod checksum, not evidence that the corresponding runtime is built or shipped. The KIC base image also installs containerd.io without an exact package version in the Dockerfile. These files establish which dependencies are declared, but do not establish that an affected runtime is present or reachable.

## Questions to judge

- **advisory_scope**: Which advisory source identifies the affected component, versions, operation, and trigger?
- **unresolved_precondition**: Which exact exploitability precondition remains unresolved?

## Cited source lines

### c1: `go.mod:52-52`

Source at pinned commit: https://github.com/kubernetes/minikube/blob/e7bf515c48f32d7ef63c81fcdba92cccef619016/go.mod#L52-L52

```text
	github.com/opencontainers/runc v1.1.14
```

### c2: `deploy/iso/minikube-iso/package/runc-master/runc-master.mk:7-10`

Source at pinned commit: https://github.com/kubernetes/minikube/blob/e7bf515c48f32d7ef63c81fcdba92cccef619016/deploy/iso/minikube-iso/package/runc-master/runc-master.mk#L7-L10

```text
RUNC_MASTER_VERSION = v1.1.15
RUNC_MASTER_COMMIT = bc20cb4497af9af01bea4a8044f1678ffca2745c
RUNC_MASTER_SITE = https://github.com/opencontainers/runc/archive
RUNC_MASTER_SOURCE = $(RUNC_MASTER_VERSION).tar.gz
```

### c3: `go.sum:1332-1332`

Source at pinned commit: https://github.com/kubernetes/minikube/blob/e7bf515c48f32d7ef63c81fcdba92cccef619016/go.sum#L1332-L1332

```text
github.com/opencontainers/runc v0.0.0-20190115041553-12f6a991201f/go.mod h1:qT5XzbpPznkRYVz/mWwUaVBUv2rmF59PVA73FjuZG0U=
```

### c4: `site/content/en/docs/drivers/none.md:31-31`

Source at pinned commit: https://github.com/kubernetes/minikube/blob/e7bf515c48f32d7ef63c81fcdba92cccef619016/site/content/en/docs/drivers/none.md#L31-L31

```text
* Containers may be able to execute arbitrary code on your host, by using container escape vulnerabilities such as [CVE-2019-5736](https://access.redhat.com/security/vulnerabilities/runcescape). Please keep your release of minikube up to date.
```

### c5: `deploy/kicbase/Dockerfile:159-159`

Source at pinned commit: https://github.com/kubernetes/minikube/blob/e7bf515c48f32d7ef63c81fcdba92cccef619016/deploy/kicbase/Dockerfile#L159-L159

```text
    clean-install docker-ce docker-ce-cli containerd.io docker-buildx-plugin
```

## Model claims

- **cl1** (c1; local check: `verified_local_predicate`): The Go manifest declares github.com/opencontainers/runc v1.1.14.

- **cl2** (c2; local check: `requires_review`): The ISO recipe selects the upstream runc v1.1.15 source archive.

- **cl3** (c1, c3; local check: `requires_review`): The January 2019 go.sum record checksums the dependency's go.mod; it does not establish selection of that older runtime.

- **cl4** (c4, c5; local check: `requires_review`): The local documentation names the CVE without giving an affected version range, and the KIC install command does not pin containerd.io to an exact package version.

The exact packet is `packet.json`. `integrity_valid` checks quoted bytes,
not whether a source supports the security conclusion. Return one filled
`annotation.json` based on `annotation.template.json`.
