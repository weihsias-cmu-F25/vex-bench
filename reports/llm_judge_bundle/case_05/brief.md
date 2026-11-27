# CVE-2024-36039 review case

Repository snapshot: https://github.com/infiniflow/ragflow/tree/c68767acdde0bbe521fad7f202f01130d7aa4ce3

Vulnerability sources for independent checking:
- https://github.com/PyMySQL/PyMySQL/releases/tag/v1.1.1
- https://github.com/advisories/GHSA-v9hf-5j83-6xpp

## Model answer

Proposed category: `uncertain`

The snapshot pins PyMySQL 1.1.0 in requirements.txt:94, and Dockerfile.scratch:38 instructs pip to install that manifest. First-party code constructs a Peewee PooledMySQLDatabase and issues parameterized queries for database locks (api/db/db_models.py:275-276, 288-289). These facts establish a dependency declaration and a database call path, but not reachability of the CVE-specific behavior. Public advisory lookup was blocked, and no local advisory was found, so the affected versions and the conditions needed to reach the vulnerable behavior could not be verified.

## Questions to judge

- **advisory_scope**: Which advisory source identifies the affected component, versions, operation, and trigger?
- **unresolved_precondition**: Which exact exploitability precondition remains unresolved?

## Cited source lines

### c1: `requirements.txt:94-94`

Source at pinned commit: https://github.com/infiniflow/ragflow/blob/c68767acdde0bbe521fad7f202f01130d7aa4ce3/requirements.txt#L94-L94

```text
PyMySQL==1.1.0
```

### c2: `Dockerfile.scratch:38-38`

Source at pinned commit: https://github.com/infiniflow/ragflow/blob/c68767acdde0bbe521fad7f202f01130d7aa4ce3/Dockerfile.scratch#L38-L38

```text
RUN conda run -n py11 pip install -i https://mirrors.aliyun.com/pypi/simple/ -r ./requirements.txt
```

### c3: `api/db/db_models.py:275-276`

Source at pinned commit: https://github.com/infiniflow/ragflow/blob/c68767acdde0bbe521fad7f202f01130d7aa4ce3/api/db/db_models.py#L275-L276

```text
        self.database_connection = PooledMySQLDatabase(
            db_name, **database_config)
```

### c4: `api/db/db_models.py:288-289`

Source at pinned commit: https://github.com/infiniflow/ragflow/blob/c68767acdde0bbe521fad7f202f01130d7aa4ce3/api/db/db_models.py#L288-L289

```text
        cursor = self.db.execute_sql(
            "SELECT GET_LOCK(%s, %s)", (self.lock_name, self.timeout))
```

## Model claims

- **cl1** (c1; local check: `verified_local_predicate`): The main Python requirements file pins PyMySQL to 1.1.0.

- **cl2** (c2; local check: `verified_local_predicate`): The scratch build runs pip install with requirements.txt.

- **cl3** (c3; local check: `verified_local_predicate`): First-party code calls PooledMySQLDatabase.

- **cl4** (c4; local check: `verified_local_predicate`): The database lock code calls self.db.execute_sql with a tuple of query parameters.

The exact packet is `packet.json`. `integrity_valid` checks quoted bytes,
not whether a source supports the security conclusion. Return one filled
`annotation.json` based on `annotation.template.json`.
