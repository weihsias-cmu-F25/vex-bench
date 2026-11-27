# CVE-2024-47874 review case

Repository snapshot: https://github.com/fastapi/fastapi/tree/febf6b6a52e36e0d64920fb54670ad7fc29b2eaa

Vulnerability sources for independent checking:
- https://github.com/Kludex/starlette/security/advisories/GHSA-f96h-pmfr-66vw

## Model answer

Proposed category: `uncertain`

The advisory could not be checked because external lookup was blocked, so the affected versions and prerequisites could not be verified. The snapshot declares Starlette >=0.37.2,<0.41.0, but no lockfile was found that selects an exact version. FastAPI's first-party routing code imports Starlette's Request and calls request.form() on incoming requests to form-body routes. That establishes a path to form parsing, but not that this snapshot resolves to an affected parser.

## Questions to judge

- **advisory_scope**: Which advisory source identifies the affected component, versions, operation, and trigger?
- **unresolved_precondition**: Which exact exploitability precondition remains unresolved?

## Cited source lines

### c1: `pyproject.toml:43-44`

Source at pinned commit: https://github.com/fastapi/fastapi/blob/febf6b6a52e36e0d64920fb54670ad7fc29b2eaa/pyproject.toml#L43-L44

```text
dependencies = [
    "starlette>=0.37.2,<0.41.0",
```

### c2: `fastapi/routing.py:63-63`

Source at pinned commit: https://github.com/fastapi/fastapi/blob/febf6b6a52e36e0d64920fb54670ad7fc29b2eaa/fastapi/routing.py#L63-L63

```text
from starlette.requests import Request
```

### c3: `fastapi/routing.py:234-247`

Source at pinned commit: https://github.com/fastapi/fastapi/blob/febf6b6a52e36e0d64920fb54670ad7fc29b2eaa/fastapi/routing.py#L234-L247

```text
    is_body_form = body_field and isinstance(body_field.field_info, params.Form)
    if isinstance(response_class, DefaultPlaceholder):
        actual_response_class: Type[Response] = response_class.value
    else:
        actual_response_class = response_class

    async def app(request: Request) -> Response:
        response: Union[Response, None] = None
        async with AsyncExitStack() as file_stack:
            try:
                body: Any = None
                if body_field:
                    if is_body_form:
                        body = await request.form()
```

### c4: `fastapi/routing.py:569-574`

Source at pinned commit: https://github.com/fastapi/fastapi/blob/febf6b6a52e36e0d64920fb54670ad7fc29b2eaa/fastapi/routing.py#L569-L574

```text
        self.app = request_response(self.get_route_handler())

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        return get_request_handler(
            dependant=self.dependant,
            body_field=self.body_field,
```

## Model claims

- **cl1** (c1; local check: `requires_review`): The Starlette dependency is declared as a range, not an exact version.

- **cl2** (c2; local check: `verified_local_predicate`): The routing module imports Request from starlette.requests.

- **cl3** (c2, c3, c4; local check: `requires_review`): Incoming requests to form-body routes reach request.form() through the registered route handler.

The exact packet is `packet.json`. `integrity_valid` checks quoted bytes,
not whether a source supports the security conclusion. Return one filled
`annotation.json` based on `annotation.template.json`.
