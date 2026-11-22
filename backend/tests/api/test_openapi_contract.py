"""The generated OpenAPI schema is the response contract (ADR-0004).

Every operation's success (2xx) response must carry a schema that references a
component model (`$ref`), either directly or as the `items` of an array — a
list of one model is typed. A route that returns a bare `dict` is documented
as the empty object — `{"type": "object", "additionalProperties": true}` —
which tells a client nothing, and a field dropped from the body tomorrow would
not change the schema, so nothing would notice. A schema with no `$ref` at the
top or as the array's items is an offender.

The route list is read from the application's own schema, not held here: a
route added tomorrow is walked without this file being touched, and an
untyped one fails at write time. The schema comes from a fresh `create_app()`
rather than the module-level `app` the other tests share and mount their own
temporary routes on, so what is walked is the application as shipped and the
result does not depend on which tests ran before this one. A response that
declares no body at all is reported the same way as an untyped one; no route
answers one today, and giving it a different treatment is a decision for
whoever adds the first.
"""

from typing import Any

import pytest

from gameframework.main import create_app

_HTTP_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}


def _success_responses(spec: dict[str, Any]) -> list[tuple[str, str, str, dict[str, Any]]]:
    """Every 2xx response of every operation, as (METHOD, path, status, response)."""
    found: list[tuple[str, str, str, dict[str, Any]]] = []
    for path, item in spec["paths"].items():
        for method, operation in item.items():
            if method not in _HTTP_METHODS:
                continue
            for status, response in operation["responses"].items():
                if status.startswith("2"):
                    found.append((method.upper(), path, status, response))
    return found


def _references_a_model(schema: dict[str, Any]) -> bool:
    if "$ref" in schema:
        return True
    return schema.get("type") == "array" and "$ref" in schema.get("items", {})


def test_every_success_response_references_a_component_model() -> None:
    spec = create_app().openapi()
    operations = [
        (method.upper(), path)
        for path, item in spec["paths"].items()
        for method in item
        if method in _HTTP_METHODS
    ]
    # A walk that finds nothing would pass vacuously.
    assert operations, "the application's OpenAPI schema declares no operations"

    successes = _success_responses(spec)
    covered = {(method, path) for method, path, _, _ in successes}
    offenders: list[str] = [
        f"{method} {path}: declares no success response"
        for method, path in operations
        if (method, path) not in covered
    ]
    for method, path, status, response in successes:
        content = response.get("content")
        if not content:
            offenders.append(f"{method} {path} -> {status}: success response has no body")
            continue
        for media_type, body in content.items():
            if not _references_a_model(body.get("schema", {})):
                offenders.append(
                    f"{method} {path} -> {status} ({media_type}): "
                    f"schema is not a component reference: {body.get('schema')}"
                )

    assert not offenders, (
        f"{len(offenders)} of {len(operations)} operations have no response model:\n"
        + "\n".join(offenders)
    )


@pytest.mark.parametrize(
    ("schema", "typed"),
    [
        ({"$ref": "#/components/schemas/UserOut"}, True),
        ({"type": "array", "items": {"$ref": "#/components/schemas/UserOut"}}, True),
        ({"type": "array", "items": {"type": "object", "additionalProperties": True}}, False),
        ({"type": "array", "items": {}}, False),
        ({"type": "object", "additionalProperties": True}, False),
        ({}, False),
    ],
)
def test_a_list_of_one_model_is_typed_and_nothing_untyped_is(
    schema: dict[str, Any], typed: bool
) -> None:
    """The rule the walk applies, held apart from the application: no route
    answers a bare array today (lists are `items` envelopes), so the walk
    alone never exercises the array branch."""
    assert _references_a_model(schema) is typed
