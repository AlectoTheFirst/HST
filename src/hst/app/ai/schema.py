"""Provider projections of catalogue schemas. Argument validation does not use a projection."""

from __future__ import annotations

from copy import deepcopy
from typing import Any


def provider_input_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """A catalogue mode union as an object that Claude upstreams accept.

    Anthropic, including through OpenRouter and Bedrock, rejects a root ``oneOf``.
    """
    if schema.get("type") != "object" or "oneOf" not in schema or "discriminator" not in schema:
        return schema

    projected = deepcopy(schema)
    discriminator = projected.pop("discriminator")["propertyName"]
    branches = projected.pop("oneOf")
    fields: dict[str, list[dict[str, Any]]] = {}
    modes: list[str] = []
    for branch in branches:
        variant = projected["$defs"][branch["$ref"].rsplit("/", 1)[-1]]
        properties = variant["properties"]
        mode = properties[discriminator]["const"]
        required = [name for name in variant.get("required", []) if name != discriminator]
        optional = [name for name in properties if name != discriminator and name not in required]
        modes.append(
            f"{discriminator}={mode}: required fields: {', '.join(required) or 'none'}; "
            f"optional fields: {', '.join(optional) or 'none'}."
        )
        for name, field in properties.items():
            if name != discriminator and field not in fields.setdefault(name, []):
                fields[name].append(field)

    # A shared field lists the schema of every mode in `anyOf`.
    projected["properties"] = {
        discriminator: {
            **projected["properties"][discriminator],
            "description": "Select the mode and supply only its fields. " + " ".join(modes),
        },
        **{
            name: variants[0] if len(variants) == 1 else {"anyOf": variants}
            for name, variants in fields.items()
        },
    }
    return projected
