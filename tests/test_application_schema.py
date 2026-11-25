"""The committed JSON Schema files and the YAML examples stay in step with the models."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from hst.applications import schema
from hst.applications.merge import merge_application
from hst.applications.models import BusinessApplicationDefinition, BusinessApplicationPatch
from hst.applications.yaml_format import canonical_yaml, definition_digest, parse_application_yaml

EXAMPLES = Path(__file__).resolve().parents[1] / "docs" / "examples"
COMPLETE = EXAMPLES / "business-application.yaml"
PARTIAL = EXAMPLES / "business-application-partial.yaml"


@pytest.mark.parametrize(
    "name,generate",
    [
        ("business-application.schema.json", schema.application_json_schema),
        ("business-application-patch.schema.json", schema.patch_json_schema),
    ],
)
def test_committed_schema_equals_the_generator_output(name, generate):
    assert (EXAMPLES / name).read_text(encoding="utf-8") == generate()


def test_schemas_name_the_draft_and_a_versioned_identifier():
    application = json.loads(schema.application_json_schema())
    patch = json.loads(schema.patch_json_schema())
    assert application["$schema"] == patch["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert application["$id"].endswith("/business-application/v2.schema.json")
    assert patch["$id"].endswith("/business-application-patch/v2.schema.json")
    assert application["required"] == ["id", "name"]
    assert patch["required"] == ["id"]


def test_generator_reports_stale_files_and_writes_both(tmp_path, monkeypatch):
    monkeypatch.setattr(schema, "EXAMPLES_DIR", tmp_path)
    assert schema.main([]) == 1
    assert schema.main(["--write"]) == 0
    assert schema.main([]) == 0
    for name, text in schema.schema_files().items():
        assert (tmp_path / name).read_text(encoding="utf-8") == text


def test_generator_writes_to_the_output_directory(tmp_path):
    assert schema.main(["--write", "--output-dir", str(tmp_path)]) == 0
    assert schema.main(["--output-dir", str(tmp_path)]) == 0
    assert sorted(path.name for path in tmp_path.iterdir()) == sorted(schema.schema_files())


def test_complete_example_parses_as_a_complete_definition():
    definition = parse_application_yaml(COMPLETE.read_text(encoding="utf-8"), partial=False)
    assert isinstance(definition, BusinessApplicationDefinition)


def test_partial_example_parses_as_a_patch():
    patch = parse_application_yaml(PARTIAL.read_text(encoding="utf-8"), partial=True)
    assert isinstance(patch, BusinessApplicationPatch)
    assert patch.name is None


@pytest.mark.parametrize(
    "path", sorted(EXAMPLES.glob("business-application*.yaml")), ids=lambda path: path.name
)
def test_example_round_trips_through_canonical_yaml(path):
    """A patch example is applied to the complete example before the round trip."""
    text = path.read_text(encoding="utf-8")
    patch = parse_application_yaml(text, partial=True)
    assert isinstance(patch, BusinessApplicationPatch)
    if patch.name is None:
        base = parse_application_yaml(COMPLETE.read_text(encoding="utf-8"))
        assert isinstance(base, BusinessApplicationDefinition)
        definition = merge_application(base, patch)
    else:
        definition = parse_application_yaml(text)
    exported = canonical_yaml(definition)
    reparsed = parse_application_yaml(exported)
    assert reparsed == definition
    assert definition_digest(reparsed) == definition_digest(definition)
    assert canonical_yaml(reparsed) == exported


def test_the_complete_example_keeps_its_version_1_digest():
    # computed on main before schema version 2 existed
    definition = parse_application_yaml(COMPLETE.read_text(encoding="utf-8"))
    assert isinstance(definition, BusinessApplicationDefinition)
    assert definition.schema_version == 1
    assert definition_digest(definition) == "ab0d9de0952e3ed00d39c0f87de2e8c96a91353162a8da4f97cd8209df1b13b8"


# The fragments of the application schema that schema version 2 adds.
PLACEHOLDER_DEFINITION = {
    "additionalProperties": False,
    "description": "Schema version 2. A described object that is not bound to inventory yet.",
    "properties": {
        "text": {"maxLength": 500, "minLength": 1, "title": "Text", "type": "string"},
        "expected_kind": {
            "anyOf": [
                {
                    "enum": [
                        "device",
                        "interface",
                        "ip",
                        "network",
                        "dns",
                        "service_requirement",
                        "vrf",
                        "identity",
                        "segment",
                    ],
                    "type": "string",
                },
                {"type": "null"},
            ],
            "default": None,
            "title": "Expected Kind",
        },
        "status": {
            "default": "unresolved",
            "enum": ["unresolved", "ambiguous"],
            "title": "Status",
            "type": "string",
        },
        "candidates": {"items": {"type": "string"}, "maxItems": 20, "title": "Candidates", "type": "array"},
        "note": {
            "anyOf": [{"maxLength": 1000, "type": "string"}, {"type": "null"}],
            "default": None,
            "title": "Note",
        },
    },
    "required": ["text"],
    "title": "Placeholder",
    "type": "object",
}
PLACEHOLDER_RULE = {
    "if": {
        "required": ["groups"],
        "properties": {
            "groups": {
                "contains": {
                    "required": ["members"],
                    "properties": {
                        "members": {
                            "contains": {
                                "required": ["placeholder"],
                                "properties": {"placeholder": {"type": "object"}},
                            }
                        }
                    },
                }
            }
        },
    },
    "then": {
        "required": ["schema_version"],
        "properties": {"schema_version": {"const": 2}, "state": {"const": "draft"}},
    },
}
VERSION = {"default": 1, "enum": [1, 2], "title": "Schema Version", "type": "integer"}


def test_the_schemas_publish_version_2_and_the_placeholder():
    application = json.loads(schema.application_json_schema())
    patch = json.loads(schema.patch_json_schema())

    for document in (application, patch):
        assert document["properties"]["schema_version"] == VERSION
        assert document["$defs"]["Placeholder"] == PLACEHOLDER_DEFINITION
        assert document["$defs"]["GroupMember"]["properties"]["placeholder"] == {
            "anyOf": [{"$ref": "#/$defs/Placeholder"}, {"type": "null"}],
            "default": None,
        }
    assert {key: application[key] for key in ("if", "then")} == PLACEHOLDER_RULE
    assert "if" not in patch


# Copied from `ApplicationMember` and `Placeholder` in web/src/applications/types.ts.
TS_APPLICATION_MEMBER = ["id", "name", "address", "inventory", "context", "placeholder"]
TS_PLACEHOLDER = ["text", "expected_kind", "status", "candidates", "note"]


def test_member_and_placeholder_properties_match_the_typescript_types():
    definitions = json.loads(schema.application_json_schema())["$defs"]

    assert sorted(definitions["GroupMember"]["properties"]) == sorted(TS_APPLICATION_MEMBER)
    assert sorted(definitions["Placeholder"]["properties"]) == sorted(TS_PLACEHOLDER)


def _placeholder_documents() -> dict[str, tuple[dict, bool]]:
    """Each document with whether the models and the published schema accept it."""
    from tests.test_business_applications import COMPLETE as VERSION_1
    from tests.test_business_applications import PLACEHOLDERS

    version_2 = yaml.safe_load(PLACEHOLDERS)
    explicit_null = yaml.safe_load(VERSION_1)
    explicit_null["groups"][1]["members"][0]["placeholder"] = None
    return {
        "complete example": (yaml.safe_load(COMPLETE.read_text(encoding="utf-8")), True),
        "version 1 with placeholder null": (explicit_null, True),
        "version 2 with placeholders": (version_2, True),
        "placeholders at version 1": ({**version_2, "schema_version": 1}, False),
        "placeholders without a version": (
            {key: value for key, value in version_2.items() if key != "schema_version"},
            False,
        ),
        "placeholders in a ready document": ({**version_2, "state": "ready"}, False),
    }


@pytest.mark.parametrize("name", list(_placeholder_documents()))
def test_the_published_schema_enforces_the_placeholder_rules_as_the_models_do(name):
    jsonschema = pytest.importorskip("jsonschema")
    document, accepted = _placeholder_documents()[name]
    validator = jsonschema.Draft202012Validator(json.loads(schema.application_json_schema()))

    assert validator.is_valid(document) is accepted
    try:
        BusinessApplicationDefinition.model_validate(document)
    except ValidationError:
        assert not accepted
    else:
        assert accepted
