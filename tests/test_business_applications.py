from __future__ import annotations

import asyncio
import re
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from hst.applications import resolution
from hst.applications.merge import merge_application
from hst.applications.models import (
    BusinessApplicationDefinition,
    DestinationCondition,
    InventoryReference,
    Placeholder,
    RemovalSet,
    stored_definition,
)
from hst.applications.resolution import (
    AddressBinding,
    GraphInventoryReader,
    InventoryCandidate,
    StaticInventoryReader,
    resolve_application,
)
from hst.applications.service import (
    commit_import,
    export_revision,
    preview_import,
    revision_origin,
    save_definition,
)
from hst.applications.validation import validate_application
from hst.applications.yaml_format import (
    ApplicationFormatError,
    canonical_yaml,
    definition_digest,
    normalized_document,
    parse_application_yaml,
)
from hst.assessment.store import MemoryAssessmentStore, RevisionConflict

COMPLETE = """\
schema_version: 1
kind: BusinessApplication
id: checkout-production
name: Checkout
environment: production
services:
  - id: checkout-frontend
    name: Checkout frontend
    connection_ids: [clients-to-frontend, frontend-to-api]
    component_roles:
      - group_id: frontend
        role: endpoint
groups:
  - id: branch-clients
    name: Branch clients
    members:
      - id: private-clients
        address: 10.0.0.0/24
        context: vrf:branch
  - id: frontend
    name: Frontend
    members:
      - id: web-primary
        address: 198.51.100.10
  - id: api
    name: API
    members:
      - id: api-primary
        inventory:
          kind: interface
          uid: interface:api-1
          role: destination
          context: vrf:production
connections:
  - id: clients-to-frontend
    name: Branch access to checkout
    source: branch-clients
    destination: frontend
    protocol: tcp
    destination_ports: [443]
    source_ports: [1024-65535]
    success: session
    source_context: {vrf: 'vrf:branch'}
    destination_condition: {kind: member, member: web-primary}
    mtu: {mode: packet, ip_packet_bytes: 1500, ipv4_df: true}
  - id: frontend-to-api
    name: Frontend to API
    source: frontend
    destination: api
    protocol: tcp
    destination_ports: [8443]
    success: round-trip
    destination_context: {vrf: 'vrf:production'}
    destination_condition:
      kind: threshold
      n: 1
      parts:
        - {kind: member, member: api-primary}
"""


def test_yaml_round_trip_is_canonical_and_semantically_complete():
    definition = parse_application_yaml(COMPLETE)
    exported = canonical_yaml(definition)
    reparsed = parse_application_yaml(exported)
    assert reparsed == definition
    assert definition_digest(reparsed) == definition_digest(definition)
    assert definition.connections[0].source_ports == ["1024-65535"]
    assert definition.connections[0].mtu.ip_packet_bytes == 1500
    assert definition.groups[1].members[0].address == "198.51.100.10"


@pytest.mark.parametrize(
    "body,match",
    [
        ("schema_version: 1\nid: app\nid: duplicate\nname: Bad\n", "duplicate key"),
        ("schema_version: 3\nkind: BusinessApplication\nid: app\nname: Bad\n", "schema_version"),
        ("schema_version: 1\nkind: BusinessApplication\nid: app\nname: Bad\nunknown: true\n", "unknown"),
        ("schema_version: 1\nkind: BusinessApplication\nid: app\nname: &n Bad\ndescription: *n\n", "aliases"),
        ("!!python/object:builtins.object {}", "could not determine a constructor"),
    ],
)
def test_yaml_rejects_unsafe_or_unknown_forms(body, match):
    with pytest.raises(ApplicationFormatError, match=match):
        parse_application_yaml(body)


def test_schema_errors_carry_the_line_and_column_and_keep_the_string_form():
    body = (
        COMPLETE.replace("address: 198.51.100.10", "address: not-an-address")
        .replace("environment: production", "environment: production\nunknown: true")
        .replace("destination_ports: [8443]", "destination_ports: [http]")
    )

    with pytest.raises(ApplicationFormatError) as caught:
        parse_application_yaml(body)

    errors = {error.path: error for error in caught.value.errors}
    assert str(caught.value) == "; ".join(f"{error.path}: {error.message}" for error in caught.value.errors)
    # the key of an unknown field
    assert (errors["unknown"].line, errors["unknown"].column) == (6, 1)
    # a model check of a member points at the list item
    assert (errors["groups.1.members.0"].line, errors["groups.1.members.0"].column) == (24, 9)
    assert "address must be an IPv4/IPv6 address or prefix" in errors["groups.1.members.0"].message
    # a union member name ends the walk at the list item it belongs to
    port = errors["connections.1.destination_ports.0.int"]
    assert (port.line, port.column) == (52, 25)


def test_a_document_level_error_has_no_position():
    body = COMPLETE.replace("source: frontend\n", "source: missing-group\n")

    with pytest.raises(ApplicationFormatError, match="unknown source group missing-group") as caught:
        parse_application_yaml(body)

    (error,) = caught.value.errors
    assert (error.path, error.line, error.column) == ("$", None, None)


@pytest.mark.parametrize(
    "body,line,column,message",
    [
        ("schema_version: 1\nid: app\nid: duplicate\nname: Bad\n", 3, 1, "duplicate key 'id'"),
        ("schema_version: 1\nid: app\nname: Bad\n  owner: x\n", 4, 8, "mapping values are not allowed here"),
        ("id: app\nname: &n Bad\ndescription: *n\n", 3, 14, "YAML aliases are not supported"),
    ],
)
def test_yaml_syntax_errors_carry_their_position(body, line, column, message):
    with pytest.raises(ApplicationFormatError) as caught:
        parse_application_yaml(body)

    (error,) = caught.value.errors
    assert error.path == "$"
    assert (error.line, error.column) == (line, column)
    assert message in error.message
    assert message in str(caught.value)


def test_bound_errors_have_a_structured_form_without_a_position():
    with pytest.raises(ApplicationFormatError) as caught:
        parse_application_yaml("- one\n- two\n")

    assert [error.as_dict() for error in caught.value.errors] == [
        {
            "path": "$",
            "message": "Business Application YAML must contain one mapping document",
            "line": None,
            "column": None,
        }
    ]


@pytest.mark.parametrize("identifier", ["validate", "generations"])
@pytest.mark.parametrize("partial", [False, True])
def test_route_names_are_reserved_application_ids(identifier, partial):
    body = f"schema_version: 1\nkind: BusinessApplication\nid: {identifier}\nname: Reserved\n"

    with pytest.raises(ApplicationFormatError, match="reserved application id") as caught:
        parse_application_yaml(body, partial=partial)

    (error,) = caught.value.errors
    assert (error.path, error.line, error.column) == ("id", 3, 1)


@pytest.mark.parametrize("identifier", ["validate", "generations"])
async def test_a_stored_definition_with_a_reserved_id_stays_readable_and_is_not_saved_again(identifier):
    store = MemoryAssessmentStore()
    stored = {"schema_version": 1, "kind": "BusinessApplication", "id": identifier, "name": "Old"}
    await store.create_application_revision(
        definition=stored, digest=definition_digest(stored), created_by=1, expected_revision=0
    )
    record = await store.get_application(identifier)

    assert BusinessApplicationDefinition.model_validate(record.definition).id == identifier
    assert f"id: {identifier}\n" in export_revision(record)
    renamed = BusinessApplicationDefinition.model_validate({**stored, "name": "New"})
    with pytest.raises(ValueError, match="reserved application id"):
        await save_definition(store, renamed, expected_revision=1, actor=1)
    assert (await store.get_application(identifier)).revision == 1


def _stored_before_choice_scope_removal(definition: BusinessApplicationDefinition) -> dict:
    """`definition` with `choice_scope: unspecified` on each connection."""
    stored = normalized_document(definition)
    stored["connections"] = [{**item, "choice_scope": "unspecified"} for item in stored["connections"]]
    return stored


async def test_a_stored_definition_with_the_removed_choice_scope_is_read_exported_and_merged():
    store = MemoryAssessmentStore()
    definition = parse_application_yaml(COMPLETE)
    stored = _stored_before_choice_scope_removal(definition)
    old_digest = definition_digest(stored)
    await store.create_application_revision(
        definition=stored, digest=old_digest, created_by=1, expected_revision=0
    )
    record = await store.get_application("checkout-production")

    assert stored_definition(record.definition) == definition
    assert export_revision(record) == canonical_yaml(definition)
    assert "choice_scope" not in export_revision(record)
    # the stored record keeps its digest; a read reports no change
    assert (await store.get_application("checkout-production")).digest == old_digest

    async def resolve(value: BusinessApplicationDefinition, revision: int) -> dict:
        return resolve_application(
            value, revision=revision, snapshot={"snapshot": "100"}, reader=StaticInventoryReader({})
        )

    checked = await validate_application(
        store, COMPLETE, mode="merge", snapshot={"snapshot": "100"}, resolve=resolve
    )
    assert checked["errors"] == []

    # a merge import of the same content previews no change and commits one clean revision
    preview = await preview_import(store, COMPLETE, RemovalSet(), "merge")
    assert not any(v for k, v in preview.changes.items() if not k.endswith("_unchanged"))
    assert preview.base_digest == old_digest
    assert preview.result_digest == definition_digest(definition)
    saved = await commit_import(
        store,
        COMPLETE,
        RemovalSet(),
        base_revision=preview.base_revision,
        base_digest=preview.base_digest,
        preview_digest=preview.preview_digest,
        actor=1,
    )
    assert saved.revision == 2
    assert "choice_scope" not in saved.definition["connections"][0]
    assert saved.digest == definition_digest(saved.definition)
    again = await preview_import(store, COMPLETE, RemovalSet(), "merge")
    assert again.no_op is True


def test_the_resolve_tool_reads_a_revision_stored_with_the_removed_choice_scope():
    from hst.twin_tools.apps import resolve_definition

    stored = _stored_before_choice_scope_removal(parse_application_yaml(COMPLETE))
    item = SimpleNamespace(definition=stored, revision=1)

    resolved = resolve_definition(
        GraphReferenceSession({}),
        SimpleNamespace(cts=4000),
        {"snapshot": "4000"},
        item,
        connection_ids=["clients-to-frontend"],
        field="application",
    )

    assert resolved["application"]["id"] == "checkout-production"
    assert [c["readiness"] for c in resolved["connections"]] == ["ready"]


def test_input_that_states_choice_scope_is_refused():
    body = COMPLETE.replace("    success: session\n", "    success: session\n    choice_scope: unspecified\n")
    with pytest.raises(ApplicationFormatError) as caught:
        parse_application_yaml(body)
    assert "connections.0.choice_scope" in {error.path for error in caught.value.errors}
    document = normalized_document(parse_application_yaml(COMPLETE))
    document["connections"][0]["choice_scope"] = "unspecified"
    with pytest.raises(ValidationError, match="choice_scope"):
        BusinessApplicationDefinition.model_validate(document)
    # the stored read drops that one field and nothing else
    document["connections"][0]["colour"] = "blue"
    with pytest.raises(ValidationError, match="colour"):
        stored_definition(document)


async def test_a_generated_digest_is_recorded_only_for_the_owner_of_the_generation():
    store = MemoryAssessmentStore()
    await store.save_application_generation({"id": "gen-1", "created_by": 7, "definition_digest": "d" * 64})

    owner = await revision_origin(store, "import", generation_id="gen-1", actor=7)
    other = await revision_origin(store, "import", generation_id="gen-1", actor=8)
    unknown = await revision_origin(store, "import", generation_id="gen-2", actor=7)

    assert (owner["source"], owner["generated_digest"]) == ("generator", "d" * 64)
    assert (other["source"], other["generation_id"], other["generated_digest"]) == (
        "generator",
        "gen-1",
        None,
    )
    assert (unknown["source"], unknown["generated_digest"]) == ("generator", None)


def test_keyed_merge_retains_omitted_entities_and_removal_checks_references():
    current = parse_application_yaml(COMPLETE)
    patch = parse_application_yaml(
        "schema_version: 1\nkind: BusinessApplication\nid: checkout-production\nowner: network-team\n",
        partial=True,
    )
    merged = merge_application(current, patch)
    assert merged.owner == "network-team"
    assert [connection.id for connection in merged.connections] == [
        "clients-to-frontend",
        "frontend-to-api",
    ]
    with pytest.raises(ValueError, match="unknown destination group"):
        merge_application(current, patch, RemovalSet(groups=["api"]))
    with pytest.raises(ValueError, match="unknown destination member"):
        merge_application(current, patch, RemovalSet(members={"api": ["api-primary"]}))


def test_partial_keyed_merge_preserves_omitted_associations_and_members():
    current = parse_application_yaml(COMPLETE)
    patch = parse_application_yaml(
        """\
schema_version: 1
kind: BusinessApplication
id: checkout-production
services:
  - id: checkout-frontend
    name: Checkout web
groups:
  - id: branch-clients
    name: Branch users
""",
        partial=True,
    )
    merged = merge_application(current, patch)
    assert merged.services[0].name == "Checkout web"
    assert merged.services[0].connection_ids == ["clients-to-frontend", "frontend-to-api"]
    assert merged.groups[0].name == "Branch users"
    assert [member.id for member in merged.groups[0].members] == ["private-clients"]


def test_all_condition_forms_and_overlapping_prefixes_validate():
    definition = parse_application_yaml(COMPLETE)
    document = definition.model_dump(mode="json")
    document["groups"][0]["members"].append(
        {"id": "private-clients-overlap", "address": "10.0.0.128/25", "context": "vrf:branch"}
    )
    document["connections"][1]["destination_condition"] = {
        "kind": "and",
        "parts": [
            {"kind": "member", "member": "api-primary"},
            {
                "kind": "or",
                "parts": [{"kind": "member", "member": "api-primary"}],
            },
        ],
    }
    validated = BusinessApplicationDefinition.model_validate(document)
    condition = validated.connections[1].destination_condition
    assert condition == DestinationCondition.model_validate(
        document["connections"][1]["destination_condition"]
    )
    assert validated.groups[0].members[1].address == "10.0.0.128/25"


async def test_revision_store_is_atomic_noop_and_stale_preview_is_fenced():
    store = MemoryAssessmentStore()
    preview = await preview_import(store, COMPLETE, RemovalSet())
    assert await store.list_applications() == []
    saved = await commit_import(
        store,
        COMPLETE,
        RemovalSet(),
        base_revision=preview.base_revision,
        base_digest=preview.base_digest,
        preview_digest=preview.preview_digest,
        actor=1,
    )
    assert saved.revision == 1
    current_preview = await preview_import(store, COMPLETE, RemovalSet())
    same = await commit_import(
        store,
        COMPLETE,
        RemovalSet(),
        base_revision=1,
        base_digest=saved.digest,
        preview_digest=current_preview.preview_digest,
        actor=1,
    )
    assert same.revision == 1
    stale = await preview_import(
        store, COMPLETE.replace("name: Checkout", "name: Checkout stale"), RemovalSet()
    )
    current = BusinessApplicationDefinition.model_validate(saved.definition)
    current.name = "Concurrent edit"
    await save_definition(store, current, expected_revision=1, actor=2)
    with pytest.raises(RevisionConflict, match="stale"):
        await commit_import(
            store,
            COMPLETE.replace("name: Checkout", "name: Checkout stale"),
            RemovalSet(),
            base_revision=stale.base_revision,
            base_digest=stale.base_digest,
            preview_digest=stale.preview_digest,
            actor=1,
        )
    assert (await store.get_application(saved.id, 1)).definition["name"] == "Checkout"


async def _commit(store, text, mode="merge", removals=None):
    removals = removals or RemovalSet()
    preview = await preview_import(store, text, removals, mode)
    return await commit_import(
        store,
        text,
        removals,
        base_revision=preview.base_revision,
        base_digest=preview.base_digest,
        preview_digest=preview.preview_digest,
        actor=1,
        mode=mode,
    )


async def test_replace_import_of_the_unchanged_export_is_a_no_op():
    store = MemoryAssessmentStore()
    saved = await _commit(store, COMPLETE)
    exported = export_revision(saved)
    preview = await preview_import(store, exported, RemovalSet(), "replace")
    assert preview.no_op is True
    assert preview.result_digest == saved.digest
    assert not any(values for key, values in preview.changes.items() if key.endswith("_removed"))
    same = await _commit(store, exported, "replace")
    assert same.revision == 1


async def test_replace_import_removes_omitted_entities_members_and_fields():
    store = MemoryAssessmentStore()
    await _commit(store, COMPLETE)
    document = parse_application_yaml(COMPLETE).model_dump(mode="json")
    del document["environment"]
    document["connections"] = [item for item in document["connections"] if item["id"] != "frontend-to-api"]
    document["services"][0]["connection_ids"] = ["clients-to-frontend"]
    document["groups"][2]["members"] = []
    edited = canonical_yaml(BusinessApplicationDefinition.model_validate(document))

    merge = await preview_import(store, edited, RemovalSet())
    assert merge.changes["connections_removed"] == []
    assert merge.changes["members_removed"] == []
    assert merge.definition["environment"] == "production"

    replace = await preview_import(store, edited, RemovalSet(), "replace")
    assert replace.no_op is False
    assert replace.changes["connections_removed"] == ["frontend-to-api"]
    assert replace.changes["members_removed"] == ["api:api-primary"]
    assert replace.changes["groups_updated"] == ["api"]
    assert replace.changes["groups_removed"] == []
    assert replace.changes["services_updated"] == ["checkout-frontend"]
    saved = await _commit(store, edited, "replace")
    assert saved.revision == 2
    assert "environment" not in saved.definition
    assert [item["id"] for item in saved.definition["connections"]] == ["clients-to-frontend"]
    assert saved.definition["groups"][2]["members"] == []


async def test_preview_lists_members_removed_by_the_removal_set():
    store = MemoryAssessmentStore()
    document = parse_application_yaml(COMPLETE).model_dump(mode="json")
    document["groups"][1]["members"].append({"id": "web-secondary", "address": "198.51.100.11"})
    await save_definition(
        store, BusinessApplicationDefinition.model_validate(document), expected_revision=0, actor=1
    )
    patch = "schema_version: 1\nkind: BusinessApplication\nid: checkout-production\n"
    preview = await preview_import(store, patch, RemovalSet(members={"frontend": ["web-secondary"]}))
    assert preview.no_op is False
    assert preview.changes["members_removed"] == ["frontend:web-secondary"]


async def test_removal_of_an_absent_member_is_not_listed_and_the_preview_is_a_no_op():
    store = MemoryAssessmentStore()
    await _commit(store, COMPLETE)
    patch = "schema_version: 1\nkind: BusinessApplication\nid: checkout-production\n"
    preview = await preview_import(store, patch, RemovalSet(members={"frontend": ["absent-member"]}))
    assert preview.changes["members_removed"] == []
    assert preview.no_op is True


async def test_merge_preview_token_cannot_commit_a_replace():
    store = MemoryAssessmentStore()
    merge = await preview_import(store, COMPLETE, RemovalSet())
    replace = await preview_import(store, COMPLETE, RemovalSet(), "replace")
    assert merge.result_digest == replace.result_digest
    assert merge.preview_digest != replace.preview_digest
    with pytest.raises(RevisionConflict, match="stale"):
        await commit_import(
            store,
            COMPLETE,
            RemovalSet(),
            base_revision=merge.base_revision,
            base_digest=merge.base_digest,
            preview_digest=merge.preview_digest,
            actor=1,
            mode="replace",
        )
    with pytest.raises(RevisionConflict, match="stale"):
        await commit_import(
            store,
            COMPLETE,
            RemovalSet(),
            base_revision=replace.base_revision,
            base_digest=replace.base_digest,
            preview_digest=replace.preview_digest,
            actor=1,
        )
    assert await store.list_applications() == []


async def test_replace_import_requires_a_complete_definition_without_removals():
    store = MemoryAssessmentStore()
    await _commit(store, COMPLETE)
    partial = "schema_version: 1\nkind: BusinessApplication\nid: checkout-production\nowner: network\n"
    assert (await preview_import(store, partial, RemovalSet())).definition["owner"] == "network"
    with pytest.raises(ApplicationFormatError, match="name"):
        await preview_import(store, partial, RemovalSet(), "replace")
    with pytest.raises(ValueError, match="removals apply only to merge imports"):
        await preview_import(store, COMPLETE, RemovalSet(groups=["api"]), "replace")


async def test_concurrent_revision_writes_create_one_revision():
    store = MemoryAssessmentStore()
    original = parse_application_yaml(COMPLETE)
    await save_definition(store, original, expected_revision=0, actor=1)
    attempts = await asyncio.gather(
        *(
            save_definition(
                store,
                original.model_copy(update={"name": name}),
                expected_revision=1,
                actor=1,
            )
            for name in ("One", "Two")
        ),
        return_exceptions=True,
    )
    assert sum(isinstance(value, RevisionConflict) for value in attempts) == 1
    assert (await store.get_application(original.id)).revision == 2


def test_a_connection_whose_ends_share_no_address_family_is_not_ready():
    # The IPv4 frontend and an IPv6-only API never connect directly.
    reader = StaticInventoryReader(
        {
            "interface:api-1": [
                InventoryCandidate(
                    "interface:api-1",
                    "interface",
                    (AddressBinding("2001:db8::10", "vrf:production", "interface:api-1"),),
                    ("raw/api-1",),
                )
            ]
        }
    )
    result = resolve_application(
        parse_application_yaml(COMPLETE),
        revision=3,
        snapshot={"snapshot": "100", "manifest_sha256": "a", "estate": "test"},
        reader=reader,
        connection_ids=["frontend-to-api"],
    )
    connection = result["connections"][0]
    assert result["ready"] is False
    assert connection["readiness"] == "unresolved"
    assert connection["request"] is None
    assert [issue["code"] for issue in connection["issues"]] == ["requirement-invalid"]
    assert "never connect directly" in connection["issues"][0]["detail"]


def test_resolution_is_snapshot_bound_and_does_not_infer_connections():
    definition = parse_application_yaml(COMPLETE)
    reader = StaticInventoryReader(
        {
            "interface:api-1": [
                InventoryCandidate(
                    "interface:api-1",
                    "interface",
                    (AddressBinding("203.0.113.10", "vrf:production", "interface:api-1"),),
                    ("raw/api-1",),
                )
            ]
        }
    )
    first = resolve_application(
        definition,
        revision=3,
        snapshot={"snapshot": "100", "manifest_sha256": "a", "estate": "test"},
        reader=reader,
        connection_ids=["frontend-to-api"],
    )
    again = resolve_application(
        definition,
        revision=3,
        snapshot={"snapshot": "100", "manifest_sha256": "a", "estate": "test"},
        reader=reader,
        connection_ids=["frontend-to-api"],
    )
    assert first == again
    assert first["ready"] is True
    assert first["connections"][0]["request"]["members"][0]["addresses"] == ["203.0.113.10"]
    assert [item["id"] for item in first["connections"]] == ["frontend-to-api"]
    changed = resolve_application(
        definition,
        revision=3,
        snapshot={"snapshot": "101", "manifest_sha256": "b", "estate": "test"},
        reader=reader,
        connection_ids=["frontend-to-api"],
    )
    assert changed["digest"] != first["digest"]


def test_resolution_preserves_unique_member_vrf_in_executable_request():
    definition = parse_application_yaml(COMPLETE)
    document = definition.model_dump(mode="json")
    document["connections"][0]["source_context"] = None
    resolved = resolve_application(
        BusinessApplicationDefinition.model_validate(document),
        revision=1,
        snapshot={"snapshot": "100", "manifest_sha256": "a", "estate": "test"},
        reader=StaticInventoryReader({}),
        connection_ids=["clients-to-frontend"],
    )
    assert resolved["ready"] is True
    assert resolved["connections"][0]["request"]["source_context"] == "vrf:branch"


def test_resolution_reports_ambiguity_without_widening_scope():
    definition = parse_application_yaml(COMPLETE)
    ambiguous = StaticInventoryReader(
        {
            "interface:api-1": [
                InventoryCandidate("one", "interface", (AddressBinding("10.0.0.1"),)),
                InventoryCandidate("two", "interface", (AddressBinding("10.0.0.2"),)),
            ]
        }
    )
    result = resolve_application(
        definition,
        revision=1,
        snapshot={"snapshot": "100"},
        reader=ambiguous,
        connection_ids=["frontend-to-api"],
    )
    assert result["ready"] is False
    assert {issue["code"] for issue in result["issues"]} == {"inventory-ambiguous", "destination-empty"}
    assert result["connections"][0]["request"] is None


@pytest.mark.parametrize(
    "candidates,expected,has_request",
    [
        ([], {"inventory-not-found", "destination-empty"}, False),
        (
            [
                InventoryCandidate(
                    "interface:api-1",
                    "interface",
                    (AddressBinding("192.0.2.10", "vrf:production"),),
                    complete=False,
                )
            ],
            {"inventory-read-incomplete"},
            True,
        ),
    ],
)
def test_resolution_exposes_missing_and_incomplete_inventory(candidates, expected, has_request):
    result = resolve_application(
        parse_application_yaml(COMPLETE),
        revision=1,
        snapshot={"snapshot": "100"},
        reader=StaticInventoryReader({"interface:api-1": candidates}),
        connection_ids=["frontend-to-api"],
    )
    assert result["ready"] is False
    assert {issue["code"] for issue in result["issues"]} == expected
    assert (result["connections"][0]["request"] is not None) is has_request


def test_resolution_requires_an_explicit_context_for_multi_context_inventory():
    document = parse_application_yaml(COMPLETE).model_dump(mode="json")
    document["groups"][2]["members"][0]["inventory"]["context"] = None
    document["connections"][1]["destination_context"] = None
    definition = BusinessApplicationDefinition.model_validate(document)
    reader = StaticInventoryReader(
        {
            "interface:api-1": [
                InventoryCandidate(
                    "interface:api-1",
                    "interface",
                    (
                        AddressBinding("192.0.2.10", "vrf:blue"),
                        AddressBinding("192.0.2.10", "vrf:red"),
                    ),
                )
            ]
        }
    )
    result = resolve_application(
        definition,
        revision=1,
        snapshot={"snapshot": "100"},
        reader=reader,
        connection_ids=["frontend-to-api"],
    )
    assert result["ready"] is False
    assert {issue["code"] for issue in result["issues"]} == {"destination-context-ambiguous"}


def test_resolution_with_no_explicit_connections_is_not_ready():
    definition = BusinessApplicationDefinition(id="empty-application", name="Empty application")
    result = resolve_application(
        definition,
        revision=1,
        snapshot={"snapshot": "100"},
        reader=StaticInventoryReader({}),
    )
    assert result["ready"] is False
    assert result["connections"] == []
    assert [issue["code"] for issue in result["issues"]] == ["no-connections-selected"]


# --- GraphInventoryReader over a fake graph session ------------------------------------------

_BINDING_FILTER = re.compile(
    r"\[(\w+) IN collect\(DISTINCT \{.*?\}\) WHERE \1\.address IS NOT NULL\]", re.DOTALL
)


class GraphReferenceSession:
    """A graph session that answers the reference read of `GraphInventoryReader`.

    `nodes` maps a uid to its labels and to the rows its two OPTIONAL MATCH
    clauses produce: one (address, context) pair per row, where the address is
    the value of the query's coalesce. A node with no address or context edge
    and no address of its own produces one row of nulls, as OPTIONAL MATCH does.
    The session collects the distinct pairs as `collect(DISTINCT {...})` does,
    and applies the query's list-comprehension filter when the query has one.
    """

    def __init__(self, nodes: dict[str, dict]) -> None:
        self.nodes = nodes
        self.params: list[dict] = []

    def execute_read(self, work):
        return work(self)

    def run(self, query, **params):
        self.params.append(params)
        node = self.nodes.get(params["uid"])
        rows = []
        if node is not None:
            pairs = node.get("rows") or [(None, None)]
            collected = [{"address": a, "context": c} for a, c in dict.fromkeys(pairs)]
            if _BINDING_FILTER.search(query):
                collected = [b for b in collected if b["address"] is not None]
            rows.append(
                {
                    "uid": params["uid"],
                    "labels": node["labels"],
                    "bindings": collected[:10001],
                    "binding_count": len(collected),
                    "evidence": node.get("evidence"),
                }
            )
        return SimpleNamespace(data=lambda: rows)


def _reference(kind: str, uid: str) -> InventoryReference:
    return InventoryReference(kind=kind, uid=uid)


def test_a_row_with_one_null_address_binding_is_complete():
    session = GraphReferenceSession({"dev:core1": {"labels": ["Obj", "Device"]}})

    (candidate,) = GraphInventoryReader(session, 4000).resolve(_reference("device", "dev:core1"), {})

    assert candidate.complete is True
    assert candidate.addresses == ()
    assert candidate.kind == "device"
    assert session.params[0]["snap"] == 4000


def test_the_unfiltered_collect_is_what_made_the_row_incomplete(monkeypatch):
    unfiltered = resolution._GRAPH_REFERENCE.replace("[b IN collect(", "collect(").replace(
        ") WHERE b.address IS NOT NULL]", ")"
    )
    assert unfiltered != resolution._GRAPH_REFERENCE
    monkeypatch.setattr(resolution, "_GRAPH_REFERENCE", unfiltered)
    session = GraphReferenceSession({"dev:core1": {"labels": ["Obj", "Device"]}})

    (candidate,) = GraphInventoryReader(session, 4000).resolve(_reference("device", "dev:core1"), {})

    assert candidate.complete is False


def one_connection_definition(kind: str, uid: str) -> BusinessApplicationDefinition:
    """One connection from a literal client prefix to one inventory member."""
    return BusinessApplicationDefinition.model_validate(
        {
            "schema_version": 1,
            "kind": "BusinessApplication",
            "id": "webshop",
            "name": "Webshop",
            "groups": [
                {"id": "clients", "name": "Clients", "members": [{"id": "lan", "address": "10.9.0.0/24"}]},
                {
                    "id": "servers",
                    "name": "Servers",
                    "members": [{"id": "web", "inventory": {"kind": kind, "uid": uid}}],
                },
            ],
            "services": [{"id": "shop", "name": "Shop", "connection_ids": ["web"]}],
            "connections": [
                {
                    "id": "web",
                    "name": "Web",
                    "source": "clients",
                    "destination": "servers",
                    "protocol": "tcp",
                    "destination_ports": [443],
                    "destination_condition": {"kind": "member", "member": "web"},
                }
            ],
        }
    )


@pytest.mark.parametrize(
    ("kind", "uid", "labels"),
    [
        ("device", "dev:core1", ["Obj", "Device"]),
        ("vrf", "vrf:core1:blue", ["Obj", "VrfInstance"]),
        ("identity", "idp:group:eng", ["Obj", "IdentityGroup"]),
        ("service_requirement", "sreq:web", ["Obj", "ServiceRequirement"]),
    ],
)
def test_an_address_less_reference_reports_no_incomplete_read(kind, uid, labels):
    session = GraphReferenceSession({uid: {"labels": labels}})

    result = resolve_application(
        one_connection_definition(kind, uid),
        revision=1,
        snapshot={"snapshot": "4000"},
        reader=GraphInventoryReader(session, 4000),
    )

    codes = {issue["code"] for issue in result["issues"]}
    assert "inventory-read-incomplete" not in codes
    assert "inventory-address-unavailable" in codes


def test_a_dns_reference_with_one_address_less_target_stays_ready():
    # the record resolves to an IpAddress and to a Device that carries no address
    session = GraphReferenceSession(
        {"dns:web.corp": {"labels": ["Obj", "DnsRecord"], "rows": [("10.0.0.5", None), (None, None)]}}
    )

    result = resolve_application(
        one_connection_definition("dns", "dns:web.corp"),
        revision=1,
        snapshot={"snapshot": "4000"},
        reader=GraphInventoryReader(session, 4000),
    )

    assert result["ready"] is True
    assert result["issues"] == []
    assert result["connections"][0]["readiness"] == "ready"
    assert result["connections"][0]["request"]["members"][0]["addresses"] == ["10.0.0.5"]


# --- Schema version 2 placeholders ------------------------------------------------------------

PLACEHOLDERS = """\
schema_version: 2
kind: BusinessApplication
id: webshop
name: Webshop
services:
  - id: shop
    name: Shop
    connection_ids: [users-to-web, snip-to-web]
groups:
  - id: clients
    name: Clients
    members:
      - id: lan
        address: 10.9.0.0/24
  - id: web-tier
    name: Web tier
    members:
      - id: web01
        name: web01
        placeholder:
          text: web01
          expected_kind: ip
          status: ambiguous
          candidates: ["ip:blue:10.0.10.5", "ip:red:10.0.10.5"]
          note: one address on two IpAddress nodes
      - id: web02
        inventory: {kind: ip, uid: "ip:corp:10.0.10.6", role: destination}
  - id: snip
    name: NetScaler source
    members:
      - id: ns01-snip
        placeholder:
          text: NetScaler ns01 subnet IP used as source towards the web pool
          expected_kind: ip
connections:
  - id: users-to-web
    name: Users to web
    source: clients
    destination: web-tier
    protocol: tcp
    destination_ports: [443]
    destination_condition: {kind: member, member: web02}
  - id: snip-to-web
    name: SNIP to web
    source: snip
    destination: web-tier
    protocol: tcp
    destination_ports: [8443]
    destination_condition: {kind: member, member: web02}
"""


def test_version_1_definition_and_resolution_digests_are_unchanged():
    definition = parse_application_yaml(COMPLETE)
    result = resolve_application(
        definition, revision=1, snapshot={"snapshot": "100"}, reader=StaticInventoryReader({})
    )

    assert definition.schema_version == 1
    assert definition_digest(definition) == "068a7f91efef4a1305b340f0214e368fb110a86212cbace0189d933630d868c8"
    assert result["digest"] == "74a63019261a84a91567c2d34692b9b5fe91c4446cff80ac46152a3caaa2a5f7"
    assert "placeholder" not in canonical_yaml(definition)


def test_an_explicit_null_placeholder_leaves_a_version_1_digest_unchanged():
    body = COMPLETE.replace("address: 198.51.100.10\n", "address: 198.51.100.10\n        placeholder: null\n")

    definition = parse_application_yaml(body)

    assert definition.schema_version == 1
    assert definition_digest(definition) == definition_digest(parse_application_yaml(COMPLETE))


def test_a_version_2_placeholder_round_trips_and_exports_no_nulls():
    definition = parse_application_yaml(PLACEHOLDERS)

    assert definition.schema_version == 2
    assert definition.groups[1].members[0].placeholder == Placeholder(
        text="web01",
        expected_kind="ip",
        status="ambiguous",
        candidates=["ip:blue:10.0.10.5", "ip:red:10.0.10.5"],
        note="one address on two IpAddress nodes",
    )
    unresolved = definition.groups[2].members[0].placeholder
    assert unresolved is not None
    assert (unresolved.status, unresolved.candidates, unresolved.note) == ("unresolved", [], None)
    exported = canonical_yaml(definition)
    assert "null" not in exported
    reparsed = parse_application_yaml(exported)
    assert reparsed == definition
    assert definition_digest(reparsed) == definition_digest(definition)


def test_version_2_without_placeholders_may_be_ready():
    body = COMPLETE.replace("schema_version: 1", "schema_version: 2").replace(
        "environment: production\n", "environment: production\nstate: ready\n"
    )

    definition = parse_application_yaml(body)

    assert (definition.schema_version, definition.state) == (2, "ready")


@pytest.mark.parametrize(
    "body,message",
    [
        (
            PLACEHOLDERS.replace("schema_version: 2\n", "schema_version: 1\n"),
            "placeholder members require schema_version 2",
        ),
        (PLACEHOLDERS.replace("schema_version: 2\n", ""), "placeholder members require schema_version 2"),
        (
            PLACEHOLDERS.replace("name: Webshop\n", "name: Webshop\nstate: ready\n"),
            "state ready is blocked by placeholders: groups.web-tier.members.web01, "
            "groups.snip.members.ns01-snip",
        ),
    ],
)
def test_placeholders_require_version_2_and_block_ready(body, message):
    with pytest.raises(ApplicationFormatError) as caught:
        parse_application_yaml(body)

    (error,) = caught.value.errors
    assert message in error.message
    assert (error.path, error.line, error.column) == ("$", None, None)


@pytest.mark.parametrize(
    "old,new,message",
    [
        (
            "        placeholder:\n          text: web01\n",
            "        address: 10.0.10.5\n        placeholder:\n          text: web01\n",
            "exactly one literal address, inventory reference or placeholder",
        ),
        ("          text: web01\n", "          text: ''\n", "at least 1 character"),
        ("          status: ambiguous\n", "          status: maybe\n", "'unresolved' or 'ambiguous'"),
        (
            "          note: one address",
            "          source: generator\n          note: one address",
            "Extra inputs are not permitted",
        ),
        (
            '["ip:blue:10.0.10.5", "ip:red:10.0.10.5"]',
            str([f"ip:{n}" for n in range(21)]),
            "at most 20 items",
        ),
    ],
)
def test_a_placeholder_is_a_bounded_third_member_source(old, new, message):
    assert old in PLACEHOLDERS

    with pytest.raises(ApplicationFormatError, match=message) as caught:
        parse_application_yaml(PLACEHOLDERS.replace(old, new))

    assert caught.value.errors[0].path.startswith("groups.1.members.0")


def test_a_placeholder_resolves_to_no_bindings_and_leaves_its_connections_unresolved():
    reader = StaticInventoryReader(
        {
            "ip:corp:10.0.10.6": [
                InventoryCandidate(
                    "ip:corp:10.0.10.6", "ip", (AddressBinding("10.0.10.6", None, "ip:corp:10.0.10.6"),)
                )
            ]
        }
    )

    result = resolve_application(
        parse_application_yaml(PLACEHOLDERS), revision=1, snapshot={"snapshot": "100"}, reader=reader
    )

    unbound = {"bindings": [], "inventory_uid": None, "evidence": []}
    assert result["groups"]["web-tier"]["web01"] == unbound
    assert result["groups"]["snip"]["ns01-snip"] == unbound
    assert result["issues"] == [
        {
            "code": "member-placeholder",
            "path": "groups.web-tier.members.web01",
            "detail": "unbound placeholder (ambiguous)",
            "severity": "error",
        },
        {
            "code": "member-placeholder",
            "path": "groups.snip.members.ns01-snip",
            "detail": "unbound placeholder (unresolved)",
            "severity": "error",
        },
        {
            "code": "source-empty",
            "path": "connections.snip-to-web.source",
            "detail": "source group resolved to no addresses",
            "severity": "error",
        },
    ]
    assert result["ready"] is False
    assert {item["id"]: item["readiness"] for item in result["connections"]} == {
        "users-to-web": "unresolved",
        "snip-to-web": "unresolved",
    }


def test_merge_carries_the_higher_schema_version():
    header = "kind: BusinessApplication\nid: checkout-production\n"
    current = parse_application_yaml(COMPLETE)
    raise_to_2 = parse_application_yaml(f"schema_version: 2\n{header}", partial=True)
    version_1 = parse_application_yaml(f"schema_version: 1\n{header}owner: web-team\n", partial=True)

    raised = merge_application(current, raise_to_2)
    kept = merge_application(raised, version_1)

    assert raised.schema_version == 2
    assert (kept.schema_version, kept.owner) == (2, "web-team")
    assert merge_application(current, version_1).schema_version == 1
    created = merge_application(None, parse_application_yaml(PLACEHOLDERS, partial=True))
    assert created.schema_version == 2
    assert definition_digest(created) == definition_digest(parse_application_yaml(PLACEHOLDERS))


def test_a_merge_that_binds_a_placeholder_clears_it_explicitly():
    current = parse_application_yaml(PLACEHOLDERS)
    bind = """\
schema_version: 2
kind: BusinessApplication
id: webshop
groups:
  - id: web-tier
    name: Web tier
    members:
      - id: web01
        placeholder: null
        inventory: {kind: ip, uid: "ip:red:10.0.10.5"}
"""

    bound = merge_application(current, parse_application_yaml(bind, partial=True))

    member = bound.groups[1].members[0]
    assert (member.placeholder, member.inventory) == (
        None,
        InventoryReference(kind="ip", uid="ip:red:10.0.10.5"),
    )
    assert bound.groups[2].members[0].placeholder is not None
    with pytest.raises(ValueError, match="exactly one literal address, inventory reference or placeholder"):
        merge_application(
            current, parse_application_yaml(bind.replace("        placeholder: null\n", ""), partial=True)
        )


@pytest.mark.parametrize("mode", ["merge", "replace"])
async def test_a_version_2_document_imports_and_exports_in_both_modes(mode):
    store = MemoryAssessmentStore()

    preview = await preview_import(store, PLACEHOLDERS, RemovalSet(), mode)
    saved = await commit_import(
        store,
        PLACEHOLDERS,
        RemovalSet(),
        base_revision=0,
        base_digest="",
        preview_digest=preview.preview_digest,
        actor=1,
        mode=mode,
    )

    assert preview.definition["schema_version"] == 2
    assert saved.revision == 1
    assert export_revision(saved) == canonical_yaml(parse_application_yaml(PLACEHOLDERS))


async def test_validation_lists_every_placeholder_as_blocking():
    async def resolve(definition: BusinessApplicationDefinition, revision: int) -> dict:
        return resolve_application(
            definition, revision=revision, snapshot={"snapshot": "100"}, reader=StaticInventoryReader({})
        )

    result = await validate_application(
        MemoryAssessmentStore(), PLACEHOLDERS, mode="replace", snapshot={"snapshot": "100"}, resolve=resolve
    )

    assert result["errors"] == []
    assert result["definition"]["schema_version"] == 2
    assert {"groups.web-tier.members.web01", "groups.snip.members.ns01-snip"} <= set(result["blocking"])
