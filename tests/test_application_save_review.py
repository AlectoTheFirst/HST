"""The import preview of the save review notes each inventory member as the
validation at the snapshot resolved it.

Without a resolution the preview cannot read the graph, so it notes that a
pinned snapshot must resolve each inventory member. A generated draft is
validated at the generation's snapshot first: the preview inside that
validation, and a preview that names the recorded validation, take the notes
from its resolution, and a member it resolved has none.
"""

from __future__ import annotations

import pytest

from hst.applications.models import BusinessApplicationDefinition, RemovalSet
from hst.applications.resolution import (
    AddressBinding,
    InventoryCandidate,
    StaticInventoryReader,
    resolve_application,
)
from hst.applications.service import preview_import
from hst.applications.validation import record_validation, validate_application
from hst.assessment.store import MemoryAssessmentStore

REFERENCE = {"snapshot": "4000", "manifest_sha256": "a" * 64, "estate": "test", "observation_floor_ms": None}

DRAFT = """\
schema_version: 1
kind: BusinessApplication
id: tunnels
name: Tunnels
state: draft
groups:
  - id: clients
    name: Clients
    members:
      - id: c1
        inventory: {kind: ip, uid: "ip:home:10.20.10.43", role: source}
      - id: c2
        inventory: {kind: ip, uid: "ip:home:10.20.10.99", role: source}
      - id: c3
        address: 10.20.210.50/31
  - id: internet
    name: Internet
    members:
      - id: high
        address: 128.0.0.0/1
  - id: spare
    name: Spare
    members:
      - id: s1
        inventory: {kind: ip, uid: "ip:home:10.20.10.43", role: component}
connections:
  - id: out
    name: Clients out
    source: clients
    destination: internet
    destination_condition: {kind: member, member: high}
"""

CANDIDATES = {
    "ip:home:10.20.10.43": [
        InventoryCandidate(
            "ip:home:10.20.10.43", "ip", (AddressBinding("10.20.10.43", None, "ip:home:10.20.10.43"),)
        )
    ]
}


async def resolve(definition: BusinessApplicationDefinition, revision: int) -> dict:
    return resolve_application(
        definition, revision=revision, snapshot=REFERENCE, reader=StaticInventoryReader(CANDIDATES)
    )


async def validated(store: MemoryAssessmentStore, text: str = DRAFT) -> dict:
    return await validate_application(
        store,
        text,
        mode="replace",
        snapshot=REFERENCE,
        resolve=resolve,
        application_id="tunnels",
        include_preview=True,
    )


EXPECTED = [
    {
        "code": "inventory-not-found",
        "path": "groups.clients.members.c2.inventory",
        "detail": "ip:home:10.20.10.99 was not found at snapshot 4000",
    },
    {
        "code": "inventory-not-resolved",
        "path": "groups.spare.members.s1.inventory",
        "detail": "No connection uses group spare, so the validation at snapshot 4000 did not resolve this "
        "inventory reference.",
    },
]


async def test_a_preview_without_a_resolution_asks_for_a_pinned_snapshot():
    preview = await preview_import(MemoryAssessmentStore(), DRAFT, RemovalSet(), "replace")

    assert [issue["path"] for issue in preview.mapping_issues] == [
        "groups.clients.members.c1.inventory",
        "groups.clients.members.c2.inventory",
        "groups.spare.members.s1.inventory",
    ]
    assert {issue["code"] for issue in preview.mapping_issues} == {"inventory-resolution-required"}


async def test_the_validation_preview_notes_only_what_the_resolution_did_not_resolve():
    result = await validated(MemoryAssessmentStore())

    # c1 resolved at the snapshot, so the preview notes nothing for it
    assert result["preview"]["mapping_issues"] == EXPECTED


async def test_a_preview_that_names_the_recorded_validation_takes_its_resolution():
    store = MemoryAssessmentStore()
    digest = await record_validation(store, await validated(store))
    assert digest is not None

    preview = await preview_import(store, DRAFT, RemovalSet(), "replace", validation_digest=digest)

    assert preview.mapping_issues == EXPECTED


async def test_a_preview_refuses_a_validation_of_another_definition():
    store = MemoryAssessmentStore()
    digest = await record_validation(store, await validated(store))
    assert digest is not None
    edited = DRAFT.replace("name: Tunnels", "name: Tunnels edited")

    with pytest.raises(ValueError, match="computed for another definition"):
        await preview_import(store, edited, RemovalSet(), "replace", validation_digest=digest)
    with pytest.raises(ValueError, match="unknown application validation"):
        await preview_import(store, DRAFT, RemovalSet(), "replace", validation_digest="f" * 64)
