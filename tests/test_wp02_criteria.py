"""WP-02 done-when criteria: canonical round trips, duplicate ids and size limits.

Each limit is accepted at its value and refused at the first value over it."""

from __future__ import annotations

import pytest

from hst.applications.models import (
    MAX_CONNECTIONS,
    MAX_GROUPS,
    MAX_MEMBERS,
    MAX_SERVICES,
    BusinessApplicationDefinition,
    BusinessApplicationPatch,
)
from hst.applications.yaml_format import (
    ApplicationFormatError,
    canonical_yaml,
    definition_digest,
    parse_application_yaml,
)

ADVANCED = """\
schema_version: 1
kind: BusinessApplication
id: payments
name: Payments
services:
  - id: card-auth
    name: Card authorisation
    connection_ids: [web-to-auth]
groups:
  - id: web
    name: Web
    members:
      - id: web-1
        address: 192.0.2.10
      - id: web-6
        address: 2001:db8::10
  - id: auth
    name: Authorisation
    members:
      - id: auth-a
        address: 198.51.100.1
      - id: auth-b
        address: 198.51.100.2
      - id: auth-c
        address: 198.51.100.3
connections:
  - id: web-to-auth
    name: Web to authorisation
    source: web
    destination: auth
    protocol: tcp
    destination_ports: [8443]
    success: session
    source_context:
      vrf: vrf:web
      device_uid: device:fw-1
      identity_uid: identity:web
      segment_uid: segment:dmz
      ingress_interface_uid: interface:fw-1:eth1
    destination_context:
      vrf: vrf:core
      device_uid: device:core-1
      identity_uid: identity:auth
      segment_uid: segment:core
      ingress_interface_uid: interface:core-1:eth2
    header_constraints:
      dscp: [[46, 46]]
      tcp_flags: [[2, 2], [16, 18]]
    provenance:
      trace_id: trace:web-to-auth
      snapshot: '1700000000000'
      captured_fields: [source, destination, protocol, destination_ports]
    destination_condition:
      kind: or
      parts:
        - kind: and
          parts:
            - {kind: member, member: auth-a}
            - {kind: member, member: auth-b}
        - kind: threshold
          n: 2
          parts:
            - {kind: member, member: auth-a}
            - {kind: member, member: auth-b}
            - {kind: member, member: auth-c}
"""


def test_advanced_connection_fields_survive_the_canonical_round_trip():
    definition = parse_application_yaml(ADVANCED)
    exported = canonical_yaml(definition)
    reparsed = parse_application_yaml(exported)

    assert reparsed == definition
    assert definition_digest(reparsed) == definition_digest(definition)
    assert canonical_yaml(reparsed) == exported
    (connection,) = reparsed.connections
    assert connection.header_constraints == {"dscp": [(46, 46)], "tcp_flags": [(2, 2), (16, 18)]}
    assert connection.provenance.model_dump() == {
        "trace_id": "trace:web-to-auth",
        "snapshot": "1700000000000",
        "captured_fields": ["source", "destination", "protocol", "destination_ports"],
    }
    assert connection.source_context.model_dump() == {
        "vrf": "vrf:web",
        "device_uid": "device:fw-1",
        "identity_uid": "identity:web",
        "segment_uid": "segment:dmz",
        "ingress_interface_uid": "interface:fw-1:eth1",
    }
    assert connection.destination_context.model_dump() == {
        "vrf": "vrf:core",
        "device_uid": "device:core-1",
        "identity_uid": "identity:auth",
        "segment_uid": "segment:core",
        "ingress_interface_uid": "interface:core-1:eth2",
    }
    condition = connection.destination_condition.model_dump(exclude_defaults=True)
    assert condition == {
        "kind": "or",
        "parts": [
            {
                "kind": "and",
                "parts": [{"kind": "member", "member": "auth-a"}, {"kind": "member", "member": "auth-b"}],
            },
            {
                "kind": "threshold",
                "n": 2,
                "parts": [
                    {"kind": "member", "member": "auth-a"},
                    {"kind": "member", "member": "auth-b"},
                    {"kind": "member", "member": "auth-c"},
                ],
            },
        ],
    }


DUPLICATES = {
    "service": ("services:\n  - {id: card-auth, name: One}\n  - {id: card-auth, name: Two}\n"),
    "group": ("groups:\n  - {id: web, name: Web}\n  - {id: web, name: Web again}\n"),
    "connection": (
        "groups:\n"
        "  - id: web\n"
        "    name: Web\n"
        "    members: [{id: web-1, address: 192.0.2.10}]\n"
        "connections:\n"
        "  - {id: web-loop, name: One, source: web, destination: web,"
        " destination_condition: {kind: member, member: web-1}}\n"
        "  - {id: web-loop, name: Two, source: web, destination: web,"
        " destination_condition: {kind: member, member: web-1}}\n"
    ),
    "component member": (
        "groups:\n"
        "  - id: web\n"
        "    name: Web\n"
        "    members:\n"
        "      - {id: web-1, address: 192.0.2.10}\n"
        "      - {id: web-1, address: 192.0.2.11}\n"
    ),
}
HEADER = "schema_version: 1\nkind: BusinessApplication\nid: payments\nname: Payments\n"


@pytest.mark.parametrize("partial", [False, True])
@pytest.mark.parametrize("noun", list(DUPLICATES))
def test_a_duplicate_id_is_refused_with_its_noun_and_id(noun, partial):
    body = HEADER + DUPLICATES[noun]
    identifier = {"service": "card-auth", "group": "web", "connection": "web-loop"}.get(noun, "web-1")

    with pytest.raises(ApplicationFormatError, match=f"duplicate {noun} ids: {identifier}"):
        parse_application_yaml(body, partial=partial)


def _document(
    *, services: int = 0, groups: int = 1, connections: int = 0, members: tuple[int, ...] = (1,)
) -> dict:
    """A definition with the given counts. Group `g0` holds member `m0-0` for the connections."""
    member_counts = list(members) + [0] * (groups - len(members))
    return {
        "id": "payments",
        "name": "Payments",
        "services": [{"id": f"s{index}", "name": f"S {index}"} for index in range(services)],
        "groups": [
            {
                "id": f"g{group}",
                "name": f"G {group}",
                "members": [
                    {"id": f"m{group}-{index}", "address": f"10.{group}.{index // 250}.{index % 250 + 1}"}
                    for index in range(member_counts[group])
                ],
            }
            for group in range(groups)
        ],
        "connections": [
            {
                "id": f"c{index}",
                "name": f"C {index}",
                "source": "g0",
                "destination": "g0",
                "destination_condition": {"kind": "member", "member": "m0-0"},
            }
            for index in range(connections)
        ],
    }


LIMITS = {
    "services": (MAX_SERVICES, 200, lambda count: _document(services=count)),
    "groups": (MAX_GROUPS, 500, lambda count: _document(groups=count)),
    "connections": (MAX_CONNECTIONS, 1000, lambda count: _document(connections=count)),
    "members of one group": (MAX_MEMBERS, 2000, lambda count: _document(members=(count,))),
}


@pytest.mark.parametrize("name", list(LIMITS))
def test_each_entity_cap_accepts_its_value_and_refuses_one_more(name):
    limit, value, build = LIMITS[name]
    assert limit == value

    BusinessApplicationDefinition.model_validate(build(value))
    with pytest.raises(ValueError, match=f"at most {value} items"):
        BusinessApplicationDefinition.model_validate(build(value + 1))


@pytest.mark.parametrize("name", ["services", "groups", "connections"])
def test_each_patch_list_cap_refuses_one_more(name):
    limit, _, build = LIMITS[name]
    document = build(limit + 1)
    patch = {"id": document["id"], name: document[name]}

    with pytest.raises(ValueError, match=f"at most {limit} items"):
        BusinessApplicationPatch.model_validate(patch)


def test_the_member_cap_counts_the_members_of_all_groups():
    half = MAX_MEMBERS // 2
    BusinessApplicationDefinition.model_validate(_document(groups=2, members=(half, half)))

    with pytest.raises(ValueError, match=f"an application supports at most {MAX_MEMBERS} group members"):
        BusinessApplicationDefinition.model_validate(_document(groups=2, members=(half, half + 1)))
