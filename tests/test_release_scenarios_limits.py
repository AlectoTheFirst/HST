"""The input limits of an analysis session and the limit of 10,000 resolved addresses.

Each limit is accepted at its value and refused at the first value over it, on
every input model that carries the field."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from hst.analysis.contracts import (
    MAX_CHANGES,
    MAX_CONNECTIONS,
    MAX_PROTECTIONS,
    ConnectionAnalysisInput,
    SimulationAnalysisInput,
)
from hst.applications.models import BusinessApplicationDefinition
from hst.applications.resolution import (
    MAX_RESOLVED_ADDRESSES,
    AddressBinding,
    InventoryCandidate,
    StaticInventoryReader,
    resolve_application,
)
from hst.assessment import evaluation as ev

SNAPSHOT = {"snapshot": "100", "manifest_sha256": "abc", "estate": "synthetic"}
REQUEST = {
    "name": "Clients to API",
    "destination": "API",
    "sources": ["10.0.0.1"],
    "members": [{"name": "api", "addresses": ["192.0.2.1"]}],
    "condition": {"kind": "member", "member": "api"},
    "success": "forward",
}
CHANGE = {"kind": "fw_rule.remove", "params": {"rulebase": "rb:1", "rule": "r1"}}


def _connections(count: int) -> list[dict]:
    return [
        {"id": f"c{index}", "name": f"C {index}", "source": {"kind": "inline", "request": REQUEST}}
        for index in range(count)
    ]


def _protections(count: int) -> list[dict]:
    return [{"kind": "inline", "name": f"p{index}", "request": REQUEST} for index in range(count)]


def _connection_input(*, connections: int = 1, changes: int = 0) -> dict:
    return {
        "kind": "connection",
        "snapshot": SNAPSHOT,
        "connections": _connections(connections),
        "changes": [CHANGE] * changes,
    }


def _simulation_input(*, changes: int = 1, protections: int = 0, flows: int = 0, sites: int = 0) -> dict:
    return {
        "kind": "simulation",
        "snapshot": SNAPSHOT,
        "changes": [CHANGE] * changes,
        "scope": {
            "flows": [{"src": "10.0.0.1", "dst": f"192.0.2.{index % 250 + 1}"} for index in range(flows)],
            "sites": [f"site-{index}" for index in range(sites)],
        },
        "protected": _protections(protections),
    }


def _assert_limit(model, build, limit: int) -> None:
    model.model_validate(build(limit))
    with pytest.raises(ValidationError):
        model.model_validate(build(limit + 1))


def test_a_session_accepts_200_selected_connections_and_refuses_201():
    assert MAX_CONNECTIONS == 200
    _assert_limit(ConnectionAnalysisInput, lambda n: _connection_input(connections=n), 200)


@pytest.mark.parametrize(
    "model,build",
    [
        (ConnectionAnalysisInput, lambda n: _connection_input(changes=n)),
        (SimulationAnalysisInput, lambda n: _simulation_input(changes=n)),
    ],
    ids=["connection", "simulation"],
)
def test_a_session_accepts_50_ordered_changes_and_refuses_51(model, build):
    assert MAX_CHANGES == 50
    _assert_limit(model, build, 50)


def test_a_session_accepts_50_protections_and_refuses_51():
    assert MAX_PROTECTIONS == 50
    _assert_limit(SimulationAnalysisInput, lambda n: _simulation_input(protections=n), 50)


def test_a_simulation_accepts_50_explicit_flows_and_refuses_51():
    _assert_limit(SimulationAnalysisInput, lambda n: _simulation_input(flows=n), 50)


def test_a_simulation_accepts_20_sites_and_refuses_21():
    _assert_limit(SimulationAnalysisInput, lambda n: _simulation_input(sites=n), 20)


# A compiled request holds at most 50 sources and 50 members of 50 addresses
# (hst.assessment.evaluation), so 10,000 resolved addresses are reached
# across four connections: one client address to four server groups of 50
# inventory members of 50 addresses each, less the addresses taken off.
SERVER_GROUPS = 4
MEMBERS = 50
PER_MEMBER = 50


def _bulk_application() -> BusinessApplicationDefinition:
    groups = [{"id": "clients", "name": "Clients", "members": [{"id": "client", "address": "10.0.0.1"}]}]
    connections = []
    for group in range(SERVER_GROUPS):
        groups.append(
            {
                "id": f"servers-{group}",
                "name": f"Servers {group}",
                "members": [
                    {"id": f"m{member}", "inventory": {"kind": "network", "uid": f"prefix:{group}:{member}"}}
                    for member in range(MEMBERS)
                ],
            }
        )
        connections.append(
            {
                "id": f"clients-to-servers-{group}",
                "name": f"Clients to servers {group}",
                "source": "clients",
                "destination": f"servers-{group}",
                "protocol": "tcp",
                "destination_ports": [443],
                "destination_condition": {
                    "kind": "threshold",
                    "n": 1,
                    "parts": [{"kind": "member", "member": f"m{member}"} for member in range(MEMBERS)],
                },
            }
        )
    return BusinessApplicationDefinition.model_validate(
        {"id": "bulk", "name": "Bulk", "groups": groups, "connections": connections}
    )


def _resolve_with(total: int) -> dict:
    """Resolve the bulk application with `total` resolved addresses in all:
    the client address and `total - 1` server addresses."""
    capacity = SERVER_GROUPS * MEMBERS * PER_MEMBER
    removed = capacity + 1 - total
    candidates = {}
    for group in range(SERVER_GROUPS):
        for member in range(MEMBERS):
            count = PER_MEMBER - (1 if group == 0 and member < removed else 0)
            uid = f"prefix:{group}:{member}"
            bindings = tuple(AddressBinding(f"10.{group + 1}.{member}.{index + 1}") for index in range(count))
            candidates[uid] = [InventoryCandidate(uid, "network", bindings)]
    return resolve_application(
        _bulk_application(), revision=1, snapshot=SNAPSHOT, reader=StaticInventoryReader(candidates)
    )


def test_resolution_accepts_10000_resolved_addresses_and_refuses_10001():
    assert MAX_RESOLVED_ADDRESSES == 10_000
    resolved = _resolve_with(MAX_RESOLVED_ADDRESSES)
    total = sum(len(member["bindings"]) for group in resolved["groups"].values() for member in group.values())
    assert total == MAX_RESOLVED_ADDRESSES
    assert resolved["ready"] is True, resolved["issues"][:1]
    for connection in resolved["connections"]:
        # the engine admits each compiled request
        ev._request_from_body(ev.RequestBody.model_validate(connection["request"]))
    with pytest.raises(ValueError, match="exceeds 10000 addresses"):
        _resolve_with(MAX_RESOLVED_ADDRESSES + 1)
