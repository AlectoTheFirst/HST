"""The generator's policy-route reads and a draft whose members are the
addresses a tunnel's policy routes send to it.

The graph is the VyOS router of `tests/support/policy_route_graph.py`: two
policies bound to two ingress VLANs, a first rule that keeps 10.20.0.0/16 in
the main table, sources from address groups and an inline range, and two
policy tables whose default route leaves through wg0 and wg44.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from tests.support import policy_route_graph as fixture
from tests.test_application_generator import REFERENCE, FakeTools, ScriptedModel, offered, search

from hst.app.ai.registry import Principal, ToolContext, ToolError
from hst.applications import generator, generator_tools
from hst.applications.models import InventoryReference
from hst.applications.resolution import (
    AddressBinding,
    InventoryCandidate,
    StaticInventoryReader,
    resolve_application,
)
from hst.applications.validation import validate_application
from hst.assessment.store import MemoryAssessmentStore
from hst.core.snapshot import Snapshot
from hst.path.gates import pbr

GROUP_A_IPS = ["10.20.10.43", "10.20.10.44", "10.20.10.45"]


def ip_uid(address: str) -> str:
    return f"ip:home:{address}"


def context() -> ToolContext:
    return ToolContext(
        settings=None,
        principal=Principal.for_role("viewer", user_id=7),
        surface="service_generator",
        snapshot=Snapshot(4000, None),
    )


def install(monkeypatch, graph: fixture.BatchGraph) -> fixture.BatchGraph:
    monkeypatch.setattr(generator_tools.dbmod, "session", graph.opened)
    return graph


@pytest.fixture()
def graph(monkeypatch):
    return install(monkeypatch, fixture.BatchGraph(fixture.batch()))


def sources(uid: str) -> dict[str, Any]:
    return generator_tools.policy_route_sources(context(), {"uid": uid})


def by_rule(answer: dict[str, Any]) -> dict[tuple[str, int], dict[str, Any]]:
    return {(rule["policy"]["uid"], rule["rule"]["position"]): rule for rule in answer["rules"]}


def addresses(rule: dict[str, Any]) -> list[tuple[str, str | None]]:
    return [(item["address"], item.get("uid")) for item in rule["sources"]]


# --- policy_route_sources -------------------------------------------------------------------


def test_the_sources_of_a_tunnel_are_the_rules_that_send_traffic_to_its_table(graph):
    answer = sources(fixture.TUNNEL_A)

    assert (answer["label"], answer["name"]) == ("Tunnel", "peer-a")
    assert answer["interfaces"] == [{"uid": fixture.WG0, "name": "wg0"}]
    assert answer["tables"] == [
        {
            "uid": fixture.TABLE_A,
            "name": "table100",
            "routes": [
                {"cidr": "0.0.0.0/0", "interface": {"uid": fixture.WG0, "name": "wg0"}, "next_hop": None}
            ],
        }
    ]
    rules = by_rule(answer)
    assert list(rules) == [(fixture.POLICY, 20), (fixture.DEDICATED, 20)]

    group = rules[(fixture.POLICY, 20)]
    assert group["policy"]["name"] == "VPN-PBR"
    assert group["policy"]["interfaces"] == [{"uid": fixture.VLAN10, "name": "eth1.10"}]
    assert [device["uid"] for device in group["policy"]["devices"]] == [fixture.DEV]
    assert group["rule"]["table"] == {"uid": fixture.TABLE_A, "name": "table100"}
    assert group["rule"]["source"]["objects"] == [{"uid": fixture.GROUP_A, "name": "tunnel-a-clients"}]
    assert group["rule"]["service"] == "any"
    # the members of the address group, each with its IpAddress node
    assert addresses(group) == [(address, ip_uid(address)) for address in GROUP_A_IPS]
    assert group["sources"][0]["chain"] == [
        {"from": fixture.POLICY, "rel": "HAS_RULE", "to": f"{fixture.POLICY}:20"},
        {"from": f"{fixture.POLICY}:20", "rel": "SRC", "to": fixture.GROUP_A},
        {"from": fixture.GROUP_A, "rel": "RESOLVES_TO", "to": ip_uid("10.20.10.43")},
    ]
    # rule 10 keeps local destinations in the main table first
    assert group["destinations"] == fixture.NOT_LOCAL
    (local,) = group["earlier_rules"]
    assert (local["position"], local["name"], local["table"]["uid"]) == (
        10,
        "local stays local",
        fixture.MAIN,
    )
    assert local["source"]["any"] is True
    assert local["destination"]["addresses"] == ["10.20.0.0/16"]

    dedicated = rules[(fixture.DEDICATED, 20)]
    assert dedicated["policy"]["interfaces"] == [{"uid": fixture.VLAN210, "name": "eth1.210"}]
    # the inline range as the smallest list of networks, with no node
    assert addresses(dedicated) == [(network, None) for network in fixture.RANGE_NETWORKS]
    assert {item["range"] for item in dedicated["sources"]} == {fixture.RANGE}
    assert dedicated["destinations"] == fixture.NOT_LOCAL
    assert [rule["position"] for rule in dedicated["earlier_rules"]] == [10]
    assert answer["notes"] == []
    assert answer["truncated"] is False


def test_the_second_tunnel_takes_a_group_that_holds_a_range(graph):
    rules = by_rule(sources(fixture.TUNNEL_B))

    assert list(rules) == [(fixture.POLICY, 30)]
    rule = rules[(fixture.POLICY, 30)]
    assert rule["rule"]["table"]["uid"] == fixture.TABLE_B
    assert addresses(rule) == [
        ("10.20.10.60", ip_uid("10.20.10.60")),
        ("10.20.10.70/31", None),
        ("10.20.10.72", None),
    ]
    assert rule["sources"][1]["range"] == "10.20.10.70-10.20.10.72"
    # rule 20 sends to another table, but none of its sources is in the group
    assert [earlier["position"] for earlier in rule["earlier_rules"]] == [10]


def test_a_table_gives_the_rules_of_its_tunnel_and_a_policy_gives_every_rule(graph):
    table = sources(fixture.TABLE_B)
    assert table["label"] == "VrfInstance"
    assert [route["cidr"] for t in table["tables"] for route in t["routes"]] == ["0.0.0.0/0"]
    assert list(by_rule(table)) == [(fixture.POLICY, 30)]
    assert (
        by_rule(table)[(fixture.POLICY, 30)]["sources"]
        == by_rule(sources(fixture.TUNNEL_B))[(fixture.POLICY, 30)]["sources"]
    )

    policy = by_rule(sources(fixture.POLICY))
    assert list(policy) == [(fixture.POLICY, 10), (fixture.POLICY, 20), (fixture.POLICY, 30)]
    local = policy[(fixture.POLICY, 10)]
    assert local["rule"]["source"]["any"] is True
    assert local["sources"] == []
    assert local["destinations"] == ["10.20.0.0/16"]
    assert [item["address"] for item in policy[(fixture.POLICY, 20)]["sources"]] == GROUP_A_IPS


def test_a_source_an_earlier_rule_takes_elsewhere_is_left_out(monkeypatch):
    def patch(cfg):
        cfg["policy"]["route"]["VPN-PBR"]["rule"]["15"] = {
            "source": {"address": "10.20.10.44"},
            "set": {"table": "main"},
        }

    install(monkeypatch, fixture.BatchGraph(fixture.batch(patch)))
    rule = by_rule(sources(fixture.TUNNEL_A))[(fixture.POLICY, 20)]

    assert addresses(rule) == [("10.20.10.43", ip_uid("10.20.10.43")), ("10.20.10.45", ip_uid("10.20.10.45"))]
    assert rule["source_networks"] == ["10.20.10.43", "10.20.10.45"]
    assert [earlier["position"] for earlier in rule["earlier_rules"]] == [10, 15]


def test_a_tunnel_no_table_routes_through_says_so(monkeypatch):
    def patch(cfg):
        cfg["protocols"]["static"]["table"]["144"] = {}

    install(monkeypatch, fixture.BatchGraph(fixture.batch(patch)))
    answer = sources(fixture.TUNNEL_B)

    assert answer["tables"] == []
    assert answer["rules"] == []
    assert answer["notes"] == ["no route of any routing table leaves through wg44"]


def test_the_tool_reads_the_rule_rows_of_the_trace(graph):
    sources(fixture.TUNNEL_A)

    assert pbr.POLICY_RULES in graph.queries
    # both reads share the trace's rule rows
    assert pbr.POLICY_RULES.endswith(pbr._PBR_RULE_ROWS)
    assert pbr._INTERFACE_POLICY_RULES.endswith(pbr._PBR_RULE_ROWS)


def test_policy_route_sources_refuses_another_kind_of_object(graph):
    with pytest.raises(ToolError) as refused:
        sources(fixture.GROUP_A)
    assert refused.value.code == "invalid_argument"
    with pytest.raises(ToolError) as missing:
        sources("tun:none")
    assert missing.value.code == "not_found"


# --- object_addresses on an address object --------------------------------------------------


def test_object_addresses_expands_an_address_group_and_its_ranges(graph):
    answer = generator_tools.object_addresses(context(), {"uid": fixture.GROUP_B})

    assert (answer["label"], answer["name"]) == ("NetObject", "tunnel-b-download")
    assert answer["items"] == [
        {
            "uid": ip_uid("10.20.10.60"),
            "label": "IpAddress",
            "address": "10.20.10.60",
            "role": "object-member",
            "chain": [{"from": fixture.GROUP_B, "rel": "RESOLVES_TO", "to": ip_uid("10.20.10.60")}],
        }
    ]
    assert answer["ranges"] == [
        {"range": "10.20.10.70-10.20.10.72", "networks": ["10.20.10.70/31", "10.20.10.72"]}
    ]
    assert answer["unresolved"] == []

    inline = generator_tools.object_addresses(context(), {"uid": f"vyos:{fixture.HOST}:obj:{fixture.RANGE}"})
    assert inline["items"] == []
    assert inline["ranges"] == [{"range": fixture.RANGE, "networks": fixture.RANGE_NETWORKS}]


def test_an_address_group_is_searchable_by_name():
    assert generator_tools.LABELS["net_object"] == "NetObject"
    assert generator_tools.LABELS["pbr_policy"] == "PbrPolicy"
    assert "NetObject" in generator_tools.CHAIN_LABELS


# --- a generation over the tunnels ----------------------------------------------------------

DESCRIPTION = (
    "A business application for my WireGuard VPN tunnels, only for the IPs that are configured to use "
    "the tunnel: the peer-a tunnel as TV-STREAMING and the peer-b tunnel as ARRRRR."
)

UNRELATED = [(f"ep:host-{index}", "Endpoint", f"host-{index}") for index in range(50)]

CALLS: list[tuple[str, dict[str, Any]]] = [
    ("search_objects", {"kind": "tunnel", "q": "peer"}),
    ("policy_route_sources", {"uid": fixture.TUNNEL_A}),
    ("policy_route_sources", {"uid": fixture.TUNNEL_B}),
    ("search_objects", {"kind": "endpoint", "q": "10.20"}),
    ("search_objects", {"kind": "device", "q": "gw"}),
]


def members(prefix: str, sources_: list[tuple[str, str | None]]) -> str:
    lines = []
    for index, (address, uid) in enumerate(sources_):
        lines.append(f"      - id: {prefix}-{index}")
        lines.append(
            f'        inventory: {{kind: ip, uid: "{uid}", role: source}}'
            if uid
            else f"        address: {address}"
        )
    return "\n".join(lines)


MODEL_YAML = f"""\
schema_version: 1
kind: BusinessApplication
id: wireguard-tunnels
name: WireGuard VPN tunnels
state: draft
groups:
  - id: tv-streaming-clients
    name: TV-STREAMING clients
    description: Rule 10 of VPN-PBR and VPN-PBR-DEDICATED keeps 10.20.0.0/16 in the main table.
    members:
{members("a", [(a, ip_uid(a)) for a in GROUP_A_IPS] + [(n, None) for n in fixture.RANGE_NETWORKS])}
  - id: tv-streaming-internet
    name: Destinations through peer-a
    members:
      - id: low
        address: 0.0.0.0/5
      - id: high
        address: 128.0.0.0/1
  - id: arrrrr-clients
    name: ARRRRR clients
    members:
{members("b", [("10.20.10.60", ip_uid("10.20.10.60")), ("10.20.10.70/31", None), ("10.20.10.72", None)])}
  - id: arrrrr-internet
    name: Destinations through peer-b
    members:
      - id: high
        address: 128.0.0.0/1
connections:
  - id: tv-streaming
    name: TV-STREAMING through peer-a
    source: tv-streaming-clients
    destination: tv-streaming-internet
    destination_condition:
      kind: or
      parts:
        - {{kind: member, member: low}}
        - {{kind: member, member: high}}
  - id: arrrrr
    name: ARRRRR through peer-b
    source: arrrrr-clients
    destination: arrrrr-internet
    destination_condition: {{kind: member, member: high}}
"""

IP_ADDRESSES = [*GROUP_A_IPS, "10.20.10.60"]
CANDIDATES = {
    ip_uid(address): [
        InventoryCandidate(ip_uid(address), "ip", (AddressBinding(address, None, ip_uid(address)),))
    ]
    for address in IP_ADDRESSES
}


class Facts:
    def resolve(self, reference: InventoryReference) -> list[InventoryCandidate]:
        return list(CANDIDATES.get(reference.uid, []))

    def ip_nodes(self, address: str) -> list[str]:
        return [ip_uid(address)] if address in IP_ADDRESSES else []

    def dns_answers(self, uid: str) -> list[tuple[str, str]]:
        return []

    def device_role(self, uid: str) -> str | None:
        return None


async def generate(graph: fixture.BatchGraph):
    """One generation whose policy_route_sources answers come from the
    fixture graph, then the validation at the snapshot and the report."""
    real = {("policy_route_sources", uid): sources(uid) for uid in (fixture.TUNNEL_A, fixture.TUNNEL_B)}
    answers = {
        ("search_objects", "peer"): search(
            "tunnel", "peer", [(fixture.TUNNEL_A, "Tunnel", "peer-a"), (fixture.TUNNEL_B, "Tunnel", "peer-b")]
        ),
        ("search_objects", "10.20"): search(
            "endpoint", "10.20", [*UNRELATED, ("ep:tv", "Endpoint", "tv-streaming")]
        ),
        ("search_objects", "gw"): search("device", "gw", [(fixture.DEV, "Device", "gw")]),
        **real,
    }
    fake = FakeTools(answers)
    _registry, tools = offered(fake)
    reply = ScriptedModel(CALLS, MODEL_YAML).ask(tools)
    steps = generator.steps_of(reply.steps)
    draft = generator.postprocess(
        reply.answer, description=DESCRIPTION, steps=steps, facts=Facts(), snapshot=REFERENCE
    )

    async def resolve(definition, revision):
        return resolve_application(
            definition, revision=revision, snapshot=REFERENCE, reader=StaticInventoryReader(CANDIDATES)
        )

    validation = await validate_application(
        MemoryAssessmentStore(), draft.yaml, mode="replace", snapshot=REFERENCE, resolve=resolve
    )
    report = generator.report(draft, generation_id="gen-1", snapshot=REFERENCE, validation=validation)
    return steps, draft, validation, report


async def test_a_tunnel_application_writes_the_policy_route_sources(graph):
    steps, draft, validation, report = await generate(graph)

    assert not any(step.is_error for step in steps)
    assert draft.errors == []
    refs = {ref["path"]: ref for ref in report["references"]}
    assert all(ref["status"] == "resolved" for ref in refs.values()), [
        (path, ref["status"]) for path, ref in refs.items() if ref["status"] != "resolved"
    ]
    member = refs["groups.tv-streaming-clients.members.a-0"]
    assert (member["kind"], member["uid"], member["selection"]) == ("ip", ip_uid("10.20.10.43"), "exact")
    assert {"from": fixture.GROUP_A, "rel": "RESOLVES_TO", "to": ip_uid("10.20.10.43")} in member["chain"]
    assert 2 in {item["step"] for item in member["evidence"]}
    ranged = refs["groups.tv-streaming-clients.members.a-3"]
    assert ranged["bindings"] == [{"address": "10.20.210.50/31", "context": None}]
    assert report["blocking"] == []
    assert validation["errors"] == []
    readiness = {c["id"]: c["readiness"] for c in validation["resolution"]["connections"]}
    assert readiness == {"tv-streaming": "ready", "arrrrr": "ready"}


async def test_a_connection_the_description_gives_no_port_allows_any_protocol_and_port(graph):
    _steps, draft, validation, _report = await generate(graph)

    assert draft.definition is not None
    for connection in draft.definition.connections:
        assert connection.protocol is None
        assert connection.destination_ports is None
    for connection in validation["resolution"]["connections"]:
        request = connection["request"]
        assert "proto" not in request and "port" not in request
        assert all("proto" not in member and "port" not in member for member in request["members"])


async def test_found_and_not_written_keeps_the_objects_that_matter_to_the_request(graph):
    _steps, _draft, _validation, report = await generate(graph)

    assert [(item["uid"], item["reason"]) for item in report["related"]] == [
        (fixture.TUNNEL_A, "policy_route_sources at step 2 started from it and returned a written member"),
        (fixture.TUNNEL_B, "policy_route_sources at step 3 started from it and returned a written member"),
        ("ep:tv", "the description names streaming"),
        (fixture.DEV, "policy_route_sources at step 2 returned it with a written member"),
    ]
    assert report["related"][0]["relation"] == "returned by search_objects at step 1"
    # the 50 endpoints of the broad search are only counted
    assert report["related_omitted"] == 50
    assert json.dumps(report["related"]).count("ep:host-") == 0


def test_the_prompt_maps_tunnel_phrases_to_the_tool_and_names_no_stand_in_port():
    system = generator.SYSTEM
    assert "policy_route_sources" in system
    assert "the IPs configured to use the tunnel" in " ".join(system.split())
    flat = " ".join(system.split())
    assert "the connection then allows any protocol and port" in flat
    assert "Never write a port that the description does not give" in flat
    assert "stand-in" not in flat
    assert "never write that the snapshot does not show something a tool result shows" in flat
    assert "policy_route_sources" in [spec.name for spec in generator_tools.specs()]
