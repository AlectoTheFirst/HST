"""The Business Application generator: its tool list, the post-processor and
the report, run on the Webshop example with fake
tools and a fake snapshot."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, get_args

import pytest

from hst.app.agent.base import AgentAnswer
from hst.app.agent.tools import agent_registry, dispatch, offered_tools
from hst.app.ai import prompt
from hst.app.ai.registry import Principal, ToolContext, ToolError
from hst.applications import generator, generator_tools
from hst.applications.models import BusinessApplicationDefinition, InventoryReference
from hst.applications.resolution import (
    AddressBinding,
    InventoryCandidate,
    StaticInventoryReader,
    resolve_application,
)
from hst.applications.validation import validate_application
from hst.applications.yaml_format import canonical_yaml, definition_digest, parse_application_yaml
from hst.assessment import discovery
from hst.assessment.store import MemoryAssessmentStore
from hst.core.snapshot import Snapshot

SNAPSHOT = "4000"
REFERENCE = {
    "snapshot": SNAPSHOT,
    "manifest_sha256": "a" * 64,
    "estate": "test",
    "observation_floor_ms": None,
}

DESCRIPTION = (
    "Webshop, owned by ecommerce, production. Frankfurt office users reach webshop.corp.example over "
    "HTTPS on the NetScaler VIP web-443. The VIP balances to web01 on 8443. web01 reads the Postgres "
    "database on db01."
)

FRA_USERS = "pfx:vrf-dev-fra01-core-01-corp:10.20.0.0/24"
FRA_GUEST = "pfx:guest:172.31.10.0/24"
DNS = "dns:webshop.corp.example:A"
VIP = "ns:dc1-ns01:lbvs:web-443"
VIP_IP = "ip:corp:10.0.30.10"
WEB_IP = "ip:corp:10.0.10.5"
DB_IP = "ip:corp:10.0.20.5"
RGRP = "rgrp:ns-ha:dc1:ns01"


def edge(a: str, rel: str, b: str) -> dict[str, str]:
    return {"from": a, "rel": rel, "to": b}


def envelope(result: dict[str, Any]) -> dict[str, Any]:
    """A catalogue envelope around `result`, with the fields the post-processor ignores."""
    return {
        "snapshot": {"id": SNAPSHOT, "collection_ts": int(SNAPSHOT), "selector": SNAPSHOT},
        "provenance": {"tool": "fake", "tool_version": 1},
        "evidence": {"status": "proven"},
        "page": {"truncated": False},
        "result": result,
        "warnings": [],
    }


def search(kind: str, q: str, items: list[tuple[str, str, str]]) -> dict[str, Any]:
    return {
        "snapshot": SNAPSHOT,
        "kind": kind,
        "q": q,
        "items": [{"uid": uid, "label": label, "kind": kind, "name": name} for uid, label, name in items],
        "truncated": False,
    }


# The answer of each call the scripted model makes, keyed by tool and the
# argument that names what the call looks up.
ANSWERS: dict[tuple[str, str], dict[str, Any]] = {
    ("search_objects", "frankfurt"): search(
        "site", "frankfurt", [("site:fra01", "Site", "Frankfurt Office 1")]
    ),
    ("search_objects", "fra01"): search(
        "network", "fra01", [(FRA_USERS, "Prefix", "fra01-users"), (FRA_GUEST, "Prefix", "fra01-guest")]
    ),
    ("resolve_hostname", "webshop.corp.example"): {
        "snapshot": SNAPSHOT,
        "fqdn": "webshop.corp.example",
        "records": [
            {
                "uid": DNS,
                "label": "DnsRecord",
                "addresses": ["10.0.30.10/32"],
                "ip_nodes": [
                    {
                        "uid": VIP_IP,
                        "label": "IpAddress",
                        "address": "10.0.30.10",
                        "role": "dns-answer",
                        "chain": [edge(DNS, "RESOLVES_TO", VIP_IP)],
                    }
                ],
            }
        ],
        "complete": True,
        "notes": [],
    },
    ("search_objects", "web-443"): search("vip", "web-443", [(VIP, "VirtualService", "web-443")]),
    ("object_addresses", VIP): {
        "snapshot": SNAPSHOT,
        "uid": VIP,
        "label": "VirtualService",
        "name": "web-443",
        "items": [
            {
                "uid": VIP_IP,
                "label": "IpAddress",
                "address": "10.0.30.10",
                "role": "vip",
                "chain": [edge(VIP, "VIP", VIP_IP)],
            },
            {
                "uid": WEB_IP,
                "label": "IpAddress",
                "address": "10.0.10.5",
                "role": "pool-member",
                "port": 8443,
                "chain": [
                    edge(VIP, "USES", "ns:dc1-ns01:sg:web"),
                    edge("ns:dc1-ns01:sg:web", "HAS_MEMBER", "ns:dc1-ns01:sg:web/10.0.10.5:8443"),
                    edge("ns:dc1-ns01:sg:web/10.0.10.5:8443", "TARGETS", WEB_IP),
                ],
            },
        ],
        "truncated": False,
        "unresolved": [
            {"chain": [edge(VIP, "ON", RGRP)], "detail": "no address is recorded along this chain"}
        ],
    },
    ("inventory_resolve", "10.0.30.10"): envelope(
        {
            "kind": "address",
            "address": "10.0.30.10",
            "sections": {"ip_nodes": {"rows": [{"uid": VIP_IP, "anchor": "corp"}], "truncated": False}},
        }
    ),
    ("inventory_search", "ns01"): envelope({"query": "ns01", "items": []}),
    ("search_objects", "web01"): search("vm", "web01", [("vc:vc01:vm-101", "Vm", "web01")]),
    ("object_addresses", "vc:vc01:vm-101"): {
        "snapshot": SNAPSHOT,
        "uid": "vc:vc01:vm-101",
        "label": "Vm",
        "name": "web01",
        "items": [
            {
                "uid": WEB_IP,
                "label": "IpAddress",
                "address": "10.0.10.5",
                "role": "vnic",
                "chain": [
                    edge("vc:vc01:vm-101/vnic/0", "OF", "vc:vc01:vm-101"),
                    edge("vc:vc01:vm-101/vnic/0", "HAS_IP", WEB_IP),
                ],
            }
        ],
        "truncated": False,
        "unresolved": [],
    },
    ("search_objects", "db01"): search("vm", "db01", [("vc:vc01:vm-102", "Vm", "db01")]),
    ("object_addresses", "vc:vc01:vm-102"): {
        "snapshot": SNAPSHOT,
        "uid": "vc:vc01:vm-102",
        "label": "Vm",
        "name": "db01",
        "items": [
            {
                "uid": DB_IP,
                "label": "IpAddress",
                "address": "10.0.20.5",
                "role": "vnic",
                "chain": [
                    edge("vc:vc01:vm-102/vnic/0", "OF", "vc:vc01:vm-102"),
                    edge("vc:vc01:vm-102/vnic/0", "HAS_IP", DB_IP),
                ],
            }
        ],
        "truncated": False,
        "unresolved": [],
    },
    ("app_applications", "list"): envelope({"mode": "list", "items": [], "related": []}),
}

# The calls of the Webshop example in order. One call names another run, which the
# generator overrides.
WEBSHOP_CALLS: list[tuple[str, dict[str, Any]]] = [
    ("search_objects", {"kind": "site", "q": "frankfurt"}),
    ("search_objects", {"kind": "network", "q": "fra01"}),
    ("resolve_hostname", {"fqdn": "webshop.corp.example"}),
    ("search_objects", {"kind": "vip", "q": "web-443"}),
    ("object_addresses", {"uid": VIP}),
    ("inventory_resolve", {"kind": "address", "address": "10.0.30.10", "snapshot": "999"}),
    ("inventory_search", {"q": "ns01", "label": "Device"}),
    ("search_objects", {"kind": "vm", "q": "web01"}),
    ("object_addresses", {"uid": "vc:vc01:vm-101"}),
    ("search_objects", {"kind": "vm", "q": "db01"}),
    ("object_addresses", {"uid": "vc:vc01:vm-102"}),
    ("app_applications", {"mode": "list", "name_contains": "webshop"}),
]

# The model writes the VIP member as the DNS record; the post-processor writes
# the ip uid the VIP lookup names.
MODEL_YAML = f"""\
schema_version: 2
kind: BusinessApplication
id: webshop
name: Webshop
description: >-
  Frankfurt office users reach webshop.corp.example over HTTPS on the NetScaler
  VIP web-443; the VIP balances to web01 on tcp/8443; web01 reads the Postgres
  database on db01.
owner: ecommerce
environment: production
state: draft
services:
  - id: webshop-storefront
    name: Webshop storefront
    connection_ids: [users-to-vip, snip-to-web]
    component_roles:
      - {{group_id: fra01-users, role: client}}
      - {{group_id: webshop-vip, role: endpoint}}
      - {{group_id: netscaler-snip, role: component}}
      - {{group_id: web-tier, role: component}}
  - id: webshop-data
    name: Webshop data tier
    connection_ids: [web-to-db]
    component_roles:
      - {{group_id: web-tier, role: component}}
      - {{group_id: db-tier, role: dependency}}
groups:
  - id: fra01-users
    name: Frankfurt Office 1 users
    members:
      - id: fra01-users-net
        name: fra01-users
        inventory: {{kind: network, uid: "{FRA_USERS}", role: source}}
  - id: webshop-vip
    name: NetScaler VIP web-443
    members:
      - id: web-443-vip
        name: webshop.corp.example
        inventory: {{kind: dns, uid: "{DNS}", role: destination}}
  - id: netscaler-snip
    name: NetScaler ns01 SNAT source
    members:
      - id: ns01-snip
        placeholder:
          text: NetScaler ns01 subnet IP used as source towards the web pool
          expected_kind: ip
          status: unresolved
          candidates: []
          note: {RGRP} has no member device and no address at this snapshot
  - id: web-tier
    name: Web tier
    members:
      - id: web01
        name: web01
        inventory: {{kind: ip, uid: "{WEB_IP}", role: component}}
  - id: db-tier
    name: Database tier
    members:
      - id: db01
        name: db01
        inventory: {{kind: ip, uid: "{DB_IP}", role: destination}}
connections:
  - id: users-to-vip
    name: Users to webshop VIP (HTTPS)
    source: fra01-users
    destination: webshop-vip
    protocol: tcp
    destination_ports: [443]
    success: session
    destination_condition: {{kind: member, member: web-443-vip}}
  - id: snip-to-web
    name: NetScaler to web01 (pool web, tcp/8443)
    source: netscaler-snip
    destination: web-tier
    protocol: tcp
    destination_ports: [8443]
    success: session
    destination_condition: {{kind: member, member: web01}}
  - id: web-to-db
    name: web01 to db01 (Postgres)
    source: web-tier
    destination: db-tier
    protocol: tcp
    destination_ports: [5432]
    success: session
    destination_condition: {{kind: member, member: db01}}
"""


def candidate(uid: str, kind: str, address: str) -> InventoryCandidate:
    return InventoryCandidate(uid=uid, kind=kind, addresses=(AddressBinding(address, None, uid),))


CANDIDATES = {
    FRA_USERS: [candidate(FRA_USERS, "network", "10.20.0.0/24")],
    FRA_GUEST: [candidate(FRA_GUEST, "network", "172.31.10.0/24")],
    DNS: [candidate(DNS, "dns", "10.0.30.10")],
    VIP_IP: [candidate(VIP_IP, "ip", "10.0.30.10")],
    WEB_IP: [candidate(WEB_IP, "ip", "10.0.10.5")],
    DB_IP: [candidate(DB_IP, "ip", "10.0.20.5")],
}


class FakeFacts:
    """The graph at snapshot 4000 as the post-processor reads it."""

    def __init__(self, candidates=None, ip_nodes=None, dns=None, roles=None):
        self.candidates = CANDIDATES if candidates is None else candidates
        self.nodes = ip_nodes or {}
        self.dns = {DNS: [(VIP_IP, "10.0.30.10")]} if dns is None else dns
        self.roles = roles or {}

    def resolve(self, reference: InventoryReference) -> list[InventoryCandidate]:
        return list(self.candidates.get(reference.uid, []))

    def ip_nodes(self, address: str) -> list[str]:
        return self.nodes.get(address) or [
            uid
            for uid, found in self.candidates.items()
            if found[0].kind == "ip" and found[0].addresses[0].address == address
        ]

    def dns_answers(self, uid: str) -> list[tuple[str, str]]:
        return list(self.dns.get(uid, []))

    def device_role(self, uid: str) -> str | None:
        return self.roles.get(uid)


class FakeTools:
    """The real generator specs with bodies that answer from `ANSWERS` and
    record the run each call read."""

    def __init__(self, answers=None):
        self.answers = ANSWERS if answers is None else answers
        self.reads: list[tuple[str, int | None, str | None]] = []

    def body(self, name: str):
        def run(ctx: ToolContext, arguments: dict[str, Any]) -> str:
            self.reads.append((name, ctx.snapshot.cts if ctx.snapshot else None, arguments.get("snapshot")))
            key = next(arguments[k] for k in ("q", "fqdn", "uid", "address", "mode") if k in arguments)
            return json.dumps(self.answers[(name, key)])

        return run

    def specs(self):
        return [replace(spec, run=self.body(spec.name)) for spec in generator.generator_specs()]


class ScriptedModel:
    """Makes the given calls through the offered tools, then answers."""

    def __init__(self, calls, answer):
        self.calls = calls
        self.answer = answer

    def ask(self, tools) -> AgentAnswer:
        steps = [dispatch(tools, name, dict(arguments)) for name, arguments in self.calls]
        return AgentAnswer(answer=self.answer, steps=steps)


def offered(fake: FakeTools):
    registry = generator.generator_registry(SNAPSHOT, fake.specs())
    ctx = ToolContext(
        settings=None,
        principal=Principal.for_role("viewer", user_id=7),
        surface="service_generator",
        snapshot=Snapshot(int(SNAPSHOT), None),
    )
    return registry, offered_tools(ctx, registry)


async def static_resolve(definition: BusinessApplicationDefinition, revision: int) -> dict:
    return resolve_application(
        definition, revision=revision, snapshot=REFERENCE, reader=StaticInventoryReader(CANDIDATES)
    )


async def generate(calls, answer, facts=None, description=DESCRIPTION, answers=None):
    """Run one generation with fake tools: the scripted model turn, the
    post-processor, the validation at the snapshot and the report."""
    fake = FakeTools(answers)
    _registry, tools = offered(fake)
    reply = ScriptedModel(calls, answer).ask(tools)
    steps = generator.steps_of(reply.steps)
    draft = generator.postprocess(
        reply.answer,
        description=description,
        steps=steps,
        facts=facts or FakeFacts(),
        snapshot=REFERENCE,
    )
    validation = await validate_application(
        MemoryAssessmentStore(),
        draft.yaml,
        mode="replace",
        snapshot=REFERENCE,
        resolve=static_resolve,
        application_id=draft.definition.id if draft.definition else None,
    )
    report = generator.report(draft, generation_id="gen-1", snapshot=REFERENCE, validation=validation)
    return fake, steps, draft, validation, report


def by_path(report):
    return {ref["path"]: ref for ref in report["references"]}


# --- the Webshop example -------------------------------------------------------------------


async def test_the_webshop_example_resolves_as_the_review_reports_it():
    _fake, steps, draft, validation, report = await generate(WEBSHOP_CALLS, f"```yaml\n{MODEL_YAML}```")

    assert [step.tool for step in steps] == [name for name, _ in WEBSHOP_CALLS]
    assert not any(step.is_error for step in steps)
    # the post-processed document is the v2 definition of the Webshop example: the
    # VIP member is the ip uid, following the hostname rule
    written = MODEL_YAML.replace(f'{{kind: dns, uid: "{DNS}"', f'{{kind: ip, uid: "{VIP_IP}"')
    expected = parse_application_yaml(written)
    assert draft.definition == expected
    assert draft.yaml == canonical_yaml(expected)
    assert draft.errors == []

    refs = by_path(report)
    assert list(refs) == [
        "groups.fra01-users.members.fra01-users-net",
        "groups.webshop-vip.members.web-443-vip",
        "groups.netscaler-snip.members.ns01-snip",
        "groups.web-tier.members.web01",
        "groups.db-tier.members.db01",
    ]
    users = refs["groups.fra01-users.members.fra01-users-net"]
    assert (users["status"], users["selection"], users["kind"], users["uid"]) == (
        "resolved",
        "model-choice",
        "network",
        FRA_USERS,
    )
    assert users["alternatives"] == [FRA_GUEST]
    assert users["bindings"] == [{"address": "10.20.0.0/24", "context": None}]
    assert {"step": 2, "tool": "search_objects", "arguments": {"kind": "network", "q": "fra01"}} in users[
        "evidence"
    ]

    vip = refs["groups.webshop-vip.members.web-443-vip"]
    assert (vip["status"], vip["selection"], vip["kind"], vip["uid"]) == ("resolved", "exact", "ip", VIP_IP)
    assert vip["phrase"] == "webshop.corp.example"
    assert vip["alternatives"] == []
    assert edge(DNS, "RESOLVES_TO", VIP_IP) in vip["chain"]
    assert edge(VIP, "VIP", VIP_IP) in vip["chain"]
    assert {3, 5, 6} <= {item["step"] for item in vip["evidence"]}

    snip = refs["groups.netscaler-snip.members.ns01-snip"]
    assert (snip["status"], snip["selection"], snip["kind"], snip["uid"]) == (
        "unresolved",
        "none",
        None,
        None,
    )
    assert [issue["code"] for issue in snip["issues"]] == ["member-placeholder"]
    assert snip["issues"][0]["detail"] == "unbound placeholder (unresolved)"

    web = refs["groups.web-tier.members.web01"]
    assert (web["status"], web["selection"], web["uid"]) == ("resolved", "exact", WEB_IP)
    assert edge("vc:vc01:vm-101/vnic/0", "HAS_IP", WEB_IP) in web["chain"]
    assert edge("ns:dc1-ns01:sg:web/10.0.10.5:8443", "TARGETS", WEB_IP) in web["chain"]
    db = refs["groups.db-tier.members.db01"]
    assert (db["status"], db["selection"], db["uid"]) == ("resolved", "exact", DB_IP)

    assert report["blocking"] == ["groups.netscaler-snip.members.ns01-snip"]
    assert [item["uid"] for item in report["related"]] == ["site:fra01"]
    assert report["definition_digest"] == definition_digest(expected)
    assert report["snapshot"] == REFERENCE

    assert validation["errors"] == []
    assert validation["preview"] is None
    readiness = {c["id"]: c["readiness"] for c in validation["resolution"]["connections"]}
    assert readiness == {"users-to-vip": "ready", "snip-to-web": "unresolved", "web-to-db": "ready"}


async def test_one_generation_reads_one_snapshot():
    fake, _steps, _draft, _validation, report = await generate(WEBSHOP_CALLS, MODEL_YAML)

    # every call read run 4000, including the one that named run 999
    assert {(cts, named) for _name, cts, named in fake.reads if named is not None} == {(4000, SNAPSHOT)}
    assert {cts for _name, cts, _named in fake.reads} == {4000}
    assert report["snapshot"]["snapshot"] == SNAPSHOT


async def test_the_step_arguments_leave_out_the_run_the_model_named():
    _fake, steps, _draft, _validation, report = await generate(WEBSHOP_CALLS, MODEL_YAML)

    assert steps[5].arguments == {"kind": "address", "address": "10.0.30.10"}
    evidence = [item for ref in report["references"] for item in ref["evidence"]]
    assert 6 in {item["step"] for item in evidence}
    assert all("snapshot" not in item["arguments"] for item in evidence)


def test_the_tools_publish_no_snapshot_and_are_offered_on_the_generator_surface_only():
    registry = generator.generator_registry(SNAPSHOT)
    assert [spec.name for spec in registry.specs()] == [
        "inventory_search",
        "inventory_resolve",
        "app_applications",
        "lb_lookup_vip",
        "search_objects",
        "resolve_hostname",
        "object_addresses",
        "policy_route_sources",
    ]
    for spec in registry.specs():
        assert spec.surfaces == frozenset({"service_generator"})
        assert spec.limits.max_model_chars <= 100_000
        assert '"snapshot"' not in json.dumps(spec.input_schema()), spec.name
    viewer = Principal.for_role("viewer", user_id=1)
    assert len(registry.offered(viewer, "service_generator")) == 8
    assert registry.offered(viewer, "drawer") == []
    # the catalogue itself keeps its snapshot argument
    assert "snapshot" in agent_registry().get("inventory_search").input_schema()["properties"]


def test_a_bound_catalogue_tool_reads_the_generation_run_whatever_the_model_names():
    fake = FakeTools()
    _registry, tools = offered(fake)
    dispatch(tools, "inventory_search", {"q": "ns01", "snapshot": "999"})
    dispatch(tools, "inventory_search", {"q": "ns01"})
    assert fake.reads == [("inventory_search", 4000, SNAPSHOT), ("inventory_search", 4000, SNAPSHOT)]


def test_a_generator_tool_without_the_pinned_run_is_refused():
    ctx = ToolContext(settings=None, principal=Principal.for_role("viewer"), surface="service_generator")
    with pytest.raises(ToolError) as refused:
        generator_tools.object_addresses(ctx, {"uid": VIP})
    assert refused.value.code == "snapshot_not_found"


def test_the_private_label_map_leaves_the_discovery_kinds_unchanged():
    assert discovery.KINDS == {
        "service": "ServiceRequirement",
        "device": "Device",
        "interface": "Interface",
        "rulebase": "FwRulebase",
        "link": "WanLink",
        "tunnel": "Tunnel",
        "domain": "FailureDomain",
    }
    assert set(get_args(generator_tools.SearchKind)) == set(generator_tools.LABELS)
    assert {generator_tools.LABELS[kind] for kind in ("vip", "zone", "vm", "endpoint")} == {
        "VirtualService",
        "Zone",
        "Vm",
        "Endpoint",
    }
    assert {"VirtualService", "Zone", "Vm", "Endpoint"} <= set(generator_tools.CHAIN_LABELS)


# --- the post-processing rules -------------------------------------------------------------


def one_member_yaml(member: str, *, state: str = "draft", version: int = 1) -> str:
    return f"""\
schema_version: {version}
kind: BusinessApplication
id: shop
name: Shop
state: {state}
groups:
  - id: clients
    name: Clients
    members:
      - {{id: lan, address: 10.20.0.0/24}}
  - id: servers
    name: Servers
    members:
      - {member}
connections:
  - id: web
    name: Web
    source: clients
    destination: servers
    protocol: tcp
    destination_ports: [443]
    destination_condition: {{kind: member, member: server}}
"""


LOOKUPS = [("search_objects", {"kind": "network", "q": "fra01"}), ("object_addresses", {"uid": VIP})]


async def test_a_uid_not_seen_in_a_step_becomes_a_placeholder():
    member = '{id: server, name: web02, inventory: {kind: ip, uid: "ip:corp:10.0.10.6", role: destination}}'
    _fake, _steps, draft, validation, report = await generate(
        LOOKUPS, one_member_yaml(member, state="ready"), description="clients 10.20.0.0/24 reach web02"
    )

    assert draft.definition is not None
    (server,) = draft.definition.groups[1].members
    assert server.inventory is None
    assert server.placeholder is not None
    assert server.placeholder.model_dump() == {
        "text": "web02",
        "expected_kind": "ip",
        "status": "unresolved",
        "candidates": [],
        "note": "not returned by any lookup",
    }
    # a placeholder makes the document schema version 2 and draft
    assert (draft.definition.schema_version, draft.definition.state) == (2, "draft")
    ref = by_path(report)["groups.servers.members.server"]
    assert (ref["status"], ref["selection"], ref["uid"]) == ("unresolved", "none", None)
    assert report["blocking"] == ["groups.servers.members.server"]
    assert validation["errors"] == []
    # the literal client prefix is named in the description and stays
    assert by_path(report)["groups.clients.members.lan"]["status"] == "resolved"


async def test_a_literal_address_named_nowhere_becomes_a_placeholder():
    member = "{id: server, name: backend, address: 198.51.100.7}"
    _fake, _steps, draft, _validation, report = await generate(
        LOOKUPS, one_member_yaml(member), description="clients 10.20.0.0/24 reach the backend"
    )
    (server,) = draft.definition.groups[1].members
    assert server.address is None
    assert (server.placeholder.expected_kind, server.placeholder.note) == ("ip", "not returned by any lookup")
    assert by_path(report)["groups.servers.members.server"]["status"] == "unresolved"


async def test_a_duplicate_ip_address_becomes_an_ambiguous_placeholder():
    member = f'{{id: server, name: web01, inventory: {{kind: ip, uid: "{WEB_IP}", role: destination}}}}'
    facts = FakeFacts(ip_nodes={"10.0.10.5": [WEB_IP, "ip:bd-12:10.0.10.5"]})
    _fake, _steps, draft, _validation, report = await generate(
        LOOKUPS, one_member_yaml(member), facts=facts, description="clients 10.20.0.0/24 reach web01"
    )
    (server,) = draft.definition.groups[1].members
    assert server.placeholder.status == "ambiguous"
    assert server.placeholder.candidates == [WEB_IP, "ip:bd-12:10.0.10.5"]
    assert "2 IpAddress nodes" in server.placeholder.note
    ref = by_path(report)["groups.servers.members.server"]
    assert (ref["status"], ref["alternatives"]) == ("ambiguous", [WEB_IP, "ip:bd-12:10.0.10.5"])


async def test_a_reference_is_resolved_again_at_the_snapshot():
    member = f'{{id: server, name: web01, inventory: {{kind: network, uid: "{WEB_IP}", role: destination}}}}'
    _fake, _steps, draft, _validation, _report = await generate(
        LOOKUPS, one_member_yaml(member), description="clients 10.20.0.0/24 reach web01"
    )
    (server,) = draft.definition.groups[1].members
    assert (server.placeholder.status, server.placeholder.note) == (
        "unresolved",
        "expected network, found ip",
    )
    assert server.placeholder.candidates == [WEB_IP]

    gone = FakeFacts(candidates={k: v for k, v in CANDIDATES.items() if k != WEB_IP})
    member = f'{{id: server, name: web01, inventory: {{kind: ip, uid: "{WEB_IP}", role: destination}}}}'
    _fake, _steps, draft, _validation, _report = await generate(
        LOOKUPS, one_member_yaml(member), facts=gone, description="clients 10.20.0.0/24 reach web01"
    )
    (server,) = draft.definition.groups[1].members
    assert server.placeholder.note == f"{WEB_IP} was not found at snapshot 4000"


async def test_a_hostname_stays_a_dns_reference_without_a_vip_or_address_for_it():
    calls = [("resolve_hostname", {"fqdn": "webshop.corp.example"})]
    member = f'{{id: server, name: webshop, inventory: {{kind: dns, uid: "{DNS}", role: destination}}}}'
    _fake, _steps, draft, _validation, report = await generate(
        calls, one_member_yaml(member), description="clients 10.20.0.0/24 reach webshop.corp.example"
    )
    (server,) = draft.definition.groups[1].members
    assert (server.inventory.kind, server.inventory.uid) == ("dns", DNS)
    assert by_path(report)["groups.servers.members.server"]["selection"] == "exact"

    # an address in the description names the node the record resolves to
    _fake, _steps, draft, _validation, _report = await generate(
        calls, one_member_yaml(member), description="clients 10.20.0.0/24 reach webshop on 10.0.30.10"
    )
    (server,) = draft.definition.groups[1].members
    assert (server.inventory.kind, server.inventory.uid) == ("ip", VIP_IP)


async def test_a_document_that_does_not_parse_comes_back_as_text_with_its_errors():
    _fake, _steps, draft, validation, report = await generate(LOOKUPS, "id: shop\nname: [unclosed\n")
    assert draft.definition is None
    assert draft.yaml == "id: shop\nname: [unclosed\n"
    assert draft.errors and draft.errors[0]["line"] is not None
    assert validation["errors"] == draft.errors
    assert report["references"] == [] and report["definition_digest"] is None


async def test_a_value_a_step_only_repeats_from_its_arguments_counts_as_not_returned():
    unknown = "ip:corp:10.0.10.9"
    answers = {
        **ANSWERS,
        ("search_objects", unknown): search("ip", unknown, []),
        ("inventory_resolve", "198.51.100.7"): envelope(
            {
                "kind": "address",
                "address": "198.51.100.7",
                "sections": {"ip_nodes": {"rows": [], "truncated": False}},
            }
        ),
    }
    calls = [
        ("search_objects", {"kind": "ip", "q": unknown}),
        ("inventory_resolve", {"kind": "address", "address": "198.51.100.7"}),
    ]
    for member in (
        f'{{id: server, name: web09, inventory: {{kind: ip, uid: "{unknown}", role: destination}}}}',
        "{id: server, name: backend, address: 198.51.100.7}",
    ):
        _fake, _steps, draft, _validation, report = await generate(
            calls, one_member_yaml(member), description="clients 10.20.0.0/24 reach it", answers=answers
        )
        (server,) = draft.definition.groups[1].members
        assert server.placeholder.note == generator.NOT_RETURNED, member
        assert by_path(report)["groups.servers.members.server"]["evidence"] == [], member


async def test_a_node_of_another_kind_on_the_chain_gives_no_alternatives():
    other = "ns:dc1-ns01:lbvs:web-80"
    answers = {
        **ANSWERS,
        ("search_objects", "web"): search(
            "vip", "web", [(VIP, "VirtualService", "web-443"), (other, "VirtualService", "web-80")]
        ),
    }
    calls = [("search_objects", {"kind": "vip", "q": "web"}), ("object_addresses", {"uid": VIP})]
    member = f'{{id: server, name: web01, inventory: {{kind: ip, uid: "{WEB_IP}", role: destination}}}}'

    _fake, _steps, _draft, _validation, report = await generate(
        calls, one_member_yaml(member), description="clients 10.20.0.0/24 reach web01", answers=answers
    )

    # the pool member's chain runs through the VIP; the other VIP is no alternative for an ip
    ref = by_path(report)["groups.servers.members.server"]
    assert edge(VIP, "USES", "ns:dc1-ns01:sg:web") in ref["chain"]
    assert (ref["status"], ref["selection"], ref["alternatives"]) == ("resolved", "exact", [])


async def test_a_firewall_or_a_router_device_becomes_a_placeholder():
    firewall = "dev:fw01"
    answers = {
        **ANSWERS,
        ("inventory_search", "fw01"): envelope(
            {"query": "fw01", "items": [{"uid": firewall, "label": "Device", "name": "fw01"}]}
        ),
    }
    calls = [("inventory_search", {"q": "fw01", "label": "Device"})]
    candidates = {**CANDIDATES, firewall: [candidate(firewall, "device", "10.0.0.1")]}
    member = f'{{id: server, name: fw01, inventory: {{kind: device, uid: "{firewall}", role: destination}}}}'

    for role in ("firewall", "router"):
        facts = FakeFacts(candidates=candidates, roles={firewall: role})
        _fake, _steps, draft, _validation, report = await generate(
            calls,
            one_member_yaml(member),
            facts=facts,
            description="clients 10.20.0.0/24 reach fw01",
            answers=answers,
        )
        (server,) = draft.definition.groups[1].members
        assert server.inventory is None
        assert (server.placeholder.status, server.placeholder.candidates) == ("unresolved", [])
        assert (
            server.placeholder.note == f"{firewall} is a {role}, and a firewall or a router is never a member"
        )
        assert by_path(report)["groups.servers.members.server"]["status"] == "unresolved"

    facts = FakeFacts(candidates=candidates)
    _fake, _steps, draft, _validation, report = await generate(
        calls,
        one_member_yaml(member),
        facts=facts,
        description="clients 10.20.0.0/24 reach fw01",
        answers=answers,
    )
    (server,) = draft.definition.groups[1].members
    assert server.inventory.uid == firewall
    assert by_path(report)["groups.servers.members.server"]["status"] == "resolved"


def test_an_edit_keeps_a_report_row_for_a_placeholder_it_leaves_unchanged():
    text = one_member_yaml(
        "{id: server, placeholder: {text: the backend host, expected_kind: ip}}", version=2
    )
    base = parse_application_yaml(text)

    draft = generator.postprocess(
        text, description="Keep the application.", steps=[], facts=FakeFacts(), snapshot=REFERENCE, base=base
    )

    assert draft.definition == base
    # the kept literal client prefix has no row; the kept placeholder has one
    (row,) = draft.references
    assert (row["path"], row["phrase"], row["status"], row["selection"]) == (
        "groups.servers.members.server",
        "the backend host",
        "unresolved",
        "none",
    )


def test_the_edit_question_fences_the_export_past_its_longest_backtick_run():
    export = "id: shop\ndescription: a ```` fenced ``` note\n"

    question = generator.edit_question("Rename it.", export, application_id="shop", revision=3)

    assert question == (
        "Change: Rename it.\n\nSaved revision 3 of application shop:\n"
        "`````yaml\nid: shop\ndescription: a ```` fenced ``` note\n`````"
    )
    plain = generator.edit_question("Rename it.", "id: shop\n", application_id="shop", revision=3)
    assert plain.endswith("```yaml\nid: shop\n```")


def test_graph_facts_read_the_device_role_and_look_up_only_single_addresses():
    class Session:
        cts = 4000

        def __init__(self):
            self.params = []

        def execute_read(self, work):
            return work(self)

        def run(self, query, **params):
            self.params.append(params)
            rows = [{"role": "firewall"}] if params.get("uid") == "dev:fw01" else []
            return SimpleNamespace(data=lambda: rows)

    session = Session()
    facts = generator_tools.GraphFacts(session, REFERENCE)

    assert facts.ip_nodes("10.0.10.0/24") == []
    assert session.params == []
    assert facts.device_role("dev:fw01") == "firewall"
    assert facts.device_role("dev:sw01") is None
    assert [params["uid"] for params in session.params] == ["dev:fw01", "dev:sw01"]
    assert {params["snap"] for params in session.params} == {4000}


def test_the_generation_record_keeps_arguments_and_result_digests():
    step = generator.Step("search_objects", {"kind": "vm", "q": "web01"}, '{"items": []}', False)
    draft = generator.Draft(yaml="id: shop\n", definition=None, errors=[{"path": "$", "message": "m"}])
    report = generator.report(draft, generation_id="gen-1", snapshot=REFERENCE, validation=None)
    record = generator.generation_record(
        generation_id="gen-1",
        created_by=3,
        created_at=datetime(2026, 9, 29, tzinfo=UTC),
        snapshot=REFERENCE,
        source={"kind": "description"},
        description="d",
        provider="anthropic",
        model="m",
        system_prompt_sha256="0" * 64,
        steps=[step],
        draft=draft,
        report=report,
        validation=None,
        validation_digest=None,
    )
    assert record["steps"] == [
        {
            "tool": "search_objects",
            "arguments": {"kind": "vm", "q": "web01"},
            "result_sha256": hashlib.sha256(b'{"items": []}').hexdigest(),
            "is_error": False,
        }
    ]
    assert "result" not in record["steps"][0]
    assert (record["created_by"], record["snapshot"], record["errors"]) == (3, REFERENCE, draft.errors)


def test_the_prompt_is_the_structured_base_and_the_generator_layer():
    assembled = generator.system_prompt(Principal.for_role("admin"), [])
    assert assembled.system == prompt.BASE_STRUCTURED + "\n\n" + generator.SYSTEM
    assert generator.extract_yaml("text\n```yaml\nid: a\n```\nmore") == "id: a\n"
    assert generator.extract_yaml("id: a\n") == "id: a\n"
