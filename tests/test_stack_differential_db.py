"""The firewall gate of the hop tracer and the access policy of the symbolic
model decide the same packets alike, except for the causes in
`tests/support/stack_differences.json`.

Each case is one collector batch with one rule shape. The tracer reads the
batch from the NEO4J_TEST_URI database, and the symbolic model reads it as a
`GraphInventory`. The tests delete the data of that database.

`FLOWS` holds requests that the 2 analysis engines answer in full. The file
lists the requests that they answer differently under `answers`.
"""

from __future__ import annotations

import importlib
import json
import os
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from tests.support import stack_differential as sd
from tests.support.batch_inventory import inventory
from tests.test_checkpoint_policy_facts import OBJECTS, _estate
from tests.test_checkpoint_policy_facts import _batch as _checkpoint_batch
from tests.test_checkpoint_policy_facts import _layer as _checkpoint_layer
from tests.test_cisco_common import _PERMIT_ANY_ACE, _acl_batch
from tests.test_firewall_rule_scope import ISOLATE, RFC1918, SSH_SRC, _cp_rule, _gw_batch, _zone
from tests.test_vyos_match_clauses import _batch as _vyos_batch
from tests.test_vyos_match_clauses import _forward

from hst.core import cycle as cyclemod
from hst.core import db as dbmod
from hst.core.config import Settings
from hst.core.finalize import finalize_derivations
from hst.core.loader import load
from hst.core.model import Batch
from hst.path.session import CycleSession
from hst.path.verdict import DENY, INDETERMINATE, PERMIT

URI = os.environ.get("NEO4J_TEST_URI")
CTS = 5_200_000_000_000
KNOWN = Path(__file__).parent / "support" / "stack_differences.json"

pytestmark = [pytest.mark.db, pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set")]


@dataclass(frozen=True, slots=True)
class Case:
    name: str
    build: Callable[[], Batch]
    hop: sd.Hop
    states: tuple[str, ...] = ("new",)


def _without(batch: Batch, rel_type: str) -> Batch:
    """The batch without its `rel_type` relationships, as the loader leaves it
    for a relationship to a node that no batch wrote."""
    return batch.model_copy(update={"rels": [r for r in batch.rels if r.rel_type != rel_type]})


# --- VyOS -----------------------------------------------------------------------------

_VYOS_HOP = sd.Hop("dev:gw", "vrf:dev:gw:default", "dev:gw/if/eth0", "dev:gw/if/eth1")
_VYOS_INTERFACES = {
    "ethernet": {"eth0": {"address": ["203.0.113.2/30"]}, "eth1": {"address": ["10.20.30.1/24"]}}
}
_WEB = {"action": "accept", "protocol": "tcp", "destination": {"address": "10.20.30.0/24", "port": "443"}}
_BLOCKED = {"action": "drop", "source": {"address": "192.168.30.0/24"}}
_GROUPS = {
    "address-group": {"BLOCKED": {"address": ["192.168.30.0/24"]}},
    "port-group": {"WEB": {"port": ["80", "443"]}},
}
_GROUP_RULES = {
    "10": {"action": "drop", "source": {"group": {"address-group": "BLOCKED"}}},
    "20": {"action": "accept", "protocol": "tcp", "destination": {"group": {"port-group": "WEB"}}},
}


def _vyos(
    rules: dict[str, Any],
    default: str | None = "drop",
    *,
    groups: dict[str, Any] | None = None,
    named: dict[str, Any] | None = None,
) -> Batch:
    firewall = _forward(rules, default or "drop", groups)
    if default is None:
        del firewall["ipv4"]["forward"]["filter"]["default-action"]
    if named:
        firewall["ipv4"]["name"] = named
    return _vyos_batch(firewall, interfaces=_VYOS_INTERFACES)


def _guard(default: str, rules: dict[str, Any]) -> dict[str, Any]:
    return {"GUARD": {"default-action": default, "rule": rules}}


_JUMP = {"10": {"action": "jump", "jump-target": "GUARD"}, "20": _WEB}

_VYOS: dict[str, Callable[[], Batch]] = {
    "plain": lambda: _vyos({"10": _WEB, "20": _BLOCKED}, "accept"),
    "negated-source": lambda: _vyos(
        {"10": {"action": "drop", "source": {"address": "!192.168.30.0/24"}}}, "accept"
    ),
    "negated-protocol": lambda: _vyos({"10": {"action": "accept", "protocol": "!tcp"}}),
    "port-range": lambda: _vyos(
        {"10": {"action": "accept", "protocol": "tcp_udp", "destination": {"port": "1000-2000"}}}
    ),
    "groups": lambda: _vyos(_GROUP_RULES, groups=_GROUPS),
    "source-port": lambda: _vyos({"10": {"action": "accept", "protocol": "tcp", "source": {"port": "2222"}}}),
    "jump": lambda: _vyos(_JUMP, named=_guard("return", {"10": _BLOCKED})),
    "jump-default-drop": lambda: _vyos(_JUMP, "accept", named=_guard("drop", {"10": _WEB})),
    "jump-return-rule": lambda: _vyos(
        _JUMP,
        named=_guard("accept", {"10": {"action": "return", "source": {"address": "192.168.30.0/24"}}}),
    ),
    "jump-undefined": lambda: _vyos(_JUMP),
    "continue": lambda: _vyos(
        {
            "10": {"action": "continue", "destination": {"address": "10.20.30.0/24"}},
            "20": {"action": "drop", "destination": {"address": "10.20.30.0/25"}},
        },
        "accept",
    ),
    "no-default": lambda: _vyos({"10": _WEB}, None),
    "unknown-match": lambda: _vyos({"10": {"action": "accept", "future-match": {"value": "x"}}}),
    "unmodeled-side": lambda: _vyos(
        {"10": {"action": "accept", "source": {"geoip": {"country-code": ["us"]}}}}
    ),
    "unknown-action": lambda: _vyos({"10": {"action": "queue"}}),
    "no-source-relationship": lambda: _without(_vyos(_GROUP_RULES, groups=_GROUPS), "SRC"),
    "no-service-relationship": lambda: _without(_vyos(_GROUP_RULES, groups=_GROUPS), "SVC"),
}
_VYOS_STATES: dict[str, Callable[[], Batch]] = {
    "state": lambda: _vyos(
        {
            "10": {"action": "accept", "state": {"established": "enable", "related": "enable"}},
            "20": {"action": "drop", "destination": {"address": "10.20.30.0/24"}},
        },
        "accept",
    ),
}

# --- Cisco ----------------------------------------------------------------------------

_CISCO_HOP = sd.Hop("dev:sw1", "vrf:dev:sw1:default", "dev:sw1/if/eth1-1", "dev:sw1/if/vlan10")
_DENY_ANY = {**_PERMIT_ANY_ACE, "action": "deny"}
_CISCO_WEB = {**_PERMIT_ANY_ACE, "dst_any": False, "dst": "10.20.30.0/24", "proto": "tcp", "ports": "443"}
_IN = [{"interface": "Ethernet1/1", "direction": "in", "acl": "EDGE"}]


def _cisco(first: dict[str, Any], bindings: list[dict[str, Any]] | None = None) -> Batch:
    return _acl_batch(
        {"lists": {"EDGE": [first, _DENY_ANY]}, "bindings": _IN if bindings is None else bindings}
    )


_CISCO: dict[str, Callable[[], Batch]] = {
    "plain": lambda: _cisco(_CISCO_WEB),
    "source": lambda: _cisco({**_DENY_ANY, "src_any": False, "src": "192.168.30.0/24"}),
    "udp-range": lambda: _cisco({**_PERMIT_ANY_ACE, "proto": "udp", "ports": "1000-2000"}),
    "source-port": lambda: _cisco({**_PERMIT_ANY_ACE, "proto": "tcp", "src_port": "2222"}),
    "opaque-service": lambda: _cisco({**_PERMIT_ANY_ACE, "svc_opaque_reason": "an object group"}),
    "opaque-source": lambda: _cisco(
        {**_PERMIT_ANY_ACE, "src_any": False, "src_opaque_reason": "an object group"}
    ),
    "qualifier": lambda: _cisco({**_CISCO_WEB, "qualifier_reason": "the entry matches established"}),
    "no-source-relationship": lambda: _without(
        _cisco({**_DENY_ANY, "src_any": False, "src": "192.168.30.0/24"}), "SRC"
    ),
    "no-destination-relationship": lambda: _without(_cisco(_CISCO_WEB), "DST"),
    "no-service-relationship": lambda: _without(_cisco(_CISCO_WEB), "SVC"),
    "bound-out": lambda: _cisco(_CISCO_WEB, [{"interface": "Vlan10", "direction": "out", "acl": "EDGE"}]),
    "bound-elsewhere": lambda: _cisco(
        _CISCO_WEB, [{"interface": "Vlan10", "direction": "in", "acl": "EDGE"}]
    ),
    "unbound": lambda: _cisco(_CISCO_WEB, []),
}

# --- UniFi ----------------------------------------------------------------------------

_CLASSIC_HOP = sd.Hop("dev:gateway", "vrf:dev:gateway:default", "dev:gateway/if/br1", "dev:gateway/if/br40")
_ZONE_HOP = sd.Hop("dev:gateway", "vrf:dev:gateway:default", "dev:gateway/if/br40", "dev:gateway/if/br1")


def _classic(first: dict[str, Any]) -> Batch:
    rule = {
        "_id": "r-first",
        "ruleset": "LAN_IN",
        "rule_index": 2000,
        "name": "first",
        "action": "accept",
        "enabled": True,
        "protocol": "all",
        "src_firewallgroup_ids": [],
        "dst_firewallgroup_ids": [],
        **first,
    }
    return _gw_batch(firewall_rules=[rule, ISOLATE], firewall_groups=[RFC1918, SSH_SRC])


_UNIFI_CLASSIC: dict[str, Callable[[], Batch]] = {
    "plain": lambda: _classic({}),
    "mac": lambda: _classic({"src_mac_address": "aa:bb:cc:dd:ee:ff"}),
    "source-port-group": lambda: _classic({"protocol": "tcp", "src_firewallgroup_ids": ["g-ssh"]}),
    "excepted-protocol": lambda: _classic({"protocol": "tcp", "protocol_match_excepted": True}),
    "no-source-relationship": lambda: _without(_classic({"action": "drop"}), "SRC"),
    "no-destination-relationship": lambda: _without(_classic({"action": "drop"}), "DST"),
    "no-service-relationship": lambda: _without(
        _classic({"protocol": "tcp", "src_firewallgroup_ids": ["g-ssh"]}), "SVC"
    ),
}
_UNIFI_CLASSIC_STATES: dict[str, Callable[[], Batch]] = {
    "states": lambda: _classic({"state_established": True, "state_related": True, "state_new": False}),
}
_UNIFI_ZONE: dict[str, Callable[[], Batch]] = {
    "plain": lambda: _zone({})[0],
    "schedule": lambda: _zone({"schedule": {"mode": "EVERY_DAY", "time_range_start": "08:00"}})[0],
    "ipv6": lambda: _zone({"ip_version": "IPV6"})[0],
    "source-addresses": lambda: _zone(
        {"source": {"zone_id": "z2", "matching_target": "IP", "ips": ["192.168.40.0/25"]}}
    )[0],
}
_UNIFI_ZONE_STATES: dict[str, Callable[[], Batch]] = {
    "respond-only": lambda: _zone({"connection_state_type": "RESPOND_ONLY", "connection_states": []})[0],
    "custom-states": lambda: _zone({"connection_state_type": "CUSTOM", "connection_states": ["ESTABLISHED"]})[
        0
    ],
}

# --- Check Point ----------------------------------------------------------------------

# The Check Point batch holds no interface. The 2 names are no nodes.
_GW_A = sd.Hop("dev:fw-a", "vrf:dev:fw-a:default", "if:in", "if:out")
_GW_B = sd.Hop("dev:fw-b", "vrf:dev:fw-b:default", "if:in", "if:out")
_SSH_TO_WEB = {"destination": ["web"], "service": ["ssh"]}


def _checkpoint(first: dict[str, Any], **estate: Any) -> Batch:
    """The estate of `tests/test_checkpoint_policy_facts.py` with `first` as
    the columns of the one rule of the layer Network."""
    rulebases = {
        "net": [{"rulebase": [_cp_rule("r1", 1, "accept", **first)], "objects-dictionary": OBJECTS}],
        "app": [
            {
                "rulebase": [_cp_rule("a1", 1, "drop", destination=["blocked"])],
                "objects-dictionary": OBJECTS,
            }
        ],
    }
    return _checkpoint_batch(_estate(rulebases=rulebases, **estate))


_CHECKPOINT: dict[str, Callable[[], Batch]] = {
    "plain": lambda: _checkpoint(_SSH_TO_WEB),
    "install-on": lambda: _checkpoint({**_SSH_TO_WEB, "install-on": ["gw-a"]}),
    "install-on-group": lambda: _checkpoint({**_SSH_TO_WEB, "install-on": ["gw-group"]}),
    "source-group": lambda: _checkpoint({**_SSH_TO_WEB, "source": ["lans"]}),
    "negated-destination": lambda: _checkpoint({**_SSH_TO_WEB, "destination-negate": True}),
    "negated-service": lambda: _checkpoint({**_SSH_TO_WEB, "service-negate": True}),
    "empty-service": lambda: _checkpoint({"destination": ["web"], "service": []}),
    "empty-source": lambda: _checkpoint({**_SSH_TO_WEB, "source": []}),
    "vpn": lambda: _checkpoint({**_SSH_TO_WEB, "vpn": ["remote-access"]}),
    "time": lambda: _checkpoint({**_SSH_TO_WEB, "time": ["work-hours"]}),
    "disabled": lambda: _checkpoint({**_SSH_TO_WEB, "enabled": False}),
    "no-cleanup": lambda: _checkpoint(
        _SSH_TO_WEB,
        layers=[
            _checkpoint_layer("net", "Network", None),
            _checkpoint_layer("app", "Application", "accept"),
        ],
    ),
}

_BOTH_STATES = ("new", "established")
CASES: list[Case] = [
    *(Case(f"vyos-{name}", build, _VYOS_HOP) for name, build in _VYOS.items()),
    *(Case(f"vyos-{name}", build, _VYOS_HOP, _BOTH_STATES) for name, build in _VYOS_STATES.items()),
    *(Case(f"cisco-{name}", build, _CISCO_HOP) for name, build in _CISCO.items()),
    *(Case(f"unifi-classic-{name}", build, _CLASSIC_HOP) for name, build in _UNIFI_CLASSIC.items()),
    *(
        Case(f"unifi-classic-{name}", build, _CLASSIC_HOP, _BOTH_STATES)
        for name, build in _UNIFI_CLASSIC_STATES.items()
    ),
    *(Case(f"unifi-zone-{name}", build, _ZONE_HOP) for name, build in _UNIFI_ZONE.items()),
    *(
        Case(f"unifi-zone-{name}", build, _ZONE_HOP, _BOTH_STATES)
        for name, build in _UNIFI_ZONE_STATES.items()
    ),
    *(Case(f"checkpoint-{name}", build, _GW_A) for name, build in _CHECKPOINT.items()),
    Case("checkpoint-install-on-other-gateway", _CHECKPOINT["install-on"], _GW_B),
]


@dataclass(frozen=True, slots=True)
class Flow:
    """One TCP request through the device of a batch."""

    name: str
    build: Callable[[], Batch]
    source: str
    destination: str
    port: int
    # False leaves the routing of the batch without an observation, as the loader writes it.
    routing_observed: bool = True


def _cisco_list(action: str, interface: str | None) -> Batch:
    bindings = [{"interface": interface, "direction": "in", "acl": "EDGE"}] if interface else []
    return _cisco({**_PERMIT_ANY_ACE, "action": action}, bindings)


_TO_VLAN10 = ("10.0.0.5", "10.10.10.50", 443)
_TO_ETH1 = ("203.0.113.1", "10.20.30.5")
_RETURN_SOURCE = {"10": {"action": "return", "source": {"address": "203.0.113.1"}}}
FLOWS: list[Flow] = [
    Flow("cisco-no-list", lambda: _cisco_list("permit", None), *_TO_VLAN10),
    Flow("cisco-permit-list-on-the-ingress", lambda: _cisco_list("permit", "Ethernet1/1"), *_TO_VLAN10),
    Flow("cisco-deny-list-on-the-ingress", lambda: _cisco_list("deny", "Ethernet1/1"), *_TO_VLAN10),
    Flow("cisco-permit-list-inbound-on-the-egress", lambda: _cisco_list("permit", "Vlan10"), *_TO_VLAN10),
    Flow(
        "cisco-deny-list-on-the-ingress-routing-not-observed",
        lambda: _cisco_list("deny", "Ethernet1/1"),
        *_TO_VLAN10,
        routing_observed=False,
    ),
    Flow("vyos-accept-rule", lambda: _vyos({"10": _WEB}), *_TO_ETH1, 443),
    Flow("vyos-default-drop", lambda: _vyos({"10": _WEB}), *_TO_ETH1, 80),
    Flow("vyos-return-rule", lambda: _vyos(_JUMP, named=_guard("accept", _RETURN_SOURCE)), *_TO_ETH1, 443),
]

# The rule has no service relationship and `svc_any` is false. The gate matches
# it on its addresses. The policy reader gives GRAPH_RULE_COLUMN_MISSING.
CONTROL = "cisco-no-service-relationship"


# --- the database ---------------------------------------------------------------------


def _cleanup(s: Any, scopes: list[str]) -> None:
    s.run(
        "MATCH (n:Obj) WHERE n._scope IN $scopes OR n._scope IN ['meta:runs', 'meta:cycle', 'meta:cycles'] "
        "DETACH DELETE n",
        scopes=scopes,
    ).consume()


@pytest.fixture(scope="module")
def database() -> Iterator[Any]:
    from neo4j import GraphDatabase

    live = Settings(_env_file=None).neo4j_uri
    if dbmod.same_endpoint(URI or "", live):
        pytest.exit("NEO4J_TEST_URI is the configured database", returncode=2)
    driver = GraphDatabase.driver(
        URI, auth=(os.environ.get("NEO4J_TEST_USER", "neo4j"), os.environ["NEO4J_TEST_PASSWORD"])
    )
    with driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j")) as s:
        dbmod.init_db(s)
        yield s
    driver.close()


def run_case(s: Any, case: Case, cts: int) -> tuple[list[sd.Probe], list[sd.Difference]]:
    """Load the batch of the case as the run `cts` and compare the 2 sides on it."""
    batch = case.build()
    _cleanup(s, [batch.scope])
    try:
        load(s, batch, ts_ms=cts, run_id=f"it-stack-{case.name}", collection_ts=cts)
        cyclemod.set_pointer(s, cts)
        return sd.differences(
            CycleSession(s, cts), inventory(batch), case.hop, case=case.name, states=case.states
        )
    finally:
        _cleanup(s, [batch.scope])


Found = dict[str, tuple[list[sd.Probe], list[sd.Difference]]]


def cause_key(cause: tuple[str, ...]) -> str:
    return " | ".join(cause)


@pytest.fixture(scope="module")
def found(database: Any) -> Found:
    return {case.name: run_case(database, case, CTS + index) for index, case in enumerate(CASES)}


def test_the_harness_reports_the_rule_without_a_service_relationship(
    found: Found,
) -> None:
    _asked, differences = found[CONTROL]
    assert differences, "the control case gave no difference"
    assert {(d.tracer.verdict, d.rules.verdict) for d in differences} <= {
        (PERMIT, INDETERMINATE),
        (DENY, INDETERMINATE),
    }
    assert any("GRAPH_RULE_COLUMN_MISSING" in d.rules.detail for d in differences)


def test_every_case_asks_probes(found: Found) -> None:
    assert {name for name, (asked, _differences) in found.items() if not asked} == set()


def test_no_cause_is_outside_the_known_causes(found: Found) -> None:
    known = set(json.loads(KNOWN.read_text(encoding="utf-8"))["causes"])
    grouped = sd.causes(d for _asked, differences in found.values() for d in differences)
    new = {
        cause_key(cause): sorted({d.case for d in items})
        for cause, items in grouped.items()
        if cause_key(cause) not in known
    }
    assert new == {}


def test_no_known_cause_is_gone(found: Found) -> None:
    known = set(json.loads(KNOWN.read_text(encoding="utf-8"))["causes"])
    seen = {cause_key(d.cause) for _asked, differences in found.values() for d in differences}
    assert known - seen == set()


def test_the_policy_compiler_decides_each_probe_as_the_reader_does(found: Found) -> None:
    """`sd.compiled_outcomes` against `sd.ir_outcomes`, for the policy and for its layers."""
    if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
        importlib.import_module("dd.cudd")
    else:
        pytest.importorskip("dd.cudd", reason="native symbolic wheel required for this test")
    different: dict[str, list[tuple[sd.Probe, tuple[str, str], tuple[str, str]]]] = {}
    for case in CASES:
        graph = inventory(case.build())
        asked, _differences = found[case.name]
        for state in case.states:
            policy = sd.symbolic_policy(graph, case.hop, state)
            probes = [probe for probe in asked if probe.state == state]
            read, compiled = sd.ir_outcomes(policy, probes), sd.compiled_outcomes(policy, probes)
            for probe in probes:
                reader = (read[probe][0].verdict, read[probe][1].verdict)
                compiler = (compiled[probe][0].verdict, compiled[probe][1].verdict)
                if reader != compiler:
                    different.setdefault(case.name, []).append((probe, reader, compiler))
    assert different == {}


def test_the_2_engines_give_each_request_the_same_verdict_except_the_known_ones(
    database: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
        importlib.import_module("dd.cudd")
    else:
        pytest.importorskip("dd.cudd", reason="native symbolic wheel required for this test")
    from hst.impact.evaluate import Network

    different: dict[str, list[str]] = {}
    for index, flow in enumerate(FLOWS):
        batch, cts = flow.build(), CTS + len(CASES) + index
        _cleanup(database, [batch.scope])
        try:
            load(database, batch, ts_ms=cts, run_id=f"it-stack-{flow.name}", collection_ts=cts)
            finalize_derivations(database, Settings(_env_file=None), cts, {})
            cyclemod.set_pointer(database, cts)
            with monkeypatch.context() as patch:
                if flow.routing_observed:
                    patch.setattr(Network, "incomplete", lambda self, context_uid, destinations=None: ())
                legacy, symbolic = sd.answer_verdicts(
                    CycleSession(database, cts),
                    inventory(batch),
                    sd.flow_request(flow.source, flow.destination, flow.port),
                )
        finally:
            _cleanup(database, [batch.scope])
        if legacy != symbolic:
            different[flow.name] = [legacy, symbolic]
    assert different == json.loads(KNOWN.read_text(encoding="utf-8"))["answers"]
