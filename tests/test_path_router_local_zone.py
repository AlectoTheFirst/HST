from __future__ import annotations

import importlib
from collections.abc import Callable
from functools import cache
from pathlib import Path
from typing import Any

import pytest
from tests.support.demo_trace_graph import TraceGraph

from hst import path
from hst.core.fixtures import load_fixture
from hst.core.model import Batch, NodeRecord, RelRecord
from hst.path.addrsets import _intervals, _ports
from hst.path.gates.local_zone import LocalZoneTransition
from hst.path.state import FlowRegion

trace_mod = importlib.import_module("hst.path.trace")

ROOT = Path(__file__).resolve().parent.parent
DEV = "dev:osl01-vyos-01"
NS = "vyos:osl01-vyos-01"
ETH1_10, ETH1_20 = f"{DEV}/if/eth1.10", f"{DEV}/if/eth1.20"
MAIN = f"vrf:{DEV}:default"
LAN_V4, LAN_V6 = "10.18.10.21", "fd00:18:10::21"
NAS_V4 = "10.18.10.20"
VPN_V4 = "10.18.10.50"
IOT_V4, IOT_V6 = "10.18.20.31", "fd00:18:20::31"
RTR_LAN_V4, RTR_LAN_V6 = "10.18.10.1", "fd00:18:10::1"
RTR_IOT_V4, RTR_IOT_V6 = "10.18.20.1", "fd00:18:20::1"
INTERNET_V4 = "192.0.2.180"
STATE_POLICY = ["established=accept", "invalid=drop", "related=accept"]
LAN_LOCAL, LAN_LOCAL_6 = f"{NS}:fw:LAN-LOCAL", f"{NS}:fw:ipv6:LAN-LOCAL-6"
IOT_LOCAL, IOT_LOCAL_6 = f"{NS}:fw:IOT-LOCAL", f"{NS}:fw:ipv6:IOT-LOCAL-6"


_LATER = {
    f"{NS}:fw:{v6}{name}{suffix}"
    for name in ("IOT-LOCAL", "GUEST-LOCAL", "LOCAL-WAN", "LOCAL-LAN", "LOCAL-IOT", "LOCAL-GUEST")
    for v6, suffix in (("", ""), ("ipv6:", "-6"))
}


@cache
def _oslo() -> Batch:
    """The office without the rule sets of `_LATER` (their rules and relationships too),
    and with LAN-LOCAL and LAN-LOCAL-6 dropping by default."""
    batch = load_fixture(ROOT / "fixtures" / "demo-enterprise" / "estate-v1.yaml")
    gone = {n.uid for n in batch.nodes if n.uid in _LATER or n.uid.rsplit(":", 1)[0] in _LATER}
    batch.nodes = [n for n in batch.nodes if n.uid not in gone]
    batch.rels = [r for r in batch.rels if r.start_uid not in gone and r.end_uid not in gone]
    for node in batch.nodes:
        if node.uid in (LAN_LOCAL, LAN_LOCAL_6):
            node.props["default_action"] = "drop"
    return batch


def _batch(*edits: Callable[[Batch], None]) -> Batch:
    batch = _oslo().model_copy(deep=True)
    for edit in edits:
        edit(batch)
    return batch


def _props(batch: Batch, uid: str) -> dict[str, Any]:
    return next(n.props for n in batch.nodes if n.uid == uid)


def _rulebase(name: str, src: str, dst: str, af: int, default: str | None) -> Callable[[Batch], None]:
    uid = f"{NS}:fw:{name}" if af == 4 else f"{NS}:fw:ipv6:{name}"

    def edit(batch: Batch) -> None:
        batch.nodes.append(
            NodeRecord(
                label="FwRulebase",
                uid=uid,
                props={
                    "name": name,
                    "kind": "access",
                    "vendor": "vyos",
                    "af": af,
                    "default_action": default,
                    "default_action_unknown": default is None,
                    "global_state_policy": STATE_POLICY,
                    "match_context": "zone-pair",
                },
            )
        )
        for rel, zone in (("FROM_ZONE", src), ("TO_ZONE", dst)):
            batch.rels.append(
                RelRecord(
                    rel_type=rel,
                    start_label="FwRulebase",
                    start_uid=uid,
                    end_label="Zone",
                    end_uid=f"{NS}:zone:{zone}",
                )
            )

    return edit


def _set(uid: str, **props: Any) -> Callable[[Batch], None]:
    def edit(batch: Batch) -> None:
        _props(batch, uid).update(props)

    return edit


def _drop(rel_type: str, start: str | None = None) -> Callable[[Batch], None]:
    def edit(batch: Batch) -> None:
        batch.rels = [r for r in batch.rels if not (r.rel_type == rel_type and start in (None, r.start_uid))]

    return edit


CORE1 = (
    _set(LAN_LOCAL, default_action="accept"),
    _set(LAN_LOCAL_6, default_action="accept"),
    _rulebase("IOT-LOCAL", "IOT", "LOCAL", 4, "drop"),
    _rulebase("IOT-LOCAL-6", "IOT", "LOCAL", 6, "drop"),
    _rulebase("GUEST-LOCAL", "GUEST", "LOCAL", 4, "drop"),
    _rulebase("GUEST-LOCAL-6", "GUEST", "LOCAL", 6, "drop"),
    _rulebase("LOCAL-WAN", "LOCAL", "WAN", 4, "accept"),
    _rulebase("LOCAL-WAN-6", "LOCAL", "WAN", 6, "accept"),
)


def _trace(batch: Batch, src: str, dst: str, port: int, proto: str, **kw: Any) -> dict[str, Any]:
    graph = TraceGraph(batch)
    result = path.trace(graph, src, dst, port=port, proto=proto, **kw)
    assert graph.refused == []
    return result


def _forward(result: dict[str, Any]) -> dict[str, Any]:
    forward: dict[str, Any] = result.get("forward", result)
    return forward


def _leg(result: dict[str, Any]) -> dict[str, Any]:
    (leg,) = _forward(result)["legs"]
    return leg


def _outcome(leg: dict[str, Any]) -> str:
    if leg.get("blocked"):
        return "deny"
    return "indeterminate" if leg.get("indeterminate") else "permit"


# --- the expected answers -------------------------------------------------------------------------

ANSWERS = [
    # (shape, src, dst, port, proto, outcome, the leg's firewall)
    ("oslo", LAN_V4, RTR_IOT_V4, 22, "tcp", "permit", "LAN-LOCAL (input) accept by rule 10"),
    ("oslo", LAN_V6, RTR_IOT_V6, 22, "tcp", "permit", "LAN-LOCAL-6 (input) accept by rule 10"),
    ("oslo", LAN_V4, RTR_IOT_V4, 53, "udp", "deny", "LAN-LOCAL (input) drop by default-action"),
    (
        "oslo",
        IOT_V4,
        RTR_LAN_V4,
        53,
        "udp",
        "deny",
        "IOT→LOCAL zone policy (no ruleset bound) (input) drop by default-action",
    ),
    (
        "oslo",
        IOT_V6,
        RTR_LAN_V6,
        53,
        "udp",
        "deny",
        "IOT→LOCAL zone policy (no ruleset bound) (input) drop by default-action",
    ),
    ("core1", LAN_V4, RTR_IOT_V4, 22, "tcp", "permit", "LAN-LOCAL (input) accept by rule 10"),
    ("core1", LAN_V4, RTR_IOT_V4, 53, "udp", "permit", "LAN-LOCAL (input) accept by default-action"),
    ("core1", LAN_V6, RTR_IOT_V6, 53, "udp", "permit", "LAN-LOCAL-6 (input) accept by default-action"),
    ("core1", IOT_V4, RTR_LAN_V4, 53, "udp", "deny", "IOT-LOCAL (input) drop by default-action"),
    ("core1", IOT_V6, RTR_LAN_V6, 53, "udp", "deny", "IOT-LOCAL-6 (input) drop by default-action"),
]


def _shape(name: str) -> Batch:
    return _batch() if name == "oslo" else _batch(*CORE1)


@pytest.mark.parametrize(("shape", "src", "dst", "port", "proto", "outcome", "firewall"), ANSWERS)
def test_a_flow_to_the_router_is_decided_by_its_local_zone_pair(
    shape, src, dst, port, proto, outcome, firewall
):
    result = _trace(_shape(shape), src, dst, port, proto)
    leg = _leg(result)

    assert leg["device_uid"] == DEV
    assert _outcome(leg) == outcome, _forward(result)["warnings"]
    assert leg["firewall"] == firewall
    assert not leg.get("indeterminate")
    assert _forward(result)["warnings"] == []


@pytest.mark.parametrize(("shape", "src", "dst", "port", "proto", "outcome", "_firewall"), ANSWERS)
def test_the_tracer_agrees_with_the_impact_engines_local_zone_gate(
    shape, src, dst, port, proto, outcome, _firewall
):
    batch = _shape(shape)
    in_if = ETH1_10 if src in (LAN_V4, LAN_V6) else ETH1_20
    proto_n = frozenset({6 if proto == "tcp" else 17})
    region = FlowRegion.from_query(_intervals([src]), _intervals([dst]), proto_n, _ports(str(port)))
    effects = LocalZoneTransition(TraceGraph(batch), DEV, in_if, None, "input").apply(region)

    assert {effect.kind for _part, effect in effects} == {outcome}
    assert _outcome(_leg(_trace(batch, src, dst, port, proto))) == outcome


# --- what is not established stays undecided -------------------------------------------------------


def test_a_family_with_no_rule_set_bound_takes_the_recorded_local_zone_default():
    batch = _batch(*CORE1, _drop("FROM_ZONE", LAN_LOCAL_6), _drop("TO_ZONE", LAN_LOCAL_6))
    leg = _leg(_trace(batch, LAN_V6, RTR_IOT_V6, 53, "udp"))

    assert leg["blocked"]
    assert leg["firewall"] == "LAN→LOCAL zone policy (no ruleset bound) (input) drop by default-action"
    # the IPv4 rule set of the pair is ruled out by family once the default decided
    assert LAN_LOCAL in leg["fw_uids"]


def test_an_unrecorded_local_zone_default_is_undecided():
    batch = _batch(
        _drop("FROM_ZONE", LAN_LOCAL_6),
        _drop("TO_ZONE", LAN_LOCAL_6),
        _set(f"{NS}:zone:LOCAL", default_action=None, default_action_unknown=True),
    )
    result = _trace(batch, LAN_V6, RTR_IOT_V6, 22, "tcp")
    leg = _leg(result)

    assert leg["indeterminate"] and not leg["blocked"]
    assert any("default action was not collected" in w for w in _forward(result)["warnings"])


def test_an_unrecorded_rule_set_default_is_undecided():
    batch = _batch(_set(LAN_LOCAL, default_action=None, default_action_unknown=True))
    result = _trace(batch, LAN_V4, RTR_IOT_V4, 53, "udp")
    leg = _leg(result)

    assert leg["indeterminate"] and not leg["blocked"]
    assert any("default action was not collected" in w for w in _forward(result)["warnings"])


def test_an_undecided_rule_match_keeps_its_undecided_result():
    batch = _batch(*CORE1, _set(f"{LAN_LOCAL}:10", in_interface_group="LAN-IFS"))
    result = _trace(batch, LAN_V4, RTR_IOT_V4, 22, "tcp")
    leg = _leg(result)

    assert leg["indeterminate"] and not leg["blocked"]
    assert any("interface-group" in w for w in _forward(result)["warnings"])


def test_a_jump_is_followed_into_the_target_rule_set():
    def jump(batch: Batch) -> None:
        batch.nodes.append(
            NodeRecord(
                label="FwRule",
                uid=f"{IOT_LOCAL}:5",
                props={
                    "position": 5,
                    "action": "jump",
                    "jump_target": f"{NS}:fw:COMMON",
                    "name": "shared rules",
                    "enabled": True,
                    "src_any": True,
                    "dst_any": True,
                    "svc_any": True,
                    "states": [],
                },
            )
        )
        batch.rels.append(
            RelRecord(
                rel_type="HAS_RULE",
                start_label="FwRulebase",
                start_uid=IOT_LOCAL,
                end_label="FwRule",
                end_uid=f"{IOT_LOCAL}:5",
            )
        )

    leg = _leg(_trace(_batch(*CORE1, jump), IOT_V4, RTR_LAN_V4, 53, "udp"))

    # COMMON rule 10 accepts udp/53; the jump returns nothing else
    assert _outcome(leg) == "permit"
    assert leg["fw_uid"] == IOT_LOCAL


def test_two_zones_with_no_interface_stay_undecided():
    def dmz(batch: Batch) -> None:
        batch.nodes.append(
            NodeRecord(
                label="Zone",
                uid=f"{NS}:zone:DMZ",
                props={
                    "name": "DMZ",
                    "local_zone": False,
                    "default_action": "drop",
                    "default_action_unknown": False,
                },
            )
        )
        batch.rels.append(
            RelRecord(
                rel_type="OWNED_BY",
                start_label="Zone",
                start_uid=f"{NS}:zone:DMZ",
                end_label="Device",
                end_uid=DEV,
            )
        )

    result = _trace(_batch(dmz, _rulebase("LAN-DMZ", "LAN", "DMZ", 4, "drop")), LAN_V4, RTR_IOT_V4, 22, "tcp")
    leg = _leg(result)

    assert leg["indeterminate"] and not leg["blocked"]
    assert any("more than one zone" in w for w in _forward(result)["warnings"])


def test_a_graph_with_no_zone_ownership_leaves_the_local_pair_unevaluated():
    result = _trace(_batch(_drop("OWNED_BY")), LAN_V4, RTR_IOT_V4, 22, "tcp")
    leg = _leg(result)

    assert leg["indeterminate"]
    assert "FwRulebase LAN-LOCAL: on path, not evaluated" in _forward(result)["warnings"]
    assert leg.get("firewall") is None


# --- the router's own address in the source's own subnet --------------------------------------------


def test_the_gateways_own_address_in_the_sources_subnet_is_router_local():
    result = _trace(_batch(), LAN_V4, RTR_LAN_V4, 22, "tcp")
    leg = _leg(result)

    assert leg["verdict"] == "router-local, terminates on osl01-vyos-01 eth1.10"
    assert leg["firewall"] == "LAN-LOCAL (input) accept by rule 10"
    assert _outcome(leg) == "permit" and _forward(result)["warnings"] == []


def test_a_plain_host_in_the_same_subnet_stays_switched(monkeypatch):
    result = _trace(_batch(), LAN_V4, NAS_V4, 445, "tcp")
    monkeypatch.setattr(trace_mod, "_gateway_own_part", lambda *_a, **_k: [])
    before = _trace(_batch(), LAN_V4, NAS_V4, 445, "tcp")

    assert _leg(result)["verdict"] == "switched in 10.18.10.0/24"
    assert not _leg(result).get("router_local") and _leg(result).get("firewall") is None
    assert result == before


def test_a_subnet_destination_that_covers_the_router_is_not_read_as_switched():
    result = _trace(_batch(), LAN_V4, "10.18.10.0/30", 22, "tcp")
    switched, local = _forward(result)["legs"]

    assert switched["verdict"] == "switched in 10.18.10.0/24"
    assert local["verdict"] == "router-local, terminates on osl01-vyos-01 eth1.10"
    assert local["firewall"] == "LAN-LOCAL (input) accept by rule 10"


# --- a flow a policy route claims, to the router's own address --------------------------------------


def test_a_policy_routed_flow_to_the_router_terminates_on_the_router():
    graph = TraceGraph(_batch())
    result = path.trace(graph, VPN_V4, RTR_IOT_V4, port=22, proto="tcp")
    leg = _leg(result)

    assert graph.refused == []
    assert leg["verdict"] == "router-local, terminates on osl01-vyos-01 eth1.20"
    assert leg["firewall"] == "LAN-LOCAL (input) accept by rule 10"
    # the own addresses are read in the ingress interface's table, not in table 100
    own = [p.get("vrf") for q, p, _rows in graph.reads if q == trace_mod._OWN_ADDRS_QUERY]
    # the split read, then the read that asks whether the source is the router's own, both
    # in the ingress interface's table
    assert own == [MAIN, MAIN]


# --- the router's own carrier packet ----------------------------------------------------------------


def test_the_carrier_is_judged_by_the_local_to_egress_zone_rule_set():
    leg = _leg(_trace(_batch(*CORE1), VPN_V4, INTERNET_V4, 443, "tcp"))

    assert not leg["blocked"] and not leg.get("indeterminate")
    assert leg["carrier"]["firewall"] == "LOCAL-WAN (output) accept by default-action"
    assert f"{NS}:fw:LOCAL-WAN" in leg["fw_uids"]


def test_a_carrier_with_no_rule_set_bound_and_disagreeing_defaults_is_undecided():
    batch = _batch(_set(f"{NS}:zone:WAN", default_action="accept"))
    result = _trace(batch, VPN_V4, INTERNET_V4, 443, "tcp")
    leg = _leg(result)

    assert leg["indeterminate"] and not leg["blocked"]
    assert any("recorded default actions differ" in w for w in _forward(result)["warnings"])


# --- the reply the router sends ---------------------------------------------------------------------


def test_the_reply_to_a_permitted_flow_is_admitted_from_session_state():
    result = _trace(_batch(*CORE1), LAN_V4, RTR_IOT_V4, 22, "tcp", reply=True)
    (reply_leg,) = result["reply"]["legs"]

    assert not result["reply"]["indeterminate"] and result["reply"]["warnings"] == []
    assert reply_leg["firewall"] == f"admitted from session state ({', '.join(STATE_POLICY)})"
    # credited: the input crossing's rule sets and the zone rule sets the reply cannot cross
    assert {LAN_LOCAL, LAN_LOCAL_6, IOT_LOCAL, f"{NS}:fw:LOCAL-WAN"} <= set(reply_leg["fw_uids"])


def test_a_blocked_flow_to_the_router_starts_no_reply():
    result = _trace(_batch(*CORE1), IOT_V4, RTR_LAN_V4, 53, "udp", reply=True)

    assert result["reply"]["legs"] == []
    assert result["reply"]["verdict"].startswith("reply not derived")


def test_an_undecided_flow_to_the_router_gets_an_undecided_reply():
    batch = _batch(*CORE1, _set(f"{LAN_LOCAL}:10", in_interface_group="LAN-IFS"))
    result = _trace(batch, LAN_V4, RTR_IOT_V4, 22, "tcp", reply=True)
    (reply_leg,) = result["reply"]["legs"]

    assert result["reply"]["indeterminate"] and reply_leg["indeterminate"]
    assert reply_leg["firewall"] == f"session state admission not established ({', '.join(STATE_POLICY)})"


def test_a_carrier_with_no_known_source_address_is_still_judged_by_the_zone_pair():
    firewall = importlib.import_module("hst.path.gates.firewall")
    eth0 = f"{DEV}/if/eth0"
    dst = _intervals(["198.51.100.7"])

    core1 = firewall._firewall_verdict_local(TraceGraph(_batch(*CORE1)), DEV, eth0, [], dst, 51820, "udp")
    oslo = firewall._firewall_verdict_local(TraceGraph(_batch()), DEV, eth0, [], dst, 51820, "udp")

    assert (core1["rb_uid"], core1["action"]) == (f"{NS}:fw:LOCAL-WAN", "accept")
    assert (oslo["rb_uid"], oslo["action"]) == ("zone-pair:LOCAL->WAN#unbound", "drop")


def _input_chain(default: str) -> Callable[[Batch], None]:
    uid = f"{NS}:fw:ipv4-input"

    def edit(batch: Batch) -> None:
        batch.nodes.append(
            NodeRecord(
                label="FwRulebase",
                uid=uid,
                props={
                    "name": "ipv4-input",
                    "kind": "access",
                    "vendor": "vyos",
                    "af": 4,
                    "chain": "input",
                    "default_action": default,
                    "default_action_unknown": False,
                    "global_state_policy": STATE_POLICY,
                },
            )
        )
        batch.rels.append(
            RelRecord(
                rel_type="ENFORCES", start_label="Device", start_uid=DEV, end_label="FwRulebase", end_uid=uid
            )
        )

    return edit


@pytest.mark.parametrize(
    ("chain_default", "outcome", "firewall"),
    [
        # both permit: the leg names the first pool, and credits both
        ("accept", "permit", "ipv4-input (input) accept by default-action"),
        ("drop", "deny", "ipv4-input (input) drop by default-action"),
    ],
)
def test_the_input_chain_and_the_local_pair_both_judge_the_packet(chain_default, outcome, firewall):
    result = _trace(_batch(_input_chain(chain_default)), LAN_V4, RTR_IOT_V4, 22, "tcp")
    leg = _leg(result)

    assert _outcome(leg) == outcome and leg["firewall"] == firewall
    assert _forward(result)["warnings"] == []
    assert {f"{NS}:fw:ipv4-input", LAN_LOCAL} <= set(leg["fw_uids"])


# --- the owner's router rule shape, built by the VyOS collector -------------------------------------
#
# The Oslo router's own payload (tools/gen_demo_enterprise.py `vyos_payload`) with the rule sets
# to and from LOCAL of the owner's core1, normalized by `normalize_vyos` and put in place of the
# router's batch in the estate: LAN-LOCAL accept; IOT-LOCAL drop with 10 udp 67, 15/20/25/30
# tcp_udp 6667/53/5353/1900 and 100 any service to 224.0.0.0/4; IOT-LOCAL-6 drop with 10 icmpv6,
# 20 tcp_udp 53, 25 tcp_udp 5353 to ff02::fb; GUEST-LOCAL; WAN-LOCAL drop; LOCAL-x accept.


@cache
def _generator() -> Any:
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "gen_demo_enterprise", ROOT / "tools" / "gen_demo_enterprise.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _core1_config(gen: Any, plain: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    ruleset, rule = gen._vyos_ruleset, gen._vyos_rule

    def tcp_udp(port: str, **extra: Any) -> dict[str, Any]:
        return {"protocol": "tcp_udp", "destination": {"port": port, **extra}}

    config = plain()
    fw = config["firewall"]
    v4, v6 = fw["ipv4"]["name"], fw["ipv6"]["name"]
    v4["LAN-LOCAL"] = ruleset("accept")
    v4["IOT-LOCAL"] = ruleset(
        "drop",
        {
            "10": rule("accept", "dhcp", protocol="udp", destination={"port": "67"}),
            "15": rule("accept", "irc", **tcp_udp("6667")),
            "20": rule("accept", "dns", **tcp_udp("53")),
            "25": rule("accept", "mdns", **tcp_udp("5353")),
            "30": rule("accept", "ssdp", **tcp_udp("1900")),
            "100": rule("accept", "mcast", destination={"address": "224.0.0.0/4"}),
        },
    )
    v4["GUEST-LOCAL"] = ruleset(
        "drop",
        {
            "10": rule("accept", "dhcp", protocol="udp", destination={"port": "67"}),
            "20": rule("accept", "dns", **tcp_udp("53")),
        },
    )
    v4["WAN-LOCAL"] = ruleset("drop")
    for zone in ("WAN", "LAN", "IOT", "GUEST"):
        v4[f"LOCAL-{zone}"] = ruleset("accept")
    v6["LAN-LOCAL-6"] = ruleset("accept")
    v6["IOT-LOCAL-6"] = ruleset(
        "drop",
        {
            "10": rule("accept", "icmpv6", protocol="ipv6-icmp"),
            "20": rule("accept", "dns", **tcp_udp("53")),
            "25": rule("accept", "mdns", **tcp_udp("5353", address="ff02::fb")),
        },
    )
    zones = fw["zone"]
    zones["LOCAL"]["from"] = {
        "LAN": {"firewall": {"name": "LAN-LOCAL", "ipv6-name": "LAN-LOCAL-6"}},
        "IOT": {"firewall": {"name": "IOT-LOCAL", "ipv6-name": "IOT-LOCAL-6"}},
        "GUEST": {"firewall": {"name": "GUEST-LOCAL"}},
        "WAN": {"firewall": {"name": "WAN-LOCAL", "ipv6-name": "WAN-LOCAL-6"}},
    }
    for zone in ("WAN", "LAN", "IOT", "GUEST"):
        zones[zone].setdefault("from", {})["LOCAL"] = {"firewall": {"name": f"LOCAL-{zone}"}}
    return config


@cache
def _core1_real() -> Batch:
    from hst.collectors.vyos import normalize_vyos

    gen = _generator()
    kw = {"l3dom": gen.VYOS_SITE["code"], "l2fabric": gen.VYOS_SITE["code"], "scope": f"vyos:{gen.VYOS_HOST}"}
    plain = gen.vyos_config
    try:
        old = normalize_vyos(gen.vyos_payload(), **kw)
        gen.vyos_config = lambda: _core1_config(gen, plain)
        new = normalize_vyos(gen.vyos_payload(), **kw)
    finally:
        gen.vyos_config = plain
    assert new.warnings == []
    estate = load_fixture(ROOT / "fixtures" / "demo-enterprise" / "estate-v1.yaml")
    router = {n.uid for n in old.nodes} | {n.uid for n in new.nodes}
    kept = {n.uid for n in new.nodes}
    keys = {(r.rel_type, r.start_uid, r.end_uid) for r in [*old.rels, *new.rels]}
    estate.nodes = [n for n in estate.nodes if n.uid not in router] + list(new.nodes)
    estate.rels = [
        r
        for r in estate.rels
        if (r.rel_type, r.start_uid, r.end_uid) not in keys
        and not any(u in router and u not in kept for u in (r.start_uid, r.end_uid))
    ] + list(new.rels)
    return estate


REAL_ANSWERS = [
    # (src, dst, port, proto, outcome, the leg's firewall)
    (IOT_V4, RTR_LAN_V4, 53, "udp", "permit", "IOT-LOCAL (input) accept by rule 20"),
    (IOT_V4, RTR_LAN_V4, 53, "tcp", "permit", "IOT-LOCAL (input) accept by rule 20"),
    (IOT_V4, RTR_LAN_V4, 22, "tcp", "deny", "IOT-LOCAL (input) drop by default-action"),
    (IOT_V6, RTR_LAN_V6, 53, "udp", "permit", "IOT-LOCAL-6 (input) accept by rule 20"),
    (IOT_V6, RTR_LAN_V6, None, "icmpv6", "permit", "IOT-LOCAL-6 (input) accept by rule 10"),
    (IOT_V6, RTR_LAN_V6, 22, "tcp", "deny", "IOT-LOCAL-6 (input) drop by default-action"),
    (LAN_V4, RTR_IOT_V4, 22, "tcp", "permit", "LAN-LOCAL (input) accept by default-action"),
    (LAN_V4, RTR_LAN_V4, 22, "tcp", "permit", "LAN-LOCAL (input) accept by default-action"),
]


@pytest.mark.parametrize(("src", "dst", "port", "proto", "outcome", "firewall"), REAL_ANSWERS)
def test_the_owners_rule_shape_decides_each_flow_to_the_router(src, dst, port, proto, outcome, firewall):
    result = _trace(_core1_real(), src, dst, port, proto)
    leg = _leg(result)

    assert leg.get("router_local")
    assert _outcome(leg) == outcome, _forward(result)["warnings"]
    assert leg["firewall"] == firewall
    assert _forward(result)["warnings"] == []


def test_the_reply_from_the_router_to_an_iot_dns_query_is_admitted():
    result = _trace(_core1_real(), IOT_V4, RTR_LAN_V4, 53, "udp", reply=True)
    (reply_leg,) = result["reply"]["legs"]

    assert not result["reply"]["indeterminate"] and result["reply"]["warnings"] == []
    assert reply_leg["firewall"] == f"admitted from session state ({', '.join(STATE_POLICY)})"


def test_the_multicast_rule_admits_the_group_and_not_the_routers_own_address():
    """Rule 100 (any service to 224.0.0.0/4) hits part of a destination set that holds the
    router's LAN address and an mDNS group: the impact engine's address filter splits it."""
    from hst.impact.evaluate import _AddressFilter

    graph = TraceGraph(_core1_real())
    region = FlowRegion.from_query(
        _intervals([IOT_V4]), _intervals([RTR_LAN_V4, "224.0.0.251"]), frozenset({17}), _ports("9999")
    )
    out = _AddressFilter(graph, LocalZoneTransition(graph, DEV, ETH1_20, None, "input")).apply(region)

    by_dst = {part.rects[0].dst: effect.kind for part, effect in out}
    assert by_dst == {
        tuple(_intervals([RTR_LAN_V4])): "deny",
        tuple(_intervals(["224.0.0.251"])): "permit",
    }


@pytest.mark.parametrize(
    ("src", "dst", "port", "proto", "pair"),
    [
        (RTR_LAN_V6, RTR_IOT_V6, 53, "udp", "LAN-LOCAL-6"),
        (RTR_IOT_V6, RTR_LAN_V6, 53, "udp", "IOT-LOCAL-6"),
        (RTR_IOT_V4, RTR_LAN_V4, 22, "tcp", "IOT-LOCAL"),
    ],
)
def test_a_packet_the_router_sends_to_itself_is_not_judged_by_a_from_zone_rule_set(
    src, dst, port, proto, pair
):
    result = _trace(_core1_real(), src, dst, port, proto)
    leg = _leg(result)

    assert leg["indeterminate"] and not leg["blocked"]
    assert leg.get("firewall") is None
    assert f"FwRulebase {pair}: on path, not evaluated" in _forward(result)["warnings"]


@pytest.mark.parametrize(
    ("source", "firewall"),
    [(IOT_V4, "IOT-LOCAL (input) drop by default-action"), ("10.18.20.0/30", None)],
)
def test_a_source_set_that_covers_a_router_address_is_not_judged_by_the_pair(source, firewall):
    """The router-local filter itself (a prefix source is not walked end to end by the
    harness): a source set holding the router's IOT address skips the local-zone pool."""
    from hst.path.gates import _Trail

    leg: dict[str, Any] = {}
    gw = {"dev_uid": DEV, "dev_name": "osl01-vyos-01", "if_uid": ETH1_20, "if_name": "eth1.20"}
    trace_mod._router_local_filter(
        TraceGraph(_core1_real()),
        _Trail(),
        leg,
        gw,
        _intervals([source]),
        _intervals([RTR_LAN_V4]),
        22,
        "tcp",
        source,
    )

    assert leg.get("firewall") == firewall


def test_the_router_to_its_own_address_in_one_subnet_takes_no_gateway_own_part(monkeypatch):
    result = _trace(_core1_real(), RTR_IOT_V4, RTR_IOT_V4, 22, "tcp")
    monkeypatch.setattr(trace_mod, "_gateway_own_part", lambda *_a, **_k: [])
    before = _trace(_core1_real(), RTR_IOT_V4, RTR_IOT_V4, 22, "tcp")

    assert result == before


def test_a_subnet_set_with_the_gateway_splits_into_switched_hosts_and_the_router():
    result = _trace(_core1_real(), LAN_V4, "10.18.10.0/30", 22, "tcp")
    switched, local = _forward(result)["legs"]

    assert switched["verdict"] == "switched in 10.18.10.0/24"
    assert switched["dst_label"] == "10.18.10.0/32, 10.18.10.2/31"
    assert local["router_local"] and local["dst_label"] == RTR_LAN_V4
    assert local["firewall"] == "LAN-LOCAL (input) accept by default-action" and not local.get(
        "indeterminate"
    )
    alone = _forward(_trace(_core1_real(), LAN_V4, "10.18.10.2/31", 22, "tcp"))
    (host,) = alone["legs"]
    assert switched["indeterminate"] == host["indeterminate"]
    unevaluated = {w for w in alone["warnings"] if w.endswith("on path, not evaluated")}
    assert unevaluated <= set(_forward(result)["warnings"])


def test_a_host_whose_address_the_router_holds_in_another_table_is_not_the_router():
    from hst.path.gates import _Trail

    estate = _core1_real()
    other, eth9, addr = f"vrf:{DEV}:blue", f"{DEV}/if/eth9", "ip:blue:10.18.20.31"
    estate.nodes += [
        NodeRecord(label="VrfInstance", uid=other, props={"name": "blue"}),
        NodeRecord(label="Interface", uid=eth9, props={"name": "eth9"}),
        NodeRecord(label="IpAddress", uid=addr, props={"ip": IOT_V4}),
    ]
    estate.rels += [
        RelRecord(type="ON", start_label="Interface", start_uid=eth9, end_label="Device", end_uid=DEV),
        RelRecord(
            type="IN_VRF", start_label="Interface", start_uid=eth9, end_label="VrfInstance", end_uid=other
        ),
        RelRecord(
            type="HAS_IP", start_label="Interface", start_uid=eth9, end_label="IpAddress", end_uid=addr
        ),
    ]
    leg: dict[str, Any] = {}
    gw = {"dev_uid": DEV, "dev_name": "osl01-vyos-01", "if_uid": ETH1_20, "if_name": "eth1.20"}
    trace_mod._router_local_filter(
        TraceGraph(estate),
        _Trail(),
        leg,
        gw,
        _intervals([IOT_V4]),
        _intervals([RTR_LAN_V4]),
        53,
        "udp",
        IOT_V4,
    )

    assert leg.get("firewall") == "IOT-LOCAL (input) accept by rule 20"
