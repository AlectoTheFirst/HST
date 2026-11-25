# ruff: noqa: F811

import pytest
from tests.test_path_reply import _rb
from tests.test_path_reply import _rule as _reply_rule
from tests.test_path_trace import GW, _own_addr, _route, _rule, _src_row, graph  # noqa: F401

from hst import path
from hst.path.gates import firewall as fwmod

_ACCEPT_ESTABLISHED = ["established=accept", "related=accept"]


def _chain(uid, name, default_action):
    return {
        "rb_uid": uid,
        "rb_name": name,
        "vendor": "vyos",
        "default_action": default_action,
        "approximate": False,
    }


def _router_local(graph, monkeypatch, *, input_action, forward_default="drop", output=None, policy=None):
    graph.sources = [_src_row()]
    graph.dev_addrs = {"dev:r1": [_own_addr("10.0.12.1")]}
    graph.routes = {
        "vrf:main": [
            _route("0.0.0.0/0", egress="eth0", next_hop="10.0.12.254"),
            _route("10.0.0.0/24", egress="eth1", kind="ORIGINATES"),
        ]
    }
    graph.rb_by_chain = {
        "forward": _chain("rb:fwd", "ipv4-forward", forward_default),
        "input": _chain("rb:in", "ipv4-input", "drop"),
    }
    if output:
        graph.rb_by_chain["output"] = _chain("rb:out", "ipv4-output", output)
    graph.zone_rules = {"rb:in": [_rule(uid="in:22", pos=22, action=input_action)]}
    monkeypatch.setattr(fwmod, "_device_state_policy", lambda session, dev: policy)


def _reply(result):
    reply = result["reply"]
    assert len(reply["legs"]) == 1
    return reply, reply["legs"][0]


def test_a_router_local_reply_is_admitted_from_session_state_not_judged_by_forward(graph, monkeypatch):
    _router_local(graph, monkeypatch, input_action="accept", policy=_ACCEPT_ESTABLISHED)

    result = path.trace(None, "10.0.0.5", "10.0.12.1", port=22, proto="tcp", gateways=[GW], reply=True)

    reply, leg = _reply(result)
    assert leg["blocked"] is False
    assert leg["firewall"] == "admitted from session state (established=accept, related=accept)"
    assert reply["indeterminate"] is False
    assert not [w for w in reply["warnings"] if "not evaluated" in w]
    assert not [h for h in reply["hops"] if h["uid"] == "rb:fwd"]


def test_a_router_local_reply_with_no_state_policy_reads_the_output_chain(graph, monkeypatch):
    """No collected state policy: the reply is judged by the output chain, as
    an established connection; the forward chain's accept is not its answer."""
    _router_local(
        graph, monkeypatch, input_action="accept", forward_default="accept", output="drop", policy=None
    )

    result = path.trace(None, "10.0.0.5", "10.0.12.1", port=22, proto="tcp", gateways=[GW], reply=True)

    reply, leg = _reply(result)
    assert leg["blocked"] is True
    assert leg["verdict"] == "BLOCKED by ipv4-output default-action"
    assert not [h for h in reply["hops"] if h["uid"] == "rb:fwd"]


def test_a_router_local_reply_with_no_output_filter_is_not_a_forward_chain_verdict(graph, monkeypatch):
    _router_local(graph, monkeypatch, input_action="accept", forward_default="drop", policy=None)

    result = path.trace(None, "10.0.0.5", "10.0.12.1", port=22, proto="tcp", gateways=[GW], reply=True)

    reply, leg = _reply(result)
    assert leg["blocked"] is False
    assert not [h for h in reply["hops"] if h["uid"] == "rb:fwd"]
    assert "ipv4-forward" not in (leg.get("firewall") or "")


def test_a_router_local_leg_the_input_chain_blocked_has_no_reply(graph, monkeypatch):
    _router_local(graph, monkeypatch, input_action="drop", policy=_ACCEPT_ESTABLISHED)

    result = path.trace(None, "10.0.0.5", "10.0.12.1", port=22, proto="tcp", gateways=[GW], reply=True)

    assert result["forward"]["legs"][0]["blocked"] is True
    assert result["reply"]["verdict"] == "reply not derived: the forward leg never confirmed delivery"
    assert result["reply"]["indeterminate"] is True


def _ranged(graph, monkeypatch):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.99.0.0/24", egress="eth2"), _route("10.0.0.0/24", egress="eth1")]}
    graph.rb = _rb(rb_uid="vyos:fwd", vendor="vyos", default_action="drop")
    graph.rules = [
        _reply_rule(
            uid="vyos:r10",
            pos=10,
            src_any=True,
            dst_cidrs=["10.99.0.0/24"],
            protos=["tcp"],
            ports=["443-444"],
        )
    ]
    monkeypatch.setattr(fwmod, "_device_state_policy", lambda session, dev: _ACCEPT_ESTABLISHED)


@pytest.mark.parametrize(
    ("port", "kw"),
    [(443, {}), ("443-444", {}), ("443,444", {}), (443, {"src_port": 40000})],
)
def test_a_ranged_forward_walk_records_the_gate_state_its_reply_reads(graph, monkeypatch, port, kw):
    _ranged(graph, monkeypatch)

    result = path.trace(
        None, "10.0.0.5", "10.99.0.7", port=port, proto="tcp", gateways=[GW], reply=True, **kw
    )

    replies = result["reply"] if isinstance(result["reply"], list) else [result["reply"]]
    for reply in replies:
        for leg in reply["legs"]:
            assert leg["blocked"] is False
            assert leg["firewall"].startswith("admitted from session state")
        assert reply["indeterminate"] is False
        assert not [w for w in reply["warnings"] if "not evaluated" in w]
    assert not [leg for leg in result["forward"]["legs"] if "gate_state" in leg]


def test_a_ranged_region_the_rulebase_drops_gives_no_session_state_reply(graph, monkeypatch):
    """A region the forward rulebase dropped records permit False: its reply
    is not admitted from session state."""
    _ranged(graph, monkeypatch)

    result = path.trace(None, "10.0.0.5", "10.99.0.7", port="443-445", proto="tcp", gateways=[GW], reply=True)

    forward = result["forward"]["legs"]
    assert any(leg["blocked"] for leg in forward) and any(not leg["blocked"] for leg in forward)
    replies = result["reply"] if isinstance(result["reply"], list) else [result["reply"]]
    admitted = [
        leg
        for reply in replies
        for leg in reply["legs"]
        if (leg.get("firewall") or "").startswith("admitted from session state")
    ]
    assert len(admitted) == sum(1 for leg in forward if not leg["blocked"])


# --- the owner's router shape: zone pairs for both families, a LOCAL zone with
# no interface, a global state policy, no input or output chain ---------------

_GW_LAN = {
    "cidr": "10.0.0.0/24",
    "l3dom": "home",
    "if_uid": "if:eth1",
    "if_name": "eth1",
    "dev_uid": "dev:r1",
    "dev_name": "r1",
}
_GW_IOT = {
    "cidr": "10.0.30.0/24",
    "l3dom": "home",
    "if_uid": "if:eth1.30",
    "if_name": "eth1.30",
    "dev_uid": "dev:r1",
    "dev_name": "r1",
}
_ZONES = ["LAN", "GUEST", "IOT", "WAN", "LOCAL"]


def _zoned_router(graph, monkeypatch, policy):
    from tests.test_path_trace import _connected

    graph.routes = {"vrf:main": [_connected("10.0.0.0/24"), _connected("10.0.30.0/24")]}
    graph.gateway_for = {
        ("pfx:10.0.0.0/24", "dev:r1"): {"uid": "if:eth1", "name": "eth1"},
        ("pfx:10.0.30.0/24", "dev:r1"): {"uid": "if:eth1.30", "name": "eth1.30"},
    }
    graph.ingress_zones = {"if:eth1": "LAN", "if:eth1.30": "IOT"}
    graph.dev_addrs = {
        "dev:r1": [
            _own_addr("10.0.0.1", if_uid="if:eth1", if_name="eth1"),
            _own_addr("10.0.30.1", if_uid="if:eth1.30", if_name="eth1.30"),
        ]
    }
    rows = [
        {"rb_uid": f"rb:{s}-{d}-{af}", "af": af, "src_zone": s, "dst_zone": d, "dst_unbound": d == "LOCAL"}
        for s in _ZONES
        for d in _ZONES
        if s != d
        for af in (4, 6)
    ]
    graph.zone_rulebases_by_dev["dev:r1"] = rows
    graph.gates = [{"uid": r["rb_uid"], "name": r["rb_uid"], "kind": "FwRulebase"} for r in rows]
    monkeypatch.setattr(fwmod, "_device_state_policy", lambda session, dev: list(policy) if policy else None)


@pytest.mark.parametrize(
    ("src", "dst", "gws", "pair"),
    [
        ("10.0.30.5", "10.0.0.1", [_GW_IOT, _GW_LAN], "IOT-LOCAL"),
        ("10.0.0.5", "10.0.30.1", [_GW_LAN, _GW_IOT], "LAN-LOCAL"),
    ],
)
def test_a_flow_to_the_zoned_router_is_undecided_on_its_local_pair_only(
    graph, monkeypatch, src, dst, gws, pair
):
    """The (zone, LOCAL) rule set is not evaluated: the forward leg is
    undecided naming that pair's rule sets only, and its reply is not admitted
    from session state on a forward leg that was never confirmed."""
    _zoned_router(graph, monkeypatch, _ACCEPT_ESTABLISHED)
    graph.sources = [_src_row(ip=src)]

    result = path.trace(None, src, dst, port=22, proto="tcp", gateways=gws, reply=True)

    forward = result["forward"]
    assert forward["legs"][0]["indeterminate"] is True
    named = " ".join(w for w in forward["warnings"] if "not evaluated" in w)
    assert f"rb:{pair}-4" in named and f"rb:{pair}-6" in named
    assert not [uid for uid in (g["uid"] for g in graph.gates) if uid in named and pair not in uid]
    reply = result["reply"]
    assert reply["indeterminate"] is True
    assert not (reply["legs"][0].get("firewall") or "").startswith("admitted from session state")


def test_a_reply_the_state_policy_drops_on_the_zoned_router_is_decided(graph, monkeypatch):
    """The state policy decides the reply ahead of every rule set: it is a
    decided block, not 'N gate(s) not evaluated'."""
    _zoned_router(graph, monkeypatch, ["established=drop"])
    graph.sources = [_src_row(ip="10.0.30.5")]

    result = path.trace(
        None, "10.0.30.5", "10.0.0.1", port=22, proto="tcp", gateways=[_GW_IOT, _GW_LAN], reply=True
    )

    reply = result["reply"]
    leg = reply["legs"][0]
    assert leg["blocked"] is True
    assert leg["verdict"] == "BLOCKED by r1's global state policy (established=drop)"
    assert not [w for w in reply["warnings"] if "not evaluated" in w]


def test_a_zoned_router_reply_with_no_state_policy_is_never_forwarded_from_nothing(graph, monkeypatch):
    _zoned_router(graph, monkeypatch, None)
    graph.sources = [_src_row(ip="10.0.30.5")]

    result = path.trace(
        None, "10.0.30.5", "10.0.0.1", port=22, proto="tcp", gateways=[_GW_IOT, _GW_LAN], reply=True
    )

    assert result["reply"]["indeterminate"] is True


def test_an_unconfirmed_forward_leg_leaves_a_state_admitted_reply_undecided_not_blocked(graph, monkeypatch):
    """An unrelated gate the walk did not evaluate leaves the forward leg
    undecided. established=accept would admit the reply ahead of the output
    chain if the flow was permitted, so the output default is not its answer."""
    _router_local(graph, monkeypatch, input_action="accept", output="drop", policy=_ACCEPT_ESTABLISHED)
    graph.gates = [{"uid": "acl:other", "name": "OTHER-ACL", "kind": "FwRulebase"}]

    result = path.trace(None, "10.0.0.5", "10.0.12.1", port=22, proto="tcp", gateways=[GW], reply=True)

    assert result["forward"]["indeterminate"] is True
    reply, leg = _reply(result)
    assert leg["blocked"] is False
    assert leg["indeterminate"] is True
    assert reply["indeterminate"] is True
    assert not [h for h in reply["hops"] if h["uid"] == "rb:out"]
    assert any("not a confirmed permit" in w and "admits the reply" in w for w in reply["warnings"])


def test_a_state_decided_reply_credits_by_the_pair_it_crosses(graph, monkeypatch):
    """The device binds LOCAL-IOT but no IOT-LOCAL rule set; the reply leaves
    toward IOT across (LOCAL, IOT), so the state policy's block is decided."""
    _zoned_router(graph, monkeypatch, ["established=drop"])
    rows = [
        r for r in graph.zone_rulebases_by_dev["dev:r1"] if (r["src_zone"], r["dst_zone"]) != ("IOT", "LOCAL")
    ]
    graph.zone_rulebases_by_dev["dev:r1"] = rows
    graph.gates = [{"uid": r["rb_uid"], "name": r["rb_uid"], "kind": "FwRulebase"} for r in rows]
    graph.sources = [_src_row(ip="10.0.30.5")]

    result = path.trace(
        None, "10.0.30.5", "10.0.0.1", port=22, proto="tcp", gateways=[_GW_IOT, _GW_LAN], reply=True
    )

    reply = result["reply"]
    assert reply["legs"][0]["blocked"] is True
    assert not [w for w in reply["warnings"] if "not evaluated" in w]
