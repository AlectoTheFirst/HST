"""Who takes a flow at the end of a link, and what a walk costs.

An address held in another routing scope is another instance, not the endpoint
of the link the flow leaves through; and the walk reads an address index, one
cached decision per context and destination set, and stops at a branch budget.
"""

import importlib
from dataclasses import replace

from tests.test_impact_evaluate import SESSION_A, VRF_A, VRF_R1, _network
from tests.test_impact_sessions import Gates, Verdict, ips, request

from hst.impact import GraphGates, Interface, Network, answer
from hst.simul.rib import Fib, RibInput

# `hst.impact.evaluate` the module, not the function the package re-exports under that name.
ev = importlib.import_module("hst.impact.evaluate")

DOMAINS = {
    "c1": frozenset({"declared:corp"}),
    "c9": frozenset({"declared:other"}),
    "c8": frozenset({"declared:third"}),
    "cn": frozenset({"declared:corp"}),
}


class RouterFilterGates(Gates):
    """Every router other than r1 refuses what is addressed to it."""

    def local_filter(self, device, ingress):
        return Verdict("deny" if device != "r1" else "pass")


def _estate(*, owners=(), domains=DOMAINS, out_segments=(), **gate_options):
    """r1 forwards 10.0.0.10 to 172.16.0.10 onto its `srv` interface (context c1,
    172.16.0.0/24). `owners` are the other interfaces that hold 172.16.0.10."""
    interfaces = [
        Interface("r1", "lan1", "lan", "c1", ("10.0.0.0/24",), ("10.0.0.1",)),
        Interface("r1", "srv1", "srv", "c1", ("172.16.0.0/24",), ("172.16.0.1",), segments=out_segments),
        *owners,
    ]
    contexts = [{"uid": i.context_uid, "device_uid": i.device_uid, "platform": "nxos"} for i in interfaces]
    connected = [
        {"context_uid": i.context_uid, "prefix": p, "interface": i.name}
        for i in interfaces
        for p in i.prefixes
    ]
    return Network(
        RibInput(contexts=contexts, connected=connected),
        tuple(interfaces),
        RouterFilterGates(**gate_options),
        context_domains=domains,
    )


def _flow():
    return replace(request("forward"), members=(ev.Member("server", ips("172.16.0.10")),))


def _holder(device, context, *, segments=(), prefixes=("172.16.0.0/24",)):
    return Interface(device, f"{device}-x", "x", context, prefixes, ("172.16.0.10",), segments=segments)


def test_an_address_in_another_routing_scope_is_not_the_endpoint_of_the_link():
    flow = _flow()
    result = answer(_estate(owners=[_holder("r9", "c9")]), flow)
    assert result.lower == flow.sources
    steps = [s for e in result.members["server"].explanations for s in e.steps]
    assert any(s.kind == "other-instance" and "r9" in s.detail for s in steps)
    # the instance in a third scope changes nothing, and neither does a second one
    assert answer(_estate(owners=[_holder("r9", "c9"), _holder("r8", "c8")]), flow).lower == flow.sources


def test_an_address_in_the_same_routing_domain_on_the_link_is_traced_into_its_device():
    flow = _flow()
    result = answer(_estate(owners=[_holder("rn", "cn")]), flow)
    # rn is the endpoint: its input filter decides, and denies
    assert not result.upper
    assert any(s.device_uid == "rn" for e in result.members["server"].explanations for s in e.steps)


def test_two_instances_in_the_scope_of_the_link_stay_ambiguous():
    domains = {**DOMAINS, "cm": frozenset({"declared:corp"})}
    owners = [_holder("rn", "cn"), _holder("rm", "cm")]
    result = answer(_estate(owners=owners, domains=domains), _flow())
    assert not result.lower
    assert result.upper == _flow().sources


def test_a_routing_domain_that_was_not_read_is_not_established_not_followed():
    flow = _flow()
    result = answer(_estate(owners=[_holder("r9", "c9")], domains=None), flow)
    assert not result.lower
    assert result.upper == flow.sources
    kinds = {s.kind for e in result.members["server"].explanations for s in e.steps}
    assert "scope-unread" in kinds


def test_a_context_with_no_recorded_domain_is_not_followed():
    result = answer(_estate(owners=[_holder("r9", "c9")], domains={"c1": DOMAINS["c1"]}), _flow())
    assert not result.lower


def test_a_shared_segment_makes_the_owner_the_endpoint_whatever_its_domain():
    owner = _holder("r9", "c9", segments=("bd:1",))
    flow = _flow()
    assert not answer(_estate(owners=[owner], out_segments=("bd:1",)), flow).upper
    # a segment of its own: another instance, however alike the prefix
    elsewhere = _holder("r9", "c9", segments=("bd:2",))
    assert answer(_estate(owners=[elsewhere], out_segments=("bd:1",)), flow).lower == flow.sources


def test_an_owner_holding_the_address_outside_the_prefix_of_the_link_is_another_instance():
    stray = _holder("rn", "cn", prefixes=("192.0.2.0/24",))
    flow = _flow()
    assert answer(_estate(owners=[stray]), flow).lower == flow.sources


def _next_hop_estate(domains):
    interfaces = [
        Interface("r1", "lan1", "lan", "c1", ("10.0.0.0/24",), ("10.0.0.1",)),
        Interface("r1", "wan1", "wan", "c1", ("192.0.2.0/30",), ("192.0.2.1",)),
        Interface("r5", "wan5", "wan", "c9", ("192.0.2.0/30",), ("192.0.2.2",)),
        Interface("r5", "lan5", "lan", "c9", ("203.0.113.0/24",), ("203.0.113.1",)),
    ]
    contexts = [{"uid": i.context_uid, "device_uid": i.device_uid, "platform": "nxos"} for i in interfaces]
    connected = [
        {"context_uid": i.context_uid, "prefix": p, "interface": i.name}
        for i in interfaces
        for p in i.prefixes
    ]
    static = [
        {"context_uid": "c1", "prefix": "203.0.113.0/24", "next_hop": "192.0.2.2"},
        {"context_uid": "c9", "prefix": "10.0.0.0/24", "next_hop": "192.0.2.1"},
    ]
    return Network(
        RibInput(contexts=contexts, connected=connected, static=static),
        tuple(interfaces),
        Gates(),
        context_domains=domains,
    )


def test_a_next_hop_is_followed_only_into_the_routing_domain_of_the_route():
    flow = request("forward")
    assert answer(_next_hop_estate({"c1": DOMAINS["c1"], "c9": DOMAINS["c1"]}), flow).lower == flow.sources
    blocked = answer(_next_hop_estate({"c1": DOMAINS["c1"], "c9": DOMAINS["c9"]}), flow)
    assert not blocked.lower
    assert any(s.kind == "other-scope" for e in blocked.members["server"].explanations for s in e.steps), (
        "the hop into another routing scope is named"
    )
    assert not answer(_next_hop_estate(None), flow).lower


# --- the cost of a walk --------------------------------------------------------------------


def _many_interfaces(count):
    return tuple(
        Interface(f"d{n}", f"i{n}", "e", f"c{n}", (), (f"10.{n // 65536}.{n // 256 % 256}.{n % 256}",))
        for n in range(count)
    )


def test_owners_read_an_address_index_built_once_for_every_overlay(monkeypatch):
    built = []
    real = ev._InterfaceIndex.build
    monkeypatch.setattr(
        ev._InterfaceIndex, "build", classmethod(lambda cls, i: built.append(1) or real.__func__(cls, i))
    )
    net = Network(RibInput(), _many_interfaces(500), GraphGates(None))
    assert [i.uid for i in net.owners("10.0.1.4")] == ["i260"]
    assert net.owners("10.9.9.9") == () and net.owners("nope") == ()
    delta = ev.ChangeSet(intents=[])
    after = ev.apply(net, delta)
    assert [i.uid for i in after.owners("10.0.1.4")] == ["i260"]
    assert after.interface_index is net.interface_index
    assert built == [1]


def test_the_address_index_answers_a_range_and_an_interface_lists_of_one_device():
    net = Network(RibInput(), _many_interfaces(300), GraphGates(None))
    index = net.interface_index
    assert sorted(index.within(ips("10.0.0.250-10.0.1.3"))) == sorted(
        f"10.0.{n // 256}.{n % 256}" for n in range(250, 260)
    )
    assert index.within(ips("11.0.0.0/8")) == []
    assert [i.uid for i in index.by_device["d7"]] == ["i7"]


def test_a_decision_about_a_context_is_taken_once_per_destination_set(monkeypatch):
    net = _network()
    asked = []
    real = Network._incomplete
    monkeypatch.setattr(Network, "_incomplete", lambda self, *a: asked.append(a) or real(self, *a))
    dst = tuple(ips("203.0.113.0/24"))
    first = net.incomplete(VRF_R1, dst)
    assert net.incomplete(VRF_R1, dst) is first
    assert net.incomplete(VRF_R1, list(dst)) is first
    net.incomplete(VRF_R1)
    net.incomplete(VRF_A, dst)
    assert len(asked) == 3


def test_the_calibration_is_built_once_for_a_baseline_and_all_its_overlays():
    base = _network()
    base.incomplete(VRF_R1, tuple(ips("203.0.113.0/24")))
    after = ev.apply(base, ev.ChangeSet(intents=[]))
    after.incomplete(VRF_R1, tuple(ips("203.0.113.0/24")))
    assert "_calibration" in base.__dict__
    assert "_calibration" not in after.__dict__


def test_a_fib_says_whether_it_covers_a_context_without_copying_its_rows():
    fib = Fib(
        [{"context_uid": "a", "device_uid": "dev:a", "prefix": "192.0.2.0/24", "next_hop": None}],
        contexts={"b": {"device_uid": "dev:b"}},
    )
    assert fib.covers("a") and fib.covers("b") and not fib.covers("c")
    assert fib.table("b") == [] and fib.table("c") is None


def test_the_advertising_sessions_of_a_prefix_are_counted_from_an_index():
    net = _network()
    inp = net.routing
    for prefix in {row["prefix"] for row in inp.observed_paths}:
        expected = {
            str(row["session_uid"])
            for row in inp.observed_paths
            if row["prefix"] == prefix and str(row["session_uid"]) in {s["uid"] for s in inp.bgp.sessions}
        }
        assert net.advertisements(VRF_R1, prefix) == len(expected)
    assert net.advertisements(VRF_R1, "198.51.100.0/24") == 0
    assert net.advertisements("vrf:none", "203.0.113.0/24") is None
    shut = replace(
        inp,
        bgp=replace(
            inp.bgp,
            sessions=[{**s, "state": "shutdown"} if s["uid"] == SESSION_A else s for s in inp.bgp.sessions],
        ),
    )
    assert replace(net, routing=shut).advertisements(VRF_R1, "203.0.113.0/24") == net.advertisements(
        VRF_R1, "203.0.113.0/24"
    ) - (1 if any(r["session_uid"] == SESSION_A for r in inp.observed_paths) else 0)


def test_the_walk_of_a_source_ends_at_the_branch_budget_as_not_established(monkeypatch):
    net = _estate_chain()
    flow = request("forward")
    assert answer(net, flow).lower == flow.sources
    monkeypatch.setattr(ev, "MAX_WALK_VISITS", 1)
    result = answer(net, flow)
    assert not result.lower
    assert result.upper == flow.sources
    kinds = {s.kind for e in result.members["server"].explanations for s in e.steps}
    assert "branch-budget" in kinds


def _estate_chain():
    from tests.test_impact_sessions import network

    net = network()
    return replace(
        net, context_domains={i.context_uid: frozenset({"declared:estate"}) for i in net.interfaces}
    )


def test_a_model_edit_of_an_interface_keeps_the_segments_it_does_not_state():
    from hst.assessment import adapters

    iface = Interface("d", "if1", "e0", "c1", ("10.0.0.0/24",), ("10.0.0.1",), segments=("bd:1",))
    net = Network(RibInput(), (iface,), GraphGates(None))
    rows = adapters._records(net, "interfaces")
    changed = [{**rows[0], "addresses": ["10.0.0.2"]}]
    edit = {
        "family": "interfaces",
        "selector": ["if1"],
        "before": rows,
        "after": changed,
        "preconditions": {"forward": adapters.digest(rows), "reverse": adapters.digest(changed)},
    }
    (edited,) = adapters.apply_model_edits(net, [edit], direction="forward").interfaces
    assert (edited.addresses, edited.segments) == (("10.0.0.2",), ("bd:1",))


def test_the_interface_read_carries_its_segments_and_the_context_read_its_domains(monkeypatch):
    from hst.assessment import evaluation

    def read(session, query, **params):
        if query == evaluation._NETWORK_INTERFACES_QUERY:
            return [
                {
                    "device_uid": "d",
                    "uid": "if1",
                    "name": "e0",
                    "context_uid": "c1",
                    "prefixes": [],
                    "addresses": [],
                    "segments": ["bd:2", "bd:1"],
                },
                {
                    "device_uid": "d",
                    "uid": "if2",
                    "name": "e1",
                    "context_uid": "c1",
                    "prefixes": [],
                    "addresses": [],
                    "segments": [],
                },
            ]
        assert query == evaluation._CONTEXT_DOMAINS_QUERY
        return [
            {"uid": "c1", "declared": ["rd:a"], "realized": ["ld:a"], "stamped": ["corp"]},
            {"uid": "c2", "declared": [], "realized": [], "stamped": []},
        ]

    monkeypatch.setattr(evaluation.pathmod, "_read", read)
    first, second = evaluation._model_interfaces(None)
    assert first.segments == ("bd:1", "bd:2") and second.segments == ()
    domains = evaluation._context_domains(None)
    assert domains == {
        "c1": frozenset({"declared:rd:a", "l3domain:ld:a", "resolved:corp"}),
        "c2": frozenset(),
    }
    net = Network(RibInput(), (), GraphGates(None), context_domains=domains)
    assert net.same_scope("c1", "c1") is True
    assert net.same_scope("c1", "c2") is None
    assert net.same_scope("c1", "c3") is None
