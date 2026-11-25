"""Baseline calibration and symbolic policy routing through the impact walk."""

from dataclasses import replace

from tests import test_impact_evaluate as estate
from tests.test_impact_evaluate import graph as graph

from hst.path.addrsets import _intervals
from hst.simul import rib


def _observed(inp):
    rows = rib.compute(inp).rib
    by_context = {}
    for row in rows:
        by_context.setdefault(row["context_uid"], []).append(dict(row))
    return replace(inp, observed_rib=by_context, rib_coverage=dict.fromkeys(by_context, "complete"))


def test_contradictory_baseline_never_proves_a_request(graph):
    inp = _observed(estate._routing())
    for row in inp.observed_rib[estate.VRF_R1]:
        if row["prefix"] == "203.0.113.0/24":
            row["next_hop"] = "10.0.2.2"
    network = estate._network(inp)
    result = estate.ev.evaluate(network, estate._changes(estate.SHUT_A), estate._request())
    assert result.before.lower == ()
    assert result.after.lower == ()
    assert result.before.upper == estate.CLIENTS
    assert result.proven_loss == ()
    assert any(e["kind"] == "rib-route-mismatch" for e in result.before.model_errors)


def test_prediction_is_calibrated_against_before_not_the_old_fib(graph):
    network = estate._network(_observed(estate._routing()))
    result = estate.ev.evaluate(network, estate._changes(estate.SHUT_A), estate._request())
    assert result.before.lower == estate.CLIENTS
    assert result.after.lower == estate.CLIENTS
    assert not any(e["kind"] == "rib-route-mismatch" for e in result.after.model_errors)


def test_an_unrelated_baseline_prefix_does_not_poison_the_request(graph):
    inp = _observed(estate._routing())
    inp.observed_rib[estate.VRF_R1].append(
        {"prefix": "192.0.2.0/24", "protocol": "static", "next_hop": "10.0.2.2"}
    )
    assert estate.ev.answer(estate._network(inp), estate._request()).lower == estate.CLIENTS


def test_an_unmodeled_default_route_does_not_poison_a_request_a_longer_route_already_answers(graph):
    # FRR installs an IPv6 default from router advertisements as `kernel`.
    inp = _observed(estate._routing())
    inp.observed_rib[estate.VRF_R1].append(
        {"prefix": "0.0.0.0/0", "protocol": "kernel", "next_hop": "10.0.1.254"}
    )
    assert estate.ev.answer(estate._network(inp), estate._request()).lower == estate.CLIENTS


def test_an_unmodeled_default_route_that_alone_covers_a_request_leaves_it_not_established(graph):
    # Nothing more specific than the default covers this destination.
    inp = _observed(estate._routing())
    inp.observed_rib[estate.VRF_R1].append(
        {"prefix": "0.0.0.0/0", "protocol": "kernel", "next_hop": "10.0.1.254"}
    )
    request = estate._request(members=(estate.ev.Member("other", estate._ivals("198.51.100.5")),))
    answer = estate.ev.answer(estate._network(inp), request)
    explanation = estate._only(answer, name="other")
    assert explanation.outcome == estate.ev.NOT_ESTABLISHED
    assert any("0.0.0.0/0" in m and "kernel" in m for m in explanation.missing)


def test_compiled_pbr_preserves_protocol_and_both_port_dimensions():
    rule = {
        "rule_uid": "rule:1",
        "pol_uid": "pbr:1",
        "pol_name": "PBR",
        "pos": 10,
        "table_uid": "vrf:redirect",
        "svc_obj_count": 1,
        "svc_protos": ["tcp"],
        "svc_port_specs": ["443"],
        "svc_src_port": True,
        "svc_src_ports": ["40000-40005"],
    }
    fib = rib.Fib([], [{"if_uid": "if:in", "context_uid": "vrf:main", "rules": [rule]}])
    src, dst = _intervals(["10.0.0.0/24"]), _intervals(["203.0.113.0/24"])
    groups = fib.partition(
        "if:in",
        src,
        dst,
        service=(frozenset({6, 17}), estate._pts("443-444"), estate._pts("40000-40010")),
    )
    selected = [g for g in groups if g["rule_uid"]]
    assert len(selected) == 1
    assert selected[0]["proto_subset"] == frozenset({6})
    assert selected[0]["port_subset"] == estate._pts("443")
    assert selected[0]["sport_subset"] == estate._pts("40000-40005")
    assert not selected[0]["opaque"]
    assert any(g["table_uid"] == "vrf:main" for g in groups)


def test_fib_forward_falls_back_only_for_the_uncovered_destination_subset():
    inputs = rib.RibInput(
        contexts=[{"uid": uid, "device_uid": "r1", "platform": "nxos"} for uid in ("main", "policy")],
        connected=[{"context_uid": "main", "prefix": "203.0.113.0/24", "interface": "lan"}],
        static=[{"context_uid": "policy", "prefix": "203.0.113.128/25", "discard": "blackhole"}],
        pbr=[
            {
                "if_uid": "in",
                "device_uid": "r1",
                "context_uid": "main",
                "rules": [{"rule_uid": "redirect", "pos": 10, "table_uid": "policy"}],
            }
        ],
    )
    groups = rib.compute(inputs).fib.forward("in", _intervals(["10.0.0.10"]), _intervals(["203.0.113.0/24"]))
    assert {
        (g["table_uid"], prefix) for g in groups for prefixes, _ in g["parts"] for prefix in prefixes
    } == {
        ("main", "203.0.113.0/25"),
        ("policy", "203.0.113.128/25"),
    }
    selected = next(g for g in groups if g["table_uid"] == "policy")
    assert selected["parts"][0][1][0]["discard"] == "blackhole"


def test_policy_table_uses_sparse_prefix_then_falls_back_per_destination(graph):
    inp = estate._routing()
    policy_context = "vrf:r1:policy"
    inp = replace(
        inp,
        contexts=[*inp.contexts, {"uid": policy_context, "device_uid": estate.R1, "platform": "nxos"}],
        static=[
            {
                "context_uid": policy_context,
                "prefix": "203.0.113.128/25",
                "discard": "blackhole",
            }
        ],
        pbr=[
            {
                "if_uid": "if:r1:eth0",
                "device_uid": estate.R1,
                "context_uid": estate.VRF_R1,
                "rules": [
                    {"rule_uid": "rule:redirect", "pol_name": "PBR", "pos": 10, "table_uid": policy_context}
                ],
            }
        ],
    )
    inp.pbr[0]["if_uid"] = next(
        i.uid for i in estate._interfaces() if i.device_uid == estate.R1 and i.name == "eth0"
    )
    result = estate.ev.answer(estate._network(inp), estate._request(dst="203.0.113.0/24"))
    member = result.members["app"]
    assert member.lower
    assert member.request.subtract(member.upper)
    assert any(s.kind == "fallback" for e in member.explanations for s in e.steps)
    assert not any("policy routing is not evaluated" in m for e in member.explanations for m in e.missing)


class TestRecursiveEgressResolution:
    @staticmethod
    def _routing(*resolvers):
        return estate._routing(
            bgp=False,
            static=[estate._static("203.0.113.0/24", "192.0.2.1"), *resolvers],
        )

    def test_recursive_next_hop_traverses_the_resolved_gateway_filter(self, graph):
        estate._firewall(graph, estate.A, "rb:a", [estate._deny(estate.APP)])
        routing = self._routing(estate._static("192.0.2.0/24", "10.0.1.2"))

        answer = estate.ev.answer(estate._network(routing), estate._request())

        explanation = estate._only(answer)
        assert explanation.outcome == estate.ev.FAILS
        assert estate._step(explanation, "filter", "deny").device_uid == estate.A

    def test_recursive_ecmp_preserves_possible_and_guaranteed_choices(self, graph):
        estate._firewall(graph, estate.B, "rb:b", [estate._deny(estate.APP)])
        routing = self._routing(
            estate._static("192.0.2.0/24", "10.0.1.2"),
            estate._static("192.0.2.0/24", "10.0.2.2"),
        )
        network = estate._network(routing)

        possible = estate.ev.answer(network, estate._request(), estate.ev.POSSIBLE)
        guaranteed = estate.ev.answer(network, estate._request(), estate.ev.GUARANTEED)

        assert possible.lower == estate.CLIENTS
        assert guaranteed.upper == ()
        for answer in (possible, guaranteed):
            assert sorted(e.outcome for e in answer.members["app"].explanations) == [
                estate.ev.FAILS,
                estate.ev.HOLDS,
            ]

    def test_contradictory_recursive_resolution_remains_unknown(self, graph):
        routing = _observed(self._routing(estate._static("192.0.2.0/24", "10.0.1.2")))
        resolver = next(row for row in routing.observed_rib[estate.VRF_R1] if row["prefix"] == "192.0.2.0/24")
        resolver["next_hop"] = "10.0.2.2"

        answer = estate.ev.answer(estate._network(routing), estate._request())

        explanation = estate._only(answer)
        assert explanation.outcome == estate.ev.NOT_ESTABLISHED
        assert estate._step(explanation, "route", "resolution-incomplete")
        assert any("not calibrated" in missing for missing in explanation.missing)


def test_a_discrepancy_on_an_unrequested_prefix_is_not_reported_beside_the_answer(graph):
    # The observed table holds a route the calculation never produces.
    inp = _observed(estate._routing())
    inp.observed_rib[estate.VRF_R1].append(
        {"prefix": "192.0.2.0/24", "protocol": "static", "next_hop": "10.0.2.2"}
    )
    inp.observed_rib[estate.VRF_R1].append({"prefix": "fe80::/64", "protocol": "connected"})
    result = estate.ev.answer(estate._network(inp), estate._request())
    assert result.lower == estate.CLIENTS
    assert not any(e["kind"] == "rib-route-mismatch" for e in result.model_errors)


def test_a_discrepancy_on_the_requested_prefix_stays_reported(graph):
    inp = _observed(estate._routing())
    for row in inp.observed_rib[estate.VRF_R1]:
        if row["prefix"] == "203.0.113.0/24":
            row["next_hop"] = "10.0.2.2"
    result = estate.ev.answer(estate._network(inp), estate._request())
    mismatches = [e for e in result.model_errors if e["kind"] == "rib-route-mismatch"]
    assert mismatches
    assert all(str(e["subject"]).endswith("/203.0.113.0/24") for e in mismatches)
