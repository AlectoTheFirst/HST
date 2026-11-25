"""D8/D9 component reuse remains equivalent to a cold routing calculation."""

from dataclasses import replace

from hst.impact.evaluate import Network, apply
from hst.simul.dependencies import PrefixPredicate
from hst.simul.fw_overlay import ChangeSet, Intent
from hst.simul.propagate import SimulationInput
from hst.simul.rib import RibInput, compute, compute_incremental, incremental_from_result


class _Gates:
    def with_changes(self, _changes):
        return self


def _input() -> RibInput:
    return RibInput(
        contexts=[
            {"uid": "a", "device_uid": "dev:a", "platform": "nxos"},
            {"uid": "b", "device_uid": "dev:b", "platform": "nxos"},
            {"uid": "independent", "device_uid": "dev:c", "platform": "nxos"},
        ],
        connected=[
            {"context_uid": "b", "prefix": "10.0.0.0/24", "interface": "b0"},
            {"context_uid": "independent", "prefix": "192.0.2.0/24", "interface": "c0"},
        ],
        static=[
            {
                "context_uid": "a",
                "prefix": "203.0.113.0/24",
                "next_hop": "10.0.0.1",
                "next_hop_context_uid": "b",
                "interface": "a0",
            }
        ],
    )


def _rows(result):
    return [
        (row["context_uid"], row["prefix"], row.get("next_hop"), row.get("interface")) for row in result.rib
    ]


def _semantic(result):
    return (
        _rows(result),
        result.validation,
        result.gaps,
        result.model_errors,
    )


def test_policy_only_overlay_reuses_every_routing_component():
    baseline = compute_incremental(_input(), validate_observed=False)
    reused = compute_incremental(_input(), previous=baseline, validate_observed=False)

    assert _rows(reused.result) == _rows(baseline.result)
    assert reused.components == baseline.components
    assert reused.result.incremental["reason"] == "POLICY_ONLY_ROUTING_REUSE"
    assert reused.result.incremental["counters"] == {
        "dirty_keys": 0,
        "affected_keys": 0,
        "components_recomputed": 0,
        "components_reused": 2,
        "dependency_fallback": 0,
    }


def test_route_dirty_key_recomputes_its_dependency_island_and_reuses_independent_one():
    before_input = _input()
    baseline = compute_incremental(before_input, validate_observed=False)
    changed = replace(
        before_input,
        connected=[
            {"context_uid": "b", "prefix": "10.0.1.0/24", "interface": "b1"},
            {"context_uid": "independent", "prefix": "192.0.2.0/24", "interface": "c0"},
        ],
    )
    incremental = compute_incremental(
        changed,
        previous=baseline,
        dirty=[PrefixPredicate("b", "10.0.0.0/24", 4)],
        validate_observed=False,
    )
    cold = compute(changed, validate_observed=False)

    assert _semantic(incremental.result) == _semantic(cold)
    assert incremental.components[("independent",)] is baseline.components[("independent",)]
    assert incremental.components[("a", "b")] is not baseline.components[("a", "b")]
    assert incremental.result.incremental["counters"] == {
        "dirty_keys": 1,
        "affected_keys": 2,
        "components_recomputed": 1,
        "components_reused": 1,
        "dependency_fallback": 0,
    }


def test_incomplete_dependency_index_rebuilds_all_components():
    baseline = compute_incremental(_input(), validate_observed=False)
    rebuilt = compute_incremental(
        _input(),
        previous=baseline,
        dirty=[PrefixPredicate("a", "203.0.113.0/24", 4)],
        dependency_complete=False,
        validate_observed=False,
    )

    assert rebuilt.result.incremental["reason"] == "DEPENDENCY_INDEX_INCOMPLETE"
    assert rebuilt.result.incremental["counters"]["components_recomputed"] == 2
    assert rebuilt.result.incremental["counters"]["components_reused"] == 0


def test_changed_unhinted_island_is_never_reused_from_a_stale_component_cache():
    before_input = _input()
    baseline = compute_incremental(before_input, validate_observed=False)
    changed = replace(
        before_input,
        connected=[
            {"context_uid": "b", "prefix": "10.0.0.0/24", "interface": "b0"},
            {"context_uid": "independent", "prefix": "192.0.3.0/24", "interface": "c1"},
        ],
    )
    incremental = compute_incremental(
        changed,
        previous=baseline,
        dirty=[PrefixPredicate("b", "10.0.0.0/24", 4)],
        validate_observed=False,
    )

    assert _semantic(incremental.result) == _semantic(compute(changed, validate_observed=False))
    assert incremental.components[("independent",)] is not baseline.components[("independent",)]
    assert incremental.result.incremental["reason"] == "DIRTY_HINT_INCOMPLETE"
    assert incremental.result.incremental["counters"]["components_recomputed"] == 2
    assert incremental.result.incremental["counters"]["components_reused"] == 0


def test_production_network_apply_reuses_routing_for_a_policy_only_overlay():
    network = Network(_input(), (), _Gates())
    before = network.routes
    after = apply(network, ChangeSet([Intent("fw_rule.modify", {"rulebase": "rb", "rule": "r"})]))

    assert after.routes is before


def test_production_network_apply_recomputes_only_the_routing_intent_island():
    source = _input()
    routing = replace(
        source,
        bgp=SimulationInput(
            processes=[
                {
                    "uid": "p:a",
                    "context_uid": "a",
                    "proto": "bgp",
                    "asn": 1,
                    "router_id": "1.1.1.1",
                },
                {
                    "uid": "p:b",
                    "context_uid": "b",
                    "proto": "bgp",
                    "asn": 2,
                    "router_id": "2.2.2.2",
                },
            ],
            sessions=[
                {
                    "uid": "a-b",
                    "process_uid": "p:a",
                    "local_ip": "10.0.0.1",
                    "peer_ip": "10.0.0.2",
                    "local_asn": 1,
                    "peer_asn": 2,
                },
                {
                    "uid": "b-a",
                    "process_uid": "p:b",
                    "local_ip": "10.0.0.2",
                    "peer_ip": "10.0.0.1",
                    "local_asn": 2,
                    "peer_asn": 1,
                },
            ],
        ),
    )
    network = Network(routing, (), _Gates())
    before = network.routes
    assert incremental_from_result(routing, before) is not None
    after = apply(network, ChangeSet([Intent("bgp_session.shut", {"session": "a-b"})]))

    assert _semantic(after.routes) == _semantic(compute(after.routing, validate_observed=False))
    assert after.routes.incremental["counters"]["components_recomputed"] == 1
    assert after.routes.incremental["counters"]["components_reused"] == 1
    assert before is network.routes
