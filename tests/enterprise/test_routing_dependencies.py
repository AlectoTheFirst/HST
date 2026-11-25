from hst.simul import certainty
from hst.simul.dependencies import PrefixPredicate, RoutingDependencies
from hst.simul.propagate import SimulationInput
from hst.simul.rib import RibInput


def _input() -> RibInput:
    processes = [
        {"uid": "p:a", "context_uid": "a", "proto": "bgp", "asn": 1, "router_id": "1.1.1.1"},
        {"uid": "p:b", "context_uid": "b", "proto": "bgp", "asn": 2, "router_id": "2.2.2.2"},
    ]
    sessions = [
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
    ]
    return RibInput(
        contexts=[{"uid": uid, "device_uid": uid, "platform": "nxos"} for uid in ("a", "b", "independent")],
        static=[{"context_uid": "a", "prefix": "203.0.113.0/24", "next_hop": None, "interface": "e0"}],
        bgp=SimulationInput(processes=processes, sessions=sessions),
    )


def test_prefix_dependency_certificate_includes_downstream_but_not_independent_context():
    certificate = RoutingDependencies(_input()).certificate([PrefixPredicate("a", "203.0.113.0/24")])

    assert certificate.downstream_contexts == ("a", "b")
    assert PrefixPredicate("a", "203.0.113.0/24") in certificate.affected
    assert all(item.context_uid != "independent" for item in certificate.affected)
    assert certificate.as_dict()["components"] == [["a", "b"]]


def test_dependency_components_are_deterministic_and_serializable():
    dependencies = RoutingDependencies(_input())

    assert dependencies.components == (("a", "b"), ("independent",))
    assert dependencies.closure(["b"]) == frozenset({"a", "b"})


def test_multiple_stable_bgp_histories_remain_uniqueness_unproven():
    gaps = certainty.proof_gaps(_input())

    assert {item["context_uid"] for item in gaps} == {"a", "b"}
    assert {item["kind"] for item in gaps} == {certainty.UNIQUENESS}
