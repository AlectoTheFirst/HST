"""The Webshop connections of the demo estate evaluate on its loaded snapshot."""

from __future__ import annotations

import importlib
import ipaddress
import os
from dataclasses import replace
from pathlib import Path

import pytest

from hst.core import cycle as cyclemod
from hst.core import db as dbmod
from hst.core.config import Settings
from hst.core.fixtures import load_fixture
from hst.core.loader import load

URI = os.environ.get("NEO4J_TEST_URI")
DEMO = Path(__file__).parents[2] / "fixtures" / "demo-enterprise" / "estate-v3.yaml"
CTS = 5_100_000_000_000
CTX1 = "vrf:aci:fab-dc1:tn-PROD:CTX1"
LEAF = "dev:dc1-leaf-05"
FIRST_FRAGMENTS = (("fragment_offset", ((0, 0),)),)

pytestmark = [pytest.mark.db, pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set")]


def _cleanup(s):
    s.run("MATCH ()-[r]->() WHERE r._scope = 'reasoner' DELETE r").consume()
    s.run(
        "MATCH (n:Obj) WHERE n._scope IN ['fixture:estate', 'meta:runs', 'meta:cycle', 'meta:cycles'] "
        "DETACH DELETE n"
    ).consume()


@pytest.fixture(scope="module")
def demo():
    """The loaded demo estate: the pinned session and the graph inventory."""
    from neo4j import GraphDatabase
    from tests.support.batch_inventory import inventory

    from hst.core.finalize import finalize_derivations
    from hst.path.session import CycleSession

    if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
        importlib.import_module("dd.cudd")
    else:
        pytest.importorskip("dd.cudd", reason="native symbolic wheel required for these tests")
    live = Settings(_env_file=None).neo4j_uri
    if dbmod.same_endpoint(URI or "", live):
        pytest.exit("NEO4J_TEST_URI is the configured database", returncode=2)
    driver = GraphDatabase.driver(
        URI, auth=(os.environ.get("NEO4J_TEST_USER", "neo4j"), os.environ["NEO4J_TEST_PASSWORD"])
    )
    with driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j")) as s:
        dbmod.init_db(s)
        _cleanup(s)
        batch = load_fixture(DEMO)
        load(s, batch, ts_ms=CTS, run_id="it-demo-webshop", collection_ts=CTS)
        finalize_derivations(s, Settings(_env_file=None), CTS, {})
        cyclemod.set_pointer(s, CTS)
        yield CycleSession(s, CTS), inventory(batch)
        _cleanup(s)
    driver.close()


def _ivals(*texts: str):
    networks = [ipaddress.ip_network(text) for text in texts]
    return tuple((4, int(n.network_address), int(n.broadcast_address)) for n in networks)


def _api_to_db(port: int = 5432):
    from hst.impact.evaluate import Member, RequestSet, Service, member

    # fixtures/demo-enterprise/apps/webshop.yaml: the API tier to webshop-db-01
    return RequestSet(
        "webshop api to db",
        _ivals(*(f"10.1.11.{host}" for host in range(11, 16))),
        "db",
        (Member("webshop-db-01", _ivals("10.1.12.11")),),
        member("webshop-db-01"),
        Service(frozenset({6}), ((0, port, port),)),
        success="session",
    )


def _clients_to_vip():
    from hst.impact.evaluate import Member, RequestSet, Service, member

    return RequestSet(
        "webshop clients to vip",
        _ivals("10.11.10.0/24", "10.13.10.0/24", "10.16.10.0/24"),
        "frontend",
        (Member("webshop-vip", _ivals("10.1.30.10")),),
        member("webshop-vip"),
        Service(frozenset({6}), ((0, 443, 443),)),
        success="session",
    )


def _verdict(network, graph, request) -> tuple[str, tuple[str, ...]]:
    from hst.assessment.symbolic_evaluation import SymbolicEvaluation
    from hst.assessment.symbolic_results import outcome

    with SymbolicEvaluation(graph, "demo") as engine:
        answer = engine.answer_network(network, request, "possible")
        return outcome(answer)["verdict"], tuple(sorted(answer.gaps))


def _forward_walk(network, graph, request):
    """The forward model of the request's one member and its walk, summarized
    while the native manager is open."""
    from hst.analysis_model.compile import compile_model
    from hst.analysis_model.network import normalize_request_network
    from hst.assessment.symbolic_evaluation import member_packets
    from hst.impact.symbolic_walk import walk
    from hst.symbolic import HeaderSchema, SymbolicManager

    (target,) = request.members
    source = normalize_request_network(network, graph, request, "demo")[target.name]
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        packets = member_packets(manager, request, target)
        result = walk(compile_model(source, manager, packets.known_fields), packets, request_id="webshop")
        gaps = {
            (
                gap.code,
                gap.state.location if gap.state else None,
                gap.state.stage if gap.state else None,
                gap.state.context.firewall_instance if gap.state else None,
            )
            for gap in result.scoped_gaps
        }
        return source, result.gap_refs, gaps, result.bounds.lower.is_empty()


def test_the_webshop_connections_evaluate_to_not_established(demo):
    from hst.assessment.evaluation import load_network

    session, graph = demo
    for request in (_api_to_db(), _clients_to_vip()):
        for success in ("forward", "session"):
            stated = replace(request, success=success)
            network = load_network(session, stated)
            verdict, gaps = _verdict(network, graph, stated)
            # no routing observation in a fixture run: nothing is proven either way
            assert verdict == "not-established", (request.name, success, verdict, gaps)


def test_api_to_db_starts_on_the_leaf_that_holds_the_api_subnet(demo):
    from hst.assessment.evaluation import load_network

    session, graph = demo
    request = replace(_api_to_db(), success="forward")
    network = load_network(session, request)
    source, gap_refs, gaps, _lower_empty = _forward_walk(network, graph, request)

    (entry,) = source.entries
    assert (entry.key.location, entry.key.context.vrf, entry.key.context.firewall_instance) == (
        f"gate:aci:{CTX1}",
        CTX1,
        LEAF,
    )
    fabric_state = f"routing:{CTX1}:ingress:{LEAF}/if/vlan111"
    assert any(node.key.location == fabric_state for node in source.nodes)
    # CTX1 is observed by no single device and the fixture run records no routing observation
    assert any("ambiguous-device" in reason for reason in network.incomplete(CTX1)), network.incomplete(CTX1)
    assert ("MODEL_SCOPE_INCOMPLETE", fabric_state, "forward", LEAF) in gaps, sorted(map(str, gaps))
    assert not any(
        code == "MODEL_SCOPE_INCOMPLETE" and stage == "aci-contract" for code, _, stage, _ in gaps
    ), sorted(map(str, gaps))
    assert "SOURCE_ATTACHMENT_UNKNOWN" not in gap_refs, gap_refs


def test_vienna_clients_with_their_source_context_are_attached(demo):
    from hst.assessment.evaluation import load_network
    from hst.impact.evaluate import Member, RequestSet, Service, member

    session, graph = demo
    request = RequestSet(
        "vie01 users to webshop vip",
        _ivals("10.11.10.0/24"),
        "webshop-vip",
        (Member("vip", _ivals("10.1.30.10")),),
        member("vip"),
        Service(frozenset({6}), ((0, 443, 443),)),
        source_context="vrf:dev:vie01-core-01:corp",
    )
    network = load_network(session, request)
    _source, gap_refs, gaps, _lower_empty = _forward_walk(network, graph, request)

    assert "SOURCE_ATTACHMENT_UNKNOWN" not in gap_refs, gap_refs
    assert not any(
        code == "MODEL_SCOPE_INCOMPLETE" and stage == "aci-contract" for code, _, stage, _ in gaps
    ), sorted(map(str, gaps))


def test_api_to_db_on_a_port_the_contract_does_not_list_is_proven_denied(demo):
    from hst.assessment.evaluation import load_network

    session, graph = demo
    request = replace(_api_to_db(22), success="forward", header_constraints=FIRST_FRAGMENTS)
    network = load_network(session, request)
    verdict, gaps = _verdict(network, graph, request)
    assert verdict == "does-not-hold", (verdict, gaps)


def test_api_to_db_is_proven_permitted_once_the_fabric_routing_is_observed(demo, monkeypatch):
    from hst.assessment.evaluation import load_network
    from hst.impact.evaluate import Network

    session, graph = demo
    observed = Network.incomplete

    def incomplete(self, context_uid, destinations=None):
        # the routing observation of the fabric VRF that a fixture run does not publish
        return () if context_uid == CTX1 else observed(self, context_uid, destinations)

    monkeypatch.setattr(Network, "incomplete", incomplete)
    request = replace(_api_to_db(), success="forward", header_constraints=FIRST_FRAGMENTS)
    network = load_network(session, request)
    verdict, gaps = _verdict(network, graph, request)
    assert verdict == "holds", (verdict, gaps)


def test_api_to_db_session_with_the_fabric_routing_observed_holds(demo, monkeypatch):
    from hst.assessment.evaluation import load_network
    from hst.impact.evaluate import Network

    session, graph = demo
    observed = Network.incomplete

    def incomplete(self, context_uid, destinations=None):
        return () if context_uid == CTX1 else observed(self, context_uid, destinations)

    monkeypatch.setattr(Network, "incomplete", incomplete)
    request = replace(_api_to_db(), header_constraints=FIRST_FRAGMENTS)
    network = load_network(session, request)
    verdict, gaps = _verdict(network, graph, request)
    assert (verdict, "FORWARDING_CHOICES_INCOMPLETE" in gaps) == ("holds", False), (verdict, gaps)
