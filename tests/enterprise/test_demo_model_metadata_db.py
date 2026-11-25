"""The compiled models of the demo estate fit the model codec's metadata limit."""

from __future__ import annotations

import importlib
import json
import os
from pathlib import Path

import pytest

from hst.core import cycle as cyclemod
from hst.core import db as dbmod
from hst.core.config import Settings
from hst.core.fixtures import load_fixture
from hst.core.loader import load

URI = os.environ.get("NEO4J_TEST_URI")
DEMO = Path(__file__).parents[2] / "fixtures" / "demo-enterprise" / "estate-v3.yaml"
CTS = 5_000_000_000_000

pytestmark = [pytest.mark.db, pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set")]


def _cleanup(s):
    s.run("MATCH ()-[r]->() WHERE r._scope = 'reasoner' DELETE r").consume()
    s.run(
        "MATCH (n:Obj) WHERE n._scope IN ['fixture:estate', 'meta:runs', 'meta:cycle', 'meta:cycles'] "
        "DETACH DELETE n"
    ).consume()


@pytest.fixture()
def session():
    from neo4j import GraphDatabase

    live = Settings(_env_file=None).neo4j_uri
    if dbmod.same_endpoint(URI or "", live):
        pytest.exit("NEO4J_TEST_URI is the configured database", returncode=2)
    driver = GraphDatabase.driver(
        URI, auth=(os.environ.get("NEO4J_TEST_USER", "neo4j"), os.environ["NEO4J_TEST_PASSWORD"])
    )
    with driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j")) as s:
        dbmod.init_db(s)
        _cleanup(s)
        yield s
        _cleanup(s)
    driver.close()


def test_demo_estate_models_fit_the_metadata_limit(session):
    if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
        importlib.import_module("dd.cudd")
    else:
        pytest.importorskip("dd.cudd", reason="native symbolic wheel required for these tests")
    from tests.enterprise.test_demo_webshop_evaluation_db import _api_to_db
    from tests.support.batch_inventory import inventory

    from hst.analysis_model.codec import MAX_METADATA_BYTES, ModelBinding, encode_model
    from hst.analysis_model.compile import compile_model
    from hst.analysis_model.model_cache import LIMITS
    from hst.analysis_model.network import normalize_reply_network, normalize_request_network
    from hst.assessment.evaluation import load_network
    from hst.assessment.symbolic_evaluation import member_packets
    from hst.core.finalize import finalize_derivations
    from hst.path.session import CycleSession
    from hst.symbolic import HeaderSchema, SymbolicManager

    batch = load_fixture(DEMO)
    load(session, batch, ts_ms=CTS, run_id="it-demo-metadata", collection_ts=CTS)
    finalize_derivations(session, Settings(_env_file=None), CTS, {})
    cyclemod.set_pointer(session, CTS)
    graph = inventory(batch)
    # The Webshop API tier to webshop-db-01 (fixtures/demo-enterprise/apps/webshop.yaml),
    # a connection that crosses the ACI fabric over the routes the graph holds.
    # The gate is scoped to the VRF a flow enters by, so a model that
    # routes nowhere carries no ACI state to measure.
    request = _api_to_db()
    network = load_network(CycleSession(session, CTS), request)
    forward = normalize_request_network(network, graph, request, "demo")[request.members[0].name]
    deliveries = tuple(
        node.key
        for node in forward.nodes
        if node.terminal == "permit" and node.key.location.startswith("delivery:")
    )
    reply = normalize_reply_network(network, graph, request, request.members[0], "demo", deliveries)
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        known = member_packets(manager, request, request.members[0]).known_fields
        for name, source in (("forward", forward), ("reply", reply)):
            model = compile_model(source, manager, known)
            binding = ModelBinding(
                estate="demo",
                manifest_digest=source.manifest_digest,
                semantic_version="test",
                header_schema=manager.capabilities.schema_version,
                ordering_version=manager.capabilities.ordering_version,
                backend_version=manager.capabilities.backend_version,
            )
            # encode_model raises ModelCodecError when the metadata passes the limit.
            artifact = encode_model(model, binding, limits=LIMITS)
            metadata = len(
                json.dumps(json.loads(artifact)["metadata"], sort_keys=True, separators=(",", ":"))
            )
            aci = sum(node.key.stage == "aci-contract" for node in source.nodes)
            assert 0 < aci < 100, (name, aci)
            assert metadata < 2 * 1024 * 1024 < MAX_METADATA_BYTES, (name, metadata, len(artifact))
