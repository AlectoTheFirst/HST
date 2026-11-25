"""The leak guard reads against a real Neo4j: the router of
`tests/support/policy_route_graph.py` loaded at one run, with the reasoner's
edges, gives the findings its batch gives through `BatchGraph` in
tests/test_policy_leak_guard.py.
"""

from __future__ import annotations

import pytest
from tests.support import policy_route_graph as fixture
from tests.test_integration_db import URI
from tests.test_integration_db import _driver as _driver
from tests.test_integration_db import session as session

from hst import reasoner
from hst.core.loader import load
from hst.path import leak_guard
from hst.path.session import CycleSession

pytestmark = [pytest.mark.db, pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set")]
CTS = 3_820_000_000_000


def _second_wan(cfg):
    cfg["interfaces"]["ethernet"]["eth2"] = {"address": ["192.0.2.2/24"], "description": "second WAN"}
    cfg["firewall"]["zone"]["WAN"]["member"]["interface"].append("eth2")
    cfg["protocols"]["static"]["route"] = {"0.0.0.0/0": {"interface": {"eth2": {}}}}


def _findings(session, patch, run_id):
    batch = fixture.batch(patch)
    load(session, batch, ts_ms=CTS, collection_ts=CTS, run_id=run_id)
    reasoner.run(session, ts_ms=CTS + 100, collection_ts=CTS)
    from_graph = leak_guard.leak_guards(CycleSession(session, CTS), fixture.LAN_WAN, fixture.GUARD, 4)
    graph = fixture.BatchGraph(batch)
    from_batch = leak_guard.leak_guards(CycleSession(graph, graph.cts), fixture.LAN_WAN, fixture.GUARD, 4)
    return from_graph, from_batch


def test_the_leak_guard_reads_answer_as_the_batch_does(session):
    from_graph, from_batch = _findings(session, None, "leak-guard")

    assert from_graph == from_batch
    (guard,) = from_graph["leak_guards"]
    assert guard["decided"] is True
    assert guard["tunnel"]["uid"] == fixture.WG44
    assert [out["interface"]["uid"] for out in guard["detail"]["breakout"]] == [fixture.ETH0]
    assert guard["detail"]["destinations"] == fixture.NOT_LOCAL


def test_a_guard_gap_reads_as_the_batch_gives_it(session):
    from_graph, from_batch = _findings(session, _second_wan, "leak-guard-gap")

    assert from_graph == from_batch
    assert from_graph["leak_guards"] == []
    (gap,) = from_graph["guard_gaps"]
    assert [out["interface"]["name"] for out in gap["detail"]["breakout"]] == ["eth2"]
