"""The generator's policy-route reads against a real Neo4j: the router of
`tests/support/policy_route_graph.py` loaded at one run gives the answers its
batch gives through `BatchGraph` in tests/test_application_generator_policy_routes.py.

Runs only with NEO4J_TEST_URI set to a scratch database.
"""

from __future__ import annotations

import contextlib

import pytest
from tests.support import policy_route_graph as fixture
from tests.test_integration_db import URI
from tests.test_integration_db import _driver as _driver
from tests.test_integration_db import session as session

from hst.app.ai.registry import Principal, ToolContext
from hst.applications import generator_tools
from hst.core.loader import load
from hst.core.snapshot import Snapshot

pytestmark = [pytest.mark.db, pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set")]
CTS = 3_810_000_000_000


def context() -> ToolContext:
    return ToolContext(
        settings=None,
        principal=Principal.for_role("viewer", user_id=7),
        surface="service_generator",
        snapshot=Snapshot(CTS, None),
    )


def answers(monkeypatch, opened) -> dict:
    monkeypatch.setattr(generator_tools.dbmod, "session", opened)
    out = {
        uid: generator_tools.policy_route_sources(context(), {"uid": uid})
        for uid in (fixture.TUNNEL_A, fixture.TUNNEL_B, fixture.TABLE_B, fixture.POLICY)
    }
    out["group"] = generator_tools.object_addresses(context(), {"uid": fixture.GROUP_B})
    return out


def test_the_policy_route_reads_answer_as_the_batch_does(session, monkeypatch):
    batch = fixture.batch()
    load(session, batch, ts_ms=CTS, collection_ts=CTS, run_id="generator-policy-routes")

    @contextlib.contextmanager
    def opened(*_args, **_kwargs):
        yield session

    from_graph = answers(monkeypatch, opened)
    from_batch = answers(monkeypatch, fixture.BatchGraph(batch).opened)

    assert from_graph == from_batch
    rules = {
        (rule["policy"]["uid"], rule["rule"]["position"]): rule
        for rule in from_graph[fixture.TUNNEL_A]["rules"]
    }
    assert [item["address"] for item in rules[(fixture.POLICY, 20)]["sources"]] == [
        "10.20.10.43",
        "10.20.10.44",
        "10.20.10.45",
    ]
    assert [item["address"] for item in rules[(fixture.DEDICATED, 20)]["sources"]] == fixture.RANGE_NETWORKS
    assert rules[(fixture.POLICY, 20)]["destinations"] == fixture.NOT_LOCAL
