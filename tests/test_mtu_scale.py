"""Deterministic query and expansion budgets, independent of machine speed."""

from types import SimpleNamespace

from tests.test_mtu_contract import observation
from tests.test_mtu_snapshot import row

import hst.path as path
from hst.core.mtu import MtuRequest
from hst.path.gates import _Trail
from hst.path.mtu_topology import MAX_STAGES, crossing, mtu_request, trace_scope


def test_thousand_subjects_use_batched_reads(monkeypatch):
    queries = []

    def read(session, query, **params):
        queries.append((query, params))
        if "HAS_MTU" in query:
            return [row(observation(subject_uid=u)) for u in params["subject_uids"]]
        return []

    monkeypatch.setattr(path, "_read", read)

    @trace_scope()
    def walk(session):
        trail = _Trail()
        for i in range(1000):
            crossing(trail, f"if:{i}", enforcement="l3")
        return {}

    with mtu_request(MtuRequest(mode="inventory"), 4):
        value = walk(SimpleNamespace(cts=42))["mtu"]
    assert len(queries) == 8  # four topology batches plus four evidence batches
    assert all(len(p["subject_uids"]) <= 256 for _, p in queries)
    assert len(value["stages"]) == 1000
    assert value["guaranteed_bytes"] is None
    assert value["known_ceiling_bytes"] == 1500


def test_crossing_budget_is_visible_in_result(monkeypatch):
    monkeypatch.setattr(path, "_read", lambda *a, **k: [])

    @trace_scope()
    def walk(session):
        trail = _Trail()
        for i in range(MAX_STAGES + 2):
            crossing(trail, f"if:{i}", enforcement="l3")
        return {}

    with mtu_request(MtuRequest(mode="inventory"), 4):
        value = walk(SimpleNamespace(cts=42))["mtu"]
    assert len(value["stages"]) == MAX_STAGES
    assert value["coverage"]["truncated"] is True
    assert value["coverage"]["complete"] is False
