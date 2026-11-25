"""The comparison reads each run once, and the one that answers a request is
bounded and remembered (core/diff.py)."""

from __future__ import annotations

from typing import Any

import pytest
from neo4j.exceptions import ClientError
from tests.test_diff_stream import DEVICES_B, A, B, _Graph, _Session

from hst.core import diff as diffmod
from hst.core.diff import diff_snapshots


def _wide(labels: int, types: int) -> tuple[dict[int, list[dict]], dict[int, list[dict]]]:
    nodes = {
        snap: [
            {"uid": f"n:{i}", "labels": ["Obj", f"Label{i}", "L3"], "props": {"uid": f"n:{i}", "v": snap}}
            for i in range(labels)
        ]
        for snap in (A, B)
    }
    rels = {
        snap: [
            {"t": f"TYPE_{i}", "start": f"n:{i}", "end": f"n:{(i + 1) % labels}", "props": {"v": snap}}
            for i in range(types)
        ]
        for snap in (A, B)
    }
    return nodes, rels


def test_each_run_is_read_once_for_nodes_and_once_for_relationships():
    nodes, rels = _wide(60, 60)
    graph = _Graph(nodes, rels)

    out = diff_snapshots(_Session(graph), A, B)

    assert sorted(graph.queries) == sorted([diffmod._ALL_NODES] * 2 + [diffmod._ALL_RELS] * 2)
    assert out["counts"] == {
        "nodes": {"added": 0, "removed": 0, "changed": 60},
        "rels": {"added": 0, "removed": 0, "changed": 60},
    }
    assert [r["label"] for r in out["nodes"]["changed"]] == sorted(f"Label{i}" for i in range(60))
    assert [r["type"] for r in out["rels"]["changed"]] == sorted(f"TYPE_{i}" for i in range(60))


def test_a_node_with_no_domain_label_is_compared_after_the_labelled_ones():
    nodes, rels = _wide(3, 0)
    for snap in (A, B):
        nodes[snap].append({"uid": "n:bare", "labels": ["Obj"], "props": {"uid": "n:bare", "v": snap}})
    records: list[dict[str, Any]] = []

    out = diff_snapshots(_Session(_Graph(nodes, rels)), A, B, observer=records.append)

    assert [r["uid"] for r in records] == ["n:0", "n:1", "n:2", "n:bare"]
    assert out["counts"]["nodes"]["changed"] == 4


class _TimedSession(_Session):
    """Records the timeout each read was issued with."""

    def __init__(self, graph: Any, error: Exception | None = None) -> None:
        super().__init__(graph)
        self.timeouts: list[float | None] = []
        self._error = error

    def execute_read(self, work: Any) -> Any:
        self.timeouts.append(getattr(work, "timeout", None))
        if self._error is not None:
            raise self._error
        return super().execute_read(work)


def test_a_request_comparison_is_bounded_and_remembered_per_run_pair():
    nodes, rels = _wide(5, 5)
    graph = _Graph(nodes, rels)
    session = _TimedSession(graph)

    first = diffmod.request_diff(session, A, B, devices_b=[])
    again = diffmod.request_diff(session, A, B, devices_b=[])
    other = diffmod.request_diff(session, A, B, devices_b=[DEVICES_B[0]])

    assert again is first
    assert other is not first
    assert session.timeouts == [diffmod.INTERACTIVE_READ_TIMEOUT_S] * 8
    assert len(graph.queries) == 8


def test_the_comparison_a_publish_makes_keeps_the_server_timeout():
    nodes, rels = _wide(2, 2)
    session = _TimedSession(_Graph(nodes, rels))

    diff_snapshots(session, A, B)

    assert session.timeouts == [None] * 4


class _TimedOut(ClientError):
    code = "Neo.ClientError.Transaction.TransactionTimedOutClientConfiguration"


def test_a_read_past_the_timeout_raises_a_diff_timeout_and_is_not_remembered():
    nodes, rels = _wide(2, 2)
    slow = _TimedSession(_Graph(nodes, rels), _TimedOut("timed out"))

    with pytest.raises(diffmod.DiffTimeout, match="took longer than 120 s"):
        diffmod.request_diff(slow, A, B, devices_b=[])
    assert diffmod._RESULTS == {}


def test_another_client_error_is_not_taken_for_a_timeout():
    nodes, rels = _wide(2, 2)
    broken = _TimedSession(_Graph(nodes, rels), ClientError("syntax"))

    with pytest.raises(ClientError):
        diffmod.request_diff(broken, A, B, devices_b=[])
