"""Streamed carry-forward and comparison against a real Neo4j: the run and the
comparison the whole in-memory references produce
(tests/support/finalize_reference.py), with buckets and chunks small enough
that every read spills and every write is chunked (core/cycle.py
`carry_forward`, core/diff.py `diff_snapshots`).

Opt-in like tests/test_snapshot_db.py: set NEO4J_TEST_URI to a scratch
database. The fixture deletes this suite's scopes and run keys before and
after every test. The run keys are this suite's own, because a comparison
reads every object a run key holds.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import pytest
from tests.support.finalize_reference import reference_carry_forward, reference_diff

from hst.core import cycle as cyclemod
from hst.core import db as dbmod
from hst.core import diff as diffmod
from hst.core.config import Settings
from hst.core.diff import diff_snapshots
from hst.core.loader import load
from hst.core.model import Batch, NodeRecord, RelRecord

URI = os.environ.get("NEO4J_TEST_URI")

pytestmark = [
    pytest.mark.db,
    pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set"),
]

SCOPE = "stream-test"
PREV, STREAMED, WHOLE = 7_310_000_001_000, 7_310_000_002_000, 7_310_000_003_000
KEYS = [PREV, STREAMED, WHOLE]
WIDTH = 5

# e1 and e6 collected in the new run (e6 lost its FwRule section); e2 to e5
# did not, each for its own reason.
REASONS = {
    f"{SCOPE}:e2": "failed",
    f"{SCOPE}:e3": "cancelled",
    f"{SCOPE}:e4": "unchanged",
    f"{SCOPE}:e5": "not-run",
}
CARRY = {
    "scopes": REASONS,
    "collected": [f"{SCOPE}:e1", f"{SCOPE}:e6"],
    "unasked": [],
    "section_labels": {f"{SCOPE}:e6": ["FwRule"]},
}


def _refuse_if_live() -> None:
    live = Settings(_env_file=None).neo4j_uri
    if dbmod.same_endpoint(URI or "", live):
        pytest.exit(
            f"NEO4J_TEST_URI ({URI}) is the live twin ({live}). This suite deletes data. "
            f"Point it at a scratch database.",
            returncode=2,
        )


@pytest.fixture(scope="module")
def _driver():
    from neo4j import GraphDatabase

    _refuse_if_live()
    driver = GraphDatabase.driver(
        URI,
        auth=(os.environ.get("NEO4J_TEST_USER", "neo4j"), os.environ["NEO4J_TEST_PASSWORD"]),
    )
    with driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j")) as s:
        dbmod.init_db(s)
    yield driver
    driver.close()


@pytest.fixture()
def session(_driver):
    with _driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j")) as s:
        _cleanup(s)
        yield s
        _cleanup(s)


def _cleanup(s) -> None:
    s.run(
        "MATCH (n:Obj) WHERE n._scope STARTS WITH $scope OR n.collection_ts IN $keys DETACH DELETE n",
        scope=SCOPE,
        keys=KEYS,
    ).consume()
    s.run("MATCH (r:CollectionRun) WHERE r.snapshot_ts IN $keys DETACH DELETE r", keys=KEYS).consume()


@pytest.fixture()
def small(monkeypatch):
    """Buckets of three rows merged two runs at a time, and writes of four."""
    monkeypatch.setattr(cyclemod, "SPILL_ROWS", 3)
    monkeypatch.setattr(cyclemod, "SPILL_RUNS", 2)
    monkeypatch.setattr(cyclemod, "BATCH", 4)


def _device(e: int, *, interfaces: int, rules: bool, parallel: bool, role: str = "router") -> Batch:
    dev = f"dev:{SCOPE}:e{e}"
    nodes = [NodeRecord(label="Device", uid=dev, props={"role": role, "name": f"e{e}"})]
    rels = []
    for i in range(interfaces):
        ifc = f"if:{SCOPE}:e{e}:{i}"
        nodes.append(NodeRecord(label="Interface", uid=ifc, props={"name": f"eth{i}", "mtu": 1500 + i}))
        rels.append(RelRecord(type="ON", start=["Interface", ifc], end=["Device", dev]))
    if rules:
        for i in range(WIDTH):
            nodes.append(NodeRecord(label="FwRule", uid=f"rule:{SCOPE}:e{e}:{i}", props={"name": f"r{i}"}))
        policy = f"rule:{SCOPE}:e{e}:policy"
        nodes.append(NodeRecord(label="FwRule", uid=policy, props={"name": "policy"}))
        # two edges of one type between one pair, told apart by their key
        directions = ("in", "out") if parallel else ("in",)
        for direction in directions:
            rels.append(
                RelRecord(
                    type="FILTERED_BY",
                    start=["Device", dev],
                    end=["FwRule", policy],
                    key={"direction": direction},
                )
            )
    return Batch(source="edge", scope=f"{SCOPE}:e{e}", nodes=nodes, rels=rels)


def _parent(s, *, parallel: bool) -> None:
    for e in range(1, 7):
        batch = _device(e, interfaces=WIDTH, rules=True, parallel=parallel)
        load(s, batch, collection_ts=PREV, ts_ms=PREV - 100, run_id=f"{SCOPE}-prev-e{e}")


def _fresh(s, cts: int) -> None:
    """What the new run loaded before its carry: e1 without its last
    interface and with a new role, and e6's device without its rules."""
    load(
        s,
        _device(1, interfaces=WIDTH - 1, rules=False, parallel=False, role="firewall"),
        collection_ts=cts,
        ts_ms=STREAMED - 50,
        run_id=f"{SCOPE}-{cts}-e1",
    )
    load(
        s,
        _device(6, interfaces=0, rules=False, parallel=False),
        collection_ts=cts,
        ts_ms=STREAMED - 50,
        run_id=f"{SCOPE}-{cts}-e6",
    )


# The run key, and the load that wrote a fresh object, which is a different
# load in each of the two runs compared.
_NOT_COMPARED = ("collection_ts", "_run_id")


def _run(s, cts: int) -> tuple[list[str], list[str]]:
    """Run `cts` as sorted canonical rows, `_NOT_COMPARED` left out."""
    nodes = s.run(
        "MATCH (n:Obj {collection_ts: $cts}) RETURN labels(n) AS labels, properties(n) AS props", cts=cts
    ).data()
    rels = s.run(
        "MATCH (a:Obj {collection_ts: $cts})-[r]->(b:Obj) WHERE r.collection_ts = $cts "
        "RETURN type(r) AS t, a.uid AS start, b.uid AS end, properties(r) AS props",
        cts=cts,
    ).data()
    return (
        sorted(
            repr(
                (sorted(n["labels"]), sorted((k, v) for k, v in n["props"].items() if k not in _NOT_COMPARED))
            )
            for n in nodes
        ),
        sorted(
            repr(
                (
                    r["t"],
                    r["start"],
                    r["end"],
                    sorted((k, v) for k, v in r["props"].items() if k not in _NOT_COMPARED),
                )
            )
            for r in rels
        ),
    )


def test_the_streamed_carry_writes_the_run_the_whole_carry_writes(session, small):
    _parent(session, parallel=True)
    _fresh(session, STREAMED)
    _fresh(session, WHOLE)

    counts = cyclemod.carry_forward(session, PREV, STREAMED, ["edge"], **CARRY)
    expected = reference_carry_forward(session, PREV, WHOLE, ["edge"], batch=4, **CARRY)

    assert counts == expected
    # e2 to e5 whole (a device, five interfaces, five rules and the policy
    # each), and e6's six FwRule objects
    assert counts["nodes"] == 4 * (1 + WIDTH + WIDTH + 1) + (WIDTH + 1)
    assert _run(session, STREAMED) == _run(session, WHOLE)
    reasons = {
        row["uid"]: row["reason"]
        for row in session.run(
            "MATCH (n:Obj {collection_ts: $cts}) WHERE n.carried "
            "RETURN n.uid AS uid, n.carried_reason AS reason",
            cts=STREAMED,
        ).data()
    }
    assert reasons[f"dev:{SCOPE}:e3"] == cyclemod.CANCELLED
    assert reasons[f"rule:{SCOPE}:e6:0"] == cyclemod.SECTION_FAILED
    assert f"if:{SCOPE}:e1:{WIDTH - 1}" not in reasons


@dataclass(frozen=True)
class _Entry:
    source: str
    host: str
    outcome: str
    fetch_ts_ms: int | None = None
    fetch_started_ms: int | None = None
    scope: str = ""


# No scope recorded, so each entry is matched by its host, the rule the
# reference comparison has.
DEVICES = (
    _Entry("edge", "e1", "collected", fetch_ts_ms=STREAMED - 60, fetch_started_ms=STREAMED - 70),
    _Entry("edge", "e2", "failed", fetch_ts_ms=PREV - 100),
    _Entry("edge", "e6", "partial", fetch_ts_ms=STREAMED - 60),
)


@pytest.mark.parametrize("devices", [None, DEVICES], ids=["no-manifest", "manifest"])
def test_the_streamed_comparison_is_the_whole_one(session, small, monkeypatch, devices):
    monkeypatch.setattr(diffmod, "DETAIL_CAP", 2)
    _parent(session, parallel=False)
    _fresh(session, STREAMED)
    cyclemod.carry_forward(session, PREV, STREAMED, ["edge"], **CARRY)

    streamed: dict[str, Any] = diff_snapshots(session, PREV, STREAMED, devices_b=devices)
    whole = reference_diff(session, PREV, STREAMED, devices_b=devices, cap=2)

    assert streamed == whole
    assert streamed["truncated"] is True
    assert streamed["counts"]["nodes"]["changed"] == 1  # e1's role
    # e1's last interface, its rules and its policy, and e6's interfaces
    assert streamed["counts"]["nodes"]["removed"] == (1 + WIDTH + 1) + WIDTH
    # their edges: e1's last ON and its FILTERED_BY, and e6's ON edges
    assert streamed["counts"]["rels"] == {"added": 0, "removed": 1 + 1 + WIDTH, "changed": 0}


def _filtered_by(out: dict[str, Any], bucket: str, e: int) -> list[dict[str, Any]]:
    return [
        r for r in out["rels"][bucket] if r["type"] == "FILTERED_BY" and r["start"] == f"dev:{SCOPE}:e{e}"
    ]


def test_the_edges_between_one_pair_are_matched_edge_for_edge(session, small):
    """Two FILTERED_BY edges between each device and its policy, told apart by
    their key. Carried, both read as unchanged, whatever order each read
    returns them in. Gone from a device that collected without its rules,
    both read as removed; collected again with one direction, the other one
    reads as removed."""
    _parent(session, parallel=True)
    _fresh(session, STREAMED)
    cyclemod.carry_forward(session, PREV, STREAMED, ["edge"], **CARRY)
    load(
        session,
        _device(1, interfaces=WIDTH, rules=True, parallel=False),
        collection_ts=WHOLE,
        ts_ms=WHOLE - 50,
        run_id=f"{SCOPE}-{WHOLE}-e1",
    )

    carried = diff_snapshots(session, PREV, STREAMED)
    one_left = diff_snapshots(session, PREV, WHOLE)

    # e1's last ON edge, its two FILTERED_BY edges and e6's ON edges
    assert carried["counts"]["rels"] == {"added": 0, "removed": 1 + 2 + WIDTH, "changed": 0}
    assert len(_filtered_by(carried, "removed", 1)) == 2
    assert not any(_filtered_by(carried, "removed", e) for e in range(2, 7))
    assert len(_filtered_by(one_left, "removed", 1)) == 1
    assert not _filtered_by(one_left, "changed", 1) and not _filtered_by(one_left, "added", 1)
