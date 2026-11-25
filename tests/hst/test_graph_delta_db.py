"""The diff observer on the fixtures loaded as 3 runs, against a scratch Neo4j."""

import itertools
from pathlib import Path
from typing import Any

import pytest
from tests.hst.conftest import drop_runs, fixture_batches, load_runs

from hst.core import manifest as manifestmod
from hst.core.model import Batch
from hst.map import events, markers, store
from hst.map.graph_delta import TABLE, GraphDeltaWriter

RUNS = (4_100_000_000_000, 4_100_000_060_000, 4_100_000_120_000)
GONE = "dev:fra01-ips-01"
TOUCHED = "dev:fra01-core-02"

pytestmark = pytest.mark.db


def _edit(batch: Batch) -> None:
    batch.nodes = [n for n in batch.nodes if n.uid != GONE]
    batch.rels = [r for r in batch.rels if GONE not in (r.start_uid, r.end_uid)]
    for node in batch.nodes:
        if node.uid == TOUCHED:
            node.props = {**node.props, "serial": "FDO22229999"}


def _counted(delta: manifestmod.GraphDelta) -> int:
    return sum(sum(bucket.values()) for bucket in delta.counts.values())


def test_the_observer_sees_every_record_the_diff_counts(neo4j_session: Any, tmp_path: Path) -> None:
    session = neo4j_session
    load_runs(session, RUNS, lambda run: fixture_batches(_edit if run == 1 else None))
    markers_dir, sidestore = tmp_path / "manifests", tmp_path / "sidestore"
    try:
        for parent, key in itertools.pairwise(RUNS):
            writer = GraphDeltaWriter(
                store.staged_path(sidestore, key, TABLE), snapshot_ts=key, parent_ts=parent
            )
            live: list[dict[str, Any]] = []
            delta = manifestmod.graph_delta(
                session, parent, key, observer=lambda r, w=writer, out=live: out.append(w.add(r))
            )
            writer.close()
            store.publish_staged(sidestore, key)
            markers.write(markers_dir, {"key": key, "kind": "full", "parent": parent, "published_ts": key})

            assert _counted(delta) > 0
            assert writer.rows == _counted(delta)
            replayed = events.LocalBus(markers_dir, sidestore).replay(key, [events.DELTA_RECORD])
            assert [e.payload for e in replayed] == live
    finally:
        drop_runs(session, RUNS)

    bus = events.LocalBus(markers_dir, sidestore)
    first = [e.payload for e in bus.replay(RUNS[1], [events.DELTA_RECORD])]
    assert {"node", "rel"} <= {row["kind"] for row in first}
    assert (GONE, "removed") in {(row["uid"], row["change"]) for row in first}
    assert (TOUCHED, "changed") in {(row["uid"], row["change"]) for row in first}
    second = [e.payload for e in bus.replay(RUNS[2], [events.DELTA_RECORD])]
    assert (GONE, "added") in {(row["uid"], row["change"]) for row in second}
