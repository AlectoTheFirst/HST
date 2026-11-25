import json
import random
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from hst.map import store
from hst.map.tiers import delta, read
from hst.map.tiers.schemas import KEYS, RENDER_T2_CABLES, SCHEMAS, TIER_DELTA


def _rows(rng: random.Random, n: int) -> dict[str, dict[str, Any]]:
    return {
        f"dev:{i:03d}": {
            "uid": f"dev:{i:03d}",
            "n_ports": rng.randrange(5),
            "label": rng.choice("abc"),
            "snapshot_ts": 1,
        }
        for i in range(n)
        if rng.random() < 0.8
    }


def _strip(rows: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {k: {c: x for c, x in v.items() if c != "snapshot_ts"} for k, v in rows.items()}


@pytest.mark.parametrize("seed", range(20))
def test_every_delta_is_invertible(seed: int) -> None:
    rng = random.Random(seed)
    before, after = _rows(rng, 30), _rows(rng, 30)
    for row in after.values():
        row["snapshot_ts"] = 2
    rows = list(delta.changes("render_t1", before, after))
    forward = {k: dict(v) for k, v in before.items()}
    delta.apply(forward, rows)
    assert _strip(forward) == _strip(after)
    backward = {k: dict(v) for k, v in after.items()}
    delta.apply(backward, rows, inverse=True)
    assert _strip(backward) == _strip(before)


def test_add_and_remove_carry_the_full_row_and_set_the_changed_columns_only() -> None:
    before = {
        "a": {"uid": "a", "x": 1, "y": 2, "snapshot_ts": 1},
        "b": {"uid": "b", "x": 1, "snapshot_ts": 1},
    }
    after = {"a": {"uid": "a", "x": 1, "y": 3, "snapshot_ts": 2}, "c": {"uid": "c", "x": 5, "snapshot_ts": 2}}
    rows = {r["uid"]: r for r in delta.changes("render_t1", before, after)}
    assert rows["a"]["op"] == delta.SET
    assert (json.loads(rows["a"]["before"]), json.loads(rows["a"]["after"])) == ({"y": 2}, {"y": 3})
    assert rows["b"]["op"] == delta.REMOVE and json.loads(rows["b"]["before"]) == {"uid": "b", "x": 1}
    assert rows["c"]["op"] == delta.ADD and json.loads(rows["c"]["after"]) == {"uid": "c", "x": 5}
    assert list(delta.changes("render_t1", after, after)) == []


def _write(sidestore: Path, name: str, key: int, rows: list[dict[str, Any]]) -> None:
    path = store.table_path(sidestore, name, key)
    path.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.Table.from_pylist(rows, schema=SCHEMAS[name]), path)


def _t1(uid: str, ports: int, ts: int) -> dict[str, Any]:
    return {"uid": uid, "label": uid, "n_ports": ports, "snapshot_ts": ts}


def test_a_cold_tier_composes_the_checkpoint_with_the_deltas_after_it(tmp_path: Path) -> None:
    sidestore = tmp_path / "sidestore"
    t1 = {1: {"a": _t1("a", 1, 1)}, 2: {"a": _t1("a", 2, 2), "b": _t1("b", 1, 2)}, 3: {"b": _t1("b", 4, 3)}}
    _write(sidestore, "render_t1", 1, list(t1[1].values()))
    for parent, key in ((1, 2), (2, 3)):
        rows = [
            {**r, "snapshot_ts": key, "parent_ts": parent}
            for r in delta.changes("render_t1", t1[parent], t1[key])
        ]
        _write(sidestore, "render_t1_delta", key, rows)
    composed = read.tier_at(sidestore, "render_t1", 3, [1, 2, 3])
    got = {r["uid"]: (r["n_ports"], r["snapshot_ts"]) for r in composed.to_pylist()}
    assert got == {"b": (4, 3)}
    assert read.tier_at(sidestore, "render_t1", 1, [1, 2, 3]).num_rows == 1
    with pytest.raises(read.NotFound):
        read.tier_at(sidestore, "render_t1", 4, [1, 2, 3])


def test_a_cold_tier_further_than_the_compose_limit_is_not_found(tmp_path: Path) -> None:
    sidestore = tmp_path / "sidestore"
    _write(sidestore, "render_t1", 1, [_t1("a", 1, 1)])
    chain = list(range(1, read.MAX_COMPOSE + 3))
    with pytest.raises(read.NotFound):
        read.tier_at(sidestore, "render_t1", chain[-1], chain)
    assert read.tier_at(sidestore, "render_t1", chain[-2], chain).num_rows == 1


def test_a_tiled_read_needs_a_tile_and_a_cable_belongs_to_both_tiles(tmp_path: Path) -> None:
    sidestore = tmp_path / "sidestore"
    cables = [
        {"cable_id": "x", "tile_a": "block:a", "tile_b": "block:b"},
        {"cable_id": "y", "tile_a": "block:b", "tile_b": "block:b"},
    ]
    _write(sidestore, "render_t2_cables", 1, cables)
    with pytest.raises(ValueError):
        read.tier_at(sidestore, "render_t2_cables", 1, [1])
    assert [
        r["cable_id"] for r in read.tier_at(sidestore, "render_t2_cables", 1, [1], "block:a").to_pylist()
    ] == ["x"]
    assert len(read.tier_at(sidestore, "render_t2_cables", 1, [1], "block:b")) == 2
    assert set(RENDER_T2_CABLES.names) >= {"tile_a", "tile_b"}


def test_every_tier_table_has_a_key_and_the_delta_schema_names_its_table() -> None:
    assert "table" in TIER_DELTA.names
    assert all(set(KEYS[name]) <= set(SCHEMAS[name].names) for name in KEYS)
