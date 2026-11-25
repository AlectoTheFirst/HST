"""The comparison hands every record to its observer, before the detail cap and
in the order it emits them (core/diff.py `Observer`)."""

from __future__ import annotations

from collections import Counter
from typing import Any

import pytest
from tests.test_diff_stream import DOMAIN, A, B, _Graph, _graph, _Session

from hst.core import cycle as cyclemod
from hst.core import diff as diffmod
from hst.core import manifest as manifestmod
from hst.core.diff import diff_snapshots


@pytest.fixture(params=["default", "spill"])
def spill(request, monkeypatch):
    if request.param == "spill":
        monkeypatch.setattr(cyclemod, "SPILL_ROWS", 7)
        monkeypatch.setattr(cyclemod, "SPILL_RUNS", 2)
    return request.param


def _one_domain_label(nodes: dict[int, list[dict]]) -> dict[int, list[dict]]:
    """Each node under its first domain label only, as the loader writes every node."""
    out: dict[int, list[dict]] = {}
    for side, rows in nodes.items():
        out[side] = []
        for node in rows:
            named = [label for label in node["labels"] if label in DOMAIN]
            if named:
                out[side].append({**node, "labels": ["Obj", named[0], DOMAIN[named[0]]]})
    return out


Observed = tuple[dict[str, Any], list[dict[str, Any]]]


def _observe(seed: int, *, single: bool = False, **kwargs: Any) -> Observed:
    nodes, rels = _graph(seed, 150, parallel=True)
    if single:
        nodes = _one_domain_label(nodes)
    records: list[dict[str, Any]] = []
    result = diff_snapshots(_Session(_Graph(nodes, rels)), A, B, observer=records.append, **kwargs)
    return result, records


def _counted(result: dict[str, Any]) -> Counter[tuple[str, str]]:
    return Counter(
        {
            (kind, change): n
            for kind, key in (("node", "nodes"), ("rel", "rels"))
            for change, n in result["counts"][key].items()
        }
    )


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_the_observer_sees_every_record_the_counts_cover(seed, spill):
    result, records = _observe(seed)
    seen = Counter((r["kind"], r["change"]) for r in records)
    assert +seen == +_counted(result)


def test_the_observer_sees_the_records_beyond_the_detail_cap(monkeypatch):
    monkeypatch.setattr(diffmod, "DETAIL_CAP", 3)
    result, records = _observe(1)
    assert result["truncated"]
    assert len(records) == sum(_counted(result).values())
    assert len(records) > 6 * 3


@pytest.mark.parametrize("seed", [1, 2])
def test_the_observer_sees_the_records_in_the_order_the_comparison_emits(seed, spill):
    _result, records = _observe(seed, single=True)
    kinds = [r["kind"] for r in records]
    assert kinds == sorted(kinds, key=lambda k: k != "node")
    nodes = [(r["label"], r["uid"]) for r in records if r["kind"] == "node"]
    assert nodes == sorted(nodes)
    rels = [
        (r["label"], diffmod._order(r["start"]), diffmod._order(r["end"]))
        for r in records
        if r["kind"] == "rel"
    ]
    assert rels == sorted(rels)


def test_a_record_carries_the_payloads_its_change_names():
    _result, records = _observe(2)
    by_change = {
        change: [r for r in records if r["change"] == change] for change in ("added", "removed", "changed")
    }
    assert all(r["before"] is None and r["after"] for r in by_change["added"])
    assert all(r["after"] is None and r["before"] is not None for r in by_change["removed"])
    for r in by_change["changed"]:
        assert set(r["before"]) == set(r["after"])
        assert all(r["before"][k] != r["after"][k] for k in r["before"])
    for r in records:
        for props in (r["before"], r["after"]):
            assert not any(k.startswith("_") or k in diffmod._EXCLUDED_PROPS for k in props or {})


def test_the_manifest_digest_passes_the_observer_and_keeps_its_value():
    nodes, rels = _graph(3, 150)
    records: list[dict[str, Any]] = []
    plain = manifestmod.graph_delta(_Session(_Graph(nodes, rels)), A, B)
    observed = manifestmod.graph_delta(_Session(_Graph(nodes, rels)), A, B, observer=records.append)
    assert observed == plain
    assert len(records) == sum(sum(bucket.values()) for bucket in plain.counts.values())
