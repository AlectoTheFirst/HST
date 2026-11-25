"""Carry-forward streams each read through a bounded external sort and writes
it back in chunks, and leaves exactly the run the whole in-memory carry
leaves (core/cycle.py `carry_forward`).

`tests/support/finalize_reference.py` holds the whole in-memory carry, the
reference. The store below answers carry-forward's statements, and the
reference's own relationship read, the way Neo4j evaluates them, the composite
uniqueness constraint included, so the parity cases run both carries over the
same parent run and compare what each writes.
"""

from __future__ import annotations

import copy
import re
import tracemalloc
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest
from tests.support.finalize_reference import READ_CARRY_RELS, reference_carry_forward

from hst.core import cycle as cyclemod

PREV, NEW = 100, 200

_CREATE_NODES = re.compile(
    r"UNWIND \$rows AS row CREATE \(n((?::\w+)+)\) SET n = row, n\.collection_ts = \$cts, n\.carried = true"
)
_CREATE_RELS = re.compile(
    r"UNWIND \$rows AS row MATCH \(a:Obj \{uid: row\.start, collection_ts: \$cts\}\), "
    r"\(b:Obj \{uid: row\.end, collection_ts: \$cts\}\) CREATE \(a\)-\[r:(\w+)\]->\(b\) "
    r"SET r = row\.props, r\.collection_ts = \$cts, r\.carried = true"
)


class _Result:
    def __init__(self, rows: Callable[[], Iterable[dict[str, Any]]]) -> None:
        self._rows = rows
        self.how = ""

    def __iter__(self) -> Iterator[dict[str, Any]]:
        self.how = "streamed"
        return iter(self._rows())

    def data(self) -> list[dict[str, Any]]:
        self.how = self.how or "materialized"
        return list(self._rows())


@dataclass
class _Node:
    labels: list[str]
    props: dict[str, Any]


@dataclass
class _Rel:
    type: str
    start: _Node
    end: _Node
    props: dict[str, Any]


@dataclass
class _Store:
    """Nodes and relationships, answering carry-forward's statements.

    A read's rows are worked out when it runs, against the store as it
    stands, which is what a transaction that reads before it writes sees.
    """

    nodes: list[_Node] = field(default_factory=list)
    rels: list[_Rel] = field(default_factory=list)
    chunks: list[int] = field(default_factory=list)
    reads: list[_Result] = field(default_factory=list)

    def node(self, labels: list[str], **props: Any) -> _Node:
        self._check_unique(labels, props)
        self.nodes.append(_Node(list(labels), props))
        return self.nodes[-1]

    def rel(self, rel_type: str, start: _Node, end: _Node, **props: Any) -> None:
        self.rels.append(_Rel(rel_type, start, end, props))

    def _check_unique(self, labels: list[str], props: dict[str, Any]) -> None:
        if "Obj" not in labels or props.get("uid") is None or props.get("collection_ts") is None:
            return
        if self._find(props["uid"], props["collection_ts"]) is not None:
            raise AssertionError(f"uniqueness constraint: {props['uid']} at {props['collection_ts']}")

    def _find(self, uid: Any, cts: int) -> _Node | None:
        if uid is None:
            return None
        for n in self.nodes:
            if "Obj" in n.labels and n.props.get("uid") == uid and n.props.get("collection_ts") == cts:
                return n
        return None

    def _row(self, n: _Node) -> dict[str, Any]:
        return {"labels": list(n.labels), "props": copy.deepcopy(n.props)}

    def _carry_nodes(self, p: dict[str, Any]) -> list[dict[str, Any]]:
        rows = []
        for old in self.nodes:
            if "Obj" not in old.labels or old.props.get("collection_ts") != p["prev"]:
                continue
            scope, sources = old.props.get("_scope"), old.props.get("_sources")
            carried = (
                sources is None
                or (scope is not None and scope in p["scopes"])
                or (scope is None and any(s in p["sources"] for s in sources))
                or (scope is not None and scope not in p["named"] and any(s in p["unasked"] for s in sources))
            )
            if carried and self._find(old.props.get("uid"), p["cts"]) is None:
                rows.append(self._row(old))
        return rows

    def _carry_section(self, p: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            self._row(old)
            for old in self.nodes
            if "Obj" in old.labels
            and old.props.get("collection_ts") == p["prev"]
            and old.props.get("_scope") == p["scope"]
            and any(label in p["labels"] for label in old.labels)
            and self._find(old.props.get("uid"), p["cts"]) is None
        ]

    def _carry_rels(self, p: dict[str, Any], *, scoped: bool) -> list[dict[str, Any]]:
        """`cycle._READ_CARRY_RELS` with `scoped`, and the reference's
        statement without, which carries no edge whose endpoints are both
        fresh and returns no `by_end`."""
        rows = []
        for r in self.rels:
            a0, b0 = r.start, r.end
            if not all("Obj" in n.labels and n.props.get("collection_ts") == p["prev"] for n in (a0, b0)):
                continue
            if (r.props.get("_scope") or "") == "reasoner" or str(r.props.get("_scope") or "").startswith(
                "derived:"
            ):
                continue
            a, b = self._find(a0.props.get("uid"), p["cts"]), self._find(b0.props.get("uid"), p["cts"])
            if a is None or b is None:
                continue
            by_end = a.props.get("carried") is True or b.props.get("carried") is True
            own = scoped and r.props.get("_scope") is not None and r.props["_scope"] in p["scopes"]
            if not (by_end or own):
                continue
            if any(x.start is a and x.end is b and x.type == r.type for x in self.rels):
                continue
            by = a if a.props.get("carried") is True else b
            row = {
                "start": a.props["uid"],
                "end": b.props["uid"],
                "t": r.type,
                "props": copy.deepcopy(r.props),
                "reason": by.props.get("carried_reason"),
            }
            if scoped:
                row["by_end"] = by_end
            rows.append(row)
        return rows

    def _kept_anchors(self, p: dict[str, Any]) -> list[dict[str, Any]]:
        rows = []
        for old in self.nodes:
            if (
                "Obj" not in old.labels
                or old.props.get("collection_ts") != p["prev"]
                or old.props.get("anchor") is None
                or not (old.props.get("_scope") in p["kept"] or old.props.get("_carried_scopes") is not None)
            ):
                continue
            new = self._find(old.props.get("uid"), p["cts"])
            if (
                new is not None
                and new.props.get("carried") is not True
                and new.props.get("anchor") is not None
                and new.props["anchor"] != old.props["anchor"]
            ):
                rows.append(
                    {
                        "uid": old.props["uid"],
                        "scope": old.props.get("_scope"),
                        "laid": old.props.get("_carried_scopes"),
                        "carried": old.props["anchor"],
                        "written": new.props["anchor"],
                    }
                )
        return rows

    def _touched(self, old: _Node, scopes: list[str]) -> list[str]:
        """`[(old)-[r]-(o) WHERE r._scope IN $scopes AND o._scope = r._scope
        | o._sources[0] + '/' + r._scope]`: a null source makes a null entry."""
        out = []
        for r in self.rels:
            if old is not r.start and old is not r.end:
                continue
            scope = r.props.get("_scope")
            other = r.end if old is r.start else r.start
            if scope is None or scope not in scopes or other.props.get("_scope") != scope:
                continue
            sources = other.props.get("_sources") or []
            out.append(f"{sources[0]}/{scope}" if sources else None)
        return out

    def _contributions(self, p: dict[str, Any]) -> list[dict[str, Any]]:
        rows = []
        for new in list(self.nodes):
            if (
                "Obj" not in new.labels
                or new.props.get("collection_ts") != p["cts"]
                or new.props.get("carried") is True
            ):
                continue
            old = self._find(new.props.get("uid"), p["prev"])
            if old is None or all(
                s in (new.props.get("_sources") or []) for s in old.props.get("_sources") or []
            ):
                continue
            rows.append(
                {
                    "labels": list(old.labels),
                    "prior": copy.deepcopy(old.props),
                    "fresh": copy.deepcopy(new.props),
                    "touched": self._touched(old, p["scopes"]),
                }
            )
        return rows

    def run(self, query: str, **params: Any) -> _Result:
        if query == cyclemod._READ_CARRY_NODES:
            rows = self._carry_nodes(params)
        elif query == cyclemod._CHECK_CARRY_ANCHORS:
            rows = self._kept_anchors(params)
        elif query == cyclemod._READ_CARRY_CONTRIBUTIONS:
            rows = self._contributions(params)
        elif query == cyclemod._WRITE_CARRY_CONTRIBUTIONS:
            self.chunks.append(len(params["rows"]))
            for row in params["rows"]:
                node = self._find(row["uid"], params["cts"])
                assert node is not None
                node.props.update(row["props"])
                node.props["_sources"] = [*(node.props.get("_sources") or []), *row["sources"]]
            rows = []
        elif query == cyclemod._READ_CARRY_SECTION_NODES:
            rows = self._carry_section(params)
        elif query == cyclemod._READ_CARRY_RELS:
            rows = self._carry_rels(params, scoped=True)
        elif query == READ_CARRY_RELS:
            rows = self._carry_rels(params, scoped=False)
        elif m := _CREATE_NODES.fullmatch(query):
            self.chunks.append(len(params["rows"]))
            for row in params["rows"]:
                self.node(
                    m.group(1).split(":")[1:], **{**row, "collection_ts": params["cts"], "carried": True}
                )
            rows = []
        elif m := _CREATE_RELS.fullmatch(query):
            self.chunks.append(len(params["rows"]))
            for row in params["rows"]:
                a, b = self._find(row["start"], params["cts"]), self._find(row["end"], params["cts"])
                if a is not None and b is not None:
                    props = {**row["props"], "collection_ts": params["cts"], "carried": True}
                    self.rel(m.group(1), a, b, **props)
            rows = []
        else:
            raise AssertionError(f"unexpected query: {query}")
        result = _Result(lambda: rows)
        if not query.startswith("UNWIND"):
            self.reads.append(result)
        return result

    def execute_read(self, work: Any) -> Any:
        return work(self)

    def execute_write(self, work: Any) -> Any:
        return work(self)

    def state(self, cts: int) -> tuple[list[str], list[str]]:
        """Run `cts` as sorted canonical rows, so two stores compare as runs."""
        nodes = sorted(
            repr((sorted(n.labels), sorted(n.props.items())))
            for n in self.nodes
            if n.props.get("collection_ts") == cts
        )
        rels = sorted(
            repr((r.type, r.start.props.get("uid"), r.end.props.get("uid"), sorted(r.props.items())))
            for r in self.rels
            if r.props.get("collection_ts") == cts
        )
        return nodes, rels


def _obj(
    store: _Store, label: str, uid: str, cts: int, *, scope: str | None, sources: list[str] | None, **props
):
    layer = {"Device": "Phys", "Interface": "L2", "FwRule": "Policy", "Prefix": "L3"}[label]
    extra = {"_scope": scope} if scope is not None else {}
    if sources is not None:
        extra["_sources"] = sources
    return store.node(
        ["Obj", label, layer],
        uid=uid,
        collection_ts=cts,
        collected_at=cts - 10,
        carried=False,
        name=uid,
        _run_id=f"run-{cts}",
        **extra,
        **props,
    )


# The run being built collected e1 and e6 (e6 lost its FwRule section), and
# e2 to e5 did not collect, each for its own reason. `gone` is a source this
# run asked nothing of, holding a device dropped from its inventory;
# `legacy` wrote objects with no recorded scope.
REASONS = {"vyos:e2": "failed", "vyos:e3": "cancelled", "vyos:e4": "unchanged", "vyos:e5": "not-run"}
COLLECTED = ["vyos:e1", "vyos:e6"]
SOURCES = ["edge", "legacy", "gone"]
UNASKED = ["gone"]
SECTIONS = {"vyos:e6": ["FwRule"], "vyos:e1": []}


def _parent_run(width: int) -> _Store:
    """The parent run, and the objects the new run loaded before its carry."""
    store = _Store()
    for e in range(1, 7):
        scope = f"vyos:e{e}"
        dev = _obj(store, "Device", f"dev:e{e}", PREV, scope=scope, sources=["edge"], role="router")
        for i in range(width):
            ifc = _obj(store, "Interface", f"if:e{e}:{i}", PREV, scope=scope, sources=["edge"], mtu=1500 + i)
            store.rel("ON", ifc, dev, _scope=scope, collected_at=PREV - 10)
            rule = _obj(store, "FwRule", f"rule:e{e}:{i}", PREV, scope=scope, sources=["edge"])
            store.rel("APPLIES_TO", rule, ifc, _scope=scope)
        # two edges of one type between one pair, told apart by a key property
        policy = _obj(store, "FwRule", f"policy:e{e}", PREV, scope=scope, sources=["edge"])
        store.rel("FILTERED_BY", dev, policy, direction="in", _scope=scope)
        store.rel("FILTERED_BY", dev, policy, direction="out", _scope=scope)
        store.rel("DERIVED", dev, policy, _scope="reasoner")
        store.rel("MEMBER_OF", dev, policy, _scope="derived:rt-domains")
    # no recorded producer: carried whatever else is true, and in e6 also
    # matched by the section read, which must not copy it a second time
    _obj(store, "FwRule", "rule:orphan:e6", PREV, scope="vyos:e6", sources=None)
    _obj(store, "Device", "site:app", PREV, scope=None, sources=None)
    for i in range(width):
        _obj(store, "Prefix", f"legacy:{i}", PREV, scope=None, sources=["legacy"])
    _obj(store, "Device", "dev:g1", PREV, scope="vyos:g1", sources=["gone"], role="router")
    _obj(store, "Device", "dev:x1", PREV, scope="vyos:x1", sources=["edge"], role="router")
    store.node(["Obj", "Device", "Phys", "Latest"], uid="dev:latest", collection_ts=PREV, collected_at=1)
    # what the new run loaded before its carry: e1 without its last interface,
    # e6's device without its rules, and one of e2's interfaces through
    # another source, which the carry must leave alone
    loaded = {"dev:e1", *(f"if:e1:{i}" for i in range(width - 1)), "dev:e6", "if:e2:0"}
    by_uid = {n.props["uid"]: n for n in list(store.nodes)}
    for uid in sorted(loaded):
        old = by_uid[uid]
        store.node(
            old.labels, **{**old.props, "collection_ts": NEW, "collected_at": NEW - 5, "_run_id": "new"}
        )
    fresh_dev = store._find("dev:e1", NEW)
    for i in range(width - 1):
        fresh_if = store._find(f"if:e1:{i}", NEW)
        assert fresh_dev is not None and fresh_if is not None
        store.rel("ON", fresh_if, fresh_dev, _scope="vyos:e1", collection_ts=NEW)
    return store


@pytest.mark.parametrize(("batch", "spill"), [(5000, None), (3, (4, 2)), (1, (1, 2)), (2, (5, 3))])
@pytest.mark.parametrize("width", [1, 6])
def test_the_streamed_carry_writes_the_run_the_whole_carry_writes(batch, spill, width, monkeypatch):
    monkeypatch.setattr(cyclemod, "BATCH", batch)
    if spill is not None:
        monkeypatch.setattr(cyclemod, "SPILL_ROWS", spill[0])
        monkeypatch.setattr(cyclemod, "SPILL_RUNS", spill[1])
    streamed, whole = _parent_run(width), _parent_run(width)
    kwargs = {"scopes": REASONS, "collected": COLLECTED, "unasked": UNASKED, "section_labels": SECTIONS}

    counts = cyclemod.carry_forward(streamed, PREV, NEW, SOURCES, **kwargs)
    expected = reference_carry_forward(whole, PREV, NEW, SOURCES, batch=batch, **kwargs)

    assert counts == expected
    assert streamed.state(NEW) == whole.state(NEW)
    assert streamed.state(PREV) == whole.state(PREV)
    assert max(streamed.chunks) <= batch
    # every read was consumed as a stream, none materialized
    assert streamed.reads and {r.how for r in streamed.reads} == {"streamed"}

    _nodes, rels = streamed.state(NEW)
    carried = {n.props["uid"]: n.props for n in streamed.nodes if n.props.get("collection_ts") == NEW}
    # the shape of the answer, beyond agreeing with the reference
    assert carried["rule:orphan:e6"]["carried_reason"] == cyclemod.NOT_RUN
    assert carried["rule:e6:0"]["carried_reason"] == cyclemod.SECTION_FAILED
    assert carried["dev:e3"]["carried_reason"] == cyclemod.CANCELLED
    assert carried["if:e2:0"]["carried"] is False
    assert f"if:e1:{width - 1}" not in carried and "dev:x1" not in carried
    assert "dev:g1" in carried and "legacy:0" in carried
    assert carried["dev:latest"]["carried"] is True
    assert sum("'FILTERED_BY'" in r for r in rels) == 2 * 5
    assert not any("'DERIVED'" in r for r in rels)
    # a `derived:` edge is re-derived by the cycle after the carry, never copied
    assert not any("'MEMBER_OF'" in r for r in rels)


def test_the_carry_statement_leaves_every_derived_scope_out():
    assert "STARTS WITH 'derived:'" in cyclemod._READ_CARRY_RELS
    assert "<> 'reasoner'" in cyclemod._READ_CARRY_RELS


def test_carry_forward_between_one_run_and_itself_writes_nothing():
    store = _parent_run(2)
    before = store.state(PREV)
    assert cyclemod.carry_forward(store, PREV, PREV, SOURCES, scopes=REASONS) == {"nodes": 0, "rels": 0}
    assert store.state(PREV) == before and not store.chunks


class _LazyCarry:
    """A parent run of `size` carried objects and edges, generated as each
    read is consumed; the writes are counted and let go."""

    def __init__(self, size: int) -> None:
        self.size = size
        self.written = 0
        self.chunks: list[int] = []

    def _nodes(self) -> Iterator[dict[str, Any]]:
        for i in range(self.size):
            yield {
                "labels": ["Obj", "Prefix", "L3"] if i % 3 else ["Obj", "Interface", "L2"],
                "props": {
                    "uid": f"prefix:{i:07d}",
                    "name": f"10.{i // 65536}.{i // 256 % 256}.{i % 256}/32",
                    "_scope": f"vyos:e{i % 4}",
                    "_sources": ["edge"],
                    "collected_at": i,
                    "collection_ts": PREV,
                    "_run_id": f"run-{i}",
                },
            }

    def _rels(self) -> Iterator[dict[str, Any]]:
        for i in range(self.size):
            yield {
                "start": "vrf:default",
                "end": f"prefix:{i:07d}",
                "t": "LEARNED_ROUTE",
                "props": {"next_hop": f"10.255.0.{i % 250}", "collection_ts": PREV},
                "reason": "failed",
                "by_end": True,
            }

    def run(self, query: str, **params: Any) -> _Result:
        if query == cyclemod._READ_CARRY_NODES:
            return _Result(self._nodes)
        if query in (cyclemod._READ_CARRY_RELS, READ_CARRY_RELS):
            return _Result(self._rels)
        if query == cyclemod._READ_CARRY_CONTRIBUTIONS:
            # nothing of this run was written afresh
            return _Result(list)
        if query.startswith("UNWIND $rows AS row"):
            self.written += len(params["rows"])
            self.chunks.append(len(params["rows"]))
            return _Result(list)
        raise AssertionError(f"unexpected query: {query}")

    def execute_read(self, work: Any) -> Any:
        return work(self)

    def execute_write(self, work: Any) -> Any:
        return work(self)


def _peak(run: Callable[[], dict[str, int]]) -> tuple[int, dict[str, int]]:
    tracemalloc.start()
    try:
        out = run()
        return tracemalloc.get_traced_memory()[1], out
    finally:
        tracemalloc.stop()


def test_what_a_carry_holds_does_not_grow_with_the_run(monkeypatch):
    """Twelve thousand carried objects and edges: the whole carry holds every
    one of them before it writes any, and the streamed one holds its spill
    buckets and one chunk."""
    monkeypatch.setattr(cyclemod, "SPILL_ROWS", 1000)
    monkeypatch.setattr(cyclemod, "SPILL_RUNS", 8)
    monkeypatch.setattr(cyclemod, "BATCH", 500)
    streamed, whole = _LazyCarry(12_000), _LazyCarry(12_000)

    streamed_peak, counts = _peak(lambda: cyclemod.carry_forward(streamed, PREV, NEW, ["edge"]))
    whole_peak, expected = _peak(lambda: reference_carry_forward(whole, PREV, NEW, ["edge"], batch=500))

    assert counts == expected == {"nodes": 12_000, "rels": 12_000}
    assert streamed.written == whole.written and max(streamed.chunks) == 500
    assert streamed_peak * 5 < whole_peak, (streamed_peak, whole_peak)
