"""How many reads `hst.app.fw_overlay_read._RouteTable` makes of the graph
and of the RIB side store, and that reading by next hop and prefix gives the
table the per-VRF read gives.

The graph read is a fake `path._read` that applies the `$hits` and `$context`
parameters of `_LEARNED_NEXT_HOPS` as the query does, and the side store is a
fake RibSource that offers the next-hop reads of `RibSource` beside `routes`.
"""

from __future__ import annotations

from typing import Any

import pytest
from tests.support import fw_overlay_golden as golden

from hst.app import fw_overlay_read
from hst.simul.fw_overlay import DeniedAddresses


class _BulkRib(golden.FakeRib):
    def __init__(self, rows: dict[tuple[str, str | None], list[dict[str, Any]]]) -> None:
        super().__init__(rows)
        self.matching: list[tuple[Any, Any]] = []

    def _all(self):
        for (device, context), rows in self.rows.items():
            for row in rows:
                if row.get("next_hop") is not None:
                    yield device, context, row

    @staticmethod
    def _vrf(context):
        return "default" if context is None else None

    def next_hop_values(self) -> set[str]:
        return {row["next_hop"] for _, _, row in self._all()}

    def route_tables(self) -> set[tuple[str, str | None, str | None]]:
        return {
            (device, context, self._vrf(context)) for device, context, row in self._all() if row.get("prefix")
        }

    def routes_matching(self, *, next_hops=None, prefixes=None):
        self.matching.append((next_hops, prefixes))
        return [
            (device, context, self._vrf(context), dict(row))
            for device, context, row in self._all()
            if (next_hops is None or row["next_hop"] in next_hops)
            and (prefixes is None or row.get("prefix") in prefixes)
        ]


class _Graph:
    """`path._read` over a case's graph rows, answering each query as its
    parameters ask."""

    def __init__(self, case: golden.Case) -> None:
        self.case = case
        self.edge_rows_read = 0

    def __call__(self, session: Any, query: str, **params: Any) -> list[dict[str, Any]]:
        graph = self.case.graph
        if query == fw_overlay_read._NEXT_HOP_VALUES:
            return [{"next_hop": h} for h in sorted({r["next_hop"] for r in graph})]
        if query == fw_overlay_read._ROUTE_CONTEXTS:
            return [{"context_uid": c} for c in sorted({r["context_uid"] for r in graph})]
        if query == fw_overlay_read._VRF_DEVICES:
            return [dict(r) for r in self.case.vrf_devices]
        if query == fw_overlay_read._LEARNED_NEXT_HOPS:
            hits, context, prefixes = params.get("hits"), params.get("context"), params.get("prefixes")
            kept = {
                (r["context_uid"], r["prefix"])
                for r in graph
                if (hits is None or r["next_hop"] in hits)
                and (context is None or r["context_uid"] == context)
                and (prefixes is None or r["prefix"] in prefixes)
            }
            rows = [dict(r) for r in graph if (r["context_uid"], r["prefix"]) in kept]
            self.edge_rows_read += len(rows)
            return sorted(rows, key=lambda r: (r["prefix"], r["context_uid"]))
        return []


def _table(monkeypatch: pytest.MonkeyPatch, case: golden.Case, rib: Any) -> tuple[Any, _Graph]:
    graph = _Graph(case)
    monkeypatch.setattr(fw_overlay_read.pathmod, "_read", graph)
    table = fw_overlay_read._RouteTable(object(), rib, DeniedAddresses(to_specs=list(golden.DENIED_V4)))
    return table, graph


@pytest.mark.parametrize("name", sorted(golden.CASES))
def test_reading_by_next_hop_gives_the_table_the_per_vrf_read_gives(name, monkeypatch):
    case = golden.CASES[name]()
    if case.rib is None:
        pytest.skip("a case with no RibSource reads the graph alone")
    per_table, _ = _table(monkeypatch, case, golden.FakeRib(case.rib))
    by_next_hop, _ = _table(monkeypatch, case, _BulkRib(case.rib))
    assert by_next_hop.relevant == per_table.relevant
    assert by_next_hop.groups == per_table.groups
    assert by_next_hop.contexts == per_table.contexts


def _estate(vrfs: int, routes: int) -> golden.Case:
    """`vrfs` VRFs of `routes` routes each, none through a denied address, and
    one VRF with a route through it."""
    devices, rib, graph = [], {}, []
    for i in range(vrfs):
        context, device = f"vrf:dev:x:r{i}:default", f"dev:x:r{i}"
        devices.append(golden._vd(context, device))
        rib[(device, context)] = [
            golden._rib_row(f"10.{i % 200}.{j}.0/24", "10.0.0.1") for j in range(routes)
        ]
        graph.append(golden._graph_row(context, "172.16.0.0/16", "10.0.0.2"))
    rib[("dev:x:r0", "vrf:dev:x:r0:default")].append(golden._rib_row("198.51.100.0/24", golden.DENIED_V4[0]))
    return golden.Case(graph=graph, intents=[golden.DENY_TO], vrf_devices=devices, rib=rib)


def test_the_side_store_is_read_for_the_estate_not_for_each_vrf(monkeypatch):
    case = _estate(300, 5)
    assert case.rib is not None
    rib = _BulkRib(case.rib)
    table, _ = _table(monkeypatch, case, rib)
    assert rib.calls == []
    assert len(rib.matching) <= 2
    assert [row["prefix"] for row in table.relevant] == ["198.51.100.0/24"]
    assert list(table.groups) == [("vrf:dev:x:r0:default", "198.51.100.0/24")]
    assert len(table.contexts) == 300


def test_the_graph_is_read_for_the_prefixes_that_hold_a_denied_next_hop(monkeypatch):
    case = _estate(300, 5)
    case.graph.append(golden._graph_row("vrf:dev:x:r1:default", "203.0.113.0/24", golden.DENIED_V4[1]))
    case.graph.append(golden._graph_row("vrf:dev:x:r1:default", "203.0.113.0/24", "10.9.9.9"))
    assert case.rib is not None
    table, graph = _table(monkeypatch, case, _BulkRib(case.rib))
    assert graph.edge_rows_read == 2
    [group] = [g for key, g in table.groups.items() if key[1] == "203.0.113.0/24"]
    assert sorted(row["next_hop"] for row in group) == ["10.9.9.9", golden.DENIED_V4[1]]
    assert len(table.contexts) == 300


def _shadowed_static() -> golden.Case:
    """A denied side-store route whose prefix also holds a graph static route
    through another next hop, which the learned route shadows in the RIB."""
    context, device = "vrf:dev:x:r0:default", "dev:x:r0"
    graph = [golden._graph_row(context, "10.0.0.0/16", "10.9.9.9", kind="STATIC_ROUTE", protocol="static")]
    rib = {(device, context): [golden._rib_row("10.0.0.0/16", golden.DENIED_V4[0])]}
    return golden.Case(
        graph=graph, intents=[golden.DENY_TO], vrf_devices=[golden._vd(context, device)], rib=rib
    )


@pytest.mark.parametrize("bulk", [True, False])
def test_the_graph_rows_of_a_prefix_only_the_side_store_denies_stay_in_its_group(monkeypatch, bulk):
    case = _shadowed_static()
    assert case.rib is not None
    table, _ = _table(monkeypatch, case, _BulkRib(case.rib) if bulk else golden.FakeRib(case.rib))
    [group] = table.groups.values()
    assert sorted(row["next_hop"] for row in group) == ["10.9.9.9", golden.DENIED_V4[0]]
