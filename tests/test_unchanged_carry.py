"""A device that did not collect comes forward whole (core/cycle.py
`carry_forward`, app/runs_exec.py `CarryScopes` and `_name_written_scopes`)."""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from typing import Any

from tests import test_carry_forward_stream as stream
from tests import test_vyos as tv

from hst.app import runs_exec
from hst.app.store import Source
from hst.collectors.ssh import SshPassword
from hst.collectors.vyos import VyosCollector, VyosConfig
from hst.core import Settings
from hst.core import cycle as cyclemod
from hst.core import manifest as manifests
from hst.core.model import Batch

PREV, NEW = stream.PREV, stream.NEW
SOURCE = "lab"
CORE, EDGE = "192.0.2.1", "192.0.2.2"
NOW = datetime(2026, 10, 1, tzinfo=UTC)


class _Store(stream._Store):
    """The carry's store, answering `cycle._WRITTEN_SCOPES` as well. A
    relationship's properties may name `start` or `end` (an overlay
    connection's `BETWEEN` edge does), so they are never keyword names here."""

    def rel(self, *edge: Any, **props: Any) -> None:
        rel_type, start, end = edge
        self.rels.append(stream._Rel(rel_type, start, end, props))

    def run(self, query: str, **params: Any) -> stream._Result:
        if query != cyclemod._WRITTEN_SCOPES:
            return super().run(query, **params)
        rows = []
        for unit in params["units"]:
            for device in unit["uids"]:
                d = self._find(device, params["prev"])
                if (
                    d is not None
                    and "Device" in d.labels
                    and unit["source"] in (d.props.get("_sources") or [])
                    and d.props.get("_scope") is not None
                    and d.props["_scope"] != unit["scope"]
                ):
                    row = {"scope": unit["scope"], "written": d.props["_scope"]}
                    if row not in rows:
                        rows.append(row)
        return stream._Result(lambda: rows)


def _collector(host: str, settings: Settings | None = None) -> VyosCollector:
    config = VyosConfig(
        host=host,
        auth=SshPassword(username="vyos", password="pw"),
        site_code="home",
        l3dom="home",
        source_name=SOURCE,
    )
    return VyosCollector(config, settings or Settings(_env_file=None))


def _raw(hostname: str, serial: str, *, pbr: bool = True) -> dict[str, Any]:
    config = copy.deepcopy(tv.CONFIG)
    config["system"]["host-name"] = hostname
    if not pbr:
        config.pop("policy")
    return {
        "config": config,
        "version_text": f"Version:          VyOS 1.5-rolling-202607150020\nHardware S/N:     {serial}\n",
        "links": tv.LINKS,
        "routes": {"default": {}},
        "routes6": {"default": {}},
    }


def _batch(collector: VyosCollector, raw: dict[str, Any]) -> Batch:
    """The collector's batch under the source row's name, as a load writes it
    (collectors/base.py `load_payload`)."""
    return collector.normalize(raw).model_copy(update={"source": SOURCE})


def _load(store: _Store, batch: Batch, cts: int) -> None:
    for n in batch.nodes:
        node = store._find(n.uid, cts)
        if node is None:
            store.node(
                ["Obj", n.label],
                **n.props,
                uid=n.uid,
                collection_ts=cts,
                collected_at=cts - 10,
                carried=False,
                _scope=batch.scope,
                _sources=[batch.source],
            )
        elif batch.source not in node.props["_sources"]:
            node.props["_sources"] = [*node.props["_sources"], batch.source]
    for r in batch.rels:
        a, b = store._find(r.start_uid, cts), store._find(r.end_uid, cts)
        assert a is not None and b is not None
        if any(x.start is a and x.end is b and x.type == r.rel_type for x in store.rels):
            continue
        store.rel(r.rel_type, a, b, **{**r.props, "_scope": batch.scope, "collection_ts": cts})


def _run(store: _Store, cts: int) -> tuple[set[str], set[tuple[str, str, str]]]:
    nodes = {str(n.props["uid"]) for n in store.nodes if n.props.get("collection_ts") == cts}
    rels = {
        (r.type, str(r.start.props["uid"]), str(r.end.props["uid"]))
        for r in store.rels
        if r.props.get("collection_ts") == cts
    }
    return nodes, rels


def _unit(collector: VyosCollector) -> runs_exec.PreparedDevice:
    return runs_exec.PreparedDevice(None, collector, None)


def _carry(store: _Store, scopes: runs_exec.CarryScopes) -> dict[str, int]:
    return cyclemod.carry_forward(
        store, PREV, NEW, [SOURCE, "vyos"], scopes=scopes.reasons, collected=scopes.collected, unasked=[]
    )


def test_the_collectors_batch_carries_the_scope_the_run_names_it_by():
    core = _collector(CORE)
    batch = _batch(core, _raw("core1", "S1"))
    assert batch.scope == core.scope == f"vyos:{CORE}"


def test_an_unchanged_run_publishes_the_graph_of_the_run_before_it():
    """Both devices' payloads matched the record: nothing is loaded, and the
    run holds every node and relationship its parent holds, the core router
    among them."""
    store = _Store()
    core, edge = _collector(CORE), _collector(EDGE)
    _load(store, _batch(core, _raw("core1", "S1")), PREV)
    _load(store, _batch(edge, _raw("edge1", "S2")), PREV)
    scopes = runs_exec.CarryScopes()
    scopes.carry(_unit(core), cyclemod.UNCHANGED)
    scopes.carry(_unit(edge), cyclemod.UNCHANGED)

    counts = _carry(store, scopes)

    assert _run(store, NEW) == _run(store, PREV)
    assert counts["nodes"] == len(_run(store, PREV)[0])
    assert "dev:core1" in _run(store, NEW)[0]
    reasons = {n.props["carried_reason"] for n in store.nodes if n.props.get("collection_ts") == NEW}
    assert reasons == {cyclemod.UNCHANGED}


def test_a_mixed_run_loads_the_changed_device_and_carries_the_unchanged_one():
    store = _Store()
    core, edge = _collector(CORE), _collector(EDGE)
    core_batch = _batch(core, _raw("core1", "S1"))
    _load(store, core_batch, PREV)
    _load(store, _batch(edge, _raw("edge1", "S2")), PREV)
    changed = _batch(edge, _raw("edge1", "S2", pbr=False))
    _load(store, changed, NEW)
    scopes = runs_exec.CarryScopes()
    scopes.ran(_unit(edge))
    scopes.carry(_unit(core), cyclemod.UNCHANGED)

    _carry(store, scopes)

    nodes, rels = _run(store, NEW)
    assert {n.uid for n in core_batch.nodes} | {n.uid for n in changed.nodes} == nodes
    core_rels = {(r.rel_type, r.start_uid, r.end_uid) for r in core_batch.rels}
    edge_rels = {(r.rel_type, r.start_uid, r.end_uid) for r in changed.rels}
    assert core_rels | edge_rels == rels
    dropped = {n.props["uid"] for n in store.nodes if n.props.get("collection_ts") == PREV} - nodes
    assert dropped and all(uid.startswith("vyos:edge1:") for uid in dropped)


def _prepared(*collectors: VyosCollector) -> list[runs_exec.PreparedSource]:
    row = Source(1, SOURCE, "vyos", {}, b"", True, NOW, NOW)
    return [runs_exec.PreparedSource(row, [_unit(c) for c in collectors])]


def _entry(host: str, devices: list[str]) -> manifests.DeviceEntry:
    return manifests.DeviceEntry(
        source=SOURCE, host=host, outcome="collected", device_uids=devices, scope=f"vyos:{host}"
    )


def test_a_parent_run_that_holds_the_device_under_its_hostname_still_carries_it():
    store = _Store()
    core = _collector(CORE)
    before = _batch(core, _raw("core1", "S1")).model_copy(update={"scope": "vyos:core1"})
    _load(store, before, PREV)
    scopes = runs_exec.CarryScopes()
    scopes.carry(_unit(core), cyclemod.UNCHANGED)

    runs_exec._name_written_scopes(
        store, PREV, _prepared(core), {(SOURCE, CORE): _entry(CORE, ["dev:core1"])}, scopes
    )
    _carry(store, scopes)

    assert scopes.reasons == {f"vyos:{CORE}": cyclemod.UNCHANGED, "vyos:core1": cyclemod.UNCHANGED}
    assert _run(store, NEW) == _run(store, PREV)


class _Answers:
    """A session whose every read returns `rows`."""

    def __init__(self, rows: list[dict[str, str]]) -> None:
        self.rows = rows
        self.units: list[dict[str, Any]] = []

    def execute_read(self, work: Any) -> Any:
        return work(self)

    def run(self, query: str, **params: Any) -> stream._Result:
        assert query == cyclemod._WRITTEN_SCOPES
        self.units = params["units"]
        return stream._Result(lambda: self.rows)


def test_a_scope_another_unit_or_another_collector_owns_is_not_taken():
    """Only a scope of the same collector type that no unit of the run or of
    the parent manifest names, and that did not collect, carries; and it
    carries for the unit's own reason."""
    core, edge = _collector(CORE), _collector(EDGE)
    scopes = runs_exec.CarryScopes()
    scopes.carry(_unit(core), "failed")
    scopes.ran(_unit(edge))
    session = _Answers(
        [
            {"scope": f"vyos:{CORE}", "written": "vyos:core1"},
            {"scope": f"vyos:{CORE}", "written": "apic:fab1"},
            {"scope": f"vyos:{CORE}", "written": f"vyos:{EDGE}"},
            {"scope": f"vyos:{CORE}", "written": "vyos:gone"},
        ]
    )
    previous = {
        (SOURCE, CORE): _entry(CORE, ["dev:core1"]),
        (SOURCE, EDGE): _entry(EDGE, ["dev:edge1"]),
        (SOURCE, "198.51.100.9"): manifests.DeviceEntry(
            source=SOURCE, host="198.51.100.9", outcome="collected", scope="vyos:gone"
        ),
    }

    runs_exec._name_written_scopes(session, PREV, _prepared(core, edge), previous, scopes)

    assert scopes.reasons == {f"vyos:{CORE}": "failed", "vyos:core1": "failed"}
    # only the unit that did not collect is looked up
    assert session.units == [{"source": SOURCE, "scope": f"vyos:{CORE}", "uids": ["dev:core1"]}]


def test_nothing_is_read_when_every_unit_collected():
    edge = _collector(EDGE)
    scopes = runs_exec.CarryScopes()
    scopes.ran(_unit(edge))
    session = _Answers([])

    runs_exec._name_written_scopes(
        session, PREV, _prepared(edge), {(SOURCE, EDGE): _entry(EDGE, ["dev:edge1"])}, scopes
    )

    assert session.units == [] and scopes.reasons == {}


def test_a_unit_of_another_collector_type_is_not_looked_up():
    scopes = runs_exec.CarryScopes()
    scopes.reasons["nxos:leaf1"] = "failed"
    session = _Answers([{"scope": "nxos:leaf1", "written": "nxos:leaf1-old"}])
    previous = {
        (SOURCE, "leaf1"): manifests.DeviceEntry(
            source=SOURCE, host="leaf1", outcome="collected", device_uids=["dev:leaf1"], scope="nxos:leaf1"
        )
    }

    runs_exec._name_written_scopes(session, PREV, _prepared(), previous, scopes)

    assert session.units == [] and scopes.reasons == {"nxos:leaf1": "failed"}
