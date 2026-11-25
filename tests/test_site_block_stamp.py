"""The per run stamp of the operator's site zone: `Device.site_zone` and `Device.site_block`."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from tests.test_manifest import PREV, _Cycle, _prepared, _Rt, _Rules, _Session, _settings

from hst.app import runs_exec
from hst.core import cycle as cyclemod
from hst.core import finalize, manifest
from hst.core.config import Settings
from hst.core.model import RunManifest
from hst.map import site_config


class _CaptureTx:
    def __init__(self, sink: list[dict[str, Any]]) -> None:
        self._sink = sink

    def run(self, query: str, **params: Any) -> Any:
        self._sink.append({"query": query, "params": params})

        class _Result:
            def data(self) -> list[dict[str, Any]]:
                return [{"n": len(params.get("rows") or [])}]

        return _Result()


class _CaptureSession:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def execute_write(self, work: Any) -> Any:
        return work(_CaptureTx(self.calls))


BLOCKS = {
    "dev:edge-01": ("Uplink", "internet"),
    "dev:fw-01": ("DMZ", "external"),
    "dev:sw-01": ("Core", None),
}


# --- the statement ------------------------------------------------------------------------


def test_every_device_of_the_run_is_cleared_before_the_blocks_are_stamped() -> None:
    session = _CaptureSession()
    assert cyclemod.apply_site_blocks(session, BLOCKS, 4242) == 3
    clear, apply_ = session.calls
    # the clear names no uid and no carried flag: a carried copy and a device whose block was removed
    # both lose the stamp of the run they came from
    assert "REMOVE d.site_zone, d.site_block" in clear["query"]
    assert clear["params"] == {"snap": 4242}
    assert "uid" not in clear["query"] and "carried" not in clear["query"]
    assert apply_["params"] == {
        "snap": 4242,
        "rows": [
            {"uid": "dev:edge-01", "block": "Uplink", "zone": "internet"},
            {"uid": "dev:fw-01", "block": "DMZ", "zone": "external"},
            # a block with no zone: the name only, a null SET writes no property
            {"uid": "dev:sw-01", "block": "Core", "zone": None},
        ],
    }
    assert "collection_ts: $snap" in apply_["query"]


def test_an_empty_map_clears_every_stamp_and_writes_none() -> None:
    session = _CaptureSession()
    assert cyclemod.apply_site_blocks(session, {}, 4242) == 0
    (clear,) = session.calls
    assert "REMOVE" in clear["query"]


# --- the finalize step ----------------------------------------------------------------------


class _Quiet:
    def run(self, session: Any, collection_ts: int | None = None) -> list[dict]:
        return []

    def execute(self, *a: Any, **k: Any) -> Any:
        return RunManifest(run_id="x", source="reasoner", scope="x")

    execute_rt_domains = execute_link_speed = execute


class _StampCycle:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []

    def apply_site_assignments(self, session: Any, assigned: Any, cts: int | None = None) -> int:
        self.calls.append(("apply", cts))
        return 0

    def carry_site_assignments(self, session: Any, resolved: Any, cts: int, parent: int | None = None) -> int:
        self.calls.append(("carry", cts))
        return 0

    def apply_site_blocks(self, session: Any, blocks: Any, cts: int) -> int:
        self.calls.append(("blocks", (dict(blocks), cts)))
        return 0


def _finalize(tmp_path: Path, cycle: Any, **kw: Any) -> None:
    finalize.finalize_derivations(
        object(),
        Settings(_env_file=None, hst_data_dir=tmp_path),
        7,
        {},
        rules=_Quiet(),
        route_targets=_Quiet(),
        cycle=cycle,
        **kw,
    )


def test_the_finalize_step_stamps_after_the_site_assignments_and_their_carry(tmp_path) -> None:
    cycle = _StampCycle()
    _finalize(tmp_path, cycle, site_blocks=BLOCKS)
    assert cycle.calls == [("apply", 7), ("carry", 7), ("blocks", (BLOCKS, 7))]


def test_the_finalize_step_given_an_empty_map_clears_and_given_none_writes_nothing(tmp_path) -> None:
    cycle = _StampCycle()
    _finalize(tmp_path, cycle, site_blocks={})
    assert cycle.calls[-1] == ("blocks", ({}, 7))
    cycle = _StampCycle()
    _finalize(tmp_path, cycle)
    assert [c[0] for c in cycle.calls] == ["apply", "carry"]


# --- the read ---------------------------------------------------------------------------------


def test_the_blocks_of_a_run_are_the_map_config_blocks_first_block_wins() -> None:
    config = site_config.from_params(
        [
            ("XA2", {"blocks": [{"name": "Uplink", "zone": "internet", "devices": ["dev:a"]}]}),
            ("XA3", {"blocks": [{"name": "Other", "zone": "internal", "devices": ["dev:a", "dev:b"]}]}),
        ]
    )
    assert runs_exec._site_blocks(config) == {"dev:a": ("Uplink", "internet"), "dev:b": ("Other", "internal")}
    assert runs_exec._site_blocks(None) == {}


class _Store:
    def __init__(self, sites: list[Any] | Exception) -> None:
        self.sites = sites

    async def list_sites(self) -> list[Any]:
        if isinstance(self.sites, Exception):
            raise self.sites
        return self.sites


def test_a_failed_read_of_the_site_parameters_gives_no_config_and_so_no_stamp(tmp_path) -> None:
    settings = _settings(tmp_path)
    config = asyncio.run(runs_exec._write_site_config(_Store(RuntimeError("db gone")), settings))  # type: ignore[arg-type]
    assert config is None
    assert runs_exec._site_blocks(config) == {}


def test_the_read_gives_back_the_config_the_map_file_holds(tmp_path) -> None:
    settings = _settings(tmp_path)
    site = SimpleNamespace(
        code="XA2",
        location=None,
        params={"blocks": [{"name": "Uplink", "zone": "internet", "devices": ["dev:a"]}]},
    )
    config = asyncio.run(runs_exec._write_site_config(_Store([site]), settings))  # type: ignore[arg-type]
    assert config == site_config.read(settings.sidestore_dir)
    assert runs_exec._site_blocks(config) == {"dev:a": ("Uplink", "internet")}


# --- the run builders ------------------------------------------------------------------------


class _BlockCycle(_Cycle):
    def __init__(self, pointer: int | None, keys: list[int]) -> None:
        super().__init__(pointer, keys)
        self.stamped: list[tuple[dict[str, Any], int]] = []

    def apply_site_blocks(self, s: Any, blocks: Any, cts: int) -> int:
        self.steps.append("apply_site_blocks")
        self.stamped.append((dict(blocks), cts))
        return len(blocks)


@pytest.fixture
def rig(monkeypatch, tmp_path):
    def build(keys: list[int] | None = None):
        settings = _settings(tmp_path)
        cycle = _BlockCycle(PREV, keys or [2_000])
        monkeypatch.setattr(runs_exec, "cycle", cycle)
        monkeypatch.setattr(runs_exec, "reasoner", _Rules())
        monkeypatch.setattr(runs_exec, "rt_reasoner", _Rt())
        monkeypatch.setattr(runs_exec.dbmod, "session", lambda s: _Session())
        return settings, cycle

    return build


def test_a_cycle_stamps_the_blocks_it_read_before_the_pointer_and_records_them(rig) -> None:
    settings, cycle = rig()
    capture = runs_exec.ExecutionCapture()
    capture.site_blocks = {"dev:r1": ("Uplink", "internet")}
    runs_exec.execute_cycle(settings, [_prepared(settings, "edge", "r1")], {"edge"}, capture=capture)
    assert cycle.stamped == [({"dev:r1": ("Uplink", "internet")}, 2_000)]
    assert cycle.steps.index("apply_site_blocks") < cycle.steps.index("set_pointer")
    record = manifest.read(settings, 2_000)
    assert record.schema_version == 7
    assert record.site_blocks == {"dev:r1": ("Uplink", "internet")}


def test_a_carried_source_is_stamped_with_the_current_blocks_without_a_new_collection(rig) -> None:
    settings, cycle = rig()
    capture = runs_exec.ExecutionCapture()
    capture.site_blocks = {"dev:r1": ("Uplink", "internet")}
    edge, ctrl = _prepared(settings, "edge", "r1"), _prepared(settings, "ctrl", "c1")
    runs_exec.execute_cycle(settings, [edge, ctrl], {"ctrl"}, capture=capture)
    assert cycle.stamped == [({"dev:r1": ("Uplink", "internet")}, 2_000)]
    record = manifest.read(settings, 2_000)
    assert {(d.host, d.outcome) for d in record.devices} >= {("r1", "carried")}


def test_a_refresh_and_a_device_run_stamp_the_blocks_too(rig) -> None:
    from hst import collectors as coll
    from hst.core import rawstore

    settings, cycle = rig(keys=[2_000, 3_000])
    blocks = {"dev:r1": ("Uplink", "internet")}
    edge, ctrl = _prepared(settings, "edge", "r1"), _prepared(settings, "ctrl", "c1")
    capture = runs_exec.ExecutionCapture()
    capture.site_blocks = blocks
    runs_exec.execute_refresh(settings, [edge, ctrl], "edge", capture=capture)
    assert manifest.read(settings, 2_000).kind == "refresh"
    coll.park(edge.units[0].collector, {"host": "r1"}, source_name="edge")
    assert rawstore.parked(settings.raw_dir)
    capture = runs_exec.ExecutionCapture()
    capture.site_blocks = {}
    runs_exec.build_device_run(settings, [edge], capture=capture)
    assert manifest.read(settings, 3_000).kind == "device"
    # the refresh stamps the blocks it read; the device run read none and clears every stamp
    assert cycle.stamped == [(blocks, 2_000), ({}, 3_000)]
    assert manifest.read(settings, 2_000).site_blocks == blocks
    assert manifest.read(settings, 3_000).site_blocks == {}


def test_a_run_that_read_no_blocks_stamps_nothing_and_records_none(rig) -> None:
    settings, cycle = rig()
    runs_exec.execute_cycle(settings, [_prepared(settings, "edge", "r1")], {"edge"})
    assert cycle.stamped == []
    assert manifest.read(settings, 2_000).site_blocks == {}


def test_a_manifest_before_schema_7_reads_with_no_site_blocks(tmp_path) -> None:
    record = manifest.SnapshotManifest.model_validate(
        {"schema_version": 6, "snapshot_key": 5, "kind": "full", "opened": "x", "published": "y"}
    )
    assert record.site_blocks == {}


def test_the_demo_load_stamps_each_run_right_after_its_load(monkeypatch, tmp_path) -> None:
    """The demo run publishes through `fixture_runs.publish`, which never reaches `_finalize_cycle`:
    the loader it is handed stamps the run it just loaded, before the derivations and the pointer."""
    from hst.app import fixture_runs
    from hst.core import fixtures as fixturesmod
    from hst.core import loader as loadermod

    events: list[Any] = []
    cycle = _BlockCycle(None, [])
    monkeypatch.setattr(runs_exec, "cycle", cycle)
    monkeypatch.setattr(runs_exec.dbmod, "session", lambda s: _Session())
    monkeypatch.setattr(fixturesmod, "load_fixture", lambda path: path.name)
    monkeypatch.setattr(
        loadermod, "load", lambda s, batch, **kw: events.append(("load", batch)) or "manifest"
    )

    def publish(
        s: Any, settings: Any, batch: Any, path: Path, *, new_run: bool, fence: Any, loader: Any
    ) -> Any:
        cts = 100 + len(events)
        loader(s, batch, run_id="r", collection_ts=cts)
        events.append(("published", cts))
        return SimpleNamespace(cts=cts, tiers_ready=True, map_failure=None)

    monkeypatch.setattr(fixture_runs, "publish", publish)
    blocks = {"dev:fr5-border-01": ("Internet edge", "internet")}
    runs = [tmp_path / "estate-v1.yaml", tmp_path / "estate-v2.yaml"]
    runs_exec.execute_demo(_settings(tmp_path), runs, site_blocks=blocks)
    assert events == [
        ("load", "estate-v1.yaml"),
        ("published", 100),
        ("load", "estate-v2.yaml"),
        ("published", 102),
    ]
    assert cycle.stamped == [(blocks, 100), (blocks, 102)]


# --- a run with no block writes the manifest of the base build ------------------------------


def test_a_run_with_no_block_writes_a_version_6_manifest_with_no_site_blocks_key(rig) -> None:
    """The base build refuses a parent of version 7 (`previous_link`)."""
    import json

    settings, _cycle = rig()
    capture = runs_exec.ExecutionCapture()
    capture.site_blocks = {}
    runs_exec.execute_cycle(settings, [_prepared(settings, "edge", "r1")], {"edge"}, capture=capture)
    raw = json.loads(manifest.path_for(settings, 2_000).read_text())
    assert raw["schema_version"] == 6 == manifest.SCHEMA_VERSION
    assert set(raw) == set(manifest.SnapshotManifest.model_fields) - {"site_blocks"}
    record = manifest.read(settings, 2_000)
    assert record.site_blocks == {}
    assert (
        manifest.canonical_json(record.model_dump(mode="json"))
        == manifest.path_for(settings, 2_000).read_bytes()
    )


def test_only_a_run_that_stamps_a_device_writes_version_7(rig) -> None:
    import json

    settings, _cycle = rig()
    capture = runs_exec.ExecutionCapture()
    capture.site_blocks = {"dev:r1": ("Uplink", "internet")}
    runs_exec.execute_cycle(settings, [_prepared(settings, "edge", "r1")], {"edge"}, capture=capture)
    raw = json.loads(manifest.path_for(settings, 2_000).read_text())
    assert raw["schema_version"] == manifest.SITE_BLOCKS_SCHEMA_VERSION == 7
    assert raw["site_blocks"] == {"dev:r1": ["Uplink", "internet"]}


# --- a block change is no network change -----------------------------------------------------


def _device_rows(zone: str | None) -> list[dict[str, Any]]:
    props: dict[str, Any] = {"uid": "dev:r1", "hostname": "r1", "_scope": "vyos:r1", "_sources": ["edge"]}
    if zone is not None:
        props.update(site_zone=zone, site_block="Uplink")
    return [{"uid": "dev:r1", "labels": ["Obj", "Device"], "props": props}]


def test_a_block_change_is_no_change_of_the_device_in_the_run_diff() -> None:
    from tests.test_diff_stream import _Graph
    from tests.test_diff_stream import _Session as _DiffSession

    from hst.core.diff import diff_snapshots

    graph = _Graph({1000: _device_rows(None), 2000: _device_rows("internet")}, {1000: [], 2000: []})
    out = diff_snapshots(_DiffSession(graph), 1000, 2000)
    assert out["counts"]["nodes"]["changed"] == 0
    graph = _Graph({1000: _device_rows("external"), 2000: _device_rows("internet")}, {1000: [], 2000: []})
    assert diff_snapshots(_DiffSession(graph), 1000, 2000)["counts"]["nodes"]["changed"] == 0


def test_a_block_change_is_no_observed_edit_in_the_semantic_stream(tmp_path, monkeypatch) -> None:
    from tests.test_assessment_semantic_cost import snapshot

    from hst import path
    from hst.assessment.semantic import read_snapshot_inputs, semantic_change_stream

    rows = {"1": _device_rows(None), "2": _device_rows("internet")}
    current = {"cts": "1"}

    def read(session: Any, query: str, **params: Any) -> list[dict[str, Any]]:
        if "type(r)" in query:
            return []
        return rows[current["cts"]][params["offset"] : params["offset"] + params["limit"]]

    monkeypatch.setattr(path, "_read", read)
    settings = SimpleNamespace(hst_data_dir=tmp_path)
    before = read_snapshot_inputs(None, snapshot("1"), settings)
    current["cts"] = "2"
    after = read_snapshot_inputs(None, snapshot("2"), settings)
    assert before["complete"] and after["complete"]
    assert semantic_change_stream(before, after)["changes"] == []


def test_a_run_whose_site_parameters_were_not_read_says_so_in_its_warnings(rig) -> None:
    settings, cycle = rig()
    capture = runs_exec.ExecutionCapture()
    capture.site_blocks = runs_exec._site_blocks(None)
    capture.site_blocks_warning = runs_exec.SITE_BLOCKS_UNREAD
    outcome = runs_exec.execute_cycle(
        settings, [_prepared(settings, "edge", "r1")], {"edge"}, capture=capture
    )
    assert cycle.stamped == [({}, 2_000)]
    assert f"warning: {runs_exec.SITE_BLOCKS_UNREAD}" in outcome.detail
    assert manifest.read(settings, 2_000).warnings.count(runs_exec.SITE_BLOCKS_UNREAD) == 1
