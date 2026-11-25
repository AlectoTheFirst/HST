"""The fixture load writes the HST map tables of its run, with the projection a collection run uses."""

from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any

import pytest

import hst.cli as cli
from hst.core import manifest
from hst.core.config import Settings


class FakeProjection:
    def __init__(self, calls: list[Any], tiers_ready: bool = True) -> None:
        self.calls = calls
        self.tiers_ready = tiers_ready
        self.failed = None if tiers_ready else "prepare: RuntimeError: boom"

    def observe(self, record: dict[str, Any]) -> None:
        self.calls.append(("observe", record))

    def prepare(self, session: Any, *, complete: bool = True) -> None:
        self.calls.append(("prepare", complete))

    def publish(self) -> dict[str, Any]:
        self.calls.append(("publish",))
        return {"tiers_ready": self.tiers_ready}


def _wire(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, projection: FakeProjection | None
) -> dict[str, Any]:
    """Every collaborator of the load replaced; the calls land in `seen["calls"]` in order."""
    settings = Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key="x" * 32)
    batch = SimpleNamespace(source="demo", scope="fixture:demo", nodes=[], rels=[])
    calls: list[Any] = projection.calls if projection is not None else []
    # `current` is the pointer: the load moves it to its own run, as the real one does
    seen: dict[str, Any] = {"calls": calls, "current": 1000, "begun": [], "discarded": []}

    @contextmanager
    def session(_settings: Any) -> Any:
        yield object()

    def projection_of(session: Any, settings: Any, cts: int, prev: int | None, kind: str) -> Any:
        seen["projection_args"] = (cts, prev, kind)
        return projection

    def graph_delta(session: Any, previous: int | None, cts: int, observer: Any = None) -> Any:
        calls.append(("delta", previous, cts))
        if observer is not None:
            observer({"kind": "node", "op": "added"})
        return manifest.GraphDelta(previous_snapshot=previous, sha256="e" * 64)

    monkeypatch.setattr(cli, "Settings", lambda: settings)
    monkeypatch.setattr(cli, "load_fixture", lambda path: batch)
    monkeypatch.setattr(cli.dbmod, "session", session)
    monkeypatch.setattr("hst.core.cycle.current_ts", lambda session: seen["current"])
    monkeypatch.setattr("hst.core.cycle.new_collection_ts", lambda: 1001)
    monkeypatch.setattr(
        "hst.core.cycle.begin_run",
        lambda session, cts, kind, parent: seen["begun"].append((cts, kind, parent)),
    )
    monkeypatch.setattr("hst.core.cycle.discard_run", lambda session, cts: seen["discarded"].append(cts))
    monkeypatch.setattr("hst.core.cycle.cycle_counts", lambda session, cts: {"nodes": 2, "rels": 1})
    monkeypatch.setattr("hst.core.cycle.write_cycle_meta", lambda session, cts, **kwargs: None)

    def set_pointer(session: Any, cts: int) -> None:
        calls.append(("pointer", cts))
        seen["current"] = cts

    monkeypatch.setattr("hst.core.cycle.set_pointer", set_pointer)
    monkeypatch.setattr(
        "hst.core.grapharchive.write",
        lambda *args, **kwargs: {
            "path": "graph-archives/1001.graph.enc",
            "sha256": "b" * 64,
            "bytes": 1,
            "snapshot_key": 1001,
            "format_version": 1,
            "graph_schema_version": 1,
            "chunks": 1,
            "nodes": 2,
            "rels": 1,
            "normalization_context": kwargs["normalization_context"],
            "normalization_context_sha256": "c" * 64,
        },
    )
    monkeypatch.setattr("hst.app.crypto.dek", lambda settings: "key")
    monkeypatch.setattr(cli, "load", lambda *args, **kwargs: SimpleNamespace(counts={}, errors=[]))
    monkeypatch.setattr(
        "hst.core.finalize.finalize_derivations", lambda session, settings, cts, sites, **kwargs: []
    )
    monkeypatch.setattr(manifest, "graph_delta", graph_delta)
    monkeypatch.setattr(manifest, "build", lambda **kwargs: seen.update(built=kwargs) or SimpleNamespace())
    monkeypatch.setattr(manifest, "write", lambda *args: "d" * 64)
    monkeypatch.setattr(manifest, "signer_for", lambda settings: None)
    monkeypatch.setattr(cli, "_print_manifest", lambda loaded: None)
    monkeypatch.setattr("hst.app.runs_exec._hst_projection", projection_of)
    return seen


def test_a_new_run_load_projects_its_tiers_against_the_run_published_before(monkeypatch, tmp_path):
    projection = FakeProjection([])
    seen = _wire(monkeypatch, tmp_path, projection)

    cli.load_fixture_cmd(tmp_path / "estate-v2.yaml", dry_run=False, new_run=True)

    assert seen["built"]["parent"] is None
    assert seen["projection_args"] == (1001, 1000, "full")
    assert seen["begun"] == [(1001, "full", None)]  # recorded before the first write
    assert seen["discarded"] == []  # the pointer names the run
    assert seen["calls"] == [
        ("delta", 1000, 1001),
        ("observe", {"kind": "node", "op": "added"}),
        ("prepare", True),
        ("pointer", 1001),
        ("publish",),
    ]


def test_the_first_load_bootstraps_the_tiers_without_a_parent(monkeypatch, tmp_path):
    projection = FakeProjection([])
    seen = _wire(monkeypatch, tmp_path, projection)
    seen["current"] = None

    cli.load_fixture_cmd(tmp_path / "estate-v1.yaml", dry_run=False, new_run=True)

    assert seen["projection_args"] == (1001, None, "full")
    assert [c[0] for c in seen["calls"]] == ["delta", "observe", "prepare", "pointer", "publish"]
    assert ("prepare", True) in seen["calls"]


def test_a_failed_projection_does_not_fail_the_load(monkeypatch, tmp_path, capsys):
    projection = FakeProjection([], tiers_ready=False)
    seen = _wire(monkeypatch, tmp_path, projection)

    cli.load_fixture_cmd(tmp_path / "estate-v3.yaml", dry_run=False, new_run=True)

    assert ("pointer", 1001) in seen["calls"]
    assert "map tables not written for snapshot 1001" in capsys.readouterr().out


def test_without_the_sidestore_extra_the_load_skips_the_projection(monkeypatch, tmp_path):
    seen = _wire(monkeypatch, tmp_path, None)

    cli.load_fixture_cmd(tmp_path / "estate-v1.yaml", dry_run=False, new_run=True)

    assert seen["calls"] == [("delta", 1000, 1001), ("pointer", 1001)]


def test_a_load_that_fails_before_the_pointer_moves_removes_the_run_it_began(monkeypatch, tmp_path):
    seen = _wire(monkeypatch, tmp_path, FakeProjection([]))

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("archive write failed")

    monkeypatch.setattr("hst.core.grapharchive.write", boom)

    with pytest.raises(RuntimeError, match="archive write failed"):
        cli.load_fixture_cmd(tmp_path / "estate-v1.yaml", dry_run=False, new_run=True)

    assert seen["begun"] == [(1001, "full", None)]
    assert seen["discarded"] == [1001]
    assert ("pointer", 1001) not in seen["calls"]
