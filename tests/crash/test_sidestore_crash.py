"""Crash injection: the process dies the instant `sidestore.write_table`
returns, before anything else about that run is
written: no manifest, no pointer move. The write is real and durable
(core/sidestore.py `_publish`), so the file survives the crash under its final
name; nothing else does.

A reader bound to a published snapshot never opens that file (no manifest
names it, and the manifest-driven reader opens the files a manifest lists),
and retention removes it once no graph-retained run protects it
(worker/maintenance.py `prune_sidestore`).

Uses the run rig from tests/test_manifest.py for the one run that does
publish, so there is a real manifest and a real pointer to be unaffected.
"""

# ruff: noqa: F811 -- the imported `rig` fixture is shadowed by design in the test signature

from __future__ import annotations

import contextlib
from types import SimpleNamespace

import pytest
from tests.app.fakes import FakeStore
from tests.crash.injectors import SimulatedCrash, crash_after
from tests.test_manifest import _HostCfg, _prepared, _RibCollector, rig  # noqa: F401  (pytest fixture)


async def test_a_crash_right_after_the_parquet_write_leaves_readers_unaffected_and_retention_removes_it(
    monkeypatch, rig
):
    pytest.importorskip("pyarrow")
    pytest.importorskip("duckdb")
    from hst.core import ribsource, sidestore
    from hst.core import snapshot as snapshotmod
    from hst.worker import maintenance

    settings, cycle = rig(keys=[2_000], rib_graph_max_routes=10)
    edge = _prepared(settings, "edge", "r1")
    edge.units[0].collector = _RibCollector(_HostCfg(host="r1", source_name="edge"), settings)

    from hst.app import runs_exec

    runs_exec.execute_cycle(settings, [edge], {"edge"})
    assert cycle.pointer == 2_000

    crash_after(monkeypatch, sidestore, "write_table")
    with pytest.raises(SimulatedCrash):
        sidestore.write_table(
            settings.sidestore_dir,
            "rib",
            "edge",
            "r1",
            "1700000099000-crash01",
            [{"device_uid": "dev:r1", "vrf": "default", "prefix": "10.9.0.0/16"}],
            snapshot_ts=3_000,
        )

    orphan = settings.sidestore_dir / "rib" / "edge" / "r1" / "1700000099000-crash01.parquet"
    assert orphan.is_file(), "the write itself must have completed and be durable"

    rib = ribsource.for_snapshot(snapshotmod.Snapshot(cycle.pointer, settings))
    assert rib.approximate is False
    assert rib.coverage("dev:r1") == "complete"

    published = settings.sidestore_dir / "rib" / "edge" / "r1"
    kept_files = set(published.glob("*.parquet")) - {orphan}
    assert kept_files, "the published run's own side-store file must exist to prove retention is selective"

    from hst.core import manifest as manifestmod

    for key in (2_000, 4_000):
        if not manifestmod.path_for(settings, key).exists():
            manifestmod.write(
                settings,
                manifestmod.SnapshotManifest(
                    snapshot_key=key,
                    kind="full",
                    opened=manifestmod.iso(key),
                    published=manifestmod.now_iso(),
                ),
            )

    retained = {2_000}
    monkeypatch.setattr(maintenance, "_session", lambda settings: contextlib.nullcontext(None))
    monkeypatch.setattr(maintenance, "cyclemod", SimpleNamespace(retained_runs=lambda s, keep: retained))
    assert await maintenance.prune_sidestore(settings, FakeStore(), keep=1) == []
    assert orphan.exists()

    retained = {4_000, 2_000}
    victims = await maintenance.prune_sidestore(settings, FakeStore(), keep=1)

    assert victims == [orphan]
    assert not orphan.exists()
    assert all(p.is_file() for p in kept_files)  # the graph-retained run's file survives
