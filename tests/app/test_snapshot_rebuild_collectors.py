"""POST /api/snapshots/{key}/rebuild builds each source's collector with
every site and every source row, as the cycle builds it: a group that
inherits its routing scope from its site replays under that scope, and a
collector that links another source finds it (tests/test_replay_callers.py
covers the CLI's replays)."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any

from tests.app.conftest import login

import hst.app.routes.snapshots as snapshots_route
from hst.app import sources as glue
from hst.core import db as dbmod
from hst.core import replay


async def test_the_rebuild_builds_each_collector_with_the_sites_and_the_source_rows(
    client, app, monkeypatch, tmp_path
):
    await login(client, "ada")
    store = app.state.store
    await store.create_site("hq", "Head office", "")
    await store.create_source("edge", "unifi", {"site_code": "hq"}, b"")
    await store.create_source("mgmt", "unifi", {}, b"")
    app.state.settings = app.state.settings.model_copy(update={"hst_data_dir": tmp_path})

    @contextmanager
    def session(settings: Any) -> Any:
        yield object()

    built: list[tuple[str, dict[str, Any]]] = []

    def build_collector(row: Any, settings: Any, resolver: Any = None, **kw: Any) -> Any:
        built.append((row.name, kw))
        return object()

    def fake_rebuild(settings: Any, target: Any, key: int, **kw: Any) -> Any:
        assert kw["source_for"]("edge") is not None
        assert kw["source_for"]("gone") is None
        return replay.ManifestRebuildReport(snapshot_key=key)

    monkeypatch.setattr(snapshots_route, "_session", session)
    monkeypatch.setattr(dbmod, "_resolve", lambda host: ["10.9.9.9"] if host == "scratch" else ["127.0.0.1"])
    monkeypatch.setattr(glue, "build_collector", build_collector)
    monkeypatch.setattr(replay, "rebuild_from_manifest", fake_rebuild)

    r = await client.post("/api/snapshots/1000/rebuild", json={"into": "bolt://scratch:7999"})

    assert r.status_code == 200, r.text
    ((name, kw),) = built
    assert name == "edge"
    assert list(kw["sites"]) == ["hq"]
    assert sorted(kw["sources"]) == ["edge", "mgmt"]
