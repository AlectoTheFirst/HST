"""The demo estate load: a `demo` run on a demo instance only, three published fixture runs under
the cycle lock, the demo sites and the five applications, and a second load that leaves the sites
and the application revisions as they are."""

from __future__ import annotations

import asyncio
import hashlib
import threading
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from tests.app.conftest import PASSWORD, login
from tests.app.fakes import FakeStore

import hst.app.runs_exec as runs_exec
from hst.app import demo_estate, fixture_runs
from hst.app.crypto import generate_key
from hst.app.main import create_app
from hst.app.security import hash_password
from hst.assessment.store import MemoryAssessmentStore
from hst.core import Settings

ROOT = Path(__file__).resolve().parents[2]
DEMO_DIR = ROOT / "fixtures" / "demo-enterprise"
SITE_CODES = {
    "dc1",
    "dc2",
    "eqx-fr5",
    "vie01",
    "waw01",
    "par01",
    "mad01",
    "zrh01",
    "lis01",
    "mil01",
    "osl01",
    "aws-eu-central-1",
    "az-gwc",
    "az-weu",
}


class DemoStore(MemoryAssessmentStore, FakeStore):
    """The run, site and application storage of the app under one fake."""


def _settings(tmp_path: Path, demo: Path | None) -> Settings:
    return Settings(
        _env_file=None,
        hst_secret_key=generate_key(),
        hst_data_dir=tmp_path,
        hst_demo_fixtures=demo,
    )


@pytest.fixture
async def store() -> DemoStore:
    store = DemoStore()
    for name, role in (("otto", "operator"), ("ada", "admin")):
        await store.create_user(name, hash_password(PASSWORD), role)
    return store


def _client_for(app: Any) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://t", headers={"X-HST-CSRF": "1"})


class Wired:
    """Every graph-side collaborator of the demo run replaced; what they were asked lands here."""

    def __init__(self) -> None:
        self.published: list[tuple[str, bool, int | None]] = []
        self.resolved: list[tuple[str, int, str]] = []
        self.loaders: list[Any] = []
        self.next_cts = 1000


def _wire(monkeypatch: pytest.MonkeyPatch) -> Wired:
    seen = Wired()

    @contextmanager
    def session(_settings: Any, **_kw: Any) -> Any:
        yield object()

    def publish(
        s: Any,
        settings: Any,
        batch: Any,
        path: Path,
        *,
        new_run: bool,
        fence: int | None = None,
        loader: Any = None,
    ):
        seen.next_cts += 1
        seen.published.append((path.name, new_run, fence))
        seen.loaders.append(loader)
        return fixture_runs.FixtureRun(
            cts=seen.next_cts,
            previous=seen.next_cts - 1,
            loaded=SimpleNamespace(),
            marker={"tiers_ready": True},
        )

    def resolve_graph(settings, definition, revision, reference, services, connections):
        seen.resolved.append((definition["id"], revision, reference["snapshot"]))
        key = f"{definition['id']}:{revision}:{reference['snapshot']}"
        return {"digest": hashlib.sha256(key.encode()).hexdigest(), "application_id": definition["id"]}

    monkeypatch.setattr(runs_exec.dbmod, "session", session)
    monkeypatch.setattr("hst.core.fixtures.load_fixture", lambda path: SimpleNamespace(source="fixture"))
    monkeypatch.setattr(fixture_runs, "publish", publish)
    monkeypatch.setattr(
        "hst.assessment.service.snapshot_reference", lambda settings, value: {"snapshot": value}
    )
    monkeypatch.setattr("hst.app.routes.business_applications._resolve_graph", resolve_graph)
    return seen


async def _wait_done(store: FakeStore, run_id: int) -> Any:
    for _ in range(500):
        run = next(r for r in await store.list_runs() if r.id == run_id)
        if run.status != "running":
            return run
        await asyncio.sleep(0.01)
    raise AssertionError("run never finished")


async def test_without_the_setting_there_is_no_demo_source(store, tmp_path):
    app = create_app(settings=_settings(tmp_path, None), store=store)
    async with _client_for(app) as client:
        await login(client, "ada")
        listing = (await client.get("/api/runs")).json()
        assert listing["demo"] is False
        assert "demo" not in listing["sources"]
        r = await client.post("/api/runs", json={"source": "demo"})
        assert r.status_code == 400 and "unknown source 'demo'" in r.json()["error"]
    # the guarantee below the route: launch starts nothing either
    assert await runs_exec.launch(store, _settings(tmp_path, None), "demo") is None
    assert await store.list_runs() == []


async def test_an_operator_cannot_load_the_demo_estate(store, tmp_path):
    app = create_app(settings=_settings(tmp_path, DEMO_DIR), store=store)
    async with _client_for(app) as client:
        await login(client, "otto")
        assert (await client.get("/api/runs")).json()["demo"] is True
        r = await client.post("/api/runs", json={"source": "demo"})
        assert r.status_code == 403
    assert await store.list_runs() == []


async def test_the_demo_run_publishes_three_runs_then_seeds_sites_and_applications(
    store, tmp_path, monkeypatch
):
    seen = _wire(monkeypatch)
    app = create_app(settings=_settings(tmp_path, DEMO_DIR), store=store)
    async with _client_for(app) as client:
        await login(client, "ada")
        r = await client.post("/api/runs", json={"source": "demo"})
        assert r.status_code == 202, r.text
        assert r.json()["source"] == "demo"
        run = await _wait_done(store, r.json()["id"])
        listing = (await client.get("/api/runs")).json()

    assert run.status == "ok", run.detail
    # three runs, in order, each from empty, under the fence of the cycle lock the run holds
    assert [(name, new_run) for name, new_run, _ in seen.published] == [
        ("estate-v1.yaml", True),
        ("estate-v2.yaml", True),
        ("estate-v3.yaml", True),
    ]
    assert all(isinstance(fence, int) for _, _, fence in seen.published)
    assert run.snapshot_key == "1003"
    assert "estate-v1 run 1001, estate-v2 run 1002, estate-v3 run 1003" in run.detail
    assert "map tables written for 3 of 3 runs" in run.detail
    # the sites, through the code POST /api/sites uses, with their map position
    sites = {s.code: s for s in await store.list_sites()}
    assert set(sites) == SITE_CODES
    assert sites["vie01"].params == {"lat": 48.2082, "lon": 16.3738}
    assert "sites: 14 created, 0 already present" in run.detail
    # the five applications, each resolved at the last of the three runs
    apps = {a.id: a.revision for a in await store.list_applications()}
    assert len(apps) == 5 and set(apps.values()) == {1}
    assert sorted(seen.resolved) == sorted((app_id, 1, "1003") for app_id in apps)
    assert "applications: 5 imported (5 new revisions), 5 resolved at run 1003" in run.detail
    # listed in the run history like any other run
    assert listing["runs"][0]["source"] == "demo" and listing["runs"][0]["status"] == "ok"
    # the FR5 internet routers' named blocks, written on the site the load created
    assert sites["eqx-fr5"].params["blocks"] == [
        {"name": "Internet edge", "zone": "internet", "devices": ["dev:fr5-inet-01"]},
        {"name": "Carrier edge", "zone": "external", "devices": ["dev:fr5-inet-02"]},
    ]


async def test_each_demo_run_stamps_the_zone_of_the_seeded_blocks_right_after_its_load(
    store, tmp_path, monkeypatch
):
    """The loader each publish is handed loads the batch and then stamps the blocks the run read
    after seeding the sites (contract A), on the run it is building."""
    seen = _wire(monkeypatch)
    admin = await store.get_user_by_username("ada")
    run = await runs_exec.run_blocking(store, _settings(tmp_path, DEMO_DIR), "demo", admin.id)
    assert run.status == "ok", run.detail
    assert len(seen.loaders) == 3
    stamped: list[tuple[dict[str, Any], int]] = []
    loaded: list[int] = []
    monkeypatch.setattr("hst.core.loader.load", lambda s, batch, **kw: loaded.append(kw["collection_ts"]))
    monkeypatch.setattr(
        runs_exec.cycle, "apply_site_blocks", lambda s, blocks, cts: stamped.append((dict(blocks), cts)) or 0
    )
    seen.loaders[0](object(), SimpleNamespace(), run_id="r", collection_ts=1001)
    assert loaded == [1001]
    assert stamped == [
        (
            {
                "dev:fr5-inet-01": ("Internet edge", "internet"),
                "dev:fr5-inet-02": ("Carrier edge", "external"),
            },
            1001,
        )
    ]


async def test_a_second_load_publishes_new_runs_and_keeps_sites_and_revisions(store, tmp_path, monkeypatch):
    seen = _wire(monkeypatch)
    settings = _settings(tmp_path, DEMO_DIR)
    admin = await store.get_user_by_username("ada")
    first = await runs_exec.run_blocking(store, settings, "demo", admin.id)
    await store.update_site(
        "vie01", name="Vienna HQ", location="Vienna, Austria", params={"lat": 1.0, "lon": 2.0}
    )
    second = await runs_exec.run_blocking(store, settings, "demo", admin.id)

    assert (first.status, second.status) == ("ok", "ok"), second.detail
    assert len(seen.published) == 6
    assert second.snapshot_key == "1006"
    assert "sites: 0 created, 14 already present" in second.detail
    # a site an operator changed is left as it is
    assert (await store.get_site("vie01")).name == "Vienna HQ"
    assert "applications: 5 imported (0 new revisions), 5 resolved at run 1006" in second.detail
    assert {a.revision for a in await store.list_applications()} == {1}


async def test_a_site_seeded_before_the_estate_had_blocks_gets_them_at_the_next_load(
    store, tmp_path, monkeypatch
):
    _wire(monkeypatch)
    settings = _settings(tmp_path, DEMO_DIR)
    admin = await store.get_user_by_username("ada")
    first = await runs_exec.run_blocking(store, settings, "demo", admin.id)
    fr5 = await store.get_site("eqx-fr5")
    seeded = fr5.params["blocks"]
    assert seeded
    await store.update_site("eqx-fr5", params={k: v for k, v in fr5.params.items() if k != "blocks"})
    assert "blocks" not in (await store.get_site("eqx-fr5")).params

    second = await runs_exec.run_blocking(store, settings, "demo", admin.id)

    assert (first.status, second.status) == ("ok", "ok"), second.detail
    assert "sites: 0 created, 14 already present (1 given their named blocks)" in second.detail
    assert (await store.get_site("eqx-fr5")).params["blocks"] == seeded

    own = [{"name": "Lab", "zone": "internal", "devices": ["dev:fr5-inet-01"]}]
    fr5 = await store.get_site("eqx-fr5")
    await store.update_site("eqx-fr5", params={**fr5.params, "blocks": own})
    third = await runs_exec.run_blocking(store, settings, "demo", admin.id)
    assert third.status == "ok", third.detail
    assert "given their named blocks" not in third.detail
    assert (await store.get_site("eqx-fr5")).params["blocks"] == own


async def test_applications_stored_with_the_removed_choice_scope_import_with_no_failure(
    store, tmp_path, monkeypatch
):
    from hst.applications.yaml_format import definition_digest, normalized_document, parse_application_yaml

    seen = _wire(monkeypatch)
    settings = _settings(tmp_path, DEMO_DIR)
    for _name, text in demo_estate.read(DEMO_DIR).apps:
        stored = normalized_document(parse_application_yaml(text))
        stored["connections"] = [{**item, "choice_scope": "unspecified"} for item in stored["connections"]]
        await store.create_application_revision(
            definition=stored, digest=definition_digest(stored), created_by=None, expected_revision=0
        )
    admin = await store.get_user_by_username("ada")
    first = await runs_exec.run_blocking(store, settings, "demo", admin.id)
    second = await runs_exec.run_blocking(store, settings, "demo", admin.id)

    assert first.status == "ok", first.detail
    assert "failed" not in first.detail and "ValidationError" not in first.detail
    assert "applications: 5 imported (5 new revisions), 5 resolved at run 1003" in first.detail
    assert "applications: 5 imported (0 new revisions), 5 resolved at run 1006" in second.detail
    assert {a.revision for a in await store.list_applications()} == {2}
    assert all(
        "choice_scope" not in connection
        for a in await store.list_applications()
        for connection in a.definition["connections"]
    )
    assert len(seen.resolved) == 10


async def test_a_folder_without_the_estate_fails_the_run_and_publishes_nothing(store, tmp_path, monkeypatch):
    seen = _wire(monkeypatch)
    empty = tmp_path / "demo"
    empty.mkdir()
    run = await runs_exec.run_blocking(store, _settings(tmp_path, empty), "demo", None)

    assert run.status == "error"
    assert "estate-v1.yaml" in run.detail and "sites.yaml" in run.detail
    assert seen.published == []
    assert await store.list_sites() == []


def test_a_stop_after_the_first_run_keeps_it_and_loads_no_further_file(tmp_path, monkeypatch):
    seen = _wire(monkeypatch)
    stop = threading.Event()
    real = fixture_runs.publish

    def publish_then_stop(*args: Any, **kwargs: Any) -> Any:
        out = real(*args, **kwargs)
        stop.set()
        return out

    monkeypatch.setattr(fixture_runs, "publish", publish_then_stop)
    runs = tuple(DEMO_DIR / name for name in demo_estate.RUN_FILES)
    outcome = runs_exec.execute_demo(_settings(tmp_path, DEMO_DIR), runs, fence=4, stop=stop)

    assert [name for name, _, _ in seen.published] == ["estate-v1.yaml"]
    assert outcome.snapshot_key == 1001
    assert "stopped before estate-v2, estate-v3" in outcome.detail


def test_a_stop_before_the_first_run_publishes_nothing(tmp_path, monkeypatch):
    seen = _wire(monkeypatch)
    stop = threading.Event()
    stop.set()
    runs = tuple(DEMO_DIR / name for name in demo_estate.RUN_FILES)
    with pytest.raises(RuntimeError):
        runs_exec.execute_demo(_settings(tmp_path, DEMO_DIR), runs, fence=4, stop=stop)
    assert seen.published == []


def test_the_bundled_estate_reads_as_three_runs_fourteen_sites_and_five_applications():
    estate = demo_estate.read(DEMO_DIR)
    assert [p.name for p in estate.runs] == ["estate-v1.yaml", "estate-v2.yaml", "estate-v3.yaml"]
    assert {s.code for s in estate.sites} == SITE_CODES
    assert len(estate.apps) == 5


def test_a_fenced_fixture_publish_moves_the_pointer_under_the_fence(tmp_path, monkeypatch):
    """`fixture_runs.publish` with a fence: the pointer refuses a run a later lock holder overtook."""
    pointer: list[tuple[int, int | None]] = []

    def set_pointer(session: Any, cts: int, fence: int | None = None) -> None:
        pointer.append((cts, fence))

    begun: list[tuple[int, str, int | None]] = []
    # the pointer names the new run once `set_pointer` has run
    monkeypatch.setattr("hst.core.cycle.current_ts", lambda session: pointer[-1][0] if pointer else 1000)
    monkeypatch.setattr("hst.core.cycle.new_collection_ts", lambda: 1001)
    monkeypatch.setattr(
        "hst.core.cycle.begin_run", lambda session, cts, kind, parent: begun.append((cts, kind, parent))
    )
    monkeypatch.setattr("hst.core.cycle.cycle_counts", lambda session, cts: {"nodes": 1, "rels": 0})
    monkeypatch.setattr("hst.core.cycle.write_cycle_meta", lambda session, cts, **kwargs: None)
    monkeypatch.setattr("hst.core.cycle.set_pointer", set_pointer)
    monkeypatch.setattr(
        "hst.core.finalize.finalize_derivations", lambda session, settings, cts, sites, **kwargs: []
    )
    monkeypatch.setattr("hst.app.crypto.dek", lambda settings: "key")
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
            "nodes": 1,
            "rels": 0,
            "normalization_context": kwargs["normalization_context"],
            "normalization_context_sha256": "c" * 64,
        },
    )
    from hst.core import manifest

    monkeypatch.setattr(manifest, "graph_delta", lambda *args: manifest.GraphDelta(previous_snapshot=1000))
    monkeypatch.setattr(manifest, "build", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(manifest, "write", lambda *args: "d" * 64)
    monkeypatch.setattr(manifest, "signer_for", lambda settings: None)
    monkeypatch.setattr(runs_exec, "_hst_projection", lambda *args: None)
    batch = SimpleNamespace(source="fixture", scope="fixture:estate", nodes=[], rels=[])

    out = fixture_runs.publish(
        object(),
        _settings(tmp_path, None),
        batch,
        tmp_path / "estate-v1.yaml",
        new_run=True,
        fence=7,
        loader=lambda *args, **kwargs: SimpleNamespace(),
    )

    assert pointer == [(1001, 7)]
    assert begun == [(1001, "full", None)]  # recorded before the first write
    assert (out.cts, out.previous, out.marker) == (1001, 1000, None)


async def test_a_queued_demo_job_runs_for_an_admin_and_is_skipped_for_an_operator(
    store, tmp_path, monkeypatch
):
    """RUN_EXECUTION=queue: the route queues a `collect.run` job, and the worker checks the account
    again when it claims the job, as it does for any run."""
    from hst.worker import collect, runtime
    from hst.worker.executor import Executor

    monkeypatch.setattr(runs_exec, "_RUNS", {})
    seen = _wire(monkeypatch)
    settings = _settings(tmp_path, DEMO_DIR).model_copy(update={"run_execution": "queue"})
    app = create_app(settings=settings, store=store)
    async with _client_for(app) as client:
        await login(client, "ada")
        r = await client.post("/api/runs", json={"source": "demo"})
        assert r.status_code == 202 and r.json()["status"] == "queued"
    executor = Executor(store, settings, bodies=runtime.bodies(), name="worker-under-test")
    await executor.poll()
    await executor.drain()
    (run,) = await store.list_runs()
    assert (run.source, run.status) == ("demo", "ok"), run.detail
    assert len(seen.published) == 3

    # one pending job per source: the operator's job is queued once the admin's has finished
    otto = await store.get_user_by_username("otto")
    refused = await collect.enqueue_run(store, "demo", otto.id)
    assert refused is not None
    await executor.poll()
    await executor.drain()
    assert store.jobs[refused.id].detail == "skipped: loading the demo estate needs the admin role"
    assert len(await store.list_runs()) == 1
    assert len(seen.published) == 3
