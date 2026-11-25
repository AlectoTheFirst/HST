"""Triggering runs: role gate, source validation, the lock, and completion."""

import asyncio
from contextlib import asynccontextmanager

import httpx
import pytest
from cryptography.fernet import Fernet
from tests.app.conftest import PASSWORD, login
from tests.app.fakes import FakeStore

import hst.app.runs_exec as runs_exec
from hst.app.crypto import dek, encrypt_secrets, generate_key
from hst.app.main import create_app
from hst.app.security import hash_password
from hst.core import Settings


@pytest.fixture
async def with_sources(seeded):
    await seeded.create_source("unifi", "unifi", {}, b"")
    await seeded.create_source("vyos", "vyos", {}, b"")
    await seeded.create_source("paused", "manual", {"devices": ""}, b"", enabled=False)
    return seeded


async def _wait_done(store, run_id, give_up_after=2.0):
    for _ in range(int(give_up_after / 0.01)):
        run = next(r for r in await store.list_runs() if r.id == run_id)
        if run.status != "running":
            return run
        await asyncio.sleep(0.01)
    raise AssertionError("run never finished")


async def test_viewer_cannot_trigger(client, with_sources):
    await login(client, "vera")
    r = await client.post("/api/runs", json={"source": "unifi"})
    assert r.status_code == 403


async def test_unknown_source_is_400_and_lists_options(client, with_sources):
    await login(client, "otto")
    r = await client.post("/api/runs", json={"source": "cisco"})
    assert r.status_code == 400
    assert "reasoner" in r.json()["error"] and "unifi" in r.json()["error"]


async def test_negative_limit_is_422(client):
    await login(client, "otto")
    r = await client.get("/api/runs", params={"limit": -1})
    assert r.status_code == 422
    assert "error" in r.json() and "detail" not in r.json()


async def test_disabled_source_is_409(client, with_sources):
    await login(client, "otto")
    r = await client.post("/api/runs", json={"source": "paused"})
    assert r.status_code == 409 and "disabled" in r.json()["error"]


async def test_launch_itself_refuses_a_disabled_source(with_sources, monkeypatch):
    executed = []
    monkeypatch.setattr(
        runs_exec, "execute_source", lambda settings, source, row: executed.append(source) or ("ok", None)
    )
    run = await runs_exec.launch(with_sources, Settings(_env_file=None), "paused")
    assert run is None
    assert executed == []
    assert await with_sources.list_runs() == []


def _stub_prepare(monkeypatch, secrets: dict[str, str] | None = None):
    """Cycle model: source triggers resolve every enabled source up front and
    then run execute_cycle. Tests stub the resolution (no real crypto or
    collector construction) and the cycle itself."""

    async def fake_prepare(store, settings):
        rows = [r for r in await store.list_sources() if r.enabled]
        return [runs_exec.PreparedSource(r, [], None) for r in rows], (secrets or {})

    monkeypatch.setattr(runs_exec, "_prepare_all", fake_prepare)


async def test_run_executes_and_records_summary(client, with_sources, monkeypatch):
    _stub_prepare(monkeypatch)

    def fake_refresh(settings, prepared, name, assigned=None, **kw):
        return runs_exec.RunOutcome(f"{name} done", [], 7000)

    monkeypatch.setattr(runs_exec, "execute_refresh", fake_refresh)
    await login(client, "otto")
    r = await client.post("/api/runs", json={"source": "unifi"})
    assert r.status_code == 202
    run = await _wait_done(with_sources, r.json()["id"])
    assert (run.status, run.detail) == ("ok", "unifi done")
    listing = (await client.get("/api/runs")).json()
    assert listing["sources"] == ["unifi", "vyos", "reasoner", "cycle", "device-run"]
    assert run.snapshot_key == "7000"
    assert listing["runs"][0]["status"] == "ok"


async def test_failure_recorded_as_error(client, with_sources, monkeypatch):
    def boom(settings, prepared, name, assigned=None, **kw):
        raise RuntimeError("ssh unreachable")

    _stub_prepare(monkeypatch)
    monkeypatch.setattr(runs_exec, "execute_refresh", boom)
    await login(client, "otto")
    r = await client.post("/api/runs", json={"source": "vyos"})
    run = await _wait_done(with_sources, r.json()["id"])
    assert run.status == "error" and "ssh unreachable" in run.detail


async def test_concurrent_same_source_is_409(client, with_sources, monkeypatch):
    def slow(settings, prepared, name, assigned=None, **kw):
        import time

        time.sleep(0.2)
        return runs_exec.RunOutcome("ok", [], 7000)

    _stub_prepare(monkeypatch)
    monkeypatch.setattr(runs_exec, "execute_refresh", slow)
    await login(client, "otto")
    first = await client.post("/api/runs", json={"source": "unifi"})
    assert first.status_code == 202
    second = await client.post("/api/runs", json={"source": "unifi"})
    assert second.status_code == 409
    await _wait_done(with_sources, first.json()["id"])


async def test_finish_run_failure_is_loud_not_silent(client, with_sources, monkeypatch, caplog):
    _stub_prepare(monkeypatch)
    monkeypatch.setattr(
        runs_exec,
        "execute_refresh",
        lambda settings, prepared, name, assigned=None, **kw: runs_exec.RunOutcome("ok", [], 7000),
    )

    async def boom_finish(run_id, status, finished_at, detail):
        raise RuntimeError("pg down")

    monkeypatch.setattr(with_sources, "finish_run", boom_finish)
    await login(client, "otto")
    r = await client.post("/api/runs", json={"source": "unifi"})
    assert r.status_code == 202
    run_id = r.json()["id"]

    for _ in range(20):
        await asyncio.sleep(0.01)

    run = next(r for r in await with_sources.list_runs() if r.id == run_id)
    assert run.status == "running"

    listing = await client.get("/api/runs")
    assert listing.status_code == 200

    assert "finish_run failed" in caplog.text


async def test_run_failure_detail_is_redacted(monkeypatch):
    settings = Settings(_env_file=None, hst_secret_key=generate_key())
    key = dek(settings)
    store = FakeStore()
    await store.create_user("otto", hash_password(PASSWORD), "operator")
    await store.create_source(
        "home-unifi", "unifi", {"url": "https://c"}, encrypt_secrets(key, {"password": "pw1"})
    )

    app = create_app(settings=settings, store=store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://t", headers={"X-HST-CSRF": "1"}
    ) as client:
        await login(client, "otto")

        def boom(settings, prepared, name, assigned=None, **kw):
            raise RuntimeError("auth pw1 rejected")

        # the redaction map comes from the up-front resolution; the stub
        # supplies the same secret the detail leaks
        async def fake_prepare(prep_store, prep_settings):
            rows = [r for r in await prep_store.list_sources() if r.enabled]
            return [runs_exec.PreparedSource(r, [], None) for r in rows], {"password": "pw1"}

        monkeypatch.setattr(runs_exec, "_prepare_all", fake_prepare)
        monkeypatch.setattr(runs_exec, "execute_refresh", boom)

        r = await client.post("/api/runs", json={"source": "home-unifi"})
        assert r.status_code == 202
        run = await _wait_done(store, r.json()["id"])
        assert run.status == "error"
        assert "***" in run.detail
        assert "pw1" not in run.detail


async def test_resolver_failure_fails_the_run_before_executing(monkeypatch):
    store = FakeStore()
    await store.create_user("otto", hash_password(PASSWORD), "operator")
    # sealed under a data key the app under test never had: its own DEK cannot open it
    await store.create_source(
        "home-unifi",
        "unifi",
        {"url": "https://c"},
        encrypt_secrets(Fernet.generate_key().decode(), {"password": "pw1"}),
    )

    executed = []
    monkeypatch.setattr(runs_exec, "execute_source", lambda settings, source, row: executed.append(source))

    app = create_app(settings=Settings(_env_file=None, hst_secret_key=generate_key()), store=store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://t", headers={"X-HST-CSRF": "1"}
    ) as client:
        await login(client, "otto")
        r = await client.post("/api/runs", json={"source": "home-unifi"})
        assert r.status_code == 202
        run = await _wait_done(store, r.json()["id"])
    assert run.status == "error"
    assert "SecretKeyError" in run.detail
    assert executed == []


async def test_first_contact_pins_the_observed_host_key(store):
    """A row with no pinned key records the one the device presented."""
    row = await store.create_source("r1", "nxos", {"host": "10.0.0.1", "host_key": ""}, b"")

    class FakeCollector:
        observed_host_key = "ssh-ed25519 OBSERVED"

    await runs_exec.pin_host_key(store, row, FakeCollector())
    assert (await store.get_source("r1")).config["host_key"] == "ssh-ed25519 OBSERVED"


async def test_an_already_pinned_key_is_not_rewritten(store):
    row = await store.create_source("r2", "nxos", {"host": "10.0.0.2", "host_key": "ssh-ed25519 PINNED"}, b"")

    class FakeCollector:
        observed_host_key = "ssh-ed25519 OBSERVED"

    await runs_exec.pin_host_key(store, row, FakeCollector())
    assert (await store.get_source("r2")).config["host_key"] == "ssh-ed25519 PINNED"


async def test_a_collector_without_host_keys_is_left_alone(store):
    row = await store.create_source("r3", "apic", {"url": "https://apic"}, b"")
    await runs_exec.pin_host_key(store, row, object())
    assert "host_key" not in (await store.get_source("r3")).config


async def test_first_contact_pins_the_bastion_key_too(store):
    row = await store.create_source(
        "r4",
        "nxos",
        {"host": "10.0.0.4", "host_key": "", "jump_host": {"host": "b", "port": 22, "host_key": ""}},
        b"",
    )

    class FakeCollector:
        observed_host_key = "ssh-ed25519 DEV"
        observed_jump_key = "ssh-ed25519 BAST"

    await runs_exec.pin_host_key(store, row, FakeCollector())
    config = (await store.get_source("r4")).config
    assert config["host_key"] == "ssh-ed25519 DEV"
    assert config["jump_host"]["host_key"] == "ssh-ed25519 BAST"


async def test_pinning_rereads_the_row_and_writes_no_stale_snapshot(store):
    row = await store.create_source("r5", "nxos", {"host": "10.0.0.5", "host_key": ""}, b"")
    await store.update_source("r5", config={"host": "10.9.9.9", "host_key": ""})

    class FakeCollector:
        observed_host_key = "ssh-ed25519 OBSERVED"

    await runs_exec.pin_host_key(store, row, FakeCollector())
    config = (await store.get_source("r5")).config
    assert config["host"] == "10.9.9.9"  # the PATCH survives
    assert config["host_key"] == "ssh-ed25519 OBSERVED"


async def test_the_test_button_pins_on_first_contact(client, with_sources, monkeypatch):
    import hst.app.routes.sources as sources_routes

    class FakeCollector:
        observed_host_key = "ssh-ed25519 OBSERVED"
        observed_jump_key = ""

        def probe(self):
            return "ok"

    monkeypatch.setattr(
        sources_routes.glue, "build_collector", lambda row, settings, **kwargs: FakeCollector()
    )
    await login(client, "otto")
    r = await client.post("/api/sources/vyos/test")
    assert r.json()["ok"] is True
    assert (await with_sources.get_source("vyos")).config["host_key"] == "ssh-ed25519 OBSERVED"


async def test_a_triggered_run_records_who_asked_for_it(client, seeded):
    await login(client, "otto")
    otto = await seeded.get_user_by_username("otto")
    r = await client.post("/api/runs", json={"source": "reasoner"})
    assert r.status_code == 202
    assert r.json()["triggered_by"] == otto.id

    history = (await client.get("/api/runs")).json()["runs"]
    assert history[0]["triggered_by"] == otto.id


# --- graph purge ---------------------------------------------------------------


class _FakeGraphSession:
    """Records queries; answers the count probe as a driver session does."""

    def __init__(self, nodes=42):
        self.nodes = nodes
        self.queries = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, **params):
        self.queries.append(query)

        class _Result:
            def single(_self):
                return {"c": self.nodes}

        return _Result()


async def test_a_launch_that_fails_before_its_task_exists_finishes_the_row_and_frees_the_source(
    with_sources, monkeypatch, tmp_path
):
    _stub_prepare(monkeypatch)
    settings = Settings(_env_file=None, hst_data_dir=tmp_path)

    async def refuse(store, prepared, run_id):
        raise RuntimeError("registry unreachable")

    monkeypatch.setattr(runs_exec, "_arm_identity", refuse)
    with pytest.raises(RuntimeError):
        await runs_exec.launch(with_sources, settings, "unifi")
    row = (await with_sources.list_runs())[0]
    assert (row.status, row.detail) == ("error", "RuntimeError: registry unreachable")
    assert await with_sources.running_run("unifi") is None

    monkeypatch.undo()
    _stub_prepare(monkeypatch)
    monkeypatch.setattr(
        runs_exec, "execute_refresh", lambda *a, **kw: runs_exec.RunOutcome("unifi done", [], 7000)
    )
    run = await runs_exec.launch(with_sources, settings, "unifi")
    assert run is not None
    assert (await _wait_done(with_sources, run.id)).status == "ok"


async def test_a_launch_that_is_cancelled_before_its_task_exists_records_the_cancel(
    with_sources, monkeypatch, tmp_path
):
    _stub_prepare(monkeypatch)
    settings = Settings(_env_file=None, hst_data_dir=tmp_path)

    async def cancelled(store, prepared, run_id):
        raise asyncio.CancelledError

    monkeypatch.setattr(runs_exec, "_arm_identity", cancelled)
    with pytest.raises(asyncio.CancelledError):
        await runs_exec.launch(with_sources, settings, "unifi")
    row = (await with_sources.list_runs())[0]
    assert (row.status, row.detail) == ("cancelled", "cancelled")
    assert await with_sources.running_run("unifi") is None


async def test_a_failed_device_record_after_the_publish_keeps_the_run_ok_and_records_the_rest(
    with_sources, monkeypatch, tmp_path, caplog
):
    import logging
    from types import SimpleNamespace

    _stub_prepare(monkeypatch)
    settings = Settings(_env_file=None, hst_data_dir=tmp_path)
    rows = {row.name: row for row in await with_sources.list_sources()}

    def collector(uid):
        return SimpleNamespace(last_device_uids=[uid], last_device_locations={})

    ran = [(rows["unifi"], None, collector("dev:u")), (rows["vyos"], None, collector("dev:v"))]
    monkeypatch.setattr(
        runs_exec, "execute_refresh", lambda *a, **kw: runs_exec.RunOutcome("unifi done", ran, 7000)
    )
    recorded: list[str] = []
    record = with_sources.record_target_devices

    async def flaky(source, host, uids, locations):
        if source == "unifi":
            raise ConnectionError("postgres went away")
        recorded.append(source)
        return await record(source, host, uids, locations)

    monkeypatch.setattr(with_sources, "record_target_devices", flaky)
    with caplog.at_level(logging.ERROR, logger=runs_exec.logger.name):
        run = await runs_exec.launch(with_sources, settings, "unifi")
        finished = await _wait_done(with_sources, run.id)
    assert (finished.status, finished.detail, finished.snapshot_key) == ("ok", "unifi done", "7000")
    assert recorded == ["vyos"]
    assert "run 7000: the devices of unifi  were not recorded:" in caplog.text


async def test_purge_graph_is_admin_only(client, monkeypatch):
    import hst.app.routes.runs as runs_routes

    fake = _FakeGraphSession()
    monkeypatch.setattr(runs_routes, "_session", lambda settings: fake)
    await login(client, "otto")
    assert (await client.post("/api/graph/purge")).status_code == 403
    assert fake.queries == []


async def test_purge_graph_deletes_everything_and_reports_the_count(client, monkeypatch):
    import hst.app.routes.runs as runs_routes

    fake = _FakeGraphSession(nodes=17)
    monkeypatch.setattr(runs_routes, "_session", lambda settings: fake)
    await login(client, "ada")
    r = await client.post("/api/graph/purge")
    assert r.status_code == 200
    assert r.json() == {"deleted_nodes": 17}
    assert any("DETACH DELETE" in q and "IN TRANSACTIONS" in q for q in fake.queries)


async def test_purge_graph_refuses_while_a_collection_runs(client, seeded, monkeypatch):
    import datetime

    import hst.app.routes.runs as runs_routes

    fake = _FakeGraphSession()
    monkeypatch.setattr(runs_routes, "_session", lambda settings: fake)
    await seeded.start_run("vyos", datetime.datetime.now(datetime.UTC))
    await login(client, "ada")
    r = await client.post("/api/graph/purge")
    assert r.status_code == 409
    assert fake.queries == []


async def test_purge_graph_refuses_while_the_cycle_lock_is_held(client, seeded, monkeypatch):
    import hst.app.routes.runs as runs_routes

    fake = _FakeGraphSession()
    monkeypatch.setattr(runs_routes, "_session", lambda settings: fake)
    await login(client, "ada")
    async with seeded.cycle_lock():
        r = await client.post("/api/graph/purge")
    assert r.status_code == 409
    assert r.json()["error"] == "a collection or a prune holds the cycle lock"
    assert fake.queries == []


async def test_purge_graph_holds_the_cycle_lock_for_the_delete(client, seeded, monkeypatch):
    import hst.app.routes.runs as runs_routes

    held: list[bool] = []

    class Watched(_FakeGraphSession):
        def run(self, query, **kwargs):
            held.append(seeded._cycle_lock.locked())
            return super().run(query, **kwargs)

    monkeypatch.setattr(runs_routes, "_session", lambda settings: Watched(nodes=2))
    await login(client, "ada")
    assert (await client.post("/api/graph/purge")).status_code == 200
    assert held and all(held)
    assert not seeded._cycle_lock.locked()


async def test_a_cycle_and_a_refresh_cannot_overlap_across_processes(with_sources, monkeypatch):
    _stub_prepare(monkeypatch)
    inside: list[str] = []

    def watch(name):
        def run(settings, prepared, *args, **kwargs):
            inside.append(name)
            return runs_exec.RunOutcome(f"{name} done", [], 7000)

        return run

    monkeypatch.setattr(runs_exec, "execute_cycle", watch("cycle"))
    monkeypatch.setattr(runs_exec, "execute_refresh", watch("refresh"))

    order: list[str] = []
    real_lock = with_sources.cycle_lock

    @asynccontextmanager
    async def traced(**kwargs):
        order.append("acquired")
        async with real_lock(**kwargs) as fence:
            yield fence
        order.append("released")

    with_sources.cycle_lock = traced

    settings = Settings(_env_file=None)
    for source in ("cycle", "unifi"):
        run = await runs_exec.launch(with_sources, settings, source)
        await _wait_done(with_sources, run.id)

    assert inside == ["cycle", "refresh"]
    assert order == ["acquired", "released", "acquired", "released"]


async def test_the_reasoner_does_not_take_the_cycle_lock(with_sources, monkeypatch):
    monkeypatch.setattr(runs_exec, "execute_source", lambda settings, source, row: ("ok", None))

    taken = []
    real_lock = with_sources.cycle_lock

    @asynccontextmanager
    async def traced(**kwargs):
        taken.append(True)
        async with real_lock(**kwargs) as fence:
            yield fence

    with_sources.cycle_lock = traced

    run = await runs_exec.launch(with_sources, Settings(_env_file=None), "reasoner")
    assert (await _wait_done(with_sources, run.id)).status == "ok"
    assert taken == []


# --- cancel (runs_exec.cancel_run) --------------------------------------------------------


async def test_a_running_run_is_cancelled_and_finishes_as_such(client, with_sources, monkeypatch):
    """The builder blocks until its stop flag is raised, the way a long VCO
    poll does between requests; the cancel raises it, the thread ends, and the
    row finishes as `cancelled` with nothing published."""
    import threading

    stopped = threading.Event()

    def blocking(settings, prepared, name, assigned=None, *, stop=None, **kw):
        assert stop is not None
        assert stop.wait(5), "the stop flag was never raised"
        stopped.set()
        raise RuntimeError("stopped at a phase boundary")

    _stub_prepare(monkeypatch)
    monkeypatch.setattr(runs_exec, "execute_refresh", blocking)
    await login(client, "otto")
    r = await client.post("/api/runs", json={"source": "unifi"})
    run_id = r.json()["id"]
    r = await client.post(f"/api/runs/{run_id}/cancel")
    assert r.status_code == 200
    assert r.json() == {"id": run_id, "status": "cancelled"}
    run = await _wait_done(with_sources, run_id)
    assert run.status == "cancelled"
    assert "otto" in run.detail
    assert run.snapshot_key is None
    assert stopped.is_set()
    # a second cancel finds nothing running
    r = await client.post(f"/api/runs/{run_id}/cancel")
    assert r.status_code == 404


async def test_one_source_of_a_cycle_is_cancelled_without_ending_the_run(client, with_sources, monkeypatch):
    import threading

    armed = threading.Event()
    flags: dict[str, threading.Event] = {}

    def blocking(settings, prepared, name, assigned=None, *, stop=None, **kw):
        assert isinstance(stop, runs_exec.RunStop)
        for source in ("nxos-edge", "vco"):
            flags[source] = stop.for_source(source)
        armed.set()
        assert flags["nxos-edge"].wait(5), "the source's flag was never raised"
        raise RuntimeError("stopped at a phase boundary")

    _stub_prepare(monkeypatch)
    monkeypatch.setattr(runs_exec, "execute_refresh", blocking)
    await login(client, "otto")
    run_id = (await client.post("/api/runs", json={"source": "unifi"})).json()["id"]
    assert armed.wait(5)
    r = await client.post(f"/api/runs/{run_id}/cancel", json={"source": "nxos-edge"})
    assert r.status_code == 200
    assert r.json() == {"id": run_id, "source": "nxos-edge", "status": "cancelled"}
    assert flags["nxos-edge"].is_set()
    assert not flags["vco"].is_set(), "the other source was stopped too"
    await _wait_done(with_sources, run_id)


async def test_cancelling_a_source_the_run_is_not_collecting_is_404(client, with_sources, monkeypatch):
    import threading

    armed = threading.Event()

    def blocking(settings, prepared, name, assigned=None, *, stop=None, **kw):
        stop.for_source("nxos-edge")
        armed.set()
        assert stop.wait(5)
        raise RuntimeError("stopped at a phase boundary")

    _stub_prepare(monkeypatch)
    monkeypatch.setattr(runs_exec, "execute_refresh", blocking)
    await login(client, "otto")
    run_id = (await client.post("/api/runs", json={"source": "unifi"})).json()["id"]
    assert armed.wait(5)
    r = await client.post(f"/api/runs/{run_id}/cancel", json={"source": "not-a-source"})
    assert r.status_code == 404
    assert "is not collecting not-a-source" in r.json()["error"]
    await client.post(f"/api/runs/{run_id}/cancel")
    await _wait_done(with_sources, run_id)


async def test_cancelling_an_unknown_run_is_404(client):
    await login(client, "otto")
    r = await client.post("/api/runs/999999/cancel")
    assert r.status_code == 404
    assert "not running on this instance" in r.json()["error"]


async def test_a_viewer_cannot_cancel(client):
    await login(client, "vera")
    r = await client.post("/api/runs/1/cancel")
    assert r.status_code == 403


# --- HTTP traces (collectors/http_trace.py) --------------------------------------------


async def test_http_traces_are_listed_and_downloaded_decrypted(app, client, tmp_path):
    from hst.collectors import http_trace
    from hst.core import rawstore

    settings = app.state.settings
    settings.hst_data_dir = tmp_path
    settings.hst_http_trace = "vco-1"
    key = dek(settings)
    raw_path = rawstore.write(settings.raw_dir, "vco-1", "1790000000000-abcdef12", {"x": 1}, key=key)
    trace = http_trace.HttpTrace("vco-1", settings.raw_dir)
    trace.record({"ts": 1, "method": "POST", "url": "https://vco/portal/rest/edge/getEdge", "status": 400})
    trace.seal(raw_path, key)

    await login(client, "otto")
    r = await client.get("/api/runs/http-traces")
    assert r.status_code == 200
    body = r.json()
    assert body["enabled"] == "vco-1"
    assert body["traces"] == [
        {
            "source": "vco-1",
            "host": "",
            "run_id": "1790000000000-abcdef12",
            "fetch_ts_ms": 1790000000000,
            "size": rawstore.trace_path(raw_path).stat().st_size,
        }
    ]

    r = await client.get("/api/runs/http-traces/1790000000000-abcdef12", params={"source": "vco-1"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/x-ndjson")
    assert r.headers["content-disposition"] == 'attachment; filename="1790000000000-abcdef12.http.jsonl"'
    [line] = r.text.splitlines()
    assert '"status": 400' in line and "getEdge" in line


async def test_a_trace_outside_the_raw_store_or_absent_is_404(app, client, tmp_path):
    settings = app.state.settings
    settings.hst_data_dir = tmp_path
    await login(client, "otto")
    r = await client.get("/api/runs/http-traces/1790000000000-abcdef12", params={"source": "vco-1"})
    assert r.status_code == 404
    escape = {"source": "..", "host": ".."}
    r = await client.get("/api/runs/http-traces/1790000000000-abcdef12", params=escape)
    assert r.status_code == 404


async def test_a_viewer_cannot_read_http_traces(client):
    await login(client, "vera")
    r = await client.get("/api/runs/http-traces")
    assert r.status_code == 403
