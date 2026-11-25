"""Live progress belongs to its run, and ETA describes the current phase."""

from datetime import UTC, datetime, timedelta

from tests.app.conftest import login

from hst.core.collection_progress import CollectionProgress, read_progress
from hst.core.config import Settings


def test_progress_eta_and_completed_fetch_are_distinct_from_run_completion(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr("hst.core.collection_progress.time.monotonic", lambda: clock[0])
    settings = Settings(_env_file=None)
    progress = CollectionProgress(settings, "vco")
    progress.phase("Collecting detailed paths", 100)
    assert read_progress(settings, source="vco", since_ms=0)[0]["phase_eta_s"] is None
    clock[0] += 10
    progress.advance(20)
    row = read_progress(settings, source="vco", since_ms=0)[0]
    assert (row["completed"], row["phase_eta_s"]) == (20, 40)
    progress.finish(True)
    assert read_progress(settings, source="vco", since_ms=0)[0]["state"] == "collected"
    assert read_progress(settings, source="vco", since_ms=row["started_at_ms"] + 1) == []
    assert read_progress(settings, source="other", since_ms=0) == []


async def test_runs_endpoint_exposes_current_progress_and_excludes_old_records(client, app, seeded):
    await login(client, "otto")
    now = datetime.now(UTC)
    settings = app.state.settings
    stale = CollectionProgress(settings, "old-vco")
    stale.phase("Discovering peers", 1000)
    stale.data["started_at_ms"] = int((now - timedelta(hours=1)).timestamp() * 1000)
    stale.write(force=True)
    await seeded.start_run("old-vco", now)
    run = await seeded.start_run("vco", now - timedelta(seconds=1))
    progress = CollectionProgress(settings, "vco")
    progress.phase("Collecting detailed paths", 500, enterprise_index=2, enterprise_total=3)
    response = await client.get("/api/runs")
    rows = {row["source"]: row for row in response.json()["runs"]}
    assert rows["vco"]["progress"][0]["total"] == 500
    assert "progress" not in rows["old-vco"]
    await seeded.finish_run(run.id, "ok", datetime.now(UTC), "finished")
    rows = {row["source"]: row for row in (await client.get("/api/runs")).json()["runs"]}
    assert "progress" not in rows["vco"]


async def test_cycle_progress_includes_each_current_source(client, app, seeded):
    await login(client, "otto")
    await seeded.start_run("cycle", datetime.now(UTC) - timedelta(seconds=1))
    for name in ("vco-a", "vco-b"):
        progress = CollectionProgress(app.state.settings, name)
        progress.phase("Discovering peers", 500)
    rows = (await client.get("/api/runs")).json()["runs"]
    assert [p["source"] for p in rows[0]["progress"]] == ["vco-a", "vco-b"]


async def test_scheduled_fetch_job_exposes_progress(client, app, seeded):
    await login(client, "otto")
    now = datetime.now(UTC) - timedelta(seconds=1)
    await seeded.enqueue_job(
        "collect.fetch",
        source="vco",
        device="",
        not_before=now,
        max_attempts=1,
        triggered_by="scheduler",
        now=now,
    )
    await seeded.claim_jobs("worker", 1, now, timedelta(minutes=5))
    progress = CollectionProgress(app.state.settings, "vco")
    progress.phase("Collecting detailed paths", 900)
    response = await client.get("/api/jobs")
    assert response.json()["jobs"][0]["progress"][0]["total"] == 900


def test_malformed_progress_is_advisory_and_ignored():
    settings = Settings(_env_file=None)
    progress = CollectionProgress(settings, "vco")
    progress.phase("Discovering peers")
    progress.path.write_text("interrupted write")
    assert read_progress(settings, source="vco", since_ms=0) == []


# --- every source reports, not only the one collector that reports itself ----


class _Unit:
    """The shape `FleetProgress` reads off a prepared unit."""

    def __init__(self, collector: object = None) -> None:
        self.collector = collector


class _OwnProgress:
    reports_progress = True


def test_a_fleet_progress_opens_one_bar_per_source():
    settings = Settings(_env_file=None)
    units = [("nxos-edge", _Unit()), ("nxos-edge", _Unit()), ("iosxe-core", _Unit())]
    from hst.app.runs_exec import FleetProgress

    FleetProgress(settings, units)
    rows = {r["source"]: r for r in read_progress(settings, source=None, since_ms=0)}
    assert rows["nxos-edge"]["total"] == 2
    assert rows["iosxe-core"]["total"] == 1
    assert rows["nxos-edge"]["phase"] == "Fetching devices"


def test_a_collector_that_reports_its_own_progress_keeps_it():
    settings = Settings(_env_file=None)
    from hst.app.runs_exec import FleetProgress

    FleetProgress(settings, [("vco", _Unit(_OwnProgress())), ("nxos", _Unit())])
    assert {r["source"] for r in read_progress(settings, source=None, since_ms=0)} == {"nxos"}


def test_each_answered_device_advances_its_own_source():
    """One count per source, and one source's devices never touch another's.

    A record is written at most once a second (`CollectionProgress.write`), and
    the page polls every five, so an intermediate count inside that second is
    not on disk. The last one always is: `advance` forces the write when the
    count reaches the total.
    """
    settings = Settings(_env_file=None)
    from hst.app.runs_exec import FleetProgress

    progress = FleetProgress(settings, [("a", _Unit()), ("a", _Unit()), ("b", _Unit())])
    for _ in range(2):
        progress.advance("a")
    progress.advance("b")
    rows = {r["source"]: r for r in read_progress(settings, source=None, since_ms=0)}
    assert (rows["a"]["completed"], rows["a"]["total"]) == (2, 2)
    assert (rows["b"]["completed"], rows["b"]["total"]) == (1, 1)
    assert rows["a"]["state"] == "collecting"


def test_the_fetch_ending_closes_every_bar():
    """A record left reading `collecting` draws a bar for a fetch that ended,
    and the runs endpoint cannot tell that from one still running."""
    settings = Settings(_env_file=None)
    from hst.app.runs_exec import FleetProgress

    FleetProgress(settings, [("a", _Unit()), ("b", _Unit())]).finish_all()
    assert {r["state"] for r in read_progress(settings, source=None, since_ms=0)} == {"collected"}


def test_advancing_a_source_with_no_bar_is_harmless():
    settings = Settings(_env_file=None)
    from hst.app.runs_exec import FleetProgress

    FleetProgress(settings, []).advance("nobody")
