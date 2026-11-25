"""Run listing (/api/snapshots), date resolution (/api/snapshots/resolve), diff
(/api/diff), manifest replay (/api/snapshots/{key}/rebuild) and the tracer's
snapshot mode under the cycle model, Neo4j faked at the module seams."""

from contextlib import contextmanager
from typing import Any

import pytest
from tests.app.conftest import login

import hst.app.routes.path as path_route
import hst.app.routes.snapshots as snapshots_route
from hst.core import db as dbmod
from hst.core import diff as diffmod
from hst.core import manifest as manifestmod
from hst.core import replay as replaymod
from hst.core import snapshot as snapshotmod

TRACE = {"verdict": "ok", "notes": [], "hops": [], "legs": []}
CYCLES = [
    {
        "id": "2000",
        "ts_ms": 2000,
        "created": "1970-01-01T00:00:02+00:00",
        "nodes": 5,
        "rels": 4,
        "sources_fresh": ["vyos"],
        "sources_carried": ["unifi"],
        "sources_failed": [],
        "degraded": False,
    },
    {
        "id": "1000",
        "ts_ms": 1000,
        "created": "1970-01-01T00:00:01+00:00",
        "nodes": 5,
        "rels": 4,
        "sources_fresh": ["unifi", "vyos"],
        "sources_carried": [],
        "sources_failed": [],
        "degraded": False,
    },
]


class _FakeGraphSession:
    """Answers the three read shapes the snapshot routes use: the pointer
    (session.run), the run listing and the diff existence check
    (execute_read)."""

    def run(self, query: str, **params: Any):
        rows: list[dict] = [{"current": 2000}] if "CyclePointer" in query else []

        class _Result:
            def data(self) -> list:
                return rows

        return _Result()

    def execute_read(self, work: Any, *args: Any) -> Any:
        return work(_FakeTx(), *args)


class _FakeTx:
    def run(self, query: str, **params: Any):
        if query == snapshotmod._RETAINED_GRAPH:
            # the run-existence check a named snapshot passes before the trace
            rows = [{"uid": "dev:a"}] if params["snap"] in (1000, 2000) else []
        elif "MATCH (c:CycleRun) WHERE c.cts IN" in query:
            rows = [{"cts": v} for v in (params["a"], params["b"]) if v in (1000, 2000)]
        elif "CycleRun" in query:
            rows = [dict(c, id=int(c["id"])) for c in CYCLES]
        else:
            rows = []

        class _Result:
            def data(self) -> list:
                return rows

        return _Result()


@contextmanager
def _fake_session_cm(settings):
    yield _FakeGraphSession()


async def test_snapshots_requires_auth(client):
    assert (await client.get("/api/snapshots")).status_code == 401


async def test_snapshots_lists_the_runs_and_the_pointer(client, monkeypatch):
    await login(client, "vera")
    monkeypatch.setattr(snapshots_route, "_session", _fake_session_cm)
    r = await client.get("/api/snapshots")
    assert r.status_code == 200
    body = r.json()
    assert body["current"] == 2000
    assert [s["id"] for s in body["snapshots"]] == ["2000", "1000"]
    assert body["snapshots"][0]["sources_carried"] == ["unifi"]


async def test_no_run_listing_offers_a_run_that_is_being_built(client, monkeypatch):
    """A build records its run before its first write (`cycle.begin_run`), so the listing, the
    date resolution and the diff's existence check leave a BUILDING run out."""
    from hst.core import cycle as cyclemod

    await login(client, "vera")
    seen: list[str] = []

    class _Recording(_FakeTx):
        def run(self, query: str, **params: Any):
            seen.append(query)
            return super().run(query, **params)

    class _Session(_FakeGraphSession):
        def execute_read(self, work: Any, *args: Any) -> Any:
            return work(_Recording(), *args)

    @contextmanager
    def session_cm(settings):
        yield _Session()

    monkeypatch.setattr(snapshots_route, "_session", session_cm)
    monkeypatch.setattr(snapshots_route, "request_diff", lambda *a, **k: {})
    assert (await client.get("/api/snapshots")).status_code == 200
    assert (await client.get("/api/diff", params={"a": "1000", "b": "2000"})).status_code == 200

    listed = [q for q in seen if "CycleRun" in q]
    assert len(listed) == 2
    assert all("coalesce(c.state, 'built') <> 'building'" in q for q in listed)
    assert "coalesce(c.state, 'built') <> 'building'" in snapshots_route._RESOLVE_AT
    assert "coalesce(c.state, 'built') <> 'building'" in cyclemod.LIST_CYCLES


async def test_diff_404_for_an_unknown_run(client, monkeypatch):
    await login(client, "vera")
    monkeypatch.setattr(snapshots_route, "_session", _fake_session_cm)
    r = await client.get("/api/diff", params={"a": "1000", "b": "9999"})
    assert r.status_code == 404
    assert "9999" in r.json()["error"]


async def test_diff_rejects_a_non_numeric_run_id(client, monkeypatch):
    await login(client, "vera")
    monkeypatch.setattr(snapshots_route, "_session", _fake_session_cm)
    r = await client.get("/api/diff", params={"a": "latest", "b": "2000"})
    assert r.status_code == 400


async def test_diff_compares_two_known_runs(client, monkeypatch):
    await login(client, "vera")
    monkeypatch.setattr(snapshots_route, "_session", _fake_session_cm)
    seen = {}

    def fake_diff(session, a, b, *, devices_b=None):
        seen.update(a=a, b=b, devices_b=devices_b)
        return {"a": a, "b": b, "counts": {}}

    monkeypatch.setattr(snapshots_route, "request_diff", fake_diff)
    r = await client.get("/api/diff", params={"a": "1000", "b": "2000"})
    assert r.status_code == 200
    assert r.json() == {"a": 1000, "b": 2000, "counts": {}}
    # the B side's device entries travel with the comparison; the fake settings
    # of this rig have no manifests directory, so there are none to pass
    assert seen == {"a": 1000, "b": 2000, "devices_b": []}


async def test_diff_past_its_timeout_answers_504(client, monkeypatch):
    await login(client, "vera")
    monkeypatch.setattr(snapshots_route, "_session", _fake_session_cm)

    def slow(session, a, b, *, devices_b=None):
        raise snapshots_route.DiffTimeout("comparing runs 1000 and 2000 took longer than 120 s")

    monkeypatch.setattr(snapshots_route, "request_diff", slow)
    r = await client.get("/api/diff", params={"a": "1000", "b": "2000"})
    assert r.status_code == 504
    assert "took longer than 120 s" in r.json()["error"]


async def test_path_pins_the_default_trace_to_the_pointer(client, monkeypatch):
    await login(client, "vera")
    monkeypatch.setattr(path_route, "_session", _fake_session_cm)
    seen = {}

    def fake_trace(
        session, src, dst, *, port=None, proto="tcp", rib=None, src_context=None, dst_context=None
    ):
        seen.update(cts=getattr(session, "cts", None), as_of=getattr(rib, "_as_of_ms", None))
        return TRACE

    monkeypatch.setattr(path_route.pathmod, "trace", fake_trace)
    r = await client.get("/api/path", params={"src": "10.0.0.1", "dst": "8.8.8.8"})
    assert r.status_code == 200 and r.json() == {**TRACE, "run": None}
    assert seen == {"cts": 2000, "as_of": 2000}


async def test_path_snapshot_pins_the_trace_to_that_run(client, monkeypatch):
    await login(client, "vera")
    monkeypatch.setattr(path_route, "_session", _fake_session_cm)
    seen = {}

    def fake_trace(
        session, src, dst, *, port=None, proto="tcp", rib=None, src_context=None, dst_context=None
    ):
        seen.update(cts=getattr(session, "cts", None), as_of=getattr(rib, "_as_of_ms", None))
        return TRACE

    monkeypatch.setattr(path_route.pathmod, "trace", fake_trace)
    r = await client.get("/api/path", params={"src": "10.0.0.1", "dst": "8.8.8.8", "snapshot": "1000"})
    assert r.status_code == 200 and r.json() == {**TRACE, "run": None}
    assert seen == {"cts": 1000, "as_of": 1000}


async def test_path_snapshot_b_alone_compares_against_the_current_run(client, monkeypatch):
    """The composer sends only snapshot_b when the A side stays on "current",
    so the A side resolves to the pointer's run."""
    await login(client, "vera")
    monkeypatch.setattr(path_route, "_session", _fake_session_cm)
    calls = []

    def fake_trace(session, src, dst, **kw):
        calls.append(session.cts)
        return TRACE

    monkeypatch.setattr(path_route.pathmod, "trace", fake_trace)
    r = await client.get("/api/path", params={"src": "10.0.0.1", "dst": "8.8.8.8", "snapshot_b": "1000"})
    assert r.status_code == 200
    body = r.json()
    assert body["a"]["snapshot"] == "2000"  # the fake pointer's current run
    assert body["b"]["snapshot"] == "1000"
    assert calls == [2000, 1000]


async def test_path_snapshot_must_be_a_run_id(client, monkeypatch):
    await login(client, "vera")
    monkeypatch.setattr(path_route, "_session", _fake_session_cm)
    r = await client.get("/api/path", params={"src": "10.0.0.1", "dst": "8.8.8.8", "snapshot": "latest"})
    assert r.status_code == 400


async def test_path_compare_returns_both_run_traces(client, monkeypatch):
    await login(client, "vera")
    monkeypatch.setattr(path_route, "_session", _fake_session_cm)
    calls = []

    def fake_trace(session, src, dst, **kw):
        calls.append(session.cts)
        return {**TRACE, "cts": session.cts}

    monkeypatch.setattr(path_route.pathmod, "trace", fake_trace)
    r = await client.get(
        "/api/path",
        params={"src": "10.0.0.1", "dst": "8.8.8.8", "snapshot": "1000", "snapshot_b": "2000"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["a"] == {"snapshot": "1000", "result": {**TRACE, "cts": 1000, "run": None}}
    assert body["b"] == {"snapshot": "2000", "result": {**TRACE, "cts": 2000, "run": None}}
    assert calls == [1000, 2000]


# --- date resolution, removal records and manifest replay -------------------------------

# Two committed runs. The pointer names 2000, so nothing above it resolves.
RESOLVE_RUNS = (
    {"cts": 1000, "kind": "full", "created": "1970-01-01T00:00:01+00:00"},
    {"cts": 2000, "kind": "partial", "created": "1970-01-01T00:00:02+00:00"},
)


class _Rows:
    def __init__(self, rows: list[dict]) -> None:
        self._rows = rows

    def data(self) -> list[dict]:
        return self._rows


class _RunsTx:
    """The resolve query (newest run at or before a bound) and the diff's
    existence check, answered off `RESOLVE_RUNS`."""

    def run(self, query: str, **params: Any):
        if "c.cts <= $bound" in query:
            older = [r for r in RESOLVE_RUNS if r["cts"] <= params["bound"]]
            return _Rows(sorted(older, key=lambda r: r["cts"], reverse=True)[:1])
        if "MATCH (c:CycleRun) WHERE c.cts IN" in query:
            known = {r["cts"] for r in RESOLVE_RUNS}
            return _Rows([{"cts": v} for v in (params["a"], params["b"]) if v in known])
        return _Rows([])


class _RunsSession:
    def run(self, query: str, **params: Any):
        return _Rows([{"current": 2000}] if "CyclePointer" in query else [])

    def execute_read(self, work: Any, *args: Any) -> Any:
        return work(_RunsTx(), *args)


@contextmanager
def _runs_session_cm(settings):
    yield _RunsSession()


def _data_dir(app, tmp_path):
    """Point the app's settings at a scratch data directory, so a manifest
    written by a test is the one the route reads."""
    app.state.settings = app.state.settings.model_copy(update={"hst_data_dir": tmp_path})
    return app.state.settings


def _device(source: str, host: str, outcome: str, **kw: Any) -> manifestmod.DeviceEntry:
    return manifestmod.DeviceEntry(source=source, host=host, outcome=outcome, **kw)


def _publish_manifest(settings, key: int, devices, published="1970-01-01T00:00:03+00:00"):
    record = manifestmod.SnapshotManifest(
        snapshot_key=key,
        kind="full",
        opened=manifestmod.iso(key),
        published=published,
        devices=list(devices),
    )
    manifestmod.write(settings, record)
    return record


async def test_resolve_returns_the_run_that_was_current_at_the_instant(client, app, monkeypatch, tmp_path):
    """An instant between two runs resolves to the earlier one: the run that
    was answering for the estate at that moment, with the observation times of
    each of its devices."""
    await login(client, "vera")
    settings = _data_dir(app, tmp_path)
    monkeypatch.setattr(snapshots_route, "_session", _runs_session_cm)
    _publish_manifest(
        settings,
        1000,
        [
            _device(
                "edge",
                "r1",
                "collected",
                effective_run="900-abc12345",
                fetch_ts_ms=900,
                fetch_started_ms=900,
                fetch_finished_ms=950,
                ingested_ms=980,
            )
        ],
    )

    r = await client.get("/api/snapshots/resolve", params={"at": "1970-01-01T00:00:01.500Z"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["snapshot"] == "1000"
    assert body["kind"] == "full"
    assert body["opened"] == "1970-01-01T00:00:01+00:00"
    assert body["published"] == "1970-01-01T00:00:03+00:00"
    assert body["approximate"] is False
    assert body["devices"] == [
        {
            "source": "edge",
            "host": "r1",
            "outcome": "collected",
            "effective_run": "900-abc12345",
            "carried": False,
            "fetch_ts_ms": 900,
            "fetch_started_ms": 900,
            "fetch_finished_ms": 950,
            "ingested_ms": 980,
        }
    ]


async def test_resolve_never_goes_past_the_pointer(client, app, monkeypatch, tmp_path):
    """An instant after the newest run resolves to the pointer's run: a run the
    pointer has not moved to is not committed, and today is not a snapshot."""
    await login(client, "vera")
    _data_dir(app, tmp_path)
    monkeypatch.setattr(snapshots_route, "_session", _runs_session_cm)
    r = await client.get("/api/snapshots/resolve", params={"at": "2026-09-05T12:00:00Z"})
    assert r.status_code == 200
    assert r.json()["snapshot"] == "2000"


async def test_resolve_reports_a_run_with_no_manifest_as_approximate(client, app, monkeypatch, tmp_path):
    """No manifest governs run 2000 here, so there are no observation times to
    report and none are invented."""
    await login(client, "vera")
    _data_dir(app, tmp_path)
    monkeypatch.setattr(snapshots_route, "_session", _runs_session_cm)
    r = await client.get("/api/snapshots/resolve", params={"at": "1970-01-01T00:00:02Z"})
    assert r.status_code == 200
    body = r.json()
    assert body["snapshot"] == "2000"
    assert body["approximate"] is True
    assert body["published"] is None
    assert body["devices"] == []


async def test_resolve_404s_when_nothing_is_committed_that_early(client, app, monkeypatch, tmp_path):
    await login(client, "vera")
    _data_dir(app, tmp_path)
    monkeypatch.setattr(snapshots_route, "_session", _runs_session_cm)
    r = await client.get("/api/snapshots/resolve", params={"at": "1970-01-01T00:00:00.500Z"})
    assert r.status_code == 404
    assert "at or before" in r.json()["error"]


async def test_resolve_rejects_an_instant_it_cannot_read(client, monkeypatch):
    await login(client, "vera")
    monkeypatch.setattr(snapshots_route, "_session", _runs_session_cm)
    r = await client.get("/api/snapshots/resolve", params={"at": "last tuesday"})
    assert r.status_code == 400
    assert "ISO-8601" in r.json()["error"]


def _node(uid: str, label: str, props: dict) -> dict:
    return {"uid": uid, "labels": [label, "Obj"], "props": props}


class _DiffTx(_RunsTx):
    """The node read `core/diff.py` issues, answered off a per-run map. No
    relationship type and no domain-less node exists in either run."""

    def __init__(self, nodes: dict[int, list[dict]]) -> None:
        self._nodes = nodes

    def run(self, query: str, **params: Any):
        rows = self._nodes.get(params.get("snap"), [])
        if query == diffmod._ALL_NODES:
            return _Rows(rows)
        return super().run(query, **params)


def _diff_session_cm(nodes: dict[int, list[dict]]):
    class _DiffSession(_RunsSession):
        def execute_read(self, work: Any, *args: Any) -> Any:
            return work(_DiffTx(nodes), *args)

    @contextmanager
    def cm(settings):
        yield _DiffSession()

    return cm


REMOVED_IN_A = {
    1000: [
        _node(
            "dev:r1",
            "Device",
            {"name": "r1", "_scope": "vyos:r1", "_sources": ["edge"], "collected_at": 900},
        )
    ],
    2000: [],
}


async def test_the_diff_carries_both_disappearance_times_on_a_removal(client, app, monkeypatch, tmp_path):
    await login(client, "vera")
    settings = _data_dir(app, tmp_path)
    _publish_manifest(
        settings,
        2000,
        [_device("edge", "r1", "collected", fetch_ts_ms=1900, fetch_started_ms=1950)],
    )
    monkeypatch.setattr(snapshots_route, "_session", _diff_session_cm(REMOVED_IN_A))

    r = await client.get("/api/diff", params={"a": "1000", "b": "2000"})
    assert r.status_code == 200, r.text
    assert r.json()["nodes"]["removed"] == [
        {
            "uid": "dev:r1",
            "label": "Device",
            "name": "r1",
            "last_seen": 900,
            "absence_detected": 1950,
            "device": {"source": "edge", "host": "r1", "outcome": "collected"},
            "status": "removed",
        }
    ]


@pytest.mark.parametrize("outcome", ["failed", "carried"])
async def test_a_removal_under_a_device_that_did_not_answer_reads_unknown(
    client, app, monkeypatch, tmp_path, outcome
):
    """A device that failed, or a source that did not run at all, answered for
    nothing: its objects' absence is a gap in the collection, not a removal."""
    await login(client, "vera")
    settings = _data_dir(app, tmp_path)
    _publish_manifest(settings, 2000, [_device("edge", "r1", outcome, fetch_started_ms=1950)])
    monkeypatch.setattr(snapshots_route, "_session", _diff_session_cm(REMOVED_IN_A))

    r = await client.get("/api/diff", params={"a": "1000", "b": "2000"})
    assert r.status_code == 200, r.text
    record = r.json()["nodes"]["removed"][0]
    assert record["status"] == "unknown"
    assert record["device"] == {"source": "edge", "host": "r1", "outcome": outcome}
    assert (record["last_seen"], record["absence_detected"]) == (900, 1950)


async def test_a_removal_with_no_owning_device_states_the_absence_and_nothing_more(
    client, app, monkeypatch, tmp_path
):
    await login(client, "vera")
    settings = _data_dir(app, tmp_path)
    _publish_manifest(settings, 2000, [_device("border", "r9", "failed", fetch_started_ms=1950)])
    monkeypatch.setattr(snapshots_route, "_session", _diff_session_cm(REMOVED_IN_A))

    r = await client.get("/api/diff", params={"a": "1000", "b": "2000"})
    record = r.json()["nodes"]["removed"][0]
    assert record["status"] == "removed"
    assert record["device"] is None
    assert (record["last_seen"], record["absence_detected"]) == (900, None)


# --- the freshness surface: what the run says about each device -------------------------


class _StatusTx(_RunsTx):
    """`_RunsTx` plus the run meta node `run_status` reads, so the current
    run's status and its per-device freshness can be asked for."""

    def run(self, query: str, **params: Any):
        if "MATCH (c:CycleRun {uid: $uid})" in query:
            return _Rows(
                [
                    {
                        "cts": 2000,
                        "created": "1970-01-01T00:00:02+00:00",
                        "degraded": True,
                        "sources_carried": [],
                        "sources_failed": ["edge"],
                        "sources_partial": [],
                    }
                ]
            )
        return super().run(query, **params)


class _StatusSession(_RunsSession):
    def run(self, query: str, **params: Any):
        if "CyclePointer" in query:
            return _Rows([{"current": 2000}])
        return _StatusTx().run(query, **params)

    def execute_read(self, work: Any, *args: Any) -> Any:
        return work(_StatusTx(), *args)


@contextmanager
def _status_session_cm(settings):
    yield _StatusSession()


async def test_run_status_reports_per_table_age_and_carried_reason(client, app, monkeypatch, tmp_path):
    await login(client, "vera")
    settings = _data_dir(app, tmp_path)
    monkeypatch.setattr(snapshots_route, "_session", _status_session_cm)
    _publish_manifest(
        settings,
        2000,
        [
            _device(
                "edge",
                "r1",
                "unchanged",
                fetch_started_ms=1900,
                tables={
                    "arp": manifestmod.TableOutcome(status="complete", row_count=4, observed_ms=1900),
                    "rib": manifestmod.TableOutcome(status="unchanged", observed_ms=1400),
                },
            ),
            # a device this run could not collect: it stands on run 900's
            # payload and reads unknown from the moment the fetch failed
            _device("edge", "r2", "failed", fetch_ts_ms=900, effective_run="900-abc12345", carried=True),
        ],
    )

    r = await client.get("/api/snapshots")
    assert r.status_code == 200, r.text
    run = r.json()["run"]
    assert run["snapshot"] == "2000"
    assert run["freshness"]["truncated"] is False and run["freshness"]["approximate"] is False
    r1, r2 = run["freshness"]["devices"]

    assert r1["host"] == "r1"
    assert r1["carried_reason"] == "unchanged"
    assert r1["last_seen"] == 1900
    # age against the run key, not against the clock
    assert r1["tables"]["arp"] == {"status": "complete", "observed_ms": 1900, "age_ms": 100}
    assert r1["tables"]["rib"] == {"status": "unchanged", "observed_ms": 1400, "age_ms": 600}

    assert r2["host"] == "r2"
    assert r2["carried_reason"] == "failed"
    assert r2["last_seen"] == 900  # "unknown since" is measured from here
    assert r2["tables"] == {}


async def test_a_partial_device_reports_its_carried_reason_as_section_failed(
    client, app, monkeypatch, tmp_path
):
    await login(client, "vera")
    settings = _data_dir(app, tmp_path)
    monkeypatch.setattr(snapshots_route, "_session", _status_session_cm)
    _publish_manifest(settings, 2000, [_device("edge", "r1", "partial", fetch_started_ms=1950)])

    r = await client.get("/api/snapshots")
    (device,) = r.json()["run"]["freshness"]["devices"]
    assert device["carried_reason"] == "section-failed"
    assert device["last_seen"] == 1950


async def test_run_status_says_nothing_per_device_for_a_run_with_no_manifest(
    client, app, monkeypatch, tmp_path
):
    await login(client, "vera")
    _data_dir(app, tmp_path)
    monkeypatch.setattr(snapshots_route, "_session", _status_session_cm)

    r = await client.get("/api/snapshots")
    assert r.json()["run"]["freshness"] == {"devices": [], "truncated": False, "approximate": True}


SCRATCH = "bolt://scratch:7999"


@pytest.fixture
def resolver(monkeypatch):
    """Name resolution of `core/db.py` from a table. `scratch` is the rebuild target."""
    table = {"localhost": ["127.0.0.1", "::1"], "scratch": ["10.9.9.9"]}
    monkeypatch.setattr(dbmod, "_resolve", lambda host: table.get(host, []))
    return table


@pytest.mark.parametrize("username", ["vera", "otto"])
async def test_rebuild_is_refused_for_a_viewer_and_an_operator(client, resolver, username):
    await login(client, username)
    r = await client.post("/api/snapshots/1000/rebuild", json={"into": SCRATCH})
    assert r.status_code == 403


async def test_rebuild_requires_a_target(client):
    await login(client, "ada")
    r = await client.post("/api/snapshots/1000/rebuild", json={})
    assert r.status_code == 400
    assert "into is required" in r.json()["error"]


async def test_rebuild_refuses_the_configured_graph(client, app):
    await login(client, "ada")
    r = await client.post("/api/snapshots/1000/rebuild", json={"into": app.state.settings.neo4j_uri})
    assert r.status_code == 400
    assert "scratch" in r.json()["error"]


@pytest.mark.parametrize(
    "into",
    [
        "bolt://172.18.0.3:7687",
        "bolt://neo4j.:7687",
        "bolt://hst-neo4j-1:7687",
        "neo4j://[::ffff:172.18.0.3]",
    ],
)
async def test_rebuild_refuses_another_name_of_the_configured_graph(client, app, resolver, into):
    await login(client, "ada")
    app.state.settings = app.state.settings.model_copy(update={"neo4j_uri": "bolt://neo4j:7687"})
    resolver.update(
        {
            "neo4j": ["172.18.0.3"],
            "hst-neo4j-1": ["172.18.0.3"],
            "172.18.0.3": ["172.18.0.3"],
            "::ffff:172.18.0.3": ["::ffff:172.18.0.3"],
        }
    )
    r = await client.post("/api/snapshots/1000/rebuild", json={"into": into})
    assert r.status_code == 400
    assert "is the configured graph" in r.json()["error"]


async def test_rebuild_refuses_a_target_that_does_not_resolve(client, resolver):
    await login(client, "ada")
    r = await client.post("/api/snapshots/1000/rebuild", json={"into": "bolt://nowhere:7999"})
    assert r.status_code == 400
    assert "does not resolve" in r.json()["error"]


async def test_rebuild_refuses_every_target_while_the_configured_graph_does_not_resolve(
    client, app, resolver
):
    await login(client, "ada")
    app.state.settings = app.state.settings.model_copy(update={"neo4j_uri": "bolt://gone:7687"})
    r = await client.post("/api/snapshots/1000/rebuild", json={"into": SCRATCH})
    assert r.status_code == 503


async def test_rebuild_replays_the_manifest_into_a_scratch_target(
    client, app, monkeypatch, tmp_path, resolver
):
    """The endpoint is `rebuild_from_manifest` with a scratch graph target and a
    scratch side-store directory under the data directory, never the estate's
    own side store."""
    await login(client, "ada")
    _data_dir(app, tmp_path)
    opened: list[str] = []
    closed: list[str] = []

    @contextmanager
    def capturing_session(settings):
        opened.append(settings.neo4j_uri)
        yield _FakeGraphSession()

    monkeypatch.setattr(snapshots_route, "_session", capturing_session)
    monkeypatch.setattr(dbmod, "close_driver", lambda settings: closed.append(settings.neo4j_uri))
    seen: dict[str, Any] = {}

    def fake_rebuild(settings, target, key, **kw):
        seen.update(key=key, **kw)
        return replaymod.ManifestRebuildReport(
            snapshot_key=key, replayed=[_device("edge", "r1", "collected")], cleared=7
        )

    monkeypatch.setattr(replaymod, "rebuild_from_manifest", fake_rebuild)
    r = await client.post(
        "/api/snapshots/1000/rebuild",
        json={"into": SCRATCH, "allow_config_drift": True},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["snapshot"] == "1000"
    assert body["into"] == SCRATCH
    assert body["replayed"] == ["edge/r1"]
    assert body["cleared"] == 7
    assert body["ok"] is True
    assert seen["key"] == 1000
    assert seen["allow_config_drift"] is True
    assert seen["dry_run"] is False
    assert seen["sidestore_scratch_dir"] == tmp_path / "replay" / "1000"
    # the graph target is the scratch URI the caller named, not the configured one
    assert opened == [SCRATCH]
    assert closed == [SCRATCH]


async def test_rebuild_404s_for_a_snapshot_that_publishes_no_manifest(
    client, app, monkeypatch, tmp_path, resolver
):
    await login(client, "ada")
    _data_dir(app, tmp_path)
    monkeypatch.setattr(snapshots_route, "_session", _fake_session_cm)
    closed: list[str] = []
    monkeypatch.setattr(dbmod, "close_driver", lambda settings: closed.append(settings.neo4j_uri))
    r = await client.post("/api/snapshots/1000/rebuild", json={"into": SCRATCH})
    assert r.status_code == 404
    assert "no manifest" in r.json()["error"]
    assert closed == [SCRATCH]


# --- one snapshot resolved per request, enforced over the source ------------------------

# The readers: every HTTP route, the agent's tools, the shared
# Cypher runner behind both, the CLI and the MCP server.
READER_SOURCES = (
    "app/routes/*.py",
    "app/agent/tools.py",
    "app/agent/readers.py",
    "app/ai/*.py",
    "app/tables.py",
    "cli.py",
    "mcp_server.py",
    "twin_tools/*.py",
)


def _reader_files():
    import pathlib

    import hst

    root = pathlib.Path(hst.__file__).parent
    files = sorted({py for pattern in READER_SOURCES for py in root.glob(pattern)})
    assert files, "the source scan found no reader modules at all, the patterns broke"
    return files


def _calls(tree):
    """Every call in one module, as (callee name, argument source segments)."""
    import ast

    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        if name is not None:
            out.append((name, node.args))
    return out


def test_no_reader_resolves_the_pointer_or_builds_a_side_store_reader_of_its_own():
    import ast

    findings = []
    for py in _reader_files():
        tree = ast.parse(py.read_text())
        for name, _args in _calls(tree):
            if name in ("current_ts_or_none", "RibSource"):
                findings.append(f"{py.name}: {name}(...)")
    assert not findings, f"readers resolving a snapshot of their own: {findings}"


def test_no_reader_passes_a_raw_run_id_to_the_side_store_reader():
    import ast

    sites = []
    findings = []
    for py in _reader_files():
        source = py.read_text()
        tree = ast.parse(source)
        for name, args in _calls(tree):
            if name != "for_snapshot":
                continue
            passed = [ast.get_source_segment(source, a) or "" for a in args]
            sites.append(f"{py.name}: for_snapshot({', '.join(passed)})")
            if len(passed) != 1 or not any(token in passed[0] for token in ("snap", "resolve(")):
                findings.append(f"{py.name}: for_snapshot({', '.join(passed)})")
    assert sites, "the source scan found no for_snapshot call at all, the scan broke"
    assert not findings, f"a raw run id passed to the side-store reader: {findings}"
