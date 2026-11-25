"""Collection debug from the UI: the switch, the captures, re-parse and bundles."""

from __future__ import annotations

import asyncio
import io
import json
import time
import zipfile
from datetime import UTC, datetime

import pytest
from tests.app.conftest import login
from tests.test_iosxe import RAW

from hst.app.crypto import dek
from hst.core import debug_capture, rawstore

RUN_ID = "1790000000000-abcdef12"


@pytest.fixture
async def edge(app, seeded, tmp_path):
    app.state.settings.hst_data_dir = tmp_path
    await seeded.create_source("edge", "iosxe", {}, b"")
    return app.state.settings


def _write(settings, raw=None, run_id=RUN_ID):
    return rawstore.write(settings.raw_dir, "edge", run_id, raw or RAW, host="r1", key=dek(settings))


async def test_a_viewer_cannot_reach_debug_capture(client, edge):
    await login(client, "vera")
    assert (await client.get("/api/debug-capture")).status_code == 403


async def test_the_switch_turns_on_for_the_configured_hours_and_off(client, edge):
    await login(client, "otto")
    r = await client.put("/api/debug-capture/sources/edge", json={"enabled": True})
    assert r.status_code == 200 and r.json()["by"] == "otto"
    hours = r.json()["until_ms"] - int(time.time() * 1000)
    assert 23 * 3_600_000 < hours <= 24 * 3_600_000
    [row] = (await client.get("/api/debug-capture")).json()["sources"]
    assert row["name"] == "edge" and row["until_ms"] == r.json()["until_ms"]
    await client.put("/api/debug-capture/sources/edge", json={"enabled": False})
    [row] = (await client.get("/api/debug-capture")).json()["sources"]
    assert row["until_ms"] is None
    assert (await client.put("/api/debug-capture/sources/nope", json={"enabled": True})).status_code == 404


async def test_a_capture_with_no_finish_lists_the_step_that_was_running(client, edge):
    raw_path = _write(edge)
    cap = debug_capture.Capture(
        rawstore.sibling(raw_path, rawstore.DEBUG_SUFFIX),
        rawstore.sibling(raw_path, rawstore.DEBUG_STACK_SUFFIX),
        dek(edge),
        stack_after_s=20,
    )
    cap.record("begin", kind="run", collector="iosxe", environment={"rss_kb": 1000})
    cap.record("start", step="textfsm", depth=1, command="show ip route vrf *", rss_kb=900_000)
    cap.close()
    await login(client, "otto")
    [row] = (await client.get("/api/debug-capture")).json()["captures"]
    assert row["source_name"] == "edge" and row["host"] == "r1" and row["run_id"] == RUN_ID
    assert row["finished"] is False and row["peak_rss_kb"] == 900_000
    assert [(s["step"], s["command"]) for s in row["open_steps"]] == [("textfsm", "show ip route vrf *")]


async def test_a_reparse_runs_in_a_child_and_its_result_is_in_the_bundle(client, edge):
    _write(edge)
    await login(client, "otto")
    r = await client.post(
        "/api/debug-capture/reparse", json={"source": "edge", "host": "r1", "run_id": RUN_ID}
    )
    assert r.status_code == 202
    r = await client.post(
        "/api/debug-capture/reparse", json={"source": "edge", "host": "r1", "run_id": RUN_ID}
    )
    assert r.status_code == 409
    for _ in range(600):
        [payload] = (await client.get("/api/debug-capture/payloads", params={"source": "edge"})).json()[
            "payloads"
        ]
        if payload["reparse"]["state"] != "running":
            break
        await asyncio.sleep(0.2)
    assert payload["reparse"]["state"] == "ok", payload
    r = await client.get(
        "/api/debug-capture/bundle", params={"source": "edge", "host": "r1", "run_id": RUN_ID}
    )
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    bundle = zipfile.ZipFile(io.BytesIO(r.content))
    prefix = f"captures/edge/r1/{RUN_ID}/"
    result = json.loads(bundle.read(prefix + "reparse.json"))
    assert result["state"] == "ok" and result["report"]["sections"]
    records = bundle.read(prefix + "reparse-debug.jsonl").decode().splitlines()
    assert any('"step": "iosxe.parse"' in line for line in records)
    assert prefix + "raw/show-ip-route-vrf-star.txt" in bundle.namelist()


async def test_a_payload_outside_the_raw_store_is_404(client, edge):
    await login(client, "otto")
    for params in (
        {"source": "..", "host": "..", "run_id": RUN_ID},
        {"source": "edge", "host": "r1", "run_id": "../../etc"},
        {"source": "edge", "host": "r1", "run_id": RUN_ID},
    ):
        assert (await client.get("/api/debug-capture/bundle", params=params)).status_code == 404


async def test_a_run_bundle_holds_the_captures_that_began_during_the_run(client, edge, seeded):
    run = await seeded.start_run("cycle", datetime.now(UTC))
    raw_path = _write(edge)
    edge.hst_debug_stack_after_s = 20
    with debug_capture.capture(
        edge, source="edge", host="r1", run_id=RUN_ID, collector="iosxe", raw=RAW, force=True
    ):
        pass
    await seeded.finish_run(run.id, "error", datetime.now(UTC), "orphaned by crash")
    await login(client, "otto")
    r = await client.get(f"/api/runs/{run.id}/debug-bundle", params={"raw": "none"})
    assert r.status_code == 200
    bundle = zipfile.ZipFile(io.BytesIO(r.content))
    assert json.loads(bundle.read("run.json"))["detail"] == "orphaned by crash"
    assert f"captures/edge/r1/{RUN_ID}/debug.jsonl" in bundle.namelist()
    assert not any("/raw/" in name for name in bundle.namelist())
    assert raw_path.is_file()

    later = await seeded.start_run("edge", datetime.now(UTC))
    assert (await client.get(f"/api/runs/{later.id}/debug-bundle")).status_code == 404


def test_a_reparse_past_its_wall_clock_limit_is_ended_and_reported(app, tmp_path):
    from hst.app import debug_reparse

    settings = app.state.settings
    settings.hst_data_dir = tmp_path
    settings.hst_debug_reparse_timeout_s = 0.5
    _write(settings)
    result = debug_reparse.run_isolated(settings, "iosxe", "edge", "r1", RUN_ID)
    assert result["state"] == "timeout"
    assert result["limits"] == {"memory_mb": settings.hst_debug_reparse_memory_mb, "timeout_s": 0.5}
    assert result["exit_code"] is not None and result["exit_code"] != 0


async def test_an_operator_cannot_download_an_unredacted_bundle(client, edge, seeded):
    run = await seeded.start_run("cycle", datetime.now(UTC))
    _write(edge)
    with debug_capture.capture(
        edge, source="edge", host="r1", run_id=RUN_ID, collector="iosxe", raw=RAW, force=True
    ):
        pass
    await seeded.finish_run(run.id, "ok", datetime.now(UTC), "")
    await login(client, "otto")
    params = {"source": "edge", "host": "r1", "run_id": RUN_ID}
    r = await client.get("/api/debug-capture/bundle", params={**params, "raw": "full"})
    assert r.status_code == 403 and r.json() == {"error": "requires permission: sources.write"}
    r = await client.get(f"/api/runs/{run.id}/debug-bundle", params={"raw": "full"})
    assert r.status_code == 403 and r.json() == {"error": "requires permission: sources.write"}
    assert (
        await client.get("/api/debug-capture/bundle", params={**params, "raw": "redacted"})
    ).status_code == 200


async def test_an_admin_downloads_an_unredacted_bundle(client, edge):
    _write(edge)
    await login(client, "ada")
    params = {"source": "edge", "host": "r1", "run_id": RUN_ID, "raw": "full"}
    r = await client.get("/api/debug-capture/bundle", params=params)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/zip")
    names = zipfile.ZipFile(io.BytesIO(r.content)).namelist()
    assert any("/raw/" in name for name in names)


async def test_a_redacted_bundle_loses_the_values_the_sources_are_configured_with(client, edge, monkeypatch):
    """A value no key names, in a command's output: only the configured
    credentials find it."""
    from hst.app import runs_exec

    secret = "opaque-license-4471"
    _write(edge, {"show version": f"System\nlicense {secret} installed"})

    async def configured(store, settings):
        return [secret]

    monkeypatch.setattr(runs_exec, "configured_secrets", configured)
    await login(client, "otto")
    params = {"source": "edge", "host": "r1", "run_id": RUN_ID}
    r = await client.get("/api/debug-capture/bundle", params=params)
    assert r.status_code == 200
    bundle = zipfile.ZipFile(io.BytesIO(r.content))
    text = "\n".join(bundle.read(n).decode() for n in bundle.namelist() if "/raw/" in n)
    assert "installed" in text and secret not in text

    await login(client, "ada")
    r = await client.get("/api/debug-capture/bundle", params={**params, "raw": "full"})
    bundle = zipfile.ZipFile(io.BytesIO(r.content))
    assert any(secret in bundle.read(n).decode() for n in bundle.namelist() if "/raw/" in n)


async def test_a_redacted_bundle_is_not_built_when_the_sources_credentials_cannot_be_read(
    client, edge, monkeypatch
):
    from hst.app import runs_exec

    _write(edge)

    async def broken(store, settings):
        raise RuntimeError("the credential store is down")

    monkeypatch.setattr(runs_exec, "configured_secrets", broken)
    await login(client, "otto")
    r = await client.get(
        "/api/debug-capture/bundle", params={"source": "edge", "host": "r1", "run_id": RUN_ID}
    )
    assert r.status_code == 503
    assert "redacted bundle was not built" in r.json()["error"]
