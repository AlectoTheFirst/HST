"""Each download of decrypted evidence writes one row and one log line with the account."""

from __future__ import annotations

import io
import logging
import zipfile
from datetime import UTC, datetime

import pytest
from tests.app.conftest import login
from tests.test_iosxe import RAW

from hst.app.crypto import dek
from hst.core import debug_capture, rawstore

RUN_ID = "1790000000000-abcdef12"
LOGGER = "hst.app.evidence_exports"


@pytest.fixture
async def edge(app, seeded, tmp_path):
    app.state.settings.hst_data_dir = tmp_path
    await seeded.create_source("edge", "iosxe", {}, b"")
    return app.state.settings


def _write(settings):
    return rawstore.write(settings.raw_dir, "edge", RUN_ID, RAW, host="r1", key=dek(settings))


def _bundle_params(raw):
    return {"source": "edge", "host": "r1", "run_id": RUN_ID, "raw": raw}


def _warnings(caplog):
    return [r for r in caplog.records if r.name == LOGGER and r.levelno == logging.WARNING]


async def test_an_unredacted_payload_bundle_is_recorded_with_the_account(client, edge, seeded, caplog):
    _write(edge)
    await login(client, "ada")
    with caplog.at_level(logging.INFO, logger=LOGGER):
        r = await client.get("/api/debug-capture/bundle", params=_bundle_params("full"))
    assert r.status_code == 200
    [row] = seeded.evidence_exports
    assert (row.username, row.kind, row.raw_mode, row.source, row.host, row.run_id, row.payloads) == (
        "ada",
        "payload_bundle",
        "full",
        "edge",
        "r1",
        RUN_ID,
        1,
    )
    assert any("ada" in w.getMessage() and RUN_ID in w.getMessage() for w in _warnings(caplog))


async def test_a_redacted_bundle_writes_a_row_and_no_warning(client, edge, seeded, caplog):
    _write(edge)
    await login(client, "otto")
    with caplog.at_level(logging.INFO, logger=LOGGER):
        r = await client.get("/api/debug-capture/bundle", params=_bundle_params("redacted"))
    assert r.status_code == 200
    [row] = seeded.evidence_exports
    assert row.username == "otto" and row.raw_mode == "redacted"
    assert not _warnings(caplog)


async def test_a_run_bundle_row_carries_the_run_id_and_the_payload_count(client, edge, seeded):
    run = await seeded.start_run("cycle", datetime.now(UTC))
    _write(edge)
    with debug_capture.capture(
        edge, source="edge", host="r1", run_id=RUN_ID, collector="iosxe", raw=RAW, force=True
    ):
        pass
    await seeded.finish_run(run.id, "ok", datetime.now(UTC), "")
    await login(client, "otto")
    r = await client.get(f"/api/runs/{run.id}/debug-bundle", params={"raw": "none"})
    assert r.status_code == 200
    names = zipfile.ZipFile(io.BytesIO(r.content)).namelist()
    captures = {n.rsplit("/", 1)[0] for n in names if n.startswith("captures/") and n.endswith("debug.jsonl")}
    [row] = seeded.evidence_exports
    assert (row.kind, row.run_id, row.raw_mode, row.source) == ("run_bundle", str(run.id), "none", "cycle")
    assert row.payloads == len(captures) == 1


async def test_an_http_trace_download_is_recorded(app, client, seeded, tmp_path):
    from hst.collectors import http_trace

    settings = app.state.settings
    settings.hst_data_dir = tmp_path
    key = dek(settings)
    raw_path = rawstore.write(settings.raw_dir, "vco-1", RUN_ID, {"x": 1}, key=key)
    trace = http_trace.HttpTrace("vco-1", settings.raw_dir)
    trace.record({"ts": 1, "method": "GET", "url": "https://vco/x", "status": 200})
    trace.seal(raw_path, key)
    await login(client, "otto")
    r = await client.get(f"/api/runs/http-traces/{RUN_ID}", params={"source": "vco-1"})
    assert r.status_code == 200
    [row] = seeded.evidence_exports
    assert (row.kind, row.raw_mode, row.source, row.host, row.run_id) == (
        "http_trace",
        None,
        "vco-1",
        "",
        RUN_ID,
    )


async def test_a_refused_request_writes_no_row(app, client, edge, seeded):
    await login(client, "otto")
    escape = {"source": "..", "host": "..", "run_id": RUN_ID, "raw": "full"}
    assert (await client.get("/api/debug-capture/bundle", params=escape)).status_code == 404
    run = await seeded.start_run("edge", datetime.now(UTC))
    assert (await client.get(f"/api/runs/{run.id}/debug-bundle")).status_code == 404
    r = await client.get(f"/api/runs/http-traces/{RUN_ID}", params={"source": "vco-1"})
    assert r.status_code == 404
    assert seeded.evidence_exports == []


async def test_an_unredacted_bundle_is_refused_when_its_row_cannot_be_written(
    client, edge, seeded, monkeypatch, caplog
):
    _write(edge)

    async def broken(**kwargs):
        raise RuntimeError("store down")

    monkeypatch.setattr(seeded, "record_evidence_export", broken)
    await login(client, "ada")
    r = await client.get("/api/debug-capture/bundle", params=_bundle_params("full"))
    assert r.status_code == 503
    assert (
        r.json()["error"] == "the export record could not be written, so the unredacted bundle was not sent"
    )
    assert not r.content.startswith(b"PK")

    caplog.clear()
    with caplog.at_level(logging.INFO, logger=LOGGER):
        r = await client.get("/api/debug-capture/bundle", params=_bundle_params("redacted"))
    assert r.status_code == 200
    assert _warnings(caplog)
