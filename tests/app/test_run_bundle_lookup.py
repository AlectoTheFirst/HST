"""GET /api/runs/{id}/debug-bundle finds its run by id (`Store.get_run`),
not in a window of the newest runs, so a run older than any such window has
its bundle as any other run does."""

from __future__ import annotations

import io
import zipfile
from datetime import UTC, datetime

from tests.app.conftest import login
from tests.test_iosxe import RAW

from hst.app.crypto import dek
from hst.core import debug_capture, rawstore

RUN_ID = "1790000000000-abcdef12"


async def test_the_bundle_of_a_run_older_than_the_newest_two_hundred(client, app, seeded, tmp_path):
    app.state.settings.hst_data_dir = tmp_path
    settings = app.state.settings
    await seeded.create_source("edge", "iosxe", {}, b"")
    old = await seeded.start_run("cycle", datetime.now(UTC))
    rawstore.write(settings.raw_dir, "edge", RUN_ID, RAW, host="r1", key=dek(settings))
    settings.hst_debug_stack_after_s = 20
    with debug_capture.capture(
        settings, source="edge", host="r1", run_id=RUN_ID, collector="iosxe", raw=RAW, force=True
    ):
        pass
    await seeded.finish_run(old.id, "ok", datetime.now(UTC), "done")
    for _ in range(205):
        newer = await seeded.start_run("reasoner", datetime.now(UTC))
        await seeded.finish_run(newer.id, "ok", datetime.now(UTC), "done")
    assert old.id not in {run.id for run in await seeded.list_runs(limit=200)}

    await login(client, "otto")
    r = await client.get(f"/api/runs/{old.id}/debug-bundle", params={"raw": "none"})
    missing = await client.get("/api/runs/999999/debug-bundle")

    assert r.status_code == 200, r.text
    assert f"captures/edge/r1/{RUN_ID}/debug.jsonl" in zipfile.ZipFile(io.BytesIO(r.content)).namelist()
    assert missing.status_code == 404
    assert missing.json()["error"] == "no run 999999"
