"""A34: a shared profile is editable when its impact exceeds 1,000 devices."""

from __future__ import annotations

import logging
import platform
import statistics
import time
import uuid
from contextlib import nullcontext
from dataclasses import asdict

import pytest
from tests.app.conftest import PASSWORD, login
from tests.app.inventory_fakes import FakeInventoryTx
from tests.app.inventory_rig import DSN, reset_pg
from tests.app.test_inventory_api import QueryCounter
from tests.app.test_inventory_collection import (
    NOW,
    VYOS_SECRETS,
    VYOS_SETTINGS,
    activate,
    make_client,
    make_store,
    seed_credential,
    seed_profile,
    settings_for,
)
from tests.app.test_inventory_profiles import API, _apply, _connection, _preview, _target

from hst.app.security import hash_password
from hst.app.store import InventoryDevice, InventoryObservation

DEVICE_COUNT = 10_000
SMALL_FLEET = 50
PAGE_LIMIT = 200
log = logging.getLogger("hst.inventory.perf")
BACKENDS = [
    pytest.param("fake", id="fake"),
    pytest.param(
        "pg",
        id="pg",
        marks=[pytest.mark.pg, pytest.mark.skipif(not DSN, reason="HST_TEST_PG_DSN not set")],
    ),
]


async def _seed_devices(store, targets, start: int, stop: int) -> dict[str, str]:
    """Bulk load fixture rows; seeding itself is outside all query measurements."""
    devices = []
    observations = []
    owners = {}
    for number in range(start, stop):
        device_id = uuid.uuid5(uuid.NAMESPACE_URL, f"hst-profile-scale:{number}")
        target_id = uuid.UUID(targets[number % len(targets)]["id"])
        devices.append(
            InventoryDevice(
                id=device_id,
                graph_uid=f"dev:profile-scale:{number:05d}",
                first_seen=NOW,
                last_seen=NOW,
                latest_snapshot_key="scale-published",
                hostname=f"scale-{number:05d}",
                platform="vyos",
                management_address=f"192.0.{number // 256}.{number % 256}",
                lifecycle="active",
                revision=1,
                collection_state="current",
                last_success_at=NOW,
                resolved_site_id=None,
                placement_state="unplaced",
                updated_at=NOW,
            )
        )
        observations.append(
            InventoryObservation(
                target_id=target_id,
                device_id=device_id,
                reported_location_handle=None,
                last_success_at=NOW,
                last_seen_snapshot_key="scale-published",
                state="current",
                authority="complete",
                notes=None,
                updated_at=NOW,
            )
        )
        owners[str(device_id)] = str(target_id)
    if hasattr(store, "_engine"):
        from hst.app.inventory import tables

        async with store._engine.begin() as connection:
            for offset in range(0, len(devices), 1000):
                await connection.execute(
                    tables.inventory_devices.insert(),
                    [asdict(row) for row in devices[offset : offset + 1000]],
                )
                await connection.execute(
                    tables.inventory_observations.insert(),
                    [asdict(row) for row in observations[offset : offset + 1000]],
                )
    else:
        tables = store.inventory().tables
        tables.devices.update((row.id, row) for row in devices)
        tables.observations.update(((row.target_id, row.device_id), row) for row in observations)
    return owners


def _select_count(counter) -> int | None:
    if counter is None:
        return None
    return sum(statement.lstrip().upper().startswith("SELECT") for statement in counter.statements)


def _distribution(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)
    return {
        "p50_ms": round(statistics.median(ordered), 2),
        "p95_ms": round(ordered[int((len(ordered) - 1) * 0.95)], 2),
    }


@pytest.mark.parametrize("backend", BACKENDS)
async def test_shared_profile_with_ten_thousand_devices_has_exact_paged_impact_and_one_apply(
    tmp_path, monkeypatch, caplog, backend
):
    caplog.set_level(logging.INFO, logger="hst.inventory.perf")
    store = await reset_pg() if backend == "pg" else await make_store()
    if backend == "pg":
        await store.create_user("ada", hash_password(PASSWORD), "admin")
    settings = settings_for(tmp_path)
    await activate(store)
    credential = await seed_credential(store, settings, VYOS_SECRETS)
    profile = await seed_profile(store, "shared-scale-profile", "vyos", VYOS_SETTINGS, credential)
    engine = getattr(store, "_engine", None)
    counter = lambda: QueryCounter(engine) if engine is not None else nullcontext()  # noqa: E731
    individual_reads = 0
    original_read = FakeInventoryTx.get_device

    async def counted_read(self, device_id):
        nonlocal individual_reads
        individual_reads += 1
        return await original_read(self, device_id)

    if backend == "fake":
        monkeypatch.setattr(FakeInventoryTx, "get_device", counted_read)
    change = {
        "settings": {**VYOS_SETTINGS, "interval_s": 333},
        "expected_revision": 1,
    }
    try:
        async with make_client(store, settings) as client:
            await login(client, "ada")
            connection = await _connection(client, profile_id=profile.id)
            # Exercise both whole-profile resolution paths, with 5k devices each.
            targets = [
                await _target(client, connection["id"], "shared-one"),
                await _target(client, connection["id"], "shared-two", profile_id=str(profile.id)),
            ]
            expected_owners = await _seed_devices(store, targets, 0, SMALL_FLEET)
            with counter() as baseline_queries:
                baseline = await _preview(client, "edit_profile", [str(profile.id)], change)
            assert baseline["affected_device_count"] == SMALL_FLEET
            baseline_selects = _select_count(baseline_queries)
            expected_owners.update(await _seed_devices(store, targets, SMALL_FLEET, DEVICE_COUNT))
            individual_reads = 0
            started = time.perf_counter()
            with counter() as preview_queries:
                preview = await _preview(client, "edit_profile", [str(profile.id)], change)
            preview_ms = (time.perf_counter() - started) * 1000
            full_individual_reads = individual_reads
            preview_selects = _select_count(preview_queries)
            assert preview["member_count"] == 1
            assert preview["members"] == [
                {"kind": "profile", "id": str(profile.id), "revision": 1, "label": "shared-scale-profile"}
            ]
            assert preview["affected_device_count"] == DEVICE_COUNT
            assert preview["affected_target_count"] == len(targets)
            assert len(str(preview)) < 4096
            assert VYOS_SECRETS["auth.password"] not in str(preview)
            assert (await client.get(f"{API}/profiles/{profile.id}")).json()["current_revision"] == 1

            items = []
            seen_cursors = set()
            cursor = None
            page_counts = []
            page_ms = []
            while True:
                started = time.perf_counter()
                with counter() as page_queries:
                    response = await client.get(
                        f"{API}/operations/previews/{preview['token']}/impact",
                        params={"limit": PAGE_LIMIT, **({"cursor": cursor} if cursor else {})},
                    )
                page_ms.append((time.perf_counter() - started) * 1000)
                page_counts.append(_select_count(page_queries))
                assert response.status_code == 200, response.text
                page = response.json()
                assert 0 < len(page["items"]) <= PAGE_LIMIT
                assert page["total"] == DEVICE_COUNT + len(targets) + 1
                assert page["generation"] == preview["generation"]
                assert VYOS_SECRETS["auth.password"] not in response.text
                items.extend(page["items"])
                cursor = page["next_cursor"]
                if cursor is None:
                    break
                assert cursor not in seen_cursors, "impact cursor repeated instead of advancing"
                seen_cursors.add(cursor)
                assert len(items) <= DEVICE_COUNT + len(targets) + 1
            device_items = [item for item in items if item["kind"] == "device"]
            assert len(device_items) == DEVICE_COUNT
            assert {
                item["entity_id"]: item["detail"]["target_id"] for item in device_items
            } == expected_owners
            assert {item["entity_id"] for item in items if item["kind"] == "target"} == {
                target["id"] for target in targets
            }
            assert [item["entity_id"] for item in items if item["kind"] == "connection"] == [connection["id"]]
            for item in (item for item in items if item["kind"] == "target"):
                assert item["detail"]["device_count"] == DEVICE_COUNT // 2

            started = time.perf_counter()
            with counter() as apply_queries:
                applied = await _apply(client, preview["token"], key="profile-scale-apply")
            apply_ms = (time.perf_counter() - started) * 1000
            assert applied["results"] == [{"kind": "profile", "id": str(profile.id), "revision": 2}]
            assert applied["job_ids"] == [], (
                "editing a profile must not enqueue one job per discovered device"
            )
            again = await _apply(client, preview["token"], key="profile-scale-apply")
            assert again["status"] == "reused"
            assert again["results"] == applied["results"]
            for target in targets:
                effective = (await client.get(f"{API}/targets/{target['id']}/effective")).json()
                assert effective["profile_revision"] == 2
                assert effective["credential_revision"] == 1
                assert effective["values"]["interval_s"] == 333
                unchanged_target = (await client.get(f"{API}/targets/{target['id']}")).json()
                assert unchanged_target["revision"] == target["revision"]
            async with store.inventory().transaction() as tx:
                assert (await tx.get_profile(profile.id)).current_revision == 2
                assert (await tx.get_profile_version(profile.id, 1)).settings["interval_s"] == 120
                assert (await tx.get_profile_version(profile.id, 2)).settings["interval_s"] == 333
                assert await tx.get_profile_version(profile.id, 3) is None

            log.info(
                "profile scale backend=%s machine=%s/%s python=%s devices=%d observations=%d "
                "preview_ms=%.2f apply_ms=%.2f impact_pages=%d page_timings=%s "
                "selects_small=%s selects_full=%s selects_apply=%s selects_pages=%s individual_reads=%d",
                backend,
                platform.system(),
                platform.machine(),
                platform.python_version(),
                DEVICE_COUNT,
                DEVICE_COUNT,
                preview_ms,
                apply_ms,
                len(page_ms),
                _distribution(page_ms),
                baseline_selects,
                preview_selects,
                _select_count(apply_queries),
                sorted(set(page_counts), key=str),
                full_individual_reads,
            )
            if engine is not None:
                assert preview_selects <= baseline_selects + 2, "profile preview reads grow with device count"
                assert len(set(page_counts)) == 1, "impact-page read count grows with page contents"
                assert max(page_counts) <= 10, "impact pagination is issuing per-row reads"
                assert _select_count(apply_queries) < 40, (
                    "one profile apply must not reread every affected device"
                )
            else:
                assert full_individual_reads <= len(targets), (
                    "profile preview looks up every device individually"
                )
    finally:
        if backend == "pg":
            await store.dispose()
