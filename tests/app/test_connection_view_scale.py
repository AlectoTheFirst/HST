"""The views and previews of a connection read each source once, not once per target."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from tests.app.inventory_fakes import InventoryFakeStore

from hst.app.inventory import connection_routes as routes
from hst.app.store import DeviceSpec
from hst.core import Settings

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _counting(obj: Any, name: str, counts: dict[str, list[int]]) -> None:
    inner = getattr(obj, name)

    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        result = await inner(*args, **kwargs)
        counts.setdefault(name, []).append(len(result) if hasattr(result, "__len__") else 1)
        return result

    setattr(obj, name, wrapper)


async def _seed(targets: int) -> tuple[Any, Any, Any]:
    store = InventoryFakeStore()
    source = await store.create_source("grp", "vyos", {}, b"")
    inventory = store.inventory().seed_source(source.id, "grp")
    devices = await store.replace_devices("grp", [DeviceSpec(f"h{i:05d}") for i in range(targets)])
    async with store.inventory().transaction() as tx:
        for device in devices:
            uid = f"dev:{device.host}"
            await store.record_target_devices("grp", device.host, [uid])
            await tx.register_device(
                uid, hostname=device.host, platform="vyos", management_address="", snapshot_key=None, now=NOW
            )
            await tx.create_target(
                source_id=source.id,
                source_key="grp",
                host=device.host,
                kind="direct",
                now=NOW,
                legacy_device_id=device.id,
            )
            await store.upsert_device_status("grp", device.host, now=NOW, ok=True)
    return store, source, inventory


async def _read_counts(targets: int) -> dict[str, list[int]]:
    store, source, inventory = await _seed(targets)
    counts: dict[str, list[int]] = {}
    for name in ("target_devices", "list_device_status", "list_devices", "get_source"):
        _counting(store, name, counts)
    async with store.inventory().transaction() as tx:
        for name in (
            "list_observations",
            "list_observations_for_targets",
            "get_device_by_graph_uid",
            "get_devices_by_graph_uids",
            "get_devices",
        ):
            _counting(tx, name, counts)
        rows = await tx.list_targets(source.id)
        view = await routes.connection_view(tx, store, Settings(_env_file=None), source, inventory)
        assert view.health.target_count == targets and view.health.device_count == targets
        views = await routes._target_views(tx, store, rows)
        assert [v.observed_device_ids != [] for v in views] == [True] * targets
        assert all(v.last_attempt_at is not None for v in views)
        impact, device_ids = await routes._impact_rows_for_targets(SimpleNamespace(tx=tx, store=store), rows)
        assert len(device_ids) == targets and len(impact) == 2 * targets
    return counts


async def test_the_reads_of_a_connection_do_not_grow_with_its_targets() -> None:
    small, large = await _read_counts(20), await _read_counts(80)
    assert {k: len(v) for k, v in small.items()} == {k: len(v) for k, v in large.items()}
    for name, sizes in large.items():
        if name in ("target_devices", "list_device_status", "list_devices"):
            assert max(sizes) == 80, name
    assert "get_device_by_graph_uid" not in large and "list_observations" not in large


async def test_a_saved_connections_view_is_built_after_its_transaction_closed(monkeypatch) -> None:
    """POST and PATCH build the view in a read transaction of their own: the write's
    transaction holds the generation row lock, and the view must not read under it."""
    from tests.app.conftest import login
    from tests.app.test_inventory_collection import make_client, make_store, settings_for
    from tests.app.test_inventory_profiles import API

    store = await make_store()
    async with store.inventory().transaction() as tx:
        await tx.activate(resolver_version=2, schema_version=1, backfill_version=1, now=NOW)
    repository = store.inventory()
    state = {"open": 0, "closed": 0}
    original_transaction = repository.transaction
    original_view = routes.connection_view
    seen: list[tuple[int, int]] = []

    def tracked():
        outer = original_transaction()

        class Tracked:
            async def __aenter__(self):
                state["open"] += 1
                return await outer.__aenter__()

            async def __aexit__(self, *exc):
                state["open"] -= 1
                state["closed"] += 1
                return await outer.__aexit__(*exc)

        return Tracked()

    async def view(*args: Any, **kwargs: Any) -> Any:
        seen.append((state["open"], state["closed"]))
        return await original_view(*args, **kwargs)

    monkeypatch.setattr(repository, "transaction", tracked)
    monkeypatch.setattr(routes, "connection_view", view)
    async with make_client(store, settings_for()) as client:
        await login(client, "ada")
        created = await client.post(
            f"{API}/connections",
            json={"name": "lab", "collector_type": "vyos", "display_name": "Lab", "enabled": True},
        )
        assert created.status_code == 201, created.text
        state["closed"] = 0
        patched = await client.patch(
            f"{API}/connections/{created.json()['id']}",
            json={"display_name": "Lab 2", "expected_revision": created.json()["revision"]},
        )
        assert patched.status_code == 200, patched.text
        assert patched.json()["display_name"] == "Lab 2"
    # the view reads in the one open transaction, and the write's transaction has closed
    assert [open_ for open_, _ in seen] == [1, 1]
    assert seen[1][1] >= 1 and seen[0][1] >= 1
