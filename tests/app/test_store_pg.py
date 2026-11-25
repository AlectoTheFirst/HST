"""PgStore behaviour no FakeStore can exercise: real cross-connection concurrency
against a disposable Postgres. The shared contract (CRUD, the run lock, crash
reconciliation) is tested once, parametrized over both stores, in
test_store_contract.py. Start a disposable Postgres with:

    podman run --rm -d --name hst-pg-test -e POSTGRES_USER=hst \
      -e POSTGRES_PASSWORD=test -e POSTGRES_DB=hst_test -p 5544:5432 postgres:16
    export HST_TEST_PG_DSN=postgresql+asyncpg://hst:test@localhost:5544/hst_test

Never point this at a live database.
"""

import asyncio
import os
from datetime import UTC, datetime, timedelta

import pytest

pytestmark = pytest.mark.pg
DSN = os.environ.get("HST_TEST_PG_DSN")
if not DSN:
    pytest.skip("HST_TEST_PG_DSN not set", allow_module_level=True)

import sqlalchemy as sa  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from hst.app.store import TurnCapExceeded  # noqa: E402
from hst.app.store.pg import AI_TURN_LOCK_CLASS, PgStore, metadata, upgrade_to_head  # noqa: E402

NOW = datetime(2026, 7, 23, 12, 0, tzinfo=UTC)


@pytest.fixture
async def store():
    await asyncio.to_thread(upgrade_to_head, DSN)
    engine = create_async_engine(DSN)
    async with engine.begin() as conn:  # clean slate per test
        for table in reversed(metadata.sorted_tables):
            await conn.execute(table.delete())
    await engine.dispose()
    st = PgStore(DSN)
    yield st
    await st.dispose()


async def test_create_first_user_admits_exactly_one_even_racing_across_usernames(store):
    await store.create_first_user("ada", "h1", "admin")
    with pytest.raises(ValueError):
        await store.create_first_user("mallory", "h2", "admin")

    # racing a fresh database: the advisory lock, not the username constraint,
    # is what makes exactly one of these win
    engine2 = create_async_engine(DSN)
    async with engine2.begin() as conn:
        for table in reversed(metadata.sorted_tables):
            await conn.execute(table.delete())
    await engine2.dispose()

    results = await asyncio.gather(
        *(store.create_first_user(f"u{i}", "h", "admin") for i in range(5)),
        return_exceptions=True,
    )
    winners = [r for r in results if not isinstance(r, Exception)]
    assert len(winners) == 1
    assert len(await store.list_users()) == 1


async def test_run_claim_excludes_across_stores(store):
    peer = PgStore(DSN)
    try:
        r = await store.start_run("unifi", NOW)
        assert await peer.start_run("unifi", NOW) is None
        await store.finish_run(r.id, "ok", NOW, "done")
        r2 = await peer.start_run("unifi", NOW)
        assert r2 is not None
        await peer.finish_run(r2.id, "ok", NOW, "done")
    finally:
        await peer.dispose()


async def _kill_claim_holders(spare: str | None = None) -> None:
    """Terminate every backend holding a run-claim advisory lock.

    `spare` names a source whose holder survives."""
    from hst.app.store.pg import RUN_CLAIM_CLASS

    engine = create_async_engine(DSN)
    try:
        async with engine.connect() as c:
            await c.execute(
                sa.text(
                    # objid is an unsigned oid; hashtext is signed int4; normalize the
                    # hash into oid range with two's-complement arithmetic, not a cast
                    "SELECT pg_terminate_backend(pid) FROM pg_locks "
                    "WHERE locktype = 'advisory' AND classid = :cls AND pid <> pg_backend_pid() "
                    "AND (CAST(:spare AS text) IS NULL "
                    "     OR objid::bigint <> (hashtext(:spare)::bigint + 4294967296) % 4294967296)"
                ),
                {"cls": RUN_CLAIM_CLASS, "spare": spare},
            )
    finally:
        await engine.dispose()


async def test_boot_sweep_spares_a_live_holder_and_reaps_a_dead_one(store):
    peer = PgStore(DSN)
    try:
        live = await peer.start_run("vyos", NOW)
        dead = await store.start_run("unifi", NOW)
        await _kill_claim_holders(spare="vyos")

        reaped = None
        for _ in range(50):
            reaped = await peer.reconcile_orphaned_runs(NOW + timedelta(minutes=1))
            if reaped:
                break
            await asyncio.sleep(0.1)
        assert reaped == 1
        runs = {r.id: r for r in await peer.list_runs()}
        assert runs[dead.id].status == "error"
        assert runs[live.id].status == "running"
        await peer.finish_run(live.id, "ok", NOW, "done")
    finally:
        await peer.dispose()


async def test_dispose_frees_outstanding_claims(store):
    await store.start_run("unifi", NOW)
    await store.dispose()
    peer = PgStore(DSN)
    try:
        fresh = None
        for _ in range(50):
            fresh = await peer.start_run("unifi", NOW)
            if fresh is not None:
                break
            await asyncio.sleep(0.1)
        assert fresh is not None
        await peer.finish_run(fresh.id, "ok", NOW, "done")
    finally:
        await peer.dispose()


async def _start(st, user_id, *, per_user_cap=2, global_cap=16):
    return await st.start_turn(
        user_id, None, "q", None, NOW, per_user_cap=per_user_cap, global_cap=global_cap
    )


async def test_start_turn_admits_the_per_user_cap_across_racing_stores(store):
    """Each store stands for one process. The per-user advisory lock makes
    the count and the insert one step, so exactly the cap is admitted."""
    ada = await store.create_user("ada", "h", "operator")
    bob = await store.create_user("bob", "h", "operator")
    peers = [PgStore(DSN) for _ in range(4)]
    try:
        results = await asyncio.gather(
            *(_start(p, ada.id) for p in peers for _ in range(2)), return_exceptions=True
        )
        refused = [r for r in results if isinstance(r, TurnCapExceeded)]
        assert len(refused) == 6
        assert {r.scope for r in refused} == {"user"}

        # the global cap is counted in the same transaction, over every user
        await _start(store, bob.id, global_cap=3)
        with pytest.raises(TurnCapExceeded) as over:
            await _start(store, bob.id, global_cap=3)
        assert over.value.scope == "global"
    finally:
        for peer in peers:
            await peer.dispose()


async def test_start_turn_waits_for_the_users_advisory_lock(store):
    ada = await store.create_user("ada", "h", "operator")
    bob = await store.create_user("bob", "h", "operator")
    engine = create_async_engine(DSN)
    try:
        async with engine.begin() as holder:
            await holder.execute(
                sa.text("SELECT pg_advisory_xact_lock(:c, :u)"), {"c": AI_TURN_LOCK_CLASS, "u": ada.id}
            )
            blocked = asyncio.create_task(_start(store, ada.id))
            done, _ = await asyncio.wait({blocked}, timeout=0.5)
            assert not done
            # the lock is per user: another user's start goes through
            assert (await asyncio.wait_for(_start(store, bob.id), 5)).status == "pending"
        # the holder's commit released the lock
        assert (await asyncio.wait_for(blocked, 5)).status == "pending"
    finally:
        await engine.dispose()


async def test_a_rename_and_a_first_mint_carry_the_inventory_device(store):
    """The registry moves the inventory device with its uid: the first mint takes
    over the inventory device of the serial-based uid, and a rename keeps it, so
    its placement and its history stay."""
    now = datetime.now(UTC)
    async with store.inventory().transaction() as tx:
        legacy, _ = await tx.register_device(
            "dev:foc1234abcd",
            hostname="core1",
            platform="",
            management_address="",
            snapshot_key=None,
            now=now,
        )

    assert await store.resolve_device("serial", "FOC1234ABCD", "core1", 1) == "dev:core1"
    async with store.inventory().transaction() as tx:
        moved = await tx.get_device_by_graph_uid("dev:core1")
        assert moved is not None and moved.id == legacy.id
        assert await tx.get_device_by_graph_uid("dev:foc1234abcd") is None

    await store.rekey_device("dev:core1", "dev:core9")
    async with store.inventory().transaction() as tx:
        renamed = await tx.get_device_by_graph_uid("dev:core9")
        assert renamed is not None and renamed.id == legacy.id
