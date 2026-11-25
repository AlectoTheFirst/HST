"""Fresh installations onboard directly into inventory without a backfill workflow."""

import os

import pytest
from tests.app.inventory_rig import fake_rig

from hst.app.inventory.runtime import initialize_fresh


async def test_fresh_start_enables_inventory_once_without_backfill():
    rig = fake_rig()
    assert await initialize_fresh(rig.store)
    state = await rig.state()
    assert state.activation_state == "active"
    assert state.resolver_version == 2
    assert state.backfill_version == 0
    assert state.read_model_snapshot_key is None
    assert not await initialize_fresh(rig.store)
    assert await rig.state() == state


async def test_initialization_does_not_silently_convert_existing_sources():
    rig = fake_rig()
    await rig.seed_source("existing", "vyos")
    assert not await initialize_fresh(rig.store)
    assert (await rig.state()).activation_state == "inactive"


@pytest.mark.pg
@pytest.mark.skipif(not os.environ.get("HST_TEST_PG_DSN"), reason="HST_TEST_PG_DSN not set")
async def test_fresh_postgres_initialization_is_idempotent():
    from tests.app.inventory_rig import reset_pg

    store = await reset_pg()
    try:
        assert await initialize_fresh(store)
        assert not await initialize_fresh(store)
        async with store.inventory().transaction() as tx:
            state = await tx.get_state()
            assert state.resolver_version == 2
            assert state.activation_state == "active"
            assert state.backfill_version == 0
    finally:
        await store.dispose()
