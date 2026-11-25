"""Inventory startup without the HTTP wiring.

The module holds the first-start activation, the resolver compatibility check,
the registration of the observation service and the publication reconcile.
`hst serve` calls `start_for` through `start` of inventory/runtime.py.
`hst worker` (worker/runtime.py) calls `start_for`. The module and its imports
do not load FastAPI.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from hst.app.inventory.collection import has_inventory
from hst.app.inventory.contracts import ActivationState
from hst.app.store import Store

if TYPE_CHECKING:
    from hst.app.inventory.observations import InventoryContext

log = logging.getLogger(__name__)
SUPPORTED_RESOLVER = 2


async def compatible(store: Store) -> bool:
    if not has_inventory(store):
        return True
    async with store.inventory().transaction() as tx:
        state = await tx.get_state()
    return state.resolver_version <= SUPPORTED_RESOLVER and (
        state.activation_state != ActivationState.ACTIVE.value or state.resolver_version == SUPPORTED_RESOLVER
    )


async def initialize_fresh(store: Store) -> bool:
    """Enable inventory for an empty installation without a legacy-data backfill."""
    from datetime import UTC, datetime

    from sqlalchemy import text

    from hst.app.inventory.repository import PgInventoryTx

    if not has_inventory(store):
        return False
    async with store.inventory().transaction() as tx:
        if isinstance(tx, PgInventoryTx):
            # Serialize first-start initialization with legacy source creation.
            await tx.connection.execute(text("LOCK TABLE sources IN SHARE ROW EXCLUSIVE MODE"))
        state = await tx.get_state()
        if state.activation_state == ActivationState.ACTIVE.value:
            return False
        if state.resolver_version > SUPPORTED_RESOLVER or state.intent_generation != 1:
            return False
        if await tx.list_source_inventory():
            return False
        await tx.activate(
            resolver_version=SUPPORTED_RESOLVER,
            schema_version=1,
            backfill_version=0,
            now=datetime.now(UTC),
        )
        return True


async def start_for(
    store: Store, settings: Any, context: Callable[[], InventoryContext] | None = None
) -> None:
    """Initialize, check and register the inventory for a process that collects.

    `context` builds the observation service's context.
    """
    from hst.app.inventory import collection
    from hst.app.inventory.observations import InventoryContext, ObservationService
    from hst.app.inventory.routing import Neo4jGraphReader

    await initialize_fresh(store)
    if not await compatible(store):
        raise RuntimeError("inventory resolver version is incompatible with this application")
    if not has_inventory(store):
        return
    ctx = context() if context is not None else InventoryContext(store, settings)
    collection.set_observation_service(ObservationService(ctx))
    execution = await collection.execution_context(store)
    if execution.activated:
        try:
            latest = await Neo4jGraphReader(settings).current_snapshot()
            await collection.reconcile_on_startup(store, latest_snapshot_key=latest)
        except Exception:
            async with store.inventory().transaction() as tx:
                from datetime import UTC, datetime

                await tx.set_sync_pending(True, datetime.now(UTC))
            log.exception("inventory publication reconciliation is pending")
