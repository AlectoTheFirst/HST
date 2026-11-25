"""Redacted event history."""

from __future__ import annotations

from typing import Any

from hst.app.inventory.contracts import EventPage, EventView, PageQuery
from hst.app.inventory.repository import InventoryError, InventoryTx
from hst.app.store import InventoryEvent, Store

SENSITIVE_PERMISSION = "runs.manage"

# Event actions on devices and placements.
DEVICE_ACTIONS = (
    "device.registered",
    "device.reappeared",
    "device.missing",
    # the device identity registry gave the device a new graph uid
    # (`hst device rekey`, or the first mint after a serial-based uid)
    "device.rekeyed",
    "placement.set",
    "placement.onboarding",
    "placement.onboarding_conflict",
    "placement.released",
    "lifecycle.archive",
    "lifecycle.unarchive",
    "collect.requested",
)


def decode_cursor(cursor: str | None) -> int | None:
    if cursor is None:
        return None
    try:
        value = int(cursor)
    except ValueError as exc:
        raise InventoryError("malformed history cursor") from exc
    if value <= 0:
        raise InventoryError("malformed history cursor")
    return value


def view_of(event: InventoryEvent, actor_names: dict[int, str]) -> EventView:
    return EventView(
        id=event.id,
        entity_type=event.entity_type,
        entity_id=event.entity_id,
        actor_id=str(event.actor_id) if event.actor_id is not None else None,
        actor_name=actor_names.get(event.actor_id) if event.actor_id is not None else None,
        action=event.action,
        at=event.at,
        before=event.before,
        after=event.after,
        request_id=event.request_id,
        snapshot_key=event.snapshot_key,
    )


async def actor_names(store: Store, events: list[InventoryEvent]) -> dict[int, str]:
    """Usernames for the distinct actors of a page, one read per actor."""
    names: dict[int, str] = {}
    for event in events:
        if event.actor_id is None or event.actor_id in names:
            continue
        user = await store.get_user(event.actor_id)
        names[event.actor_id] = user.username if user is not None else ""
    return names


async def page_history(
    tx: InventoryTx,
    store: Store,
    *,
    entity_type: str,
    entity_id: str,
    query: PageQuery,
    permissions: frozenset[str] | set[str],
) -> EventPage:
    """One page of an entity's history, newest first, with sensitive events
    omitted unless the caller may manage runs."""
    before = decode_cursor(query.cursor)
    events, next_before = await tx.page_events(
        entity_type=entity_type,
        entity_id=entity_id,
        before_id=before,
        limit=query.limit,
        include_sensitive=SENSITIVE_PERMISSION in permissions,
    )
    names = await actor_names(store, events)
    return EventPage(
        items=[view_of(e, names) for e in events],
        next_cursor=str(next_before) if next_before is not None else None,
    )


def placement_payload(placement: Any) -> dict[str, Any] | None:
    """The `before` and `after` payload of a placement event."""
    if placement is None:
        return None
    return {
        "mode": placement.mode,
        "site_id": placement.site_id,
        "origin": placement.origin,
        "revision": placement.revision,
    }
