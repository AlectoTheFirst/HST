"""Activation-aware legacy source adapters shared by HTTP and the local CLI."""

from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import UTC, datetime

from hst.app import crypto
from hst.app import sources as glue
from hst.app.inventory import collection, credentials
from hst.app.inventory.connection_routes import ExecutionRecords
from hst.app.inventory.contracts import ErrorCode, FieldCategory, PlacementMode, PlacementOrigin
from hst.app.inventory.observations import InventoryContext, ReadModel
from hst.app.inventory.repository import Conflict, InventoryError, InventoryTx, NotFound
from hst.app.store import DeviceSpec, Source, Store, live_run
from hst.core import Settings


class NormalizationMigrated(Conflict):
    code = ErrorCode.NORMALIZATION_MIGRATED


async def active(store: Store) -> bool:
    if not collection.has_inventory(store):
        return False
    context = await collection.execution_context(store)
    if context.activated and context.resolver_version != 2:
        raise Conflict("inventory requires a compatible application version")
    return context.activated


class LegacyConnections:
    def __init__(
        self,
        store: Store,
        settings: Settings,
        *,
        actor_id: int | None = None,
        context: InventoryContext | None = None,
    ):
        self.store, self.settings, self.actor_id = store, settings, actor_id
        self.ctx = context or InventoryContext(store, settings)

    async def _source(self, tx: InventoryTx, name: str, *, lock: bool = False) -> Source:
        row = await ExecutionRecords(self.store, tx).get_source(name, lock=lock)
        if row is None:
            raise NotFound(f"no source {name!r}")
        return row

    async def _synthesize(self, tx: InventoryTx, row: Source) -> Source:
        inventory = await tx.get_source_inventory(row.id)
        config = dict(row.config)
        sealed = b""
        if inventory is not None:
            frozen = collection.frozen_normalization_values(row, inventory, self.settings)["values"]
            config.update({k: v for k, v in frozen.items() if k != "site_code"})
            if inventory.default_profile_id is not None:
                profile = await tx.get_profile(inventory.default_profile_id)
                version = (
                    await tx.get_profile_version(profile.id, profile.current_revision) if profile else None
                )
                if version is not None:
                    config = glue._overlay(config, version.settings)
                    if version.credential_id is not None and version.credential_revision is not None:
                        credential = await tx.get_credential_version(
                            version.credential_id, version.credential_revision
                        )
                        if credential is not None:
                            sealed = credential.sealed
        return replace(row, config=config, secrets=sealed)

    async def read(self, row: Source) -> Source:
        async with self.store.inventory().transaction() as tx:
            return await self._synthesize(tx, row)

    async def _profile(
        self, tx: InventoryTx, row: Source, config: dict, sealed: bytes, *, create: bool
    ) -> None:
        now = datetime.now(UTC)
        inventory = await tx.get_source_inventory(row.id)
        if inventory is None:
            raise Conflict("source inventory expansion missing")
        settings = collection.unflatten(
            {
                p: v
                for p, v in collection.flatten(config).items()
                if collection.category_of(row.type, p) == FieldCategory.PROFILE.value
            }
        )
        key = crypto.dek(self.settings)
        secret_map = crypto.decrypt_secrets(key, sealed)
        credential, cv = await tx.create_credential(
            display_name=f"Legacy {row.name} {uuid.uuid4().hex[:8]}",
            sealed=credentials.seal(key, secret_map),
            secret_paths=sorted(secret_map),
            actor_id=self.actor_id,
            now=now,
        )
        profile = await tx.get_profile(inventory.default_profile_id) if inventory.default_profile_id else None
        refs = await tx.profile_references(profile.id) if profile else None
        shared = refs is not None and (any(s != row.id for s in refs.source_ids) or bool(refs.target_ids))
        if profile is None or shared or create:
            profile, _ = await tx.create_profile(
                display_name=f"Legacy {row.name} {uuid.uuid4().hex[:8]}",
                collector_type=row.type,
                settings=settings,
                credential_id=credential.id,
                credential_revision=cv.revision,
                actor_id=self.actor_id,
                now=now,
            )
            await tx.update_source_inventory(
                row.id, expected_revision=inventory.inventory_revision, default_profile_id=profile.id, now=now
            )
        else:
            await tx.add_profile_version(
                profile.id,
                expected_revision=profile.current_revision,
                settings=settings,
                credential_id=credential.id,
                credential_revision=cv.revision,
                actor_id=self.actor_id,
                now=now,
            )

    async def create(self, name: str, collector_type: str, config: dict, enabled: bool = True) -> Source:
        from hst.app.inventory.connection_routes import RESERVED_NAMES

        if name in RESERVED_NAMES:
            raise Conflict("reserved connection name")
        if any(config.get(p) for p in ("routing_scope", "l3dom", "l2fabric")):
            raise NormalizationMigrated(
                "normalization is owned by inventory; create the connection without legacy routing overrides"
            )
        from pydantic import ValidationError

        unknown = [p for p in collection.flatten(config) if collection.category_of(collector_type, p) is None]
        if unknown:
            raise InventoryError("unclassified configuration fields", references=unknown)
        try:
            validated, secret_map = glue.validate_source(collector_type, config)
        except (KeyError, ValidationError) as exc:
            raise InventoryError("invalid source configuration") from exc
        own = collection.unflatten(
            {
                p: v
                for p, v in collection.flatten(validated).items()
                if collection.category_of(collector_type, p)
                in (FieldCategory.CONNECTION.value, FieldCategory.TARGET.value)
            }
        )
        if "site_code" in config:
            own["site_code"] = config["site_code"]
        now = datetime.now(UTC)
        async with self.store.inventory().transaction() as tx:
            records = ExecutionRecords(self.store, tx)
            row = await records.create_source(name, collector_type, own, enabled)
            await self._profile(
                tx, row, validated, credentials.seal(crypto.dek(self.settings), secret_map), create=True
            )
            site_id = await self._site_id(tx, own.get("site_code"))
            if not glue.is_group(collector_type) or own.get("host"):
                await tx.create_target(
                    source_id=row.id,
                    source_key=row.name,
                    host=str(own.get("host") or ""),
                    kind="implicit" if own.get("host") else "controller",
                    enabled=enabled,
                    onboarding_site_id=site_id if glue.is_group(collector_type) else None,
                    now=now,
                )
            await tx.append_event(
                entity_type="connection",
                entity_id=str(row.id),
                actor_id=self.actor_id,
                action="legacy.created",
                now=now,
                after={"name": name},
                sensitive=True,
            )
            return await self._synthesize(tx, row)

    async def _site_id(self, tx: InventoryTx, code: str | None) -> int | None:
        if not code:
            return None
        site = next((s for s in await self.ctx.site_rows(tx).list() if s.code == code), None)
        if site is None:
            raise NotFound(f"site {code!r} not found")
        return site.id

    async def _place_source(self, tx: InventoryTx, row: Source, code: str | None) -> None:
        now = datetime.now(UTC)
        site_id = await self._site_id(tx, code)
        targets = await tx.list_targets(row.id)
        device_ids = {
            o.device_id for t in targets for o in await tx.list_observations(t.id) if o.state != "absent"
        }
        own_ids = {t.id for t in targets}
        for device_id in device_ids:
            observations = await tx.get_observations(device_id)
            if any(o.state != "absent" and o.target_id not in own_ids for o in observations):
                raise Conflict(
                    "shared device placement requires the inventory preview API", references=[str(device_id)]
                )
        for target in targets:
            await tx.update_target(
                target.id, expected_revision=target.revision, onboarding_site_id=site_id, now=now
            )
        for device_id in device_ids:
            placement = await tx.get_placement(device_id)
            await tx.set_placement(
                device_id,
                mode=PlacementMode.ASSIGNED if site_id else PlacementMode.UNPLACED,
                site_id=site_id,
                origin=PlacementOrigin.MANUAL.value,
                expected_revision=placement.revision if placement else 0,
                actor_id=self.actor_id,
                now=now,
            )
        await ReadModel(self.ctx).refresh(tx, device_ids, now, collection=False)

    async def patch(self, name: str, overlay: dict | None, enabled: bool | None = None) -> Source:
        now = datetime.now(UTC)
        async with self.store.inventory().transaction() as tx:
            records = ExecutionRecords(self.store, tx)
            row = await self._source(tx, name, lock=True)
            effective = await self._synthesize(tx, row)
            own = dict(row.config)
            if overlay is not None:
                for path in ("routing_scope", "l3dom", "l2fabric"):
                    if path in overlay and overlay[path] != effective.config.get(path):
                        raise NormalizationMigrated(
                            "normalization is frozen; use inventory routing inspection",
                            references=[f"{name}:{path}"],
                        )
                for path in collection.identity_paths(
                    row.type, FieldCategory.CONNECTION.value, FieldCategory.TARGET.value
                ):
                    if path in collection.flatten(overlay) and collection.flatten(overlay)[
                        path
                    ] != collection.flatten(effective.config).get(path):
                        raise Conflict("identity changes require the inventory target replacement preview")
                from pydantic import ValidationError

                unknown = [
                    p for p in collection.flatten(overlay) if collection.category_of(row.type, p) is None
                ]
                if unknown:
                    raise InventoryError("unclassified configuration fields", references=unknown)
                try:
                    merged, sealed = glue.merge_config(effective, overlay, crypto.dek(self.settings))
                except (ValidationError, glue.SecretsUnreadable) as exc:
                    raise InventoryError("invalid or unreadable source configuration") from exc
                # A full-object compatibility PATCH may contain unchanged frozen values.
                changed = {
                    p: v
                    for p, v in collection.flatten(overlay).items()
                    if collection.category_of(row.type, p)
                    in (FieldCategory.PROFILE.value, FieldCategory.CREDENTIAL.value)
                }
                if changed:
                    await self._profile(tx, row, merged, sealed, create=False)
                for path, value in collection.flatten(merged).items():
                    if collection.category_of(row.type, path) in (
                        FieldCategory.CONNECTION.value,
                        FieldCategory.TARGET.value,
                    ):
                        own = glue._overlay(own, collection.unflatten({path: value}))
                if "site_code" in overlay and overlay["site_code"] != row.config.get("site_code"):
                    await self._place_source(tx, row, overlay["site_code"])
                    own["site_code"] = overlay["site_code"]
            await records.update_source(name, config=own, enabled=enabled)
            inventory = await tx.get_source_inventory(row.id)
            if inventory is not None:
                await tx.update_source_inventory(
                    row.id, expected_revision=inventory.inventory_revision, now=now
                )
            await tx.append_event(
                entity_type="connection",
                entity_id=str(row.id),
                actor_id=self.actor_id,
                action="legacy.updated",
                now=now,
                after={"name": name},
                sensitive=True,
            )
            await tx.bump_generation(now)
            return await self._synthesize(tx, await self._source(tx, name))

    async def delete(self, name: str) -> None:
        now = datetime.now(UTC)
        async with self.store.inventory().transaction() as tx:
            row = await self._source(tx, name)
            records = ExecutionRecords(self.store, tx)
            if await records.active_lease(name) or await live_run(self.store, name):
                raise Conflict("connection has an active execution lease")
            for target in await tx.archive_source_targets(row.id, now):
                await tx.retire_observations(target.id, now)
            await tx.clear_target_source(row.id, now)
            await records.delete_source(name)
            await tx.append_event(
                entity_type="connection",
                entity_id=str(row.id),
                actor_id=self.actor_id,
                action="legacy.deleted",
                now=now,
                before={"name": name},
                sensitive=True,
            )
            await tx.bump_generation(now)

    async def replace_devices(self, name: str, specs: list[DeviceSpec]):
        from hst.app.store.pg import devices as devices_table

        now = datetime.now(UTC)
        if len({s.host for s in specs}) != len(specs):
            raise Conflict("duplicate device host")
        async with self.store.inventory().transaction() as tx:
            row = await self._source(tx, name)
            if not glue.is_group(row.type):
                raise Conflict("connection does not support a device fleet")
            records = ExecutionRecords(self.store, tx)
            if await records.active_lease(name) or await live_run(self.store, name):
                raise Conflict("connection has an active execution lease")
            prior = {d.host: d for d in await self.store.list_devices(name)}
            keep = {s.host for s in specs}
            for host in prior.keys() - keep:
                target = await tx.get_active_target(name, host)
                if target:
                    await tx.retire_observations(target.id, now)
                    await tx.archive_target(target.id, expected_revision=target.revision, now=now)
                await records.remove_device(name, host)
            site_id = await self._site_id(tx, row.config.get("site_code"))
            for spec in specs:
                if spec.host not in prior:
                    device = await records.add_device(name, spec.host, spec.port, spec.enabled)
                else:
                    device = prior[spec.host]
                    if tx.connection is not None:
                        await tx.connection.execute(
                            devices_table.update()
                            .where(devices_table.c.id == device.id)
                            .values(port=spec.port, enabled=spec.enabled, updated_at=now)
                        )
                    else:
                        await records.set_device_enabled(name, spec.host, spec.enabled)
                target = await tx.get_active_target(name, spec.host)
                if target is None:
                    await tx.create_target(
                        source_id=row.id,
                        source_key=name,
                        host=spec.host,
                        kind="direct",
                        legacy_device_id=device.id,
                        enabled=spec.enabled,
                        onboarding_site_id=site_id,
                        now=now,
                    )
                elif target.enabled != spec.enabled:
                    await tx.update_target(
                        target.id, expected_revision=target.revision, enabled=spec.enabled, now=now
                    )
            if tx.connection is None:
                await self.store.replace_devices(name, specs)
            await tx.append_event(
                entity_type="connection",
                entity_id=str(row.id),
                actor_id=self.actor_id,
                action="legacy.targets_replaced",
                now=now,
                after={"targets": len(specs)},
            )
            await tx.bump_generation(now)
            return [await records.get_device(name, spec.host) for spec in specs]

    async def probe(self, name: str, host: str | None = None) -> dict:
        import asyncio

        from hst.app import runs_exec
        from hst.app.inventory.connection_routes import _resolve_target

        async with self.store.inventory().transaction() as tx:
            row = await self._source(tx, name)
            targets = await tx.list_targets(row.id)
            target = next((t for t in targets if (t.host == host if host is not None else t.enabled)), None)
            if target is None:
                raise NotFound("no enabled collection target")
            try:
                resolved, row, device = await _resolve_target(
                    self.store, self.settings, tx, target, key=crypto.dek(self.settings)
                )
            except Conflict as exc:
                return {"ok": False, "detail": str(exc)}
        rows = {r.name: r for r in await self.store.list_sources()}
        try:
            if device is not None:
                collector = glue.build_device_collector(
                    row, device, self.settings, sources=rows, effective=resolved
                )
            else:
                collector = glue.build_collector(row, self.settings, sources=rows, effective=resolved)
            detail = await asyncio.to_thread(collector.probe)
            await runs_exec.pin_host_key(self.store, row, collector, device)
            return {"ok": True, "detail": glue.redacted(str(detail), resolved.secrets)}
        except Exception as exc:
            return {"ok": False, "detail": glue.redacted(f"{type(exc).__name__}: {exc}", resolved.secrets)}

    async def effective(self, name: str) -> dict:
        from hst.app.inventory.connection_routes import _resolve_target

        result = []
        async with self.store.inventory().transaction() as tx:
            row = await self._source(tx, name)
            site_codes = {s.id: s.code for s in await self.ctx.site_rows(tx).list()}
            for target in await tx.list_targets(row.id):
                resolved, _, _ = await _resolve_target(self.store, self.settings, tx, target, key=None)
                observations = [o for o in await tx.list_observations(target.id) if o.state != "absent"]
                device_ids: list[uuid.UUID | None] = [o.device_id for o in observations] or [None]
                for device_id in device_ids:
                    device = await tx.get_device(device_id) if device_id else None
                    placement = (await ReadModel(self.ctx).gather(tx, device)).resolve() if device else None
                    site_id = placement.desired_site_id if placement else target.onboarding_site_id
                    result.append(
                        {
                            "host": target.host,
                            "device_uids": [device.graph_uid] if device else [],
                            "site": site_codes.get(site_id) if site_id else None,
                            "values": {
                                p: (resolved.payload or {}).get(p) for p in ("routing_scope", "l2fabric")
                            },
                            "origins": {
                                **resolved.effective.origins,
                                "site": placement.basis.value if placement else "onboarding",
                            },
                        }
                    )
        return {"devices": result}
