"""Effective collection resolution and the execution seams."""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, NamedTuple, Protocol
from uuid import UUID

from hst.app import sources as sources_glue
from hst.app.crypto import SecretKeyError, decrypt_secrets
from hst.app.inventory import field_metadata as _fm
from hst.app.inventory.contracts import (
    REDACTED,
    ActivationState,
    Authority,
    EffectiveCollection,
    FieldCategory,
    ProfileOrigin,
    redact_paths,
)
from hst.app.inventory.repository import InventoryTx
from hst.app.store import (
    CollectionCredentialVersion,
    CollectionProfile,
    CollectionProfileVersion,
    Device,
    InventoryState,
    InventoryTarget,
    Site,
    Source,
    SourceInventory,
    Store,
)
from hst.core import Settings
from hst.core.model import SectionOutcome, section_verdict
from hst.core.uid import slug

if TYPE_CHECKING:
    from hst.app.inventory.observations import ObservedDevice as StagedDevice

log = logging.getLogger(__name__)

RESOLVER_V1 = 1
RESOLVER_V2 = 2

BASE_NORMALIZATION_PATHS = ("site_code", "routing_scope", "l2fabric")

# The origins of an effective value.
ORIGIN_PROFILE = "profile"
ORIGIN_CONNECTION = "connection"
ORIGIN_TARGET = "target"
ORIGIN_INTERNAL = "internal"
ORIGIN_FROZEN = "frozen"
ORIGIN_CREDENTIAL = "credential"
ORIGIN_FALLBACK = "fallback"
ORIGIN_APPLICATION = "application"


# --- bastion pins -----------------------------------------------------------------

# The row config key that holds the host keys learned from bastions on first
# contact, by `jump_pin_key`.
JUMP_PINS = "jump_pins"


def jump_pin_key(host: Any, port: Any) -> str:
    """The key of the pin of one bastion. It is the lower-case host, a colon and the port.
    The port defaults to 22."""
    return f"{str(host).strip().lower()}:{port or 22}"


def jump_pin(config: Mapping[str, Any], host: Any, port: Any) -> str:
    """The host key learned from the bastion at `host`:`port`, or ""."""
    pins = config.get(JUMP_PINS)
    pin = pins.get(jump_pin_key(host, port)) if isinstance(pins, Mapping) else None
    return pin if isinstance(pin, str) else ""


# --- target key --------------------------------------------------------------


class TargetKey(NamedTuple):
    """The execution key of one target. It holds the name of the source row and
    the exact host text. The host is `devices.host` for a fleet row, `config.host`
    for an implicit target and "" for a controller without a host."""

    source: str
    host: str

    @property
    def slugged(self) -> tuple[str, str]:
        """The raw-store path segments and the parked-payload join key."""
        return slug(self.source), slug(self.host)

    @property
    def label(self) -> str:
        return f"{self.source}/{self.host}" if self.host else self.source


def target_key(source_key: str, host: str) -> TargetKey:
    return TargetKey(source_key, host)


def unit_host(device: Device | None, config: Any) -> str:
    """The host of the key of a unit. It is the host of the fleet row, or else the
    `host` of the built collector config, or else "" for a controller without a host."""
    if device is not None:
        return device.host
    return str(getattr(config, "host", "") or "")


def row_host(row: Source, device: Device | None) -> str:
    """The host of the key of a unit, read from the source row before a collector exists."""
    if device is not None:
        return device.host
    return str(row.config.get("host") or "")


# --- activation ----------------------------------------------------------------------


@dataclass(frozen=True)
class ExecutionContext:
    """The activation state for an execution path. It is captured once per run
    or per job, and every unit of the run resolves with it."""

    resolver_version: int = RESOLVER_V1
    activated: bool = False
    # The intent generation captured for the run. Under v2 it is part of the
    # skip fingerprint.
    placement_generation: int = 0
    read_model_snapshot_key: str | None = None

    @property
    def v2(self) -> bool:
        return self.resolver_version >= RESOLVER_V2


LEGACY_CONTEXT = ExecutionContext()


def context_from_state(state: InventoryState) -> ExecutionContext:
    activated = state.activation_state == ActivationState.ACTIVE.value
    return ExecutionContext(
        resolver_version=state.resolver_version if activated else RESOLVER_V1,
        activated=activated,
        placement_generation=state.intent_generation,
        read_model_snapshot_key=state.read_model_snapshot_key,
    )


def has_inventory(store: Any) -> bool:
    return callable(getattr(store, "inventory", None))


async def execution_context(store: Store) -> ExecutionContext:
    """The activation state as one immutable value."""
    if not has_inventory(store):
        return LEGACY_CONTEXT
    async with store.inventory().transaction() as tx:
        return context_from_state(await tx.get_state())


# --- config path helpers ---------------------------------------------------------------


def flatten(value: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    """Return the leaves of a nested mapping by dotted path. A list, a scalar and
    an empty mapping are leaves."""
    out: dict[str, Any] = {}
    for key, item in value.items():
        path = f"{prefix}{key}"
        if isinstance(item, Mapping) and item:
            out.update(flatten(item, f"{path}."))
        else:
            out[path] = item
    return out


def set_path(target: dict[str, Any], path: str, value: Any) -> None:
    head, _, tail = path.partition(".")
    if not tail:
        target[head] = value
        return
    branch = target.setdefault(head, {})
    if not isinstance(branch, dict):
        branch = {}
        target[head] = branch
    set_path(branch, tail, value)


def unflatten(paths: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for path, value in paths.items():
        set_path(out, path, value)
    return out


def category_of(collector_type: str, path: str) -> str | None:
    """Return the category of a dotted path for a collector, across variants,
    or None for a path that the classification does not hold.

    A leaf below a classified mapping field (`site_fabrics.dc1`,
    `vsid_gateway_object_uids.2`, `resolved_origins.host`) has the category of
    the field."""
    coll = _fm.COLLECTORS.get(collector_type)
    if coll is None:
        return None
    by_path = {f.path: f.category for f in coll.fields}
    candidate = path
    while candidate:
        if candidate in by_path:
            return by_path[candidate]
        candidate, _, _ = candidate.rpartition(".")
    return None


def paths_in_category(collector_type: str, category: str) -> frozenset[str]:
    coll = _fm.COLLECTORS.get(collector_type)
    if coll is None:
        return frozenset()
    return frozenset(f.path for f in coll.fields if f.category == category)


def identity_paths(collector_type: str, *categories: str) -> frozenset[str]:
    """The paths of the given categories with the sensitivity `identity` or
    `scope`. A change of one of these paths takes the replace workflow."""
    coll = _fm.COLLECTORS.get(collector_type)
    if coll is None:
        return frozenset()
    return frozenset(
        f.path
        for f in coll.fields
        if f.category in categories and f.identity_sensitivity in ("identity", "scope")
    )


def normalization_paths(collector_type: str) -> tuple[str, ...]:
    extra = sorted(paths_in_category(collector_type, FieldCategory.LEGACY_NORMALIZATION.value))
    return tuple(dict.fromkeys((*BASE_NORMALIZATION_PATHS, *extra)))


class SettingsRejected(ValueError):
    """A settings map holds a path of a category that it may not hold.
    `paths` maps each rejected path to its category."""

    def __init__(self, paths: dict[str, str]):
        self.paths = paths
        listed = ", ".join(f"{p} ({c})" for p, c in sorted(paths.items()))
        super().__init__(f"profile settings may only contain profile fields; rejected: {listed}")


# Profile paths that the form hides for a collector that does not read them.
HIDDEN_PROFILE_PATHS = frozenset({("zia", "capture_bgp"), ("zpa", "capture_bgp")})


def validate_profile_settings(collector_type: str, settings: Mapping[str, Any]) -> dict[str, Any]:
    """Accept a nested or dotted settings map that contains only profile-category
    paths of `collector_type`. Return the map nested."""
    if collector_type not in _fm.COLLECTORS:
        raise SettingsRejected({"*": f"unknown collector type {collector_type!r}"})
    flat = flatten(settings)
    bad: dict[str, str] = {}
    for path in flat:
        category = category_of(collector_type, path)
        if category != FieldCategory.PROFILE.value and (collector_type, path) not in HIDDEN_PROFILE_PATHS:
            bad[path] = category or "unknown"
    if bad:
        raise SettingsRejected(bad)
    return unflatten(flat)


def validate_connection_config(collector_type: str, config: Mapping[str, Any]) -> dict[str, Any]:
    """Accept a connection config that contains only paths of the connection and
    target categories (an implicit host, a controller URL, vendor selectors).
    Return the config nested."""
    if collector_type not in _fm.COLLECTORS:
        raise SettingsRejected({"*": f"unknown collector type {collector_type!r}"})
    flat = flatten(config)
    allowed = (FieldCategory.CONNECTION.value, FieldCategory.TARGET.value)
    bad: dict[str, str] = {}
    for path in flat:
        category = category_of(collector_type, path)
        if category not in allowed:
            bad[path] = category or "unknown"
    if bad:
        raise SettingsRejected(bad)
    return unflatten(flat)


# --- digests ------------------------------------------------------------------------------


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def configuration_digest(parts: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(parts).encode()).hexdigest()


def normalization_revision(values: Mapping[str, Any]) -> str:
    """A 16-character digest of the normalization values applied to a target.
    It changes when the frozen values or the v1 resolution change."""
    return hashlib.sha256(_canonical(dict(values)).encode()).hexdigest()[:16]


def skip_fingerprint(raw_sha: str, revision: str, placement_generation: int) -> str:
    """The value that the skip decision compares under v2. It is a hash of the
    payload hash, the normalization revision and the captured placement generation.
    Under v1 the skip decision compares the raw hash."""
    return hashlib.sha256(f"{raw_sha}|{revision}|{placement_generation}".encode()).hexdigest()


# --- resolution ------------------------------------------------------------------------------


class ResolutionError(Exception):
    """The target cannot be resolved to a runnable configuration. The message
    holds ids and paths and no values."""


class RepairRequired(ResolutionError):
    """The pinned credential version does not open under the current data key.
    The collection is blocked."""

    def __init__(self, credential_id: UUID, revision: int):
        self.credential_id = credential_id
        self.revision = revision
        super().__init__(f"credential {credential_id} revision {revision} needs repair before collection")


@dataclass
class ResolvedCollection:
    """The resolution of one target. `payload` is the collector config with the
    secrets injected. The v2 resolver sets it only when the caller asks for secrets.
    It is never serialized. `effective` is the redacted contract model."""

    effective: EffectiveCollection
    key: TargetKey
    normalization_revision: str
    placement_generation: int
    interval_s: int
    enabled: bool
    payload: dict[str, Any] | None = None
    secrets: dict[str, str] = field(default_factory=dict)
    target: InventoryTarget | None = None
    profile_origin: ProfileOrigin = ProfileOrigin.NONE
    # The reason that `enabled` is False, for the run detail. It is "" when `enabled` is True.
    reason: str = ""
    # The row config paths that the field classification does not hold. Under v2
    # they are left out of the effective values.
    unclassified: tuple[str, ...] = ()

    def evidence(self) -> dict[str, Any]:
        """The revision block recorded in run evidence and the manifest's
        normalization context."""
        e = self.effective
        return {
            "resolver_version": e.resolver_version,
            "profile_id": str(e.profile_id) if e.profile_id else None,
            "profile_revision": e.profile_revision,
            "credential_id": str(e.credential_id) if e.credential_id else None,
            "credential_revision": e.credential_revision,
            "normalization_revision": self.normalization_revision,
            "configuration_digest": e.configuration_digest,
            "placement_generation": self.placement_generation,
        }


def _interval(values: Mapping[str, Any]) -> int:
    try:
        return int(values.get("interval_s") or 0)
    except (TypeError, ValueError):
        return 0


def resolve_v1(
    row: Source,
    settings: Settings,
    *,
    device: Device | None = None,
    sites: Mapping[str, Site] | None = None,
    secrets: Mapping[str, str] | None = None,
    placement_generation: int = 0,
) -> ResolvedCollection:
    """The v1 resolution as an `EffectiveCollection`."""
    effective_payload, origins = sources_glue.resolve_normalization(
        row, settings, device=device, sites=dict(sites) if sites else None
    )
    effective_payload.pop("resolved_origins", None)
    host = row_host(row, device)
    key = target_key(row.name, host)
    flat = flatten(effective_payload)
    secret_set = _fm.secret_paths(row.type) if row.type in _fm.COLLECTORS else frozenset()
    values: dict[str, Any] = {}
    value_origins: dict[str, str] = {}
    for path, value in flat.items():
        values[path] = value
        if path in ("host", "port", "host_key") and device is not None:
            value_origins[path] = ORIGIN_TARGET
        elif path in BASE_NORMALIZATION_PATHS:
            value_origins[path] = origins.get(path, origins.get("site", ORIGIN_CONNECTION))
        else:
            value_origins[path] = ORIGIN_CONNECTION
    for path in sorted(secrets or {}):
        values[path] = REDACTED
        value_origins[path] = ORIGIN_CONNECTION
    for path in secret_set:
        if path in values and values[path] not in (None, ""):
            values[path] = REDACTED
    values["source_name"] = row.name
    value_origins["source_name"] = ORIGIN_INTERNAL
    norm = {p: effective_payload.get(p) for p in BASE_NORMALIZATION_PATHS}
    revision = normalization_revision(norm)
    digest = configuration_digest(
        {
            "source_key": row.name,
            "target_key": list(key),
            "collector_type": row.type,
            "profile": None,
            "credential": None,
            "values": values,
            "frozen_normalization": {},
            "resolver_version": RESOLVER_V1,
        }
    )
    effective = EffectiveCollection(
        source_key=row.name,
        target_key=host,
        target_id=None,
        collector_type=row.type,
        profile_id=None,
        profile_revision=None,
        credential_id=None,
        credential_revision=None,
        values=values,
        origins=value_origins,
        frozen_normalization={},
        resolver_version=RESOLVER_V1,
        configuration_digest=digest,
    )
    payload = sources_glue.inject_secrets(effective_payload, dict(secrets or {}))
    payload["source_name"] = row.name
    return ResolvedCollection(
        effective=effective,
        key=key,
        normalization_revision=revision,
        placement_generation=placement_generation,
        interval_s=_interval(row.config),
        enabled=row.enabled and (device.enabled if device is not None else True),
        payload=payload,
        secrets=dict(secrets or {}),
    )


class Resolver:
    """The v2 resolver over one repository transaction, with per-transaction
    caches.

    `key` is the data key. `resolve` uses it only when the caller asks for
    secrets.
    """

    def __init__(
        self,
        tx: InventoryTx,
        settings: Settings,
        *,
        context: ExecutionContext,
        key: str | None = None,
    ) -> None:
        self.tx = tx
        self.settings = settings
        self.context = context
        self.key = key
        self._sources: dict[str, SourceInventory | None] = {}
        self._targets: dict[TargetKey, InventoryTarget | None] = {}
        self._profiles: dict[UUID, CollectionProfile | None] = {}
        self._versions: dict[tuple[UUID, int], CollectionProfileVersion | None] = {}
        self._credentials: dict[tuple[UUID, int], CollectionCredentialVersion | None] = {}
        self._opened: dict[tuple[UUID, int], dict[str, str]] = {}

    async def source_inventory(self, row: Source) -> SourceInventory | None:
        if row.name not in self._sources:
            found = await self.tx.get_source_inventory_by_key(row.name)
            if found is None and row.id:
                found = await self.tx.get_source_inventory(row.id)
            self._sources[row.name] = found
        return self._sources[row.name]

    async def target(self, key: TargetKey) -> InventoryTarget | None:
        if key not in self._targets:
            self._targets[key] = await self.tx.get_active_target(key.source, key.host)
        return self._targets[key]

    async def profile(self, profile_id: UUID) -> CollectionProfile | None:
        if profile_id not in self._profiles:
            self._profiles[profile_id] = await self.tx.get_profile(profile_id)
        return self._profiles[profile_id]

    async def profile_version(self, profile_id: UUID, revision: int) -> CollectionProfileVersion | None:
        k = (profile_id, revision)
        if k not in self._versions:
            self._versions[k] = await self.tx.get_profile_version(profile_id, revision)
        return self._versions[k]

    async def credential_version(
        self, credential_id: UUID, revision: int
    ) -> CollectionCredentialVersion | None:
        k = (credential_id, revision)
        if k not in self._credentials:
            self._credentials[k] = await self.tx.get_credential_version(credential_id, revision)
        return self._credentials[k]

    async def open_credential(self, version: CollectionCredentialVersion) -> dict[str, str]:
        k = (version.credential_id, version.revision)
        if k not in self._opened:
            if self.key is None:
                raise ResolutionError("no data key to open the credential with")
            try:
                self._opened[k] = decrypt_secrets(self.key, version.sealed)
            except SecretKeyError as exc:
                raise RepairRequired(version.credential_id, version.revision) from exc
        return self._opened[k]

    async def resolve(
        self,
        row: Source,
        *,
        device: Device | None = None,
        host: str | None = None,
        with_secrets: bool = False,
        sites: Mapping[str, Site] | None = None,
    ) -> ResolvedCollection:
        """Resolve one target. `host` overrides the row-derived host for a
        caller that names the target by key (the fetch job, the routes)."""
        if not self.context.v2:
            secrets: dict[str, str] | None = None
            if with_secrets:
                if self.key is None:
                    raise ResolutionError("no data key to open the source secrets with")
                try:
                    secrets = decrypt_secrets(self.key, row.secrets)
                except SecretKeyError as exc:
                    raise ResolutionError("stored credentials cannot be decrypted") from exc
            return resolve_v1(
                row,
                self.settings,
                device=device,
                sites=sites,
                secrets=secrets,
                placement_generation=self.context.placement_generation,
            )
        return await self._resolve_v2(row, device=device, host=host, with_secrets=with_secrets)

    async def _resolve_v2(
        self, row: Source, *, device: Device | None, host: str | None, with_secrets: bool
    ) -> ResolvedCollection:
        collector_type = row.type
        if collector_type not in _fm.COLLECTORS:
            raise ResolutionError(f"unknown collector type {collector_type!r}")
        key = target_key(row.name, row_host(row, device) if host is None else host)
        inventory = await self.source_inventory(row)
        target = await self.target(key)

        # 1. The row config gives the values of the connection and target categories.
        values: dict[str, Any] = {}
        origins: dict[str, str] = {}
        keep = (FieldCategory.CONNECTION.value, FieldCategory.TARGET.value)
        unclassified: list[str] = []
        for path, value in flatten(row.config).items():
            if path == "l3dom":
                # `l3dom` is an alias of routing_scope.
                continue
            if path == JUMP_PINS or path.startswith(f"{JUMP_PINS}."):
                # Step 3b reads the bastion pins by address.
                continue
            category = category_of(collector_type, path)
            if category in keep:
                values[path] = value
                origins[path] = ORIGIN_CONNECTION
            elif category is None:
                # A path without a classification is left out of the effective values.
                unclassified.append(path)
        if unclassified:
            log.warning(
                "%s: config paths without a field classification left out of the effective values: %s",
                row.name,
                ", ".join(sorted(unclassified)),
            )
        if target is not None:
            for path, value in flatten(target.endpoint_config).items():
                if category_of(collector_type, path) != FieldCategory.TARGET.value or path in {
                    "host",
                    "port",
                    "host_key",
                }:
                    raise ResolutionError(f"invalid target-local identity field {path!r}")
                values[path] = value
                origins[path] = ORIGIN_TARGET
        # 2. The host, the port and the host key of the execution record override the row values.
        if device is not None:
            values["host"] = device.host
            origins["host"] = ORIGIN_TARGET
            if device.port is not None:
                values["port"] = device.port
                origins["port"] = ORIGIN_TARGET
            values["host_key"] = device.host_key
            origins["host_key"] = ORIGIN_TARGET
        elif "host" in values:
            origins["host"] = ORIGIN_TARGET
            if "host_key" in values:
                origins["host_key"] = ORIGIN_TARGET
            if "port" in values:
                origins["port"] = ORIGIN_TARGET
        # 3. The settings of one profile revision. The profile of the target wins
        #    over the profile of the connection.
        profile_id: UUID | None = None
        profile_origin = ProfileOrigin.NONE
        if target is not None and target.profile_id is not None:
            profile_id, profile_origin = target.profile_id, ProfileOrigin.TARGET
        elif inventory is not None and inventory.default_profile_id is not None:
            profile_id, profile_origin = inventory.default_profile_id, ProfileOrigin.CONNECTION
        profile_revision: int | None = None
        credential_id: UUID | None = None
        credential_revision: int | None = None
        version: CollectionProfileVersion | None = None
        if profile_id is not None:
            profile = await self.profile(profile_id)
            if profile is None:
                raise ResolutionError(f"profile {profile_id} does not exist")
            if profile.collector_type != collector_type:
                raise ResolutionError(
                    f"profile {profile_id} is for {profile.collector_type}, not {collector_type}"
                )
            version = await self.profile_version(profile_id, profile.current_revision)
            if version is None:
                raise ResolutionError(f"profile {profile_id} has no revision {profile.current_revision}")
            profile_revision = version.revision
            credential_id, credential_revision = version.credential_id, version.credential_revision
            for path, value in flatten(version.settings).items():
                values[path] = value
                origins[path] = ORIGIN_PROFILE
        # 3b. The host key of the bastion. A `jump_host.host_key` in the values wins
        #     over the key that the first contact stored on the row. Without a key,
        #     the first contact pins the host key, as for a device.
        jump_host = values.get("jump_host.host")
        if jump_host and not values.get("jump_host.host_key"):
            learned = jump_pin(row.config, jump_host, values.get("jump_host.port"))
            if learned:
                values["jump_host.host_key"] = learned
                origins["jump_host.host_key"] = ORIGIN_TARGET
        # 4. The frozen normalization values.
        frozen = frozen_normalization_values(row, inventory, self.settings)
        for path, value in frozen["values"].items():
            values[path] = value
            origins[path] = frozen["origins"].get(path, ORIGIN_FROZEN)
        # 5. The internal values.
        values["source_name"] = row.name
        origins["source_name"] = ORIGIN_INTERNAL
        # 6. The credential version. The effective values hold the redacted secret
        #    paths. The payload holds the secret values.
        secret_set = _fm.secret_paths(collector_type)
        secrets: dict[str, str] = {}
        credential_paths: list[str] = []
        if credential_id is not None and credential_revision is not None:
            cversion = await self.credential_version(credential_id, credential_revision)
            if cversion is None:
                raise ResolutionError(f"credential {credential_id} revision {credential_revision} is missing")
            credential_paths = list(cversion.secret_paths)
            for path in credential_paths:
                values[path] = REDACTED
                origins[path] = ORIGIN_CREDENTIAL
            if with_secrets:
                secrets = dict(await self.open_credential(cversion))
        for path in list(values):
            if path in secret_set and path not in credential_paths:
                if values[path] in (None, ""):
                    continue
                values[path] = REDACTED
        redacted_values = redact_paths(unflatten(values), secret_set)
        flat_values = flatten(redacted_values)
        digest = configuration_digest(
            {
                "source_key": row.name,
                "target_key": list(key),
                "collector_type": collector_type,
                "profile": [str(profile_id), profile_revision] if profile_id else None,
                "credential": [str(credential_id), credential_revision] if credential_id else None,
                "values": flat_values,
                "frozen_normalization": frozen["values"],
                "frozen_input_digest": (inventory.frozen_normalization or {}).get("input_digest")
                if inventory
                else None,
                "resolver_version": RESOLVER_V2,
            }
        )
        effective = EffectiveCollection(
            source_key=row.name,
            target_key=key.host,
            target_id=target.id if target is not None else None,
            collector_type=collector_type,
            profile_id=profile_id,
            profile_revision=profile_revision,
            credential_id=credential_id,
            credential_revision=credential_revision,
            values=flat_values,
            origins=origins,
            frozen_normalization=dict(frozen["values"]),
            resolver_version=RESOLVER_V2,
            configuration_digest=digest,
        )
        payload: dict[str, Any] | None = None
        if with_secrets:
            plain = {p: v for p, v in values.items() if p not in secret_set}
            payload = unflatten(plain)
            payload = sources_glue.inject_secrets(payload, secrets)
            payload["source_name"] = row.name
            payload["resolved_origins"] = {
                p: origins[p] for p in BASE_NORMALIZATION_PATHS if p in origins
            } | {"site": origins.get("site_code", ORIGIN_FROZEN)}
        # Under v2 a unit is enabled only with an active, enabled inventory target.
        reason = ""
        if target is None:
            enabled = False
            reason = "no active inventory target"
        elif not target.enabled:
            enabled = False
            reason = "target disabled"
        elif device is not None and not device.enabled:
            enabled = False
            reason = "execution record disabled"
        else:
            enabled = True
        if enabled and not row.enabled:
            enabled, reason = False, "connection disabled"
        return ResolvedCollection(
            effective=effective,
            key=key,
            normalization_revision=normalization_revision(frozen["values"]),
            placement_generation=self.context.placement_generation,
            interval_s=_interval(values),
            enabled=enabled,
            payload=payload,
            secrets=secrets,
            target=target,
            profile_origin=profile_origin,
            reason=reason,
            unclassified=tuple(sorted(unclassified)),
        )


def _implicit_home_scope(
    row: Source, stored: Mapping[str, Any], stored_origins: Mapping[str, Any]
) -> str | None:
    """The namespace a frozen controller row is re-resolved to, or None to keep
    its frozen routing scope."""
    from hst.app.inventory.normalization import IMPLICIT_SITE

    own = sources_glue.source_routing_namespace(row)
    if own is None or stored.get("routing_scope") != IMPLICIT_SITE:
        return None
    if str(stored_origins.get("routing_scope")) not in ("site_code", "backfill", ORIGIN_FALLBACK):
        return None
    if str(stored_origins.get("site_code")) not in ("implicit", ORIGIN_FALLBACK):
        return None
    return own


def frozen_normalization_values(
    row: Source, inventory: SourceInventory | None, settings: Settings
) -> dict[str, dict[str, Any]]:
    """The normalization values a v2 target collects with, and their origins.

    `sources.frozen_normalization` holds the frozen values of a source as
    `{"values": {path: value}, "origins": {path: origin}}`. A flat
    `{path: value}` map is read the same way. A source without frozen values
    (a connection created after activation) gets the fallback values. The
    fallback values are the values that the source config states, the
    `inventory:<source-key>` routing namespace and the l2fabric of the application.
    Geography is not read.
    """
    from hst.app.inventory.normalization import v2_namespace

    paths = normalization_paths(row.type)
    frozen = inventory.frozen_normalization if inventory is not None else None
    values: dict[str, Any] = {}
    origins: dict[str, str] = {}
    stored: Mapping[str, Any] = {}
    stored_origins: Mapping[str, Any] = {}
    if isinstance(frozen, Mapping):
        if isinstance(frozen.get("values"), Mapping):
            stored = frozen["values"]
            if isinstance(frozen.get("origins"), Mapping):
                stored_origins = frozen["origins"]
        elif isinstance(frozen.get("routing_scope"), Mapping):
            stored = {
                path: frozen[path]["value"]
                for path in ("site_code", "routing_scope", "l2fabric")
                if isinstance(frozen.get(path), Mapping)
            }
            stored_origins = {path: frozen[path]["origin"] for path in stored}
            alias = frozen.get("l3dom_alias") or {}
            if alias.get("origin") == "alias-effective" and alias.get("value"):
                stored = {**stored, "l3dom": alias["value"]}
        else:
            stored = frozen
    implicit_scope = _implicit_home_scope(row, stored, stored_origins)
    for path in paths:
        if path == "routing_scope" and implicit_scope is not None:
            values[path] = implicit_scope
            origins[path] = ORIGIN_FALLBACK
            continue
        if path in stored:
            values[path] = stored[path]
            origins[path] = str(stored_origins.get(path, ORIGIN_FROZEN))
            continue
        own = row.config.get(path)
        if path == "site_code":
            values[path] = own or "home"
            origins[path] = ORIGIN_CONNECTION if own else ORIGIN_FALLBACK
        elif path == "routing_scope":
            values[path] = own or v2_namespace(row.name, row.type)
            origins[path] = ORIGIN_CONNECTION if own else ORIGIN_FALLBACK
        elif path == "l2fabric":
            values[path] = own or settings.l2fabric_of(row.name)
            origins[path] = ORIGIN_CONNECTION if own else ORIGIN_APPLICATION
        elif own is not None:
            values[path] = own
            origins[path] = ORIGIN_CONNECTION
    if "l3dom" in stored:
        values["l3dom"] = stored["l3dom"]
        origins["l3dom"] = ORIGIN_FROZEN
    return {"values": values, "origins": origins}


# --- convenience entry points -------------------------------------------------------------


async def resolve_for_cli(
    store: Store, settings: Settings, source: str, host: str | None = None
) -> EffectiveCollection:
    """The resolution adapter of the CLI."""
    row = await store.get_source(source)
    if row is None:
        raise ResolutionError(f"no source {source!r}")
    device = None
    if host:
        device = next((d for d in await store.list_devices(source) if d.host == host), None)
    context = await execution_context(store)
    sites = {site.code: site for site in await store.list_sites()}
    if not has_inventory(store):
        return resolve_v1(row, settings, device=device, sites=sites).effective
    async with store.inventory().transaction() as tx:
        resolver = Resolver(tx, settings, context=context)
        resolved = await resolver.resolve(
            row, device=device, host=host if device is None and host is not None else None, sites=sites
        )
    return resolved.effective


# --- skip fingerprint and authority ----------------------------------------------------------


def fingerprint_for(resolved: ResolvedCollection | None, raw_sha: str) -> str:
    """The value that `device_status.last_raw_sha` holds for a unit. Under v1 it
    is the payload hash. Under v2 it is the skip fingerprint of the payload hash,
    the normalization revision and the placement generation."""
    if resolved is None or resolved.effective.resolver_version < RESOLVER_V2:
        return raw_sha
    return skip_fingerprint(raw_sha, resolved.normalization_revision, resolved.placement_generation)


def authority_verdict(sections: Mapping[str, SectionOutcome], authoritative: Sequence[str] = ()) -> Authority:
    """A batch that writes no sections (every orchestrator
    collector) is complete for membership. A collector that writes
    sections is complete when `section_verdict` is ok and partial otherwise."""
    if not sections:
        return Authority.COMPLETE
    verdict = section_verdict(dict(sections), tuple(authoritative))
    return Authority.COMPLETE if verdict == "ok" else Authority.PARTIAL


# --- publication seam ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ObservedDevice:
    """One graph device that a target reported in a run. It holds the graph uid
    and the reported location that the collector attached."""

    graph_uid: str
    reported_location_id: str | None = None
    reported_location_name: str = ""
    hostname: str = ""
    platform: str = ""
    management_address: str = ""
    notes: dict[str, Any] | None = None


class ObservationService(Protocol):
    """The seam between execution and the inventory read model.

    `stage_observations` is called once per target result of a run, inside
    one repository transaction that the caller opened. It takes the snapshot
    key of the run, the execution key of the target, the devices that the
    target reported and the authority verdict. `succeeded` is False for a
    target that failed. The observations are then empty, and the prior claims
    stay as stale evidence.
    `publish` is called after the snapshot pointer has moved. `reconcile` is
    called at startup with the latest published snapshot key.
    """

    async def stage_observations(
        self,
        txn: InventoryTx,
        snapshot_key: str,
        target_key: tuple[str, str],
        observations: Sequence[StagedDevice],
        authority: Authority,
        *,
        succeeded: bool = True,
        attempted_at: datetime | None = None,
    ) -> Any: ...

    async def compose_placements(self, snapshot_key: str) -> Any: ...

    async def publish(self, snapshot_key: str) -> Any: ...

    async def reconcile(self, latest_snapshot_key: str | None) -> Any: ...


class NoopObservationService:
    """The observation service while the inventory is not activated.
    `stage_observations`, `publish` and `reconcile` write nothing.
    `compose_placements` raises."""

    async def stage_observations(
        self,
        txn: InventoryTx,
        snapshot_key: str,
        target_key: tuple[str, str],
        observations: Sequence[StagedDevice],
        authority: Authority,
        *,
        succeeded: bool = True,
        attempted_at: datetime | None = None,
    ) -> None:
        return None

    async def compose_placements(self, snapshot_key: str) -> Any:
        raise RuntimeError("inventory is not activated")

    async def publish(self, snapshot_key: str) -> None:
        return None

    async def reconcile(self, latest_snapshot_key: str | None) -> None:
        return None


NOOP_OBSERVATIONS = NoopObservationService()
_observation_service: ObservationService | None = None


def set_observation_service(service: ObservationService | None) -> None:
    """Register the observation service, or clear it with None."""
    global _observation_service
    _observation_service = service


def observation_service(context: ExecutionContext) -> ObservationService:
    if not context.activated:
        return NOOP_OBSERVATIONS
    if _observation_service is None:
        raise RuntimeError("activated inventory requires an observation service")
    return _observation_service


async def reconcile_on_startup(store: Store, latest_snapshot_key: str | None = None) -> None:
    """Reconcile against `latest_snapshot_key`. Without it, an activated inventory
    uses the snapshot key of the latest published publication, or else the
    read-model snapshot key."""
    from hst.app.inventory.contracts import PublicationState

    context = await execution_context(store)
    if latest_snapshot_key is None and context.activated:
        async with store.inventory().transaction() as tx:
            published = await tx.latest_publication(PublicationState.PUBLISHED)
            latest_snapshot_key = published.snapshot_key if published else context.read_model_snapshot_key
    await observation_service(context).reconcile(latest_snapshot_key)


def observed_devices(collector: Any) -> list[ObservedDevice]:
    """The devices that one collector reported after its load. Each device has its
    uid, the reported location that the orchestrator attached and its facts."""
    uids = getattr(collector, "last_device_uids", None) or ()
    locations = getattr(collector, "last_device_locations", None) or {}
    facts = getattr(collector, "last_device_facts", None) or {}
    out: list[ObservedDevice] = []
    for uid in sorted(set(uids)):
        loc = locations.get(uid)
        loc_id: str | None = None
        loc_name = ""
        if isinstance(loc, tuple | list) and loc:
            loc_id = str(loc[0]) if loc[0] is not None else None
            loc_name = str(loc[1]) if len(loc) > 1 and loc[1] is not None else ""
        elif isinstance(loc, str):
            loc_id = loc
        fact = facts.get(uid, {})
        out.append(
            ObservedDevice(
                uid,
                loc_id,
                loc_name,
                hostname=str(fact.get("hostname") or ""),
                platform=str(fact.get("platform") or ""),
                management_address=str(fact.get("management_address") or ""),
                notes={"warnings": list(fact["warnings"])} if fact.get("warnings") else None,
            )
        )
    return out


def deep_redacted(value: Any, secret_values: Sequence[str]) -> Any:
    """Replace every occurrence of a secret value inside a nested value."""
    if isinstance(value, dict):
        return {k: deep_redacted(v, secret_values) for k, v in value.items()}
    if isinstance(value, list):
        return [deep_redacted(v, secret_values) for v in value]
    if isinstance(value, str):
        for secret in secret_values:
            if secret:
                value = value.replace(secret, REDACTED)
        return value
    return value


def copy_without_secrets(payload: Mapping[str, Any], collector_type: str) -> dict[str, Any]:
    return redact_paths(deepcopy(dict(payload)), _fm.secret_paths(collector_type))
