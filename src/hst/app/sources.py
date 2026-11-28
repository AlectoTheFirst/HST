"""Platform glue between source rows and collector classes."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Awaitable, Callable, Coroutine, Mapping
from copy import deepcopy
from typing import TYPE_CHECKING, Any, TypeVar, get_args

from pydantic import BaseModel, SecretStr

from hst import collectors as coll
from hst.app import source_egress
from hst.app.crypto import SecretKeyError, decrypt_secrets, dek, encrypt_secrets
from hst.app.secrets import FernetResolver, SecretResolver
from hst.app.source_egress import CredentialsRequired as CredentialsRequired
from hst.app.store import Device, Site, Source, Store
from hst.collectors.base import Collector, SourceConfig
from hst.core import Settings, redaction
from hst.core.identity import DeviceResolver, Kind, MemoryResolver, identifier

if TYPE_CHECKING:
    from hst.app.inventory.collection import ResolvedCollection

NAME_PATTERN = r"^[a-z0-9-]{2,32}$"

# The v1 resolver version is recorded in the normalization context of every payload.
RESOLVER_VERSION = "1"

T = TypeVar("T")


class StoreResolver:
    """The device identity registry in the store,
    for the collectors of one run.

    A collector resolves on the builder thread of the run. Each call runs the
    store coroutine on the event loop and waits for its result. The resolver
    asks the store for each identifier 1 time per run. A rename takes effect
    at the next run. `run_id` is the run that a mint records. It is None
    outside a run.
    """

    def __init__(
        self, store: Store, loop: asyncio.AbstractEventLoop, generation: int, run_id: int | None = None
    ) -> None:
        self._store = store
        self._loop = loop
        self._generation = generation
        self.run_id = run_id
        self._uids: dict[tuple[str, str], str] = {}
        self._bound: set[tuple[str, str, str]] = set()
        self._lock = threading.Lock()

    @classmethod
    async def open(cls, store: Store, run_id: int | None = None) -> StoreResolver:
        """A resolver on the running loop, with the generation read now."""
        return cls(store, asyncio.get_running_loop(), await store.identity_generation(), run_id)

    def _call(self, coro: Coroutine[Any, Any, T]) -> T:
        try:
            running: asyncio.AbstractEventLoop | None = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is self._loop:
            coro.close()
            raise RuntimeError("the device identity registry cannot be called from its own event loop")
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result()

    def resolve_device(self, kind: Kind, value: str, hostname: str | None) -> str:
        key = (kind, identifier(kind, value))
        with self._lock:
            found = self._uids.get(key)
        if found is None:
            found = self._call(self._store.resolve_device(kind, value, hostname, self.run_id))
            with self._lock:
                self._uids[key] = found
        return found

    def bind_device(self, uid: str, kind: Kind, value: str) -> None:
        bound = (uid, kind, identifier(kind, value))
        with self._lock:
            if bound in self._bound:
                return
        self._call(self._store.bind_device(uid, kind, value, self.run_id))
        with self._lock:
            self._bound.add(bound)

    def identity_generation(self) -> int:
        return self._generation


async def registry_snapshot(store: Store) -> MemoryResolver:
    """An in-memory copy of the device identity registry for a collector that
    must not write to the registry.

    A replay into a scratch graph and a repair of side tables use the copy. An
    identifier that the registry does not hold is minted in memory only.
    """
    rows = await store.device_identities()
    return MemoryResolver(((r.uid, r.kind, r.value) for r in rows), await store.identity_generation())


def resolve_normalization(
    row: Source,
    settings: Settings,
    *,
    device: Device | None = None,
    sites: dict[str, Site] | None = None,
) -> tuple[dict, dict[str, str]]:
    """Resolve the normalization fields `site_code`, `routing_scope` and
    `l2fabric` of a source row. Returns the payload and the origin of each field.

    A value in the config of the row wins. When `source_routing_namespace` is
    None, the routing scope falls back to the `routing_scope` of the site and
    then to the site code. Otherwise it falls back to that namespace. The L2
    fabric falls back to `settings.l2fabric_of`. A device states none of the 3
    fields. No other parameter of the site enters the payload.
    """
    payload = device_config(row, device) if device is not None else deepcopy(row.config)
    site = row.config.get("site_code") or "home"
    site_row = (sites or {}).get(site)
    site_params = (site_row.params if site_row is not None else {}) or {}
    origins = {"site": "group"}

    def choose(field: str, fallback: str, fallback_origin: str, *, from_site: bool = False) -> str:
        if row.config.get(field):
            origins[field] = "group"
            return row.config[field]
        if from_site and site_params.get(field):
            origins[field] = "site"
            return site_params[field]
        origins[field] = fallback_origin
        return fallback

    payload["site_code"] = site
    own_scope = source_routing_namespace(row)
    if own_scope is None:
        # The routing scope falls back to the site's default and then to the site code.
        payload["routing_scope"] = choose("routing_scope", site, "site_code", from_site=True)
    else:
        # A controller row with no site falls back to its own namespace.
        payload["routing_scope"] = choose("routing_scope", own_scope, "source")
    # The L2 fabric has no site fallback. The setting `l2_fabrics` lists the
    # member sources of each fabric.
    payload["l2fabric"] = choose("l2fabric", settings.l2fabric_of(row.name), "application")
    payload["resolved_origins"] = origins
    return payload, origins


def source_routing_namespace(row: Source) -> str | None:
    """The routing scope that a controller row falls back to when its config
    has none.

    It is `inventory:<row name>` for a non-group row whose collector reads the
    routing scope. It is None for a group and for a collector that does not
    read the scope.
    """
    from hst.app.inventory.normalization import v2_namespace

    if is_group(row.type):
        return None
    return v2_namespace(row.name, row.type)


def backfill_routing_scope(row: Source) -> str | None:
    """The routing scope that the v1 backfill writes into a row that has no
    `routing_scope` key.

    It is the site code of the row. Without a site code it is None for a row
    that has a routing namespace and "home" for each other row.
    """
    site = row.config.get("site_code")
    if site:
        return site
    if source_routing_namespace(row) is not None:
        return None
    return "home"


def shared_routing_scope_warnings(row: Source, rows: list[Source], scopes: Mapping[str, str]) -> list[str]:
    """One warning when another controller row resolves to the routing scope
    that `row` resolves to. `scopes` maps each row name to its effective
    routing scope. The comparison covers the non-group rows whose collector
    reads the scope. 2 such rows on one scope write one Prefix node and one
    address node for a subnet that both use."""
    from hst.app.inventory.normalization import READS_ROUTING_SCOPE

    def compared(r: Source) -> bool:
        return not is_group(r.type) and r.type in READS_ROUTING_SCOPE and bool(scopes.get(r.name))

    if not compared(row):
        return []
    scope = scopes[row.name]
    peers = sorted(r.name for r in rows if r.name != row.name and compared(r) and scopes[r.name] == scope)
    if not peers:
        return []
    return [
        f"routing scope {scope!r} is also the routing scope of {', '.join(peers)}: prefixes and "
        "addresses these sources report for one subnet are one node"
    ]


async def routing_scope_warnings(
    store: Store,
    settings: Settings,
    name: str,
    read: Callable[[Source], Awaitable[Source]] | None = None,
) -> list[str]:
    """`shared_routing_scope_warnings` for the stored row `name`, as a source
    save returns it. `read` returns each row with the configuration that it
    collects with. Under resolver v2 these are the frozen normalization
    values. Without `read` the rows are compared as stored."""
    rows = await store.list_sources()
    if read is not None:
        rows = [await read(r) for r in rows]
    row = next((r for r in rows if r.name == name), None)
    if row is None:
        return []
    sites = {site.code: site for site in await store.list_sites()}
    scopes = {
        r.name: str(resolve_normalization(r, settings, sites=sites)[0]["routing_scope"] or "") for r in rows
    }
    return shared_routing_scope_warnings(row, rows, scopes)


def resolve_device_sites(
    placed: dict[str, str],
    mappings: list,
    sources: dict[str, Source],
    bound: dict[tuple[str, str], str],
) -> dict[str, tuple[str, str]]:
    """The site of each collected device and the origin of the placement.

    Returns a dict from device uid to (site code, origin). The origin is
    "group", "hand" or "location". A device absent from the result is unplaced.

    A group device sits at the site of its group.

    A controller device sits at the site where an operator placed it by hand.
    Without a hand placement it sits at the site that its reported location is
    bound to.

    The newest observation places a uid that more than one target observed.
    """
    resolved: dict[str, tuple[str, str]] = {}
    for mapping in sorted(mappings, key=lambda m: m.updated_at):
        row = sources.get(mapping.source)
        if row is None:
            continue
        if is_group(row.type):
            # A hand placement of a group device is ignored.
            site = row.config.get("site_code")
            if site:
                resolved[mapping.device_uid] = (site, "group")
            continue
        site = placed.get(mapping.device_uid)
        if site:
            resolved[mapping.device_uid] = (site, "hand")
            continue
        site = bound.get((mapping.source, mapping.location_id))
        if site:
            resolved[mapping.device_uid] = (site, "location")
    return resolved


def redacted(text: str, secrets: dict[str, str]) -> str:
    """Replace any stored secret value that appears in `text` with `***`."""
    return redaction.redact_known(text, secrets.values())


def _model_variants(annotation: Any) -> list[type[BaseModel]]:
    """Every BaseModel reachable from a field annotation, unwrapping Annotated
    metadata and union members. A discriminated union contributes all of its
    variants."""
    found: list[type[BaseModel]] = []
    stack = [annotation]
    while stack:
        current = stack.pop()
        if isinstance(current, type) and issubclass(current, BaseModel):
            found.append(current)
            continue
        args = get_args(current)
        if args:
            # pop() yields the args in declared order.
            stack.extend(a for a in reversed(args) if a is not type(None))
    return found


def secret_paths(model_cls: type[BaseModel], prefix: str = "") -> set[str]:
    """Dotted paths of every SecretStr field, recursing into nested models.

    The paths cover every union variant."""
    paths: set[str] = set()
    for name, field in model_cls.model_fields.items():
        path = f"{prefix}{name}"
        if field.annotation is SecretStr:
            paths.add(path)
            continue
        for variant in _model_variants(field.annotation):
            paths |= secret_paths(variant, prefix=f"{path}.")
    return paths


secret_fields = secret_paths


def secret_paths_for_payload(model_cls: type[BaseModel], payload: dict) -> set[str]:
    """Secret paths this particular payload calls for.

    A union field contributes only the variant that the `method` of the payload
    selects. Without a `method`, it contributes the first variant. An optional
    model field that the payload omits (`jump_host`) contributes nothing."""
    paths: set[str] = set()
    for name, field in model_cls.model_fields.items():
        if field.annotation is SecretStr:
            paths.add(name)
            continue
        variants = _model_variants(field.annotation)
        if not variants:
            continue
        branch = payload.get(name)
        if type(None) in get_args(field.annotation) and not isinstance(branch, dict):
            continue
        chosen = variants
        if len(variants) > 1:
            method = branch.get("method") if isinstance(branch, dict) else None
            selected = [
                v
                for v in variants
                if v.model_fields.get("method") is not None and v.model_fields["method"].default == method
            ]
            chosen = selected or [variants[0]]
        for variant in chosen:
            sub = secret_paths_for_payload(variant, branch if isinstance(branch, dict) else {})
            paths |= {f"{name}.{p}" for p in sub}
    return paths


def split_secrets(model: BaseModel, prefix: str = "") -> tuple[dict, dict]:
    """Split a validated model instance into (non-secret config, secrets by path).

    A union field contributes only the chosen variant."""
    config: dict[str, Any] = {}
    secrets: dict[str, str] = {}
    for name, field in model.__class__.model_fields.items():
        value = getattr(model, name)
        if field.exclude_if is not None and field.exclude_if(value):
            continue
        path = f"{prefix}{name}"
        if isinstance(value, SecretStr):
            secrets[path] = value.get_secret_value()
        elif isinstance(value, BaseModel):
            nested_config, nested_secrets = split_secrets(value, prefix=f"{path}.")
            config[name] = nested_config
            secrets |= nested_secrets
        else:
            config[name] = value
    return config, secrets


def inject_secrets(config: dict, secrets: dict[str, str]) -> dict:
    """Re-attach secrets at their recorded dotted paths. Returns a new dict
    and leaves `config` unchanged.

    A secret at auth.password with a non-dict `auth` in config raises
    ValueError."""
    merged = deepcopy(config)
    for path, value in secrets.items():
        head, _, tail = path.partition(".")
        if not tail:
            merged[head] = value
            continue
        branch = merged.setdefault(head, {})
        if not isinstance(branch, dict):
            raise ValueError(f"config and secrets disagree on the shape of {head!r}")
        merged[head] = inject_secrets(branch, {tail: value})
    return merged


def source_types() -> list[dict]:
    return [
        {"type": name, "kind": cls.KIND, "schema": cls.ConfigModel.model_json_schema()}
        for name, cls in sorted(coll.REGISTRY.items())
    ]


def validate_source(type_: str, payload: dict) -> tuple[dict, dict]:
    """Validate a submitted config against its type's model and split out secrets.

    Raises KeyError for an unknown type and pydantic.ValidationError for a payload
    that fails the model.
    """
    model_cls = coll.REGISTRY[type_].ConfigModel
    return split_secrets(model_cls(**payload))


def build_collector(
    row: Source,
    settings: Settings,
    resolver: SecretResolver | None = None,
    *,
    sites: dict[str, Site] | None = None,
    sources: Mapping[str, Source] | None = None,
    effective: ResolvedCollection | None = None,
    identity: DeviceResolver | None = None,
) -> Collector:
    """`sources` is every configured source row by name, for a collector whose
    config names another source (`Collector.link_sources`). Without the rows,
    the collector reports the missing link at normalize time.

    `effective` is a target already resolved by
    `app/inventory/collection.Resolver` (resolver v2, whole-profile
    assignment, frozen normalization, the pinned credential version). When it
    is given, the v1 resolution below is not run and the row's own secrets are
    not read.

    `identity` is the device identity registry the collector resolves its
    Device uids against (`StoreResolver` for a run, `registry_snapshot` for a
    replay). Without it the collector keeps its in-memory default."""
    cls = coll.REGISTRY[row.type]
    if effective is not None:
        payload = _effective_payload(row, effective)
    else:
        resolver = resolver or FernetResolver(dek(settings))
        resolved, _origins = resolve_normalization(row, settings, sites=sites)
        payload = inject_secrets(resolved, resolver.resolve(row))
        payload["source_name"] = row.name
    if sources is not None:
        payload = cls.link_sources(payload, sources)
    return _with_identity(cls(cls.ConfigModel(**payload), settings), identity)


def _with_identity(collector: Collector, identity: DeviceResolver | None) -> Collector:
    if identity is not None:
        collector.identity = identity
    return collector


def kind_of(type_: str) -> str:
    """ "group" or "orchestrator", as the collector class declares it."""
    return coll.REGISTRY[type_].KIND


def is_group(type_: str) -> bool:
    """True when the type is a group. Only a group has a device list.

    False for a type the registry does not know.
    """
    return type_ in coll.REGISTRY and kind_of(type_) == "group"


def device_config(row: Source, device: Device) -> dict:
    """The non-secret config of a device. It is the config of the group with
    the `host`, the `port` and the `host_key` of the device."""
    payload = deepcopy(row.config)
    payload["host"] = device.host
    if device.port is not None:
        payload["port"] = device.port
    payload["host_key"] = device.host_key
    return payload


def build_device_collector(
    row: Source,
    device: Device,
    settings: Settings,
    resolver: SecretResolver | None = None,
    *,
    sites: dict[str, Site] | None = None,
    sources: Mapping[str, Source] | None = None,
    effective: ResolvedCollection | None = None,
    identity: DeviceResolver | None = None,
) -> Collector:
    """`build_collector` for one device of a group. The payload is the config
    of the group with the address of the device. `effective` is a v2
    resolution of the target of the device. `identity` is the device identity
    registry."""
    cls = coll.REGISTRY[row.type]
    if effective is not None:
        payload = _effective_payload(row, effective)
    else:
        resolver = resolver or FernetResolver(dek(settings))
        resolved, _origins = resolve_normalization(row, settings, device=device, sites=sites)
        payload = inject_secrets(resolved, resolver.resolve(row))
        payload["source_name"] = row.name
    if sources is not None:
        payload = cls.link_sources(payload, sources)
    return _with_identity(cls(cls.ConfigModel(**payload), settings), identity)


def _effective_payload(row: Source, effective: ResolvedCollection) -> dict:
    """The collector payload of a v2 resolution.

    The resolver injects the secrets of the credential version with
    `with_secrets=True`. A resolution without them raises ValueError.
    """
    if effective.payload is None:
        raise ValueError(f"{row.name}: resolution carries no secrets; resolve with_secrets=True to build")
    payload = deepcopy(effective.payload)
    payload["source_name"] = row.name
    return payload


def model_for(type_: str) -> type[SourceConfig]:
    return coll.REGISTRY[type_].ConfigModel


class SecretsUnreadable(Exception):
    """Raised by merge_config when the stored secrets blob does not decrypt under
    the current key and the overlay does not supply every secret field of the
    type."""

    def __init__(self, missing: set[str]):
        self.missing = missing
        fields = ", ".join(sorted(missing))
        super().__init__(f"stored credentials cannot be decrypted; missing secret fields: {fields}")


def _path_missing(payload: dict, path: str) -> bool:
    node: Any = payload
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return True
        node = node[part]
    return False


def merge_config(row: Source, overlay: dict, key: str) -> tuple[dict, bytes]:
    """The PATCH of a source config for the API and the CLI.

    The function decrypts the stored secrets, applies the overlay, removes
    `source_name`, validates the result and encrypts the secrets. Raises
    ValidationError, SecretsUnreadable or CredentialsRequired.

    When the stored blob does not decrypt under `key`, the overlay must hold
    every secret field of the type. Otherwise SecretsUnreadable lists the
    missing paths.

    When the result moves the endpoint or weakens the TLS check
    (`source_egress.change`), the overlay must hold every stored secret that the
    result keeps. Otherwise CredentialsRequired lists the kept paths.
    """
    try:
        stored_secrets = decrypt_secrets(key, row.secrets)
    except SecretKeyError:
        stored_secrets = None
    merged = inject_secrets(row.config, stored_secrets or {})
    merged = _overlay(merged, overlay)
    merged.pop("source_name", None)
    if stored_secrets is None:
        missing = {
            path
            for path in secret_paths_for_payload(model_for(row.type), merged)
            if _path_missing(merged, path)
        }
        if missing:
            raise SecretsUnreadable(missing)
    config, secrets = validate_source(row.type, merged)
    if stored_secrets:
        given = {path for path, value in _flat(overlay).items() if isinstance(value, str) and value}
        kept = [path for path, value in secrets.items() if value and stored_secrets.get(path) == value]
        source_egress.require_secrets(row.type, _stored_config(row, stored_secrets), config, kept, given)
    return config, encrypt_secrets(key, secrets)


def _flat(tree: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, value in tree.items():
        if isinstance(value, Mapping):
            out.update(_flat(value, f"{prefix}{name}."))
        else:
            out[f"{prefix}{name}"] = value
    return out


def _stored_config(row: Source, secrets: dict[str, str]) -> dict:
    """The stored config with the defaults of the model, or the stored config
    as it is when it no longer validates."""
    try:
        return validate_source(row.type, inject_secrets(row.config, secrets))[0]
    except (KeyError, ValueError):  # pydantic's ValidationError is a ValueError
        return row.config


def _overlay(base: dict, overlay: dict) -> dict:
    """Recursive dict overlay. A PATCH of `auth.password` alone keeps
    `auth.username`. A non-dict value replaces the stored value. A dict whose
    `method` differs from the stored `method` replaces the stored dict."""
    out = deepcopy(base)
    for key, value in overlay.items():
        if (
            isinstance(value, dict)
            and isinstance(out.get(key), dict)
            and value.get("method", out[key].get("method")) == out[key].get("method")
        ):
            out[key] = _overlay(out[key], value)
        else:
            out[key] = value
    return out
