"""Routing context inspection and user routing groups."""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from hst.app.inventory.contracts import (
    ApplyRequest,
    ApplyResponse,
    ApplyResult,
    ApplyStatus,
    DeviceRoutingResponse,
    ErrorCode,
    Generation,
    PreviewMember,
    PreviewMemberKind,
    PreviewOperation,
    PreviewRequest,
    PreviewResponse,
    RouteTargetDirection,
    RouteTargetView,
    RoutingContextView,
    RoutingGroupCreate,
    RoutingGroupPatch,
    RoutingGroupRef,
    RoutingGroupView,
    RoutingMembersChange,
    RoutingMemberView,
)
from hst.app.inventory.repository import (
    InventoryError,
    InventoryRepository,
    InventoryTx,
    NotFound,
)
from hst.app.store import InventoryRoutingGroup, InventoryRoutingMember
from hst.core import uid as uidmod
from hst.core.model import Batch

EVENT_ENTITY = "routing_group"
PREVIEW_TTL = timedelta(minutes=10)
OPERATION = PreviewOperation.EDIT_ROUTING_MEMBERS


class MembershipBasis:
    DECLARED = "declared"
    RT_COMPONENT = "rt-component"
    DECLARED_AND_RT = "declared+rt-component"
    LEGACY = "legacy-l3domain"
    NONE = "none"


class ContextKind:
    VRF = "vrf"
    SDWAN_SEGMENT = "sdwan-segment"
    VSX_PREFIX = "vsx-"


# Uid prefixes the collectors write (core/uid.py velocloud(), core/firewall_context.py
# _uid("firewall-instance", ...)). `context_kind` reads identity from these prefixes.
_VELOCLOUD_PREFIX = "vco:"
_FIREWALL_INSTANCE_PREFIX = "firewall-instance:"
_DECLARED_BASIS = "declared"
_RT_BASIS = "rt-component"


class ObservedStoreUnavailable(InventoryError):
    code = ErrorCode.OBSERVED_STORE_UNAVAILABLE
    status = 503


class Forbidden(InventoryError):
    code = ErrorCode.FORBIDDEN
    status = 403


# --- typed graph rows ------------------------------------------------------------------


@dataclass(frozen=True)
class Membership:
    domain_uid: str
    domain_name: str
    basis: str


@dataclass(frozen=True)
class ObservedContext:
    """One `VrfInstance` of a snapshot with its owner device, its context, its domain
    memberships and its route targets."""

    context_uid: str
    name: str
    table_id: str | None
    is_global: bool | None
    rd: str | None
    owner_uid: str
    owner_platform: str | None
    enterprise_id: str | None
    enterprise_name: str | None
    instance_uid: str | None
    instance_kind: str | None
    instance_name: str | None
    authority: str | None
    domain: str | None
    vsid: int | None
    appliance_uid: str | None
    memberships: tuple[Membership, ...]
    legacy_domains: tuple[Membership, ...]
    imports: tuple[str, ...]
    exports: tuple[str, ...]


@dataclass(frozen=True)
class SegmentRow:
    uid: str
    name: str | None
    segment_id: str | None
    enterprise_id: str | None
    enterprise_name: str | None


class GraphReader(Protocol):
    async def current_snapshot(self) -> str | None: ...
    async def has_snapshot(self, snapshot_key: str) -> bool: ...
    async def contexts_of(self, device_uid: str, snapshot_key: str) -> list[ObservedContext]: ...
    async def segments(self, uids: Sequence[str], snapshot_key: str) -> dict[str, SegmentRow]: ...
    async def present(self, context_uids: Sequence[str], snapshot_key: str) -> dict[str, str]: ...


# --- Cypher ---------------------------------------------------------------------------------

# Every query reads one run. Each node has `n.collection_ts = $snap` and `NOT :Retired`,
# the anchor is an `:Obj` node and each edge has `_retired_at IS NULL`. The queries follow
# relationships between endpoints keyed by uid.
#
# Ownership is the `OWNED_BY` edge of the collector (collectors/util.py VrfDomains.add,
# checkpoint_gateway.py normalize_checkpoint_gateway). For a VrfInstance that no device
# owns, the owner is the device of an interface in the table
# (`Interface -[:ON]-> Device`, `Interface -[:IN_VRF]-> VrfInstance`).
_CONTEXTS = """
CALL {
  MATCH (v:VrfInstance)-[o:OWNED_BY]->(d:Device:Obj {uid: $dev, collection_ts: $snap})
  WHERE v.collection_ts = $snap
    AND NOT v:Retired AND NOT d:Retired AND o._retired_at IS NULL
  RETURN v, d
  UNION
  MATCH (i:Interface)-[on:ON]->(d:Device:Obj {uid: $dev, collection_ts: $snap}),
        (i)-[iv:IN_VRF]->(v:VrfInstance)
  WHERE v.collection_ts = $snap
    AND i.collection_ts = $snap
    AND NOT v:Retired AND NOT d:Retired AND NOT i:Retired
    AND on._retired_at IS NULL AND iv._retired_at IS NULL
    AND NOT (v)-[:OWNED_BY]->(:Device)
  RETURN v, d
}
WITH DISTINCT v, d
OPTIONAL MATCH (v)-[ic:IN_CONTEXT]->(ctx)
  WHERE ic._retired_at IS NULL AND ctx.collection_ts = $snap AND NOT ctx:Retired
OPTIONAL MATCH (ctx)-[ro:RUNS_ON]->(app:Device)
  WHERE ro._retired_at IS NULL AND app.collection_ts = $snap AND NOT app:Retired
OPTIONAL MATCH (v)-[m:MEMBER_OF]->(rd:RoutingDomain)
  WHERE m._retired_at IS NULL AND rd.collection_ts = $snap AND NOT rd:Retired
OPTIONAL MATCH (v)-[rl:REALIZES]->(l3:L3Domain)
  WHERE rl._retired_at IS NULL AND l3.collection_ts = $snap AND NOT l3:Retired
OPTIONAL MATCH (v)-[im:IMPORTS]->(rti:RouteTarget)
  WHERE im._retired_at IS NULL AND rti.collection_ts = $snap AND NOT rti:Retired
OPTIONAL MATCH (v)-[ex:EXPORTS]->(rte:RouteTarget)
  WHERE ex._retired_at IS NULL AND rte.collection_ts = $snap AND NOT rte:Retired
RETURN v.uid AS uid, v.name AS name, v.table_id AS table_id, v.is_global AS is_global, v.rd AS rd,
       d.uid AS owner_uid, d.platform AS owner_platform,
       d.enterprise_logical_id AS enterprise_id, d.enterprise_name AS enterprise_name,
       ctx.uid AS instance_uid, ctx.kind AS instance_kind, ctx.name AS instance_name,
       ctx.authority AS authority, ctx.domain AS domain,
       ro.vsid AS vsid, app.uid AS appliance_uid,
       collect(DISTINCT {uid: rd.uid, name: rd.name, basis: m.basis}) AS memberships,
       collect(DISTINCT {uid: l3.uid, name: l3.name}) AS legacy_domains,
       collect(DISTINCT rti.value) AS imports, collect(DISTINCT rte.value) AS exports
ORDER BY uid, instance_uid
"""

_SEGMENTS = """
MATCH (s:SdwanSegment:Obj)
WHERE s.uid IN $uids AND s.collection_ts = $snap AND NOT s:Retired
RETURN s.uid AS uid, s.name AS name, s.segment_id AS segment_id,
       s.enterprise_logical_id AS enterprise_id, s.enterprise_name AS enterprise_name
"""

_PRESENT = """
MATCH (v:VrfInstance:Obj)
WHERE v.uid IN $uids AND v.collection_ts = $snap AND NOT v:Retired
OPTIONAL MATCH (v)-[o:OWNED_BY]->(d:Device)
  WHERE o._retired_at IS NULL AND d.collection_ts = $snap AND NOT d:Retired
RETURN v.uid AS uid, d.uid AS owner_uid
"""

_HAS_SNAPSHOT = "MATCH (n:Obj {collection_ts: $snap}) RETURN n.uid AS uid LIMIT 1"


def _clean(value: Any) -> str | None:
    return None if value is None else str(value)


def _memberships(rows: Iterable[Mapping[str, Any]], default_basis: str) -> tuple[Membership, ...]:
    out = []
    for r in rows:
        if not r or r.get("uid") is None:
            continue
        out.append(
            Membership(str(r["uid"]), str(r.get("name") or r["uid"]), str(r.get("basis") or default_basis))
        )
    return tuple(sorted(out, key=lambda m: (m.basis, m.domain_uid)))


def _context_from_row(row: Mapping[str, Any]) -> ObservedContext:
    vsid = row.get("vsid")
    return ObservedContext(
        context_uid=str(row["uid"]),
        name=str(row.get("name") or ""),
        table_id=_clean(row.get("table_id")),
        is_global=row.get("is_global") if isinstance(row.get("is_global"), bool) else None,
        rd=_clean(row.get("rd")),
        owner_uid=str(row["owner_uid"]),
        owner_platform=_clean(row.get("owner_platform")),
        enterprise_id=_clean(row.get("enterprise_id")),
        enterprise_name=_clean(row.get("enterprise_name")),
        instance_uid=_clean(row.get("instance_uid")),
        instance_kind=_clean(row.get("instance_kind")),
        instance_name=_clean(row.get("instance_name")),
        authority=_clean(row.get("authority")),
        domain=_clean(row.get("domain")),
        vsid=int(vsid) if isinstance(vsid, int) and not isinstance(vsid, bool) else None,
        appliance_uid=_clean(row.get("appliance_uid")),
        memberships=_memberships(row.get("memberships") or (), _DECLARED_BASIS),
        legacy_domains=_memberships(row.get("legacy_domains") or (), MembershipBasis.LEGACY),
        imports=tuple(sorted(str(v) for v in (row.get("imports") or ()) if v is not None)),
        exports=tuple(sorted(str(v) for v in (row.get("exports") or ()) if v is not None)),
    )


class Neo4jGraphReader:
    """The production reader. Each call opens one sync driver session on a worker thread."""

    def __init__(self, settings: Any, session_factory: Callable[[Any], Any] | None = None) -> None:
        self._settings = settings
        if session_factory is None:
            from hst.core import db as dbmod

            session_factory = dbmod.session
        self._session = session_factory

    def _run(self, fn: Callable[[Any], Any]) -> Any:
        try:
            with self._session(self._settings) as s:
                return fn(s)
        except InventoryError:
            raise
        except Exception as exc:  # driver, server and socket failures alike
            raise ObservedStoreUnavailable(f"observed store unavailable: {type(exc).__name__}") from exc

    async def current_snapshot(self) -> str | None:
        from hst.core import cycle as cyclemod

        cts = await asyncio.to_thread(self._run, cyclemod.current_ts_or_none)
        return None if cts is None else str(cts)

    async def has_snapshot(self, snapshot_key: str) -> bool:
        snap = _cts_of(snapshot_key)

        def read(s: Any) -> bool:
            rows = s.execute_read(lambda tx: tx.run(_HAS_SNAPSHOT, snap=snap).data())
            return bool(rows)

        return bool(await asyncio.to_thread(self._run, read))

    async def contexts_of(self, device_uid: str, snapshot_key: str) -> list[ObservedContext]:
        snap = _cts_of(snapshot_key)

        def read(s: Any) -> list[dict[str, Any]]:
            return list(s.execute_read(lambda tx: tx.run(_CONTEXTS, dev=device_uid, snap=snap).data()))

        rows = await asyncio.to_thread(self._run, read)
        return [_context_from_row(r) for r in rows]

    async def segments(self, uids: Sequence[str], snapshot_key: str) -> dict[str, SegmentRow]:
        if not uids:
            return {}
        snap = _cts_of(snapshot_key)

        def read(s: Any) -> list[dict[str, Any]]:
            return list(s.execute_read(lambda tx: tx.run(_SEGMENTS, uids=list(uids), snap=snap).data()))

        rows = await asyncio.to_thread(self._run, read)
        return {
            str(r["uid"]): SegmentRow(
                str(r["uid"]),
                _clean(r.get("name")),
                _clean(r.get("segment_id")),
                _clean(r.get("enterprise_id")),
                _clean(r.get("enterprise_name")),
            )
            for r in rows
        }

    async def present(self, context_uids: Sequence[str], snapshot_key: str) -> dict[str, str]:
        if not context_uids:
            return {}
        snap = _cts_of(snapshot_key)

        def read(s: Any) -> list[dict[str, Any]]:
            return list(
                s.execute_read(lambda tx: tx.run(_PRESENT, uids=list(context_uids), snap=snap).data())
            )

        rows = await asyncio.to_thread(self._run, read)
        return {str(r["uid"]): str(r.get("owner_uid") or "") for r in rows}


def _cts_of(snapshot_key: str) -> int:
    if not snapshot_key.isdigit():
        raise InventoryError("snapshot_key must be a run id")
    return int(snapshot_key)


class BatchGraphReader:
    """`GraphReader` over collector batches in memory, keyed by snapshot.

    The reader walks the joins of the Cypher queries over `Batch.nodes` and `Batch.rels` by
    uid. The parity tests and the callers that hold a normalized batch use it to inspect a
    snapshot without a database."""

    def __init__(self, batches: Mapping[str, Sequence[Batch]], current: str | None = None) -> None:
        self._snapshots = {key: _Index(list(items)) for key, items in batches.items()}
        self._current = (
            current if current is not None else (max(self._snapshots) if self._snapshots else None)
        )

    async def current_snapshot(self) -> str | None:
        return self._current

    async def has_snapshot(self, snapshot_key: str) -> bool:
        return snapshot_key in self._snapshots

    async def contexts_of(self, device_uid: str, snapshot_key: str) -> list[ObservedContext]:
        index = self._snapshots.get(snapshot_key)
        return [] if index is None else index.contexts_of(device_uid)

    async def segments(self, uids: Sequence[str], snapshot_key: str) -> dict[str, SegmentRow]:
        index = self._snapshots.get(snapshot_key)
        if index is None:
            return {}
        out: dict[str, SegmentRow] = {}
        for u in uids:
            props = index.nodes.get(("SdwanSegment", u))
            if props is not None:
                out[u] = SegmentRow(
                    u,
                    _clean(props.get("name")),
                    _clean(props.get("segment_id")),
                    _clean(props.get("enterprise_logical_id")),
                    _clean(props.get("enterprise_name")),
                )
        return out

    async def present(self, context_uids: Sequence[str], snapshot_key: str) -> dict[str, str]:
        index = self._snapshots.get(snapshot_key)
        if index is None:
            return {}
        out: dict[str, str] = {}
        for u in context_uids:
            if ("VrfInstance", u) in index.nodes:
                owners = index.out(u, "OWNED_BY")
                out[u] = owners[0][0] if owners else ""
        return out


class _Index:
    def __init__(self, batches: Sequence[Batch]) -> None:
        self.nodes: dict[tuple[str, str], dict[str, Any]] = {}
        self.by_uid: dict[str, dict[str, Any]] = {}
        self.labels: dict[str, set[str]] = {}
        self._out: dict[tuple[str, str], list[tuple[str, dict[str, Any]]]] = {}
        self._in: dict[tuple[str, str], list[tuple[str, dict[str, Any]]]] = {}
        for b in batches:
            for n in b.nodes:
                self.nodes[(n.label, n.uid)] = n.props
                self.by_uid.setdefault(n.uid, {}).update(n.props)
                self.labels.setdefault(n.uid, set()).add(n.label)
            for r in b.rels:
                props = {**r.key, **r.props}
                self._out.setdefault((r.start_uid, r.rel_type), []).append((r.end_uid, props))
                self._in.setdefault((r.end_uid, r.rel_type), []).append((r.start_uid, props))

    def out(self, start_uid: str, rel_type: str) -> list[tuple[str, dict[str, Any]]]:
        # The loader drops a rel whose endpoint is not in the load. `out` drops it too.
        return [(end, props) for end, props in self._out.get((start_uid, rel_type), []) if end in self.by_uid]

    def _owned_by(self, vrf_uid: str, device_uid: str) -> bool:
        """The OWNED_BY edge, or the interface fallback of `_CONTEXTS` for a
        table no device owns."""
        owners = [end for end, _ in self.out(vrf_uid, "OWNED_BY") if "Device" in self.labels.get(end, set())]
        if owners:
            return device_uid in owners
        for iface, _ in self._in.get((vrf_uid, "IN_VRF"), []):
            if "Interface" not in self.labels.get(iface, set()):
                continue
            if any(end == device_uid for end, _ in self.out(iface, "ON")):
                return True
        return False

    def contexts_of(self, device_uid: str) -> list[ObservedContext]:
        rows: list[dict[str, Any]] = []
        if device_uid not in self.by_uid or "Device" not in self.labels.get(device_uid, set()):
            return []
        for (label, vuid), props in self.nodes.items():
            if label != "VrfInstance":
                continue
            if not self._owned_by(vuid, device_uid):
                continue
            owner = self.by_uid[device_uid]
            instances: list[tuple[str | None, dict[str, Any]]] = list(self.out(vuid, "IN_CONTEXT")) or [
                (None, {})
            ]
            for instance_uid, _ in instances:
                inst = self.by_uid.get(instance_uid, {}) if instance_uid else {}
                runs_on = self.out(instance_uid, "RUNS_ON") if instance_uid else []
                app_uid: str | None = runs_on[0][0] if runs_on else None
                ro: dict[str, Any] = runs_on[0][1] if runs_on else {}
                rows.append(
                    {
                        "uid": vuid,
                        "name": props.get("name"),
                        "table_id": props.get("table_id"),
                        "is_global": props.get("is_global"),
                        "rd": props.get("rd"),
                        "owner_uid": device_uid,
                        "owner_platform": owner.get("platform"),
                        "enterprise_id": owner.get("enterprise_logical_id"),
                        "enterprise_name": owner.get("enterprise_name"),
                        "instance_uid": instance_uid,
                        "instance_kind": inst.get("kind"),
                        "instance_name": inst.get("name"),
                        "authority": inst.get("authority"),
                        "domain": inst.get("domain"),
                        "vsid": ro.get("vsid"),
                        "appliance_uid": app_uid,
                        "memberships": [
                            {"uid": end, "name": self.by_uid[end].get("name"), "basis": p.get("basis")}
                            for end, p in self.out(vuid, "MEMBER_OF")
                            if "RoutingDomain" in self.labels.get(end, set())
                        ],
                        "legacy_domains": [
                            {"uid": end, "name": self.by_uid[end].get("name")}
                            for end, _ in self.out(vuid, "REALIZES")
                            if "L3Domain" in self.labels.get(end, set())
                        ],
                        "imports": [self.by_uid[end].get("value") for end, _ in self.out(vuid, "IMPORTS")],
                        "exports": [self.by_uid[end].get("value") for end, _ in self.out(vuid, "EXPORTS")],
                    }
                )
        rows.sort(key=lambda r: (r["uid"], r["instance_uid"] or ""))
        return [_context_from_row(r) for r in rows]


# --- inspection ------------------------------------------------------------------------------


def context_kind(ctx: ObservedContext) -> str:
    """Return the kind of the context. The uid prefixes of the firewall instance and of the
    owner decide it."""
    if ctx.instance_uid is not None and ctx.instance_uid.startswith(_FIREWALL_INSTANCE_PREFIX):
        return f"{ContextKind.VSX_PREFIX}{ctx.instance_kind or 'context'}"
    if ctx.owner_uid.startswith(_VELOCLOUD_PREFIX):
        return ContextKind.SDWAN_SEGMENT
    return ContextKind.VRF


def segment_uid(ctx: ObservedContext) -> str | None:
    """Return the uid of the `SdwanSegment` that the collector wrote for the table of the context.

    The result is None when the context is not an SD-WAN segment or has no enterprise or no
    table id. velocloud.py writes the segment as `uid.velocloud(enterprise, "segment", seg_id)`.
    The VrfInstance of the edge has `table_id=seg_id`. The Device of the edge has the
    enterprise."""
    if context_kind(ctx) != ContextKind.SDWAN_SEGMENT or not ctx.enterprise_id or not ctx.table_id:
        return None
    return uidmod.velocloud(ctx.enterprise_id, "segment", ctx.table_id)


def membership_of(ctx: ObservedContext) -> tuple[str | None, str]:
    """(declared domain name, basis) from the edges the snapshot holds."""
    declared = [m for m in ctx.memberships if m.basis == _DECLARED_BASIS]
    derived = [m for m in ctx.memberships if m.basis == _RT_BASIS]
    if declared:
        basis = MembershipBasis.DECLARED_AND_RT if derived else MembershipBasis.DECLARED
        return declared[0].domain_name, basis
    if derived:
        return None, MembershipBasis.RT_COMPONENT
    if ctx.legacy_domains:
        return ctx.legacy_domains[0].domain_name, MembershipBasis.LEGACY
    return None, MembershipBasis.NONE


def context_view(
    ctx: ObservedContext,
    segments: Mapping[str, SegmentRow],
    groups: Sequence[InventoryRoutingGroup],
) -> RoutingContextView:
    kind = context_kind(ctx)
    declared, basis = membership_of(ctx)
    seg = segments.get(segment_uid(ctx) or "")
    identifier = ctx.name
    enterprise = segment = management_domain = None
    if kind == ContextKind.SDWAN_SEGMENT:
        identifier = ctx.table_id or ctx.name
        enterprise = ctx.enterprise_id
        segment = (seg.name if seg is not None and seg.name else None) or ctx.name
    elif kind.startswith(ContextKind.VSX_PREFIX):
        management_domain = ctx.domain
    targets = [RouteTargetView(value=v, direction=RouteTargetDirection.IMPORT) for v in ctx.imports] + [
        RouteTargetView(value=v, direction=RouteTargetDirection.EXPORT) for v in ctx.exports
    ]
    return RoutingContextView(
        authority=ctx.authority,
        instance_uid=ctx.instance_uid,
        vsid=ctx.vsid,
        enterprise_name=ctx.enterprise_name,
        derived_domains=[m.domain_uid for m in ctx.memberships if m.basis == _RT_BASIS],
        context_uid=ctx.context_uid,
        kind=kind,
        owner_uid=ctx.owner_uid,
        identifier=identifier,
        management_domain=management_domain,
        enterprise=enterprise,
        segment=segment,
        route_targets=targets,
        declared_domain=declared,
        membership_basis=basis,
        user_groups=[
            RoutingGroupRef(group_id=g.id, display_name=g.display_name, updated_at=g.updated_at)
            for g in groups
        ],
    )


# --- service -------------------------------------------------------------------------------------


@dataclass
class Actor:
    id: int
    name: str
    permissions: frozenset[str] = field(default_factory=frozenset)


def _now() -> datetime:
    return datetime.now(UTC)


def _digest(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


class RoutingService:
    """Inspection and annotation over one repository and one graph reader.
    Each write is one repository transaction that writes the intent row and its event."""

    def __init__(
        self,
        repo: InventoryRepository,
        graph: GraphReader,
        *,
        clock: Callable[[], datetime] = _now,
    ) -> None:
        self._repo = repo
        self._graph = graph
        self._clock = clock

    # --- snapshots ---

    async def _published_key(self, tx: InventoryTx) -> str | None:
        """The read-model snapshot key, else the graph pointer."""
        state = await tx.get_state()
        if state.read_model_snapshot_key:
            return state.read_model_snapshot_key
        return await self._graph.current_snapshot()

    async def _resolve_key(self, tx: InventoryTx, requested: str | None) -> str:
        if requested is not None:
            if not requested.isdigit():
                raise InventoryError("snapshot_key must be a run id")
            if not await self._graph.has_snapshot(requested):
                raise NotFound(f"snapshot {requested} is not published")
            return requested
        key = await self._published_key(tx)
        if key is None:
            raise NotFound("no published snapshot")
        return key

    # --- inspection ---

    async def device_routing(
        self, device_id: uuid.UUID, snapshot_key: str | None = None
    ) -> DeviceRoutingResponse:
        async with self._repo.transaction() as tx:
            device = await tx.get_device(device_id)
            if device is None:
                raise NotFound("device not found")
            key = await self._resolve_key(tx, snapshot_key)
            contexts = await self._graph.contexts_of(device.graph_uid, key)
            seg_uids = sorted({u for u in (segment_uid(c) for c in contexts) if u})
            segments = await self._graph.segments(seg_uids, key)
            groups = await tx.groups_for_contexts([c.context_uid for c in contexts])
        views = [context_view(c, segments, groups.get(c.context_uid, [])) for c in contexts]
        stamps = [g.updated_at for gs in groups.values() for g in gs]
        return DeviceRoutingResponse(
            device_id=device_id,
            snapshot_key=key,
            contexts=views,
            annotations_as_of=max(stamps) if stamps else None,
        )

    # --- groups ---

    async def _views(
        self, tx: InventoryTx, groups: Sequence[InventoryRoutingGroup]
    ) -> list[RoutingGroupView]:
        members: dict[uuid.UUID, list[InventoryRoutingMember]] = {}
        for g in groups:
            members[g.id] = await tx.list_routing_members(g.id)
        uids = sorted({m.context_uid for ms in members.values() for m in ms})
        key = await self._published_key(tx)
        present = await self._graph.present(uids, key) if key is not None and uids else {}
        return [_group_view(g, members[g.id], present) for g in groups]

    async def list_groups(self) -> list[RoutingGroupView]:
        async with self._repo.transaction() as tx:
            return await self._views(tx, await tx.list_routing_groups())

    async def get_group(self, group_id: uuid.UUID) -> RoutingGroupView:
        async with self._repo.transaction() as tx:
            group = await tx.get_routing_group(group_id)
            if group is None:
                raise NotFound("routing group not found")
            (view,) = await self._views(tx, [group])
            return view

    async def create_group(self, body: RoutingGroupCreate, actor: Actor) -> RoutingGroupView:
        now = self._clock()
        async with self._repo.transaction() as tx:
            owners = await self._observed(tx, body.context_uids)
            group = await tx.create_routing_group(
                display_name=body.display_name, description=body.description, now=now
            )
            if body.context_uids:
                group = await tx.set_routing_members(
                    group.id,
                    expected_revision=group.revision,
                    add=[(u, owners[u]) for u in body.context_uids],
                    remove=[],
                    actor_id=actor.id,
                    now=now,
                )
            await tx.append_event(
                entity_type=EVENT_ENTITY,
                entity_id=str(group.id),
                actor_id=actor.id,
                action="create",
                now=now,
                after={
                    "display_name": group.display_name,
                    "description": group.description,
                    "members": list(body.context_uids),
                    "revision": group.revision,
                },
            )
            (view,) = await self._views(tx, [group])
            return view

    async def patch_group(
        self, group_id: uuid.UUID, body: RoutingGroupPatch, actor: Actor
    ) -> RoutingGroupView:
        now = self._clock()
        async with self._repo.transaction() as tx:
            before = await tx.get_routing_group(group_id)
            if before is None or before.archived_at is not None:
                raise NotFound("routing group not found")
            kwargs: dict[str, Any] = {}
            if body.display_name is not None:
                kwargs["display_name"] = body.display_name
            if body.description is not None:
                kwargs["description"] = body.description
            group = await tx.update_routing_group(
                group_id, expected_revision=body.expected_revision, now=now, **kwargs
            )
            await tx.append_event(
                entity_type=EVENT_ENTITY,
                entity_id=str(group.id),
                actor_id=actor.id,
                action="update",
                now=now,
                before={"display_name": before.display_name, "description": before.description},
                after={"display_name": group.display_name, "description": group.description},
            )
            (view,) = await self._views(tx, [group])
            return view

    async def delete_group(self, group_id: uuid.UUID, expected_revision: int, actor: Actor) -> None:
        now = self._clock()
        async with self._repo.transaction() as tx:
            before = await tx.get_routing_group(group_id)
            if before is None or before.archived_at is not None:
                raise NotFound("routing group not found")
            members = await tx.list_routing_members(group_id)
            group = await tx.archive_routing_group(group_id, expected_revision=expected_revision, now=now)
            await tx.append_event(
                entity_type=EVENT_ENTITY,
                entity_id=str(group.id),
                actor_id=actor.id,
                action="archive",
                now=now,
                before={"display_name": before.display_name, "members": [m.context_uid for m in members]},
                after={"archived_at": now.isoformat(), "revision": group.revision},
            )

    async def _observed(self, tx: InventoryTx, uids: Sequence[str]) -> dict[str, str]:
        """Return the owner uid of each context uid. A uid that the published snapshot does not
        hold is refused."""
        if not uids:
            return {}
        key = await self._published_key(tx)
        present = await self._graph.present(uids, key) if key is not None else {}
        missing = [u for u in uids if u not in present]
        if missing:
            raise InventoryError(
                "context uids are not in the published snapshot: " + ", ".join(sorted(missing)),
                references=sorted(missing),
            )
        return present

    # --- preview and apply of edit_routing_members ---

    async def preview_members(self, request: PreviewRequest, actor: Actor) -> PreviewResponse:
        if request.operation != OPERATION:
            raise InventoryError(f"{request.operation.value} is not a routing operation")
        change = request.typed_change()
        if not isinstance(change, RoutingMembersChange):
            raise InventoryError("edit_routing_members needs a routing members change")
        if request.selection.ids != [str(change.group_id)]:
            raise InventoryError("selection.ids must name exactly the group of the change")
        now = self._clock()
        async with self._repo.transaction() as tx:
            group = await tx.get_routing_group(change.group_id)
            if group is None or group.archived_at is not None:
                raise NotFound("routing group not found")
            current = {m.context_uid: m for m in await tx.list_routing_members(group.id)}
            owners = await self._observed(tx, change.add_context_uids)
            warnings: list[str] = []
            for u in change.add_context_uids:
                if u in current:
                    warnings.append(f"{u} is already a member")
            for u in change.remove_context_uids:
                if u not in current:
                    warnings.append(f"{u} is not a member")
            touched = {u: owners[u] for u in change.add_context_uids}
            touched.update({u: current[u].owner_uid for u in change.remove_context_uids if u in current})
            affected = sorted({o for o in touched.values() if o})
            state = await tx.get_state()
            member = PreviewMember(
                kind=PreviewMemberKind.ROUTING_GROUP,
                id=str(group.id),
                revision=group.revision,
                label=group.display_name,
            )
            changes = {
                "change": change.model_dump(mode="json"),
                "owners": {u: owners[u] for u in change.add_context_uids},
            }
            preview = await tx.create_preview(
                actor_id=actor.id,
                operation=OPERATION.value,
                permissions=["sources.write"],
                intent_generation=state.intent_generation,
                snapshot_key=state.read_model_snapshot_key,
                members=[member.model_dump(mode="json")],
                changes=changes,
                impact={"devices": affected, "contexts": sorted(touched)},
                secret_draft=None,
                now=now,
                ttl=PREVIEW_TTL,
            )
            await tx.add_preview_impacts(
                preview.token,
                [
                    (
                        PreviewMemberKind.DEVICE.value,
                        owner,
                        {"context_uids": sorted(u for u, o in touched.items() if o == owner)},
                    )
                    for owner in affected
                ],
            )
            return PreviewResponse(
                token=preview.token,
                operation=OPERATION,
                expires_at=preview.expires_at,
                generation=Generation(
                    snapshot_key=state.read_model_snapshot_key,
                    intent_generation=state.intent_generation,
                    inventory_sync_pending=state.inventory_sync_pending,
                ),
                members=[member],
                member_count=1,
                affected_device_count=len(affected),
                affected_target_count=0,
                changes=changes["change"],
                warnings=warnings,
            )

    async def apply_members(self, request: ApplyRequest, actor: Actor) -> ApplyResponse:
        now = self._clock()
        from hst.app.inventory.inventory_routes import request_digest

        digest = request_digest(request)
        async with self._repo.transaction() as tx:
            reused = await tx.check_idempotency(actor.id, request.idempotency_key, digest)
            if reused is not None:
                return ApplyResponse.model_validate({**reused.response, "status": ApplyStatus.REUSED.value})
            preview = await tx.get_preview(request.token, actor.id, now)
            if preview.operation != OPERATION.value:
                raise InventoryError("the preview is not an edit_routing_members preview")
            if not set(preview.permissions) <= actor.permissions:
                raise Forbidden("requires permission: sources.write")
            change = RoutingMembersChange.model_validate(preview.changes["change"])
            owners: dict[str, str] = dict(preview.changes.get("owners") or {})
            (member,) = preview.members
            group_id = uuid.UUID(str(member["id"]))
            before = [m.context_uid for m in await tx.list_routing_members(group_id)]
            group = await tx.set_routing_members(
                group_id,
                expected_revision=int(member["revision"]),
                add=[(u, owners.get(u, "")) for u in change.add_context_uids],
                remove=list(change.remove_context_uids),
                actor_id=actor.id,
                now=now,
            )
            after = [m.context_uid for m in await tx.list_routing_members(group_id)]
            await tx.append_event(
                entity_type=EVENT_ENTITY,
                entity_id=str(group_id),
                actor_id=actor.id,
                action="members",
                now=now,
                before={"members": before, "revision": int(member["revision"])},
                after={
                    "members": after,
                    "added": list(change.add_context_uids),
                    "removed": list(change.remove_context_uids),
                    "revision": group.revision,
                },
                request_id=request.idempotency_key,
                snapshot_key=preview.snapshot_key,
            )
            state = await tx.get_state()
            response = ApplyResponse(
                token=request.token,
                operation=OPERATION,
                status=ApplyStatus.APPLIED,
                generation=Generation(
                    snapshot_key=state.read_model_snapshot_key,
                    intent_generation=state.intent_generation,
                    inventory_sync_pending=state.inventory_sync_pending,
                ),
                results=[
                    ApplyResult(
                        kind=PreviewMemberKind.ROUTING_GROUP, id=str(group.id), revision=group.revision
                    )
                ],
            )
            recorded = await tx.record_operation_result(
                actor_id=actor.id,
                idempotency_key=request.idempotency_key,
                request_digest=digest,
                status=200,
                response=response.model_dump(mode="json"),
                now=now,
            )
            await tx.consume_preview(request.token, actor.id, now, result_id=recorded.id)
            return response


def _group_view(
    group: InventoryRoutingGroup, members: Sequence[InventoryRoutingMember], present: Mapping[str, str]
) -> RoutingGroupView:
    return RoutingGroupView(
        id=group.id,
        display_name=group.display_name,
        description=group.description,
        revision=group.revision,
        archived_at=group.archived_at,
        members=[
            RoutingMemberView(
                context_uid=m.context_uid,
                owner_uid=m.owner_uid,
                added_at=m.added_at,
                actor_id=None if m.actor_id is None else str(m.actor_id),
                present=m.context_uid in present,
            )
            for m in members
        ],
        created_at=group.created_at,
        updated_at=group.updated_at,
    )
