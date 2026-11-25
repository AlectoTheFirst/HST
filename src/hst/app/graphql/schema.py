"""The read-only GraphQL schema of the endpoints, devices, sites, segments,
prefixes and IP addresses of one run.

Each root field is a Relay-style connection (`edges { cursor node }`,
`pageInfo`, `totalCountCapped`, `totalCountExact`, `run`) over the paged
list of core/entity_read.py. `EntityFilterInput` filters the list. It is the
typed form of the filter of core/filters.py. A filter kind that an entity
does not support raises an error. `first` is the page size
(`limits.PAGE_DEFAULT`, at most `limits.PAGE_MAX`). `after` is the
`endCursor` of the page before. `run` selects the run. Without `run`, the
request reads the run of the cursor or the current run (context.py). The
count is exact up to `filters.COUNT_CAP` matches.

The nested fields (an endpoint's attachments and segment, a device's site
and endpoints, a site's devices, a segment's endpoints, a prefix's
addresses, an address's prefix and endpoints) read through the loaders of
the request. Each level of a selection is one batched read. Child lists take
`first` (`limits.CHILD_DEFAULT`, at most `limits.CHILD_MAX`).

The schema has no mutation type and no subscription type.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any, Generic, TypeVar

import strawberry
from graphql import GraphQLError
from strawberry.extensions import AddValidationRules, MaskErrors, MaxAliasesLimiter, MaxTokensLimiter
from strawberry.extensions.query_depth_limiter import IgnoreContext, QueryDepthLimiter
from strawberry.types import Info
from strawberry.types.nodes import SelectedField

from hst.app.graphql import limits
from hst.app.graphql.context import GraphContext
from hst.core import entity_read
from hst.core import filters as filtermod

T = TypeVar("T")


def _when(ms: Any) -> datetime | None:
    if not isinstance(ms, int | float) or isinstance(ms, bool):
        return None
    return datetime.fromtimestamp(ms / 1000, tz=UTC)


def _ctx(info: Info) -> GraphContext:
    ctx = info.context
    if not isinstance(ctx, GraphContext):
        raise GraphQLError("no request context")
    return ctx


def _bounded(first: int, maximum: int) -> int:
    if first < 1 or first > maximum:
        raise GraphQLError(f"first must be between 1 and {maximum}")
    return first


async def _objects(info: Info, kind: str, uids: list[str]) -> list[dict[str, Any]]:
    rows = await _ctx(info).rows[kind].load_many(uids)
    return [r for r in rows if r is not None]


async def _children(info: Info, parent: str, child: str, uid: str, first: int) -> list[dict[str, Any]]:
    uids = await _ctx(info).children[(parent, child)].load((uid, _bounded(first, limits.CHILD_MAX)))
    return await _objects(info, child, uids)


# --- the filter input -------------------------------------------------------------------


@strawberry.enum
class TextField(Enum):
    NAME = "name"
    HOSTNAME = "hostname"
    MAC = "mac"
    VENDOR = "vendor"
    PORT = "port"


@strawberry.enum
class RegexField(Enum):
    NAME = "name"
    HOSTNAME = "hostname"


@strawberry.input(description="A list filter; every kind given must match.")
class EntityFilterInput:
    ip: str | None = None
    subnet: str | None = None
    range_start: str | None = None
    range_end: str | None = None
    text: str | None = None
    text_fields: list[TextField] | None = None
    regex: str | None = None
    regex_fields: list[RegexField] | None = None
    site: list[str] | None = None
    vrf: list[str] | None = None
    routing_domain: list[str] | None = None
    segment: list[str] | None = None
    device: list[str] | None = None
    port: list[str] | None = None
    last_seen_after: datetime | None = None
    last_seen_before: datetime | None = None


def _filter(value: EntityFilterInput | None) -> filtermod.EntityFilter:
    if value is None:
        return filtermod.EntityFilter()
    values = {
        name: getattr(value, name)
        for name in (
            "ip",
            "subnet",
            "range_start",
            "range_end",
            "text",
            "regex",
            *filtermod.SCOPES,
            "last_seen_after",
            "last_seen_before",
        )
    }
    values["text_fields"] = [f.value for f in value.text_fields] if value.text_fields is not None else None
    values["regex_fields"] = [f.value for f in value.regex_fields] if value.regex_fields is not None else None
    try:
        return filtermod.parse_filter(values)
    except filtermod.FilterError as exc:
        raise GraphQLError(str(exc)) from exc


# --- connections ------------------------------------------------------------------------


@strawberry.type
class PageInfo:
    has_next_page: bool
    has_previous_page: bool
    start_cursor: str | None
    end_cursor: str | None


# `Edge` and `Connection` use `Generic[T]`. Strawberry resolves the type of a field
# from the globals of the module. A PEP 695 type parameter of a class is not in them.
@strawberry.type
class Edge(Generic[T]):  # noqa: UP046
    cursor: str
    node: T


@strawberry.type
class Connection(Generic[T]):  # noqa: UP046
    run: strawberry.ID | None = strawberry.field(
        description="The run every object of this answer is read from."
    )
    edges: list[Edge[T]]
    page_info: PageInfo
    total_count_capped: int = strawberry.field(
        description="The matching objects, exact when totalCountExact, else this many at least."
    )
    total_count_exact: bool


def _counts(info: Info) -> bool:
    """Whether the selection has `totalCountCapped` or `totalCountExact`.
    `read_page` runs the count query only if it has one of them. A fragment in
    the selection counts as a selection of the count."""
    for selected in info.selected_fields:
        for sub in getattr(selected, "selections", None) or ():
            if not isinstance(sub, SelectedField) or sub.name in ("totalCountCapped", "totalCountExact"):
                return True
    return False


async def _connection(
    info: Info,
    kind: str,
    build: Any,
    where: EntityFilterInput | None,
    first: int,
    after: str | None,
    run: strawberry.ID | None,
) -> Any:
    ctx = _ctx(info)
    f = _filter(where)
    _bounded(first, limits.PAGE_MAX)
    try:
        # A filter kind that this list does not support fails before the run is resolved.
        filtermod.compile_filter(f, kind)
    except filtermod.FilterError as exc:
        raise GraphQLError(str(exc)) from exc
    cursor = None
    if after:
        try:
            cursor = filtermod.decode_cursor(after, kind=kind, filter_print=f.fingerprint())
        except filtermod.FilterError as exc:
            raise GraphQLError(str(exc)) from exc
    snapshot = await ctx.pin(run, cursor.run if cursor is not None else None)
    try:
        page = await ctx.in_thread(
            entity_read.read_page,
            kind,
            f,
            snap=ctx.snap,
            run=snapshot.cts,
            cursor=cursor,
            limit=first,
            count=_counts(info),
        )
    except filtermod.FilterError as exc:
        raise GraphQLError(str(exc)) from exc
    rows = await _ctx(info).rows[kind].load_many(page.uids)
    edges = []
    for uid, key, row in zip(page.uids, page.keys, rows, strict=True):
        if row is None:
            continue
        # each edge's cursor is the position after its own row
        edge_cursor = filtermod.Cursor(
            kind=kind, run=snapshot.cts, key=key, uid=uid, filter=f.fingerprint()
        ).encode()
        edges.append(Edge(cursor=edge_cursor, node=build(row)))
    return Connection(
        run=strawberry.ID(str(snapshot.cts)) if snapshot.cts is not None else None,
        edges=edges,
        page_info=PageInfo(
            has_next_page=page.next_cursor is not None,
            has_previous_page=cursor is not None,
            start_cursor=edges[0].cursor if edges else None,
            end_cursor=edges[-1].cursor if edges else None,
        ),
        total_count_capped=page.total_capped,
        total_count_exact=page.total_exact,
    )


# --- the entity types -------------------------------------------------------------------


@strawberry.type
class Site:
    uid: strawberry.ID
    code: str | None
    kind: str | None

    @strawberry.field(description="The devices LOCATED_IN the site, by hostname.")
    async def devices(self, info: Info, first: int = limits.CHILD_DEFAULT) -> list[Device]:
        return [Device.of(r) for r in await _children(info, "site", "device", self.uid, first)]

    @staticmethod
    def of(row: dict[str, Any]) -> Site:
        return Site(uid=strawberry.ID(row["uid"]), code=row.get("code"), kind=row.get("kind"))


@strawberry.type
class Device:
    uid: strawberry.ID
    name: str
    hostname: str | None
    role: str | None
    tier: str | None
    vendor: str | None
    model: str | None
    mgmt_ip: str | None
    mac: str | None
    last_seen: datetime | None = strawberry.field(
        description="When a run last collected the device; a carried device keeps the time it was collected."
    )
    site_uid: strawberry.Private[str | None]

    @strawberry.field
    async def site(self, info: Info) -> Site | None:
        if self.site_uid is None:
            return None
        rows = await _objects(info, "site", [self.site_uid])
        return Site.of(rows[0]) if rows else None

    @strawberry.field(description="The endpoints attached to the device or to its ports, by name.")
    async def endpoints(self, info: Info, first: int = limits.CHILD_DEFAULT) -> list[Endpoint]:
        return [Endpoint.of(r) for r in await _children(info, "device", "endpoint", self.uid, first)]

    @staticmethod
    def of(row: dict[str, Any]) -> Device:
        return Device(
            uid=strawberry.ID(row["uid"]),
            name=row.get("name") or row["uid"],
            hostname=row.get("hostname"),
            role=row.get("role"),
            tier=row.get("tier"),
            vendor=row.get("vendor"),
            model=row.get("model"),
            mgmt_ip=row.get("mgmt_ip"),
            mac=row.get("mac"),
            last_seen=_when(row.get("last_seen")),
            site_uid=row.get("site"),
        )


@strawberry.type
class Attachment:
    port: str | None
    ssid: str | None
    sites: list[str]
    device_uid: strawberry.Private[str | None]

    @strawberry.field
    async def device(self, info: Info) -> Device | None:
        if self.device_uid is None:
            return None
        rows = await _objects(info, "device", [self.device_uid])
        return Device.of(rows[0]) if rows else None


@strawberry.type
class Endpoint:
    uid: strawberry.ID
    name: str
    label: str | None
    hostname: str | None
    mac: str | None
    vendor: str | None
    kind: str | None
    wired: bool | None
    last_seen: datetime | None = strawberry.field(
        description="When the source last saw the endpoint, else when a run last collected it."
    )
    ips: list[str]
    attachments: list[Attachment]
    segment_uid: strawberry.Private[str | None]

    @strawberry.field
    async def segment(self, info: Info) -> Segment | None:
        if self.segment_uid is None:
            return None
        rows = await _objects(info, "segment", [self.segment_uid])
        return Segment.of(rows[0]) if rows else None

    @strawberry.field(description="The IpAddress objects the endpoint holds, in address order.")
    async def addresses(self, info: Info, first: int = limits.CHILD_DEFAULT) -> list[IpAddress]:
        return [IpAddress.of(r) for r in await _children(info, "endpoint", "ip_address", self.uid, first)]

    @staticmethod
    def of(row: dict[str, Any]) -> Endpoint:
        return Endpoint(
            uid=strawberry.ID(row["uid"]),
            name=row.get("name") or row["uid"],
            label=row.get("label"),
            hostname=row.get("hostname"),
            mac=row.get("mac"),
            vendor=row.get("vendor"),
            kind=row.get("kind"),
            wired=row.get("wired"),
            last_seen=_when(row.get("last_seen")),
            ips=list(row.get("ips") or []),
            attachments=[
                Attachment(
                    port=a.get("port"),
                    ssid=a.get("ssid"),
                    sites=list(a.get("sites") or []),
                    device_uid=a.get("device"),
                )
                for a in row.get("attachments") or []
            ],
            segment_uid=row.get("bd"),
        )


@strawberry.type
class Segment:
    uid: strawberry.ID
    name: str | None
    security_class: str | None

    @strawberry.field(description="The endpoints IN the segment, by name.")
    async def endpoints(self, info: Info, first: int = limits.CHILD_DEFAULT) -> list[Endpoint]:
        return [Endpoint.of(r) for r in await _children(info, "segment", "endpoint", self.uid, first)]

    @staticmethod
    def of(row: dict[str, Any]) -> Segment:
        return Segment(
            uid=strawberry.ID(row["uid"]), name=row.get("name"), security_class=row.get("security_class")
        )


@strawberry.type
class Prefix:
    uid: strawberry.ID
    cidr: str | None
    af: int | None
    kind: str | None
    anchor: str | None
    vrf: str | None

    @strawberry.field(description="The IpAddress objects IN the prefix, in address order.")
    async def addresses(self, info: Info, first: int = limits.CHILD_DEFAULT) -> list[IpAddress]:
        return [IpAddress.of(r) for r in await _children(info, "prefix", "ip_address", self.uid, first)]

    @staticmethod
    def of(row: dict[str, Any]) -> Prefix:
        return Prefix(
            uid=strawberry.ID(row["uid"]),
            cidr=row.get("cidr"),
            af=row.get("af"),
            kind=row.get("kind"),
            anchor=row.get("anchor"),
            vrf=row.get("vrf"),
        )


@strawberry.type
class IpAddress:
    uid: strawberry.ID
    ip: str | None
    af: int | None
    anchor: str | None
    prefix_uid: strawberry.Private[str | None]

    @strawberry.field
    async def prefix(self, info: Info) -> Prefix | None:
        if self.prefix_uid is None:
            return None
        rows = await _objects(info, "prefix", [self.prefix_uid])
        return Prefix.of(rows[0]) if rows else None

    @strawberry.field(description="The endpoints that hold the address, by name.")
    async def endpoints(self, info: Info, first: int = limits.CHILD_DEFAULT) -> list[Endpoint]:
        return [Endpoint.of(r) for r in await _children(info, "ip_address", "endpoint", self.uid, first)]

    @staticmethod
    def of(row: dict[str, Any]) -> IpAddress:
        return IpAddress(
            uid=strawberry.ID(row["uid"]),
            ip=row.get("ip"),
            af=row.get("af"),
            anchor=row.get("anchor"),
            prefix_uid=row.get("prefix"),
        )


# --- the root ---------------------------------------------------------------------------

_FIRST = limits.PAGE_DEFAULT


@strawberry.type
class Query:
    @strawberry.field(description="Endpoints, by name then uid.")
    async def endpoints(
        self,
        info: Info,
        filter: EntityFilterInput | None = None,
        first: int = _FIRST,
        after: str | None = None,
        run: strawberry.ID | None = None,
    ) -> Connection[Endpoint]:
        return await _connection(info, "endpoint", Endpoint.of, filter, first, after, run)

    @strawberry.field(description="Devices, by hostname then uid.")
    async def devices(
        self,
        info: Info,
        filter: EntityFilterInput | None = None,
        first: int = _FIRST,
        after: str | None = None,
        run: strawberry.ID | None = None,
    ) -> Connection[Device]:
        return await _connection(info, "device", Device.of, filter, first, after, run)

    @strawberry.field(description="Sites, by code.")
    async def sites(
        self,
        info: Info,
        filter: EntityFilterInput | None = None,
        first: int = _FIRST,
        after: str | None = None,
        run: strawberry.ID | None = None,
    ) -> Connection[Site]:
        return await _connection(info, "site", Site.of, filter, first, after, run)

    @strawberry.field(description="Segments (bridge domains), by name then uid.")
    async def segments(
        self,
        info: Info,
        filter: EntityFilterInput | None = None,
        first: int = _FIRST,
        after: str | None = None,
        run: strawberry.ID | None = None,
    ) -> Connection[Segment]:
        return await _connection(info, "segment", Segment.of, filter, first, after, run)

    @strawberry.field(description="Prefixes, in address order.")
    async def prefixes(
        self,
        info: Info,
        filter: EntityFilterInput | None = None,
        first: int = _FIRST,
        after: str | None = None,
        run: strawberry.ID | None = None,
    ) -> Connection[Prefix]:
        return await _connection(info, "prefix", Prefix.of, filter, first, after, run)

    @strawberry.field(description="IP addresses, in address order.")
    async def ip_addresses(
        self,
        info: Info,
        filter: EntityFilterInput | None = None,
        first: int = _FIRST,
        after: str | None = None,
        run: strawberry.ID | None = None,
    ) -> Connection[IpAddress]:
        return await _connection(info, "ip_address", IpAddress.of, filter, first, after, run)


def _ignore_introspection(context: IgnoreContext) -> bool:
    return context.field_name.startswith("__")


def build_schema() -> strawberry.Schema:
    """The schema with its limits (limits.py)."""
    return strawberry.Schema(
        query=Query,
        # Each factory gives a request its own extension instance.
        extensions=[
            lambda: MaxTokensLimiter(max_token_count=limits.MAX_TOKENS),
            limits.FragmentLimit,
            lambda: MaxAliasesLimiter(max_alias_count=limits.MAX_ALIASES),
            lambda: QueryDepthLimiter(max_depth=limits.MAX_DEPTH, should_ignore=_ignore_introspection),
            lambda: AddValidationRules([limits.CostLimit]),
            limits.FieldPermissions,
            lambda: MaskErrors(should_mask_error=limits.should_mask),
        ],
    )


schema = build_schema()
