"""The collector never calls a mutation operation."""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Any, ClassVar
from urllib.parse import urlsplit

import httpx
from pydantic import AliasChoices, Field, field_validator

from hst.core import uid
from hst.core.collection_progress import CollectionProgress
from hst.core.identity import chassis_serial
from hst.core.l3domain import DomainPolicy
from hst.core.model import Batch, SectionOutcome, TableOutcome
from hst.core.mtu import canonical_json

from . import http
from .auth import ApiKeyCredential, SshJumpHost, TlsConfig
from .base import Collector, SourceConfig, register
from .util import (
    GraphBuilder,
    OverlayEnd,
    VrfDomains,
    as_int,
    connected_address,
    lpm_columns,
    overlay_connection,
)
from .velocloud_poll import PollCache, bounded_map, digest

logger = logging.getLogger(__name__)

API_PROFILE = "velocloud-vco-6.4.0-v3"
MAX_COLLECTION_PAGES = 10_000
RATE_LIMIT_RETRIES = 3
RATE_LIMIT_PAUSE_S = 5.0
READ_PATHS = {
    "enterprises": "/enterprises",
    # The inventory fallback for a refused Portal listing. probe() reads this path.
    "edges": "/enterprises/{enterprise}/edges",
    "bgp_sessions": "/enterprises/{enterprise}/bgpSessions",
}
# The filter is sent on the first page of a walk only.
BGP_SESSION_FILTER = {"state[is]": "ESTABLISHED"}
PORTAL_READ_PATHS = {
    "aggregates": "/portal/rest/monitoring/getAggregates",
    "enterprise_edges": "/portal/rest/enterprise/getEnterpriseEdges",
    "enterprise_configurations": "/portal/rest/enterprise/getEnterpriseConfigurations",
    "configuration_modules": "/portal/rest/edge/getEdgeConfigurationModules",
    "route_table": "/portal/rest/enterprise/getEnterpriseRouteTable",
}
# A Portal read that the VCO refuses with one of these is a recorded gap.
PORTAL_GAP_STATUSES = frozenset({400, 403, 404, 405, 501})
ERROR_BODY_CHARS = 200
# getEnterpriseEdges returns the whole inventory for these `with` values.
# `configuration` is the module summary. The cache signature of the per-edge
# read includes it.
EDGE_WITH = ("site", "links", "ha", "configuration")
# The graph needs these 2 modules, and no enterprise-wide read returns them.
EDGE_MODULES = ("WAN", "controlPlane")
VCMP_PORT = 2426
ENCAP = "velocloud-vcmp"
GLOBAL_SEGMENT_NAME = "Global Segment"
GATEWAY_PREFIX = "gateway"
VPN_TUNNEL_ROLE = "VPN_TUNNEL"
RIB_TABLE = "rib"
# The overlay-origin scope of the route table.
RIB_SCOPE_KEY = "rib:overlay-flow-control"
EXIT_FIELDS = (
    "type",
    "exitType",
    "entity",
    "state",
    "protocol",
    "routeType",
    "cost",
    "metric",
    "segmentId",
    "edgeId",
    "edgeLogicalId",
    "interface",
    "neighborIp",
    "nextHopIp",
    "cidrIp",
    "cidrPrefix",
    "isOwner",
    "advertise",
    "neighborTag",
    "learnedBy",
    "filtered",
)
ROUTE_FIELDS = ("cidrIp", "cidrPrefix", "segmentId", "logicalId")


def _lines(value: str) -> list[str]:
    return [line.strip() for line in value.replace(",", "\n").splitlines() if line.strip()]


class VeloCloudJumpHost(SshJumpHost):
    host_key: str = Field(
        min_length=1,
        description="Trusted SSH host public key of the jump host, verified before the jump-host "
        "credential is sent",
    )


class VeloCloudConfig(SourceConfig):
    url: str
    enterprise_logical_ids: str = Field(
        default="",
        title="Enterprises",
        description="One enterprise logicalId per line, empty for every enterprise GET /enterprises answers",
        json_schema_extra={"format": "multiline"},
        # `enterprise_logical_id` is the key of a stored config with one enterprise.
        validation_alias=AliasChoices("enterprise_logical_ids", "enterprise_logical_id"),
    )
    orchestrator_release: str
    auth: ApiKeyCredential
    tls: TlsConfig = TlsConfig()
    jump_host: VeloCloudJumpHost | None = Field(
        default=None,
        title="SSH jump host",
        description="SSH host that resolves and connects the VCO HTTPS endpoint",
    )
    api_base_path: str = "/api/sdwan/v2"
    poll_concurrency: int = Field(
        default=4,
        ge=1,
        le=16,
        title="Concurrent VCO requests",
        description="Maximum concurrent reads of one poll, SSH tunneling included, and maximum new "
        "requests per second",
    )
    cache_enabled: bool = Field(
        default=True,
        title="Cache VCO responses",
        description="Encrypted per-edge WAN and control-plane modules kept between polls",
    )
    configuration_refresh_s: int = Field(
        default=1800,
        ge=0,
        title="Configuration refresh (seconds)",
        description="Maximum age of a cached edge WAN and control-plane module read, 0 for a read "
        "on every poll",
    )
    provider_name: str = Field(
        default="",
        title="MPLS provider",
        description="Private carrier of a link the WAN module does not describe",
    )
    private_carriers: str = Field(
        default="",
        title="Private carriers",
        description="Private carrier names of a link the WAN module does not describe, one per line",
        json_schema_extra={"format": "multiline"},
    )

    @field_validator("orchestrator_release")
    @classmethod
    def _supported_release(cls, value: str) -> str:
        try:
            parts = tuple(int(part) for part in value.split("."))
        except ValueError as exc:
            raise ValueError("must be a dotted numeric VeloCloud release") from exc
        if not 3 <= len(parts) <= 4 or any(part < 0 for part in parts):
            raise ValueError("must be a dotted numeric VeloCloud release")
        if parts + (0,) * (4 - len(parts)) < (5, 0, 0, 0):
            raise ValueError("full APIv2 configuration reads require VCO 5.0.0.0 or newer")
        return value

    @property
    def enterprise_ids(self) -> list[str]:
        return _lines(self.enterprise_logical_ids)

    @property
    def private_carrier_names(self) -> set[str]:
        names = set(_lines(self.private_carriers))
        if self.provider_name:
            names.add(self.provider_name)
        return {name.lower() for name in names}


def _transport(config: VeloCloudConfig) -> httpx.BaseTransport | None:
    return None


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


def _pace(seconds: float) -> None:
    """`_sleep` is the 429 retry-after wait."""
    time.sleep(seconds)


def _items(value: Any) -> list[dict[str, Any]]:
    """The rows of a response. The response is a bare array or a collection
    envelope with a `data` array."""
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict) and isinstance(value.get("data"), list):
        return [item for item in value["data"] if isinstance(item, dict)]
    return []


def _numeric_id(value: Any) -> int | None:
    if type(value) is int and value > 0:
        return value
    if type(value) is float and value.is_integer() and value > 0:
        return int(value)
    return None


def _exit_withheld(exit_: dict[str, Any]) -> bool:
    """True when the orchestrator keeps this exit out of use. A route filter
    removed the exit (`filtered`), or its `state` is `UNREACHABLE`. An exit
    with no `state`, such as a connected exit, is in use."""
    filtered = exit_.get("filtered")
    if filtered is True or str(filtered).lower() in ("1", "true"):
        return True
    return str(exit_.get("state") or "").upper() == "UNREACHABLE"


def _reduce_route_table(body: Any) -> Any:
    """`poll_stats` keeps the full response size."""
    if not isinstance(body, dict):
        return body
    subnets = []
    for record in _items(body.get("subnets")):
        route = record.get("learnedRoute")
        subnets.append(
            {
                "subnet": record.get("subnet"),
                "ipVersion": record.get("ipVersion"),
                "learnedRoute": (
                    {k: route.get(k) for k in ROUTE_FIELDS if k in route} if isinstance(route, dict) else None
                ),
                **{
                    bucket: [
                        {k: exit_.get(k) for k in EXIT_FIELDS if k in exit_}
                        for exit_ in _items(record.get(bucket))
                    ]
                    for bucket in ("preferredExits", "eligableExits")
                },
            }
        )
    return {"profiles": body.get("profiles"), "subnets": subnets, "reduced": True}


def _error_detail(response: httpx.Response) -> str:
    try:
        body = " ".join(response.text.split())
    except httpx.ResponseNotRead:
        return ""
    if len(body) <= ERROR_BODY_CHARS:
        return body
    return body[:ERROR_BODY_CHARS] + "..."


def _raise_for_status(response: httpx.Response) -> None:
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        detail = _error_detail(response)
        if not detail:
            raise
        raise httpx.HTTPStatusError(
            f"{exc}\nOrchestrator answered: {detail}", request=exc.request, response=response
        ) from None


def _portal_gap(operation: str, status: int | None, detail: str) -> dict[str, Any]:
    capability: dict[str, Any] = {
        "status": "unavailable",
        "http_status": status,
        "operation": PORTAL_READ_PATHS.get(operation, operation),
        "reason": "VCO Portal read unavailable",
    }
    if detail:
        capability["detail"] = detail
    return {"_capability": capability}


def _scope(url: str) -> str:
    host = urlsplit(url).netloc or url
    return f"velocloud:{uid.slug(host)}"


@register
class VeloCloudCollector(Collector):
    reports_progress: ClassVar[bool] = True
    name = "velocloud"
    ConfigModel = VeloCloudConfig
    KIND = "orchestrator"
    PARSER_VERSION = "5"
    VOLATILE_RAW_KEYS = ("fetched_at_ms", "poll_stats")
    # These properties hold the poll time and the time of the last module read
    # by the poll cache. They change on every refresh. The batch digest
    # (collectors/base.py `graph_sha`) leaves them out. The forced full load
    # bounds the age of the stored values.
    VOLATILE_GRAPH_PROPS: ClassVar[dict[str, tuple[str, ...]]] = {
        "Device": ("configuration_observed_at_ms",),
        "WanLink": ("configuration_observed_at_ms",),
        "Tunnel": ("configuration_observed_at_ms",),
        "SdwanBusinessPolicy": ("observed_at_ms",),
    }
    NORMALIZATION_VERSIONS: ClassVar[dict[str, str]] = {
        # the '.' of a subinterface name stays in the Interface and Port uid
        "iface_uid": uid.IFACE_UID_VERSION,
        "forwarding-boundary": "1",
        "api-capability": API_PROFILE,
        "path-direction": "4",
        "effective-configuration": "2",
        # A refused Portal read degrades the configuration and profile_segments
        # sections. A refused route-table read or BGP read degrades its table.
        "read-failures": "1",
        # A placeholder serial identifies no chassis.
        "serial": "1",
    }
    AUTHORITATIVE_SECTIONS = ("edges", "segments")
    SECTION_LABELS: ClassVar[dict[str, tuple[str, ...]]] = {
        "edges": ("Device", "Port", "WanLink", "ForwardingBoundary", "ProviderNetwork", "Provider"),
        "segments": ("RoutingDomain",),
        # A refused profile read fails only this optional section.
        "profile_segments": ("SdwanSegment", "VrfInstance"),
        "configuration": (
            "SdwanBusinessPolicy",
            "Interface",
            "IpAddress",
            "Prefix",
            "RoutingProcess",
            "BgpSession",
        ),
        "observations": ("Tunnel", "SdwanGateway", "OverlayConnection"),
        # The cached fallback is scoped to the failed read.
        "poll_refresh": (),
    }
    SIDE_TABLES = ("bgp_sessions", RIB_TABLE)

    def __init__(self, config: VeloCloudConfig, settings):
        super().__init__(config, settings)
        self.scope = _scope(config.url)
        self._cooldown = threading.Lock()
        self._pace_lock = threading.Lock()
        self._next_slot: float | None = None
        self._stats_lock = threading.Lock()
        self._request_stats: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"requests": 0, "elapsed_ms": 0, "bytes": 0, "retries": 0}
        )
        self._cache: PollCache | None = None
        self._aggregates: Any = None
        self._progress: CollectionProgress | None = None

    def _phase(self, phase, total=None, **context):
        if self._progress:
            self._progress.phase(phase, total, **context)

    def _advance(self, count):
        if self._progress:
            if self._cache:
                self._progress.data["cache_hits"] = self._cache.hits
            self._progress.advance(count)

    def _client(self) -> httpx.Client:
        c = self.config
        client = http.client(
            c.url.rstrip("/"),
            c.tls,
            timeout=60,
            transport=_transport(c),
            jump_host=c.jump_host,
            max_connections=c.poll_concurrency,
        )
        client.headers["Authorization"] = f"Token {c.auth.key.get_secret_value()}"
        return client

    def _path(self, path: str) -> str:
        base = self.config.api_base_path
        return path if path.startswith(base + "/") else base + "/" + path.lstrip("/")

    def _get(self, client: httpx.Client, path: str, **params: Any) -> Any:
        query = {k: v for k, v in params.items() if v is not None} or None
        return self._read(client, "GET", self._path(path), params=query)

    def _portal_read(self, client: httpx.Client, operation: str, body: dict[str, Any] | None = None) -> Any:
        path = PORTAL_READ_PATHS.get(operation)
        if path is None:
            raise ValueError("VeloCloud Portal operation is not an allowed read")
        return self._read(client, "POST", path, json=body or {})

    def _throttle(self) -> None:
        """Hold the dispatch rate of the whole poll at poll_concurrency requests
        per second across all worker threads."""
        min_interval = 1.0 / self.config.poll_concurrency
        with self._pace_lock:
            now = time.monotonic()
            wait = max(0.0, (self._next_slot or now) - now)
            self._next_slot = max(now, self._next_slot or now) + min_interval
        if wait:
            _pace(wait)

    def _read(self, client: httpx.Client, method: str, path: str, **kwargs: Any) -> Any:
        """Retry read-only requests on 429, including Portal discovery POSTs."""
        for attempt in range(RATE_LIMIT_RETRIES + 1):
            self.check_stop()
            # All workers wait while any request backs off.
            with self._cooldown:
                pass
            self._throttle()
            started = time.monotonic()
            response = None
            try:
                response = client.request(method, path, **kwargs)
            finally:
                with self._stats_lock:
                    stats = self._request_stats[path.rsplit("/", 1)[-1]]
                    stats["requests"] += 1
                    stats["elapsed_ms"] += round((time.monotonic() - started) * 1000)
                    stats["bytes"] += len(response.content) if response is not None else 0
                    stats["retries"] += int(attempt > 0)
            if response.status_code != 429 or attempt == RATE_LIMIT_RETRIES:
                _raise_for_status(response)
                return response.json()
            retry_after = response.headers.get("Retry-After", "")
            try:
                pause = max(0.0, float(retry_after))
            except ValueError:
                try:
                    pause = max(0.0, parsedate_to_datetime(retry_after).timestamp() - time.time())
                except (ValueError, TypeError, OverflowError):
                    pause = RATE_LIMIT_PAUSE_S
            with self._cooldown:
                _sleep(pause)
        raise AssertionError("unreachable")

    def _pages(self, client: httpx.Client, path: str, **params: Any) -> list[Any]:
        """The server ignores every other query parameter with `nextPageLink`."""
        pages: list[Any] = []
        token: str | None = None
        seen: set[str] = set()
        while True:
            if len(pages) >= MAX_COLLECTION_PAGES:
                raise ValueError("VeloCloud pagination exceeds the collection page limit")
            if token is None:
                page = self._get(client, path, **params)
            else:
                page = self._get(client, path, nextPageLink=token)
            pages.append(page)
            meta = page.get("metaData") if isinstance(page, dict) else None
            if meta is None:
                return pages
            if not isinstance(meta, dict):
                raise ValueError("VeloCloud returned malformed pagination metadata")
            token = meta.get("nextPageLink")
            if token in (None, ""):
                return pages
            if not isinstance(token, str):
                raise ValueError("VeloCloud returned a malformed pagination token")
            if token in seen:
                raise ValueError("VeloCloud pagination is cyclic")
            seen.add(token)

    def probe(self) -> str:
        client = self._client()
        try:
            ids = self.config.enterprise_ids
            if ids:
                self._get(client, READ_PATHS["edges"].format(enterprise=ids[0]), limit=1)
                return f"login ok: VeloCloud APIv2, {len(ids)} configured enterprise(s)"
            page = self._get(client, READ_PATHS["enterprises"], limit=1)
            return (
                f"login ok: VeloCloud APIv2, enterprise discovery {'answers' if _items(page) else 'is empty'}"
            )
        finally:
            client.close()

    def _enterprises(self, client: httpx.Client) -> list[dict[str, Any]]:
        ids = self.config.enterprise_ids
        if ids:
            return [{"logicalId": eid} for eid in ids]
        pages = self._pages(client, READ_PATHS["enterprises"])
        return [
            {"logicalId": str(row["logicalId"]), "name": row.get("name")}
            for page in pages
            for row in _items(page)
            if row.get("logicalId")
        ]

    def _cached_read(self, key, ttl, signature, fetch, *, stale_on_error=False):
        if self._cache is None:
            return fetch(), {}
        return self._cache.read(key, ttl, signature, fetch, stale_on_error=stale_on_error)

    def _enterprise(self, client: httpx.Client, enterprise: str, pool: ThreadPoolExecutor) -> dict[str, Any]:
        """Reads one enterprise with the Portal reads of the inventory, the
        profiles and the route table, the BGP session pages and one cached
        module read per edge."""
        gaps: list[dict[str, Any]] = []
        self._phase("Resolving the enterprise")
        enterprise_id, gap = self._enterprise_id(client, enterprise)
        edges: list[dict[str, Any]] = []
        profiles: dict[str, Any] = {}
        route_table: Any = None
        if gap:
            gaps.append(gap)
        else:
            self._phase("Reading the edge inventory")
            edges, gap = self._portal_edges(client, enterprise_id)
            if gap:
                gaps.append(gap)
            self._phase("Reading the enterprise profiles")
            profiles, gap = self._portal_profiles(client, enterprise_id)
            if gap:
                gaps.append(gap)
            self._phase("Reading the overlay route table")
            route_table, gap = self._route_table(client, enterprise_id)
            if gap:
                gaps.append(gap)
        if not edges:
            edges = self._apiv2_edges(client, enterprise)
        edge_details = {str(edge["logicalId"]): {"_freshness": {}} for edge in edges}
        numeric_ids = {
            str(edge["logicalId"]): numeric
            for edge in edges
            if (numeric := _numeric_id(edge.get("id"))) is not None
        }
        signatures = {str(edge["logicalId"]): _edge_signature(edge) for edge in edges}

        def modules(eid: str):
            value, freshness = self._cached_read(
                (enterprise, eid, "modules"),
                self.config.configuration_refresh_s,
                signatures[eid],
                lambda: self._edge_modules(client, enterprise_id, numeric_ids.get(eid)),
                stale_on_error=True,
            )
            return eid, value, freshness

        if enterprise_id is not None and edge_details:
            self._phase("Reading the WAN and control-plane modules", len(edge_details), edges=len(edges))
            for count, (eid, value, freshness) in enumerate(
                bounded_map(pool, self.config.poll_concurrency, modules, edge_details), 1
            ):
                edge_details[eid]["modules"] = value
                edge_details[eid]["_freshness"]["modules"] = freshness
                self._advance(count)
        self._phase("Reading BGP sessions")
        return {
            "logicalId": enterprise,
            "enterprise_id": enterprise_id,
            "edges": edges,
            "profiles": profiles,
            "edge_details": edge_details,
            "route_table": route_table,
            "bgp_sessions": self._bgp_sessions(client, enterprise),
            "gaps": gaps,
        }

    def _enterprise_id(
        self, client: httpx.Client, enterprise: str
    ) -> tuple[int | None, dict[str, Any] | None]:
        """The numeric id of the enterprise. Every Portal operation addresses
        an enterprise by this id. getAggregates lists the numeric id and the
        logicalId of each enterprise. getAggregates is read once per poll."""
        operation = "aggregates"
        try:
            if self._aggregates is None:
                self._aggregates = self._portal_read(client, operation)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code not in PORTAL_GAP_STATUSES:
                raise
            return None, _portal_gap(operation, exc.response.status_code, _error_detail(exc.response))
        aggregates = self._aggregates
        rows = aggregates.get("enterprises") if isinstance(aggregates, dict) else aggregates
        enterprise_id = next(
            (
                numeric
                for row in _items(rows)
                if row.get("logicalId") == enterprise and (numeric := _numeric_id(row.get("id")))
            ),
            None,
        )
        if enterprise_id is None:
            return None, _portal_gap(operation, None, f"no numeric id for enterprise {enterprise}")
        return enterprise_id, None

    def _portal_edges(
        self, client: httpx.Client, enterprise_id: int
    ) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
        """Reads the whole inventory in one read. Each edge has its site, links,
        HA state and configuration stack summary. The answer is a superset of
        the APIv2 `EdgeResource` with the numeric edge id and `isHub`."""
        operation = "enterprise_edges"
        try:
            listing = self._portal_read(
                client, operation, {"enterpriseId": enterprise_id, "with": list(EDGE_WITH)}
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code not in PORTAL_GAP_STATUSES:
                raise
            return [], _portal_gap(operation, exc.response.status_code, _error_detail(exc.response))
        edges = [row for row in _items(listing) if row.get("logicalId")]
        if not edges:
            return [], _portal_gap(operation, None, f"no edge answered for enterprise {enterprise_id}")
        return edges, None

    def _portal_profiles(
        self, client: httpx.Client, enterprise_id: int
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Every enterprise profile body, keyed by its numeric id. The listing
        binds each edge to one profile. `edgeSpecificData` overrides the
        profile."""
        operation = "enterprise_configurations"
        try:
            rows = self._portal_read(client, operation, {"enterpriseId": enterprise_id, "with": ["modules"]})
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code not in PORTAL_GAP_STATUSES:
                raise
            return {}, _portal_gap(operation, exc.response.status_code, _error_detail(exc.response))
        profiles = {
            str(numeric): row for row in _items(rows) if (numeric := _numeric_id(row.get("id"))) is not None
        }
        if not profiles:
            return {}, _portal_gap(operation, None, f"no profile answered for enterprise {enterprise_id}")
        return profiles, None

    def _route_table(self, client: httpx.Client, enterprise_id: int) -> tuple[Any, dict[str, Any] | None]:
        """The Overlay Flow Control table of the whole enterprise. The VCO
        accepts and ignores a `segmentId`. The VCO refuses a `limit` and an
        `offset`. The answer is reduced to the fields that a `rib` row reads."""
        operation = "route_table"
        try:
            body = self._portal_read(client, operation, {"enterpriseId": enterprise_id})
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code not in PORTAL_GAP_STATUSES:
                raise
            return None, _portal_gap(operation, exc.response.status_code, _error_detail(exc.response))
        if isinstance(body, dict) and isinstance(body.get("error"), dict):
            detail = str(body["error"].get("message") or "")
            return None, _portal_gap(operation, None, detail)
        return _reduce_route_table(body), None

    def _edge_modules(self, client: httpx.Client, enterprise_id: int | None, edge_id: int | None) -> Any:
        """The `WAN` and `controlPlane` modules of one edge. No enterprise-wide
        read returns them. The profile `WAN` body is empty and the listing has
        no `WAN.edgeSpecificData`."""
        operation = "configuration_modules"
        if enterprise_id is None or edge_id is None:
            return _portal_gap(operation, None, "no numeric id for this edge")
        try:
            return self._portal_read(
                client,
                operation,
                {"enterpriseId": enterprise_id, "edgeId": edge_id, "modules": list(EDGE_MODULES)},
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code not in PORTAL_GAP_STATUSES:
                raise
            return _portal_gap(operation, exc.response.status_code, _error_detail(exc.response))

    def _apiv2_edges(self, client: httpx.Client, enterprise: str) -> list[dict[str, Any]]:
        """The inventory fallback. It has no numeric id and no `isHub`. The
        per-edge module read and the hub resolution degrade."""
        pages = self._pages(client, READ_PATHS["edges"].format(enterprise=enterprise))
        if any(
            not isinstance(page, list) and not (isinstance(page, dict) and isinstance(page.get("data"), list))
            for page in pages
        ):
            raise ValueError("VeloCloud edge inventory is not an array")
        return [edge for page in pages for edge in _items(page) if edge.get("logicalId")]

    def _bgp_sessions(self, client: httpx.Client, enterprise: str) -> Any:
        """The observed sessions in state ESTABLISHED (BGP_SESSION_FILTER)."""
        try:
            pages = self._pages(
                client, READ_PATHS["bgp_sessions"].format(enterprise=enterprise), **BGP_SESSION_FILTER
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code not in {403, 404, 405, 501}:
                raise
            return {
                "_capability": {
                    "status": "unavailable",
                    "http_status": exc.response.status_code,
                    "operation": READ_PATHS["bgp_sessions"],
                    "reason": "APIv2 read unavailable",
                }
            }
        return [row for page in pages for row in _items(page)]

    def fetch(self) -> dict[str, Any]:
        client = self._client()
        now_ms = int(time.time() * 1000)
        self._request_stats.clear()
        self._aggregates = None
        c = self.config
        self._cache = PollCache(
            self.settings,
            {
                "source": c.source_name,
                "url": c.url.rstrip("/"),
                "base": c.api_base_path,
                "credential": digest(c.auth.key.get_secret_value()),
                "release": c.orchestrator_release,
                "profile": API_PROFILE,
            },
            enabled=c.cache_enabled,
        )
        complete = False
        self._progress = CollectionProgress(self.settings, c.source_name or self.scope)
        try:
            enterprises = []
            self._phase("Discovering enterprises")
            discovered = self._enterprises(client)
            with ThreadPoolExecutor(max_workers=c.poll_concurrency, thread_name_prefix="vco") as pool:
                for index, ent in enumerate(discovered, 1):
                    self._progress.data.update(
                        enterprise=ent.get("name") or ent["logicalId"],
                        enterprise_index=index,
                        enterprise_total=len(discovered),
                    )
                    body = self._enterprise(client, ent["logicalId"], pool)
                    body["name"] = ent.get("name")
                    enterprises.append(body)
            complete = True
            stats = {
                "endpoints": dict(self._request_stats),
                "cache_hits": self._cache.hits,
                "stale_reads": self._cache.stale,
                "persistent_cache": self._cache.key is not None,
            }
            logger.info("velocloud poll: %s", stats)
            return {
                "api_profile": API_PROFILE,
                "orchestrator_release": self.config.orchestrator_release,
                "fetched_at_ms": now_ms,
                "discovered": not self.config.enterprise_ids,
                "enterprises": enterprises,
                "poll_stats": stats,
            }
        finally:
            client.close()
            self._cache.save(complete=complete)
            self._cache = None
            self._progress.finish(complete)
            self._progress = None

    def normalize(self, raw: dict[str, Any]) -> Batch:
        return normalize_velocloud(
            raw,
            scope=self.scope,
            provider_name=self.config.provider_name or None,
            private_carriers=self.config.private_carrier_names,
        )

    def side_tables(self, raw: dict[str, Any]) -> dict[str, list[dict]]:
        return {"bgp_sessions": bgp_session_rows(raw), RIB_TABLE: rib_rows(raw)}

    def table_outcomes(self, raw: dict[str, Any]) -> dict[str, TableOutcome]:
        """Returns the overlay-origin scope of the `rib` rows under the key
        `RIB_SCOPE_KEY`. A written table has the status `complete` for the rows
        that it holds. The Overlay Flow Control table holds the routes that an
        edge advertises into the overlay. It holds no route that an edge
        learned over the overlay.

        The result also holds `failed` for the `rib` and `bgp_sessions` tables
        of an enterprise whose read the orchestrator refused
        (`_refused_tables`)."""
        refused = _refused_tables(raw)
        if not any(isinstance(body, dict) and body.get("route_table") for body in _bodies(raw)):
            return refused
        records = [
            record
            for body in _bodies(raw)
            for record in _items((body.get("route_table") or {}).get("subnets"))
        ]
        exits = [
            exit_
            for record in records
            for bucket in ("preferredExits", "eligableExits")
            for exit_ in _items(record.get(bucket))
        ]
        skipped = sum(1 for exit_ in exits if str(exit_.get("exitType") or "").upper() != "EDGE")
        withheld = sum(
            1
            for exit_ in exits
            if str(exit_.get("exitType") or "").upper() == "EDGE" and _exit_withheld(exit_)
        )
        # The eligible edge exits that the orchestrator did not select.
        eligible = sum(
            1
            for record in records
            for exit_ in _items(record.get("eligableExits"))
            if str(exit_.get("exitType") or "").upper() == "EDGE" and not _exit_withheld(exit_)
        )
        detail = (
            "Overlay Flow Control scope: the routes each edge advertises into the overlay, "
            "not the routes it learned over the overlay. "
            f"{skipped} exits name a local router and carry no row. "
            f"{withheld} edge exits are filtered or marked UNREACHABLE by the orchestrator and carry no row. "
            f"{eligible} eligible exits are backups the orchestrator did not select and carry no row."
        )
        return {**refused, RIB_SCOPE_KEY: TableOutcome(status="partial", detail=detail)}


# --- readers -----------------------------------------------------------------------------


def _bodies(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, dict):
        return []
    return [body for body in raw.get("enterprises") or [] if isinstance(body, dict)]


# The link fields of the cache signature, with the link address and no volatile link state.
_LINK_IDENTITY = ("logicalId", "internalId", "interface", "ipAddress", "ipV6Address", "netmask")


def _edge_signature(edge: dict[str, Any]) -> str:
    """The cache signature of the `WAN` and `controlPlane` modules of one edge.

    The signature holds the whole `configuration` block of the listing. The
    block has every module version stamp, both profile bindings, every
    `isEdgeSpecific` flag and every `edgeSpecificData` body. A change to any of
    them refetches that edge alone. `controlPlane` reports `version` 0 on every
    edge. `configuration_refresh_s` bounds the age of a cached `controlPlane`
    module."""
    return digest(
        {
            "serial": edge.get("serialNumber"),
            "links": sorted(
                ({k: link.get(k) for k in _LINK_IDENTITY} for link in _items(edge.get("links"))),
                key=canonical_json,
            ),
            "configuration": edge.get("configuration"),
        }
    )


def _first(mapping: Any, *keys: str) -> Any:
    if not isinstance(mapping, dict):
        return None
    for key in keys:
        value = mapping.get(key)
        if value not in (None, ""):
            return value
    return None


def _ref_id(node: Any) -> str | None:
    """The logicalId of a linked resource. It is the `logicalId` field when the
    server expanded the resource, else the last path segment of `_href`."""
    if not isinstance(node, dict):
        return None
    value = node.get("logicalId")
    if value not in (None, ""):
        return str(value)
    href = node.get("_href")
    if isinstance(href, str) and href.strip("/"):
        return href.rstrip("/").rsplit("/", 1)[-1]
    return None


def _cidr(node: Any) -> str | None:
    """`cidrIp` with `cidrPrefix` or `netmask` as one `ip/len` string. Returns
    None when the address is absent or does not parse."""
    ip = _first(node, "cidrIp", "interfaceAddress", "ipAddress")
    if not ip:
        return None
    plen = _first(node, "cidrPrefix")
    mask = _first(node, "netmask")
    try:
        if plen is not None:
            return str(ipaddress.ip_interface(f"{ip}/{int(plen)}"))
        if mask:
            return str(ipaddress.ip_interface(f"{ip}/{mask}"))
        return str(ipaddress.ip_interface(str(ip)))
    except ValueError:
        return None


def _address_only(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value).split("/")[0])) if value else None
    except ValueError:
        return None


def _segment_keys(node: Any) -> list[str]:
    """Every key of the segment of a settings object. The keys are the integer
    `segmentId`, the logicalId of the nested `segment` object (the tail of its
    `_href`) and the name of the segment. The first registered key is used.

    A routed interface, a LAN network and a loopback have `segmentId` on the
    object itself. A Portal `segments[]` block has it inside the nested
    `segment` object alone, as `{segmentId, name, type}`. That object has no
    logicalId. The route table identifies a segment by the integer alone."""
    if not isinstance(node, dict):
        return []
    keys: list[str] = []
    nested = node.get("segment")
    for sid in (node.get("segmentId"), nested.get("segmentId") if isinstance(nested, dict) else None):
        if sid not in (None, "") and str(sid) not in keys:
            keys.append(str(sid))
    if isinstance(nested, dict):
        ref = _ref_id(nested)
        if ref:
            keys.append(ref)
        name = nested.get("name")
        if name:
            keys.append(str(name))
    return keys


def _settings_data(settings: Any) -> dict[str, Any]:
    """The body of a configuration module. A profile module wraps its body in
    `data`. An `edgeSpecificData` body and a stored payload have no wrapper."""
    if not isinstance(settings, dict):
        return {}
    data = settings.get("data")
    return data if isinstance(data, dict) else settings


def _module(source: Any, name: str) -> dict[str, Any]:
    """One named module of a profile row, of a listing configuration scope or of
    a module read. A profile row and a listing scope have a `modules` array.
    `getEdgeConfigurationModules` returns an object keyed by module name."""
    if not isinstance(source, dict):
        return {}
    direct = source.get(name)
    if isinstance(direct, dict):
        return direct
    for module in source.get("modules") or []:
        if isinstance(module, dict) and module.get("name") == name:
            return module
    return {}


def _effective(profile: Any, override: Any, *, qos: bool = False) -> dict[str, Any]:
    """A `segments` entry merges key by key with the profile entry of the same `segmentId`."""
    base = _settings_data(profile)
    edge = _settings_data(override)
    if not edge:
        return base
    if not base:
        return edge
    merged: dict[str, Any] = {**base, **edge}
    blocks: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for block in list(base.get("segments") or []) + list(edge.get("segments") or []):
        if not isinstance(block, dict):
            continue
        keys = _segment_keys(block)
        key = keys[0] if keys else canonical_json(block)
        if key not in blocks:
            blocks[key] = dict(block)
            order.append(key)
        elif qos and isinstance(block.get("rules"), list):
            profile_rules = blocks[key].get("rules") or []
            edge_rules = [{**r, "_override": True} for r in block["rules"] if isinstance(r, dict)]
            repeated = {r.get("ruleLogicalId") for r in edge_rules if r.get("ruleLogicalId")}
            blocks[key].update(block)
            blocks[key]["rules"] = edge_rules + [
                r for r in profile_rules if not (isinstance(r, dict) and r.get("ruleLogicalId") in repeated)
            ]
        else:
            blocks[key].update(block)
    if order:
        merged["segments"] = [blocks[key] for key in order]
    return merged


_WIRELESS = ("WIRELESS", "CELLULAR", "LTE", "5G")


def _wan_kind(
    link: dict[str, Any], wan: dict[str, Any] | None, private_carriers: set[str]
) -> tuple[str, bool]:
    """`WAN.links[].mode` is PRIVATE or PUBLIC."""
    mode = str((wan or {}).get("mode") or "").upper()
    if mode == "PRIVATE":
        return "mpls", True
    if mode == "PUBLIC":
        access = str((wan or {}).get("type") or "").upper()
        return ("lte" if any(word in access for word in _WIRELESS) else "dia"), True
    names = {
        str(value).lower() for value in (link.get("isp"), link.get("org"), link.get("displayName")) if value
    }
    if names & private_carriers:
        return "mpls", False
    return "dia", False


# One warning lists at most this many links and gives the count of the rest.
ASSUMED_DIA_NAMED = 10


def _assumed_dia_warning(edge: _Edge, links: list[str]) -> str:
    """One warning for an edge with links that the configuration does not describe. The kind
    "dia" is assumed for these links. The warning lists the sorted links, at most
    `ASSUMED_DIA_NAMED`, and the count of the rest."""
    ordered = sorted(set(links))
    named = ", ".join(ordered[:ASSUMED_DIA_NAMED])
    if len(ordered) > ASSUMED_DIA_NAMED:
        named += f" and {len(ordered) - ASSUMED_DIA_NAMED} more"
    noun = "link" if len(ordered) == 1 else "links"
    return (
        f'edge {edge.name} ({edge.eid}): kind "dia" is assumed for WAN {noun} {named}: the configuration '
        "does not describe them (no WAN module mode and no private carrier name)"
    )


_PROVIDER_KIND = {"mpls": "mpls", "dia": "internet", "lte": "internet"}


# --- normalize ---------------------------------------------------------------------------


class _Enterprise:
    """The state that the section writers share across the edges of one enterprise."""

    def __init__(self, b: GraphBuilder, enterprise: str, body: dict[str, Any]) -> None:
        self.b = b
        self.id = enterprise
        self.edges = [e for e in body.get("edges") or [] if isinstance(e, dict) and e.get("logicalId")]
        details = body.get("edge_details")
        self.details: dict[str, dict[str, Any]] = details if isinstance(details, dict) else {}
        profiles = body.get("profiles")
        self.profiles: dict[str, Any] = profiles if isinstance(profiles, dict) else {}
        # Each dict is keyed by edge id. `settings` and `qos` hold the effective
        # `deviceSettings` and `QOS` bodies. `wan` and `control` hold the 2
        # modules of `getEdgeConfigurationModules`.
        self.settings: dict[str, dict[str, Any]] = {}
        self.qos: dict[str, dict[str, Any]] = {}
        self.wan: dict[str, dict[str, Any]] = {}
        self.control: dict[str, dict[str, Any]] = {}
        for edge in self.edges:
            eid = str(edge["logicalId"])
            modules = self.details.get(eid, {}).get("modules")
            self.wan[eid] = _settings_data(_module(modules, "WAN"))
            self.control[eid] = _settings_data(_module(modules, "controlPlane"))
            for name, target in (("deviceSettings", self.settings), ("QOS", self.qos)):
                target[eid] = _effective(*self._scopes(edge, name), qos=name == "QOS")
        self.edge_names = {str(e["logicalId"]): str(e.get("name") or e["logicalId"]) for e in self.edges}
        self.segments = self._segments()
        self.segment_uids: dict[str, str] = {}
        self.global_name = GLOBAL_SEGMENT_NAME
        for seg in self.segments:
            if seg["is_global"]:
                self.global_name = seg["name"]
        self.clusters = self._clusters()
        self.hub_ids = self._hubs()

    def _scopes(self, edge: dict[str, Any], name: str) -> tuple[dict[str, Any], Any]:
        """Only the enterprise profile body is read."""
        configuration = edge.get("configuration") if isinstance(edge.get("configuration"), dict) else {}
        for scope_name in ("enterprise", "operator"):
            scope = configuration.get(scope_name)
            module = _module(scope, name)
            if not module:
                continue
            numeric = _numeric_id((scope or {}).get("id"))
            return _module(self.profiles.get(str(numeric)), name), module.get("edgeSpecificData")
        return {}, None

    def _segments(self) -> list[dict[str, Any]]:
        """The segments of the enterprise as the union of
        `deviceSettings.segments[].segment` of every edge. Each segment has one
        entry with all of its keys.

        2 blocks that share a key are one segment. The id is the logicalId
        when a block has one (an APIv2 body), else the integer `segmentId`
        (a Portal body has no logicalId), else the name. The entry keeps every
        key. The route table identifies a segment by the integer alone and
        resolves through these keys."""
        entries: list[dict[str, Any]] = []
        for data in self.settings.values():
            for block in data.get("segments") or []:
                if not isinstance(block, dict):
                    continue
                keys = _segment_keys(block)
                if not keys:
                    continue
                nested = block.get("segment") if isinstance(block.get("segment"), dict) else {}
                numeric = as_int(block.get("segmentId"))
                if numeric is None:
                    numeric = as_int(nested.get("segmentId"))
                found = {
                    "numeric": None if numeric is None else str(numeric),
                    "ref": _ref_id(nested),
                    "name": str(nested["name"]) if nested.get("name") else None,
                    "keys": set(keys),
                }
                for entry in [e for e in entries if e["keys"] & found["keys"]]:
                    entries.remove(entry)
                    for field in ("numeric", "ref", "name"):
                        found[field] = found[field] or entry[field]
                    found["keys"] |= entry["keys"]
                entries.append(found)
        by_id: dict[str, dict[str, Any]] = {}
        for entry in entries:
            ident = entry["ref"] or entry["numeric"] or entry["name"]
            name = entry["name"] or f"segment-{ident}"
            by_id[ident] = {
                "id": ident,
                "name": name,
                "keys": entry["keys"] | {name},
                "is_global": entry["numeric"] == "0" or name.lower().replace(" ", "") == "globalsegment",
            }
        if not by_id and self.edges:
            # The Portal listing was refused if no edge has a `deviceSettings` body.
            return [
                {
                    "id": "global",
                    "name": GLOBAL_SEGMENT_NAME,
                    "keys": {"0", GLOBAL_SEGMENT_NAME},
                    "is_global": True,
                }
            ]
        return sorted(by_id.values(), key=lambda s: (not s["is_global"], s["name"]))

    def _clusters(self) -> dict[str, dict[str, Any]]:
        """Names are compared without the spaces around them."""
        clusters: dict[str, dict[str, Any]] = {}

        def entry(cid: Any, name: Any) -> dict[str, Any] | None:
            if not cid:
                return None
            found = clusters.setdefault(str(cid), {"id": str(cid), "name": None, "members": set()})
            if name and str(name).strip():
                found["name"] = found["name"] or str(name).strip()
            return found

        for control in self.control.values():
            cluster = control.get("memberCluster") if isinstance(control.get("memberCluster"), dict) else {}
            found = entry(cluster.get("clusterLogicalId"), cluster.get("clusterName"))
            for member in _items(cluster.get("members")) if found else []:
                ref = str(member.get("edgeLogicalId") or "")
                if ref in self.edge_names:
                    found["members"].add(ref)
            for block in control.get("segments") or []:
                vpn = block.get("vpn") if isinstance(block, dict) else None
                for row in _items((vpn or {}).get("dataCenterEdges")):
                    found = entry(row.get("clusterLogicalId"), row.get("clusterName"))
                    ref = _ref_id(row)
                    if found and ref in self.edge_names:
                        found["members"].add(ref)
        by_name = {c["name"]: c for c in clusters.values() if c["name"]}
        for edge in self.edges:
            ha = edge.get("ha") if isinstance(edge.get("ha"), dict) else {}
            data = ha.get("data") if isinstance(ha.get("data"), dict) else {}
            found = by_name.get(str(data.get("clusterName") or "").strip())
            if found:
                found["members"].add(str(edge["logicalId"]))
        return clusters

    def cluster_of(self, eid: str) -> dict[str, Any] | None:
        return next((c for c in self.clusters.values() if eid in c["members"]), None)

    def ref_cluster(self, ref: Any) -> dict[str, Any] | None:
        """The cluster of one hub reference, matched by id or by name, or None."""
        if not isinstance(ref, dict):
            return None
        for key in (_ref_id(ref), _ref_id(ref.get("data")), ref.get("edgeLogicalId")):
            if key and str(key) in self.clusters:
                return self.clusters[str(key)]
        name = str(ref.get("name") or "").strip()
        return next((c for c in self.clusters.values() if name and c["name"] == name), None)

    def hub_edges(self, ref: Any) -> set[str]:
        """The edges of one hub reference. The result is the referenced edge,
        or every member of the referenced cluster. An unresolved reference
        gives an empty set."""
        if not isinstance(ref, dict):
            return set()
        for key in (_ref_id(ref), _ref_id(ref.get("data")), ref.get("edgeLogicalId")):
            if key and str(key) in self.edge_names:
                return {str(key)}
        cluster = self.ref_cluster(ref)
        if cluster:
            return set(cluster["members"])
        by_edge = {n: eid for eid, n in self.edge_names.items()}
        name = str(ref.get("name") or "").strip()
        return {by_edge[name]} if name in by_edge else set()

    def _hubs(self) -> set[str]:
        """The edges that act as hubs. An edge is a hub when its listing row
        has `isHub`, when it is a member of a hub cluster, when a
        `dataCenterEdges` or `dataCenterEdgeList` row of a `controlPlane`
        module refers to it, or when a profile hub reference resolves to it
        (`hub_edges`). No operation lists the clusters.
        `getEnterpriseHubClusters` answers `methodError`."""
        hubs = {str(e["logicalId"]) for e in self.edges if e.get("isHub")}
        for cluster in self.clusters.values():
            hubs |= cluster["members"]
        for control in self.control.values():
            for block in control.get("segments") or []:
                vpn = block.get("vpn") if isinstance(block, dict) else None
                rows = list((vpn or {}).get("dataCenterEdges") or []) + list(
                    (block or {}).get("dataCenterEdgeList") or []
                )
                for row in rows:
                    ref = _ref_id(row) if isinstance(row, dict) else None
                    if ref in self.edge_names:
                        hubs.add(ref)
        for data in self.settings.values():
            for block in data.get("segments") or []:
                for ref in _hub_refs(block):
                    hubs |= self.hub_edges(ref)
        return hubs


def _hub_refs(block: Any) -> list[dict[str, Any]]:
    """The VPN hubs and the backhaul hubs of one `deviceSettings.segments[]`
    block."""
    vpn = block.get("vpn") if isinstance(block, dict) else None
    if not isinstance(vpn, dict):
        return []
    detail = vpn.get("edgeToEdgeDetail") if isinstance(vpn.get("edgeToEdgeDetail"), dict) else {}
    return [
        hub
        for hub in list(detail.get("vpnHubs") or []) + list(vpn.get("backHaulEdges") or [])
        if isinstance(hub, dict)
    ]


class _Edge:
    """The per-edge state the section writers share."""

    def __init__(self, ent: _Enterprise, edge: dict[str, Any], scope: str) -> None:
        self.b = ent.b
        self.ent = ent
        self.enterprise = ent.id
        self.eid = str(edge["logicalId"])
        self.name = edge.get("name") or self.eid
        self.uid = uid.velocloud(ent.id, "edge", self.eid)
        self.vrfs = VrfDomains(
            ent.b,
            self.uid,
            DomainPolicy(scope=f"{scope}:{uid.slug(ent.id)}"),
            lambda name: uid.vrf(self.uid, uid.slug(name)),
        )
        self.segment_vrf: dict[str, str] = {}  # VrfInstance uid by segment key
        self.segment_name: dict[str, str] = {}
        self.global_vrf: str | None = None
        self.vrf_name: dict[str, str] = {}  # segment name by VrfInstance uid
        self.if_uids: dict[str, str] = {}
        self.wan_ip_by_link: dict[str, str] = {}  # address by link id or interface
        self.link_if: dict[str, str] = {}  # interface name by link id
        self.link_name: dict[str, str] = {}  # WanLink name by link id
        self.link_uids: dict[str, str] = {}  # WanLink uid by link id
        self.link_kind: dict[str, str] = {}  # kind by link id
        self.link_public: dict[str, str] = {}  # address after NAT by link id
        self.link_network: dict[str, str] = {}  # private network name by link id
        self.segment_ids: list[str] = []
        self.policy_uid: str | None = None
        # The (application class, route type) pairs that the policy backhauls to each hub edge id.
        self.backhaul: dict[str, set[tuple[str, str]]] = {}
        self.gateway_tunnels: list[str] = []

    def vrf_for(self, node: Any) -> str | None:
        for key in _segment_keys(node):
            if key in self.segment_vrf:
                return self.segment_vrf[key]
        return None


def _segment_vrfs(edge: _Edge, data: dict[str, Any]) -> list[str]:
    """Writes one VrfInstance for each segment in the settings of the edge, or
    for every enterprise segment when the settings have none. The Global
    Segment is the global table of the edge. The WAN interfaces are in it, and
    the carrier trace routes the encapsulated packet in it (`path/trace.py`
    `_LOCAL_VRF_QUERY` reads `is_global`). Returns the segment ids of the edge."""
    own: set[str] = set()
    for block in data.get("segments") or []:
        for key in _segment_keys(block):
            for seg in edge.ent.segments:
                if key in seg["keys"]:
                    own.add(seg["id"])
    present = [seg for seg in edge.ent.segments if not own or seg["id"] in own]
    for seg in present:
        vu = edge.vrfs.add(seg["name"], is_global=seg["is_global"] or None, table_id=seg["id"])
        for key in seg["keys"] | {seg["id"]}:
            edge.segment_vrf[key] = vu
            edge.segment_name[key] = seg["name"]
        edge.vrf_name[vu] = seg["name"]
        if seg["is_global"] and edge.global_vrf is None:
            edge.global_vrf = vu
    if edge.global_vrf is None:
        edge.global_vrf = edge.vrfs.add(GLOBAL_SEGMENT_NAME, is_global=True)
        edge.vrf_name[edge.global_vrf] = GLOBAL_SEGMENT_NAME
    return [seg["id"] for seg in present]


def _interface(edge: _Edge, name: str, kind: str, cidr: str | None, vrf_uid: str | None, **props: Any) -> str:
    iu = uid.interface(edge.uid, name)
    edge.if_uids[name] = iu
    edge.b.node("Interface", iu, name=name, kind=kind, **props)
    edge.b.rel("ON", "Interface", iu, "Device", edge.uid)
    if kind == "phys":
        # The physical port of a routed interface. A Cisco LLDP row
        # (cable-from-neighbor-name) or the ARP-and-MAC join
        # (cable-from-arp-port) attaches a CONNECTED_TO edge to it.
        pu = edge.b.node("Port", uid.port(edge.uid, name), name=name)
        edge.b.rel("ON", "Port", pu, "Device", edge.uid)
        edge.b.rel("REALIZED_BY", "Interface", iu, "Port", pu)
    if vrf_uid:
        edge.b.rel("IN_VRF", "Interface", iu, "VrfInstance", vrf_uid)
    if cidr and vrf_uid:
        name_ = edge.vrf_name.get(vrf_uid, "")
        ipu, _ = connected_address(
            edge.b, cidr, anchor=vrf_uid, dom=edge.vrfs.domains.get(name_, name_), vrf_uid=vrf_uid
        )
        edge.b.rel("HAS_IP", "Interface", iu, "IpAddress", ipu)
    return iu


def subinterface_name(parent: str, sub_id: Any) -> str:
    """The name of a routed subinterface. The orchestrator identifies a
    subinterface by its parent interface and its `subinterfaceId` and gives it
    no name. The collector defines the form `<parent>:<subinterfaceId>`. A
    static route identifies the same subinterface by `wanInterface` and
    `subinterfaceId` and resolves to the same name."""
    return f"{parent}:{sub_id}"


def _subinterface(edge: _Edge, parent: str, sub: Any) -> None:
    """Writes one `routedInterfaces[].subinterfaces[]` entry. The entry is a
    VLAN-tagged interface on the port of the parent, with its own address and
    its own segment. A hub reaches its LAN routers through subinterfaces. Each
    BGP neighbor of a segment is on the connected prefix of a subinterface."""
    if not isinstance(sub, dict) or sub.get("disabled") is True:
        return
    sub_id = as_int(sub.get("subinterfaceId"))
    if sub_id is None or sub_id < 0:
        return
    addressing = sub.get("addressing") if isinstance(sub.get("addressing"), dict) else {}
    vid = as_int(sub.get("vlanId"))
    iu = _interface(
        edge,
        subinterface_name(parent, sub_id),
        "subif",
        _cidr(addressing),
        edge.vrf_for(sub) or edge.global_vrf,
        vlan=vid if vid is not None and vid >= 0 else None,
        subinterface_id=sub_id,
    )
    edge.b.rel("REALIZED_BY", "Interface", iu, "Port", uid.port(edge.uid, parent))


def _lan(edge: _Edge, data: dict[str, Any]) -> None:
    """Writes the routed interfaces, their subinterfaces, the loopbacks and the
    LAN networks (VLAN interfaces) from `deviceSettings`. A routed interface
    with a `wanOverlay` that is set and is not DISABLED is a WAN interface. A
    WAN interface is in the global table. Its `addressing.gateway` is the WAN
    next hop of the carrier walk."""
    for iface in data.get("routedInterfaces") or []:
        if not isinstance(iface, dict) or iface.get("disabled") is True:
            continue
        name = str(iface.get("name") or "")
        if not name:
            continue
        addressing = iface.get("addressing") if isinstance(iface.get("addressing"), dict) else {}
        cidr = _cidr(addressing)
        overlay = str(iface.get("wanOverlay") or "").upper()
        is_wan = overlay not in ("", "DISABLED")
        vrf_uid = edge.global_vrf if is_wan else (edge.vrf_for(iface) or edge.global_vrf)
        _interface(
            edge,
            name,
            "phys",
            cidr,
            vrf_uid,
            wan_overlay=is_wan or None,
            next_hop=_address_only(addressing.get("gateway")) if is_wan else None,
        )
        if cidr and is_wan:
            edge.wan_ip_by_link[name] = _address_only(cidr) or ""
        for sub in iface.get("subinterfaces") or []:
            _subinterface(edge, name, sub)
    # `loopbackInterfaces` is an object keyed by the loopback name
    loopbacks = data.get("loopbackInterfaces")
    for name, lo in sorted(loopbacks.items()) if isinstance(loopbacks, dict) else []:
        if not isinstance(lo, dict) or not name:
            continue
        cidr = None if lo.get("disableV4") is True else _cidr(lo)
        _interface(edge, str(name), "loopback", cidr, edge.vrf_for(lo) or edge.global_vrf)
    lan = data.get("lan") if isinstance(data.get("lan"), dict) else {}
    for network in lan.get("networks") or []:
        if not isinstance(network, dict) or network.get("disabled") is True:
            continue
        vid = as_int(network.get("vlanId"))
        name = str(network.get("name") or (f"vlan{vid}" if vid is not None else ""))
        if not name:
            continue
        _interface(edge, name, "vlan-if", _cidr(network), edge.vrf_for(network) or edge.global_vrf, vlan=vid)


_ORIGIN_CONTROLS = (
    "advertiseExternal",
    "advertiseInterArea",
    "advertiseIntraArea",
    "advertiseInternal",
    "advertiseStatic",
    "advertiseConnected",
)


def _origin_controls(edge: _Edge) -> dict[str, Any]:
    """The configured origin controls of one edge, from
    `controlPlane.routingConfiguration`. The block holds an `edge` role and a
    `hub` role. Each role has an `ospf`, a `bgp` and an `assigned` section.
    The block also holds the `preferenceBuckets`. They order the exits of the
    overlay route table by entity, exit type, protocol and route type."""
    control = edge.ent.control.get(edge.eid, {})
    routing = control.get("routingConfiguration")
    if not isinstance(routing, dict):
        return {}
    role = routing.get("hub" if edge.eid in edge.ent.hub_ids else "edge")
    props: dict[str, Any] = {
        "origin_role": "hub" if edge.eid in edge.ent.hub_ids else "edge",
        "preference_buckets": canonical_json(routing.get("preferenceBuckets"))
        if routing.get("preferenceBuckets")
        else None,
    }
    if not isinstance(role, dict):
        return props
    for section in role.values():
        if not isinstance(section, dict):
            continue
        for name in _ORIGIN_CONTROLS:
            if name in section:
                props[_snake(name)] = section[name]
    return props


def _snake(name: str) -> str:
    return "".join(f"_{c.lower()}" if c.isupper() else c for c in name)


def _bgp(edge: _Edge, data: dict[str, Any], boundary_gaps: list[str]) -> None:
    """Writes one RoutingProcess for each segment with BGP enabled and one
    BgpSession for each neighbor. `BgpSession` requires both ASNs
    (`core/labels.py`). A neighbor without an ASN is recorded as a gap on the
    edge and gets no session. The `controlPlane` origin controls are configured
    evidence. They apply to every process of the edge."""
    controls = _origin_controls(edge)
    for block in data.get("segments") or []:
        if not isinstance(block, dict):
            continue
        bgp = block.get("bgp")
        if not isinstance(bgp, dict) or bgp.get("enabled") is False:
            continue
        vrf_uid = edge.vrf_for(block)
        if vrf_uid is None:
            continue
        vrf_name = edge.vrf_name[vrf_uid]
        asn = as_int(_first(bgp, "ASN", "asn"))
        if asn is None:
            boundary_gaps.append(f"bgp local ASN absent in segment {vrf_name}")
            continue
        ru = edge.b.node(
            "RoutingProcess",
            uid.routing_process(edge.uid, vrf_name, "bgp"),
            proto="bgp",
            asn=asn,
            router_id=_first(bgp, "routerId"),
            origin_config_recorded=True,
            **controls,
        )
        edge.b.rel("IN_VRF", "RoutingProcess", ru, "VrfInstance", vrf_uid)
        for neighbor in bgp.get("neighbors") or []:
            if not isinstance(neighbor, dict):
                continue
            peer_ip = _address_only(neighbor.get("neighborIp"))
            peer_asn = as_int(neighbor.get("neighborAS"))
            if not peer_ip:
                continue
            if peer_asn is None:
                boundary_gaps.append(f"bgp neighbor {peer_ip} has no ASN")
                continue
            su = uid.bgp_session(ru, peer_ip, vrf_name)
            edge.b.node(
                "BgpSession",
                su,
                local_asn=asn,
                peer_asn=peer_asn,
                peer_ip=peer_ip,
                local_ip=_address_only(neighbor.get("localIp")),
                description=_first(neighbor, "neighborTag"),
            )
            edge.b.rel("HAS", "RoutingProcess", ru, "BgpSession", su)
            # The peer address anchors on the VRF of the session, like every
            # interface address (collectors/util.py connected_address).
            peer_uid = edge.b.node(
                "IpAddress",
                uid.ip(vrf_uid, peer_ip),
                ip=peer_ip,
                af=ipaddress.ip_address(peer_ip).version,
                anchor=vrf_uid,
                l3dom=edge.vrfs.domains.get(vrf_name, vrf_name),
            )
            edge.b.rel("ENDPOINT", "BgpSession", su, "IpAddress", peer_uid)


def _static_routes(edge: _Edge, data: dict[str, Any], sid: str, boundary_uid: str) -> None:
    """The SD-WAN gate reads these rows after the overlay rules (`path/gates/sdwan.py`)."""
    seg_keys = next((s["keys"] for s in edge.ent.segments if s["id"] == sid), set())
    for block in data.get("segments") or []:
        if not isinstance(block, dict) or not set(_segment_keys(block)) & seg_keys:
            continue
        routes = block.get("routes") if isinstance(block.get("routes"), dict) else {}
        for row in [*_items(routes.get("static")), *_items(routes.get("staticV6"))]:
            destination = _address_only(row.get("destination"))
            prefix = row.get("cidrPrefix")
            if prefix in (None, ""):
                prefix = row.get("netmask")
            if not destination or prefix in (None, ""):
                continue
            try:
                cidr = str(ipaddress.ip_network(f"{destination}/{prefix}", strict=False))
            except ValueError:
                continue
            gateway = _address_only(row.get("gateway"))
            parent = _first(row, "wanInterface")
            sub_id = row.get("subinterfaceId")
            interface = (
                subinterface_name(parent, sub_id) if parent and sub_id not in (None, "", -1, "-1") else parent
            )
            ru = edge.b.node(
                "SdwanStaticRoute",
                uid.velocloud(
                    edge.enterprise, f"edge-{edge.eid}-static", f"{sid}:{cidr}:{gateway or interface}"
                ),
                cidr=cidr,
                next_hop=gateway,
                interface=interface,
                cost=as_int(row.get("cost")),
                preferred=row.get("preferred"),
                advertise=row.get("advertise"),
                description=_first(row, "description"),
                segment_id=sid,
            )
            edge.b.rel("HAS_ROUTE", "ForwardingBoundary", boundary_uid, "SdwanStaticRoute", ru)


def _iso_s(value: Any) -> float:
    """An ISO 8601 time as epoch seconds, or minus infinity."""
    try:
        return datetime.fromisoformat(str(value)).timestamp()
    except ValueError:
        return float("-inf")


def _last_active_s(link: dict[str, Any]) -> float:
    """`lastActive` of a listing link row as epoch seconds, or minus infinity.
    The listing writes it as an ISO 8601 string. The `WAN` module row also
    has a `lastActive` in epoch milliseconds. That value is the time the link
    was first written to the configuration. The collector does not read it."""
    return _iso_s(link.get("lastActive"))


def _current_link_rows(
    rows: list[dict[str, Any]], wan_rows: list[dict[str, Any]]
) -> tuple[list[tuple[dict[str, Any], dict[str, Any] | None]], int, int]:
    """The configured link is the row whose `internalId` equals the `internalId` of a `WAN` row."""
    by_internal = {str(r["internalId"]): r for r in wan_rows if r.get("internalId")}
    by_lid = {str(ref): r for r in wan_rows if (ref := _ref_id(r))}
    groups: dict[str, list[dict[str, Any]]] = {}
    for link in rows:
        lid = _ref_id(link)
        if not lid or str(link.get("networkSide") or "WAN").upper() == "LAN":
            continue
        groups.setdefault(lid, []).append(link)
    chosen: list[tuple[dict[str, Any], dict[str, Any] | None]] = []
    duplicates = unconfigured = 0
    for lid, group in groups.items():
        duplicates += len(group) - 1
        wan = by_lid.get(lid)
        configured = [r for r in group if str(r.get("internalId") or "") in by_internal]
        link = configured[0] if configured else max(group, key=_last_active_s)
        wan = by_internal.get(str(link.get("internalId") or "")) or wan
        if wan is None and wan_rows:
            unconfigured += 1
            continue
        chosen.append((link, wan))
    return chosen, duplicates, unconfigured


def _wan_links(
    edge: _Edge,
    edge_row: dict[str, Any],
    provider_name: str | None,
    private: set[str],
    gaps: list[str],
    warnings: list[str] | None = None,
) -> None:
    """A link that the configuration does not describe keeps the fallback kind `dia`."""
    wan_rows = _items(edge.ent.wan.get(edge.eid, {}).get("links"))
    rows, duplicates, unconfigured = _current_link_rows(_items(edge_row.get("links")), wan_rows)
    if duplicates:
        gaps.append(
            f"{duplicates} older listing link rows share a logicalId with a written link and are not written"
        )
    if unconfigured:
        gaps.append(f"{unconfigured} listing links are not in the WAN module and are not written")
    freshness = edge.ent.details.get(edge.eid, {}).get("_freshness", {}).get("modules", {})
    assumed: list[str] = []
    for link, wan in rows:
        lid = str(_ref_id(link))
        ifname = str(link.get("interface") or "")
        kind, proven = _wan_kind(link, wan, private)
        network = _private_network(wan)
        # The carrier of a private link with no ISP is the name of its private network.
        carrier = (
            _first(link, "isp", "org")
            or _first(wan, "isp")
            or (network if kind == "mpls" else None)
            or ("mpls" if kind == "mpls" else "unknown")
        )
        # The listing `ipAddress` is the address of the link as the orchestrator
        # sees it, after any NAT in front of the edge. The address of the
        # interface comes from `deviceSettings` and can differ.
        own = edge.wan_ip_by_link.get(ifname) or None
        address = _address_only(link.get("ipAddress")) or own
        # The name of the WAN row is the name that the operator configured. The
        # listing `displayName` is the address for a link without a configured
        # name.
        link_name = str(_first(wan, "name") or link.get("displayName") or ifname or lid)
        if kind == "dia" and not proven:
            assumed.append(f"{link_name} ({lid})")
        link_uid = edge.b.node(
            "WanLink",
            uid.velocloud(edge.enterprise, f"edge-{edge.eid}-link", lid),
            name=link_name,
            kind=kind,
            carrier=carrier,
            public_ip=address,
            interface=ifname or None,
            link_logical_id=lid,
            state=link.get("state"),
            link_mode=link.get("linkMode"),
            wan_mode=_first(wan, "mode"),
            access_type=_first(wan, "type"),
            upstream_mbps=as_int(_first(wan, "upstreamMbps")),
            downstream_mbps=as_int(_first(wan, "downstreamMbps")),
            mtu=as_int(_first(wan, "MTU")),
            next_hop=_address_only(_first(wan, "nextHopIpAddress")),
            private_network=network,
            backup_only=(wan or {}).get("backupOnly"),
            hot_standby=(wan or {}).get("hotStandby"),
            vpn_state=link.get("vpnState"),
            backup_state=link.get("backupState"),
            # A graph property holds primitives. The row is stored as canonical JSON.
            configuration=canonical_json(wan) if wan else None,
            configuration_observed_at_ms=freshness.get("observed_at_ms"),
            configuration_stale=freshness.get("stale"),
            origin_config_recorded=proven,
            candidate_set_complete=False,
        )
        edge.b.rel("HAS_LINK", "Device", edge.uid, "WanLink", link_uid)
        edge.link_uids[lid] = link_uid
        edge.link_name[lid] = link_name
        edge.link_kind[lid] = kind
        if address:
            edge.link_public[lid] = address
        if network:
            edge.link_network[lid] = network
        if ifname:
            edge.link_if[lid] = ifname
        local = own or address
        if local:
            # The edge sends tunnel traffic from this address.
            edge.wan_ip_by_link[lid] = local
        if address and ifname and ifname not in edge.if_uids and edge.global_vrf:
            _interface(edge, ifname, "phys", f"{address}/32", edge.global_vrf, wan_overlay=True)
            own = local = address
        if ifname in edge.if_uids:
            edge.b.rel("ON", "WanLink", link_uid, "Interface", edge.if_uids[ifname])
        if edge.global_vrf:
            # The link holds the address of the interface and the address after
            # NAT. The shared interface address joins the link to its interface
            # (`path/gates/sdwan.py`, `path/trace.py` `_PROVIDER_OF_LINK_QUERY`).
            # The tunnel of another edge terminates on the address after NAT.
            # The interface holds the interface address alone.
            for ip in dict.fromkeys(x for x in (local, address) if x):
                ipu = edge.b.node(
                    "IpAddress",
                    uid.ip(edge.global_vrf, ip),
                    ip=ip,
                    af=ipaddress.ip_address(ip).version,
                    anchor=edge.global_vrf,
                )
                edge.b.rel("HAS_IP", "WanLink", link_uid, "IpAddress", ipu)
                if ip == local and not own and ifname in edge.if_uids:
                    # `deviceSettings` has no address for a DHCP interface. The
                    # link address is the only known address of the interface.
                    edge.b.rel("HAS_IP", "Interface", edge.if_uids[ifname], "IpAddress", ipu)
        pkind = _PROVIDER_KIND[kind]
        pnet = edge.b.node(
            "ProviderNetwork", uid.provider_network(pkind, str(carrier)), name=str(carrier), kind=pkind
        )
        edge.b.rel("PROVIDED_BY", "WanLink", link_uid, "ProviderNetwork", pnet)
        if pkind == "mpls" and provider_name:
            prov = edge.b.node("Provider", uid.provider(provider_name), name=provider_name)
            edge.b.rel("PROVIDED_BY", "ProviderNetwork", pnet, "Provider", prov)
    if assumed and warnings is not None:
        warnings.append(_assumed_dia_warning(edge, assumed))


def _gateway_tunnels(edge: _Edge, segment_ids: list[str]) -> None:
    """Only a gateway with the `VPN_TUNNEL` role terminates an overlay tunnel."""
    ent = edge.ent
    control = ent.control.get(edge.eid, {})
    freshness = ent.details.get(edge.eid, {}).get("_freshness", {}).get("modules", {})
    # The key is a gateway logicalId. The value is (row, the segment keys of the gateway).
    gateways: dict[str, tuple[dict[str, Any], set[str]]] = {}

    def remember(row: Any, keys: set[str]) -> None:
        if not isinstance(row, dict):
            return
        if not any(
            str((role or {}).get("role") or "") == VPN_TUNNEL_ROLE
            for role in row.get("roles") or []
            if isinstance(role, dict)
        ):
            return
        gid = _ref_id(row)
        if not gid:
            return
        # `controlPlane` prefixes the uuid with `gateway`. Every other operation
        # returns the uuid without the prefix. The uid is built from the uuid
        # without the prefix.
        gid = gid.removeprefix(GATEWAY_PREFIX)
        entry = gateways.setdefault(gid, (row, set()))
        entry[1].update(keys)

    for block in control.get("gatewaySegmentDetailList") or []:
        if not isinstance(block, dict):
            continue
        keys = set(_segment_keys(block)) or set(_segment_keys(block.get("segment")))
        for row in block.get("gatewayDetailList") or []:
            remember(row, keys)
    for row in control.get("gatewayDetailList") or []:
        remember(row, set(segment_ids))

    for gid, (row, keys) in sorted(gateways.items()):
        far_ip = _address_only(row.get("ipAddress"))
        far_name = str(row.get("name") or gid)
        far_uid = edge.b.node(
            "SdwanGateway",
            uid.velocloud(edge.enterprise, "gateway", gid),
            name=far_name,
            ip=far_ip,
            roles=canonical_json(row.get("roles")) if row.get("roles") else None,
        )
        realized: list[str] = []
        for lid in sorted(edge.link_uids):
            tu = edge.b.node(
                "Tunnel",
                uid.velocloud(edge.enterprise, "path", f"{_link_end(edge, lid)}~gw:{gid}"),
                # The name holds the WAN link and the gateway. The hostname is on
                # the device and the port is on the `ENDPOINT` interface.
                name=f"{_link_name(edge, lid)} to {far_name}",
                encap=ENCAP,
                carrier_proto="udp",
                endpoint_port=VCMP_PORT,
                endpoint=far_ip,
                local_address=edge.wan_ip_by_link.get(lid),
                pair=uid.tunnel(ENCAP, _link_end(edge, lid), f"gw:{gid}"),
                peer_type="gateway",
                direction_observed=False,
                origin_config_recorded=True,
                configuration_observed_at_ms=freshness.get("observed_at_ms"),
                configuration_stale=freshness.get("stale"),
            )
            edge.gateway_tunnels.append(tu)
            realized.append(tu)
            src_if = _link_interface(edge, lid)
            if src_if:
                edge.b.rel("ENDPOINT", "Tunnel", tu, "Interface", src_if)
            edge.b.rel("TERMINATES_ON", "Tunnel", tu, "SdwanGateway", far_uid)
            for key in keys or set(segment_ids):
                seg_uid = ent.segment_uids.get(key)
                if seg_uid:
                    edge.b.rel("CARRIES", "Tunnel", tu, "SdwanSegment", seg_uid)
        # The edge reports a gateway assignment. The collector does not read the gateway.
        overlay_connection(
            edge.b,
            ENCAP,
            (
                OverlayEnd(edge.uid, "Device", edge.uid, _edge_role(edge), reported=True),
                OverlayEnd(far_uid, "SdwanGateway", far_uid, "gateway"),
            ),
            realized,
            name=f"{edge.name} to {far_name}",
        )


def _edge_role(edge: _Edge) -> str:
    """The role of an edge as an end of an `OverlayConnection`."""
    return "hub" if edge.eid in edge.ent.hub_ids else "edge"


def _link_name(edge: _Edge, link_id: str) -> str:
    """The name of a WAN link in a `Tunnel` name. It is the `WanLink` name,
    else the interface name, else the logicalId."""
    return edge.link_name.get(link_id) or edge.link_if.get(link_id) or link_id


def _link_end(edge: _Edge, link_id: str) -> str:
    """The link logicalId alone is not unique in an enterprise."""
    return f"{edge.eid}:{link_id}"


def _link_interface(edge: _Edge, link_id: str) -> str | None:
    name = edge.link_if.get(link_id)
    return edge.if_uids.get(name) if name else None


def _private_network(wan: dict[str, Any] | None) -> str | None:
    """The private network of a PRIVATE link from the `WAN` row. The field is
    `privateNetwork` (a name, or an object with a name) or `mplsNetwork`."""
    for key in ("privateNetwork", "mplsNetwork"):
        value = (wan or {}).get(key)
        if isinstance(value, dict):
            value = value.get("name") or value.get("logicalId")
        if value not in (None, "") and str(value).strip():
            return str(value).strip()
    return None


def _links_pair(a: _Edge, lid_a: str, b: _Edge, lid_b: str) -> bool:
    """True when 2 WAN links can form an overlay tunnel. A public link pairs
    with a public link over the internet. A private link pairs with a private
    link. When both private links have a private network name, the names must
    be equal."""
    kind_a, kind_b = a.link_kind.get(lid_a), b.link_kind.get(lid_b)
    if (kind_a == "mpls") != (kind_b == "mpls"):
        return False
    net_a, net_b = a.link_network.get(lid_a), b.link_network.get(lid_b)
    return kind_a != "mpls" or not (net_a and net_b) or net_a == net_b


def _assigned_hubs(ent: _Enterprise, edge: _Edge, block: dict[str, Any], ref: dict[str, Any]) -> set[str]:
    """The hub edges of one reference of a branch segment. For a cluster, the
    result is the member that the `controlPlane` of the branch assigns
    (`segments[].vpn.dataCenterEdges[]` with the `clusterLogicalId` of the
    cluster), else every member."""
    members = ent.hub_edges(ref)
    cluster = ent.ref_cluster(ref)
    if cluster is None or len(members) < 2:
        return members
    keys = set(_segment_keys(block))
    assigned: set[str] = set()
    fallback: set[str] = set()
    for cp_block in ent.control.get(edge.eid, {}).get("segments") or []:
        vpn = cp_block.get("vpn") if isinstance(cp_block, dict) else None
        same_segment = bool(keys & set(_segment_keys(cp_block)))
        for row in _items((vpn or {}).get("dataCenterEdges")):
            member = _ref_id(row)
            if str(row.get("clusterLogicalId") or "") == cluster["id"] and member in members:
                (assigned if same_segment else fallback).add(str(member))
    return assigned or fallback or members


def _control_hub_refs(ent: _Enterprise, eid: str, block: dict[str, Any]) -> list[dict[str, Any]]:
    """The single hub edges in the `controlPlane` of the edge for the segment
    of one `deviceSettings.segments[]` block. They are the
    `vpn.dataCenterEdges` rows of type `edgeHub`. The orchestrator returns
    these rows for a branch-to-hub VPN that a profile sets in
    `vpn.edgeToEdgeHub`. `_hub_refs` does not read `vpn.edgeToEdgeHub`. The
    cluster rows of `vpn.dataCenterEdges` repeat the `vpnHubs` clusters."""
    keys = set(_segment_keys(block))
    refs: list[dict[str, Any]] = []
    for cp_block in ent.control.get(eid, {}).get("segments") or []:
        if not isinstance(cp_block, dict) or not keys & set(_segment_keys(cp_block)):
            continue
        vpn = cp_block.get("vpn") if isinstance(cp_block.get("vpn"), dict) else {}
        refs += [row for row in _items(vpn.get("dataCenterEdges")) if str(row.get("type") or "") == "edgeHub"]
    return refs


def _hub_tunnels(ent: _Enterprise, edges: dict[str, _Edge]) -> None:
    """Both ends need a `WAN` module body."""
    pairs: dict[tuple[str, str], set[str]] = {}
    for eid, edge in edges.items():
        for block in ent.settings.get(eid, {}).get("segments") or []:
            sid = next((seg["id"] for seg in ent.segments if set(_segment_keys(block)) & seg["keys"]), None)
            if sid is None:
                continue
            for ref in _hub_refs(block) + _control_hub_refs(ent, eid, block):
                for hub_id in _assigned_hubs(ent, edge, block, ref):
                    if hub_id != eid and hub_id in edges and sid in edges[hub_id].segment_ids:
                        pairs.setdefault((eid, hub_id), set()).add(sid)
    for (eid, hub_id), sids in sorted(pairs.items()):
        missing = [e for e in (eid, hub_id) if not ent.wan.get(e)]
        if missing:
            # No link pair is readable. The boundary of each edge gets a gap with the edge
            # that has no WAN body.
            for near, far in ((eid, hub_id), (hub_id, eid)):
                _boundary_gap(
                    ent,
                    edges[near],
                    sids,
                    f"no Tunnel to {edges[far].name} is written: "
                    f"{', '.join(edges[m].name for m in missing)} has no WAN module body",
                )
            continue
        edge, hub = edges[eid], edges[hub_id]
        realized: list[str] = []
        for lid in sorted(edge.link_uids):
            for hlid in sorted(hub.link_uids):
                if not _links_pair(edge, lid, hub, hlid):
                    continue
                pair = uid.tunnel(ENCAP, _link_end(edge, lid), _link_end(hub, hlid))
                for near, near_lid, far, far_lid in ((edge, lid, hub, hlid), (hub, hlid, edge, lid)):
                    # `peer_type` is the role of the far edge. When 2 edges refer
                    # to each other, both keys of `pairs` write the same tunnels
                    # with the same peer type.
                    peer_type = "hub" if far.eid in ent.hub_ids else "edge"
                    tu = _edge_tunnel(ent, near, near_lid, far, far_lid, pair, peer_type, sids)
                    realized.append(tu)
                    for rule_name, route_type in sorted(near.backhaul.get(far.eid, ())):
                        if near.policy_uid:
                            near.b.rel(
                                "STEERS_VIA",
                                "SdwanBusinessPolicy",
                                near.policy_uid,
                                "Tunnel",
                                tu,
                                key={"application_class": rule_name, "route_type": route_type},
                                application_class=rule_name,
                                route_type=route_type,
                                route_policy="backhaul",
                            )
        # When 2 edges refer to each other, both keys of `pairs` write the same
        # connection. An edge reports the connection when its configuration
        # refers to the other edge.
        ends = sorted((edge, hub), key=lambda e: e.uid)
        overlay_connection(
            edge.b,
            ENCAP,
            (
                OverlayEnd(edge.uid, "Device", edge.uid, _edge_role(edge), reported=(eid, hub_id) in pairs),
                OverlayEnd(hub.uid, "Device", hub.uid, _edge_role(hub), reported=(hub_id, eid) in pairs),
            ),
            realized,
            name=f"{ends[0].name} to {ends[1].name}",
        )


def _boundary_gap(ent: _Enterprise, edge: _Edge, sids: set[str], gap: str) -> None:
    """Add `gap` to the edge's forwarding boundary in each segment of `sids`."""
    for sid in sorted(sids):
        boundary = uid.velocloud(ent.id, f"edge-{edge.eid}-boundary", sid)
        held = edge.b.props("ForwardingBoundary", boundary)
        if not held:
            continue
        gaps = list(held.get("gaps") or [])
        if gap not in gaps:
            edge.b.node("ForwardingBoundary", boundary, gaps=[*gaps, gap])


def _edge_tunnel(
    ent: _Enterprise,
    near: _Edge,
    near_lid: str,
    far: _Edge,
    far_lid: str,
    pair: str,
    peer_type: str,
    sids: set[str],
) -> str:
    freshness = ent.details.get(near.eid, {}).get("_freshness", {}).get("modules", {})
    far_ip = far.link_public.get(far_lid) or far.wan_ip_by_link.get(far_lid)
    tu = near.b.node(
        "Tunnel",
        uid.velocloud(ent.id, "path", f"{_link_end(near, near_lid)}~link:{_link_end(far, far_lid)}"),
        # The name holds the 2 WAN links. The hostnames are on the devices at
        # the ends, and the near port is the `ENDPOINT` interface.
        name=f"{_link_name(near, near_lid)} to {_link_name(far, far_lid)}",
        encap=ENCAP,
        carrier_proto="udp",
        endpoint_port=VCMP_PORT,
        endpoint=far_ip,
        local_address=near.wan_ip_by_link.get(near_lid),
        pair=pair,
        peer_type=peer_type,
        direction_observed=False,
        origin_config_recorded=True,
        configuration_observed_at_ms=freshness.get("observed_at_ms"),
        configuration_stale=freshness.get("stale"),
    )
    src_if = _link_interface(near, near_lid)
    if src_if:
        near.b.rel("ENDPOINT", "Tunnel", tu, "Interface", src_if)
    if far_ip and far.global_vrf:
        near.b.rel("TERMINATES_ON", "Tunnel", tu, "IpAddress", uid.ip(far.global_vrf, far_ip))
    for sid in sorted(sids):
        seg_uid = ent.segment_uids.get(sid)
        if seg_uid:
            near.b.rel("CARRIES", "Tunnel", tu, "SdwanSegment", seg_uid)
    return tu


_LINK_POLICY_KIND = {
    "fixed": None,
    "auto": None,
    "mpls": "mpls",
    "private": "mpls",
    "internet": "dia",
    "public": "dia",
    "direct": "dia",
    "wireless": "lte",
    "lte": "lte",
}


def _steering(edge: _Edge, policy_uid: str, qos: dict[str, Any]) -> None:
    """Writes `STEERS_VIA` from the effective policy to each WAN link of a
    business rule. A `QOSRouteAction` selects a link by
    `linkInternalLogicalId`, `wanlink` or `interface`, or a class of link by
    `linkPolicy`. The SD-WAN gate reads these edges at rule 4
    (`path/gates/sdwan.py`)."""
    by_interface = {name: lid for lid, name in edge.link_if.items()}
    for block in qos.get("segments") or []:
        if not isinstance(block, dict):
            continue
        for rule in block.get("rules") or []:
            if not isinstance(rule, dict):
                continue
            action = rule.get("action") if isinstance(rule.get("action"), dict) else {}
            targets: set[str] = set()
            preference = None
            for key in ("edge2EdgeRouteAction", "edge2DataCenterRouteAction", "edge2CloudRouteAction"):
                route = action.get(key)
                if not isinstance(route, dict):
                    continue
                for ref in (
                    route.get("linkInternalLogicalId"),
                    route.get("wanlink"),
                    _ref_id(route.get("link")),
                    by_interface.get(str(route.get("interface") or "")),
                ):
                    if ref and str(ref) in edge.link_uids:
                        targets.add(str(ref))
                policy = str(route.get("linkPolicy") or "").lower()
                want = _LINK_POLICY_KIND.get(policy)
                if want:
                    preference = preference or policy
                    targets.update(lid for lid, kind in edge.link_kind.items() if kind == want)
            rule_name = str(rule.get("name") or rule.get("ruleLogicalId") or "")
            for lid in sorted(targets):
                edge.b.rel(
                    "STEERS_VIA",
                    "SdwanBusinessPolicy",
                    policy_uid,
                    "WanLink",
                    edge.link_uids[lid],
                    key={"application_class": rule_name},
                    application_class=rule_name,
                    preference=preference,
                )
            for key in _ROUTE_ACTIONS:
                route = action.get(key)
                if isinstance(route, dict):
                    _route_policy(edge, policy_uid, block, rule_name, key.removesuffix("RouteAction"), route)


_ROUTE_ACTIONS = ("edge2EdgeRouteAction", "edge2DataCenterRouteAction", "edge2CloudRouteAction")


def _route_policy(
    edge: _Edge,
    policy_uid: str,
    block: dict[str, Any],
    rule_name: str,
    route_type: str,
    route: dict[str, Any],
) -> None:
    """Writes the `STEERS_VIA` edges of one route action for the traffic that
    its rule matches.

    `routePolicy` is `direct`, `gateway`, `backhaul` or `auto`. `direct` sends
    the traffic out of the public links of the edge to the internet and writes
    an edge to each public `WanLink`. `gateway` sends it through the cloud
    gateways and writes an edge to each gateway `Tunnel`. `backhaul` sends it
    to the hubs of `routeCfg.backhaulEdges` and writes an edge to each hub
    `Device`. A cluster resolves to the member that the edge is assigned.
    `_hub_tunnels` writes the edges to the tunnels of the edge to the hub.
    `auto` leaves the choice to the orchestrator and writes no edge. Each edge
    has `route_policy`, `route_type` and the `segment_id` of the segment of
    the rule. A boundary reads the exits of its own segment by `segment_id`.
    The SD-WAN gate evaluates the match of the rule at rule 4
    (`path/gates/sdwan.py`) and selects the candidates from these edges."""
    policy = str(route.get("routePolicy") or "").lower()
    segment = block.get("segment") if isinstance(block.get("segment"), dict) else {}
    sid = str(segment.get("segmentId", ""))
    props = {
        "application_class": rule_name,
        "route_type": route_type,
        "route_policy": policy,
        "segment_id": sid,
    }
    key = {"application_class": rule_name, "route_type": route_type, "segment_id": sid}
    if policy == "direct":
        for lid in sorted(lid for lid, kind in edge.link_kind.items() if kind != "mpls"):
            edge.b.rel(
                "STEERS_VIA",
                "SdwanBusinessPolicy",
                policy_uid,
                "WanLink",
                edge.link_uids[lid],
                key=key,
                **props,
            )
    elif policy == "gateway":
        for tu in edge.gateway_tunnels:
            edge.b.rel("STEERS_VIA", "SdwanBusinessPolicy", policy_uid, "Tunnel", tu, key=key, **props)
    elif policy == "backhaul":
        cfg = route.get("routeCfg") if isinstance(route.get("routeCfg"), dict) else {}
        for ref in _items(cfg.get("backhaulEdges")):
            for hub_id in sorted(_assigned_hubs(edge.ent, edge, block, ref)):
                if hub_id == edge.eid:
                    continue
                hub_uid = uid.velocloud(edge.enterprise, "edge", hub_id)
                edge.b.rel(
                    "STEERS_VIA", "SdwanBusinessPolicy", policy_uid, "Device", hub_uid, key=key, **props
                )
                edge.backhaul.setdefault(hub_id, set()).add((rule_name, route_type))


# `routeType` selects the route actions of a rule. The property prefix of each
# of the 3 keys is the spelling of the orchestrator in lower case.
_RULE_ROUTE_PREFIX = {
    "edge2EdgeRouteAction": "edge2edge",
    "edge2DataCenterRouteAction": "edge2datacenter",
    "edge2CloudRouteAction": "edge2cloud",
}
_PROTO_NAME = {1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp", 58: "icmpv6"}


def _set(value: Any) -> Any:
    """The orchestrator writes -1, an empty string or "any" for a field that
    the rule leaves open. The function returns None for each of them."""
    if value is None or value == -1 or value == "-1" or value == "" or value == "any":
        return None
    return value


def _rule_prefix(ip: Any, mask: Any) -> str | None:
    if _set(ip) is None:
        return None
    try:
        return str(ipaddress.ip_network(f"{ip}/{mask or '255.255.255.255'}", strict=False))
    except ValueError:
        return str(ip)


def _rule_ports(low: Any, high: Any) -> str | None:
    if _set(low) is None:
        return None
    return str(low) if _set(high) is None or high == low else f"{low}-{high}"


# The match keys that `_rule_match` maps. `match_unmapped` lists any other key
# with a set value.
_MAPPED_MATCH_KEYS = frozenset(
    {
        "appid",
        "classid",
        "dscp",
        "proto",
        "sip",
        "ssm",
        "dip",
        "dsm",
        "sport_low",
        "sport_high",
        "dport_low",
        "dport_high",
        "hostname",
        "sInterface",
        "dInterface",
        "svlan",
        "dvlan",
        "ipVersion",
    }
)


def _unmapped_match(match: dict[str, Any]) -> list[str] | None:
    names = sorted(
        key
        for key, value in match.items()
        if key not in _MAPPED_MATCH_KEYS and _set(value) is not None and value not in ([], {}, "ANY")
    )
    return names or None


def _rule_match(match: dict[str, Any]) -> dict[str, Any]:
    proto = _set(match.get("proto"))
    props: dict[str, Any] = {
        "match_app_id": _set(match.get("appid")),
        "match_app_class_id": _set(match.get("classid")),
        "match_dscp": _set(match.get("dscp")),
        "match_proto": _PROTO_NAME.get(proto, str(proto)) if proto is not None else None,
        "match_src": _rule_prefix(match.get("sip"), match.get("ssm")),
        "match_dst": _rule_prefix(match.get("dip"), match.get("dsm")),
        "match_src_port": _rule_ports(match.get("sport_low"), match.get("sport_high")),
        "match_dst_port": _rule_ports(match.get("dport_low"), match.get("dport_high")),
        "match_hostname": _set(match.get("hostname")),
        "match_src_interface": _set(match.get("sInterface")),
        "match_dst_interface": _set(match.get("dInterface")),
        "match_src_vlan": _set(match.get("svlan")),
        "match_dst_vlan": _set(match.get("dvlan")),
        "match_ip_version": _set(match.get("ipVersion")),
    }
    words = [
        f"app {props['match_app_id']}" if props["match_app_id"] is not None else None,
        f"class {props['match_app_class_id']}" if props["match_app_class_id"] is not None else None,
        f"dscp {props['match_dscp']}" if props["match_dscp"] is not None else None,
        props["match_proto"],
        f"src {props['match_src']}" if props["match_src"] else None,
        f"dst {props['match_dst']}" if props["match_dst"] else None,
        f"sport {props['match_src_port']}" if props["match_src_port"] else None,
        f"dport {props['match_dst_port']}" if props["match_dst_port"] else None,
        f"host {props['match_hostname']}" if props["match_hostname"] else None,
    ]
    props["match_summary"] = " ".join(w for w in words if w) or "any"
    return props


def _rule_action(action: dict[str, Any]) -> dict[str, Any]:
    qos = action.get("QoS") if isinstance(action.get("QoS"), dict) else {}
    tx = qos.get("txScheduler") if isinstance(qos.get("txScheduler"), dict) else {}
    rx = qos.get("rxScheduler") if isinstance(qos.get("rxScheduler"), dict) else {}
    sla = action.get("sla") if isinstance(action.get("sla"), dict) else {}
    nat = action.get("nat") if isinstance(action.get("nat"), dict) else {}
    props: dict[str, Any] = {
        "qos_class": _set(qos.get("type")),
        "priority_tx": _set(tx.get("priority")),
        "priority_rx": _set(rx.get("priority")),
        "bandwidth_cap_pct_tx": _set(tx.get("bandwidthCapPct")),
        "bandwidth_cap_pct_rx": _set(rx.get("bandwidthCapPct")),
        "route_type": _set(action.get("routeType")),
        # The orchestrator writes "0" for an unset threshold.
        "sla_latency_ms": _set(sla.get("latencyMs")) if str(sla.get("latencyMs")) != "0" else None,
        "sla_jitter_ms": _set(sla.get("jitterMs")) if str(sla.get("jitterMs")) != "0" else None,
        "sla_loss_pct": _set(sla.get("lossPct")) if str(sla.get("lossPct")) not in ("0", "0.0") else None,
        "nat_source": _set(nat.get("sourceIp")) if nat.get("sourceIp") != "no" else None,
        "nat_dest": _set(nat.get("destIp")) if nat.get("destIp") != "no" else None,
    }
    for key, prefix in _RULE_ROUTE_PREFIX.items():
        route = action.get(key)
        if not isinstance(route, dict):
            continue
        cfg = route.get("routeCfg") if isinstance(route.get("routeCfg"), dict) else {}
        hubs = [str(ref.get("name") or "").strip() for ref in _items(cfg.get("backhaulEdges"))]
        props[f"{prefix}_route_policy"] = _set(route.get("routePolicy"))
        props[f"{prefix}_link_policy"] = _set(route.get("linkPolicy"))
        props[f"{prefix}_wanlink"] = None if route.get("wanlink") == "auto" else _set(route.get("wanlink"))
        props[f"{prefix}_outer_dscp"] = _set(route.get("linkOuterDscpTag"))
        props[f"{prefix}_backhaul_hubs"] = [h for h in hubs if h] or None
    return props


def _policy_rules(edge: _Edge, policy_uid: str, qos: dict[str, Any]) -> int:
    """Writes one `SdwanPolicyRule` for each rule of each segment. The order is
    the order in which the edge reads the rules, first the `rules` of the
    segment and then its `defaults`. Each rule has its match and its action as
    flat properties. A field that the rule leaves open is absent. Returns the
    count of written rules."""
    count = 0
    for block in qos.get("segments") or []:
        if not isinstance(block, dict):
            continue
        segment = block.get("segment") if isinstance(block.get("segment"), dict) else {}
        sid = str(segment.get("segmentId", ""))
        position = 0
        for default, rules in ((False, block.get("rules")), (True, block.get("defaults"))):
            for index, rule in enumerate(rules or []):
                if not isinstance(rule, dict):
                    continue
                position += 1
                # A rule with no ruleLogicalId is keyed by the index in its own list
                # (rules or defaults) and the name.
                fallback = (
                    f"{'default' if default else 'rule'}-{index + 1}-{uid.slug(str(rule.get('name') or ''))}"
                )
                rid = str(rule.get("ruleLogicalId") or fallback)
                match = rule.get("match") if isinstance(rule.get("match"), dict) else {}
                action = rule.get("action") if isinstance(rule.get("action"), dict) else {}
                rule_uid = edge.b.node(
                    "SdwanPolicyRule",
                    uid.velocloud(edge.enterprise, f"edge-{edge.eid}-rule", f"{sid}:{rid}"),
                    name=str(rule.get("name") or rid),
                    rule_logical_id=rule.get("ruleLogicalId"),
                    override=True if rule.get("_override") else None,
                    position=position,
                    default=default,
                    segment_id=sid or None,
                    segment_name=segment.get("name"),
                    **_rule_match(match),
                    match_unmapped=_unmapped_match(match),
                    **_rule_action(action),
                )
                edge.b.rel(
                    "HAS_RULE",
                    "SdwanBusinessPolicy",
                    policy_uid,
                    "SdwanPolicyRule",
                    rule_uid,
                    position=position,
                )
                seg_uid = edge.ent.segment_uids.get(sid)
                if seg_uid:
                    edge.b.rel("IN", "SdwanPolicyRule", rule_uid, "SdwanSegment", seg_uid)
                count += 1
    return count


def _normalize_enterprise(
    b: GraphBuilder,
    body: dict[str, Any],
    *,
    scope: str,
    provider_name: str | None,
    private: set[str],
    warnings: list[str] | None = None,
) -> None:
    enterprise = str(body.get("logicalId") or "")
    if not enterprise:
        return
    ent = _Enterprise(b, enterprise, body)
    for seg in ent.segments:
        su = b.node(
            "SdwanSegment",
            uid.velocloud(enterprise, "segment", seg["id"]),
            segment_id=seg["id"],
            name=seg["name"],
            enterprise_logical_id=enterprise,
            enterprise_name=body.get("name"),
        )
        for key in seg["keys"] | {seg["id"]}:
            ent.segment_uids[key] = su
    enterprise_gaps = [
        canonical_json(gap.get("_capability") or gap)
        for gap in body.get("gaps") or []
        if isinstance(gap, dict)
    ]
    # The listing, the profiles and the route table are read live on every poll.
    # The poll time is the observation time of the effective configuration of
    # each edge. The 2 cached modules have their own stamp on the `WanLink` and
    # the `Tunnel`. A stale module read is a gap on the boundary.
    observed_at_ms = body.get("fetched_at_ms")
    built: dict[str, _Edge] = {}
    for edge_row in ent.edges:
        edge = _Edge(ent, edge_row, scope)
        built[edge.eid] = edge
        eid = edge.eid
        observed = ent.details.get(eid, {})
        data = ent.settings.get(eid, {})
        site = edge_row.get("site") if isinstance(edge_row.get("site"), dict) else {}
        # The site of the orchestrator (`EdgeResource.site`, a SiteResource).
        # An operator binds the reported location to a Site on the Sites
        # page, and the next run writes LOCATED_IN (collectors/base.py
        # REPORTED_LOCATION_PROP). The reported location is keyed by
        # enterprise. 2 enterprises can have a site with the same name.
        site_id = _ref_id(site) or site.get("name")
        b.node(
            "Device",
            edge.uid,
            hostname=edge.name,
            serial=chassis_serial(edge_row.get("serialNumber")) or eid,
            platform="velocloud-edge",
            role="sdwan-hub" if eid in ent.hub_ids else "sdwan-edge",
            vendor="VeloCloud",
            model=edge_row.get("modelNumber"),
            software_version=edge_row.get("softwareVersion"),
            edge_state=edge_row.get("edgeState"),
            enterprise_logical_id=enterprise,
            enterprise_name=body.get("name"),
            edge_logical_id=eid,
            reported_location=f"{enterprise}/{site_id}" if site_id else None,
            reported_location_name=site.get("name") or site_id,
            site_city=site.get("city"),
            site_country=site.get("country"),
            site_lat=site.get("lat"),
            site_lon=site.get("lon"),
            sdwan_role="hub" if eid in ent.hub_ids else None,
            configuration_observed_at_ms=observed_at_ms,
            **_ha_props(ent, edge_row),
        )
        segment_ids = _segment_vrfs(edge, data)
        qos = ent.qos.get(eid, {})
        modules = observed.get("modules")
        module_gap = modules.get("_capability") if isinstance(modules, dict) else None
        policy_uid = b.node(
            "SdwanBusinessPolicy",
            uid.velocloud(enterprise, f"edge-{eid}-policy", "edge"),
            name=f"{edge.name} effective business policy",
            precedence="edge-effective",
            # The profile read was refused if the QOS body is missing.
            capability_gap=None
            if qos
            else canonical_json(
                {
                    "status": "unavailable",
                    "operation": PORTAL_READ_PATHS["enterprise_configurations"],
                    "reason": "no QOS profile body answered for this edge",
                }
            ),
            observed_at_ms=observed_at_ms,
        )
        b.rel("ENFORCES", "Device", edge.uid, "SdwanBusinessPolicy", policy_uid)
        gaps: list[str] = list(enterprise_gaps)
        freshness = observed.get("_freshness", {}).get("modules", {})
        if freshness.get("stale"):
            gaps.append(
                "WAN and control-plane module refresh failed; last-known configuration, if any, retained"
            )
        if module_gap:
            gaps.append(canonical_json(module_gap))
        if not ent.wan.get(eid):
            gaps.append("no WAN module body for this edge; the link kind comes from the carrier name")
        gaps.append(
            "no branch-to-branch Tunnel is written: the orchestrator builds one on demand, "
            "and the configuration names no link pair for it"
        )
        _lan(edge, data)
        _bgp(edge, data, gaps)
        _wan_links(edge, edge_row, provider_name, private, gaps, warnings)
        edge.segment_ids = segment_ids
        _gateway_tunnels(edge, segment_ids)
        edge.policy_uid = policy_uid
        _steering(edge, policy_uid, qos)
        # A refused read writes no rule_count.
        if qos:
            b.node("SdwanBusinessPolicy", policy_uid, rule_count=_policy_rules(edge, policy_uid, qos))
        for sid in segment_ids:
            seg_uid = ent.segment_uids[sid]
            boundary = b.node(
                "ForwardingBoundary",
                uid.velocloud(enterprise, f"edge-{eid}-boundary", sid),
                edge_logical_id=eid,
                segment_id=sid,
                api_profile=body.get("api_profile"),
                orchestrator_release=body.get("orchestrator_release"),
                candidate_set_complete=False,
                selector="dynamic-steering",
                unsupported_reason="VeloCloud dynamic path selection is opaque",
                gaps=gaps or None,
            )
            b.rel("HAS_BOUNDARY", "Device", edge.uid, "ForwardingBoundary", boundary)
            b.rel("IN", "ForwardingBoundary", boundary, "SdwanSegment", seg_uid)
            b.rel("STEERS_VIA", "SdwanBusinessPolicy", policy_uid, "ForwardingBoundary", boundary)
            _static_routes(edge, data, sid, boundary)
    _hub_tunnels(ent, built)


def _ha_props(ent: _Enterprise, edge_row: dict[str, Any]) -> dict[str, Any]:
    """The high availability and hub cluster facts of the edge. `ha.type` is
    `ACTIVE_STANDBY` for a standby pair. The `ha.data` of a standby pair holds
    the standby serial and the pair state. `ha.type` is `ACTIVE_ACTIVE` for a
    hub cluster member. The `ha.data` of a hub cluster member holds the cluster
    name. The type `NONE` is written unchanged."""
    ha = edge_row.get("ha") if isinstance(edge_row.get("ha"), dict) else {}
    data = ha.get("data") if isinstance(ha.get("data"), dict) else {}
    cluster = ent.cluster_of(str(edge_row["logicalId"]))
    pair = str(ha.get("type") or "").upper() == "ACTIVE_STANDBY"
    return {
        "ha_type": ha.get("type") or None,
        # The row-level HA fields are read for a standby pair alone.
        "ha_state": _first(data, "haState") or (_first(edge_row, "haState") if pair else None),
        "ha_standby_serial": _first(data, "haSerialNumber")
        or (_first(edge_row, "haSerialNumber") if pair else None),
        "hub_cluster_id": cluster["id"] if cluster else None,
        "hub_cluster_name": (cluster or {}).get("name")
        or (str(data.get("clusterName") or "").strip() or None),
    }


def normalize_velocloud(
    raw: dict[str, Any],
    *,
    scope: str = "velocloud",
    provider_name: str | None = None,
    private_carriers: set[str] | None = None,
) -> Batch:
    b = GraphBuilder()
    private = {name.lower() for name in private_carriers or set()}
    if provider_name:
        private.add(provider_name.lower())
    link_warnings: list[str] = []
    for body in raw.get("enterprises") or []:
        if not isinstance(body, dict):
            continue
        _normalize_enterprise(
            b,
            {
                **body,
                "api_profile": raw.get("api_profile"),
                "orchestrator_release": raw.get("orchestrator_release"),
                "fetched_at_ms": raw.get("fetched_at_ms"),
            },
            scope=scope,
            provider_name=provider_name,
            private=private,
            warnings=link_warnings,
        )
    batch = b.batch("velocloud", scope)
    batch.warnings.extend(sorted(set(link_warnings)))
    for name, outcome in _read_failure_sections(raw).items():
        batch.sections[name] = outcome
        batch.warnings.append(f"{name}: {outcome.detail}")
    stale = raw.get("poll_stats", {}).get("stale_reads", 0)
    if stale:
        detail = f"{stale} observation reads failed; last-known data retained where available"
        batch.sections["poll_refresh"] = SectionOutcome(status="failed", detail=detail)
        batch.warnings.append(detail)
    return batch


def _refused_operations(body: dict[str, Any]) -> set[str]:
    """The Portal request paths this enterprise's poll recorded as gaps."""
    return {
        str((gap.get("_capability") or {}).get("operation") or "")
        for gap in body.get("gaps") or []
        if isinstance(gap, dict)
    }


_APIV2_FALLBACK_PATHS = frozenset({PORTAL_READ_PATHS["aggregates"], PORTAL_READ_PATHS["enterprise_edges"]})


def _read_failure_sections(raw: dict[str, Any]) -> dict[str, SectionOutcome]:
    """The sections a refused Portal read leaves incomplete."""
    configuration: list[str] = []
    profiles: list[str] = []
    fallback: list[str] = []
    modules = 0
    for body in _bodies(raw):
        name = str(body.get("name") or body.get("logicalId") or "")
        refused = _refused_operations(body)
        edges = [e for e in body.get("edges") or [] if isinstance(e, dict)]
        for operation in ("aggregates", "enterprise_edges", "enterprise_configurations"):
            path = PORTAL_READ_PATHS[operation]
            if path in refused and (edges or operation != "enterprise_configurations"):
                profiles.append(f"{name}: {path}")
        if edges and refused & _APIV2_FALLBACK_PATHS:
            fallback.append(name)
        for detail in (body.get("edge_details") or {}).values():
            value = detail.get("modules") if isinstance(detail, dict) else None
            if isinstance(value, dict) and "_capability" in value:
                modules += 1
    configuration.extend(profiles)
    if modules:
        configuration.append(f"{modules} edge module read(s) {PORTAL_READ_PATHS['configuration_modules']}")
    out: dict[str, SectionOutcome] = {}
    if configuration:
        out["configuration"] = SectionOutcome(status="failed", detail="refused: " + "; ".join(configuration))
    if profiles:
        out["profile_segments"] = SectionOutcome(status="failed", detail="refused: " + "; ".join(profiles))
    if fallback:
        out["edges"] = SectionOutcome(
            status="partial",
            detail="edge listing not read from the Portal, edges read from the APIv2 fallback: "
            + ", ".join(fallback),
        )
    return out


def _refused_tables(raw: dict[str, Any]) -> dict[str, TableOutcome]:
    """Returns `failed` for the `rib` and `bgp_sessions` tables of every
    enterprise whose read was refused or not made."""
    rib: list[str] = []
    bgp: list[str] = []
    for body in _bodies(raw):
        name = str(body.get("name") or body.get("logicalId") or "")
        # A payload sealed before the route table was read has no `route_table` key.
        if "route_table" in body and body.get("route_table") is None:
            rib.append(name)
        sessions = body.get("bgp_sessions")
        if isinstance(sessions, dict) and "_capability" in sessions:
            bgp.append(name)
    out: dict[str, TableOutcome] = {}
    if rib:
        out[RIB_TABLE] = TableOutcome(
            status="failed",
            detail=f"{PORTAL_READ_PATHS['route_table']} not answered for: " + ", ".join(rib),
        )
    if bgp:
        out["bgp_sessions"] = TableOutcome(
            status="failed", detail=f"{READ_PATHS['bgp_sessions']} refused for: " + ", ".join(bgp)
        )
    return out


_EXIT_PROTOCOL = {"BGP": "bgp", "OSPF": "ospf"}


def rib_rows(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """The orchestrator's selection is the `preferredExits` bucket."""
    rows: list[dict[str, Any]] = []
    for body in _bodies(raw):
        table = body.get("route_table")
        if not isinstance(table, dict) or not body.get("logicalId"):
            continue
        ent = _Enterprise(GraphBuilder(), str(body["logicalId"]), body)
        seg_name = {key: seg["name"] for seg in ent.segments for key in seg["keys"] | {seg["id"]}}
        by_numeric = {
            str(numeric): str(edge["logicalId"])
            for edge in ent.edges
            if (numeric := _numeric_id(edge.get("id"))) is not None
        }
        for record in _items(table.get("subnets")):
            route = record.get("learnedRoute") if isinstance(record.get("learnedRoute"), dict) else {}
            # The `subnet` key is `cidr:segmentId`. The split is at the last
            # colon and keeps an IPv6 prefix whole.
            prefix, _, tail = str(record.get("subnet") or "").rpartition(":")
            if not prefix:
                prefix, tail = _cidr(route) or "", ""
            columns = lpm_columns(prefix)
            if not columns:
                continue
            for exit_ in _items(record.get("preferredExits")):
                if str(exit_.get("exitType") or "").upper() != "EDGE" or _exit_withheld(exit_):
                    continue
                numeric = _numeric_id(exit_.get("edgeId"))
                eid = str(exit_.get("edgeLogicalId") or "") or (
                    by_numeric.get(str(numeric)) if numeric is not None else None
                )
                if not eid:
                    continue
                # `learnedRoute.segmentId` is absent on some records.
                segment = next(
                    (
                        str(value)
                        for value in (exit_.get("segmentId"), route.get("segmentId"), tail)
                        if value not in (None, "")
                    ),
                    None,
                )
                vrf = seg_name.get(segment or "", ent.global_name)
                device_uid = uid.velocloud(ent.id, "edge", eid)
                context_uid = uid.vrf(device_uid, uid.slug(vrf))
                kind = str(exit_.get("type") or "").upper()
                protocol = _EXIT_PROTOCOL.get(str(exit_.get("protocol") or "").upper()) or kind.lower()
                next_hop = _address_only(_first(exit_, "neighborIp", "nextHopIp"))
                rows.append(
                    {
                        "device_uid": device_uid,
                        "vrf": vrf,
                        "context_uid": context_uid,
                        "prefix": prefix,
                        "next_hop": next_hop,
                        "next_hop_context_uid": context_uid if next_hop else None,
                        "interface": exit_.get("interface") or None,
                        "protocol": protocol or None,
                        # The column holds "blackhole", "reject" or None. An
                        # overlay exit is not a discard route.
                        "discard": None,
                        "metric": as_int(_first(exit_, "cost", "metric")),
                        **columns,
                    }
                )
    return rows


def bgp_session_rows(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """The session's VRF is the segment whose configured neighbors have the same
    `neighborIp` on that edge."""
    rows: list[dict[str, Any]] = []
    for body in raw.get("enterprises") or []:
        if not isinstance(body, dict) or not body.get("logicalId"):
            continue
        ent = _Enterprise(GraphBuilder(), str(body["logicalId"]), body)
        seg_name = {key: seg["name"] for seg in ent.segments for key in seg["keys"] | {seg["id"]}}
        # The segment name of each (edge, neighbor address) pair, from the configured neighbors.
        neighbor_segment: dict[tuple[str, str], str] = {}
        for eid, data in ent.settings.items():
            for block in data.get("segments") or []:
                bgp = block.get("bgp") if isinstance(block, dict) else None
                if not isinstance(bgp, dict):
                    continue
                name = next((seg_name[k] for k in _segment_keys(block) if k in seg_name), None)
                if name is None:
                    continue
                for neighbor in bgp.get("neighbors") or []:
                    peer = _address_only(neighbor.get("neighborIp")) if isinstance(neighbor, dict) else None
                    if peer:
                        neighbor_segment.setdefault((eid, peer), name)
        # Each session gets one row. The resource has one row for each recorded
        # state of a neighbor. The row with the newest `timestamp` is the
        # current state.
        newest: dict[str, tuple[float, dict[str, Any]]] = {}
        for session in _items(body.get("bgp_sessions")):
            eid = _ref_id(session.get("edge"))
            peer_ip = _address_only(session.get("neighborIp"))
            if not eid or not peer_ip:
                continue
            dev = uid.velocloud(ent.id, "edge", eid)
            vrf_name = neighbor_segment.get((eid, peer_ip), ent.global_name)
            vrf_uid = uid.vrf(dev, uid.slug(vrf_name))
            ru = uid.routing_process(dev, vrf_name, "bgp")
            su = uid.bgp_session(ru, peer_ip, vrf_name)
            stamp = _iso_s(session.get("timestamp"))
            if su in newest and newest[su][0] >= stamp:
                continue
            newest[su] = (
                stamp,
                {
                    "device_uid": dev,
                    "context_uid": vrf_uid,
                    "session_uid": su,
                    "peer_ip": peer_ip,
                    "af": ipaddress.ip_address(peer_ip).version,
                    "safi": "unicast",
                    "state": session.get("state"),
                    # `upDownTime` is relative to a sample time that the row
                    # does not hold. No absolute time is derived from it.
                    "established_since_ms": None,
                    "prefixes_received": as_int(session.get("pfxRcvd")),
                    "prefixes_advertised": None,
                    "capabilities": None,
                },
            )
        rows.extend(row for _, row in newest.values())
    return rows
