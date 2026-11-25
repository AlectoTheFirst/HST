"""The Equinix collector reads the Fabric v4 ports of the account and the
virtual circuits (connections) that terminate on the ports. When the source
enables `network_edge`, the collector also reads the Network Edge virtual
devices and their device links.

One source reads one Fabric account. The collector sends no write request. It
reads the OAuth2 client-credentials token, the port list, the connection
search, the Network Edge device list and the device link groups. The
connection search is filtered to the ports of the account, sorted and paged.
Every page is kept as raw. `_without_secrets` removes the credential fields of
a Network Edge answer.

Normalization produces these objects.

- `FabricPort` and `VirtualCircuit` nodes.
- The `A_END` and `Z_END` edges with the link protocol and the VLAN tags per
  side.
- `LOCATED_IN` for each port whose IBX the operator mapped to a site.
- `REALIZED_BY` from a Fabric port to the device port that the operator bound
  it to.
- A `Device platform=network-edge` with its `Interface` nodes for each Network
  Edge device. A circuit end on that device is an edge to one of these
  interfaces.
- A `VirtualCircuit type=DEVICE_LINK` between the 2 interfaces of each pair of
  members of a Network Edge device link group.

The reasoner rule `fabric-port-from-description` binds a Fabric port without
an operator binding to the device port whose description holds the name of the
Fabric port. The reasoner rule `cable-from-fabric-circuit` turns a circuit that
is not ended and whose 2 ends both realize a device port into a `CONNECTED_TO`
link. The reasoner check `vlan-stretch` compares the tags per side with the
trunk membership of the 2 device ports.

Live answers of October 2026 confirm these parts: the port list
(`/fabric/v4/ports` with `offset` and `limit`), the connection search
(`/fabric/v4/connections/search`, a POST of `filter.or[]` with the properties
`/aSide/accessPoint/port/uuid` and `/zSide/accessPoint/port/uuid` and the
operator `IN`, `pagination` and `sort`), the Network Edge device list
(`/ne/v1/devices` with `offset` and `limit`), the device link groups
(`/ne/v1/links` with `offset` and `limit`), the `data` and `pagination.total`
envelope, and every port, connection and device field that the collector
reads. A member of a device link group holds its device uuid and interface id.
The search does not accept the operator `NOT IN`. The search returns
deprovisioned circuits beside the live circuits. It returns a circuit between
the ports of 2 parties once per direction.

FIRST CONTACT: the token request (`TOKEN_PATH`, a JSON body with
`grant_type`, `client_id` and `client_secret`, and the `access_token` answer
field) is not in the captures.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Any, ClassVar

import httpx
from pydantic import Field, field_validator

from hst.core import uid
from hst.core.model import Batch, SectionOutcome, SectionStatus

from . import http
from .auth import OAuthClientCredentials, TlsConfig
from .base import Collector, SourceConfig, register
from .util import GraphBuilder, canonical_mac, parse_pairs, without_keys

API_PROFILE = "equinix-fabric-v4"
MAX_COLLECTION_PAGES = 10_000
PROVIDER_UID = uid.provider("equinix")

TOKEN_PATH = "/oauth2/v1/token"  # noqa: S105  a URL path
PORTS_PATH = "/fabric/v4/ports"
CONNECTIONS_SEARCH_PATH = "/fabric/v4/connections/search"
# The Network Edge virtual devices of the account (routers, firewalls and
# SD-WAN edges that Equinix hosts). The collector reads them when the source
# enables `network_edge`.
EDGE_DEVICES_PATH = "/ne/v1/devices"
# The Network Edge device link groups are the L2 segments between virtual
# devices. A member holds its device uuid and interface id.
EDGE_LINKS_PATH = "/ne/v1/links"
# The search returns a circuit between the ports of 2 parties once per direction.
CONNECTIONS_SORT = [{"property": "/changeLog/createdDateTime", "direction": "ASC"}]
# The search filter property names for the two port ends.
A_SIDE_PORT_PROPERTY = "/aSide/accessPoint/port/uuid"
Z_SIDE_PORT_PROPERTY = "/zSide/accessPoint/port/uuid"
# The Fabric v4 search fields for the circuits of the Network Edge devices of
# the account (equinix-sdk-go services/fabricv4/model_search_field_name.go).
# No capture holds them.
A_SIDE_VIRTUAL_DEVICE_PROPERTY = "/aSide/accessPoint/virtualDevice/uuid"
Z_SIDE_VIRTUAL_DEVICE_PROPERTY = "/zSide/accessPoint/virtualDevice/uuid"
# Maps each optional Network Edge section to its key in the raw payload.
EDGE_SECTIONS = {
    "network_edge_devices": "edge_device_pages",
    "network_edge_links": "edge_link_pages",
    "network_edge_connections": "edge_connection_pages",
}

_TAG_TYPES = {"DOT1Q": "dot1q", "QINQ": "qinq", "UNTAGGED": "untagged", "NULL": "untagged"}

# A Network Edge answer holds the initial admin password in `vendorConfig`.
_EDGE_SECRET_KEYS = ("vendorconfig", "password", "secret", "privatekey", "token")

# Maps the `deviceTypeCategory` of a Network Edge device to the Device role.
_EDGE_ROLES = {"ROUTER": "router", "FIREWALL": "firewall", "SDWAN": "sdwan-edge"}


class EquinixConfig(SourceConfig):
    api_url: str = Field("https://api.equinix.com", title="API URL")
    auth: OAuthClientCredentials
    tls: TlsConfig = TlsConfig()
    ibx_sites: str = Field(
        "",
        title="IBX to site",
        description="One line per IBX, `IBX, site_code`, for example `FR2, fr2`",
        json_schema_extra={"format": "multiline"},
    )
    port_bindings: str = Field(
        "",
        title="Port bindings",
        description="One line per Fabric port, `fabric port uuid, device port uid`",
        json_schema_extra={"format": "multiline"},
    )
    page_size: int = Field(100, ge=1, le=1000, title="Page size")
    network_edge: bool = Field(
        False,
        title="Network Edge",
        description="Network Edge virtual devices and their interfaces",
    )
    edge_device_bindings: str = Field(
        "",
        title="Network Edge device bindings",
        description="One line per Network Edge device that another source also collects, "
        "`network edge device uuid or name, device uid`",
        json_schema_extra={"format": "multiline"},
    )

    @field_validator("ibx_sites")
    @classmethod
    def _ibx_sites_shape(cls, value: str) -> str:
        parse_pairs(value, field="ibx_sites")
        return value

    @field_validator("port_bindings")
    @classmethod
    def _port_bindings_shape(cls, value: str) -> str:
        parse_pairs(value, field="port_bindings")
        return value

    @field_validator("edge_device_bindings")
    @classmethod
    def _edge_device_bindings_shape(cls, value: str) -> str:
        parse_pairs(value, field="edge_device_bindings")
        return value

    @property
    def ibx_site_map(self) -> dict[str, str]:
        return {ibx.upper(): code for ibx, code in parse_pairs(self.ibx_sites, field="ibx_sites").items()}

    @property
    def port_binding_map(self) -> dict[str, str]:
        return parse_pairs(self.port_bindings, field="port_bindings")

    @property
    def edge_device_binding_map(self) -> dict[str, str]:
        return parse_pairs(self.edge_device_bindings, field="edge_device_bindings")


def _transport(config: EquinixConfig) -> httpx.BaseTransport | None:
    return None  # Tests replace this function to return an httpx.MockTransport.


def _scope(source_name: str) -> str:
    return f"equinix:{uid.slug(source_name or 'fabric')}"


def _items(page: Any) -> list[dict[str, Any]]:
    if isinstance(page, dict) and isinstance(page.get("data"), list):
        return [item for item in page["data"] if isinstance(item, dict)]
    if isinstance(page, list):
        return [item for item in page if isinstance(item, dict)]
    return []


def _page_total(page: Any) -> int | None:
    if not isinstance(page, dict):
        return None
    pagination = page.get("pagination")
    if not isinstance(pagination, dict):
        return None
    total = pagination.get("total")
    return total if isinstance(total, int) else None


@register
class EquinixCollector(Collector):
    name = "equinix"
    ConfigModel = EquinixConfig
    KIND = "orchestrator"
    # Version 2 has the cross-connect ids, redundancy and LAG of a port, and Network Edge.
    # Version 3 has the circuits of the Network Edge virtual devices.
    PARSER_VERSION = "3"
    NORMALIZATION_VERSIONS: ClassVar[dict[str, str]] = {
        "api-capability": API_PROFILE,
        # A failed Network Edge circuit read fails `connections`.
        "edge-circuit-failure": "1",
        "iface_uid": uid.IFACE_UID_VERSION,
    }
    VOLATILE_RAW_KEYS = ("fetched_at_ms",)
    AUTHORITATIVE_SECTIONS = ("ports", "connections")
    SECTION_LABELS: ClassVar[dict[str, tuple[str, ...]]] = {
        "ports": ("FabricPort",),
        "connections": ("VirtualCircuit",),
        # Only the Network Edge stage writes Device, Interface and Port here.
        "network_edge_devices": ("Device", "Interface", "Port"),
        "network_edge_links": (),
        "network_edge_connections": (),
    }

    def __init__(self, config: EquinixConfig, settings):
        super().__init__(config, settings)
        self.scope = _scope(config.source_name)

    def _client(self) -> httpx.Client:
        """Return an authenticated client. The token request is the login
        step. A failure of the token request closes the client and is raised."""
        c = self.config
        client = http.client(c.api_url.rstrip("/"), c.tls, timeout=60, transport=_transport(c))
        try:
            # FIRST CONTACT: no capture holds the JSON body and the `access_token` answer field.
            response = client.post(
                TOKEN_PATH,
                json={
                    "grant_type": "client_credentials",
                    "client_id": c.auth.client_id,
                    "client_secret": c.auth.client_secret.get_secret_value(),
                },
            )
            response.raise_for_status()
            token = response.json().get("access_token")
            if not isinstance(token, str) or not token:
                raise ValueError("Equinix token response carries no access_token")
            client.headers["Authorization"] = f"Bearer {token}"
        except BaseException:
            client.close()
            raise
        return client

    def _get(self, client: httpx.Client, path: str, **params: Any) -> Any:
        response = client.get(path, params=params or None)
        response.raise_for_status()
        return response.json()

    def _post(self, client: httpx.Client, path: str, body: dict[str, Any]) -> Any:
        response = client.post(path, json=body)
        response.raise_for_status()
        return response.json()

    def _pages(self, fetch_page: Any, what: str) -> list[Any]:
        """If a page holds a total, the read continues until `offset` reaches
        the total. An empty page before the total raises. A page with no total
        ends the read when it is empty or short. A read past the collection page
        limit raises."""
        pages: list[Any] = []
        offset = 0
        limit = self.config.page_size
        while True:
            if len(pages) >= MAX_COLLECTION_PAGES:
                raise ValueError("Equinix pagination exceeds the collection page limit")
            page = fetch_page(offset, limit)
            pages.append(page)
            items = _items(page)
            offset += len(items)
            total = _page_total(page)
            if total is not None:
                if offset >= total:
                    return pages
                if not items:
                    raise ValueError(f"Equinix {what}: paging stopped at {offset} of {total} items")
                continue
            if not items or len(items) < limit:
                return pages

    def _port_pages(self, client: httpx.Client) -> list[Any]:
        return self._pages(
            lambda offset, limit: self._get(client, PORTS_PATH, offset=offset, limit=limit), "ports"
        )

    def _edge_link_pages(self, client: httpx.Client) -> list[Any]:
        return [
            _without_secrets(page)
            for page in self._pages(
                lambda offset, limit: self._get(client, EDGE_LINKS_PATH, offset=offset, limit=limit),
                "network edge links",
            )
        ]

    def _edge_device_pages(self, client: httpx.Client) -> list[Any]:
        return [
            _without_secrets(page)
            for page in self._pages(
                lambda offset, limit: self._get(client, EDGE_DEVICES_PATH, offset=offset, limit=limit),
                "network edge devices",
            )
        ]

    def _connection_pages(self, client: httpx.Client, port_uuids: list[str]) -> list[Any]:
        return self._search_pages(
            client, A_SIDE_PORT_PROPERTY, Z_SIDE_PORT_PROPERTY, port_uuids, "connections"
        )

    def _search_pages(
        self, client: httpx.Client, a_property: str, z_property: str, values: list[str], what: str
    ) -> list[Any]:
        if not values:
            return []
        filter_body = {
            "or": [
                {"property": a_property, "operator": "IN", "values": values},
                {"property": z_property, "operator": "IN", "values": values},
            ]
        }
        return self._pages(
            lambda offset, limit: self._post(
                client,
                CONNECTIONS_SEARCH_PATH,
                {
                    "filter": filter_body,
                    "pagination": {"offset": offset, "limit": limit},
                    "sort": CONNECTIONS_SORT,
                },
            ),
            what,
        )

    def probe(self) -> str:
        client = self._client()
        try:
            page = self._get(client, PORTS_PATH, offset=0, limit=1)
            total = _page_total(page)
            count = total if total is not None else len(_items(page))
            return f"token ok: {count} Fabric port(s)"
        finally:
            client.close()

    def fetch(self) -> dict[str, Any]:
        client = self._client()
        try:
            port_pages = self._port_pages(client)
            port_uuids = [
                str(port["uuid"]) for page in port_pages for port in _items(page) if port.get("uuid")
            ]
            connection_pages = self._connection_pages(client, port_uuids)
            raw: dict[str, Any] = {
                "api_profile": API_PROFILE,
                "fetched_at_ms": int(time.time() * 1000),
                "port_pages": port_pages,
                "connection_pages": connection_pages,
            }
            if self.config.network_edge:
                errors: dict[str, dict[str, Any]] = {}
                devices = self._optional(errors, "network_edge_devices", self._edge_device_pages, client)
                links = self._optional(errors, "network_edge_links", self._edge_link_pages, client)
                if devices is not None:
                    raw["edge_device_pages"] = devices
                    device_uuids = [str(d["uuid"]) for page in devices for d in _items(page) if d.get("uuid")]
                    if device_uuids:
                        found = self._optional(
                            errors,
                            "network_edge_connections",
                            lambda c: self._search_pages(
                                c,
                                A_SIDE_VIRTUAL_DEVICE_PROPERTY,
                                Z_SIDE_VIRTUAL_DEVICE_PROPERTY,
                                device_uuids,
                                "network edge connections",
                            ),
                            client,
                        )
                        if found is not None:
                            raw["edge_connection_pages"] = found
                if links is not None:
                    raw["edge_link_pages"] = links
                raw["section_errors"] = errors
            return raw
        finally:
            client.close()

    @staticmethod
    def _optional(errors: dict[str, dict[str, Any]], section: str, read: Any, client: httpx.Client) -> Any:
        """Return `read(client)`, or None after an HTTP status error. The error
        is recorded for `section` and the run continues."""
        try:
            return read(client)
        except httpx.HTTPStatusError as exc:
            code = exc.response.status_code
            errors[section] = {"status": code, "detail": f"HTTP {code} for {exc.request.url.path}"}
            return None

    def normalize(self, raw: dict[str, Any]) -> Batch:
        return normalize_equinix(
            raw,
            scope=self.scope,
            ibx_sites=self.config.ibx_site_map,
            port_bindings=self.config.port_binding_map,
            edge_device_bindings=self.config.edge_device_binding_map,
        )


def _without_secrets(value: Any) -> Any:
    """Return `value` without the mapping keys of credentials
    (`_EDGE_SECRET_KEYS`), at any depth."""
    return without_keys(value, _EDGE_SECRET_KEYS)


def _cross_connect_id(value: Any) -> str | None:
    """The cable id of a cross connect without the `-A` suffix."""
    text = str(value or "").strip().upper()
    if not text:
        return None
    return text.split("-", 1)[0] or None


def _physical_ports(port: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [pp for pp in port.get("physicalPorts") or [] if isinstance(pp, Mapping)]


def _link_protocol(access_point: Mapping[str, Any]) -> tuple[str | None, int | None, int | None]:
    """Return (protocol, outer tag, inner tag) of one connection end from
    `linkProtocol.type`, `vlanTag`, `vlanSTag` and `vlanCTag`."""
    link = access_point.get("linkProtocol")
    if not isinstance(link, Mapping):
        return None, None, None
    kind = str(link.get("type") or "").upper()
    protocol = _TAG_TYPES.get(kind, kind.lower() or None)
    outer = _tag(link.get("vlanSTag")) if kind == "QINQ" else _tag(link.get("vlanTag"))
    if outer is None and kind == "QINQ":
        outer = _tag(link.get("vlanTag"))
    inner = _tag(link.get("vlanCTag")) if kind == "QINQ" else None
    return protocol, outer, inner


def _tag(value: Any) -> int | None:
    try:
        tag = int(value)
    except (TypeError, ValueError):
        return None
    return tag if tag > 0 else None


def _port_end(
    b: GraphBuilder, vc_uid: str, rel: str, access_point: Mapping[str, Any], known_ports: set[str]
) -> bool:
    """Bind one end of a circuit to a FabricPort of this account. Returns
    whether the end was bound. An end whose port is not in the account's port
    list (the far party's port, or a port the read missed) stays unbound."""
    port = access_point.get("port")
    port_uuid = str(port.get("uuid")) if isinstance(port, Mapping) and port.get("uuid") else None
    if port_uuid is None or port_uuid not in known_ports:
        return False
    protocol, outer, inner = _link_protocol(access_point)
    b.rel(
        rel,
        "VirtualCircuit",
        vc_uid,
        "FabricPort",
        uid.equinix("port", port_uuid),
        link_protocol=protocol,
        vlan_tag=outer,
        inner_vlan_tag=inner,
    )
    return True


def _section_status(http_status: int) -> SectionStatus:
    """Return `unauthorized` for 401 and 403, and `failed` for every other status."""
    return "unauthorized" if http_status in (401, 403) else "failed"


def _edge_binding_key(device: Mapping[str, Any], bindings: Mapping[str, str]) -> str | None:
    """Return the `edge_device_bindings` key of a Network Edge device. The
    uuid of the device is tried first, then its name or host name. The
    comparison ignores case."""
    folded = {key.casefold(): key for key in bindings}
    uuid_key = folded.get(str(device.get("uuid") or "").casefold())
    if uuid_key is not None:
        return uuid_key
    names = {str(device[k]).casefold() for k in ("name", "hostName") if device.get(k)}
    return next((folded[k] for k in folded if k in names), None)


def _edge_binding(device: Mapping[str, Any], bindings: Mapping[str, str]) -> str | None:
    """The device uid the operator bound a Network Edge device to, looked up
    by the device uuid and then by its name, case-insensitively."""
    key = _edge_binding_key(device, bindings)
    return bindings[key] if key is not None else None


def _edge_stage(
    b: GraphBuilder,
    raw: dict[str, Any],
    *,
    ibx_map: Mapping[str, str],
    bindings: Mapping[str, str],
) -> tuple[dict[str, str], dict[tuple[str, str], str]]:
    """Emit the Network Edge devices and their interfaces. Return 2 maps of
    Interface uids. The key of the first map is the Network Edge interface
    uuid, which the virtual-device end of a circuit holds in
    `accessPoint.interface.uuid`. The key of the second map is (device uuid,
    interface id), which a device link member holds.

    Each device is a `Device` with the uid `uid.equinix("device", uuid)`,
    outside the identity registry. Each interface is an `Interface` that
    realizes a `Port` of the same name. The path engine walks this shape
    (`Interface -REALIZED_BY-> Port -CONNECTED_TO- Port`). Both have
    `edge_device_uid`, the uid of the device.

    A device in `edge_device_bindings` has the bound device uid as
    `bound_device_uid`. It is not placed in a site, and its interfaces and
    ports get no `ON` edge. The reasoner rule `edge-device-from-binding` puts
    them on the bound device after every source has loaded. The batch does not
    write the bound device."""
    interfaces: dict[str, str] = {}
    by_id: dict[tuple[str, str], str] = {}
    for device in (d for page in raw.get("edge_device_pages") or [] for d in _items(page)):
        device_uuid = device.get("uuid")
        if not device_uuid:
            continue
        device_uuid = str(device_uuid)
        name = device.get("name") or device.get("hostName") or device_uuid
        edge_facts: dict[str, Any] = {
            "edge_device_uuid": device_uuid,
            "edge_device_name": name,
            "edge_device_type": device.get("deviceTypeCode"),
            "edge_status": device.get("status"),
            "edge_management_ip": device.get("sshIpAddress"),
            "ibx": device.get("ibx"),
            "metro": device.get("metroCode"),
        }
        bound = _edge_binding(device, bindings)
        dev = b.node(
            "Device",
            uid.equinix("device", device_uuid),
            hostname=name,
            vendor=device.get("deviceTypeVendor"),
            model=device.get("deviceTypeCode"),
            platform="network-edge",
            virtual=True,
            role=_EDGE_ROLES.get(str(device.get("deviceTypeCategory") or "").upper(), "router"),
            os_version=device.get("version"),
            redundancy=(str(device["redundancyType"]).lower() if device.get("redundancyType") else None),
            identities=sorted({str(x) for x in (device.get("name"), device.get("hostName")) if x}),
            bound_device_uid=bound,
            **edge_facts,
        )
        site_code = ibx_map.get(str(device.get("ibx") or "").upper())
        if site_code and not bound:
            site = b.node("Site", uid.site(site_code), code=site_code, kind="colo")
            b.rel("LOCATED_IN", "Device", dev, "Site", site)
        b.rel("PROVIDED_BY", "Device", dev, "Provider", PROVIDER_UID)
        for ifc in device.get("interfaces") or []:
            if not isinstance(ifc, Mapping) or not ifc.get("name"):
                continue
            ifname = str(ifc["name"])
            mac = canonical_mac(ifc.get("macAddress"))
            iface_uuid = str(ifc["uuid"]) if ifc.get("uuid") else None
            iu = b.node(
                "Interface",
                uid.interface(dev, ifname),
                name=ifname,
                kind=(str(ifc["type"]).lower() if ifc.get("type") else None),
                mac=mac,
                state=ifc.get("status"),
                # the name of the circuit Network Edge shows on the interface
                assigned=ifc.get("assignedType") or None,
                edge_interface_uuid=iface_uuid,
                edge_interface_id=(str(ifc["id"]) if ifc.get("id") is not None else None),
                edge_device_uid=dev,
            )
            pu = b.node(
                "Port",
                uid.port(dev, ifname),
                name=ifname,
                kind="mgmt" if str(ifc.get("type") or "").upper() == "SSH" else "phys",
                mac=mac,
                edge_interface_uuid=iface_uuid,
                edge_device_uid=dev,
            )
            b.rel("REALIZED_BY", "Interface", iu, "Port", pu)
            if not bound:
                b.rel("ON", "Interface", iu, "Device", dev)
                b.rel("ON", "Port", pu, "Device", dev)
            if iface_uuid:
                interfaces[iface_uuid] = iu
            if ifc.get("id") is not None:
                by_id[(device_uuid, str(ifc["id"]))] = iu
    return interfaces, by_id


def _throughput_mbps(metro_links: Any) -> int | None:
    """The smallest throughput of a device link group's metro links, in
    Mbit/s. A group inside one metro has no metro link and no throughput."""
    values = []
    for link in metro_links or []:
        if not isinstance(link, Mapping) or str(link.get("throughputUnit") or "").lower() != "mbps":
            continue
        try:
            values.append(int(str(link.get("throughput"))))
        except ValueError:
            continue
    return min(values) if values else None


def _edge_link_stage(b: GraphBuilder, raw: dict[str, Any], members: Mapping[tuple[str, str], str]) -> None:
    """Emit each pair of members of a Network Edge device link group as a
    `VirtualCircuit type=DEVICE_LINK` with an `A_END` and a `Z_END` on the 2
    Network Edge interfaces. The reasoner rule cable-from-fabric-circuit
    draws the link between the ports that the interfaces realize, also on a
    bound device. A group of n members gives n(n-1)/2 pairs. The segment is
    one L2 domain, and every member reaches every other member in one hop. A
    member on a device outside the device list of the account is in no pair."""
    for group in (g for page in raw.get("edge_link_pages") or [] for g in _items(page)):
        group_uuid = group.get("uuid")
        if not group_uuid:
            continue
        found = sorted(
            {
                (f"{m.get('deviceUuid')}.{m.get('interfaceId')}", members[key])
                for m in group.get("linkDevices") or []
                if isinstance(m, Mapping)
                and (key := (str(m.get("deviceUuid")), str(m.get("interfaceId")))) in members
            }
        )
        for index, (a_key, a_iface) in enumerate(found):
            for z_key, z_iface in found[index + 1 :]:
                vc = b.node(
                    "VirtualCircuit",
                    uid.equinix("device-link", f"{group_uuid}:{a_key}:{z_key}"),
                    name=group.get("groupName") or str(group_uuid),
                    type="DEVICE_LINK",
                    state=group.get("status"),
                    bandwidth_mbps=_throughput_mbps(group.get("metroLinks")),
                    a_side_kind="vd",
                    z_side_kind="vd",
                    redundancy=(
                        str(group["redundancyType"]).lower() if group.get("redundancyType") else None
                    ),
                    device_link_group_uuid=str(group_uuid),
                )
                b.rel("PROVIDED_BY", "VirtualCircuit", vc, "Provider", PROVIDER_UID)
                b.rel("A_END", "VirtualCircuit", vc, "Interface", a_iface)
                b.rel("Z_END", "VirtualCircuit", vc, "Interface", z_iface)


def _edge_end(
    b: GraphBuilder,
    vc_uid: str,
    rel: str,
    access_point: Mapping[str, Any],
    edge_interfaces: Mapping[str, str],
) -> bool:
    """Bind a virtual-device end of a circuit to the Network Edge interface
    with the interface uuid of the end. An end on a device outside the device
    list of the account (the device of another party, or a deprovisioned
    device) stays unbound."""
    interface = access_point.get("interface")
    iface_uuid = (
        str(interface.get("uuid")) if isinstance(interface, Mapping) and interface.get("uuid") else None
    )
    iu = edge_interfaces.get(iface_uuid) if iface_uuid else None
    if iu is None:
        return False
    protocol, outer, inner = _link_protocol(access_point)
    b.rel(
        rel,
        "VirtualCircuit",
        vc_uid,
        "Interface",
        iu,
        link_protocol=protocol,
        vlan_tag=outer,
        inner_vlan_tag=inner,
    )
    return True


def normalize_equinix(
    raw: dict[str, Any],
    *,
    scope: str,
    ibx_sites: Mapping[str, str],
    port_bindings: Mapping[str, str],
    edge_device_bindings: Mapping[str, str] | None = None,
) -> Batch:
    """Return the ports and circuits of the account as a batch.

    `ibx_sites` maps an IBX code to a site code. A port in an unmapped IBX
    gets no `LOCATED_IN` edge. `port_bindings` maps a Fabric port uuid to the
    device port uid that the operator copied from the Devices page. The
    binding is stored on the FabricPort as `bound_port_uid` and emitted as
    `REALIZED_BY`. The loader drops the edge when the Port is not in the run.
    The reasoner check `vlan-stretch` reports every FabricPort whose binding
    has no `REALIZED_BY` edge.

    With `edge_device_pages` in the raw payload, each virtual device is a
    `Device platform=network-edge virtual=true` with its interfaces. A device
    in `edge_device_bindings` is bound to the device of the binding
    (`_edge_stage`). A circuit end on an interface of a virtual device is an
    `A_END` or `Z_END` to that `Interface`.
    """
    b = GraphBuilder()
    b.node("Provider", PROVIDER_UID, name="Equinix", kind="colo")
    ibx_map = {ibx.upper(): code for ibx, code in ibx_sites.items()}
    known_ports: set[str] = set()
    bindings_by_uuid = {key.casefold(): target for key, target in port_bindings.items()}
    used_port_keys: set[str] = set()

    for port in (p for page in raw.get("port_pages") or [] for p in _items(page)):
        port_uuid = port.get("uuid")
        if not port_uuid:
            continue
        port_uuid = str(port_uuid)
        known_ports.add(port_uuid)
        location = port.get("location") if isinstance(port.get("location"), Mapping) else {}
        encapsulation = port.get("encapsulation") if isinstance(port.get("encapsulation"), Mapping) else {}
        ibx = location.get("ibx")
        bound = bindings_by_uuid.get(port_uuid.casefold())
        if bound:
            used_port_keys.add(port_uuid.casefold())
        physical = _physical_ports(port)
        redundancy = port.get("redundancy") if isinstance(port.get("redundancy"), Mapping) else {}
        lag = port.get("lag") if isinstance(port.get("lag"), Mapping) else {}
        fp = b.node(
            "FabricPort",
            uid.equinix("port", port_uuid),
            name=port.get("name") or port_uuid,
            port_uuid=port_uuid,
            state=port.get("state"),
            ibx=ibx,
            metro=location.get("metroCode"),
            speed_mbps=_tag(port.get("bandwidth")),
            physical_ports_speed=port.get("physicalPortsSpeed"),
            encapsulation=(str(encapsulation.get("type")).lower() if encapsulation.get("type") else None),
            bound_port_uid=bound,
            # The cable id of each physical port. The reasoner rule
            # fabric-port-from-description compares it with the cable id in a
            # port description.
            cross_connect_ids=sorted(
                {
                    cid
                    for pp in physical
                    if isinstance(pp.get("tether"), Mapping)
                    and (cid := _cross_connect_id(pp["tether"].get("crossConnectId")))
                }
            )
            or None,
            redundancy=(str(redundancy["priority"]).lower() if redundancy.get("priority") else None),
            lag_name=(lag.get("name") if lag.get("enabled") else None),
        )
        site_code = ibx_map.get(str(ibx).upper()) if ibx else None
        if site_code:
            site = b.node("Site", uid.site(site_code), code=site_code, kind="colo")
            b.rel("LOCATED_IN", "FabricPort", fp, "Site", site)
        if bound:
            b.rel("REALIZED_BY", "FabricPort", fp, "Port", bound)

    edge_interfaces, edge_members = _edge_stage(b, raw, ibx_map=ibx_map, bindings=edge_device_bindings or {})
    _edge_link_stage(b, raw, edge_members)

    connections = [
        c
        for key in ("connection_pages", "edge_connection_pages")
        for page in raw.get(key) or []
        for c in _items(page)
    ]
    for conn in connections:
        conn_uuid = conn.get("uuid")
        if not conn_uuid:
            continue
        conn_uuid = str(conn_uuid)
        a_side = conn.get("aSide") if isinstance(conn.get("aSide"), Mapping) else {}
        z_side = conn.get("zSide") if isinstance(conn.get("zSide"), Mapping) else {}
        a_point = a_side.get("accessPoint") if isinstance(a_side.get("accessPoint"), Mapping) else {}
        z_point = z_side.get("accessPoint") if isinstance(z_side.get("accessPoint"), Mapping) else {}
        z_profile = z_point.get("profile") if isinstance(z_point.get("profile"), Mapping) else {}
        a_device = a_point.get("virtualDevice") if isinstance(a_point.get("virtualDevice"), Mapping) else {}
        vc = b.node(
            "VirtualCircuit",
            uid.equinix("connection", conn_uuid),
            name=conn.get("name") or conn_uuid,
            connection_uuid=conn_uuid,
            type=conn.get("type"),
            state=conn.get("state"),
            bandwidth_mbps=_tag(conn.get("bandwidth")),
            a_side_kind=(str(a_point.get("type")).lower() if a_point.get("type") else None),
            z_side_kind=(str(z_point.get("type")).lower() if z_point.get("type") else None),
            # A service-profile far end is a cloud on-ramp. The circuit holds
            # the name of the provider, and no cloud object is created.
            provider=z_profile.get("name"),
            provider_profile_uuid=z_profile.get("uuid"),
            # A Network Edge A end holds its device, also a device outside the
            # device list of the account.
            a_virtual_device=a_device.get("name"),
            a_virtual_device_uuid=a_device.get("uuid"),
        )
        b.rel("PROVIDED_BY", "VirtualCircuit", vc, "Provider", PROVIDER_UID)
        _port_end(b, vc, "A_END", a_point, known_ports) or _edge_end(b, vc, "A_END", a_point, edge_interfaces)
        _port_end(b, vc, "Z_END", z_point, known_ports) or _edge_end(b, vc, "Z_END", z_point, edge_interfaces)

    batch = b.batch("equinix", scope)
    errors = raw.get("section_errors") or {}
    for section, key in EDGE_SECTIONS.items():
        if section in errors:
            error = errors[section]
            batch.sections[section] = SectionOutcome(
                status=_section_status(int(error.get("status") or 0)), detail=error.get("detail")
            )
        elif key in raw:
            count = sum(len(_items(page)) for page in raw[key] or [])
            batch.sections[section] = SectionOutcome(status="ok" if count else "empty", row_count=count)
    # A failed link, circuit or device read fails `connections`.
    unread = [
        f"{section}: {errors[section].get('detail') or 'read failed'}"
        for section in ("network_edge_devices", "network_edge_links", "network_edge_connections")
        if section in errors
    ]
    if unread:
        batch.sections["connections"] = SectionOutcome(
            status="failed", detail="Network Edge circuits not read: " + "; ".join(unread)
        )
    for key in sorted(port_bindings):
        if key.casefold() not in used_port_keys and key.casefold() not in {u.casefold() for u in known_ports}:
            batch.warnings.append(
                f"port_bindings names Fabric port {key}, which is not in the account's port list"
            )
    devices = [d for page in raw.get("edge_device_pages") or [] for d in _items(page)]
    if edge_device_bindings and "edge_device_pages" in raw and "network_edge_devices" not in errors:
        matched = {_edge_binding_key(d, edge_device_bindings) for d in devices}
        for key in sorted(edge_device_bindings):
            if key not in matched:
                batch.warnings.append(
                    f"edge_device_bindings names {key}, which matches no Network Edge device of the account"
                )
    bound_to: dict[str, list[str]] = {}
    for device in devices:
        target = _edge_binding(device, edge_device_bindings or {})
        if target and device.get("uuid"):
            bound_to.setdefault(target, []).append(uid.equinix("device", str(device["uuid"])))
    for target, sources in sorted(bound_to.items()):
        if len(sources) > 1:
            batch.warnings.append(
                f"Network Edge devices {', '.join(sorted(sources))} are bound to the same device {target}"
            )
    return batch
