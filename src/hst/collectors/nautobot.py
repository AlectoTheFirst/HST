"""The Nautobot collector reads the intent for drift: sites, racks, devices,
ports and cables.

The collector reads locations, racks, devices, the physical interfaces of the
devices as ports, cables with exactly 2 interface ends, and IPAM IP addresses
with their VRF. Virtual, LAG and bridge interfaces are skipped. An IP address
becomes an `IpAddress` with `IN_VRF` to a `VrfInstance`. An address without a
VRF is skipped. The interface MTU is read when `capture_mtu` is set. The
collector does not read VLANs, prefixes, the assignment of an IP address to an
interface, virtual chassis and modules.

The collector targets Nautobot 3.x.

First contact with a reachable Nautobot:
    curl -s -H "Authorization: Token <token>" https://<nautobot>/api/status/
    curl -s -H "Authorization: Token <token>" -H "Content-Type: application/json" \
         -X POST https://<nautobot>/api/graphql \
         -d '{"query": "{ devices(limit: 3) { name serial } }"}'
    # The answers go under data/raw/nautobot/first-contact/ as input of normalize_nautobot.

Data-entry conventions for uid alignment:
- The serial of a device is the serial that the live source reports, or the
  MAC for UniFi gear without a serial.
- UniFi switch and AP interfaces have the name "Port <idx>" with the
  controller port_idx (iface_slug("Port 5") == "port5" == the unifi port uid
  segment). The AP uplink is "Port 0".
- VyOS interfaces have their native name (eth0, eth1).
- Every other name is plain.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any, ClassVar, Literal

import httpx

from hst.core import uid
from hst.core.identity import DeviceResolver, MemoryResolver, chassis_serial, resolve_chassis
from hst.core.model import Batch, SectionOutcome
from hst.core.mtu import MTU_NORMALIZATION_VERSION, canonical_json
from hst.core.mtu_profiles import emit_observation, observation_from_raw
from hst.core.normalize import normalize_hostname

from . import http
from .auth import ApiKeyCredential, TlsConfig
from .base import RAW_OUTCOMES_KEY, Collector, SourceConfig, register
from .util import GraphBuilder, canonical_mac, offset_paged

logger = logging.getLogger(__name__)

STATUS_PATH = "/api/status/"
GRAPHQL_PATH = "/api/graphql"
PAGE = 100

# Nautobot interface types that are not physical ports.
_VIRTUAL_TYPES = ("virtual", "lag", "bridge")
_LEGACY_IPAM_STATUS = {"complete": "ok", "incomplete": "failed"}


def _transport(config: NautobotConfig) -> httpx.BaseTransport | None:
    return None  # A test replaces this function to set the transport.


def _scope(host: str) -> str:
    return f"nautobot:{uid.slug(host).replace('.', '-')}"


class NautobotConfig(SourceConfig):
    capture_mtu: bool = False
    mtu_basis: Literal[
        "unknown", "ip_packet", "ethernet_frame_excluding_fcs", "ethernet_frame_including_fcs"
    ] = "unknown"
    url: str
    auth: ApiKeyCredential
    tls: TlsConfig = TlsConfig()


# The nested interface list of a device does not paginate.
DEVICES_QUERY = """
query ($limit: Int, $offset: Int) {
  devices(limit: $limit, offset: $offset) {
    id name serial asset_tag position
    status { name } role { name } platform { name }
    device_type { model manufacturer { name } }
    location { id name } rack { name location { id name } }
    primary_ip4 { address }
    interfaces { name type enabled mgmt_only mac_address description }
  }
}
"""

LOCATIONS_QUERY = """
query ($limit: Int, $offset: Int) {
  locations(limit: $limit, offset: $offset) {
    id name location_type { name } parent { id name }
  }
}
"""

RACKS_QUERY = """
query ($limit: Int, $offset: Int) {
  racks(limit: $limit, offset: $offset) { id name location { id name } }
}
"""

CABLES_QUERY = """
query ($limit: Int, $offset: Int) {
  cables(limit: $limit, offset: $offset) {
    id status { name }
    terminations {
      termination {
        __typename
        ... on InterfaceType { name device { name serial } }
      }
    }
  }
}
"""

# Population resolution reads the stable IDs of the IPAM objects.
IP_ADDRESSES_QUERY = """
query ($limit: Int, $offset: Int) {
  ip_addresses(limit: $limit, offset: $offset) {
    id address
    vrf { id } namespace { id } role { id }
    tags { id } tenant { id }
    interfaces { device { location { id } } }
  }
}
"""


def _gql(client: httpx.Client, query: str, variables: dict[str, Any]) -> dict[str, Any]:
    resp = client.post(GRAPHQL_PATH, json={"query": query, "variables": variables})
    resp.raise_for_status()
    body = resp.json()
    if body.get("errors"):
        raise RuntimeError(f"nautobot graphql: {body['errors'][0].get('message', body['errors'])}")
    return body["data"]


def _paged(client: httpx.Client, query: str, field: str, *, max_pages: int | None = None) -> list[dict]:
    def fetch(offset: int) -> tuple[list[dict], int | None]:
        if max_pages is not None and offset >= max_pages * PAGE:
            raise RuntimeError("Nautobot MTU page budget exhausted")
        page = _gql(client, query, {"limit": PAGE, "offset": offset})[field] or []
        # A short page is the last page. The answer has no total.
        return page, None if len(page) < PAGE else offset + PAGE

    return [row for page in offset_paged(fetch) for row in page]


@register
class NautobotCollector(Collector):
    name = "nautobot"
    ConfigModel = NautobotConfig
    KIND = "orchestrator"
    # Version 3 keys locations by id.
    PARSER_VERSION = "3"
    NORMALIZATION_VERSIONS: ClassVar[dict[str, str]] = {
        "mtu": MTU_NORMALIZATION_VERSION,
        "iface_uid": uid.IFACE_UID_VERSION,
        # A placeholder serial identifies no chassis. When 2 devices report one
        # serial in one run, the later device is keyed by its ref.
        "serial": "1",
    }
    NORMALIZATION_OUTCOME_KEYS = ("mtu:interfaces",)
    NORMALIZATION_CONFIG_KEYS = ("mtu_basis",)

    def __init__(self, config: NautobotConfig, settings):
        super().__init__(config, settings)
        self.scope = _scope(httpx.URL(config.url).host or config.url)

    def _client(self) -> httpx.Client:
        c = self.config
        client = http.client(c.url, c.tls, timeout=60, transport=_transport(c))
        client.headers["Authorization"] = f"Token {c.auth.key.get_secret_value()}"
        return client

    def probe(self) -> str:
        client = self._client()
        try:
            v = client.get(STATUS_PATH)
            v.raise_for_status()
            return f"ok: Nautobot {v.json().get('nautobot-version', '?')} at {self.config.url}"
        finally:
            client.close()

    def fetch(self) -> dict[str, Any]:
        client = self._client()
        try:
            raw = {
                "locations": _paged(client, LOCATIONS_QUERY, "locations"),
                "racks": _paged(client, RACKS_QUERY, "racks"),
                "devices": _paged(client, DEVICES_QUERY, "devices"),
                "cables": _paged(client, CABLES_QUERY, "cables"),
            }
            try:
                raw["ip_addresses"] = _paged(client, IP_ADDRESSES_QUERY, "ip_addresses")
                rows = len(raw["ip_addresses"])
                raw.setdefault(RAW_OUTCOMES_KEY, {})["ipam:addresses"] = {
                    "status": "ok" if rows else "empty",
                    "row_count": rows,
                }
            except (httpx.HTTPError, RuntimeError, ValueError, KeyError, TypeError) as exc:
                raw.setdefault(RAW_OUTCOMES_KEY, {})["ipam:addresses"] = {
                    "status": "failed",
                    "detail": f"{type(exc).__name__}: {exc}",
                }
            if self.config.capture_mtu:
                self._fetch_mtu(client, raw)
            return raw
        finally:
            client.close()

    def _fetch_mtu(self, client: httpx.Client, raw: dict[str, Any]) -> None:
        query = DEVICES_QUERY.replace("mac_address description", "mac_address description mtu")
        try:
            devices = _paged(client, query, "devices", max_pages=100)
            raw["mtu_devices"] = devices
            count = sum("mtu" in i for d in devices for i in (d.get("interfaces") or []))
            outcome = {"status": "ok" if count else "empty", "row_count": count}
        except (httpx.HTTPError, RuntimeError, ValueError, KeyError, TypeError) as exc:
            status = "failed"
            if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code in (401, 403):
                status = "unauthorized"
            elif isinstance(exc, RuntimeError) and "Cannot query field" in str(exc):
                status = "unsupported"
            elif isinstance(exc, (ValueError, KeyError, TypeError)):
                status = "malformed"
            outcome = {"status": status, "detail": f"{type(exc).__name__}: {exc}"}
        raw.setdefault(RAW_OUTCOMES_KEY, {})["mtu:interfaces"] = outcome

    def normalize(self, raw: dict[str, Any]) -> Batch:
        c = self.config
        host = httpx.URL(c.url).host or c.url
        return normalize_nautobot(raw, host=host, mtu_basis=c.mtu_basis, resolver=self.identity)


def _device_uid(dev: dict[str, Any], resolver: DeviceResolver) -> str | None:
    """Return the Device uid of one Nautobot device. The registry resolves the
    serial, and a documented serial resolves to the uid of the collected
    device. `chassis_serial` returns None for a placeholder serial. A device
    without a serial resolves by the ref `nautobot:<name>`. Return None for a
    device with no serial and no name."""
    serial = chassis_serial(dev.get("serial"))
    name = dev.get("name")
    if serial:
        return resolve_chassis(resolver, serial, ("ref", f"nautobot:{name}") if name else None, name)
    if name:
        return resolver.resolve_device("ref", f"nautobot:{name}", name)
    return None


def normalize_nautobot(
    raw: dict[str, Any], *, host: str, mtu_basis: str = "unknown", resolver: DeviceResolver | None = None
) -> Batch:
    """Build the twin of one Nautobot instance. `resolver` is the device
    identity registry (`Collector.identity`) that gives each device its uid
    (`_device_uid`). With None, a `MemoryResolver` resolves the devices."""
    resolver = resolver or MemoryResolver()
    b = GraphBuilder()
    mtu_interfaces = {
        (d.get("id"), i.get("name")): i
        for d in raw.get("mtu_devices", [])
        for i in (d.get("interfaces") or [])
        if d.get("id") and i.get("name")
    }

    loc_by_name = {loc["name"]: loc for loc in raw.get("locations", [])}

    def _place(location: dict[str, Any] | None) -> tuple[str, str]:
        """Return the Nautobot location id and name. An operator binds the id
        to a Site. A device without a Nautobot location is unplaced.

        A location name is unique only under its parent."""
        location = location or {}
        name = str(location.get("name") or "")
        place = location.get("id") or (loc_by_name.get(name) or {}).get("id")
        return str(place or ""), name

    # The schema has no edge from Rack to Site.
    rack_uids: dict[tuple[str, str], str] = {}
    for r in raw.get("racks", []):
        place, _ = _place(r.get("location"))
        rack_uids[(place, r["name"])] = b.node("Rack", uid.rack(place, r["name"]), name=r["name"])

    unkeyed = 0
    for dev in raw.get("devices", []):
        duid = _device_uid(dev, resolver)
        if duid is None:
            unkeyed += 1
            continue
        hn = normalize_hostname(dev.get("name") or "")
        place_id, place_name = _place(dev.get("location"))
        b.node(
            "Device",
            duid,
            hostname=hn.short or None,
            hostname_fqdn=hn.fqdn,
            identities=[hn.short] if hn.short else None,
            serial=chassis_serial(dev.get("serial")),
            role=((dev.get("role") or {}).get("name") or "unknown").lower(),
            platform=((dev.get("platform") or {}).get("name") or "").lower() or None,
            vendor=(((dev.get("device_type") or {}).get("manufacturer") or {}).get("name") or "").lower()
            or None,
            model=(dev.get("device_type") or {}).get("model"),
            status=((dev.get("status") or {}).get("name") or "").lower() or None,
            mgmt_ip=((dev.get("primary_ip4") or {}).get("address") or "").split("/")[0] or None,
            asset_tag=dev.get("asset_tag"),
            position=dev.get("position"),
            location=(dev.get("location") or {}).get("name"),
            reported_location=place_id or None,
            reported_location_name=place_name or None,
        )
        rack = (dev.get("rack") or {}).get("name")
        if rack:
            rack_place, _ = _place(dev["rack"].get("location"))
            ruid = rack_uids.get((rack_place, rack)) or b.node("Rack", uid.rack(rack_place, rack), name=rack)
            b.rel("IN_RACK", "Device", duid, "Rack", ruid)

        for i in dev.get("interfaces") or []:
            itype = (i.get("type") or "").lower()
            if any(v in itype for v in _VIRTUAL_TYPES):
                continue
            puid = b.node(
                "Port",
                uid.port(duid, i["name"]),
                name=i["name"],
                media=i.get("type"),
                mac=canonical_mac(i.get("mac_address")),
                admin="up" if i.get("enabled", True) else "down",
                description=i.get("description"),
            )
            b.rel("ON", "Port", puid, "Device", duid)
            evidence_iface = mtu_interfaces.get((dev.get("id"), i.get("name")), i)
            outcome = raw.get(RAW_OUTCOMES_KEY, {}).get("mtu:interfaces", {})
            if "mtu" in evidence_iface and outcome.get("status") not in {
                "failed",
                "malformed",
                "unauthorized",
                "unsupported",
            }:
                metrics = (
                    ("ipv4_mtu_bytes", "ipv6_mtu_bytes")
                    if mtu_basis == "ip_packet"
                    else ("unknown" if mtu_basis == "unknown" else "l2_max_frame_bytes",)
                )

                for metric in metrics:
                    emit_observation(
                        b,
                        "Port",
                        observation_from_raw(
                            subject_uid=puid,
                            source="nautobot",
                            source_target=host,
                            source_field="interface.mtu",
                            raw_value=evidence_iface["mtu"],
                            profile_id=mtu_basis,
                            metric=metric,
                            direction="both",
                            bound_kind="ceiling" if mtu_basis != "unknown" else "unknown",
                            enforcement="l3" if mtu_basis == "ip_packet" else "l2",
                            assertion_kind="intent",
                            collector_version="2",
                            raw_evidence_ref=f"device:{dev.get('id', duid)}/interface:{i['name']}/mtu",
                            selector_json=canonical_json(
                                {
                                    "version": 1,
                                    "basis_origin": "operator_declared",
                                    "evidence_origin": "inventory_intent",
                                }
                            ),
                        ),
                    )

    # An IPAM address with a /24 mask is one assigned host.
    for row in raw.get("ip_addresses", []):
        if not isinstance(row, dict) or not row.get("id") or not row.get("address"):
            continue
        vrf = (row.get("vrf") or {}).get("id") or row.get("vrf_id")
        namespace = (row.get("namespace") or {}).get("id") or row.get("namespace_id") or ""
        if not vrf:
            continue
        try:
            address = ipaddress.ip_address(str(row["address"]).split("/", 1)[0])
        except ValueError:
            continue
        location_ids = {
            str(interface.get("device", {}).get("location", {}).get("id"))
            for interface in row.get("interfaces", []) or []
            if isinstance(interface, dict) and interface.get("device", {}).get("location", {}).get("id")
        }
        anchor = f"nautobot:{namespace}:{vrf}"
        vrf_node = b.node(
            "VrfInstance",
            uid.vrf(anchor, str(vrf)),
            name=str(vrf),
            anchor=anchor,
            namespace_id=str(namespace),
            nautobot_vrf_id=str(vrf),
            population_source="nautobot",
        )
        ip_node = b.node(
            "IpAddress",
            uid.ip(anchor, str(address)),
            ip=str(address),
            af=address.version,
            anchor=anchor,
            nautobot_id=str(row["id"]),
            vrf_id=str(vrf),
            namespace_id=str(namespace),
            role_id=str((row.get("role") or {}).get("id") or row.get("role_id") or "") or None,
            location_id=next(iter(location_ids)) if len(location_ids) == 1 else None,
            tag_ids=sorted(
                str(item.get("id") if isinstance(item, dict) else item)
                for item in (row.get("tags") or row.get("tag_ids") or [])
            ),
            population_source="nautobot",
        )
        b.rel("IN_VRF", "IpAddress", ip_node, "VrfInstance", vrf_node)

    if unkeyed:
        logger.warning("nautobot: skipped %d device(s) with neither serial nor name", unkeyed)

    # Only a cable with exactly 2 ends that are both interfaces becomes CONNECTED_TO.
    skipped = 0
    for c in raw.get("cables", []):
        terms = [t.get("termination") or {} for t in c.get("terminations") or []]
        ifaces = [
            t for t in terms if t.get("__typename") == "InterfaceType" and (t.get("device") or {}).get("name")
        ]
        if len(terms) != 2 or len(ifaces) != 2:
            skipped += 1
            continue
        ends = [uid.port(_device_uid(t["device"], resolver), t["name"]) for t in ifaces]
        a, z = sorted(ends)
        b.rel("CONNECTED_TO", "Port", a, "Port", z, key={"source": "nautobot-cable"})
    if skipped:
        logger.warning(
            "nautobot: skipped %d cable(s) not interface<->interface with exactly 2 terminations", skipped
        )

    batch = b.batch("nautobot", _scope(host))
    outcome = raw.get(RAW_OUTCOMES_KEY, {}).get("mtu:interfaces")
    batch.sections["mtu"] = (
        SectionOutcome.model_validate(outcome)
        if outcome
        else SectionOutcome(
            status="unknown",
            detail="MTU intent not captured; numeric interpretation requires declared mtu_basis",
        )
    )
    batch.sections["mtu:operational"] = SectionOutcome(
        status="unsupported",
        detail="Nautobot inventory is intent, not operational or guest/vSwitch receive evidence",
    )
    ipam_outcome = raw.get(RAW_OUTCOMES_KEY, {}).get("ipam:addresses")
    if ipam_outcome:
        # A stored payload can hold the status complete or incomplete.
        ipam_outcome = {
            **ipam_outcome,
            "status": _LEGACY_IPAM_STATUS.get(ipam_outcome.get("status"), ipam_outcome.get("status")),
        }
    batch.sections["ipam:addresses"] = (
        SectionOutcome.model_validate(ipam_outcome)
        if ipam_outcome
        else SectionOutcome(status="unknown", detail="Nautobot IPAM addresses were not captured")
    )
    return batch
