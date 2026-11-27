"""APIC collector that reads an ACI fabric with class-level queries.

    curl -sk -X POST https://<apic>/api/aaaLogin.json \
      -d '{"aaaUser":{"attributes":{"name":"<ro-user>","pwd":"<pw>"}}}'
    curl -sk -b APIC-cookie=<token> \
      'https://<apic>/api/class/<cls>.json?page-size=1000&page=0&order-by=<cls>.dn'
    # Store the concatenated imdata of each page in data/raw/apic/first-contact/<cls>.json.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from typing import Any, ClassVar

import httpx

from hst.core import uid
from hst.core.aci_filter import BYPASS_NOT_COLLECTED, DIRECTION_IN, DIRECTION_OUT, aci_port
from hst.core.identity import DeviceResolver, MemoryResolver, chassis_serial
from hst.core.l3domain import DEFAULT_VRF, DomainPolicy, Vrf
from hst.core.l3domain import resolve as l3d_resolve
from hst.core.manifest import BGP_ROUTES_TABLE, BGP_SESSIONS_TABLE, OSPF_LSDB_TABLE, bgp_direction_key
from hst.core.model import Batch, SectionOutcome, TableOutcome
from hst.core.mtu import MTU_NORMALIZATION_VERSION

from . import http
from .auth import TlsConfig, UserPassword
from .base import RAW_OUTCOMES_KEY, Collector, SourceConfig, register
from .cli_collector import recorded_outcomes
from .mtu_apic import (
    MTU_CLASSES,
    MTU_MAX_PAGES,
    MTU_OUTCOME_KEYS,
    MTU_POLICY_PATH,
    MtuCaptureError,
    mtu_sections,
    node_device_uid,
    normalize_mtu_apic,
    validate_capture,
)
from .util import GraphBuilder, canonical_mac, renew_deadline

logger = logging.getLogger(__name__)

CLASS_PATH = "/api/class/{cls}.json"

CLASSES: tuple[str, ...] = (
    "fabricNode",
    "topSystem",
    "l1PhysIf",
    "lldpAdjEp",
    "pcAggrIf",
    "cdpAdjEp",
    "fvTenant",
    "fvAp",
    "fvAEPg",
    "fvBD",
    "fvSubnet",
    "fvCtx",
    "fvRsCtx",
    "fvRsBd",
    "vzBrCP",
    "vzSubj",
    "vzRsSubjFiltAtt",
    # A subject with "apply both directions" off attaches its filters under its
    # vzInTerm (intmnl) and vzOutTerm (outtmnl).
    "vzRsFiltAtt",
    "vzRsSubjGraphAtt",
    "vzFilter",
    "vzEntry",
    "fvRsProv",
    "fvRsCons",
    "l3extOut",
    "l3extInstP",
    "l3extRsEctx",
    "l3extSubnet",
    "vnsAbsGraph",
    "vnsGraphInst",
    "vnsSvcRedirectPol",
    "vnsRedirectDest",
    "fvCEp",
    "fvIp",
    "fvRsPathAtt",
    "fvRsDomAtt",
    # The L3Out OSPF operational classes, per node and per VRF.
    "ospfDom",
    "ospfArea",
    "ospfIf",
    "ospfAdjEp",
)

# The classes that decide whether an EPG pair of a VRF may be permitted outside its
# EPG-to-EPG contracts. They are vzAny, with its preferred group and the contracts it
# provides or consumes, and the ESGs with their VRF scope. A class that the run could
# not read sets `contract_bypass` of every VRF to "not-collected" (`_contract_bypass`).
# The ACI gates then state no implicit deny.
CONTRACT_BYPASS_CLASSES: tuple[str, ...] = (
    "vzAny",
    "vzRsAnyToProv",
    "vzRsAnyToCons",
    "vzRsAnyToConsIf",
    "fvESg",
    "fvRsScope",
)

PAGE_SIZE = 1000


def _attrs(mo: dict[str, Any]) -> dict[str, Any]:
    """Return the attributes of an imdata item {"<cls>": {"attributes": {...}}}."""
    return next(iter(mo.values()))["attributes"]


def _transport(config: ApicConfig) -> httpx.BaseTransport | None:
    """Test seam. None selects the httpx default transport."""
    return None


# APIC's own default session lifetime, used when aaaLogin does not report one.
DEFAULT_TOKEN_LIFETIME_S = 600
TOKEN_REFRESH_FRACTION = 0.66


class ApicConfig(SourceConfig):
    url: str  # e.g. https://apic1.example
    auth: UserPassword
    fabric: str  # uid namespace: uid.aci(fabric, dn)
    capture_mtu: bool = False  # reads the optional MTU classes (`MTU_CLASSES`)
    tls: TlsConfig = TlsConfig()  # `verify` defaults to True


@register
class ApicCollector(Collector):
    name = "apic"
    ConfigModel = ApicConfig
    KIND = "orchestrator"
    PARSER_VERSION = "4"
    NORMALIZATION_VERSIONS: ClassVar[dict[str, str]] = {
        "mtu": MTU_NORMALIZATION_VERSION,
        "iface_uid": uid.IFACE_UID_VERSION,
        # A placeholder serial identifies no chassis. When 2 devices report one serial
        # in a run, the later device is keyed by its ref.
        "serial": "1",
    }
    NORMALIZATION_OUTCOME_KEYS: ClassVar[tuple[str, ...]] = MTU_OUTCOME_KEYS
    SIDE_TABLES: ClassVar[tuple[str, ...]] = (OSPF_LSDB_TABLE, BGP_ROUTES_TABLE, BGP_SESSIONS_TABLE)

    def __init__(self, config: ApicConfig, settings):
        super().__init__(config, settings)
        self.scope = f"apic:{config.fabric}"
        self._token_expires = 0.0

    def _login(self, client: httpx.Client) -> None:
        c = self.config
        resp = client.post(
            "/api/aaaLogin.json",
            json={
                "aaaUser": {
                    "attributes": {"name": c.auth.username, "pwd": c.auth.password.get_secret_value()}
                }
            },
        )
        if resp.status_code != 200:
            raise RuntimeError(f"APIC login failed: HTTP {resp.status_code}")
        attrs = _attrs(resp.json()["imdata"][0])
        client.cookies.set("APIC-cookie", attrs["token"])
        self._token_expires = renew_deadline(
            time.monotonic(),
            attrs.get("refreshTimeoutSeconds"),
            default=DEFAULT_TOKEN_LIFETIME_S,
            fraction=TOKEN_REFRESH_FRACTION,
            floor=60,
        )

    def _client(self) -> httpx.Client:
        c = self.config
        return http.logged_in_client(c.url, c.tls, self._login, timeout=60, transport=_transport(c))

    def _keep_alive(self, client: httpx.Client) -> None:
        if time.monotonic() < self._token_expires:
            return
        try:
            resp = client.get("/api/aaaRefresh.json")
            if resp.status_code == 200:
                attrs = _attrs(resp.json()["imdata"][0])
                if attrs.get("token"):
                    client.cookies.set("APIC-cookie", attrs["token"])
                self._token_expires = renew_deadline(
                    time.monotonic(),
                    None,
                    default=DEFAULT_TOKEN_LIFETIME_S,
                    fraction=TOKEN_REFRESH_FRACTION,
                )
                return
        except httpx.HTTPError:
            pass
        self._login(client)

    def _get_class(
        self,
        client: httpx.Client,
        cls: str,
        *,
        max_pages: int | None = None,
    ) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        page = 0
        while True:
            if max_pages is not None and page >= max_pages:
                raise RuntimeError(f"{cls}: page budget {max_pages} exhausted; capture incomplete")
            self._keep_alive(client)
            resp = client.get(
                CLASS_PATH.format(cls=cls),
                params={"page-size": str(PAGE_SIZE), "page": str(page), "order-by": f"{cls}.dn"},
            )
            if resp.status_code in (401, 403):
                self._login(client)
                resp = client.get(
                    CLASS_PATH.format(cls=cls),
                    params={"page-size": str(PAGE_SIZE), "page": str(page), "order-by": f"{cls}.dn"},
                )
            resp.raise_for_status()
            body = resp.json()
            if max_pages is not None:
                validate_capture(body.get("imdata") if isinstance(body, dict) else None, cls)
            batch = body.get("imdata", [])
            rows.extend(batch)
            if len(batch) < PAGE_SIZE:
                total_raw = body.get("totalCount")
                if total_raw is None:
                    logger.warning(
                        "apic: %s page reply carries no totalCount, trusting short-page termination", cls
                    )
                else:
                    total = int(total_raw)
                    if len(rows) < total:
                        raise RuntimeError(f"{cls}: page total {total} not covered")
                return rows
            page += 1

    def probe(self) -> str:
        # The client of `http.logged_in_client` raises when entered as a context
        # manager.
        client = self._client()
        try:
            rows = self._get_class(client, "firmwareCtrlrRunning")
            version = _attrs(rows[0])["version"] if rows else "unknown"
            return f"login ok: APIC {version} at {self.config.url}"
        finally:
            client.close()

    def fetch(self) -> dict[str, list[dict[str, Any]]]:
        client = self._client()
        try:
            raw: dict[str, Any] = {cls: self._get_class(client, cls) for cls in CLASSES}
            for cls in CONTRACT_BYPASS_CLASSES:
                try:
                    raw[cls] = self._get_class(client, cls)
                except (httpx.HTTPError, RuntimeError) as exc:
                    # `_contract_bypass` treats a class that is missing from `raw` as
                    # not collected.
                    logger.warning("apic: %s failed (%s); contract bypass inputs not collected", cls, exc)
            self._fetch_bgp_observations(client, raw)
            self._fetch_mtu(client, raw)
            return raw
        finally:
            client.close()

    def _fetch_bgp_observations(self, client: httpx.Client, raw: dict[str, Any]) -> None:
        if self.config.capture_bgp == "none":
            return
        outcomes: dict[str, dict[str, Any]] = {}
        for cls in BGP_CLASSES:
            try:
                raw[cls] = self._get_class(client, cls)
                outcomes[cls] = {"status": "ok"}
            except (httpx.HTTPError, RuntimeError) as exc:
                logger.warning("apic: %s failed (%s); continuing without it", cls, exc)
                raw[cls] = []
                outcomes[cls] = {"status": "failed", "detail": f"{type(exc).__name__}: {exc}"}
        raw[RAW_OUTCOMES_KEY] = outcomes

    def _fetch_mtu(self, client: httpx.Client, raw: dict[str, Any]) -> None:
        """Read only documented optional classes, retaining per-source failures."""
        if not self.config.capture_mtu:
            return
        outcomes = raw.setdefault(RAW_OUTCOMES_KEY, {})
        for cls in MTU_CLASSES:
            try:
                if cls == "l2InstPol":
                    self._keep_alive(client)
                    response = client.get(MTU_POLICY_PATH)
                    if response.status_code in (401, 403):
                        self._login(client)
                        response = client.get(MTU_POLICY_PATH)
                    response.raise_for_status()
                    rows = response.json().get("imdata")
                else:
                    rows = self._get_class(client, cls, max_pages=MTU_MAX_PAGES)
                rows = validate_capture(rows, cls)
                raw[cls] = rows
                outcomes[f"mtu:{cls}"] = {
                    "status": "ok" if rows else "empty",
                    "row_count": len(rows),
                }
            except (httpx.HTTPError, RuntimeError, ValueError, TypeError, AttributeError) as exc:
                status = "failed"
                if isinstance(exc, MtuCaptureError):
                    status = exc.status
                elif isinstance(exc, httpx.HTTPStatusError):
                    if exc.response.status_code in (401, 403):
                        status = "unauthorized"
                    elif exc.response.status_code == 404:
                        status = "unsupported"
                elif isinstance(exc, (ValueError, TypeError, AttributeError)):
                    status = "malformed"
                raw[cls] = []
                outcomes[f"mtu:{cls}"] = {"status": status, "detail": f"{type(exc).__name__}: {exc}"}
                logger.warning("apic: optional MTU %s %s; continuing without that evidence", cls, status)

    def normalize(self, raw: dict[str, Any]) -> Batch:
        batch = normalize_apic(
            raw,
            fabric=self.config.fabric,
            l3dom=self.config.effective_routing_scope,
            resolver=self.identity,
        )
        policy_classes = (
            "vzBrCP",
            "vzSubj",
            "vzFilter",
            "vzEntry",
            "vnsAbsGraph",
            "vnsGraphInst",
            "vnsSvcRedirectPol",
            "vnsRedirectDest",
        )
        rows = sum(len(raw.get(name) or ()) for name in policy_classes)
        batch.sections["policy"] = SectionOutcome(status="ok" if rows else "empty", row_count=rows)
        endpoint_classes = ("fvCEp", "fvIp")
        endpoint_rows = sum(len(raw.get(name) or ()) for name in endpoint_classes)
        batch.sections["endpoint"] = SectionOutcome(
            status="ok" if endpoint_rows else "empty", row_count=endpoint_rows
        )
        batch.sections.update(mtu_sections(raw))
        return batch

    def side_tables(self, raw: dict[str, Any]) -> dict[str, list[dict]]:
        """`bgp_session_routes` is always empty."""
        return bgp_side_rows(raw, self.config.fabric, self.identity)

    def table_outcomes(self, raw: dict[str, Any]) -> dict[str, TableOutcome]:
        return {
            OSPF_LSDB_TABLE: TableOutcome(
                status="not-captured",
                detail="the ACI class model exposes no OSPF link-state-database class",
            ),
            **bgp_table_outcomes(
                raw, self.config.fabric, capture=self.config.capture_bgp, resolver=self.identity
            ),
        }


class _AciDomains:
    """Resolves an ACI object to the L3 domain of the VRF behind it.

    The Ctx dn is the identity of the VRF.
    """

    def __init__(self, raw: dict[str, Any], fabric: str, l3dom: str) -> None:
        self._policy = DomainPolicy(scope=l3dom)
        self._fabric = fabric
        self._default = l3d_resolve(Vrf(device=fabric, name=DEFAULT_VRF), self._policy)
        self._epg_bd: dict[str, str] = {}
        self._bd_ctx: dict[str, str] = {}
        for mo in raw.get("fvRsBd", []):
            a = _attrs(mo)
            if a.get("tDn"):
                self._epg_bd[_parent_dn(a["dn"])] = a["tDn"]
        for mo in raw.get("fvRsCtx", []):
            a = _attrs(mo)
            if a.get("tDn"):
                self._bd_ctx[_parent_dn(a["dn"])] = a["tDn"]

    def for_ctx(self, ctx_dn: str | None) -> str:
        if not ctx_dn:
            return self._default
        return l3d_resolve(Vrf(device=self._fabric, name=ctx_dn), self._policy)

    def for_bd(self, bd_dn: str | None) -> str:
        return self.for_ctx(self._bd_ctx.get(bd_dn or ""))

    def for_epg(self, epg_dn: str | None) -> str:
        return self.for_bd(self._epg_bd.get(epg_dn or ""))

    def bd_dn_for_epg(self, epg_dn: str | None) -> str | None:
        return self._epg_bd.get(epg_dn or "") or None


def normalize_apic(
    raw: dict[str, Any], *, fabric: str, l3dom: str, resolver: DeviceResolver | None = None
) -> Batch:
    """The twin of one fabric. `resolver` is the device identity registry
    (`Collector.identity`) that gives each fabric node its Device uid (`_device_uid`).
    None selects a `MemoryResolver`."""
    resolver = resolver or MemoryResolver()
    b = GraphBuilder()
    domains = _AciDomains(raw, fabric, l3dom)
    _fabric_stage(b, raw, fabric, resolver)
    _tenant_stage(b, raw, fabric, l3dom, domains)
    _contract_stage(b, raw, fabric, domains)
    _service_stage(b, raw, fabric, l3dom, domains, resolver)
    _ospf_stage(b, raw, fabric, resolver)
    normalize_mtu_apic(b, raw, fabric, resolver)
    return b.batch("apic", f"apic:{fabric}")


def _device_uid(a: dict[str, Any], resolver: DeviceResolver, fabric: str) -> str:
    """The Device uid of one fabricNode. The registry resolves the serial or the ref of
    the node (`node_device_uid`). Every stage and the BGP observation rows use this
    function for the uid."""
    return node_device_uid(a, fabric, resolver)


def _node_dn(dn: str) -> str:
    """Return the node dn of a dn, `topology/pod-1/node-101` for
    `topology/pod-1/node-101/sys/...`.
    """
    parts = dn.split("/")
    return "/".join(parts[:3])


# Device platform by fabricNode role.
_ACI_PLATFORM = {"controller": "apic", "leaf": "aci-leaf", "spine": "aci-spine"}


def _fabric_stage(b: GraphBuilder, raw: dict[str, Any], fabric: str, resolver: DeviceResolver) -> None:
    """Write the Device, Port, Fabric and Pod structure and the reported location of
    each Device from fabricNode, topSystem, l1PhysIf, lldpAdjEp, pcAggrIf and cdpAdjEp."""
    fab_uid = b.node("Fabric", uid.fabric(fabric), name=fabric)
    dev_by_node_dn: dict[str, str] = {}
    for mo in raw.get("fabricNode", []):
        a = _attrs(mo)
        pod_dn = "/".join(a["dn"].split("/")[:2])  # topology/pod-1
        duid = b.node(
            "Device",
            _device_uid(a, resolver, fabric),
            hostname=a.get("name"),
            role=a.get("role") or "unknown",
            serial=chassis_serial(a.get("serial")),
            model=a.get("model"),
            os_version=a.get("version"),
            platform=_ACI_PLATFORM.get(a.get("role"), "aci"),
            dn=a["dn"],
            # The location is per pod. One fabric can span more than one site.
            reported_location=f"{fabric}/{pod_dn}",
            reported_location_name=f"{fabric} {pod_dn}",
        )
        dev_by_node_dn[a["dn"]] = duid
        b.rel("MEMBER_OF", "Device", duid, "Fabric", fab_uid)
        pod_uid = b.node("Pod", uid.aci(fabric, pod_dn), name=pod_dn)
        b.rel("IN_POD", "Device", duid, "Pod", pod_uid)
        b.rel("PART_OF", "Pod", pod_uid, "Fabric", fab_uid)
    for mo in raw.get("topSystem", []):
        a = _attrs(mo)
        duid = dev_by_node_dn.get(_node_dn(a["dn"]))
        if duid and a.get("oobMgmtAddr"):
            b.node("Device", duid, mgmt_ip=a["oobMgmtAddr"])
    for mo in raw.get("l1PhysIf", []):
        a = _attrs(mo)
        duid = dev_by_node_dn.get(_node_dn(a["dn"]))
        if not duid:
            continue
        puid = b.node(
            "Port", f"{duid}/port/{uid.slug(a['id'])}", name=a["id"], admin_state=a.get("adminSt"), dn=a["dn"]
        )
        b.rel("ON", "Port", puid, "Device", duid)
    for mo in raw.get("pcAggrIf", []):
        a = _attrs(mo)
        duid = dev_by_node_dn.get(_node_dn(a["dn"]))
        if not duid:
            continue
        puid = b.node("Port", f"{duid}/port/{uid.slug(a['id'])}", name=a["id"], kind="lag", dn=a["dn"])
        b.rel("ON", "Port", puid, "Device", duid)
    for mo in raw.get("lldpAdjEp", []):
        a = _attrs(mo)
        duid = dev_by_node_dn.get(_node_dn(a["dn"]))
        if not duid:
            continue
        ifid = a["dn"].split("/if-[")[1].split("]")[0]  # ...if-[eth1/2]/adj-1
        b.node(
            "Port",
            f"{duid}/port/{uid.slug(ifid)}",
            lldp_neighbor_mac=a.get("chassisIdV"),
            lldp_neighbor_name=a.get("sysName"),
            lldp_neighbor_port=a.get("portIdV"),
        )
    for mo in raw.get("cdpAdjEp", []):
        a = _attrs(mo)
        duid = dev_by_node_dn.get(_node_dn(a["dn"]))
        if not duid:
            continue
        ifid = a["dn"].split("/if-[")[1].split("]")[0]  # ...if-[eth1/1]/adj-1
        b.node(
            "Port",
            f"{duid}/port/{uid.slug(ifid)}",
            cdp_neighbor_name=a.get("sysName") or a.get("devId"),
            cdp_neighbor_port=a.get("portId"),
        )


def _parent_dn(dn: str) -> str:
    """Strip the last rn segment off a dn.

    A dn that contains '-[' is cut before the segment that contains it.

    >>> _parent_dn("uni/tn-prod/ap-web/epg-fe")
    'uni/tn-prod/ap-web'
    >>> _parent_dn("uni/tn-prod/BD-web-bd/subnet-[10.1.1.1/24]")
    'uni/tn-prod/BD-web-bd'
    """
    if "-[" in dn:
        return dn[: dn.rindex("/", 0, dn.index("-["))]
    return dn.rsplit("/", 1)[0]


def _tenant_stage(
    b: GraphBuilder, raw: dict[str, Any], fabric: str, l3dom: str, domains: _AciDomains
) -> None:
    """Write the tenant, BD, EPG, VRF and subnet graph from fvTenant, fvAp, fvAEPg,
    fvBD, fvSubnet, fvCtx, fvRsCtx and fvRsBd.
    """

    def aci_node(label: str, dn: str, **props) -> str:
        return b.node(label, uid.aci(fabric, dn), dn=dn, **props)

    for mo in raw.get("fvTenant", []):
        a = _attrs(mo)
        aci_node("Tenant", a["dn"], name=a.get("name"))
    for mo in raw.get("fvAp", []):
        a = _attrs(mo)
        ap = aci_node("AppProfile", a["dn"], name=a.get("name"))
        b.rel("HAS", "Tenant", uid.aci(fabric, _parent_dn(a["dn"])), "AppProfile", ap)
    for mo in raw.get("fvAEPg", []):
        a = _attrs(mo)
        pref_group = a.get("prefGrMemb")
        epg = aci_node(
            "Epg",
            a["dn"],
            name=a.get("name"),
            pref_group_member=pref_group.lower() if pref_group else None,
        )
        b.rel("HAS", "AppProfile", uid.aci(fabric, _parent_dn(a["dn"])), "Epg", epg)
    bypass = _contract_bypass(raw)
    for mo in raw.get("fvCtx", []):
        a = _attrs(mo)
        # pcEnfPref ("enforced"/"unenforced") drives gates/aci.py's contract verdict.
        pc_enf_pref = a.get("pcEnfPref")
        aci_node(
            "VrfInstance",
            a["dn"],
            name=a.get("name"),
            pc_enf_pref=pc_enf_pref.lower() if pc_enf_pref else None,
            contract_bypass=bypass[a["dn"]],
        )
    for mo in raw.get("fvBD", []):
        a = _attrs(mo)
        aci_node("BridgeDomain", a["dn"], name=a.get("name"))
    for mo in raw.get("fvRsCtx", []):
        a = _attrs(mo)
        tdn = a.get("tDn")
        if not tdn:
            continue
        b.rel(
            "IN_VRF",
            "BridgeDomain",
            uid.aci(fabric, _parent_dn(a["dn"])),
            "VrfInstance",
            uid.aci(fabric, tdn),
        )
    for mo in raw.get("fvRsBd", []):
        a = _attrs(mo)
        tdn = a.get("tDn")
        if not tdn:
            continue
        b.rel("IN_BD", "Epg", uid.aci(fabric, _parent_dn(a["dn"])), "BridgeDomain", uid.aci(fabric, tdn))
    for mo in raw.get("fvSubnet", []):
        a = _attrs(mo)
        iface = ipaddress.ip_interface(a["ip"])
        bd_dn = _parent_dn(a["dn"])
        dom = domains.for_bd(bd_dn)
        pfx = b.node(
            "Prefix",
            uid.aci(fabric, a["dn"]),
            cidr=str(iface.network),
            gateway_ip=str(iface.ip),
            l3dom=dom,
            anchor=dom,
            dn=a["dn"],
        )
        b.rel("IN", "Prefix", pfx, "BridgeDomain", uid.aci(fabric, bd_dn))


def _contract_bypass(raw: dict[str, Any]) -> dict[str, str]:
    """The `contract_bypass` value of each fvCtx dn. The value is the comma-separated
    flags of what may permit an EPG pair of the VRF outside its EPG-to-EPG contracts.
    core/aci_filter.py `contract_bypass` reads it.

    The flag "vzany" is set when the vzAny of the VRF provides or consumes a contract.
    The flag "preferred-group" is set when the prefGrMemb of the vzAny is not
    "disabled". The flag "esg" is set when an ESG is scoped to the VRF. An ESG without a
    collected scope sets "esg" on every VRF. The value is "" when no flag is set. The
    value is "not-collected" on every VRF when a class of CONTRACT_BYPASS_CLASSES was
    not read.
    """
    ctx_dns = [_attrs(mo)["dn"] for mo in raw.get("fvCtx", [])]
    if any(cls not in raw for cls in CONTRACT_BYPASS_CLASSES):
        return dict.fromkeys(ctx_dns, BYPASS_NOT_COLLECTED)
    flags: dict[str, set[str]] = {dn: set() for dn in ctx_dns}

    def add(ctx_dn: str, flag: str) -> None:
        if ctx_dn in flags:
            flags[ctx_dn].add(flag)

    for mo in raw["vzAny"]:
        a = _attrs(mo)
        if str(a.get("prefGrMemb") or "").strip().lower() != "disabled":
            add(_parent_dn(a["dn"]), "preferred-group")
    for cls in ("vzRsAnyToProv", "vzRsAnyToCons", "vzRsAnyToConsIf"):
        for mo in raw[cls]:
            a = _attrs(mo)
            # In uni/tn-x/ctx-y/any/rsanyToProv-c the parent is the vzAny and its parent
            # is the ctx.
            add(_parent_dn(_parent_dn(a["dn"])), "vzany")
    esgs = {_attrs(mo)["dn"] for mo in raw["fvESg"]}
    scoped: set[str] = set()
    for mo in raw["fvRsScope"]:
        a = _attrs(mo)
        parent = _parent_dn(a["dn"])
        if parent in esgs and a.get("tDn"):
            scoped.add(parent)
            add(a["tDn"], "esg")
    if esgs - scoped:
        for dn in flags:
            flags[dn].add("esg")
    return {dn: ",".join(sorted(values)) for dn, values in flags.items()}


def _contract_stage(b: GraphBuilder, raw: dict[str, Any], fabric: str, domains: _AciDomains) -> None:
    """Write the contract graph from vzBrCP, vzSubj, vzRsSubjFiltAtt, vzRsFiltAtt,
    vzFilter, vzEntry, fvRsProv, fvRsCons, l3extOut, l3extInstP, l3extRsEctx and
    l3extSubnet.

    An external EPG matches each of its subnets that has the scope
    `import-security`. A contract relation of an external EPG starts at its
    `ExtEpg` node.
    """

    def aci_node(label: str, dn: str, **props) -> str:
        return b.node(label, uid.aci(fabric, dn), dn=dn, **props)

    for mo in raw.get("vzBrCP", []):
        a = _attrs(mo)
        ct = aci_node("Contract", a["dn"], name=a.get("name"))
        b.rel("HAS", "Tenant", uid.aci(fabric, _parent_dn(a["dn"])), "Contract", ct)
    contract_dns = {_attrs(mo)["dn"] for mo in raw.get("vzBrCP", [])}
    kept_subject_dns: set[str] = set()
    for mo in raw.get("vzSubj", []):
        a = _attrs(mo)
        if _parent_dn(a["dn"]) not in contract_dns:
            continue
        kept_subject_dns.add(a["dn"])
        subj = aci_node("ContractSubject", a["dn"], name=a.get("name"))
        b.rel("HAS", "Contract", uid.aci(fabric, _parent_dn(a["dn"])), "ContractSubject", subj)
    for mo in raw.get("vzFilter", []):
        a = _attrs(mo)
        aci_node("AciFilter", a["dn"], name=a.get("name"))
    for mo in raw.get("vzEntry", []):
        a = _attrs(mo)
        entry = aci_node(
            "FilterEntry",
            a["dn"],
            name=a.get("name"),
            # APIC writes well-known ports by name (dFromPort "https"). `aci_port`
            # returns the number. Every ACI gate reads the number (core/aci_filter.py).
            # `ether_type` is written on every entry. It is the vzEntry default
            # "unspecified" when the reply omits etherT.
            proto=a.get("prot"),
            ether_type=a.get("etherT") or "unspecified",
            s_from_port=aci_port(a.get("sFromPort")),
            s_to_port=aci_port(a.get("sToPort")),
            d_from_port=aci_port(a.get("dFromPort")),
            d_to_port=aci_port(a.get("dToPort")),
            # tcpRules ("est", "syn", ...) and applyToFrag narrow what the entry
            # matches. Both are written on every entry. A reply that omits them gives
            # "unspecified" and "no". The gates read a missing value as not collected.
            # `stateful` changes only how the leaf tracks return traffic.
            tcp_rules=a.get("tcpRules") or "unspecified",
            apply_to_frag=a.get("applyToFrag") or "no",
            stateful=a.get("stateful"),
        )
        b.rel("HAS", "AciFilter", uid.aci(fabric, _parent_dn(a["dn"])), "FilterEntry", entry)
    for mo in raw.get("vzRsSubjFiltAtt", []):
        a = _attrs(mo)
        tdn = a.get("tDn")
        if not tdn:
            continue
        if _parent_dn(a["dn"]) not in kept_subject_dns:
            continue
        b.rel(
            "USES_FILTER",
            "ContractSubject",
            uid.aci(fabric, _parent_dn(a["dn"])),
            "AciFilter",
            uid.aci(fabric, tdn),
            action=a.get("action"),
            directives=a.get("directives"),
        )
    for mo in raw.get("vzRsFiltAtt", []):
        a = _attrs(mo)
        tdn = a.get("tDn")
        if not tdn:
            continue
        # In .../subj-x/intmnl/rsfiltAtt-f the parent is the term and its parent is the
        # subject.
        term = _parent_dn(a["dn"])
        subject = _parent_dn(term)
        direction = {"intmnl": DIRECTION_IN, "outtmnl": DIRECTION_OUT}.get(term.rsplit("/", 1)[-1])
        if direction is None or subject not in kept_subject_dns:
            continue
        # The relationship is keyed by direction. One filter can be attached under both
        # terms, and each attachment has its own action.
        b.rel(
            "USES_FILTER",
            "ContractSubject",
            uid.aci(fabric, subject),
            "AciFilter",
            uid.aci(fabric, tdn),
            key={"direction": direction},
            action=a.get("action"),
            directives=a.get("directives"),
        )
    for cls, rtype in (("fvRsProv", "PROVIDES"), ("fvRsCons", "CONSUMES")):
        for mo in raw.get(cls, []):
            a = _attrs(mo)
            tdn = a.get("tDn")
            if not tdn:
                continue
            owner = _parent_dn(a["dn"])
            label = "ExtEpg" if owner.rsplit("/", 1)[-1].startswith("instP-") else "Epg"
            b.rel(rtype, label, uid.aci(fabric, owner), "Contract", uid.aci(fabric, tdn))
    for mo in raw.get("l3extOut", []):
        a = _attrs(mo)
        out = aci_node("L3Out", a["dn"], name=a.get("name"))
        b.rel("PART_OF", "L3Out", out, "Tenant", uid.aci(fabric, _parent_dn(a["dn"])))
    for mo in raw.get("l3extInstP", []):
        a = _attrs(mo)
        ext = aci_node("ExtEpg", a["dn"], name=a.get("name"))
        b.rel("PART_OF", "ExtEpg", ext, "L3Out", uid.aci(fabric, _parent_dn(a["dn"])))
    l3out_ctx: dict[str, str] = {}
    for mo in raw.get("l3extRsEctx", []):
        a = _attrs(mo)
        tdn = a.get("tDn")
        if not tdn:
            continue
        l3out_ctx[_parent_dn(a["dn"])] = tdn
        b.rel("IN_VRF", "L3Out", uid.aci(fabric, _parent_dn(a["dn"])), "VrfInstance", uid.aci(fabric, tdn))
    for mo in raw.get("l3extSubnet", []):
        a = _attrs(mo)
        if "import-security" not in str(a.get("scope") or "").split(","):
            continue
        ext_dn = _parent_dn(a["dn"])
        dom = domains.for_ctx(l3out_ctx.get(_parent_dn(ext_dn)))
        pfx = b.node(
            "Prefix",
            uid.aci(fabric, a["dn"]),
            cidr=str(ipaddress.ip_network(a["ip"], strict=False)),
            l3dom=dom,
            anchor=dom,
            dn=a["dn"],
        )
        b.rel("MATCHES", "ExtEpg", uid.aci(fabric, ext_dn), "Prefix", pfx)


def _service_stage(
    b: GraphBuilder,
    raw: dict[str, Any],
    fabric: str,
    l3dom: str,
    domains: _AciDomains,
    resolver: DeviceResolver,
) -> None:
    """Write the service graphs, PBR, endpoints and static and VMM bindings from
    vnsAbsGraph, vnsGraphInst, vzRsSubjGraphAtt, vnsSvcRedirectPol, vnsRedirectDest,
    fvCEp, fvIp, fvRsPathAtt and fvRsDomAtt."""

    def aci_node(label: str, dn: str, **props) -> str:
        return b.node(label, uid.aci(fabric, dn), dn=dn, **props)

    unresolved_bd: set[str] = set()

    def endpoint_uid(epg_dn: str, mac: str) -> str:
        """Endpoint identity is the mac within the bridge domain of the EPG."""
        bd_dn = domains.bd_dn_for_epg(epg_dn)
        if bd_dn is None:
            if epg_dn not in unresolved_bd:
                unresolved_bd.add(epg_dn)
                logger.warning(
                    "apic: no bridge domain resolved for EPG %s; scoping its endpoint identity to the EPG dn",
                    epg_dn,
                )
            return uid.endpoint(uid.aci(fabric, epg_dn), mac)
        return uid.endpoint(uid.aci(fabric, bd_dn), mac)

    node_serial = {  # device uid by node id
        _attrs(mo)["dn"].rsplit("/node-", 1)[1]: _device_uid(_attrs(mo), resolver, fabric)
        for mo in raw.get("fabricNode", [])
    }

    for mo in raw.get("vnsAbsGraph", []):
        a = _attrs(mo)
        aci_node("ServiceGraphTemplate", a["dn"], name=a.get("name"))
    for mo in raw.get("vnsGraphInst", []):
        a = _attrs(mo)
        aci_node("ServiceGraphInstance", a["dn"], ctrct_dn=a.get("ctrctDn"))
    contract_dns = {_attrs(mo)["dn"] for mo in raw.get("vzBrCP", [])}
    kept_subject_dns = {
        _attrs(mo)["dn"] for mo in raw.get("vzSubj", []) if _parent_dn(_attrs(mo)["dn"]) in contract_dns
    }
    for mo in raw.get("vzRsSubjGraphAtt", []):
        a = _attrs(mo)
        tdn = a.get("tDn")
        if not tdn:
            continue
        if _parent_dn(a["dn"]) not in kept_subject_dns:
            continue
        b.rel(
            "APPLIES_GRAPH",
            "ContractSubject",
            uid.aci(fabric, _parent_dn(a["dn"])),
            "ServiceGraphTemplate",
            uid.aci(fabric, tdn),
        )
    for mo in raw.get("vnsSvcRedirectPol", []):
        a = _attrs(mo)
        aci_node("PbrPolicy", a["dn"], name=a.get("name"))
    for mo in raw.get("vnsRedirectDest", []):
        a = _attrs(mo)
        dest = aci_node("PbrDest", a["dn"], ip=a.get("ip"), mac=a.get("mac"))
        b.rel("HAS_DEST", "PbrPolicy", uid.aci(fabric, _parent_dn(a["dn"])), "PbrDest", dest)
    for mo in raw.get("fvCEp", []):
        a = _attrs(mo)
        mac = canonical_mac(a["mac"])
        if mac is None:
            logger.warning("apic: skipping fvCEp %s: unparseable mac %r", a.get("dn"), a.get("mac"))
            continue
        epg_dn = _parent_dn(a["dn"])
        ep = b.node("Endpoint", endpoint_uid(epg_dn, a["mac"]), mac=mac, name=a.get("name"))
        b.rel("IN_EPG", "Endpoint", ep, "Epg", uid.aci(fabric, epg_dn))
        # The bridge domain of the EPG is the flood domain of the endpoint. The UniFi
        # collector writes the same relationship.
        bd_dn = domains.bd_dn_for_epg(epg_dn)
        if bd_dn is not None:
            b.rel("IN", "Endpoint", ep, "BridgeDomain", uid.aci(fabric, bd_dn))
    for mo in raw.get("fvIp", []):
        a = _attrs(mo)
        cep_dn = _parent_dn(a["dn"])
        mac = cep_dn.rsplit("cep-", 1)[1]
        af = 6 if ":" in a["addr"] else 4
        epg_dn = _parent_dn(cep_dn)
        # The IpAddress is scoped to the tenant VRF of the EPG of the endpoint. Equal
        # addresses of 2 tenants are separate nodes.
        dom = domains.for_epg(epg_dn)
        ipu = b.node("IpAddress", uid.ip(dom, a["addr"]), ip=a["addr"], af=af, l3dom=dom, anchor=dom)
        b.rel("HAS_IP", "Endpoint", endpoint_uid(epg_dn, mac), "IpAddress", ipu)
    skipped_paths = 0
    for mo in raw.get("fvRsPathAtt", []):
        a = _attrs(mo)
        tdn = a.get("tDn")  # single: .../paths-101/pathep-[eth1/1]
        # vPC:    .../protpaths-101-102/pathep-[po-web]
        if not tdn:
            continue
        ifid = tdn.split("pathep-[")[1].rstrip("]")
        if "/protpaths-" in tdn:
            node_ids = tdn.split("/protpaths-")[1].split("/")[0].split("-")
        else:
            node_ids = [tdn.split("/paths-")[1].split("/")[0]]
        epg_uid = uid.aci(fabric, _parent_dn(a["dn"]))
        for node_id in node_ids:
            duid = node_serial.get(node_id)
            if not duid:
                skipped_paths += 1
                continue
            puid = f"{duid}/port/{uid.slug(ifid)}"
            b.node("Port", puid, name=ifid)  # the Port node of the STATIC_BINDING target
            b.rel("ON", "Port", puid, "Device", duid)
            b.rel("STATIC_BINDING", "Epg", epg_uid, "Port", puid, encap=a.get("encap"), mode=a.get("mode"))
    if skipped_paths:
        logger.warning(
            "apic: skipped %d fvRsPathAtt rows referencing nodes outside fabricNode", skipped_paths
        )
    for mo in raw.get("fvRsDomAtt", []):
        a = _attrs(mo)
        tdn = a.get("tDn")
        if not tdn:
            continue
        if not tdn.startswith("uni/vmmp-"):
            continue  # physical domains are not VMM bindings
        pg = aci_node("DvPortgroup", tdn, name=tdn.rsplit("dom-", 1)[-1])
        b.rel("VMM_BINDING", "Epg", uid.aci(fabric, _parent_dn(a["dn"])), "DvPortgroup", pg)


# The L3Out OSPF operational classes.
#
# FIRST CONTACT: no capture of a live APIC confirms the dn shapes and attribute names below.
#
#   ospfDom:   topology/pod-1/node-101/sys/ospf/inst-default/dom-<tenant>:<vrf>
#   ospfArea:  .../dom-<tenant>:<vrf>/area-<area-id>
#   ospfIf:    .../area-<area-id>/if-[<ifId>]
#   ospfAdjEp: .../if-[<ifId>]/adj-<neighbor-router-id>

# ACI area-type words, mapped onto the schema's own vocabulary.
_ACI_AREA_TYPES = {
    "regular": "normal",
    "normal": "normal",
    "backbone": "normal",
    "stub": "stub",
    "nssa": "nssa",
}

_ACI_NETWORK_TYPES = {
    "p2p": "point-to-point",
    "bcast": "broadcast",
    "nbma": "nbma",
    "p2mp": "point-to-multipoint",
    "unspecified": None,
}


def _ospf_int(value: Any) -> int | None:
    if isinstance(value, bool) or value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _ospf_ctx_dn(dom_name: str) -> str | None:
    if ":" not in dom_name:
        return None
    tenant, vrf_name = dom_name.split(":", 1)
    return f"uni/tn-{tenant}/ctx-{vrf_name}"


def _ospf_stage(b: GraphBuilder, raw: dict[str, Any], fabric: str, resolver: DeviceResolver) -> None:
    """Write RoutingProcess (proto=ospf), OspfArea, IN_AREA and OspfAdjacency from
    ospfDom, ospfArea, ospfIf and ospfAdjEp."""
    dev_by_node_dn = {
        _attrs(mo)["dn"]: _device_uid(_attrs(mo), resolver, fabric) for mo in raw.get("fabricNode", [])
    }

    proc_uids: dict[str, str] = {}  # RoutingProcess uid by ospfDom dn
    for mo in raw.get("ospfDom", []):
        a = _attrs(mo)
        duid = dev_by_node_dn.get(_node_dn(a["dn"]))
        if duid is None:
            continue
        dom_name = a["dn"].rsplit("/dom-", 1)[-1]
        rpu = uid.routing_process(duid, dom_name, "ospf")
        b.node("RoutingProcess", rpu, proto="ospf", router_id=a.get("rtrId"))
        proc_uids[a["dn"]] = rpu
        ctx_dn = _ospf_ctx_dn(dom_name)
        if ctx_dn:
            b.rel("IN_VRF", "RoutingProcess", rpu, "VrfInstance", uid.aci(fabric, ctx_dn))

    area_uids: dict[str, str] = {}  # OspfArea uid by ospfArea dn
    area_rpu: dict[str, str] = {}  # owning RoutingProcess uid by ospfArea dn
    area_id_by_dn: dict[str, str] = {}  # area id by ospfArea dn
    for mo in raw.get("ospfArea", []):
        a = _attrs(mo)
        dom_dn = a["dn"].rsplit("/area-", 1)[0]
        rpu = proc_uids.get(dom_dn)
        if rpu is None:
            logger.warning("apic: ospfArea %s names no ospfDom this fabric returned; skipped", a["dn"])
            continue
        area_id = a.get("id") or a["dn"].rsplit("/area-", 1)[-1]
        raw_type = str(a.get("areaType") or "").strip().lower()
        au = uid.ospf_area(rpu, area_id)
        b.node("OspfArea", au, area_id=area_id, type=_ACI_AREA_TYPES.get(raw_type, raw_type or None))
        b.rel("HAS", "RoutingProcess", rpu, "OspfArea", au)
        area_uids[a["dn"]] = au
        area_rpu[a["dn"]] = rpu
        area_id_by_dn[a["dn"]] = area_id

    iface_uids: dict[str, str] = {}  # Interface uid by ospfIf dn
    if_rpu: dict[str, str] = {}  # owning RoutingProcess uid by ospfIf dn
    if_area_id: dict[str, str] = {}  # area id by ospfIf dn
    if_id: dict[str, str] = {}  # bare interface id by ospfIf dn
    for mo in raw.get("ospfIf", []):
        a = _attrs(mo)
        if "/if-[" not in a["dn"]:
            continue
        area_dn = a["dn"].rsplit("/if-[", 1)[0]
        au = area_uids.get(area_dn)
        rpu = area_rpu.get(area_dn)
        duid = dev_by_node_dn.get(_node_dn(a["dn"]))
        ifid = a["dn"].split("/if-[")[1].split("]")[0]
        if au is None or rpu is None or duid is None:
            continue
        iu = b.node("Interface", uid.interface(duid, ifid), name=ifid)
        b.rel("ON", "Interface", iu, "Device", duid)
        iface_uids[a["dn"]] = iu
        if_rpu[a["dn"]] = rpu
        if_area_id[a["dn"]] = area_id_by_dn.get(area_dn, "")
        if_id[a["dn"]] = ifid
        ctrl = str(a.get("ctrl") or "")
        raw_type = str(a.get("nwT") or "").strip().lower()
        b.rel(
            "IN_AREA",
            "Interface",
            iu,
            "OspfArea",
            au,
            cost=_ospf_int(a.get("cost")),
            network_type=_ACI_NETWORK_TYPES.get(raw_type, raw_type or None),
            passive="passive" in ctrl.split(","),
        )

    for mo in raw.get("ospfAdjEp", []):
        a = _attrs(mo)
        if_dn = a["dn"].rsplit("/adj-", 1)[0]
        iu = iface_uids.get(if_dn)
        rpu = if_rpu.get(if_dn)
        rid = a.get("rtrId")
        if iu is None or rpu is None or not rid:
            continue
        state = a.get("state")
        adju = uid.ospf_adjacency(rpu, iu, str(rid))
        b.node(
            "OspfAdjacency",
            adju,
            state=str(state).upper() if state else None,
            area=if_area_id.get(if_dn),
            neighbor_router_id=str(rid),
            neighbor_ip=a.get("addr"),
            local_interface=if_id.get(if_dn),
        )
        b.rel("HAS", "RoutingProcess", rpu, "OspfAdjacency", adju)
        b.rel("ENDPOINT", "OspfAdjacency", adju, "Interface", iu)


# BGP session observations from the L3Out node operational classes.
#
# FIRST CONTACT: no capture of a live APIC confirms the dn nesting
#   topology/pod-<p>/node-<n>/sys/bgp/inst/dom-<tenant>:<ctx>/peer-[<peerIp>]
# for `bgpPeerEntry`, with `/af-[<afi>-<safi>]` appended for the child
# `bgpPeerAfEntry`, or the attribute names (`operSt` for state).
#
#     curl -sk -b APIC-cookie=<token> \
#       'https://<apic>/api/class/bgpPeerEntry.json?page-size=1000&page=0'
#     curl -sk -b APIC-cookie=<token> \
#       'https://<apic>/api/class/bgpPeerAfEntry.json?page-size=1000&page=0'

BGP_CLASSES: tuple[str, ...] = ("bgpPeerEntry", "bgpPeerAfEntry")

_BGP_AF_SAFI: dict[str, tuple[int, str]] = {
    "ipv4-ucast": (4, "unicast"),
    "ipv6-ucast": (6, "unicast"),
}

_CAPTURE_REASONS: dict[str, str] = {"none": "the source's capture_bgp setting is none"}

_ROUTES_NOT_EXPOSED = (
    "the APIC class model exposes no per-peer, per-prefix BGP path table: "
    "bgpPeerAfEntry carries per-address-family counters only, and no fetched "
    "class states which prefixes crossed a session"
)


def _device_by_node_id(raw: dict[str, Any], resolver: DeviceResolver, fabric: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for mo in raw.get("fabricNode", []):
        a = _attrs(mo)
        if a.get("serial"):
            out[a["dn"].rsplit("/node-", 1)[1]] = _device_uid(a, resolver, fabric)
    return out


def _bgp_peer_dn_parts(dn: str) -> tuple[str, str, str] | None:
    """Return (node-id, dom-segment value, peer ip) from a `bgpPeerEntry` dn of the form
    `topology/pod-<p>/node-<n>/sys/bgp/inst/dom-<tenant>:<ctx>/peer-[<ip>]`.
    Return None for a dn without the `/node-`, `/dom-` or `/peer-[` segment."""
    if "/node-" not in dn or "/dom-" not in dn or "/peer-[" not in dn:
        return None
    node_id = dn.split("/node-", 1)[1].split("/", 1)[0]
    dom_value = dn.split("/dom-", 1)[1].split("/peer-[", 1)[0]
    peer_ip = dn.split("/peer-[", 1)[1].split("]", 1)[0]
    return node_id, dom_value, peer_ip


def _bgp_af_from_dn(dn: str) -> tuple[int, str] | None:
    """Return (af, safi) from the `af-[<afi>-<safi>]` segment of a `bgpPeerAfEntry` dn,
    or None for a token that `_BGP_AF_SAFI` does not hold."""
    if "/af-[" not in dn:
        return None
    token = dn.split("/af-[", 1)[1].split("]", 1)[0]
    return _BGP_AF_SAFI.get(token)


def _bgp_peer_dn(af_dn: str) -> str:
    return af_dn.rsplit("/af-[", 1)[0]


def _bgp_vrf_key(dom_value: str) -> tuple[str, str]:
    tenant, sep, ctx = dom_value.partition(":")
    return (tenant, ctx) if sep else ("common", tenant)


def _bgp_context_uid(fabric: str, tenant: str, ctx: str) -> str:
    return uid.aci(fabric, f"uni/tn-{tenant}/ctx-{ctx}")


def _bgp_session_uid(session: dict[str, Any]) -> str:
    ru = uid.routing_process(session["device_uid"], session["vrf_name"], "bgp")
    return uid.bgp_session(ru, session["peer_ip"], session["vrf_name"])


def bgp_observed_sessions(
    raw: dict[str, Any], fabric: str, resolver: DeviceResolver | None = None
) -> list[dict[str, Any]]:
    """Join `bgpPeerEntry` (per-peer operational state) with `bgpPeerAfEntry`
    (per-address-family state) into one observed session record per peer and address
    family.
    """
    dev_by_node = _device_by_node_id(raw, resolver or MemoryResolver(), fabric)
    peers: dict[str, dict[str, Any]] = {}
    for mo in raw.get("bgpPeerEntry", []):
        a = _attrs(mo)
        dn = a.get("dn") or ""
        parts = _bgp_peer_dn_parts(dn)
        if parts is None:
            continue
        node_id, dom_value, peer_ip = parts
        device_uid = dev_by_node.get(node_id)
        if device_uid is None:
            continue
        tenant, ctx = _bgp_vrf_key(dom_value)
        peers[dn] = {
            "device_uid": device_uid,
            "vrf_name": dom_value,
            "context_uid": _bgp_context_uid(fabric, tenant, ctx),
            "peer_ip": peer_ip,
            "state": a.get("operSt"),
        }
    out: list[dict[str, Any]] = []
    for mo in raw.get("bgpPeerAfEntry", []):
        a = _attrs(mo)
        dn = a.get("dn") or ""
        peer = peers.get(_bgp_peer_dn(dn))
        if peer is None:
            continue
        af_safi = _bgp_af_from_dn(dn)
        if af_safi is None:
            continue
        out.append({**peer, "state": a.get("operSt") or peer["state"], "af": af_safi[0], "safi": af_safi[1]})
    return out


def bgp_side_rows(
    raw: dict[str, Any], fabric: str, resolver: DeviceResolver | None = None
) -> dict[str, list[dict]]:
    sessions = []
    for s in bgp_observed_sessions(raw, fabric, resolver):
        sessions.append(
            {
                "device_uid": s["device_uid"],
                "context_uid": s["context_uid"],
                "session_uid": _bgp_session_uid(s),
                "peer_ip": s["peer_ip"],
                "af": s["af"],
                "safi": s["safi"],
                "state": s["state"],
                # Neither class states an absolute or relative uptime, a
                # prefix count, or a capability list.
                "established_since_ms": None,
                "prefixes_received": None,
                "prefixes_advertised": None,
                "capabilities": None,
            }
        )
    return {"bgp_sessions": sessions, "bgp_session_routes": []}


def bgp_table_outcomes(
    raw: dict[str, Any], fabric: str, *, capture: str, resolver: DeviceResolver | None = None
) -> dict[str, TableOutcome]:
    """The outcomes of the BGP tables and of the 3 directions of each observed session."""
    outcomes: dict[str, TableOutcome] = {}
    if capture == "none":
        detail = _CAPTURE_REASONS["none"]
        outcomes[BGP_SESSIONS_TABLE] = TableOutcome(status="not-captured", detail=detail)
        outcomes[BGP_ROUTES_TABLE] = TableOutcome(status="not-captured", detail=detail)
        return outcomes
    recorded = recorded_outcomes(raw)
    broken = next((recorded[c] for c in BGP_CLASSES if c in recorded and recorded[c].status != "ok"), None)
    if broken is not None:
        outcomes[BGP_SESSIONS_TABLE] = TableOutcome(status="failed", detail=broken.detail)
    outcomes[BGP_ROUTES_TABLE] = TableOutcome(status="not-captured", detail=_ROUTES_NOT_EXPOSED)
    for s in bgp_observed_sessions(raw, fabric, resolver):
        session_uid = _bgp_session_uid(s)
        for direction in ("received", "accepted", "advertised"):
            outcomes[bgp_direction_key(session_uid, direction)] = TableOutcome(
                status="not-captured", detail=_ROUTES_NOT_EXPOSED
            )
    return outcomes
