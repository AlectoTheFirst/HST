"""The NetScaler (Citrix ADC) collector writes VirtualService, Pool, PoolMember and
Monitor nodes and SNAT_FROM edges.

First contact, with a reachable NITRO management endpoint:
    curl -sk -H "X-NITRO-USER: <user>" -H "X-NITRO-PASS: <pass>" \\
        "https://<nsip>/nitro/v1/config/lbvserver"
    curl -sk -H "X-NITRO-USER: <user>" -H "X-NITRO-PASS: <pass>" \\
        "https://<nsip>/nitro/v1/config/servicegroup"
    # save under data/raw/netscaler/first-contact/ and rerun normalize_netscaler
    # on the captures.

First-contact checklist:
- Auth is header auth (`X-NITRO-USER`/`X-NITRO-PASS` on each request).
- The collector does not read the Net Profile join of `lbvserver_netprofile_binding`
  and `netprofile_netprofile_srcip_binding`.
- `gslbvserver` and `csvserver` (VirtualService.kind gslb/cs) are not fetched.
- A vserver that binds `service` objects directly gives no Pool.
"""

from __future__ import annotations

import ipaddress
from typing import Any, ClassVar, Literal

import httpx

from hst.core import uid
from hst.core.model import Batch, SectionOutcome
from hst.core.mtu import MTU_NORMALIZATION_VERSION
from hst.core.mtu_profiles import emit_observation, observation_from_raw

from . import http
from .auth import TlsConfig, UserPassword
from .base import RAW_OUTCOMES_KEY, Collector, SourceConfig, register
from .util import GraphBuilder

_PROTO_BY_SERVICETYPE = {
    "UDP": "udp",
    "DNS": "udp",
    "RTSP": "tcp",
}


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _truthy(value: Any) -> bool:
    return str(value).strip().lower() in ("true", "yes", "1", "on")


def _af(addr: str) -> int | None:
    try:
        return ipaddress.ip_address(addr).version
    except ValueError:
        return None


def _proto_of(servicetype: Any) -> str:
    return _PROTO_BY_SERVICETYPE.get(str(servicetype or "").strip().upper(), "tcp")


def _member_state(svrstate: Any) -> str:
    return "up" if str(svrstate or "").strip().upper() == "UP" else "down"


class NetScalerConfig(SourceConfig):
    host: str  # NSIP management address, e.g. https://192.0.2.10
    auth: UserPassword
    tls: TlsConfig = TlsConfig()
    # The uid.netscaler() namespace, such as "dc1-ns01", is shared by the 2 NSIPs of an HA pair.
    scope_name: str
    # The Device or RedundancyGroup that the VirtualServices are ON.
    on_uid: str
    on_label: Literal["Device", "RedundancyGroup"] = "RedundancyGroup"
    # The anchor/l3dom of each IpAddress is a source-scoped domain string.
    l3dom: str = ""
    capture_mtu: bool = False
    mtu_device_uid: str = ""  # The Device uid of the appliance, for an `on_uid` that is an HA group.


@register
class NetScalerCollector(Collector):
    name = "netscaler"
    ConfigModel = NetScalerConfig
    KIND = "group"
    PARSER_VERSION = "2"
    NORMALIZATION_VERSIONS: ClassVar[dict[str, str]] = {
        "mtu": MTU_NORMALIZATION_VERSION,
        "iface_uid": uid.IFACE_UID_VERSION,
    }
    NORMALIZATION_OUTCOME_KEYS = ("mtu:Interface",)
    NORMALIZATION_CONFIG_KEYS = ("mtu_device_uid", "on_uid", "on_label")

    def __init__(self, config: NetScalerConfig, settings):
        super().__init__(config, settings)
        self.scope = f"netscaler:{config.scope_name}"

    def _client(self):
        c = self.config
        client = http.client(c.host, c.tls, timeout=30)
        client.headers["X-NITRO-USER"] = c.auth.username
        client.headers["X-NITRO-PASS"] = c.auth.password.get_secret_value()
        return client

    def _get(self, client, resource: str) -> list[dict[str, Any]]:
        resp = client.get(f"/nitro/v1/config/{resource}")
        resp.raise_for_status()
        return resp.json().get(resource, [])

    def probe(self) -> str:
        client = self._client()
        try:
            rows = self._get(client, "lbvserver")
            return f"NITRO ok: {len(rows)} lbvserver(s) on {self.config.host}"
        finally:
            client.close()

    def fetch(self) -> dict[str, Any]:
        client = self._client()
        try:
            raw = {
                "lbvserver": self._get(client, "lbvserver"),
                "lbvserver_servicegroup_binding": self._get(client, "lbvserver_servicegroup_binding"),
                "servicegroup": self._get(client, "servicegroup"),
                "servicegroup_servicegroupmember_binding": self._get(
                    client, "servicegroup_servicegroupmember_binding"
                ),
                "servicegroup_lbmonitor_binding": self._get(client, "servicegroup_lbmonitor_binding"),
                "lbmonitor": self._get(client, "lbmonitor"),
            }
            if self.config.capture_mtu:
                self._fetch_mtu_interfaces(client, raw)
            return raw
        finally:
            client.close()

    def _fetch_mtu_interfaces(self, client: httpx.Client, raw: dict[str, Any]) -> None:
        try:
            response = client.get("/nitro/v1/config/Interface")
            response.raise_for_status()
            body = response.json()
            if body.get("errorcode", 0) != 0:
                raise RuntimeError(f"NITRO interface read failed: {body.get('message', 'unknown error')}")
            rows = body.get("Interface")
            if not isinstance(rows, list) or any(not isinstance(r, dict) or not r.get("id") for r in rows):
                raise ValueError("NITRO Interface response lacks an explicit interface list/identity")
            if len(rows) > 4096:
                raise RuntimeError("NITRO Interface response exceeds 4096-record budget")
            raw["Interface"] = rows
            outcome = {"status": "ok" if rows else "empty", "row_count": len(rows)}
        except (httpx.HTTPError, RuntimeError, ValueError, AttributeError) as exc:
            status = "failed"
            if isinstance(exc, httpx.HTTPStatusError):
                if exc.response.status_code in (401, 403):
                    status = "unauthorized"
                elif exc.response.status_code == 404:
                    status = "unsupported"
            elif isinstance(exc, (ValueError, AttributeError)):
                status = "malformed"
            raw["Interface"] = []
            outcome = {"status": status, "detail": f"{type(exc).__name__}: {exc}"}
        raw.setdefault(RAW_OUTCOMES_KEY, {})["mtu:Interface"] = outcome

    def normalize(self, raw: dict[str, Any]) -> Batch:
        batch = normalize_netscaler(
            raw,
            scope_name=self.config.scope_name,
            on_uid=self.config.on_uid,
            on_label=self.config.on_label,
            l3dom=self.config.l3dom or self.config.effective_routing_scope,
        )
        owner = self.config.mtu_device_uid or (self.config.on_uid if self.config.on_label == "Device" else "")
        _netscaler_mtu(batch, raw, device_uid=owner, target=self.config.host)
        return batch


def normalize_netscaler(
    raw: dict[str, Any],
    *,
    scope_name: str,
    on_uid: str,
    on_label: str = "RedundancyGroup",
    l3dom: str = "",
) -> Batch:
    """The IpAddress nodes of 2 sources merge only when both have the same `l3dom`."""
    b = GraphBuilder()
    anchor = l3dom or scope_name

    def ip_node(addr: str, **props: Any) -> str:
        return b.node(
            "IpAddress",
            uid.ip(anchor, addr),
            ip=addr,
            l3dom=l3dom or None,
            anchor=anchor,
            af=_af(addr),
            **props,
        )

    # Each servicegroup binding of an lbvserver gives a Pool.
    vs_to_sg: dict[str, list[str]] = {}
    for row in raw.get("lbvserver_servicegroup_binding", []):
        name, sg = row.get("name"), row.get("servicegroupname")
        if name and sg and sg not in vs_to_sg.setdefault(name, []):
            vs_to_sg[name].append(sg)
    sg_members: dict[str, list[dict[str, Any]]] = {}
    for row in raw.get("servicegroup_servicegroupmember_binding", []):
        sg = row.get("servicegroupname")
        if sg and row.get("ip"):
            sg_members.setdefault(sg, []).append(row)
    monitor_rows = {row["monitorname"]: row for row in raw.get("lbmonitor", []) if row.get("monitorname")}
    # The collector reads the Monitor binding per servicegroup (Pool).
    sg_monitor_uid: dict[str, str] = {}
    for row in raw.get("servicegroup_lbmonitor_binding", []):
        sg = row.get("servicegroupname")
        mon_name = row.get("monitor_name")
        if not sg or not mon_name:
            continue
        mon_row = monitor_rows.get(mon_name, {})
        mu = b.node(
            "Monitor",
            uid.netscaler(scope_name, "mon", mon_name),
            kind=(mon_row.get("type") or "").lower() or None,
            target=mon_name,
        )
        sg_monitor_uid[sg] = mu

    for vs in raw.get("lbvserver", []):
        name = vs.get("name")
        if not name:
            continue
        vip = vs.get("ipv46")
        usip = _truthy(vs.get("usip"))
        snat_ip = vs.get("snat_ip")
        if usip:
            snat_mode = "none"
        elif snat_ip:
            snat_mode = "snat_from"
        else:
            snat_mode = "automap"
        vsu = b.node(
            "VirtualService",
            uid.netscaler(scope_name, "lbvs", name),
            name=name,
            vip=vip,
            port=_int_or_none(vs.get("port")),
            proto=_proto_of(vs.get("servicetype")),
            kind="lb",
            snat_mode=snat_mode,
        )
        b.rel("ON", "VirtualService", vsu, on_label, on_uid)
        if vip:
            vipu = ip_node(vip)
            b.rel("VIP", "VirtualService", vsu, "IpAddress", vipu)
        if snat_mode == "snat_from" and snat_ip:
            snu = ip_node(snat_ip, ns_role="snip")
            b.rel("SNAT_FROM", "VirtualService", vsu, "IpAddress", snu)

        for sg_name in vs_to_sg.get(name, []):
            pu = b.node(
                "Pool",
                uid.netscaler(scope_name, "sg", sg_name),
                name=sg_name,
                lb_method=(vs.get("lbmethod") or "").lower() or None,
            )
            b.rel("USES", "VirtualService", vsu, "Pool", pu)
            mon_uid = sg_monitor_uid.get(sg_name)
            if mon_uid:
                b.rel("CHECKED_BY", "Pool", pu, "Monitor", mon_uid)
            for member in sg_members.get(sg_name, []):
                m_ip = member["ip"]
                m_port = _int_or_none(member.get("port"))
                pmu = b.node(
                    "PoolMember",
                    f"{pu}/{m_ip}:{m_port}",
                    port=m_port,
                    weight=_int_or_none(member.get("weight")),
                    # `gates.lb._member_regions` reads None as health not collected.
                    state=(_member_state(member.get("svrstate")) if mon_uid else None),
                )
                b.rel("HAS_MEMBER", "Pool", pu, "PoolMember", pmu)
                b.rel("TARGETS", "PoolMember", pmu, "IpAddress", ip_node(m_ip))

    return b.batch(source="netscaler", scope=f"netscaler:{scope_name}")


def _netscaler_mtu(batch: Batch, raw: dict[str, Any], *, device_uid: str, target: str) -> None:
    outcome = raw.get(RAW_OUTCOMES_KEY, {}).get("mtu:Interface")
    if outcome:
        batch.sections["mtu"] = SectionOutcome.model_validate(outcome)
        if outcome.get("status") not in {"ok", "empty", "partial"}:
            return
    rows = raw.get("Interface", [])
    if not rows:
        batch.sections.setdefault(
            "mtu",
            SectionOutcome(
                status="unknown",
                detail="NITRO Interface MTU not captured; enable capture_mtu with explicit device identity",
            ),
        )
        return
    if not device_uid:
        batch.sections["mtu"] = SectionOutcome(
            status="partial",
            detail="Interface source captured but appliance Device UID is unresolved; set mtu_device_uid",
        )
        return
    b = GraphBuilder()
    for record in rows:
        if not isinstance(record, dict) or not record.get("id"):
            continue
        iu = b.node(
            "Interface",
            uid.interface(device_uid, record["id"]),
            name=record["id"],
            mtu_source="NITRO Interface",
            operational_mtu_basis="unknown",
        )
        b.rel("ON", "Interface", iu, "Device", device_uid)
        for field, authority in (("mtu", "configured"), ("actualmtu", "operational")):
            if field not in record:
                continue
            # The documented mtu excludes the 14-byte Ethernet header and 4-byte CRC of an untagged frame.
            configured = field == "mtu"
            obs = observation_from_raw(
                subject_uid=iu,
                source="netscaler",
                source_target=target,
                source_field=f"Interface.{field}",
                raw_value=record[field],
                profile_id="ethernet_payload" if configured else "unknown",
                metric="l2_max_frame_bytes" if configured else "unknown",
                direction="both",
                bound_kind="ceiling" if configured else "unknown",
                enforcement="l2",
                assertion_kind=authority,
                tag_depth=0 if configured else None,
                tag_accounting="included" if configured else "unknown",
                tag_allowance_bytes=0 if configured else None,
                collector_version="2",
                raw_evidence_ref=f"Interface:{record['id']}:{field}",
            )
            emit_observation(b, "Interface", obs)
    extra = b.batch(batch.source, batch.scope)
    batch.nodes.extend(extra.nodes)
    batch.rels.extend(extra.rels)
    batch.sections["mtu"] = SectionOutcome(
        status="partial",
        row_count=len(rows),
        detail="configured untagged frame limits; actualmtu size basis and tagged allowances unverified",
    )
