#!/usr/bin/env python3
"""Generate the synthetic Norlund estate as three complete HST fixtures.

    python3 tools/gen_demo_enterprise.py

Writes fixtures/demo-enterprise/estate-v{1,2,3}.yaml and fixtures/demo-enterprise/apps/*.yaml.
Run it with the project's environment: the Oslo office's router is normalized by this tree's
VyOS collector (src/hst/collectors/vyos.py), which the script imports from src/.

Every label, property name and relationship type comes from fixtures/mini-dc.yaml,
fixtures/mini-enterprise.yaml and fixtures/equinix-site.yaml in the HST repository, except the
Oslo office's router, whose nodes and relationships are the VyOS collector's own batch for a
synthetic payload (`vyos_payload`).
The output is YAML written as one JSON flow mapping per line, which PyYAML reads as is.
Addressing is RFC 1918 and documentation space only; every name is invented.

Routing model (what the hst path engine reads, so a trace runs end to end):
  - every forwarding device has a VrfInstance; its interfaces carry IN_VRF, HAS_IP on a connected Prefix the
    table ORIGINATES, and GATEWAY_FOR on the gateway interface (the reasoner derives that edge only for
    router-role devices, so leaf SVIs and the NetScaler VIP side carry it explicitly)
  - routes are (VrfInstance)-[STATIC_ROUTE|LEARNED_ROUTE {next_hop, interface, protocol}]->(Prefix) with
    (Prefix)-[VIA {vrf}]->(Interface); a next hop must sit on a connected or host prefix of the same table
  - office: core SVIs -> FortiGate (zone pairs corp->wan, wan->corp, guest->wan) -> SD-WAN edge -> one
    overlay /30 per data-center hub (the VCMP tunnels drawn as point-to-point tunnel interfaces)
  - data center: hub and border on L3Out /30s of leaf-07/08; the ACI VRF CTX1 is the leaf table; the
    PBR redirect is a PbrPolicy rule on the L3Out and bridge-domain SVIs whose REDIRECTS_VIA table has one
    route to the Check Point cluster address; the NetScaler owns the VIP /24 behind a transit /29
  - VM endpoints ATTACHED to leaf ports, IN_EPG, IN their segment, so delivery and ACI contracts resolve

  - Oslo office (osl01, every version): one dual-stack VyOS router with zones LAN, IOT, GUEST,
    WAN and LOCAL, an IPv4 and an IPv6 rule set per zone pair, source and destination NAT,
    nat66, policy route and policy route6 into a WireGuard table; six dual-stack endpoints

Versions:
  v1  the estate in mid 2026
  v2  v1 plus the Lisbon office (lis01), the Claims Portal API tier and its firewall rules
  v3  v2 minus the Milan office (mil01) and the retired Intranet port-80 VIP, plus Azure West Europe
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
OUT = ROOT / "fixtures" / "demo-enterprise"
ORG = "norlund"
DOMAIN = "norlund.example"
CORP_SUPER = "10.0.0.0/8"
GUEST_SUPER = "172.31.0.0/16"


def slug(text: str) -> str:
    return text.lower().replace(":", "-").replace("/", "-")


class Graph:
    """Nodes keyed by uid, relationships deduplicated, endpoints checked at insert."""

    def __init__(self, version: int) -> None:
        self.version = version
        self.nodes: dict[str, tuple[str, dict]] = {}
        self.order: list[tuple[str, str]] = []
        self.rels: list[tuple] = []
        self.relkeys: set[tuple] = set()
        self.section = "misc"
        self.rng = random.Random(20260614)  # noqa: S311 - seeded, for reproducible fixture data only

    def sec(self, name: str) -> None:
        self.section = name

    def node(self, label: str, uid: str, **props) -> str:
        props = {k: v for k, v in props.items() if v is not None}
        if uid in self.nodes:
            label0, props0 = self.nodes[uid]
            if label0 != label:
                raise ValueError(f"label conflict for {uid}: {label0} vs {label}")
            for k, v in props.items():
                if props0.get(k, v) != v:
                    raise ValueError(f"property conflict for {uid}.{k}: {props0.get(k)!r} vs {v!r}")
            props0.update(props)
        else:
            self.nodes[uid] = (label, props)
            self.order.append((self.section, uid))
        return uid

    def rel(
        self, rtype: str, start: str, end: str, props: dict | None = None, key: dict | None = None
    ) -> None:
        if start not in self.nodes:
            raise KeyError(f"dangling start {start} ({rtype} -> {end})")
        if end not in self.nodes:
            raise KeyError(f"dangling end {end} ({rtype} from {start})")
        k = (rtype, start, end, json.dumps(key or {}, sort_keys=True))
        if k in self.relkeys:
            return
        self.relkeys.add(k)
        self.rels.append((self.section, rtype, start, end, props, key))

    # --- domain helpers -------------------------------------------------------------
    @staticmethod
    def digits(key: str, n: int) -> str:
        """n decimal digits derived from key: the same object gets the same serial in every version."""
        return str(int(hashlib.sha1(key.encode(), usedforsecurity=False).hexdigest(), 16))[-n:].rjust(n, "7")

    @staticmethod
    def serial(prefix: str, key: str) -> str:
        return f"{prefix}{Graph.digits(key, 8)}"

    @staticmethod
    def mac(key: str, oui: str = "00:50:56") -> str:
        h = hashlib.sha1(("mac:" + key).encode(), usedforsecurity=False).hexdigest()[:6]
        return oui + ":" + ":".join(h[i : i + 2] for i in (0, 2, 4))

    def device(
        self,
        site: str,
        hostname: str,
        platform: str,
        role: str,
        vendor: str,
        serial: str,
        mgmt_ip: str,
        **extra,
    ) -> str:
        uid = f"dev:{hostname}"
        if serial.isalpha():
            serial = self.serial(serial, hostname)
        self.node(
            "Device",
            uid,
            hostname=hostname,
            hostname_fqdn=f"{hostname}.{DOMAIN}",
            platform=platform,
            role=role,
            vendor=vendor,
            serial=serial,
            mgmt_ip=mgmt_ip,
            **extra,
        )
        self.rel("LOCATED_IN", uid, site)
        return uid

    def port(self, dev: str, short: str, name: str, speed_mbps: int | None = None) -> str:
        uid = f"{dev}/port/{short}"
        self.node("Port", uid, name=name, speed_mbps=speed_mbps)
        self.rel("ON", uid, dev)
        return uid

    def iface(self, dev: str, short: str, name: str, kind: str, port: str | None = None, **props) -> str:
        uid = f"{dev}/if/{short}"
        self.node("Interface", uid, name=name, kind=kind, **props)
        self.rel("ON", uid, dev)
        if port:
            self.rel("REALIZED_BY", uid, port)
        return uid

    def cable(self, a: str, b: str, **props) -> None:
        self.rel("CONNECTED_TO", a, b, props={"source": "fixture", **props})

    def prefix(
        self,
        l3dom: str,
        cidr: str,
        kind: str,
        name: str | None = None,
        anchor: str | None = None,
        parent: str | None = None,
    ) -> str:
        anchor = anchor or l3dom
        uid = f"pfx:{slug(anchor)}:{cidr}"
        self.node("Prefix", uid, cidr=cidr, af=4, kind=kind, l3dom=l3dom, name=name, anchor=anchor)
        if parent:
            self.rel("WITHIN", uid, parent)
        return uid

    def ip(
        self,
        l3dom: str,
        addr: str,
        prefix: str | None = None,
        anchor: str | None = None,
        name: str | None = None,
    ) -> str:
        anchor = anchor or l3dom
        uid = f"ip:{slug(anchor)}:{addr}"
        self.node("IpAddress", uid, ip=addr, af=4, l3dom=l3dom, anchor=anchor, name=name)
        if prefix:
            self.rel("IN", uid, prefix)
        return uid

    def vrf(self, uid: str, name: str, rdom: str | None = None, **props) -> str:
        self.node("VrfInstance", uid, name=name, **props)
        if rdom:
            self.rel("MEMBER_OF", uid, rdom, props={"basis": "declared"})
        return uid

    def route(
        self,
        vrf: str,
        pfx: str,
        kind: str = "STATIC_ROUTE",
        next_hop: str | None = None,
        iface: str | None = None,
        protocol: str | None = None,
    ) -> None:
        """One routing-table row the path engine reads: (VrfInstance)-[kind {next_hop, interface,
        protocol}]->(Prefix), plus (Prefix)-[VIA {vrf}]->(Interface) when the row names its egress.
        The edge key separates equal-cost rows to one prefix (the vyos collector's `via` key)."""
        props: dict = {}
        if next_hop:
            props["next_hop"] = next_hop
        if protocol:
            props["protocol"] = protocol
        if iface:
            props["interface"] = self.nodes[iface][1]["name"]
        self.rel(
            kind, vrf, pfx, props=props or None, key={"via": f"{next_hop or ''}|{props.get('interface', '')}"}
        )
        if iface:
            self.rel("VIA", pfx, iface, props={"vrf": vrf}, key={"vrf": vrf})

    def connected(
        self,
        vrf: str,
        iface: str,
        addr: str,
        pfx: str,
        l3dom: str = "corp",
        anchor: str | None = None,
        gateway: bool = True,
    ) -> str:
        """An interface address on a connected prefix: HAS_IP, IN_VRF, ORIGINATES and, unless told
        otherwise, GATEWAY_FOR (the reasoner derives that edge only for router-role devices)."""
        ipu = self.ip(l3dom, addr, pfx, anchor=anchor or vrf)
        self.rel("HAS_IP", iface, ipu)
        self.rel("IN_VRF", iface, vrf)
        self.rel("ORIGINATES", vrf, pfx, props={"proto": "connected"})
        if gateway:
            self.rel("GATEWAY_FOR", iface, pfx)
        return ipu

    # --- output ---------------------------------------------------------------------
    def write(self, path: Path, header: str) -> None:
        lines = [f"# {line}" if line else "#" for line in header.strip().splitlines()]
        lines += ["source: fixture", 'scope: "fixture:estate"', "", "nodes:"]
        last = None
        for section, uid in self.order:
            if section != last:
                lines.append(f"  # --- {section}")
                last = section
            label, props = self.nodes[uid]
            lines.append(
                "  - " + json.dumps({"label": label, "uid": uid, "props": props}, ensure_ascii=False)
            )
        lines += ["", "rels:"]
        last = None
        for section, rtype, start, end, props, key in self.rels:
            if section != last:
                lines.append(f"  # --- {section}")
                last = section
            row = {"type": rtype, "start": [self.nodes[start][0], start], "end": [self.nodes[end][0], end]}
            if key:
                row["key"] = key
            if props:
                row["props"] = props
            lines.append("  - " + json.dumps(row, ensure_ascii=False))
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# --- estate description -------------------------------------------------------------
DCS = [
    {"code": "dc1", "city": "Frankfurt", "n": 1, "fabric": "fab-dc1", "zdc": "FRA4", "pop": "FRA"},
    {"code": "dc2", "city": "Munich", "n": 2, "fabric": "fab-dc2", "zdc": "MUC1", "pop": "MUC"},
]
OFFICES = [
    {
        "code": "vie01",
        "city": "Vienna",
        "n": 11,
        "cores": "nxos",
        "zdc": "VIE1",
        "dia": "fibrenta",
        "pop": "FRA",
        "since": 1,
        "until": 99,
    },
    {
        "code": "mil01",
        "city": "Milan",
        "n": 12,
        "cores": "nxos",
        "zdc": "MIL1",
        "dia": "lumetra",
        "pop": "MUC",
        "since": 1,
        "until": 2,
    },
    {
        "code": "waw01",
        "city": "Warsaw",
        "n": 13,
        "cores": "iosxe",
        "zdc": "WAW1",
        "dia": "fibrenta",
        "pop": "FRA",
        "since": 1,
        "until": 99,
    },
    {
        "code": "par01",
        "city": "Paris",
        "n": 14,
        "cores": "nxos",
        "zdc": "PAR2",
        "dia": "lumetra",
        "pop": "FRA",
        "since": 1,
        "until": 99,
    },
    {
        "code": "mad01",
        "city": "Madrid",
        "n": 15,
        "cores": "iosxe",
        "zdc": "MAD1",
        "dia": "fibrenta",
        "pop": "MUC",
        "since": 1,
        "until": 99,
    },
    {
        "code": "zrh01",
        "city": "Zurich",
        "n": 16,
        "cores": "nxos",
        "zdc": "ZRH1",
        "dia": "lumetra",
        "pop": "MUC",
        "since": 1,
        "until": 99,
    },
    {
        "code": "lis01",
        "city": "Lisbon",
        "n": 17,
        "cores": "iosxe",
        "zdc": "LIS1",
        "dia": "fibrenta",
        "pop": "FRA",
        "since": 2,
        "until": 99,
    },
]
# tiers: name -> (dc, vm count, service port, since version)
APPS = {
    "webshop": {
        "name": "Webshop",
        "crit": "high",
        "tiers": {"web": ("dc1", 5, 8443, 1), "api": ("dc1", 5, 8080, 1), "db": ("dc1", 3, 5432, 1)},
        "flows": [("web", "api", 8080, 1), ("api", "db", 5432, 1)],
        "vips": [("web", 443, "https", 1, 99), ("api", 8080, "http", 1, 99)],
    },
    "payments": {
        "name": "Payments",
        "crit": "high",
        "tiers": {"web": ("dc2", 4, 8443, 1), "api": ("dc2", 5, 9443, 1), "db": ("dc2", 3, 1521, 1)},
        "flows": [("web", "api", 9443, 1), ("api", "db", 1521, 1)],
        "vips": [("web", 443, "https", 1, 99), ("api", 9443, "https", 1, 99)],
    },
    "claims": {
        "name": "Claims Portal",
        "crit": "medium",
        "tiers": {
            "web": ("dc1", 4, 8443, 1),
            "app": ("dc1", 4, 8009, 1),
            "db": ("dc2", 3, 5432, 1),
            "api": ("dc1", 4, 8443, 2),
        },
        "flows": [
            ("web", "app", 8009, 1),
            ("app", "db", 5432, 1),
            ("web", "api", 8443, 2),
            ("api", "db", 5432, 2),
        ],
        "vips": [("web", 443, "https", 1, 99), ("app", 8009, "tcp", 1, 99), ("api", 8443, "https", 2, 99)],
    },
    "intranet": {
        "name": "Intranet",
        "crit": "low",
        "tiers": {"web": ("dc2", 4, 8080, 1), "db": ("dc2", 2, 3306, 1)},
        "flows": [("web", "db", 3306, 1)],
        "vips": [("web", 443, "https", 1, 99), ("web", 80, "http", 1, 2)],
    },
    "dwh": {
        "name": "Data Warehouse",
        "crit": "medium",
        "tiers": {"etl": ("dc2", 5, 8443, 1), "db": ("dc2", 3, 5439, 1)},
        "flows": [("etl", "db", 5439, 1)],
        "vips": [("etl", 8443, "https", 1, 99)],
    },
}
INFRA_VMS = [
    "dns-01",
    "dns-02",
    "ad-01",
    "ad-02",
    "mon-01",
    "bkp-01",
    "log-01",
    "smtp-01",
    "ntp-01",
    "vcsa-01",
    "jump-01",
    "sccm-01",
    "print-01",
    "zpa-conn-01",
    "zpa-conn-02",
]
IDENTITY_GROUPS = [
    ("employees", 77101),
    ("sales", 77102),
    ("finance", 77103),
    ("claims-agents", 77104),
    ("contractors", 77105),
    ("it-admins", 77106),
]
APP_IDENTITY = {
    "webshop": ["employees", "sales"],
    "payments": ["finance"],
    "claims": ["claims-agents"],
    "intranet": ["employees"],
    "dwh": ["finance", "it-admins"],
}
OFFICE_VLANS = [  # (vid, name, third octet)
    (10, "users", 10),
    (20, "voice", 20),
    (30, "printers", 30),
    (40, "servers", 40),
    (99, "mgmt", 99),
    (250, "fw-transit", 250),
]


def tier_subnets() -> dict[tuple[str, str], int]:
    """Stable third octet per (app, tier): v1 tiers first, then later ones, per DC."""
    out: dict[tuple[str, str], int] = {}
    nxt = {"dc1": 10, "dc2": 10}
    for since in (1, 2, 3):
        for app, spec in APPS.items():
            for tier, (dc, _n, _port, s) in spec["tiers"].items():
                if s == since:
                    out[(app, tier)] = nxt[dc]
                    nxt[dc] += 1
    return out


SUBNET = tier_subnets()


class Estate:
    def __init__(self, version: int) -> None:
        self.v = version
        self.g = Graph(version)
        self.vm_ips: dict[tuple[str, str], list[str]] = {}  # (app, tier) -> VM ip uids
        self.vm_uids: dict[tuple[str, str], list[str]] = {}
        self.infra_ip: dict[str, dict[str, str]] = {}  # dc -> infra vm name -> ip uid
        self.infra_vm: dict[str, dict[str, str]] = {}
        self.tier_prefix: dict[tuple[str, str], str] = {}
        self.vip_ip: dict[tuple[str, str, int], str] = {}  # (app, tier, port) -> ip uid
        self.vip_svc: dict[tuple[str, str, int], str] = {}
        self.dns_vip: dict[str, str] = {}  # dc -> dns VIP ip uid
        self.office_users: dict[str, str] = {}  # site code -> users prefix uid
        self.office_mgmt: dict[str, str] = {}
        self.border_lo: dict[str, str] = {}  # dc -> border-01 lo0 ip uid
        self.cp_cluster: dict[str, str] = {}
        self.leaf_if: dict[str, list[str]] = {}
        self.esx_hosts: dict[str, list[str]] = {}
        self.app_component: dict[tuple[str, str], str] = {}
        self.zpa_conn_vm: dict[str, list[str]] = {}
        self.dc_agg: dict[str, str] = {}
        self.offices = [o for o in OFFICES if o["since"] <= version <= o["until"]]
        self.cp_rules: dict[str, int] = {}
        self.leaf_port: dict[str, list[str]] = {}  # dc -> leaf port per ESX host (endpoint attachment)
        self.hub_vrf: dict[str, str] = {}  # dc -> SD-WAN hub corp VRF
        self.ctx_ifaces: dict[str, list[str]] = {}  # dc -> ACI VRF interfaces that enforce the PBR redirect
        self.dc_pbr: dict[str, str] = {}  # dc -> PbrPolicy uid
        self.dc_server_pfx: dict[str, list[str]] = {}  # dc -> server prefixes the redirect covers

    def rp(self, cidr: str, name: str) -> str:
        """A corp-side Prefix for a route target that lives in another routing domain (a cloud
        aggregate): the corp table routes toward the CIDR, the cloud side owns its own node."""
        uid = f"pfx:corp:{cidr}"
        if uid not in self.g.nodes:
            self.g.prefix("corp", cidr, "aggregate", name)
        return uid

    def campus_prefixes(self) -> list[str]:
        """Every network outside the data centers that the firewalls treat as campus: the offices
        of this version, the colo and the cloud aggregates."""
        out = [f"pfx:corp:10.{o['n']}.0.0/16" for o in self.offices]
        out += [
            self.rp("10.72.0.0/16", "eqx-fr5"),
            self.rp("10.64.0.0/16", "aws-prod"),
            self.rp("10.80.0.0/16", "az-gwc"),
        ]
        if self.v >= 3:
            out.append(self.rp("10.81.0.0/16", "az-weu"))
        return out

    # ------------------------------------------------------------------ shared ---
    def build(self) -> Graph:
        g = self.g
        g.sec("routing domains and global addressing")
        self.rdom = {
            name: g.node("RoutingDomain", f"rdom:{name}", name=name)
            for name in ("corp", "guest", "aws-prod", "az-prod")
        }
        if self.v >= 3:
            self.rdom["az-weu-prod"] = g.node("RoutingDomain", "rdom:az-weu-prod", name="az-weu-prod")
        self.corp_super = g.prefix("corp", CORP_SUPER, "aggregate", "corp-super")
        self.guest_super = g.prefix("guest", GUEST_SUPER, "aggregate", "guest-super")
        self.corp_default = g.prefix("corp", "0.0.0.0/0", "default", "default")
        self.guest_default = g.prefix("guest", "0.0.0.0/0", "default", "default")
        self.providers()
        self.business_services()
        for dc in DCS:
            self.datacenter(dc)
        self.sdwan_global()
        self.zscaler_global()
        for office in self.offices:
            self.office(office)
        self.colo()
        self.aws()
        self.azure(
            "az-gwc", "Azure Germany West Central", "germanywestcentral", "10.80", "az-prod", "er-fra", "gwc"
        )
        if self.v >= 3:
            self.azure("az-weu", "Azure West Europe", "westeurope", "10.81", "az-weu-prod", "er-ams", "weu")
        self.equinix_circuits()
        self.zpa()
        for dc in DCS:
            self.checkpoint_policy(dc)
        # vyos_office and fr5_internet_edges run last.
        self.vyos_office()
        self.fr5_internet_edges()
        return g

    def providers(self) -> None:
        g = self.g
        g.sec("providers (DORA register)")
        rows = [
            ("velorum", "Velorum Networks", "carrier", "C-2024-1101", "high"),
            ("fibrenta", "Fibrenta", "carrier", "C-2025-1102", "medium"),
            ("lumetra", "Lumetra Telecom", "carrier", "C-2023-1103", "medium"),
            ("zscaler", "Zscaler", "security-cloud", "C-2024-2001", "high"),
            ("equinix", "Equinix", "colo", "C-2022-3001", "high"),
            ("aws", "AWS", "cloud", "C-2023-4001", "high"),
            ("azure", "Microsoft Azure", "cloud", "C-2023-4002", "high"),
        ]
        self.provider = {}
        for key, name, kind, ref, crit in rows:
            self.provider[key] = g.node(
                "Provider", f"provider:{key}", name=name, kind=kind, contract_ref=ref, criticality=crit
            )
        self.pnet = {
            "velorum": g.node("ProviderNetwork", "pnet:mpls-velorum", name="Velorum MPLS VPN", kind="mpls"),
            "fibrenta": g.node(
                "ProviderNetwork", "pnet:internet-fibrenta", name="Fibrenta DIA", kind="internet"
            ),
            "lumetra": g.node(
                "ProviderNetwork", "pnet:internet-lumetra", name="Lumetra DIA", kind="internet"
            ),
        }
        for key, pnet in self.pnet.items():
            g.rel("PROVIDED_BY", pnet, self.provider[key])

    def business_services(self) -> None:
        g = self.g
        g.sec("business services and application components (ServiceNow)")
        self.bs = {}
        for app, spec in APPS.items():
            self.bs[app] = g.node(
                "BusinessService", f"snow:bs-{app}", name=spec["name"], criticality=spec["crit"]
            )
            for tier, (_dc, _n, _port, since) in spec["tiers"].items():
                if since <= self.v:
                    comp = g.node("AppComponent", f"snow:appc-{app}-{tier}", name=f"{app}-{tier}")
                    g.rel("PART_OF", comp, self.bs[app])
                    self.app_component[(app, tier)] = comp
        for app, tier in (("webshop", "cdn-origin"), ("dwh", "reporting"), ("intranet", "search")):
            comp = g.node("AppComponent", f"snow:appc-{app}-{tier}", name=f"{app}-{tier}")
            g.rel("PART_OF", comp, self.bs[app])
            self.app_component[(app, tier)] = comp
        if self.v >= 3:
            comp = g.node("AppComponent", "snow:appc-claims-dr", name="claims-dr")
            g.rel("PART_OF", comp, self.bs["claims"])
            self.app_component[("claims", "dr")] = comp

    # -------------------------------------------------------------- data centers ---
    def datacenter(self, dc: dict) -> None:
        g, v = self.g, self.v
        code, n, fab = dc["code"], dc["n"], dc["fabric"]
        base = f"10.{n}"
        g.sec(f"{code} site, fabric and devices")
        site = g.node(
            "Site", f"site:{code}", code=code, name=f"{dc['city']} Data Center", kind="dc", criticality="high"
        )
        fabric = g.node("Fabric", f"fabric:{fab}", name=fab, kind="aci")
        for pnet in self.pnet.values():
            g.rel("SERVED_BY", site, pnet)
        agg = g.prefix("corp", f"{base}.0.0/16", "aggregate", f"{code}", parent=self.corp_super)
        self.dc_agg[code] = agg
        mgmt_pfx = g.prefix("corp", f"{base}.0.0/24", "connected", f"{code}-mgmt", parent=agg)
        lo_pfx = g.prefix("corp", f"{base}.255.0/24", "connected", f"{code}-loopbacks", parent=agg)

        spines = [
            g.device(site, f"{code}-spine-0{i}", "aci-spine", "spine", "cisco", "FDO", f"{base}.0.{10 + i}")
            for i in (1, 2)
        ]
        leafs = [
            g.device(site, f"{code}-leaf-{i:02d}", "aci-leaf", "leaf", "cisco", "FDO", f"{base}.0.{20 + i}")
            for i in range(1, 9)
        ]
        apics = [
            g.device(site, f"{code}-apic-0{i}", "apic", "controller", "cisco", "FCH", f"{base}.0.{30 + i}")
            for i in (1, 2, 3)
        ]
        for d in spines + leafs:
            g.rel("MEMBER_OF", d, fabric)
        apic_grp = g.node(
            "RedundancyGroup", f"rgrp:apic-cluster:{code}:apic", kind="apic-cluster", name=f"{code}-apic"
        )
        for d in apics:
            g.rel("MEMBER_OF", d, apic_grp)
        # spine-leaf links and vPC pairs
        for i, leaf in enumerate(leafs, start=1):
            for s, spine in enumerate(spines, start=1):
                lp = g.port(leaf, f"eth1-{48 + s}", f"ethernet1/{48 + s}", 100000)
                sp = g.port(spine, f"eth1-{i}", f"ethernet1/{i}", 100000)
                g.cable(lp, sp)
        for pair in range(4):
            a, b = leafs[2 * pair], leafs[2 * pair + 1]
            grp = g.node(
                "RedundancyGroup",
                f"rgrp:vpc:{fab}:{101 + pair}",
                kind="vpc",
                name=f"{code}-leaf-{2 * pair + 1:02d}-{2 * pair + 2:02d}",
                domain_id=101 + pair,
                peer_link="port-channel1",
            )
            g.rel("MEMBER_OF", a, grp, props={"role": "primary"})
            g.rel("MEMBER_OF", b, grp, props={"role": "secondary"})
            g.cable(
                g.port(a, "eth1-53", "ethernet1/53", 100000),
                g.port(b, "eth1-53", "ethernet1/53", 100000),
                role="vpc-peer-link",
            )

        # Check Point cluster
        fw_pfx = g.prefix("corp", f"{base}.250.0/29", "service", f"{code}-fw-svc", parent=agg)
        cp_grp = g.node(
            "RedundancyGroup", f"rgrp:cp-cluster:{code}:cpfw01", kind="cp-cluster", name=f"{code}-cpfw01"
        )
        self.cp_cluster[code] = cp_grp
        # the ACI VRF is the one routing table every leaf forwards in; its gateway interfaces are
        # placed on the leaf each attached device hangs off (the fabric's anycast gateway, drawn once)
        # contract_bypass "": the demo fabric uses no vzAny contract, preferred group or ESG, so an
        # EPG pair with no permitting contract is implicitly denied (core/aci_filter.py)
        vrf_aci = g.vrf(
            f"vrf:aci:{fab}:tn-PROD:CTX1",
            "CTX1",
            self.rdom["corp"],
            pc_enf_pref="enforced",
            contract_bypass="",
        )
        self.aci_vrf = getattr(self, "aci_vrf", {})
        self.aci_vrf[code] = vrf_aci
        self.ctx_ifaces[code] = []
        fw_ifs = []
        # the firewall service bridge domain: gateway on leaf-01, the cluster members and the
        # cluster address on it, the Check Point default route back to the fabric
        fw_svi = g.iface(leafs[0], "vlan250", "vlan250", "svi", vlan=250)
        g.connected(vrf_aci, fw_svi, f"{base}.250.1", fw_pfx)
        fw_vip = g.ip("corp", f"{base}.250.10", fw_pfx, name=f"{code}-cpfw01-inside")
        for idx, suffix in enumerate("ab"):
            fw = g.device(
                site,
                f"{code}-cpfw-01{suffix}",
                "checkpoint",
                "firewall",
                "checkpoint",
                "CP",
                f"{base}.0.{41 + idx}",
            )
            g.rel("MEMBER_OF", fw, cp_grp)
            p1 = g.port(fw, "eth1", "eth1", 10000)
            psync = g.port(fw, "eth2", "eth2", 10000)
            fw_ifs.append((fw, p1, psync))
            leaf_port = g.port(leafs[idx], "eth1-1", "ethernet1/1", 10000)
            g.iface(leafs[idx], "eth1-1", "ethernet1/1", "phys", port=leaf_port)
            g.cable(leaf_port, p1)
            fi = g.iface(fw, "eth1", "eth1", "phys", port=p1)
            fw_vrf = g.vrf(f"vrf:dev:{code}-cpfw-01{suffix}:default", "default", self.rdom["corp"])
            g.rel("HAS_IP", fi, g.ip("corp", f"{base}.250.{11 + idx}", fw_pfx))
            g.rel("HAS_IP", fi, fw_vip)
            g.rel("IN_VRF", fi, fw_vrf)
            g.rel("ORIGINATES", fw_vrf, fw_pfx, props={"proto": "connected"})
            g.route(fw_vrf, self.corp_default, "STATIC_ROUTE", next_hop=f"{base}.250.1", iface=fi)
        g.cable(fw_ifs[0][2], fw_ifs[1][2], role="cp-sync")
        fw_mac = g.mac(f"{code}-cpfw01", "00:1c:7f")
        ep = g.node(
            "Endpoint",
            f"ep:corp:{fw_mac.replace(':', '')}",
            mac=fw_mac,
            kind="infra",
            name=f"{code}-cpfw01-inside",
        )
        g.rel("OWNED_BY", ep, cp_grp)
        g.rel("ATTACHED", ep, f"{leafs[0]}/if/eth1-1", props={"encap": "vlan-250"})
        g.rel("HAS_IP", ep, fw_vip)

        # NetScaler pair
        # NetScaler pair: the NSIPs on a transit /29 whose fabric gateway sits on leaf-05, the VIP
        # subnet owned by the pair (the primary is its gateway), one static default back to the fabric
        ns_grp = g.node("RedundancyGroup", f"rgrp:ns-ha:{code}:ns01", kind="ns-ha", name=f"{code}-ns01")
        vip_pfx = g.prefix("corp", f"{base}.30.0/24", "service", f"{code}-vip", parent=agg)
        ns_pfx = g.prefix(
            "corp", f"{base}.31.0/29", "connected", f"{code}-ns-transit", anchor=vrf_aci, parent=agg
        )
        ns_svi = g.iface(leafs[4], "vlan31", "vlan31", "svi", vlan=31)
        g.connected(vrf_aci, ns_svi, f"{base}.31.1", ns_pfx)
        self.ctx_ifaces[code].append(ns_svi)
        snip = g.ip("corp", f"{base}.30.250", vip_pfx, name=f"{code}-ns01-snip")
        for idx, suffix in enumerate("ab"):
            ns = g.device(
                site, f"{code}-ns-01{suffix}", "netscaler", "gateway", "citrix", "NS", f"{base}.0.{51 + idx}"
            )
            g.rel("MEMBER_OF", ns, ns_grp)
            p = g.port(ns, "10-1", "10/1", 10000)
            g.cable(g.port(leafs[4 + idx], "eth1-1", "ethernet1/1", 10000), p)
            nif = g.iface(ns, "10-1", "10/1", "phys", port=p)
            ns_vrf = g.vrf(f"vrf:dev:{code}-ns-01{suffix}:default", "default", self.rdom["corp"])
            g.connected(ns_vrf, nif, f"{base}.31.{2 + idx}", ns_pfx, gateway=False)
            vif = g.iface(ns, "vlan30", "vlan30", "vlan", vlan=30)
            g.connected(ns_vrf, vif, f"{base}.30.{251 + idx}", vip_pfx, gateway=idx == 0)
            if idx == 0:
                g.rel("HAS_IP", vif, snip)
            g.route(ns_vrf, self.corp_default, "STATIC_ROUTE", next_hop=f"{base}.31.1", iface=nif)
        g.route(vrf_aci, vip_pfx, "STATIC_ROUTE", next_hop=f"{base}.31.2")

        # border routers and SD-WAN hub
        # border routers on the campus L3Out of leaf-07 and leaf-08 (a routed /30 each): the fabric
        # sends the colo and cloud aggregates there, and the border leaves the twin by its MPLS uplink
        borders = []
        wan_pfx = [
            self.rp("10.72.0.0/16", "eqx-fr5"),
            self.rp("10.64.0.0/16", "aws-prod"),
            self.rp("10.80.0.0/16", "az-gwc"),
        ]
        if v >= 3:
            wan_pfx.append(self.rp("10.81.0.0/16", "az-weu"))
        for i in (1, 2):
            br = g.device(site, f"{code}-border-0{i}", "nxos", "router", "cisco", "FDO", f"{base}.0.{60 + i}")
            borders.append(br)
            bp = g.port(br, "eth1-1", "ethernet1/1", 100000)
            leaf_port = g.port(leafs[5 + i], "eth1-1", "ethernet1/1", 100000)
            g.cable(leaf_port, bp)
            bi = g.iface(br, "eth1-1", "ethernet1/1", "phys", port=bp)
            lo = g.iface(br, "lo0", "loopback0", "loopback")
            lo_ip = g.ip("corp", f"{base}.255.{200 + i}", lo_pfx)
            g.rel("HAS_IP", lo, lo_ip)
            vrf = g.vrf(f"vrf:dev:{code}-border-0{i}:corp", "corp", self.rdom["corp"])
            g.rel("IN_VRF", lo, vrf)
            g.rel("ORIGINATES", vrf, agg, props={"proto": "aggregate"})
            g.rel("IMPORTS", vrf, self.rt())
            g.rel("EXPORTS", vrf, self.rt())
            l3o_pfx = g.prefix(
                "corp",
                f"{base}.254.{4 * (i - 1)}/30",
                "connected",
                f"{code}-l3out-campus-{i}",
                anchor=vrf_aci,
                parent=agg,
            )
            li = g.iface(leafs[5 + i], "eth1-1", "ethernet1/1", "phys", port=leaf_port)
            g.connected(vrf_aci, li, f"{base}.254.{4 * (i - 1) + 1}", l3o_pfx)
            self.ctx_ifaces[code].append(li)
            g.connected(vrf, bi, f"{base}.254.{4 * (i - 1) + 2}", l3o_pfx, gateway=False)
            g.route(
                vrf,
                self.corp_super,
                "LEARNED_ROUTE",
                next_hop=f"{base}.254.{4 * (i - 1) + 1}",
                iface=bi,
                protocol="bgp",
            )
            up = g.iface(
                br,
                "eth1-48",
                "ethernet1/48",
                "phys",
                port=g.port(br, "eth1-48", "ethernet1/48", 10000),
                description="Velorum MPLS uplink",
            )
            g.rel("IN_VRF", up, vrf)
            for pfx in wan_pfx:
                g.route(vrf, pfx, "LEARNED_ROUTE", iface=up, protocol="bgp")
                if i == 1:
                    g.route(vrf_aci, pfx, "LEARNED_ROUTE", next_hop=f"{base}.254.2", protocol="bgp")
            if i == 1:
                self.border_lo[code] = lo_ip
        # the SD-WAN hub on its own L3Out of leaf-07; the overlay interfaces toward the offices and
        # the other hub are added when those are built
        hub = g.device(
            site,
            f"{code}-vch-01",
            "velocloud-edge",
            "sdwan-hub",
            "vmware",
            f"VCH-{code.upper()}-{g.digits(code + '-vch', 4)}",
            f"{base}.0.71",
        )
        hp = g.port(hub, "ge3", "ge3", 10000)
        hub_leaf_port = g.port(leafs[6], "eth1-2", "ethernet1/2", 10000)
        g.cable(hub_leaf_port, hp)
        hi = g.iface(hub, "ge3", "ge3", "phys", port=hp)
        hub_vrf = g.vrf(f"vrf:dev:{code}-vch-01:corp", "corp", self.rdom["corp"])
        self.hub_vrf[code] = hub_vrf
        hub_pfx = g.prefix(
            "corp", f"{base}.253.0/30", "connected", f"{code}-l3out-sdwan", anchor=vrf_aci, parent=agg
        )
        hli = g.iface(leafs[6], "eth1-2", "ethernet1/2", "phys", port=hub_leaf_port)
        g.connected(vrf_aci, hli, f"{base}.253.1", hub_pfx)
        self.ctx_ifaces[code].append(hli)
        g.connected(hub_vrf, hi, f"{base}.253.2", hub_pfx, gateway=False)
        g.route(hub_vrf, agg, "LEARNED_ROUTE", next_hop=f"{base}.253.1", iface=hi, protocol="bgp")
        g.route(hub_vrf, self.corp_super, "LEARNED_ROUTE", next_hop=f"{base}.253.1", iface=hi, protocol="bgp")
        g.route(vrf_aci, self.corp_super, "LEARNED_ROUTE", next_hop=f"{base}.253.2", protocol="bgp")
        if code == "dc1":
            g.device(site, "cpmgmt-01", "checkpoint", "management", "checkpoint", "CP", f"{base}.0.45")
            g.device(site, "vco-01", "velocloud-orchestrator", "controller", "vmware", "VCO", f"{base}.0.72")
        # out-of-band management interface on every device, fabric loopbacks on spines and leafs
        g.sec(f"{code} management and loopbacks")
        for dev_uid, (label, props) in list(g.nodes.items()):
            if label != "Device" or (dev_uid, "LOCATED_IN", site) not in {
                (r[2], r[1], r[3]) for r in g.rels if r[1] == "LOCATED_IN"
            }:
                continue
            mname = {
                "checkpoint": "Mgmt",
                "netscaler": "0/1",
                "velocloud-edge": "ge1",
                "velocloud-orchestrator": "eth0",
                "apic": "oobmgmt",
            }.get(props["platform"], "mgmt0")
            mi = g.iface(dev_uid, "mgmt0", mname, "mgmt")
            g.rel("HAS_IP", mi, g.ip("corp", props["mgmt_ip"], mgmt_pfx, name=f"{props['hostname']}-mgmt"))
        for k, d in enumerate(spines + leafs, start=1):
            lo = g.iface(d, "lo0", "loopback0", "loopback")
            g.rel("HAS_IP", lo, g.ip("corp", f"{base}.255.{k}", lo_pfx))

        # ESX hosts, dual-homed to a leaf pair
        g.sec(f"{code} vSphere")
        vc = f"vc:vc-{code}"
        hosts = []
        for i in range(6):
            host = g.node(
                "EsxHost",
                f"{vc}:host-{11 + i}",
                hostname=f"{code}-esx-{i + 1:02d}",
                serial=g.serial("VMW", f"{code}-esx-{i + 1:02d}"),
            )
            hosts.append(host)
            pair = i // 3
            for k in range(2):
                leaf = leafs[2 * pair + k]
                pnic = g.node("Pnic", f"{host}/pnic/vmnic{k}", name=f"vmnic{k}")
                g.rel("ON", pnic, host)
                lp = g.port(leaf, f"eth1-{10 + i}", f"ethernet1/{10 + i}", 25000)
                g.iface(leaf, f"eth1-{10 + i}", f"ethernet1/{10 + i}", "phys", port=lp)
                g.cable(pnic, lp)
            self.leaf_if.setdefault(code, []).append(f"{leafs[2 * pair]}/if/eth1-{10 + i}")
            self.leaf_port.setdefault(code, []).append(f"{leafs[2 * pair]}/port/eth1-{10 + i}")
        self.esx_hosts[code] = hosts

        # ACI tenant tree
        g.sec(f"{code} ACI tenant tree")
        tn = g.node("Tenant", f"aci:{fab}:uni/tn-PROD", name="PROD")
        vm_counter = [100]
        epg_of: dict[str, str] = {}
        self.dc_server_pfx[code] = [vip_pfx]

        def tier_block(app: str, tier: str, subnet: int, vm_names: list[str], vlan: int) -> str:
            ap = g.node("AppProfile", f"aci:{fab}:uni/tn-PROD/ap-{app}", name=app)
            g.rel("HAS", tn, ap)
            epg = g.node("Epg", f"aci:{fab}:uni/tn-PROD/ap-{app}/epg-{tier}", name=tier, pctag=16000 + subnet)
            g.rel("HAS", ap, epg)
            bd = g.node(
                "BridgeDomain",
                f"aci:{fab}:uni/tn-PROD/BD-{app}-{tier}",
                name=f"BD-{app}-{tier}",
                unicast_route=True,
            )
            g.rel("HAS", tn, bd)
            g.rel("IN_BD", epg, bd)
            g.rel("IN_VRF", bd, vrf_aci)
            seg = g.node("BridgeDomain", f"l2seg:{code}-{app}-{tier}", name=f"{code}-{app}-{tier}")
            g.rel("REALIZES", bd, seg)
            dvpg = g.node("DvPortgroup", f"{vc}:dvpg-{app}-{tier}", name=f"dvpg-{app}-{tier}", vlan=vlan)
            g.rel("REALIZES", dvpg, seg)
            g.rel("VMM_BINDING", epg, dvpg)
            pfx = g.prefix(
                "corp",
                f"{base}.{subnet}.0/24",
                "connected",
                f"{code}-{app}-{tier}",
                anchor=vrf_aci,
                parent=agg,
            )
            self.tier_prefix[(app, tier)] = pfx
            self.dc_server_pfx[code].append(pfx)
            # the bridge domain's gateway: an SVI on leaf-05 that realizes the segment in the ACI VRF
            svi = g.iface(leafs[4], f"vlan{vlan}", f"vlan{vlan}", "svi", vlan=vlan)
            g.connected(vrf_aci, svi, f"{base}.{subnet}.1", pfx)
            vl = g.node("VlanInstance", f"vlan:{leafs[4]}:{vlan}", vid=vlan, name=f"{app}-{tier}")
            g.rel("REALIZES", vl, seg)
            g.rel("BOUND_TO", svi, vl)
            self.ctx_ifaces[code].append(svi)
            ips, vms = [], []
            for i, name in enumerate(vm_names):
                vm_counter[0] += 1
                vm = g.node("Vm", f"{vc}:vm-{vm_counter[0]}", name=name, power="on")
                host_idx = (i + subnet) % 6
                g.rel("ON", vm, hosts[host_idx])
                mac = g.mac(name)
                vnic = g.node("Vnic", f"{vm}/vnic/0", mac=mac)
                g.rel("OF", vnic, vm)
                g.rel("PLUGGED_INTO", vnic, dvpg)
                ipu = g.ip("corp", f"{base}.{subnet}.{11 + i}", pfx, anchor=vrf_aci, name=name)
                g.rel("HAS_IP", vnic, ipu)
                ep = g.node("Endpoint", f"ep:corp:{mac.replace(':', '')}", mac=mac, kind="vm", name=name)
                g.rel("ATTACHED", ep, self.leaf_port[code][host_idx], props={"encap": f"vlan-{vlan}"})
                g.rel("HAS_IP", ep, ipu)
                g.rel("IN_EPG", ep, epg)
                g.rel("IN", ep, seg)
                ips.append(ipu)
                vms.append(vm)
            self.vm_ips[(app, tier)] = ips
            self.vm_uids[(app, tier)] = vms
            epg_of[f"{app}/{tier}"] = epg
            return epg

        for app, spec in APPS.items():
            for tier, (tdc, count, _port, since) in spec["tiers"].items():
                if tdc != code or since > v:
                    continue
                sub = SUBNET[(app, tier)]
                names = [f"{code}-{app}-{tier}-{i + 1:02d}" for i in range(count)]
                tier_block(app, tier, sub, names, 100 + sub)
                for vm in self.vm_uids[(app, tier)]:
                    g.rel("PART_OF", vm, self.app_component[(app, tier)])
        tier_block("infra", "shared", 5, [f"{code}-{nm}" for nm in INFRA_VMS], 105)
        self.infra_ip[code] = dict(zip(INFRA_VMS, self.vm_ips[("infra", "shared")], strict=False))
        self.infra_vm[code] = dict(zip(INFRA_VMS, self.vm_uids[("infra", "shared")], strict=False))
        self.zpa_conn_vm[code] = [self.infra_vm[code]["zpa-conn-01"], self.infra_vm[code]["zpa-conn-02"]]

        # contracts for the in-DC flows, one PBR-redirected through the firewall
        filters: dict[int, str] = {}

        def aci_filter(port: int, proto: str = "tcp") -> str:
            if port not in filters:
                flt = g.node("AciFilter", f"aci:{fab}:uni/tn-PROD/flt-{proto}-{port}", name=f"{proto}-{port}")
                g.rel("HAS", tn, flt)
                # the entry as the APIC collector writes vzEntry etherT, sFromPort/sToPort,
                # dFromPort/dToPort, tcpRules and applyToFrag, which every ACI gate reads
                # (core/aci_filter.py)
                e = g.node(
                    "FilterEntry",
                    f"{flt}/e-{proto}-{port}",
                    proto=proto,
                    ether_type="ip",
                    s_from_port="unspecified",
                    s_to_port="unspecified",
                    d_from_port=str(port),
                    d_to_port=str(port),
                    tcp_rules="unspecified",
                    apply_to_frag="no",
                )
                g.rel("HAS", flt, e)
                filters[port] = flt
            return filters[port]

        sgt = g.node("ServiceGraphTemplate", f"aci:{fab}:uni/tn-PROD/AbsGraph-fw", name="fw-graph")
        g.rel("HAS", tn, sgt)
        snode = g.node("ServiceNode", f"{sgt}/AbsNode-FW", name="FW", function="fw", managed=False)
        g.rel("HAS_NODE", sgt, snode, props={"seq": 1})
        pbr = g.node(
            "PbrPolicy",
            f"aci:{fab}:uni/tn-PROD/svcCont/svcRedirectPol-fw-pbr",
            name="fw-pbr",
            hashing="sip-dip",
        )
        g.rel("REDIRECTS_VIA", snode, pbr)
        dest = g.node("PbrDest", f"{pbr}/dest-{base}.250.10", ip=f"{base}.250.10", mac=fw_mac.upper())
        g.rel("HAS_DEST", pbr, dest)
        g.rel("RESOLVES_TO", dest, ep)
        self.dc_pbr[code] = pbr
        # the redirect as the path engine reads it: every ACI VRF interface except the firewall's own
        # bridge domain enforces the policy, and a matching rule forwards in a one-row table whose
        # only route points at the cluster address (the rule itself is written with the DC policy,
        # once the campus prefixes it matches exist)
        redirect = g.vrf(f"vrf:aci:{fab}:tn-PROD:fw-redirect", "fw-redirect", kind="pbr-redirect")
        host = g.prefix(
            "corp", f"{base}.250.10/32", "host", f"{code}-cpfw01-inside", anchor=redirect, parent=fw_pfx
        )
        g.route(redirect, host, "STATIC_ROUTE")
        g.route(redirect, self.corp_default, "STATIC_ROUTE", next_hop=f"{base}.250.10")
        for iface in self.ctx_ifaces[code]:
            g.rel("ENFORCES", iface, pbr)
        first = True
        # the contracts of a tier pair with 1 tier in this fabric, each as (contract, consumer, provider)
        # with None for the tier of the other fabric; the campus external EPG stands for that tier
        crossing = []
        for app, spec in APPS.items():
            for src, dst, port, since in spec["flows"]:
                consumer, provider = epg_of.get(f"{app}/{src}"), epg_of.get(f"{app}/{dst}")
                if since > v or (consumer is None and provider is None):
                    continue
                c = g.node(
                    "Contract",
                    f"aci:{fab}:uni/tn-PROD/brc-{app}-{src}-to-{dst}",
                    name=f"{app}-{src}-to-{dst}",
                    scope="context",
                )
                g.rel("HAS", tn, c)
                subj = g.node("ContractSubject", f"{c}/subj-{port}", name=f"tcp-{port}")
                g.rel("HAS", c, subj)
                g.rel("USES_FILTER", subj, aci_filter(port), props={"action": "permit"})
                if consumer is None or provider is None:
                    crossing.append((c, consumer, provider))
                    continue
                g.rel("CONSUMES", consumer, c)
                g.rel("PROVIDES", provider, c)
                if first:
                    g.rel("APPLIES_GRAPH", subj, sgt)
                    first = False
        # every tier reaches shared infra (dns, ntp, ldap) and the campus L3Out reaches the web tiers
        infra_c = g.node(
            "Contract", f"aci:{fab}:uni/tn-PROD/brc-infra-services", name="infra-services", scope="context"
        )
        g.rel("HAS", tn, infra_c)
        for port, proto in ((53, "udp"), (123, "udp"), (636, "tcp")):
            subj = g.node("ContractSubject", f"{infra_c}/subj-{proto}-{port}", name=f"{proto}-{port}")
            g.rel("HAS", infra_c, subj)
            g.rel("USES_FILTER", subj, aci_filter(port, proto), props={"action": "permit"})
        g.rel("PROVIDES", epg_of["infra/shared"], infra_c)
        l3out = g.node("L3Out", f"aci:{fab}:uni/tn-PROD/out-campus", name="campus")
        g.rel("HAS", tn, l3out)
        g.rel("IN_VRF", l3out, vrf_aci)
        ext = g.node("ExtEpg", f"{l3out}/instP-campus", name="campus-users")
        g.rel("HAS", l3out, ext)
        g.rel("MATCHES", ext, self.corp_super)
        for c, consumer, provider in crossing:
            g.rel("CONSUMES", consumer or ext, c)
            g.rel("PROVIDES", provider or ext, c)
        for key, epg in epg_of.items():
            if key != "infra/shared":
                g.rel("CONSUMES", epg, infra_c)
            app, tier = key.split("/")
            if tier in ("web", "etl"):
                c = g.node(
                    "Contract",
                    f"aci:{fab}:uni/tn-PROD/brc-users-to-{app}-{tier}",
                    name=f"users-to-{app}-{tier}",
                    scope="context",
                )
                g.rel("HAS", tn, c)
                port = APPS[app]["tiers"][tier][2]
                subj = g.node("ContractSubject", f"{c}/subj-{port}", name=f"tcp-{port}")
                g.rel("HAS", c, subj)
                g.rel("USES_FILTER", subj, aci_filter(port), props={"action": "permit"})
                g.rel("CONSUMES", ext, c)
                g.rel("PROVIDES", epg, c)

        # NetScaler virtual services
        g.sec(f"{code} NetScaler")
        nsid = f"ns:{code}-ns01"
        vip_host = 10

        def vip(
            name: str, port: int, proto: str, members: list[str], mport: int, monitor: str, fqdn: str
        ) -> None:
            nonlocal vip_host
            ipu = g.ip("corp", f"{base}.30.{vip_host}", vip_pfx, name=name)
            vip_host += 1
            vs = g.node(
                "VirtualService",
                f"{nsid}:lbvs:{name}",
                name=name,
                vip=f"{base}.30.{vip_host - 1}",
                port=port,
                proto="udp" if proto == "dns" else "tcp",
                kind="lb",
                snat_mode="snat_from",
                ssl="offload" if proto == "https" else None,
                state="up",
            )
            g.rel("ON", vs, ns_grp)
            g.rel("VIP", vs, ipu)
            g.rel("SNAT_FROM", vs, snip)
            pool = g.node("Pool", f"{nsid}:sg:{name}", name=name, lb_method="leastconnection")
            g.rel("USES", vs, pool)
            mon = g.node("Monitor", f"{nsid}:mon:{name}", kind=monitor, target=f"tcp/{mport}")
            g.rel("CHECKED_BY", pool, mon)
            for m in members:
                addr = g.nodes[m][1]["ip"]
                pm = g.node("PoolMember", f"{pool}/{addr}:{mport}", port=mport, state="up")
                g.rel("HAS_MEMBER", pool, pm)
                g.rel("TARGETS", pm, m)
            rec = g.node("DnsRecord", f"dns:{fqdn}:A", fqdn=fqdn, type="A")
            g.rel("RESOLVES_TO", rec, ipu)
            return ipu, vs

        for app, spec in APPS.items():
            for k, (tier, port, proto, since, until) in enumerate(spec["vips"]):
                tdc = spec["tiers"][tier][0]
                if tdc != code or not (since <= v <= until):
                    continue
                fqdn = f"{app}.{DOMAIN}" if k == 0 else f"{app}-{tier}-{port}.{DOMAIN}"
                ipu, vs = vip(
                    f"{app}-{tier}-{port}",
                    port,
                    proto,
                    self.vm_ips[(app, tier)],
                    spec["tiers"][tier][2],
                    "http" if proto in ("https", "http") else "tcp",
                    fqdn,
                )
                self.vip_ip[(app, tier, port)] = ipu
                self.vip_svc[(app, tier, port)] = vs
        inf = self.infra_ip[code]
        dns_ip, _ = vip(
            "dns-53", 53, "dns", [inf["dns-01"], inf["dns-02"]], 53, "dns", f"dns-{code}.{DOMAIN}"
        )
        self.dns_vip[code] = dns_ip
        vip("ldap-636", 636, "tcp", [inf["ad-01"], inf["ad-02"]], 636, "tcp", f"ldap-{code}.{DOMAIN}")
        vip("smtp-25", 25, "tcp", [inf["smtp-01"]], 25, "tcp", f"smtp-{code}.{DOMAIN}")
        vip("syslog-514", 514, "tcp", [inf["log-01"]], 514, "tcp", f"syslog-{code}.{DOMAIN}")

    def rt(self) -> str:
        if not hasattr(self, "_rt"):
            g = self.g
            self._rt = g.node("RouteTarget", "rt:65001:50001", value="65001:50001")
            evpn = g.node("EvpnInstance", "evpn:corp:l3vni-50001", l3vni=50001, kind="l3")
            g.rel("USES_RT", evpn, self._rt)
            g.rel("MEMBER_OF", evpn, self.rdom["corp"], props={"basis": "declared"})
        return self._rt

    # ----------------------------------------------------------- SD-WAN, Zscaler ---
    def sdwan_global(self) -> None:
        g = self.g
        g.sec("SD-WAN orchestrator objects")
        vco = f"vco:{ORG}"
        self.sdwan_seg = g.node("SdwanSegment", f"{vco}:segment:1", segment_id=1, name="corp")
        g.rel("MEMBER_OF", self.sdwan_seg, self.rdom["corp"], props={"basis": "declared"})
        self.sdwan_guest_seg = g.node("SdwanSegment", f"{vco}:segment:2", segment_id=2, name="guest")
        g.rel("MEMBER_OF", self.sdwan_guest_seg, self.rdom["guest"], props={"basis": "declared"})
        self.sdwan_gw = {
            pop: g.node("SdwanGateway", f"{vco}:gw:{pop.lower()}-gw1", name=f"{pop.lower()}-gw1", pop=pop)
            for pop in ("FRA", "MUC")
        }
        self.bizpol = {
            "web": g.node(
                "SdwanBusinessPolicy",
                f"{vco}:bizpol:web-to-zscaler",
                name="web-to-zscaler",
                match="default web traffic",
                action="cloud-security",
            ),
            "voice": g.node(
                "SdwanBusinessPolicy",
                f"{vco}:bizpol:voice-mpls",
                name="voice-mpls",
                match="voice vlans",
                action="steer-mpls",
            ),
            "dc": g.node(
                "SdwanBusinessPolicy",
                f"{vco}:bizpol:dc-apps-mpls-preferred",
                name="dc-apps-mpls-preferred",
                match="data center aggregates",
                action="steer-mpls",
            ),
        }
        g.rel("MATCHES", self.bizpol["web"], self.corp_default)
        for agg in self.dc_agg.values():
            g.rel("MATCHES", self.bizpol["dc"], agg)
        # hub-to-hub overlay: each data center routes the other's aggregate across it
        hh_pfx = g.prefix("corp", "10.254.0.0/30", "connected", "sdwan-dc1-dc2", anchor=self.sdwan_seg)
        hubs = [(dc["code"], f"dev:{dc['code']}-vch-01") for dc in DCS]
        for k, (code, hub) in enumerate(hubs):
            other_code, _other = hubs[1 - k]
            ti = g.iface(
                hub,
                f"vcmp-{other_code}",
                f"vcmp-{other_code}",
                "tunnel",
                description=f"VCMP overlay to {other_code}-vch-01",
            )
            g.connected(self.hub_vrf[code], ti, f"10.254.0.{k + 1}", hh_pfx, gateway=False)
            g.route(
                self.hub_vrf[code],
                self.dc_agg[other_code],
                "LEARNED_ROUTE",
                next_hop=f"10.254.0.{2 - k}",
                iface=ti,
                protocol="sdwan",
            )

    def zscaler_global(self) -> None:
        g = self.g
        g.sec("Zscaler ZIA cloud")
        zia = f"zia:{ORG}"
        self.zdc = {}
        for _i, name in enumerate(["FRA4", "MUC1", "VIE1", "MIL1", "WAW1", "PAR2", "MAD1", "ZRH1", "LIS1"]):
            self.zdc[name] = g.node("ZscalerDc", f"{zia}:dc:{name.lower()}", name=name)
            g.rel("PROVIDED_BY", self.zdc[name], self.provider["zscaler"])
        g.rel("STEERS_VIA", self.bizpol["web"], self.zdc["FRA4"])
        self.zia_locgrp = g.node("ZiaLocationGroup", f"{zia}:locgrp:9101", name="eu-offices", dynamic=False)
        g.node(
            "ZiaForwardingRule",
            f"{zia}:fwdrule:9201",
            name="corp-apps-to-zpa",
            order=1,
            forward_method="zpa",
            enabled=True,
            zpa_app_segment_ids=[str(2001 + i) for i in range(len(APPS))],
        )
        g.node(
            "ZiaForwardingRule",
            f"{zia}:fwdrule:9202",
            name="trusted-saas-direct",
            order=2,
            forward_method="direct",
            enabled=True,
        )

    # ------------------------------------------------------------------- offices ---
    def office(self, o: dict) -> None:
        g, v = self.g, self.v
        code, n = o["code"], o["n"]
        base = f"10.{n}"
        g.sec(f"{code} office site and devices")
        site = g.node(
            "Site",
            f"site:{code}",
            code=code,
            name=f"{o['city']} Office",
            kind="office",
            criticality="high" if n in (11, 16) else "medium",
        )
        g.rel("SERVED_BY", site, self.pnet["velorum"])
        g.rel("SERVED_BY", site, self.pnet[o["dia"]])
        core_platform = o["cores"]
        core_vendor = "cisco"
        ifname = (
            (lambda i: f"ethernet1/{i}")
            if core_platform == "nxos"
            else (lambda i: f"TenGigabitEthernet1/0/{i}")
        )
        ifshort = (lambda i: f"eth1-{i}") if core_platform == "nxos" else (lambda i: f"te1-0-{i}")
        cores = [
            g.device(
                site,
                f"{code}-core-0{i}",
                core_platform,
                "router",
                core_vendor,
                "FDO" if core_platform == "nxos" else "FJC",
                f"{base}.99.{i}",
            )
            for i in (1, 2)
        ]
        n_acc = 2 + (n % 3)
        access = [
            g.device(site, f"{code}-acc-{i:02d}", "iosxe", "switch", "cisco", "FJC", f"{base}.99.{10 + i}")
            for i in range(1, n_acc + 1)
        ]
        fgt = g.device(
            site,
            f"{code}-fgt-01",
            "fortigate",
            "firewall",
            "fortinet",
            f"FGT100F{g.digits(code + '-fgt', 10)}",
            f"{base}.99.21",
        )
        vce = g.device(
            site,
            f"{code}-vce-01",
            "velocloud-edge",
            "sdwan-edge",
            "vmware",
            f"VCE-{code.upper()}-{g.digits(code + '-vce', 4)}",
            f"{base}.99.22",
        )
        wlc = g.device(site, f"{code}-wlc-01", "wlc", "controller", "cisco", "FCW", f"{base}.99.23")

        # addressing
        agg = g.prefix("corp", f"{base}.0.0/16", "aggregate", f"{code}", parent=self.corp_super)
        vrf_corp = [g.vrf(f"vrf:dev:{code}-core-0{i}:corp", "corp", self.rdom["corp"]) for i in (1, 2)]
        vrf_guest = [g.vrf(f"vrf:dev:{code}-core-0{i}:guest", "guest", self.rdom["guest"]) for i in (1, 2)]
        vrf_fgt = g.vrf(f"vrf:dev:{code}-fgt-01:root", "root", None, kind="vdom")
        pfx = {}
        for _vid, name, third in OFFICE_VLANS:
            pfx[name] = g.prefix(
                "corp", f"{base}.{third}.0/24", "connected", f"{code}-{name}", anchor=vrf_corp[0], parent=agg
            )
            for vrf in vrf_corp:
                g.rel("ORIGINATES", vrf, pfx[name], props={"proto": "connected"})
        guest_pfx = g.prefix(
            "guest", f"172.31.{n}.0/24", "connected", f"{code}-guest", parent=self.guest_super
        )
        lo_pfx = g.prefix("corp", f"{base}.255.0/24", "connected", f"{code}-loopbacks", parent=agg)
        self.office_users[code] = pfx["users"]
        self.office_mgmt[code] = pfx["mgmt"]
        self.office_edge: dict[str, str] = getattr(self, "office_edge", {})

        # VLANs, segments, SVIs, HSRP
        g.sec(f"{code} L2 and L3")
        segs = {
            name: g.node("BridgeDomain", f"l2seg:{code}-{name}", name=f"{code}-{name}")
            for _vid, name, _t in [*OFFICE_VLANS, (900, "guest", 0)]
        }
        vlans: dict[tuple[str, int], str] = {}
        for dev in cores + access:
            for vid, name, _t in [*OFFICE_VLANS, (900, "guest", 0)]:
                if dev in access and name == "fw-transit":
                    continue
                vl = g.node("VlanInstance", f"vlan:{dev}:{vid}", vid=vid, name=name)
                vlans[(dev, vid)] = vl
                g.rel("REALIZES", vl, segs[name])
        for i, core in enumerate(cores):
            for vid, name, third in OFFICE_VLANS:
                svi = g.iface(core, f"vlan{vid}", f"vlan{vid}", "svi", vlan=vid)
                g.rel("BOUND_TO", svi, vlans[(core, vid)])
                g.rel("IN_VRF", svi, vrf_corp[i])
                vip_addr = f"{base}.{third}.1"
                fhrp = g.node(
                    "FhrpGroup",
                    f"fhrp:hsrp:{code}-{name}:{vip_addr}",
                    kind="hsrp",
                    group_id=vid,
                    vip=vip_addr,
                )
                vip_ip = g.ip("corp", vip_addr, pfx[name])
                g.rel(
                    "MEMBER_OF",
                    svi,
                    fhrp,
                    props={"priority": 110 if i == 0 else 90, "state": "active" if i == 0 else "standby"},
                )
                g.rel(
                    "HAS_IP",
                    svi,
                    vip_ip,
                    props={"fhrp": "hsrp", "group": vid, "state": "active" if i == 0 else "standby"},
                )
                g.rel("HAS_IP", svi, g.ip("corp", f"{base}.{third}.{2 + i}", pfx[name], anchor=vrf_corp[i]))
                if i == 0:
                    g.rel("GATEWAY_FOR", fhrp, pfx[name])
                    g.rel("HAS_IP", fhrp, vip_ip)
            gsvi = g.iface(core, "vlan900", "vlan900", "svi", vlan=900)
            g.rel("BOUND_TO", gsvi, vlans[(core, 900)])
            g.rel("IN_VRF", gsvi, vrf_guest[i])
            lo = g.iface(core, "lo0", "loopback0", "loopback")
            g.rel("IN_VRF", lo, vrf_corp[i])
            g.rel("HAS_IP", lo, g.ip("corp", f"{base}.255.{1 + i}", lo_pfx))
        # named hosts in the office
        for name, third, host in (
            ("file-01", 40, 11),
            ("dhcp-01", 40, 12),
            ("print-01", 30, 21),
            ("print-02", 30, 22),
            ("badge-01", 40, 31),
        ):
            g.ip(
                "corp",
                f"{base}.{third}.{host}",
                pfx[{40: "servers", 30: "printers"}[third]],
                name=f"{code}-{name}",
            )

        # cabling: core pair, core-access trunks, firewall, edge, controller
        g.sec(f"{code} cabling")
        c1p1 = g.port(cores[0], ifshort(1), ifname(1), 10000)
        c2p1 = g.port(cores[1], ifshort(1), ifname(1), 10000)
        g.cable(c1p1, c2p1)
        core_if = [g.iface(cores[i], ifshort(1), ifname(1), "phys", port=(c1p1, c2p1)[i]) for i in range(2)]
        for i in range(2):
            g.rel("IN_VRF", core_if[i], vrf_corp[i])
            g.rel("CARRIES", (c1p1, c2p1)[i], vlans[(cores[i], 10)])
        trunk_vids = (10, 20, 30, 99, 900)
        for k, acc in enumerate(access, start=1):
            for i, core in enumerate(cores):
                cp = g.port(core, ifshort(10 + k), ifname(10 + k), 10000)
                ap = g.port(acc, f"te1-1-{i + 1}", f"TenGigabitEthernet1/1/{i + 1}", 10000)
                g.cable(cp, ap)
                for vid in trunk_vids:
                    g.rel("CARRIES", cp, vlans[(core, vid)])
                    g.rel("CARRIES", ap, vlans[(acc, vid)])
        fp1 = g.port(fgt, "port1", "port1", 10000)
        fp2 = g.port(fgt, "port2", "port2", 10000)
        fp3 = g.port(fgt, "port3", "port3", 1000)
        g.cable(g.port(cores[0], ifshort(3), ifname(3), 10000), fp1)
        g.cable(g.port(cores[1], ifshort(3), ifname(3), 10000), fp2)
        g.rel("CARRIES", f"{cores[0]}/port/{ifshort(3)}", vlans[(cores[0], 250)])
        g.rel("CARRIES", f"{cores[1]}/port/{ifshort(3)}", vlans[(cores[1], 900)])
        vp2 = g.port(vce, "ge2", "ge2", 1000)
        vp3 = g.port(vce, "ge3", "ge3", 1000)
        g.cable(fp3, vp2)
        wp = g.port(wlc, "te0-0-0", "TenGigabitEthernet0/0/0", 10000)
        g.cable(g.port(cores[1], ifshort(4), ifname(4), 10000), wp)
        for vid in (10, 900):
            g.rel("CARRIES", f"{cores[1]}/port/{ifshort(4)}", vlans[(cores[1], vid)])
        fi1 = g.iface(fgt, "port1", "port1", "phys", port=fp1)
        fi2 = g.iface(fgt, "port2", "port2", "phys", port=fp2)
        fi3 = g.iface(fgt, "port3", "port3", "phys", port=fp3)
        for fi in (fi1, fi2, fi3):
            g.rel("IN_VRF", fi, vrf_fgt)
        # FortiGate addressing: port1 on the core transit VLAN, port2 the guest gateway, port3 a
        # routed /30 to the SD-WAN edge. Default and corp routes toward the edge, the office
        # aggregate back to the core HSRP address.
        edge_pfx = g.prefix(
            "corp", f"{base}.251.0/30", "connected", f"{code}-fw-edge", anchor=vrf_fgt, parent=agg
        )
        self.office_edge[code] = edge_pfx
        g.connected(vrf_fgt, fi1, f"{base}.250.6", pfx["fw-transit"], gateway=False)
        g.connected(
            vrf_fgt, fi2, f"172.31.{n}.1", guest_pfx, l3dom="guest", gateway=False
        )  # the reasoner derives it (sole firewall interface)
        fgt_edge_ip = g.connected(vrf_fgt, fi3, f"{base}.251.1", edge_pfx, gateway=False)
        g.route(vrf_fgt, self.corp_default, "STATIC_ROUTE", next_hop=f"{base}.251.2", iface=fi3)
        g.route(vrf_fgt, self.corp_super, "STATIC_ROUTE", next_hop=f"{base}.251.2", iface=fi3)
        g.route(vrf_fgt, agg, "STATIC_ROUTE", next_hop=f"{base}.250.1", iface=fi1)
        # the core routers: the office VLANs connected, everything else via the FortiGate
        for i, vrf in enumerate(vrf_corp):
            svi250 = f"{cores[i]}/if/vlan250"
            g.route(
                vrf, self.corp_super, "LEARNED_ROUTE", next_hop=f"{base}.250.6", iface=svi250, protocol="ospf"
            )
            g.route(
                vrf,
                self.corp_default,
                "LEARNED_ROUTE",
                next_hop=f"{base}.250.6",
                iface=svi250,
                protocol="ospf",
            )
        # SD-WAN edge: ge2 toward the firewall, ge3 the WAN side, one overlay /30 per data center hub
        vce_vrf = g.vrf(
            f"vrf:dev:{code}-vce-01:corp", "corp", self.rdom["corp"], kind="sdwan-segment", table_id=1
        )
        vi3 = g.iface(vce, "ge3", "ge3", "phys", port=vp3)
        vi2 = g.iface(vce, "ge2", "ge2", "phys", port=vp2)
        g.rel("IN_VRF", vi3, vce_vrf)
        g.connected(vce_vrf, vi2, f"{base}.251.2", edge_pfx, gateway=False)
        g.route(vce_vrf, agg, "STATIC_ROUTE", next_hop=f"{base}.251.1", iface=vi2)
        g.route(vce_vrf, self.corp_default, "STATIC_ROUTE", iface=vi3)
        overlay_anchor = self.sdwan_seg
        for k, dc in enumerate(DCS):
            dcode = dc["code"]
            hub = f"dev:{dcode}-vch-01"
            ov_pfx = g.prefix(
                "corp", f"10.254.{n}.{4 * k}/30", "connected", f"sdwan-{code}-{dcode}", anchor=overlay_anchor
            )
            ti = g.iface(
                vce, f"vcmp-{dcode}", f"vcmp-{dcode}", "tunnel", description=f"VCMP overlay to {dcode}-vch-01"
            )
            hti = g.iface(
                hub, f"vcmp-{code}", f"vcmp-{code}", "tunnel", description=f"VCMP overlay to {code}-vce-01"
            )
            g.connected(vce_vrf, ti, f"10.254.{n}.{4 * k + 1}", ov_pfx, gateway=False)
            g.connected(self.hub_vrf[dcode], hti, f"10.254.{n}.{4 * k + 2}", ov_pfx, gateway=False)
            g.route(
                vce_vrf,
                self.dc_agg[dcode],
                "LEARNED_ROUTE",
                next_hop=f"10.254.{n}.{4 * k + 2}",
                iface=ti,
                protocol="sdwan",
            )
            g.route(
                self.hub_vrf[dcode],
                agg,
                "LEARNED_ROUTE",
                next_hop=f"10.254.{n}.{4 * k + 1}",
                iface=hti,
                protocol="sdwan",
            )
            if dcode == "dc1":
                # the Frankfurt hub is the exit for the other offices, the colo and AWS
                for target in (
                    self.corp_super,
                    self.rp("10.72.0.0/16", "eqx-fr5"),
                    self.rp("10.64.0.0/16", "aws-prod"),
                ):
                    g.route(
                        vce_vrf,
                        target,
                        "LEARNED_ROUTE",
                        next_hop=f"10.254.{n}.{4 * k + 2}",
                        iface=ti,
                        protocol="sdwan",
                    )
            else:
                # the Munich hub is the exit for Azure (ExpressRoute lands on the second colo border)
                targets = [self.rp("10.80.0.0/16", "az-gwc")] + (
                    [self.rp("10.81.0.0/16", "az-weu")] if v >= 3 else []
                )
                for target in targets:
                    g.route(
                        vce_vrf,
                        target,
                        "LEARNED_ROUTE",
                        next_hop=f"10.254.{n}.{4 * k + 2}",
                        iface=ti,
                        protocol="sdwan",
                    )
        # wireless
        ssid_corp = g.node("Ssid", f"ssid:{code}:corp", name="Norlund-Corp", security="wpa2-enterprise")
        ssid_guest = g.node("Ssid", f"ssid:{code}:guest", name="Norlund-Guest", security="open-portal")
        g.rel("BRIDGED_TO", ssid_corp, vlans[(cores[0], 10)])
        g.rel("BRIDGED_TO", ssid_guest, vlans[(cores[0], 900)])

        # routing: OSPF between the cores, EVPN overlay to the data center borders
        g.sec(f"{code} routing")
        area = g.node("OspfArea", f"ospf:{code}:area-0", area_id="0.0.0.0")  # noqa: S104 - an OSPF area id, not a bind address
        for ci in core_if:
            g.rel("IN_AREA", ci, area)
        adj = g.node("OspfAdjacency", f"ospf:adj:{code}-core-01~{code}-core-02", state="full", area="0.0.0.0")  # noqa: S104 - an OSPF area id
        for ci in core_if:
            g.rel("ENDPOINT", adj, ci)
        for i, _vrf in enumerate(vrf_corp):
            dc = "dc1" if i == 0 else "dc2"
            peer = self.border_lo[dc]
            sess = g.node(
                "BgpSession",
                f"bgp:dev:{code}-core-0{i + 1}~{g.nodes[peer][1]['ip']}:corp",
                local_asn=65001,
                peer_asn=65001,
                afi_safi=["l2vpn-evpn"],
                kind="overlay",
                state="established",
            )
            g.rel("ENDPOINT", sess, f"ip:corp:{base}.255.{1 + i}")
            g.rel("ENDPOINT", sess, peer)

        # FortiGate policy: guest to corp dns, guest to internet, corp mgmt to guest, source NAT
        g.sec(f"{code} FortiGate policy")
        fgid = f"fgt:{g.nodes[fgt][1]['serial']}:root"
        zones = {z: g.node("Zone", f"{fgid}:zone:{z}", name=z) for z in ("guest", "corp", "wan")}
        for z, fi in (("corp", fi1), ("guest", fi2), ("wan", fi3)):
            g.rel("CONTAINS", zones[z], fi)
        obj_guest = g.node("NetObject", f"{fgid}:addr:guest-net", name="guest-net", kind="network")
        g.rel("RESOLVES_TO", obj_guest, guest_pfx)
        obj_dns = g.node("NetObject", f"{fgid}:addr:corp-dns", name="corp-dns", kind="host")
        g.rel("RESOLVES_TO", obj_dns, self.dns_vip["dc1"])
        obj_mgmt = g.node("NetObject", f"{fgid}:addr:mgmt-net", name="mgmt-net", kind="network")
        g.rel("RESOLVES_TO", obj_mgmt, pfx["mgmt"])
        obj_inet = g.node("NetObject", f"{fgid}:addr:internet", name="internet", kind="network")
        g.rel("RESOLVES_TO", obj_inet, self.guest_default)
        svc = {
            p: g.node("SvcObject", f"{fgid}:svc:{nm}", name=nm, proto=pr, ports=str(p))
            for p, nm, pr in (
                (53, "DNS", "udp"),
                (443, "HTTPS", "tcp"),
                (80, "HTTP", "tcp"),
                (22, "SSH", "tcp"),
                (631, "IPP", "tcp"),
            )
        }
        # the predefined FortiOS service ALL (protocol IP, number 0): every protocol and port.
        # FortiOS policies always name a service. A rule on ALL also carries svc_any, the graph
        # convention the collectors write for a rule that matches every service
        svc_all = g.node("SvcObject", f"{fgid}:svc:ALL", name="ALL", proto="all")
        obj_printers = g.node("NetObject", f"{fgid}:addr:printers-net", name="printers-net", kind="network")
        g.rel("RESOLVES_TO", obj_printers, pfx["printers"])

        def rulebase(name: str, kind: str, src_zone: str, dst_zone: str, rules: list[tuple]) -> str:
            # match_context zone-pair: the rulebase receives only the flows that enter through an
            # interface of its source zone and leave through one of its destination zone
            rb = g.node(
                "FwRulebase",
                f"{fgid}:policy:{name}",
                name=f"{code}-{name}",
                kind=kind,
                vendor="fortinet",
                default_action="drop",
                match_context="zone-pair",
            )
            g.rel("ENFORCES", fgt, rb)
            g.rel("FROM_ZONE", rb, zones[src_zone])
            g.rel("TO_ZONE", rb, zones[dst_zone])
            for pos, (rid, rname, srcs, dsts, svcs, action) in enumerate(rules, start=1):
                r = g.node(
                    "FwRule",
                    f"{fgid}:policy:{rid}",
                    name=rname,
                    position=pos,
                    action=action,
                    enabled=True,
                    rule_uid=str(rid),
                    svc_any=True if svcs == [svc_all] else None,
                )
                g.rel("HAS_RULE", rb, r)
                for s in srcs:
                    g.rel("SRC", r, s)
                for d in dsts:
                    g.rel("DST", r, d)
                for s in svcs:
                    g.rel("SVC", r, s)
            return rb

        obj_office = g.node("NetObject", f"{fgid}:addr:office-net", name="office-net", kind="network")
        g.rel("RESOLVES_TO", obj_office, agg)
        obj_dc = g.node("NetObject", f"{fgid}:addr:dc-networks", name="dc-networks", kind="group")
        for dc_agg in self.dc_agg.values():
            g.rel("RESOLVES_TO", obj_dc, dc_agg)
        obj_corp = g.node("NetObject", f"{fgid}:addr:corp-networks", name="corp-networks", kind="network")
        g.rel("RESOLVES_TO", obj_corp, self.corp_super)
        rulebase(
            "guest-corp",
            "access",
            "guest",
            "corp",
            [(1, "guest-to-printers", [obj_guest], [obj_printers], [svc[631]], "accept")],
        )
        guest_internet = [
            (10, "guest-to-dns", [obj_guest], [obj_dns], [svc[53]], "accept"),
            (2, "guest-web", [obj_guest], [obj_inet], [svc[80], svc[443]], "accept"),
            (3, "guest-deny-rest", [obj_guest], [obj_inet], [svc_all], "drop"),
        ]
        if code == "vie01":
            # a leftover rule that guest-web shadows completely: every flow it matches is taken by
            # the earlier rule, so no flow arrives at it
            guest_internet.insert(
                2, (11, "guest-https-legacy", [obj_guest], [obj_inet], [svc[443]], "accept")
            )
        rulebase("guest-internet", "access", "guest", "wan", guest_internet)
        rulebase(
            "corp-guest",
            "access",
            "corp",
            "guest",
            [(4, "mgmt-to-guest-ssh", [obj_mgmt], [obj_guest], [svc[22]], "accept")],
        )
        # the corp side toward the SD-WAN: office networks reach the data centers and the other
        # corp networks on any service, the internet on web ports; the data centers reach the office
        rulebase(
            "corp-wan",
            "access",
            "corp",
            "wan",
            [
                (5, "office-to-corp", [obj_office], [obj_corp], [svc_all], "accept"),
                (6, "office-web", [obj_office], [obj_inet], [svc[80], svc[443]], "accept"),
                (7, "office-deny-rest", [obj_office], [obj_inet], [svc_all], "drop"),
            ],
        )
        rulebase(
            "wan-corp",
            "access",
            "wan",
            "corp",
            [
                (8, "dc-to-office", [obj_dc], [obj_office], [svc_all], "accept"),
                (9, "wan-deny-rest", [obj_corp], [obj_office], [svc_all], "drop"),
            ],
        )
        nat_rb = g.node("FwRulebase", f"{fgid}:policy:nat", name=f"{code}-nat", kind="nat", vendor="fortinet")
        g.rel("ENFORCES", fgt, nat_rb)
        # the NAT stage reads the original and translated addresses from the edge targets
        nat = g.node(
            "NatRule", f"{fgid}:ippool:guest-snat", name="guest-snat", kind="snat", position=1, out_if="port3"
        )
        g.rel("HAS_RULE", nat_rb, nat)
        g.rel("ORIG_SRC", nat, guest_pfx)
        g.rel("XLATE_SRC", nat, fgt_edge_ip)
        g.rel(
            "INTERCONNECTED_BY",
            self.rdom["guest"],
            fgt,
            props={"derived": True, "rule": "fixture-demo", "kind": "firewall"},
        )
        g.rel(
            "INTERCONNECTED_BY",
            self.rdom["corp"],
            fgt,
            props={"derived": True, "rule": "fixture-demo", "kind": "firewall"},
        )

        # SD-WAN edge: two WAN links, tunnels to the regional gateway and to the DC hubs
        g.sec(f"{code} SD-WAN")
        vco = f"vco:{ORG}"
        mpls = g.node(
            "WanLink",
            f"{vco}:link:{code}-mpls",
            name=f"{code}-mpls",
            kind="mpls",
            bandwidth_mbps=100 if n % 2 else 200,
            carrier="Velorum Networks",
        )
        dia = g.node(
            "WanLink",
            f"{vco}:link:{code}-dia",
            name=f"{code}-dia",
            kind="dia",
            bandwidth_mbps=300 if n % 2 else 500,
            carrier=g.nodes[self.provider[o["dia"]]][1]["name"],
        )
        g.rel("ON", mpls, f"{vce}/if/ge3")
        g.rel("ON", dia, f"{vce}/if/ge3")
        g.rel("HAS_LINK", vce, mpls)
        g.rel("HAS_LINK", vce, dia)
        g.rel("PROVIDED_BY", mpls, self.pnet["velorum"])
        g.rel("PROVIDED_BY", dia, self.pnet[o["dia"]])
        gw = self.sdwan_gw[o["pop"]]
        tun = g.node("Tunnel", f"tun:velocloud-vcmp:{vce}~{gw}", encap="velocloud-vcmp", state="up")
        g.rel("ENDPOINT", tun, f"{vce}/if/ge3")
        g.rel("TERMINATES_ON", tun, gw)
        g.rel("CARRIES", tun, self.sdwan_seg)
        g.rel("CARRIES", tun, self.sdwan_guest_seg)
        for dc in DCS:
            hub = f"dev:{dc['code']}-vch-01"
            htun = g.node("Tunnel", f"tun:velocloud-vcmp:{vce}~{hub}", encap="velocloud-vcmp", state="up")
            g.rel("ENDPOINT", htun, f"{vce}/if/ge3")
            g.rel("TERMINATES_ON", htun, hub)
            g.rel("CARRIES", htun, self.sdwan_seg)
        # the MPLS preference of the voice and DC policies is the policy's `action`
        g.rel("MATCHES", self.bizpol["voice"], pfx["voice"])

        # Zscaler ZIA location with a GRE tunnel to the nearest DC and FRA4 as fallback
        g.sec(f"{code} Zscaler ZIA")
        zia = f"zia:{ORG}"
        loc = g.node(
            "ZiaLocation",
            f"{zia}:loc:90{n}",
            name=f"{code}-guest",
            zia_id=f"90{n}",
            egress_ips=[f"198.51.100.{n}"],
            country="EU",
        )
        g.rel("REPRESENTS", loc, site)
        gre = g.node("Tunnel", f"{zia}:gre:93{n}", encap="gre", source_ip=f"198.51.100.{n}")
        g.rel("USES", loc, gre)
        g.rel(
            "TERMINATES_ON", gre, self.zdc[o["zdc"]], key={"role": "primary"}, props={"vip": f"203.0.113.{n}"}
        )
        g.rel("TERMINATES_ON", gre, self.zdc["FRA4"], key={"role": "secondary"}, props={"vip": "203.0.113.4"})
        g.rel("MEMBER_OF", loc, self.zia_locgrp)

    # ---------------------------------------------------------------------- colo ---
    def colo(self) -> None:
        g = self.g
        g.sec("Equinix FR5 colo site")
        site = g.node(
            "Site", "site:eqx-fr5", code="eqx-fr5", name="Equinix FR5", kind="colo", criticality="high"
        )
        self.colo_site = site
        g.rel("SERVED_BY", site, self.pnet["velorum"])
        base = "10.72"
        agg = g.prefix("corp", f"{base}.0.0/16", "aggregate", "eqx-fr5", parent=self.corp_super)
        lo_pfx = g.prefix("corp", f"{base}.255.0/24", "connected", "eqx-fr5-loopbacks", parent=agg)
        transit = g.prefix("corp", f"{base}.1.0/24", "connected", "eqx-fr5-core-border", parent=agg)
        cores = [
            g.device(site, f"fr5-core-0{i}", "nxos", "router", "cisco", "FDO", f"{base}.0.{10 + i}")
            for i in (1, 2)
        ]
        borders = [
            g.device(site, f"fr5-border-0{i}", "iosxe", "router", "cisco", "FXS", f"{base}.0.{20 + i}")
            for i in (1, 2)
        ]
        vpc = g.node(
            "RedundancyGroup",
            "rgrp:vpc:nxos-fr5:100",
            kind="vpc",
            name="fr5-core-vpc-100",
            domain_id=100,
            peer_link="port-channel1",
        )
        g.rel("MEMBER_OF", cores[0], vpc, props={"role": "primary"})
        g.rel("MEMBER_OF", cores[1], vpc, props={"role": "secondary"})
        g.cable(
            g.port(cores[0], "eth1-47", "ethernet1/47", 100000),
            g.port(cores[1], "eth1-47", "ethernet1/47", 100000),
            role="vpc-peer-link",
        )
        self.colo_border_ports = []
        for i, (core, br) in enumerate(zip(cores, borders, strict=False)):
            cvrf = g.vrf(f"vrf:dev:fr5-core-0{i + 1}:corp", "corp", self.rdom["corp"])
            bvrf = g.vrf(f"vrf:dev:fr5-border-0{i + 1}:corp", "corp", self.rdom["corp"])
            cp = g.port(core, "eth1-1", "ethernet1/1", 10000)
            bp = g.port(br, "gi0-0-0", "GigabitEthernet0/0/0", 10000)
            g.cable(cp, bp)
            ci = g.iface(core, "eth1-1", "ethernet1/1", "phys", port=cp)
            bi = g.iface(br, "gi0-0-0", "GigabitEthernet0/0/0", "phys", port=bp)
            g.rel("IN_VRF", ci, cvrf)
            g.rel("IN_VRF", bi, bvrf)
            g.rel("HAS_IP", ci, g.ip("corp", f"{base}.1.{1 + 4 * i}", transit))
            g.rel("HAS_IP", bi, g.ip("corp", f"{base}.1.{2 + 4 * i}", transit))
            lo = g.iface(br, "lo0", "Loopback0", "loopback")
            g.rel("IN_VRF", lo, bvrf)
            lo_ip = g.ip("corp", f"{base}.255.{1 + i}", lo_pfx)
            g.rel("HAS_IP", lo, lo_ip)
            g.rel("ORIGINATES", bvrf, agg, props={"proto": "aggregate"})
            g.rel("IMPORTS", bvrf, self.rt())
            g.rel("EXPORTS", bvrf, self.rt())
            fab_port = g.port(br, "te0-1-0", "TenGigabitEthernet0/1/0", 10000)
            self.colo_border_ports.append((br, bvrf, fab_port))
            # wan link toward both data centers over the overlay
            peer = self.border_lo["dc1" if i == 0 else "dc2"]
            sess = g.node(
                "BgpSession",
                f"bgp:dev:fr5-border-0{i + 1}~{g.nodes[peer][1]['ip']}:corp",
                local_asn=65001,
                peer_asn=65001,
                afi_safi=["l2vpn-evpn"],
                kind="overlay",
                state="established",
            )
            g.rel("ENDPOINT", sess, lo_ip)
            g.rel("ENDPOINT", sess, peer)
        self.colo_borders = borders

    # ----------------------------------------------------------------------- AWS ---
    def aws(self) -> None:
        g = self.g
        g.sec("AWS eu-central-1")
        acct = "210987654321"
        arn = f"aws:arn:aws:ec2:eu-central-1:{acct}"
        site = g.node(
            "Site",
            "site:aws-eu-central-1",
            code="aws-eu-central-1",
            name="AWS eu-central-1",
            kind="cloud-region",
        )
        org = g.node("Organization", f"aws:org:o-{ORG}7f3k", name=ORG)
        account = g.node("Account", f"aws:acct:{acct}", name="prod-network")
        g.rel("IN_ORG", account, org)
        g.rel("PROVIDED_BY", account, self.provider["aws"])
        region = g.node("Region", "aws:region:eu-central-1", name="eu-central-1")
        g.rel("REALIZES", region, site)
        vpc = g.node("Vpc", f"{arn}:vpc/vpc-0prod", name="prod", cidr="10.64.0.0/16")
        g.rel("IN_ACCOUNT", vpc, account)
        g.rel("IN_REGION", vpc, region)
        g.rel("MEMBER_OF", vpc, self.rdom["aws-prod"], props={"basis": "declared"})
        agg = g.prefix("aws-prod", "10.64.0.0/16", "aggregate", "aws-prod")
        tgw = g.node("Tgw", f"{arn}:transit-gateway/tgw-0hub", name="eu-hub", asn=64512)
        tgw_rt = g.node("TgwRouteTable", f"{arn}:transit-gateway-route-table/tgw-rtb-0main", name="main")
        att = g.node("TgwAttachment", f"{arn}:transit-gateway-attachment/tgw-attach-0vpc", kind="vpc")
        g.rel("PART_OF", att, tgw)
        g.rel("OF", att, vpc)
        g.rel("ASSOCIATED", att, tgw_rt)
        g.rel("PROPAGATES", att, tgw_rt)
        rtb = g.node("RouteTable", f"{arn}:route-table/rtb-0main", name="prod-main")
        route = g.node("CloudRoute", f"{rtb}/route/10.0.0.0-8", dest="10.0.0.0/8", state="active")
        g.rel("HAS_ROUTE", rtb, route)
        g.rel("FOR", route, self.corp_super)
        g.rel("VIA", route, tgw)
        sgs = {}
        for name, port, src in (("web", 443, self.corp_super), ("app", 8443, None)):
            sg = g.node(
                "FwRulebase", f"{arn}:security-group/sg-0{name}", name=f"{name}-sg", kind="sg", vendor="aws"
            )
            rule = g.node(
                "FwRule",
                f"aws:sg:sg-0{name}:ingress:{port}",
                position=1,
                action="accept",
                name=f"tcp-{port}-ingress",
                rule_uid=f"sgr-0{name}{port}",
            )
            g.rel("HAS_RULE", sg, rule)
            obj = g.node(
                "NetObject",
                f"aws:obj:{'corp-super' if src else 'web-subnets'}",
                name="corp-supernet" if src else "web-subnets",
                kind="network",
            )
            g.rel("SRC", rule, obj)
            g.rel("RESOLVES_TO", obj, src or agg)
            svc = g.node("SvcObject", f"aws:svc:tcp-{port}", name=f"tcp-{port}", proto="tcp", ports=str(port))
            g.rel("SVC", rule, svc)
            sgs[name] = sg
        subnets = (
            ("web-a", "eu-central-1a", 1, "web"),
            ("web-b", "eu-central-1b", 2, "web"),
            ("app-a", "eu-central-1a", 11, "app"),
            ("app-b", "eu-central-1b", 12, "app"),
        )
        instances = {
            "web-a": ("webshop-origin-01", ("webshop", "cdn-origin")),
            "web-b": ("webshop-origin-02", ("webshop", "cdn-origin")),
            "app-a": ("dwh-ingest-01", ("dwh", "etl")),
            "app-b": ("dwh-ingest-02", ("dwh", "etl")),
        }
        self.aws_ips = {}
        for name, az, third, tier in subnets:
            sn = g.node("Subnet", f"{arn}:subnet/subnet-0{name}", name=name, az=az)
            g.rel("PART_OF", sn, vpc)
            pfx = g.prefix("aws-prod", f"10.64.{third}.0/24", "cloud-subnet", name, parent=agg)
            g.rel("REALIZES", sn, pfx)
            g.rel("ASSOCIATED", rtb, sn)
            inst_name, comp = instances[name]
            inst = g.node("Instance", f"{arn}:instance/i-0{inst_name}", name=inst_name, type="m6i.large")
            eni = g.node("Eni", f"{arn}:network-interface/eni-0{inst_name}")
            g.rel("OF", eni, inst)
            g.rel("PROTECTED_BY", eni, sgs[tier])
            ipu = g.ip("aws-prod", f"10.64.{third}.10", pfx, name=inst_name)
            g.rel("HAS_IP", eni, ipu)
            g.rel("PART_OF", inst, self.app_component[comp])
            self.aws_ips[inst_name] = ipu
        # Direct Connect at Equinix FR5, BGP from the colo border
        dxcon = g.node(
            "DxConnection",
            f"aws:arn:aws:directconnect:eu-central-1:{acct}:dxcon/dxcon-0fr5",
            name="fr5-primary",
            bandwidth="1Gbps",
        )
        dxvif = g.node(
            "DxVif",
            f"aws:arn:aws:directconnect:eu-central-1:{acct}:dxvif/dxvif-0corp",
            vlan=100,
            kind="transit",
        )
        dxgw = g.node(
            "DxGw", f"aws:arn:aws:directconnect::{acct}:dx-gateway/dxgw-0corp", name="corp-dxgw", asn=64512
        )
        g.rel("PART_OF", dxvif, dxcon)
        g.rel("TERMINATES_ON", dxvif, dxgw)
        g.rel("ASSOCIATED", dxgw, tgw)
        self.dxcon = dxcon
        br, bvrf, _ = self.colo_border_ports[0]
        peer_pfx_corp = g.prefix("corp", "192.0.2.0/30", "service", "dx-peering")
        peer_pfx_aws = g.prefix("aws-prod", "192.0.2.0/30", "service", "dx-peering")
        sub = g.iface(br, "te0-1-0-100", "TenGigabitEthernet0/1/0.100", "subif")
        g.rel("IN_VRF", sub, bvrf)
        local = g.ip("corp", "192.0.2.1", peer_pfx_corp, anchor=bvrf)
        remote = g.ip("aws-prod", "192.0.2.2", peer_pfx_aws)
        g.rel("HAS_IP", sub, local)
        sess = g.node(
            "BgpSession",
            f"bgp:{br}~192.0.2.2:corp",
            local_asn=65001,
            peer_asn=64512,
            afi_safi=["ipv4-unicast"],
            kind="cloud",
            state="established",
        )
        g.rel("ENDPOINT", sess, local)
        g.rel("ENDPOINT", sess, remote)

    # --------------------------------------------------------------------- Azure ---
    def azure(
        self, code: str, name: str, location: str, base: str, rdom: str, er_name: str, tag: str
    ) -> None:
        g = self.g
        g.sec(f"Azure {name}")
        sub_id = "3c1f2a84-0000-4000-8000-0000000000a1"
        subp = f"az:/subscriptions/{sub_id}"
        site = g.node("Site", f"site:{code}", code=code, name=name, kind="cloud-region")
        subscription = g.node("Subscription", subp, name="prod-network")
        g.rel("PROVIDED_BY", subscription, self.provider["azure"])
        rg = f"{subp}/resourcegroups/rg-prod-{tag}/providers/microsoft.network"
        rgc = f"{subp}/resourcegroups/rg-prod-{tag}/providers/microsoft.compute"
        rgn = f"{subp}/resourcegroups/rg-net-{tag}/providers/microsoft.network"
        vnet = g.node(
            "VNet", f"{rg}/virtualnetworks/vnet-prod-{tag}", name=f"vnet-prod-{tag}", cidr=f"{base}.0.0/16"
        )
        g.rel("PART_OF", vnet, subscription)
        g.rel("LOCATED_IN", vnet, site)
        g.rel("MEMBER_OF", vnet, self.rdom[rdom], props={"basis": "declared"})
        agg = g.prefix(rdom, f"{base}.0.0/16", "aggregate", f"{code}")
        vgw = g.node(
            "VNetGw", f"{rgn}/virtualnetworkgateways/vgw-er-{tag}", name=f"vgw-er-{tag}", kind="expressroute"
        )
        g.rel("PART_OF", vgw, vnet)
        er = g.node("ErCircuit", f"{rgn}/expressroutecircuits/{er_name}", name=er_name, bandwidth_mbps=1000)
        g.rel("TERMINATES_ON", er, vgw)
        self.er_circuits = getattr(self, "er_circuits", {})
        self.er_circuits[code] = er
        rt = g.node("RouteTable", f"{rg}/routetables/rt-{tag}", name=f"rt-{tag}")
        route = g.node(
            "CloudRoute",
            f"az:rt:rt-{tag}/route/to-onprem",
            dest="10.0.0.0/8",
            next_hop_type="VirtualNetworkGateway",
        )
        g.rel("HAS_ROUTE", rt, route)
        g.rel("FOR", route, self.corp_super)
        g.rel("VIA", route, vgw)
        obj = g.node("NetObject", f"az:obj:{tag}:corp-super", name="corp-supernet", kind="network")
        g.rel("RESOLVES_TO", obj, self.corp_super)
        vms = {
            "gwc": [
                ("snet-web", 1, "az-dwh-report-01", ("dwh", "reporting")),
                ("snet-web", 1, "az-dwh-report-02", ("dwh", "reporting")),
                ("snet-data", 2, "az-intranet-search-01", ("intranet", "search")),
            ],
            "weu": [
                ("snet-web", 1, "az-claims-dr-01", ("claims", "dr")),
                ("snet-data", 2, "az-claims-dr-02", ("claims", "dr")),
            ],
        }[tag]
        self.az_ips = getattr(self, "az_ips", {})
        for sname, third, port in (("snet-web", 1, 443), ("snet-data", 2, 5432)):
            sn = g.node("Subnet", f"{vnet}/subnets/{sname}", name=sname)
            g.rel("PART_OF", sn, vnet)
            pfx = g.prefix(rdom, f"{base}.{third}.0/24", "cloud-subnet", f"{code}-{sname}", parent=agg)
            g.rel("REALIZES", sn, pfx)
            g.rel("ASSOCIATED", rt, sn)
            nsg = g.node(
                "FwRulebase",
                f"{rg}/networksecuritygroups/nsg-{sname}",
                name=f"nsg-{sname}-{tag}",
                kind="nsg",
                vendor="azure",
            )
            g.rel("PROTECTED_BY", sn, nsg)
            rule = g.node(
                "FwRule",
                f"az:nsg:{tag}:nsg-{sname}:rule:allow-corp-{port}",
                position=100,
                action="accept",
                name=f"allow-corp-{port}",
                rule_uid=f"allow-corp-{port}",
            )
            g.rel("HAS_RULE", nsg, rule)
            g.rel("SRC", rule, obj)
            svc = g.node("SvcObject", f"az:svc:tcp-{port}", name=f"tcp-{port}", proto="tcp", ports=str(port))
            g.rel("SVC", rule, svc)
            for i, (_vs, _t, vm_name, comp) in enumerate(v for v in vms if v[0] == sname):
                vm = g.node("Vm", f"{rgc}/virtualmachines/{vm_name}", name=vm_name)
                nic = g.node("Nic", f"{rg}/networkinterfaces/nic-{vm_name}")
                g.rel("OF", nic, vm)
                ipu = g.ip(rdom, f"{base}.{third}.{10 + i}", pfx, name=vm_name)
                g.rel("HAS_IP", nic, ipu)
                g.rel("PART_OF", vm, self.app_component[comp])
                self.az_ips[vm_name] = ipu
        # ExpressRoute peering from the second colo border
        br, bvrf, _ = self.colo_border_ports[1]
        third = {"gwc": 4, "weu": 8}[tag]
        peer_pfx_corp = g.prefix("corp", f"192.0.2.{third}/30", "service", f"er-peering-{tag}")
        peer_pfx_az = g.prefix(rdom, f"192.0.2.{third}/30", "service", f"er-peering-{tag}")
        vlan = {"gwc": 200, "weu": 201}[tag]
        sub = g.iface(br, f"te0-1-0-{vlan}", f"TenGigabitEthernet0/1/0.{vlan}", "subif")
        g.rel("IN_VRF", sub, bvrf)
        local = g.ip("corp", f"192.0.2.{third + 1}", peer_pfx_corp, anchor=bvrf)
        remote = g.ip(rdom, f"192.0.2.{third + 2}", peer_pfx_az)
        g.rel("HAS_IP", sub, local)
        sess = g.node(
            "BgpSession",
            f"bgp:{br}~192.0.2.{third + 2}:corp",
            local_asn=65001,
            peer_asn=12076,
            afi_safi=["ipv4-unicast"],
            kind="cloud",
            state="established",
        )
        g.rel("ENDPOINT", sess, local)
        g.rel("ENDPOINT", sess, remote)

    def equinix_circuits(self) -> None:
        g = self.g
        g.sec("Equinix Fabric ports and virtual circuits")
        ports = []
        for i, (_br, _vrf, fab_port) in enumerate(self.colo_border_ports, start=1):
            fp = g.node(
                "FabricPort",
                f"eqx:port:fr5-00000000-0000-000{i}",
                name=f"fr5-fabric-10g-{i}",
                speed="10g",
                bound_port_uid=fab_port,
            )
            g.rel("LOCATED_IN", fp, self.colo_site)
            g.rel("REALIZED_BY", fp, fab_port)
            ports.append(fp)
        circuits = [("fr5-to-aws", ports[0], self.dxcon, 100)]
        for code, er in self.er_circuits.items():
            circuits.append((f"fr5-to-{code}", ports[1], er, 200 if code == "az-gwc" else 201))
        for i, (name, a_end, z_end, vlan) in enumerate(circuits, start=1):
            vc = g.node(
                "VirtualCircuit",
                f"eqx:vc:fr5-0000000{i}-{name}",
                name=name,
                bandwidth_mbps=1000,
                state="active",
            )
            g.rel("PROVIDED_BY", vc, self.provider["equinix"])
            g.rel("A_END", vc, a_end, props={"link_protocol": "dot1q", "vlan_tag": vlan})
            g.rel("Z_END", vc, z_end)

    # ----------------------------------------------------------------------- ZPA ---
    def zpa(self) -> None:
        g = self.g
        g.sec("Zscaler ZPA")
        zpa = f"zpa:{ORG}"
        idg = {
            name: g.node("IdentityGroup", f"{zpa}:idp:7001-{sid}", name=name, source="scim")
            for name, sid in IDENTITY_GROUPS
        }
        seggrp = g.node("ZpaSegmentGroup", f"{zpa}:seggrp:100", name="corp-apps")
        srvgrp, cgrp = {}, {}
        for i, dc in enumerate(DCS):
            code = dc["code"]
            srvgrp[code] = g.node("ZpaServerGroup", f"{zpa}:srvgrp:30{i}", name=f"{code}-servers")
            cgrp[code] = g.node(
                "ZpaAppConnectorGroup", f"{zpa}:cgrp:50{i}", name=f"{code}-connectors", location=code
            )
            g.rel("USES", srvgrp[code], cgrp[code])
            for k, vm in enumerate(self.zpa_conn_vm[code]):
                ipu = self.infra_ip[code][f"zpa-conn-0{k + 1}"]
                conn = g.node(
                    "ZpaAppConnector",
                    f"{zpa}:conn:6{i}{k}",
                    name=f"{code}-conn-0{k + 1}",
                    enabled=True,
                    health="up",
                    control_channel_status="ZPN_STATUS_AUTHENTICATED",
                    private_ip=g.nodes[ipu][1]["ip"],
                )
                g.rel("HAS", cgrp[code], conn)
                g.rel("RUNS_ON", conn, vm)
        pos = 0
        for i, (app, spec) in enumerate(APPS.items()):
            tier = spec["vips"][0][0]
            dc = spec["tiers"][tier][0]
            seg = g.node(
                "ZpaAppSegment",
                f"{zpa}:seg:{2001 + i}",
                name=f"{app}-internal",
                zpa_id=str(2001 + i),
                enabled=True,
                domains=[f"{app}.{DOMAIN}"],
                tcp_port_ranges=["443", "443"],
            )
            g.rel("MEMBER_OF", seg, seggrp)
            g.rel("SERVED_BY", seg, srvgrp[dc])
            g.rel("RESOLVES_TO", seg, f"dns:{app}.{DOMAIN}:A")
            groups = APP_IDENTITY[app]
            pos += 1
            sids = [str(sid) for name, sid in IDENTITY_GROUPS if name in groups]
            rule = g.node(
                "ZpaAccessRule",
                f"{zpa}:rule:{100 * pos}",
                position=pos,
                priority=pos,
                name=f"{'-'.join(groups)}-to-{app}",
                action="allow",
                action_raw="ALLOW",
                conditions=json.dumps(
                    [
                        {"operator": "OR", "operands": [{"type": "APP", "rhs": str(2001 + i)}]},
                        {"operator": "OR", "operands": [{"type": "SCIM_GROUP", "rhs": s} for s in sids]},
                    ]
                ),
                conditions_summary=f"APP={2001 + i}; SCIM_GROUP={','.join(sids)}",
                identity_scope="listed",
                app_scope="listed",
            )
            g.rel("FOR", rule, seg)
            for name in groups:
                g.rel("GRANTS", rule, idg[name])
        pos += 1
        deny = g.node(
            "ZpaAccessRule",
            f"{zpa}:rule:{100 * pos}",
            position=pos,
            priority=pos,
            name="contractors-deny-corp",
            action="deny",
            action_raw="DENY",
            conditions=json.dumps(
                [
                    {"operator": "OR", "operands": [{"type": "APP_GROUP", "rhs": "100"}]},
                    {"operator": "OR", "operands": [{"type": "SCIM_GROUP", "rhs": "77105"}]},
                ]
            ),
            conditions_summary="APP_GROUP=100; SCIM_GROUP=77105",
            identity_scope="listed",
            app_scope="listed",
        )
        g.rel("FOR", deny, seggrp)
        g.rel("DENIES", deny, idg["contractors"])

    # ---------------------------------------------------------- Check Point policy ---
    def checkpoint_policy(self, dc: dict) -> None:
        """One policy package per data center, written as the Check Point management collector
        writes a package (collectors/checkpoint.py `normalize_checkpoint`): every node uid is
        `cp:<management>:<domain>:<api uid>`, the package, layer, rules and objects carry the
        API object as `checkpoint_envelope`, the package lists its layer (HAS_LAYER) and its
        installation targets, and each target gateway ENFORCES the layer. The package states
        the R81.20 releases, API 1.9 and a complete capture, so symbolic-v2 qualifies it."""
        g, v = self.g, self.v
        code = dc["code"]
        g.sec(f"{code} Check Point policy")
        mgmt, domain = "cpmgmt-01", "smc"
        mg = f"cp:{mgmt}:{domain}"
        dom = {"uid": domain, "name": "SMC User", "domain-type": "domain"}

        def envelope(value: dict) -> str:
            return json.dumps(value, sort_keys=True, separators=(",", ":"))

        def api_uid(node_uid: str) -> str:
            return node_uid.removeprefix(f"{mg}:")

        # the Any object and the two rule actions, shared by both packages
        any_obj = g.node(
            "CpPolicyObject",
            f"{mg}:cpmi-any-object",
            checkpoint_envelope=envelope(
                {"uid": "cpmi-any-object", "name": "Any", "type": "CpmiAnyObject", "domain": dom}
            ),
        )
        actions = {
            action: g.node(
                "CpPolicyObject",
                f"{mg}:rulebase-action-{action}",
                checkpoint_envelope=envelope(
                    {
                        "uid": f"rulebase-action-{action}",
                        "name": action.capitalize(),
                        "type": "RulebaseAction",
                        "domain": dom,
                    }
                ),
            )
            for action in ("accept", "drop")
        }
        # the cluster members are the installation targets of the package
        gateways = []
        for suffix in "ab":
            gw_api = f"gw-{code}-cpfw-01{suffix}"
            gateways.append(
                g.node(
                    "Device",
                    f"dev:{code}-cpfw-01{suffix}",
                    cp_type="CpmiClusterMember",
                    cp_uid=f"{mg}:{gw_api}",
                    cp_raw_uid=gw_api,
                )
            )
        install_on = [str(g.nodes[gw][1]["cp_raw_uid"]) for gw in gateways]
        layer_api = f"pkg-{code}-access"
        rb = g.node(
            "FwRulebase",
            f"{mg}:{layer_api}",
            name=f"{code}-access",
            kind="access",
            vendor="checkpoint",
            default_action="drop",
            match_context="device",
            checkpoint_envelope=envelope(
                {
                    "uid": layer_api,
                    "name": f"{code}-access",
                    "type": "access-layer",
                    "domain": dom,
                    "firewall": True,
                    "applications-and-url-filtering": False,
                    "content-awareness": False,
                    "mobile-access": False,
                    "shared": False,
                    "implicit-cleanup-action": "drop",
                }
            ),
        )
        g.rel("ENFORCES", self.cp_cluster[code], rb)
        package_api = f"policy-{code}"
        package = g.node(
            "CpPolicyPackage",
            f"{mg}:package:{package_api}",
            checkpoint_envelope=envelope(
                {
                    "uid": package_api,
                    "name": f"{code}-policy",
                    "type": "package",
                    "domain": dom,
                    "access": True,
                    "threat-prevention": False,
                    "nat-policy": False,
                    "access-layers": [layer_api],
                    "installation-targets": install_on,
                }
            ),
            capture_complete=True,
            implied_complete=True,
            authority_uid=mgmt,
            domain_uid=domain,
            management_release="R81.20",
            gateway_release="R81.20",
            api_version="1.9",
        )
        g.rel("HAS_LAYER", package, rb, props={"position": 0})
        for gw in gateways:
            g.rel("ENFORCES", gw, rb, props={"configured": True})
        objs: dict[str, str] = {}
        svcs: dict[tuple[str, int], str] = {}

        def obj(name: str, target: str, kind: str) -> str:
            if name not in objs:
                label, props = g.nodes[target]
                raw: dict = {"uid": f"obj-{name}", "name": name, "type": kind, "domain": dom}
                if kind == "host" and label == "IpAddress":
                    address = {"ip": props["ip"]}
                    raw["ipv4-address"] = props["ip"]
                elif kind == "network" and label == "Prefix":
                    net = ipaddress.ip_network(props["cidr"])
                    address = {"cidr": props["cidr"]}
                    raw["subnet4"] = str(net.network_address)
                    raw["mask-length4"] = net.prefixlen
                    raw["subnet-mask"] = str(net.netmask)
                else:
                    raise ValueError(f"Check Point {kind} object {name} on {label} {target}")
                objs[name] = g.node(
                    "NetObject",
                    f"{mg}:obj-{name}",
                    name=name,
                    kind=kind,
                    checkpoint_envelope=envelope(raw),
                    **address,
                )
                g.rel("RESOLVES_TO", objs[name], target)
            return objs[name]

        def svc(port: int, proto: str = "tcp") -> str:
            if (proto, port) not in svcs:
                svc_api = f"svc-{proto}-{port}"
                svcs[(proto, port)] = g.node(
                    "SvcObject",
                    f"{mg}:{svc_api}",
                    name=f"{proto}-{port}",
                    kind=f"service-{proto}",
                    proto=proto,
                    ports=str(port),
                    checkpoint_envelope=envelope(
                        {
                            "uid": svc_api,
                            "name": f"{proto}-{port}",
                            "type": f"service-{proto}",
                            "domain": dom,
                            "port": str(port),
                            "source-port": "",
                            "protocol": "",
                            "match-by-protocol-signature": False,
                        }
                    ),
                )
            return svcs[(proto, port)]

        pos = [0]

        def rule(
            rid: str,
            name: str,
            srcs: list[str],
            dsts: list[str],
            services: list[str],
            action: str = "accept",
            *,
            any_service: bool = False,
        ) -> None:
            pos[0] += 1
            r = f"{mg}:rule-{code}-{rid}"
            # the service column holds the Any object: the management API names it, and the
            # collector writes svc_any and no SVC edge for it
            column = [api_uid(any_obj)] if any_service else [api_uid(s) for s in services]
            g.node(
                "FwRule",
                r,
                name=name,
                position=pos[0],
                action=action,
                enabled=True,
                rule_uid=f"7b1e{dc['n']:04x}-0000-4000-8000-{pos[0]:012d}",
                rulebase_uid=layer_api,
                src_any=False,
                dst_any=False,
                svc_any=any_service,
                src_negate=False,
                dst_negate=False,
                svc_negate=False,
                checkpoint_envelope=envelope(
                    {
                        "uid": api_uid(r),
                        "name": name,
                        "type": "access-rule",
                        "domain": dom,
                        "rule-number": pos[0],
                        "enabled": True,
                        "action": api_uid(actions[action]),
                        "source": [api_uid(s) for s in srcs],
                        "destination": [api_uid(d) for d in dsts],
                        "service": column,
                        "source-negate": False,
                        "destination-negate": False,
                        "service-negate": False,
                        "install-on": install_on,
                        "time": [api_uid(any_obj)],
                        "vpn": [api_uid(any_obj)],
                        "content": [api_uid(any_obj)],
                    }
                ),
            )
            g.rel("HAS_RULE", rb, r)
            for s in srcs:
                g.rel("SRC", r, s)
            for d in dsts:
                g.rel("DST", r, d)
            for s in services:
                g.rel("SVC", r, s)

        infra_obj = obj(f"{code}-infra", f"pfx:{slug(self.aci_vrf[code])}:10.{dc['n']}.5.0/24", "network")
        [obj(f"{site}-users", p, "network") for site, p in self.office_users.items()]
        office_mgmt = [obj(f"{site}-mgmt", p, "network") for site, p in self.office_mgmt.items()]
        # one rule per office and application VIP
        for app, spec in APPS.items():
            for tier, port, _proto, since, until in spec["vips"]:
                if spec["tiers"][tier][0] != code or not (since <= v <= until):
                    continue
                vip_obj = obj(f"vip-{app}-{tier}-{port}", self.vip_ip[(app, tier, port)], "host")
                for site in self.office_users:
                    rule(
                        f"{site}-{app}-{tier}-{port}",
                        f"{site} users to {app} {tier} {port}",
                        [objs[f"{site}-users"]],
                        [vip_obj],
                        [svc(port)],
                    )
        # guest Wi-Fi resolves names on the corp DNS VIP: the source is the office firewall's NAT address
        if code == "dc1":
            dns_obj = obj("vip-dns-53", self.dns_vip[code], "host")
            for site, p in self.office_edge.items():
                rule(
                    f"{site}-guest-dns",
                    f"{site} guest wifi to corp dns",
                    [obj(f"{site}-fw-edge", p, "network")],
                    [dns_obj],
                    [svc(53, "udp")],
                )
        # tier to tier flows, including the cross-site Claims Portal database leg
        for app, spec in APPS.items():
            for src, dst, port, since in spec["flows"]:
                if since > v:
                    continue
                sdc, ddc = spec["tiers"][src][0], spec["tiers"][dst][0]
                if code not in (sdc, ddc):
                    continue
                so = obj(f"{sdc}-{app}-{src}", self.tier_prefix[(app, src)], "network")
                do = obj(f"{ddc}-{app}-{dst}", self.tier_prefix[(app, dst)], "network")
                rule(f"{app}-{src}-to-{dst}", f"{app} {src} to {dst}", [so], [do], [svc(port)])
        # infrastructure services, monitoring, backup and administration per tier
        tiers_here = [
            (app, tier)
            for app, spec in APPS.items()
            for tier, (tdc, _n, _p, s) in spec["tiers"].items()
            if tdc == code and s <= v
        ]
        tier_objs = [
            obj(f"{code}-{app}-{tier}", self.tier_prefix[(app, tier)], "network") for app, tier in tiers_here
        ]
        rule(
            "tiers-to-infra-dns-ntp",
            "tiers to infra dns and ntp",
            tier_objs,
            [infra_obj],
            [svc(53, "udp"), svc(123, "udp")],
        )
        rule("tiers-to-infra-ldap", "tiers to infra ldap", tier_objs, [infra_obj], [svc(636)])
        rule(
            "infra-mon-to-tiers", "monitoring to tiers", [infra_obj], tier_objs, [svc(9100), svc(161, "udp")]
        )
        rule("tiers-to-infra-backup", "tiers to backup", tier_objs, [infra_obj], [svc(10000)])
        rule("tiers-to-infra-syslog", "tiers to syslog", tier_objs, [infra_obj], [svc(514)])
        rule(
            "admins-to-tiers-ssh",
            "office mgmt to tiers ssh",
            office_mgmt,
            [*tier_objs, infra_obj],
            [svc(22), svc(3389)],
        )
        other = "dc2" if code == "dc1" else "dc1"
        other_infra = obj(
            f"{other}-infra",
            f"pfx:{slug(self.aci_vrf[other])}:10.{DCS[1 if code == 'dc1' else 0]['n']}.5.0/24",
            "network",
        )
        rule(
            "infra-replication",
            "infra replication between data centers",
            [infra_obj],
            [other_infra],
            [svc(389), svc(636), svc(53, "udp"), svc(88)],
        )
        if v >= 2:
            # the Claims Portal API tier arrives with its own operational rules
            api = obj("dc1-claims-api", self.tier_prefix[("claims", "api")], "network")
            rule("claims-api-to-infra-smtp", "claims api to smtp relay", [api], [infra_obj], [svc(25)])
            rule(
                "claims-api-to-infra-syslog-tls", "claims api to syslog tls", [api], [infra_obj], [svc(6514)]
            )
            rule("claims-api-metrics", "monitoring to claims api metrics", [infra_obj], [api], [svc(9102)])
            rule(
                "claims-api-admins-https",
                "office mgmt to claims api console",
                office_mgmt,
                [api],
                [svc(9443)],
            )
            rule(
                "claims-api-to-webshop-api",
                "claims api to webshop api",
                [api],
                [obj("dc1-webshop-api", self.tier_prefix[("webshop", "api")], "network")],
                [svc(8080)],
            )
            rule(
                "claims-api-to-payments-api",
                "claims api to payments api",
                [api],
                [obj("dc2-payments-api", self.tier_prefix[("payments", "api")], "network")],
                [svc(9443)],
            )
        rule(
            "cleanup",
            "cleanup",
            [obj("any", self.corp_default, "network")],
            [objs["any"]],
            [],
            action="drop",
            any_service=True,
        )
        self.cp_rules[code] = pos[0]
        # the ACI PBR redirect: campus sources toward the DC server networks are steered into the
        # firewall cluster (the one-row fw-redirect table built with the fabric)
        pbr = self.dc_pbr[code]
        campus = g.node(
            "NetObject", f"aci:{dc['fabric']}:obj-campus-networks", name="campus-networks", kind="group"
        )
        for p in [*self.campus_prefixes(), self.dc_agg[other]]:
            g.rel("RESOLVES_TO", campus, p)
        servers = g.node(
            "NetObject",
            f"aci:{dc['fabric']}:obj-{code}-server-networks",
            name=f"{code}-server-networks",
            kind="group",
        )
        for p in self.dc_server_pfx[code]:
            g.rel("RESOLVES_TO", servers, p)
        redirect_rule = g.node(
            "FwRule",
            f"{pbr}/rule-1",
            name="campus-to-servers-via-fw",
            position=1,
            action="redirect",
            enabled=True,
            rule_uid=f"pbr-{code}-1",
        )
        g.rel("HAS_RULE", pbr, redirect_rule)
        g.rel("SRC", redirect_rule, campus)
        g.rel("DST", redirect_rule, servers)
        g.rel("REDIRECTS_VIA", redirect_rule, f"vrf:aci:{dc['fabric']}:tn-PROD:fw-redirect")

    # ------------------------------------------------------------- Oslo, VyOS ---
    def vyos_office(self) -> None:
        """The Oslo office: one dual-stack VyOS router, in every version.

        Every node and relationship of the router is what the VyOS collector writes: the
        synthetic payload `vyos_payload` goes through `hst.collectors.vyos.normalize_vyos`
        and the batch is copied in as it comes. A uid the estate already holds stops the
        generator. The collector writes no Site and no LOCATED_IN (a run assigns the device
        to its site), no endpoint and no GATEWAY_FOR (the reasoner derives that edge for a
        router), so the Site, the router's LOCATED_IN and the endpoints are written here.

        An endpoint is a wired client as the UniFi collector writes one: an Endpoint IN the
        VLAN's BridgeDomain (the uid the router's vif realizes), with one IpAddress per family,
        each anchored on the router's table and IN the router's connected prefix, and ATTACHED
        to the router's trunk port eth1."""
        # this tree's collector, whatever else the interpreter has on its path
        if str(SRC) not in sys.path:
            sys.path.insert(0, str(SRC))
        from hst.collectors.vyos import normalize_vyos
        from hst.core import uid as uidmod

        g = self.g
        code, host = VYOS_SITE["code"], VYOS_HOST
        g.sec(f"{code} VyOS router (collector normalization)")
        batch = normalize_vyos(vyos_payload(), l3dom=code, l2fabric=code, scope=f"vyos:{host}")
        if batch.warnings:
            raise ValueError(f"{host}: the collector warned: {batch.warnings}")
        mine: set[str] = set()
        for rec in sorted(batch.nodes, key=lambda n: (n.label, n.uid)):
            if rec.uid in g.nodes and rec.uid not in mine:
                raise ValueError(f"{host}: the collector's uid {rec.uid} is already in the estate")
            mine.add(rec.uid)
            g.node(rec.label, rec.uid, **rec.props)
        for rel in sorted(
            batch.rels,
            key=lambda r: (r.rel_type, r.start_uid, r.end_uid, json.dumps(r.key, sort_keys=True)),
        ):
            if (g.nodes[rel.start_uid][0], g.nodes[rel.end_uid][0]) != (rel.start_label, rel.end_label):
                raise ValueError(f"{host}: label mismatch on {rel.rel_type} {rel.start_uid} -> {rel.end_uid}")
            g.rel(
                rel.rel_type,
                rel.start_uid,
                rel.end_uid,
                props=dict(rel.props) or None,
                key=dict(rel.key) or None,
            )

        g.sec(f"{code} site and endpoints")
        dev = f"dev:{host}"
        site = g.node(
            "Site",
            f"site:{code}",
            code=code,
            name=f"{VYOS_SITE['city']} Office",
            kind="office",
            criticality="medium",
        )
        g.rel("LOCATED_IN", dev, site)
        g.rel("SERVED_BY", site, self.pnet[VYOS_SITE["dia"]])
        table = f"vrf:{dev}:default"
        trunk = uidmod.port(dev, "eth1")
        for index, (name, vid, host_id) in enumerate(VYOS_ENDPOINTS, start=1):
            v4_net, v6_net = VYOS_LANS[vid]
            mac = f"02:18:00:00:{vid:02x}:{index:02x}"
            ep = g.node(
                "Endpoint",
                uidmod.endpoint(code, mac),
                mac=uidmod.norm_mac(mac),
                kind="client",
                name=name,
                wired=True,
            )
            g.rel("IN", ep, uidmod.bridge_domain(code, vid))
            g.rel("ATTACHED", ep, trunk)
            for net in (v4_net, v6_net):
                network = ipaddress.ip_network(net)
                # the same digits in both families: host 21 is .21 and ::21
                addr = str(network.network_address + int(str(host_id), 10 if network.version == 4 else 16))
                ipu = g.node(
                    "IpAddress", uidmod.ip(table, addr), ip=addr, af=network.version, l3dom=code, anchor=table
                )
                g.rel("HAS_IP", ep, ipu)
                g.rel("IN", ipu, uidmod.prefix(table, net))

    def fr5_internet_edges(self) -> None:
        """Two internet routers (IOS-XE) at Equinix FR5, in every version, each behind one core,
        and a dual-stack jump host behind each core.

        Each internet router has GigabitEthernet0/0/1 on a provider /30 and /64 and static default
        routes of both families to the provider's gateway, which no collected interface holds; no
        WAN link is written, as an IOS-XE collector writes none. Its table carries no route target,
        so its routes are its own. Each core gets a host LAN, a routed link to its internet router
        and default routes of both families to it, and the internet router routes the LAN back.
        The demo loader puts fr5-inet-01 in a block of zone `internet` and fr5-inet-02 in a block of
        zone `external` (`FR5_BLOCKS`, sites.yaml), so the two answer differently on the same
        configuration."""
        g = self.g
        base = "10.72"
        g.sec("eqx-fr5 internet routers and jump hosts")

        def prefix6(cidr: str, kind: str, name: str) -> str:
            return g.node(
                "Prefix",
                f"pfx:corp:{cidr}",
                cidr=cidr,
                af=6,
                kind=kind,
                l3dom="corp",
                name=name,
                anchor="corp",
            )

        def ip6(addr: str, pfx: str, anchor: str, name: str | None = None) -> str:
            uid = g.node(
                "IpAddress",
                f"ip:{slug(anchor)}:{addr}",
                ip=addr,
                af=6,
                l3dom="corp",
                anchor=anchor,
                name=name,
            )
            g.rel("IN", uid, pfx)
            return uid

        agg = f"pfx:corp:{base}.0.0/16"
        default6 = prefix6("::/0", "default", "default-v6")
        for i, (v4_net, v6_net) in enumerate(FR5_UPLINKS, start=1):
            core = f"dev:fr5-core-0{i}"
            cvrf = f"vrf:dev:fr5-core-0{i}:corp"
            inet = g.device(
                self.colo_site, f"fr5-inet-0{i}", "iosxe", "router", "cisco", "FXS", f"{base}.0.{30 + i}"
            )
            ivrf = g.vrf(f"vrf:dev:fr5-inet-0{i}:default", "default", self.rdom["corp"])

            # the routed link from the core to its internet router
            link4 = g.prefix(
                "corp", f"{base}.2.{4 * (i - 1)}/30", "connected", f"eqx-fr5-core-inet-0{i}", parent=agg
            )
            link6 = prefix6(f"2001:db8:72:f{i}::/64", "connected", f"eqx-fr5-core-inet-0{i}-v6")
            cp = g.port(core, "eth1-11", "ethernet1/11", 10000)
            ip_ = g.port(inet, "gi0-0-0", "GigabitEthernet0/0/0", 10000)
            g.cable(cp, ip_)
            core_if = g.iface(core, "eth1-11", "ethernet1/11", "phys", port=cp)
            inet_if = g.iface(inet, "gi0-0-0", "GigabitEthernet0/0/0", "phys", port=ip_)
            core_v4, inet_v4 = f"{base}.2.{4 * (i - 1) + 1}", f"{base}.2.{4 * (i - 1) + 2}"
            core_v6, inet_v6 = f"2001:db8:72:f{i}::1", f"2001:db8:72:f{i}::2"
            for vrf, iface, v4, v6 in ((cvrf, core_if, core_v4, core_v6), (ivrf, inet_if, inet_v4, inet_v6)):
                g.connected(vrf, iface, v4, link4, gateway=False)
                g.rel("HAS_IP", iface, ip6(v6, link6, vrf))
                g.rel("ORIGINATES", vrf, link6, props={"proto": "connected"})

            # the host LAN behind the core, and the jump host on it
            lan = g.prefix("corp", f"{base}.10{i}.0/24", "connected", f"eqx-fr5-hosts-0{i}", parent=agg)
            lan6 = prefix6(f"2001:db8:72:10{i}::/64", "connected", f"eqx-fr5-hosts-0{i}-v6")
            lan_port = g.port(core, "eth1-10", "ethernet1/10", 10000)
            lan_if = g.iface(core, "eth1-10", "ethernet1/10", "phys", port=lan_port)
            g.connected(cvrf, lan_if, f"{base}.10{i}.1", lan)
            g.rel("HAS_IP", lan_if, ip6(f"2001:db8:72:10{i}::1", lan6, cvrf))
            g.rel("ORIGINATES", cvrf, lan6, props={"proto": "connected"})
            g.rel("GATEWAY_FOR", lan_if, lan6)
            name = f"fr5-jump-0{i}"
            mac = g.mac(name)
            ep = g.node("Endpoint", f"ep:corp:{mac.replace(':', '')}", mac=mac, kind="server", name=name)
            g.rel("ATTACHED", ep, lan_port)
            g.rel("HAS_IP", ep, g.ip("corp", f"{base}.10{i}.10", lan, anchor=cvrf, name=name))
            g.rel("HAS_IP", ep, ip6(f"2001:db8:72:10{i}::10", lan6, cvrf, name))
            # the core's defaults to its internet router
            g.route(
                cvrf, self.corp_default, "STATIC_ROUTE", next_hop=inet_v4, iface=core_if, protocol="static"
            )
            g.route(cvrf, default6, "STATIC_ROUTE", next_hop=inet_v6, iface=core_if, protocol="static")

            # the internet uplink: the provider's gateway is the first address, the router's the second
            net4, net6 = ipaddress.ip_network(v4_net), ipaddress.ip_network(v6_net)
            gw4, own4 = str(net4.network_address + 1), str(net4.network_address + 2)
            gw6, own6 = str(net6.network_address + 1), str(net6.network_address + 2)
            up_port = g.port(inet, "gi0-0-1", "GigabitEthernet0/0/1", 1000)
            up_if = g.iface(
                inet, "gi0-0-1", "GigabitEthernet0/0/1", "phys", port=up_port, description="internet"
            )
            up4 = g.prefix("corp", v4_net, "connected", f"eqx-fr5-internet-0{i}")
            up6 = prefix6(v6_net, "connected", f"eqx-fr5-internet-0{i}-v6")
            g.connected(ivrf, up_if, own4, up4, gateway=False)
            g.rel("HAS_IP", up_if, ip6(own6, up6, ivrf))
            g.rel("ORIGINATES", ivrf, up6, props={"proto": "connected"})
            g.route(ivrf, self.corp_default, "STATIC_ROUTE", next_hop=gw4, iface=up_if, protocol="static")
            g.route(ivrf, default6, "STATIC_ROUTE", next_hop=gw6, iface=up_if, protocol="static")
            # and the host LAN back to the core
            g.route(ivrf, lan, "STATIC_ROUTE", next_hop=core_v4, iface=inet_if, protocol="static")
            g.route(ivrf, lan6, "STATIC_ROUTE", next_hop=core_v6, iface=inet_if, protocol="static")


# The provider networks of the FR5 internet routers, by router: (IPv4 /30, IPv6 /64).
FR5_UPLINKS = (("203.0.113.16/30", "2001:db8:72:e1::/64"), ("203.0.113.20/30", "2001:db8:72:e2::/64"))
# The named blocks the demo loader gives the FR5 internet routers (sites.yaml).
FR5_BLOCKS = (
    {"name": "Internet edge", "zone": "internet", "devices": ["dev:fr5-inet-01"]},
    {"name": "Carrier edge", "zone": "external", "devices": ["dev:fr5-inet-02"]},
)


# --- the Oslo office's VyOS router: the payload its collector would seal --------------
VYOS_SITE = {"code": "osl01", "city": "Oslo", "dia": "fibrenta"}
VYOS_HOST = "osl01-vyos-01"
VYOS_VERSION = "Version:          VyOS 1.5-rolling-202607150020\nHardware S/N:     NLOSL0118\n"
# vid -> (IPv4 network, IPv6 network) of the LAN, IOT and GUEST VLANs on eth1
VYOS_LANS = {
    10: ("10.18.10.0/24", "fd00:18:10::/64"),
    20: ("10.18.20.0/24", "fd00:18:20::/64"),
    30: ("10.18.30.0/24", "fd00:18:30::/64"),
}
# (name, vid, host number in both networks)
VYOS_ENDPOINTS = [
    ("osl01-pc-01", 10, 21),
    ("osl01-nas-01", 10, 20),
    ("osl01-vpn-01", 10, 50),
    ("osl01-cam-01", 20, 31),
    ("osl01-hub-01", 20, 32),
    ("osl01-guest-01", 30, 41),
]


# the partner network behind the second tunnel wg1, whose carrier LOCAL-WAN does not permit
VYOS_PARTNER_NET = "172.20.0.0/16"
# a configured static FRR does not install (next hop unreachable): absent from the RIB rows
VYOS_UNINSTALLED_NET = "192.0.2.0/25"
# the RIB reads the collector's fetch records, each one `ok`: the main table and table 100
VYOS_RIB_READS = ("routes", "routes6", "routes_table_100", "routes6_table_100")


def _vyos_zone_pair(v4: str, v6: str) -> dict:
    return {"firewall": {"name": v4, "ipv6-name": v6}}


def _vyos_ruleset(default: str, rules: dict | None = None) -> dict:
    return {"default-action": default, **({"rule": rules} if rules else {})}


def _vyos_rule(action: str, description: str, **match) -> dict:
    return {"action": action, "description": description, **match}


def _local_dns() -> dict:
    """Rules 20 and 21: DNS to the router, udp and tcp."""
    return {
        "20": _vyos_rule("accept", "dns", protocol="udp", destination={"port": "53"}),
        "21": _vyos_rule("accept", "dns tcp", protocol="tcp", destination={"port": "53"}),
    }


def _router_services() -> dict:
    """Rules 20, 21 and 30 of LOCAL-WAN: the router's own DNS and NTP queries."""
    return {**_local_dns(), "30": _vyos_rule("accept", "ntp", protocol="udp", destination={"port": "123"})}


def _frr_route(prefix: str, *nexthops: dict, protocol: str, table: int = 254) -> dict:
    """One `show ip[v6] route ... json` entry keyed by prefix, as FRR prints an installed route."""
    entry = {"prefix": prefix, "protocol": protocol, "table": table, "nexthops": list(nexthops)}
    return {prefix: [{**entry, "installed": True, "selected": True}]}


def _frr_nh(ip: str | None = None, dev: str | None = None, **extra) -> dict:
    nh: dict = {"fib": True, "active": True, **extra}
    if ip:
        nh["ip"] = ip
    if dev:
        nh["interfaceName"] = dev
    return nh


def vyos_config() -> dict:
    """`show configuration json` of the Oslo router (VyOS 1.5 syntax).

    Zones LAN (eth1.10), IOT (eth1.20), GUEST (eth1.30), WAN (eth0, wg0, wg1) and the local
    zone LOCAL; an IPv4 and an IPv6 rule set per zone pair; a global state policy; LAN-WAN
    jumps to the shared COMMON set. Each zone has a rule set to LOCAL and one from LOCAL;
    LOCAL-WAN permits the carrier of wg0 but not that of the partner tunnel wg1. Source NAT
    masquerades on eth0, a destination NAT rule forwards WAN port 443 to the NAS, and `nat66`
    masquerades the LAN on the WireGuard tunnel.
    `policy route` and `policy route6` on eth1.10 send the VPN host groups into table 100,
    whose default routes leave by wg0. The main table routes the partner network by wg1 and
    holds a static whose next hop is in no connected network, which FRR does not install."""
    v4 = {
        "COMMON": _vyos_ruleset(
            "return", {"10": _vyos_rule("accept", "dns", protocol="udp", destination={"port": "53"})}
        ),
        "LAN-WAN": _vyos_ruleset(
            "accept", {"5": {"action": "jump", "jump-target": "COMMON", "description": "shared rules"}}
        ),
        "GUEST-WAN": _vyos_ruleset(
            "drop", {"10": _vyos_rule("accept", "guest web", protocol="tcp", destination={"port": "80,443"})}
        ),
        "IOT-WAN": _vyos_ruleset("drop"),
        "WAN-LAN": _vyos_ruleset(
            "drop",
            {
                "10": _vyos_rule(
                    "accept",
                    "nas port forward",
                    protocol="tcp",
                    destination={"group": {"address-group": "NAS"}, "port": "443"},
                )
            },
        ),
        "LAN-IOT": _vyos_ruleset(
            "drop",
            {
                "10": _vyos_rule(
                    "accept",
                    "iot web",
                    protocol="tcp",
                    destination={"group": {"network-group": "IOT-NET"}, "port": "443"},
                )
            },
        ),
        "IOT-LAN": _vyos_ruleset(
            "drop",
            {
                "10": _vyos_rule(
                    "accept",
                    "mqtt to nas",
                    protocol="tcp",
                    destination={"group": {"address-group": "NAS"}, "port": "1883"},
                )
            },
        ),
        "LAN-LOCAL": _vyos_ruleset(
            "accept", {"10": _vyos_rule("accept", "ssh", protocol="tcp", destination={"port": "22"})}
        ),
        "IOT-LOCAL": _vyos_ruleset("drop", _local_dns()),
        "GUEST-LOCAL": _vyos_ruleset(
            "drop",
            {"10": _vyos_rule("accept", "dhcp", protocol="udp", destination={"port": "67"}), **_local_dns()},
        ),
        "WAN-LOCAL": _vyos_ruleset("drop"),
        # what the router itself sends: the carrier of the VPN provider's tunnel wg0 (not the
        # partner tunnel wg1), DNS, NTP and the DHCP client of the WAN address
        "LOCAL-WAN": _vyos_ruleset(
            "drop",
            {
                "10": _vyos_rule(
                    "accept",
                    "wireguard vpn-provider",
                    protocol="udp",
                    destination={"address": "198.51.100.180", "port": "51820"},
                ),
                **_router_services(),
                "40": _vyos_rule("accept", "dhcp client", protocol="udp", destination={"port": "67"}),
            },
        ),
        "LOCAL-LAN": _vyos_ruleset("accept"),
        "LOCAL-IOT": _vyos_ruleset("accept"),
        "LOCAL-GUEST": _vyos_ruleset(
            "drop", {"10": _vyos_rule("accept", "dhcp", protocol="udp", destination={"port": "68"})}
        ),
    }
    v6 = {
        "COMMON-6": _vyos_ruleset(
            "return", {"10": _vyos_rule("accept", "dns", protocol="udp", destination={"port": "53"})}
        ),
        "LAN-WAN-6": _vyos_ruleset(
            "accept", {"5": {"action": "jump", "jump-target": "COMMON-6", "description": "shared rules"}}
        ),
        "GUEST-WAN-6": _vyos_ruleset(
            "drop", {"10": _vyos_rule("accept", "guest web", protocol="tcp", destination={"port": "80,443"})}
        ),
        "IOT-WAN-6": _vyos_ruleset("drop"),
        "WAN-LAN-6": _vyos_ruleset("drop"),
        "LAN-IOT-6": _vyos_ruleset(
            "drop",
            {
                "10": _vyos_rule(
                    "accept",
                    "iot api",
                    protocol="tcp",
                    destination={"group": {"ipv6-network-group": "IOT-NET6", "port-group": "IOT-API"}},
                )
            },
        ),
        "IOT-LAN-6": _vyos_ruleset("drop"),
        "LAN-LOCAL-6": _vyos_ruleset(
            "accept", {"10": _vyos_rule("accept", "ssh", protocol="tcp", destination={"port": "22"})}
        ),
        "IOT-LOCAL-6": _vyos_ruleset("drop", _local_dns()),
        "GUEST-LOCAL-6": _vyos_ruleset(
            "drop",
            {
                "10": _vyos_rule("accept", "dhcpv6", protocol="udp", destination={"port": "547"}),
                **_local_dns(),
            },
        ),
        "WAN-LOCAL-6": _vyos_ruleset("drop"),
        "LOCAL-WAN-6": _vyos_ruleset("drop", _router_services()),
        "LOCAL-LAN-6": _vyos_ruleset("accept"),
        "LOCAL-IOT-6": _vyos_ruleset("accept"),
        "LOCAL-GUEST-6": _vyos_ruleset(
            "drop", {"10": _vyos_rule("accept", "dhcpv6", protocol="udp", destination={"port": "546"})}
        ),
    }
    zone = _vyos_zone_pair

    def gateway(net: str) -> str:
        network = ipaddress.ip_network(net)
        return f"{network.network_address + 1}/{network.prefixlen}"

    vifs = {
        str(vid): {"description": name, "address": [gateway(net) for net in nets]}
        for (vid, nets), name in zip(VYOS_LANS.items(), ("LAN", "IOT", "GUEST"), strict=True)
    }
    return {
        "system": {"host-name": VYOS_HOST},
        "interfaces": {
            "ethernet": {
                "eth0": {
                    "description": "WAN Fibrenta DIA",
                    "address": ["dhcp", "2001:db8:18::2/64"],
                    "dhcp-options": {"no-default-route": {}},
                },
                "eth1": {"description": "LAN trunk", "vif": vifs},
            },
            "wireguard": {
                "wg0": {
                    "description": "VPN provider tunnel",
                    "address": ["10.18.250.2/30", "fd00:18:250::2/64"],
                    "port": "51820",
                    "peer": {
                        "vpn-provider": {
                            "address": "198.51.100.180",
                            "port": "51820",
                            "allowed-ips": ["0.0.0.0/0", "::/0"],
                        }
                    },
                },
                "wg1": {
                    "description": "partner tunnel",
                    "address": ["10.18.251.2/30"],
                    "port": "51821",
                    "peer": {
                        "partner": {
                            "address": "198.51.100.190",
                            "port": "51821",
                            "allowed-ips": ["172.20.0.0/16"],
                        }
                    },
                },
            },
        },
        "firewall": {
            "global-options": {
                "state-policy": {
                    "established": {"action": "accept"},
                    "related": {"action": "accept"},
                    "invalid": {"action": "drop"},
                }
            },
            "group": {
                "address-group": {
                    "NAS": {"address": ["10.18.10.20"]},
                    "VPN-HOSTS": {"address": ["10.18.10.50"]},
                },
                "ipv6-address-group": {
                    "NAS6": {"address": ["fd00:18:10::20"]},
                    "VPN-HOSTS6": {"address": ["fd00:18:10::50"]},
                },
                "network-group": {"IOT-NET": {"network": ["10.18.20.0/24"]}},
                "ipv6-network-group": {"IOT-NET6": {"network": ["fd00:18:20::/64"]}},
                "port-group": {"IOT-API": {"port": ["8443-8445"]}},
            },
            "ipv4": {"name": v4},
            "ipv6": {"name": v6},
            "zone": {
                "LAN": {
                    "default-action": "drop",
                    "member": {"interface": ["eth1.10"]},
                    "from": {
                        "WAN": zone("WAN-LAN", "WAN-LAN-6"),
                        "IOT": zone("IOT-LAN", "IOT-LAN-6"),
                        "LOCAL": zone("LOCAL-LAN", "LOCAL-LAN-6"),
                    },
                },
                "IOT": {
                    "default-action": "drop",
                    "member": {"interface": ["eth1.20"]},
                    "from": {"LAN": zone("LAN-IOT", "LAN-IOT-6"), "LOCAL": zone("LOCAL-IOT", "LOCAL-IOT-6")},
                },
                "GUEST": {
                    "default-action": "drop",
                    "member": {"interface": ["eth1.30"]},
                    "from": {"LOCAL": zone("LOCAL-GUEST", "LOCAL-GUEST-6")},
                },
                "WAN": {
                    "default-action": "drop",
                    "member": {"interface": ["eth0", "wg0", "wg1"]},
                    "from": {
                        "LAN": zone("LAN-WAN", "LAN-WAN-6"),
                        "GUEST": zone("GUEST-WAN", "GUEST-WAN-6"),
                        "IOT": zone("IOT-WAN", "IOT-WAN-6"),
                        "LOCAL": zone("LOCAL-WAN", "LOCAL-WAN-6"),
                    },
                },
                "LOCAL": {
                    "default-action": "drop",
                    "local-zone": {},
                    "from": {
                        "LAN": zone("LAN-LOCAL", "LAN-LOCAL-6"),
                        "IOT": zone("IOT-LOCAL", "IOT-LOCAL-6"),
                        "GUEST": zone("GUEST-LOCAL", "GUEST-LOCAL-6"),
                        "WAN": zone("WAN-LOCAL", "WAN-LOCAL-6"),
                    },
                },
            },
        },
        "nat": {
            "source": {
                "rule": {
                    "100": {
                        "description": "internet masquerade",
                        "outbound-interface": {"name": "eth0"},
                        "translation": {"address": "masquerade"},
                    }
                }
            },
            "destination": {
                "rule": {
                    "10": {
                        "description": "nas https",
                        "inbound-interface": {"name": "eth0"},
                        "protocol": "tcp",
                        "destination": {"port": "443"},
                        "translation": {"address": "10.18.10.20"},
                    }
                }
            },
        },
        "nat66": {
            "source": {
                "rule": {
                    "10": {
                        "description": "vpn masquerade",
                        "outbound-interface": {"name": "wg0"},
                        "source": {"prefix": "fd00:18:10::/64"},
                        "translation": {"address": "masquerade"},
                    }
                }
            }
        },
        "policy": {
            "route": {
                "VPN-PBR": {
                    "interface": ["eth1.10"],
                    "rule": {
                        "10": {
                            "description": "vpn hosts",
                            "source": {"group": {"address-group": "VPN-HOSTS"}},
                            "set": {"table": "100"},
                        }
                    },
                }
            },
            "route6": {
                "VPN-PBR6": {
                    "interface": ["eth1.10"],
                    "rule": {
                        "10": {
                            "description": "vpn hosts",
                            "source": {"group": {"address-group": "VPN-HOSTS6"}},
                            "set": {"table": "100"},
                        }
                    },
                }
            },
        },
        "protocols": {
            "static": {
                "route": {
                    "0.0.0.0/0": {"next-hop": {"203.0.113.201": {}}},
                    VYOS_PARTNER_NET: {"interface": {"wg1": {}}},
                    # a lab network behind a router that is gone: the next hop is in no
                    # connected network, so FRR does not install the route
                    VYOS_UNINSTALLED_NET: {"next-hop": {"10.18.99.1": {}}},
                },
                "route6": {"::/0": {"next-hop": {"2001:db8:18::1": {}}}},
                "table": {
                    "100": {
                        "route": {"0.0.0.0/0": {"interface": {"wg0": {}}}},
                        "route6": {"::/0": {"interface": {"wg0": {}}}},
                    }
                },
            }
        },
    }


def vyos_payload() -> dict:
    """The payload the VyOS collector's fetch seals for the Oslo router: the configuration,
    `show version`, the links, the DHCP-learned WAN address and the FRR RIB of the main table
    and of policy table 100, each RIB answer as the JSON text vtysh prints, and the outcome
    the fetch records for each RIB read (`ok`), so the collector mirrors both tables."""
    # this tree's collector, whatever else the interpreter has on its path
    if str(SRC) not in sys.path:
        sys.path.insert(0, str(SRC))
    from hst.collectors.base import RAW_OUTCOMES_KEY

    connected = {
        4: {"203.0.113.200/29": "eth0", "10.18.250.0/30": "wg0", "10.18.251.0/30": "wg1"},
        6: {"2001:db8:18::/64": "eth0", "fd00:18:250::/64": "wg0"},
    }
    for vid, nets in VYOS_LANS.items():
        for net in nets:
            connected[ipaddress.ip_network(net).version][net] = f"eth1.{vid}"

    def rib(default: str, gateway: str) -> dict:
        routes = _frr_route(default, _frr_nh(gateway, "eth0"), protocol="static")
        if ":" not in default:
            routes.update(_frr_route(VYOS_PARTNER_NET, _frr_nh(dev="wg1"), protocol="static"))
        for net, dev in connected[6 if ":" in default else 4].items():
            routes.update(_frr_route(net, _frr_nh(dev=dev, directlyConnected=True), protocol="connected"))
        return {"default": routes}

    return {
        "config": vyos_config(),
        "version_text": VYOS_VERSION,
        "links": [
            {"ifname": "eth0", "address": "02:00:18:00:00:01"},
            {"ifname": "eth1", "address": "02:00:18:00:00:02"},
        ],
        "addrs": [
            {
                "ifname": "eth0",
                "addr_info": [
                    {"family": "inet", "local": "203.0.113.202", "prefixlen": 29, "scope": "global"}
                ],
            }
        ],
        "routes": json.dumps(rib("0.0.0.0/0", "203.0.113.201")),
        "routes6": json.dumps(rib("::/0", "2001:db8:18::1")),
        "routes_tables": {
            "100": json.dumps(_frr_route("0.0.0.0/0", _frr_nh(dev="wg0"), protocol="static", table=100))
        },
        "routes6_tables": {
            "100": json.dumps(_frr_route("::/0", _frr_nh(dev="wg0"), protocol="static", table=100))
        },
        RAW_OUTCOMES_KEY: {read: {"status": "ok"} for read in VYOS_RIB_READS},
    }


# --- Business Application definitions ------------------------------------------------
def yaml_block(value, indent: int = 0) -> list[str]:
    """Minimal block-style YAML for dicts, lists and scalars (enough for the application files)."""
    pad = "  " * indent
    out: list[str] = []
    if isinstance(value, dict):
        for k, val in value.items():
            if isinstance(val, (dict, list)) and val:
                out.append(f"{pad}{k}:")
                out.extend(yaml_block(val, indent + 1))
            else:
                out.append(f"{pad}{k}: {yaml_scalar(val)}")
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                rows = yaml_block(item, indent + 1)
                out.append(f"{pad}- {rows[0].strip()}")
                out.extend(rows[1:])
            else:
                out.append(f"{pad}- {yaml_scalar(item)}")
    return out


def yaml_scalar(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        return "[" + ", ".join(yaml_scalar(v) for v in value) + "]"
    text = str(value)
    if text == "" or any(c in text for c in ":#{}[],&*!|>'\"%@`") or text != text.strip():
        return json.dumps(text)
    return text


def write_apps(est: Estate) -> dict[str, dict]:
    """Five applications on addresses every version carries (no Milan, no retired VIP)."""
    g = est.g

    def addr(uid):
        return g.nodes[uid][1]["ip"]

    def cidr(uid):
        return g.nodes[uid][1]["cidr"]

    clients = [
        ("vienna-users", cidr(est.office_users["vie01"])),
        ("warsaw-users", cidr(est.office_users["waw01"])),
        ("zurich-users", cidr(est.office_users["zrh01"])),
    ]
    apps = {}

    def define(app: str, slug_id: str, env_desc: str, groups: list[dict], connections: list[dict]) -> None:
        spec = APPS[app]
        doc = {
            "schema_version": 1,
            "kind": "BusinessApplication",
            "id": f"{slug_id}-production",
            "name": spec["name"],
            "description": env_desc,
            "environment": "production",
            "state": "draft",
            "services": [
                {
                    "id": f"{slug_id}-service",
                    "name": f"{spec['name']} service",
                    "connection_ids": [c["id"] for c in connections],
                    "component_roles": [{"group_id": groups[1]["id"], "role": "endpoint"}],
                }
            ],
            "groups": groups,
            "connections": connections,
        }
        apps[slug_id] = doc

    def group(gid: str, name: str, members: list[tuple[str, str]]) -> dict:
        return {"id": gid, "name": name, "members": [{"id": mid, "address": a} for mid, a in members]}

    def conn(
        cid: str,
        name: str,
        src: str,
        dst: str,
        port: int,
        member: str,
        success: str = "session",
        proto: str = "tcp",
    ) -> dict:
        return {
            "id": cid,
            "name": name,
            "source": src,
            "destination": dst,
            "protocol": proto,
            "destination_ports": [port],
            "success": success,
            "destination_condition": {"kind": "member", "member": member},
        }

    def tier_members(app: str, tier: str) -> list[tuple[str, str]]:
        return [(f"{app}-{tier}-{i + 1:02d}", addr(u)) for i, u in enumerate(est.vm_ips[(app, tier)])]

    define(
        "webshop",
        "webshop",
        "Customer-facing shop: office clients to the NetScaler VIP, web to API, API to PostgreSQL.",
        [
            group("office-clients", "Office clients", clients),
            group("frontend", "Webshop VIP", [("webshop-vip", addr(est.vip_ip[("webshop", "web", 443)]))]),
            group("web", "Web tier", tier_members("webshop", "web")),
            group("api", "API tier", tier_members("webshop", "api")),
            group("db", "Database", tier_members("webshop", "db")),
        ],
        [
            conn("clients-to-vip", "Office clients to VIP", "office-clients", "frontend", 443, "webshop-vip"),
            conn("web-to-api", "Web to API", "web", "api", 8080, "webshop-api-01", "round-trip"),
            conn("api-to-db", "API to database", "api", "db", 5432, "webshop-db-01"),
        ],
    )
    define(
        "payments",
        "payments",
        "Card and transfer processing in Munich: PCI tiers behind the dc2 firewall cluster.",
        [
            group("office-clients", "Finance clients", clients[:2]),
            group("frontend", "Payments VIP", [("payments-vip", addr(est.vip_ip[("payments", "web", 443)]))]),
            group("web", "Web tier", tier_members("payments", "web")),
            group("api", "Payments API", tier_members("payments", "api")),
            group("db", "Oracle database", tier_members("payments", "db")),
        ],
        [
            conn(
                "clients-to-vip", "Finance clients to VIP", "office-clients", "frontend", 443, "payments-vip"
            ),
            conn("web-to-api", "Web tier to API", "web", "api", 9443, "payments-api-01", "round-trip"),
            conn("api-to-db", "API to Oracle", "api", "db", 1521, "payments-db-01"),
        ],
    )
    define(
        "claims",
        "claims-portal",
        "Claims handling: web and application tiers in Frankfurt, database in Munich.",
        [
            group("agents", "Claims agents", clients),
            group("frontend", "Claims VIP", [("claims-vip", addr(est.vip_ip[("claims", "web", 443)]))]),
            group("web", "Web tier", tier_members("claims", "web")),
            group("app", "Application tier", tier_members("claims", "app")),
            group("db", "Database in dc2", tier_members("claims", "db")),
        ],
        [
            conn("agents-to-vip", "Agents to VIP", "agents", "frontend", 443, "claims-vip"),
            conn(
                "web-to-app",
                "Web to application tier",
                "web",
                "app",
                8009,
                "claims-app-01",
                "round-trip",
            ),
            conn("app-to-db", "Application tier to database", "app", "db", 5432, "claims-db-01"),
        ],
    )
    define(
        "intranet",
        "intranet",
        "Employee intranet in Munich with the search index in Azure.",
        [
            group("employees", "Employees", clients),
            group("frontend", "Intranet VIP", [("intranet-vip", addr(est.vip_ip[("intranet", "web", 443)]))]),
            group("web", "Web tier", tier_members("intranet", "web")),
            group("db", "MariaDB", tier_members("intranet", "db")),
            group("search", "Azure search", [("intranet-search", addr(est.az_ips["az-intranet-search-01"]))]),
        ],
        [
            conn("employees-to-vip", "Employees to VIP", "employees", "frontend", 443, "intranet-vip"),
            conn("web-to-db", "Web to MariaDB", "web", "db", 3306, "intranet-db-01"),
            conn(
                "web-to-search",
                "Web to Azure search",
                "web",
                "search",
                443,
                "intranet-search",
                "round-trip",
            ),
        ],
    )
    define(
        "dwh",
        "data-warehouse",
        "Nightly loads from AWS ingest into the Munich warehouse, reporting from Azure.",
        [
            group(
                "ingest",
                "AWS ingest",
                [
                    ("dwh-ingest-01", addr(est.aws_ips["dwh-ingest-01"])),
                    ("dwh-ingest-02", addr(est.aws_ips["dwh-ingest-02"])),
                ],
            ),
            group("etl", "ETL tier", tier_members("dwh", "etl")),
            group("db", "Warehouse database", tier_members("dwh", "db")),
            group(
                "reporting",
                "Azure reporting",
                [
                    ("dwh-report-01", addr(est.az_ips["az-dwh-report-01"])),
                    ("dwh-report-02", addr(est.az_ips["az-dwh-report-02"])),
                ],
            ),
        ],
        [
            conn("ingest-to-etl", "AWS ingest to ETL", "ingest", "etl", 8443, "dwh-etl-01"),
            conn("etl-to-db", "ETL to warehouse", "etl", "db", 5439, "dwh-db-01"),
            conn(
                "reporting-to-db",
                "Azure reporting to warehouse",
                "reporting",
                "db",
                5439,
                "dwh-db-01",
                "round-trip",
            ),
        ],
    )
    (OUT / "apps").mkdir(parents=True, exist_ok=True)
    for slug_id, doc in apps.items():
        (OUT / "apps" / f"{slug_id}.yaml").write_text("\n".join(yaml_block(doc)) + "\n", encoding="utf-8")
    return apps


HEADERS = {
    1: "Norlund estate, version 1 (mid 2026): two ACI data centers, Equinix FR5, six offices, AWS and Azure.",
    2: "Norlund estate, version 2: v1 plus the Lisbon office (lis01), the Claims Portal API tier "
    "and its firewall rules.",
    3: "Norlund estate, version 3: v2 minus the Milan office (mil01) and the retired Intranet port-80 VIP, "
    "plus Azure West Europe.",
}
# every version: the Oslo office, built from the VyOS collector's own batch (`Estate.vyos_office`)
OSLO_HEADER = "The Oslo office (osl01) is a dual-stack VyOS site, normalized by the VyOS collector."


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    estates = {}
    for v in (1, 2, 3):
        est = Estate(v)
        g = est.build()
        path = OUT / f"estate-v{v}.yaml"
        g.write(
            path,
            HEADERS[v] + "\nGenerated by tools/gen_demo_enterprise.py; do not edit by hand.\n" + OSLO_HEADER,
        )
        labels = sorted({label for label, _ in g.nodes.values()})
        print(
            f"{path.name}: {len(g.nodes)} nodes, {len(g.rels)} rels, {len(labels)} labels, "
            f"cp rules {est.cp_rules}"
        )
        estates[v] = est
    write_apps(estates[1])
    if "--diff" in sys.argv:
        for a, b in ((1, 2), (2, 3)):
            na, nb = estates[a].g.nodes, estates[b].g.nodes
            added = sorted(u for u in nb if u not in na)
            removed = sorted(u for u in na if u not in nb)
            print(f"v{a} -> v{b}: +{len(added)} nodes, -{len(removed)} nodes")
            for u in added[:400]:
                print("  +", u)
            for u in removed[:400]:
                print("  -", u)


if __name__ == "__main__":
    main()
