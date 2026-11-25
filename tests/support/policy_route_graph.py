"""A VyOS router that steers clients into two WireGuard tunnels with policy
routes, and a graph session that answers the generator tools' reads from the
collector's batch.

The config has the shape of the policy-route application report: two
`policy route` policies bound to two ingress VLANs, each starting with a rule
that keeps local destinations in the main table; rules whose sources are an
address group (one with a range) or an inline range; and two policy tables
whose single default route leaves through `wg0` and `wg44`. The main table's
default route leaves through `eth0`, the WAN. A zone firewall puts the client
VLANs in zone LAN and `eth0`, `wg0` and `wg44` in zone WAN, and the LAN-WAN
ruleset (default accept) drops the tunnel-b-download sources leaving by
`eth0` in rule 10: the leak guard of `wg44` that `policy_evaluate` explains
(`path/leak_guard.py`).

`BatchGraph` answers each query the tools issue (`generator_tools`,
`path.gates.pbr.POLICY_RULES` and the reads of `path.leak_guard`) by walking
the batch's nodes and edges, in the row shape the Cypher returns.
`tests/test_application_generator_policy_routes_db.py` and
`tests/test_policy_leak_guard_db.py` run the same reads on the same batch
loaded into Neo4j.
"""

from __future__ import annotations

import contextlib
import copy
from collections.abc import Callable, Iterator
from types import SimpleNamespace
from typing import Any

from hst.applications import generator_tools as tools
from hst.collectors.vyos import normalize_vyos
from hst.core import uid as uidmod
from hst.core.model import Batch
from hst.path import leak_guard, netobjects
from hst.path.gates import firewall, pbr, routing
from hst.path.trace import _IFACE_BY_NAME_QUERY, _ROUTES_QUERY, _VRF_NAME_QUERY

HOST = "gw"
DEV = f"dev:{HOST}"
TUNNEL_A = f"tun:wireguard:{DEV}~wg0~peer-a"
TUNNEL_B = f"tun:wireguard:{DEV}~wg44~peer-b"
WG0 = f"{DEV}/if/wg0"
WG44 = f"{DEV}/if/wg44"
VLAN10 = uidmod.interface(DEV, "eth1.10")
VLAN210 = uidmod.interface(DEV, "eth1.210")
TABLE_A = f"vrf:{DEV}:table100"
TABLE_B = f"vrf:{DEV}:table144"
MAIN = f"vrf:{DEV}:default"
ETH0 = f"{DEV}/if/eth0"
LAN_WAN = f"vyos:{HOST}:fw:LAN-WAN"
GUARD = f"{LAN_WAN}:10"
POLICY = f"vyos:{HOST}:pbr:VPN-PBR"
DEDICATED = f"vyos:{HOST}:pbr:VPN-PBR-DEDICATED"
GROUP_A = f"vyos:{HOST}:grp:addr:tunnel-a-clients"
GROUP_B = f"vyos:{HOST}:grp:addr:tunnel-b-download"
RANGE = "10.20.210.50-10.20.210.100"
# the networks of RANGE, smallest first
RANGE_NETWORKS = [
    "10.20.210.50/31",
    "10.20.210.52/30",
    "10.20.210.56/29",
    "10.20.210.64/27",
    "10.20.210.96/30",
    "10.20.210.100",
]
# every IPv4 destination outside 10.20.0.0/16
NOT_LOCAL = [
    "0.0.0.0/5",
    "8.0.0.0/7",
    "10.0.0.0/12",
    "10.16.0.0/14",
    "10.21.0.0/16",
    "10.22.0.0/15",
    "10.24.0.0/13",
    "10.32.0.0/11",
    "10.64.0.0/10",
    "10.128.0.0/9",
    "11.0.0.0/8",
    "12.0.0.0/6",
    "16.0.0.0/4",
    "32.0.0.0/3",
    "64.0.0.0/2",
    "128.0.0.0/1",
]

LOCAL_RULE = {
    "description": "local stays local",
    "destination": {"address": "10.20.0.0/16"},
    "set": {"table": "main"},
}

CONFIG: dict[str, Any] = {
    "system": {"host-name": HOST},
    "interfaces": {
        "ethernet": {
            "eth0": {"address": ["dhcp"], "description": "WAN"},
            "eth1": {
                "address": ["10.20.1.1/24"],
                "vif": {
                    "10": {"address": ["10.20.10.1/24"], "description": "clients"},
                    "210": {"address": ["10.20.210.1/24"], "description": "media"},
                },
            },
        },
        "wireguard": {
            "wg0": {
                "address": ["10.66.0.2/32"],
                "peer": {
                    "peer-a": {"address": "198.51.100.10", "port": "51820", "allowed-ips": ["0.0.0.0/0"]}
                },
            },
            "wg44": {
                "address": ["10.67.0.2/32"],
                "description": "peer b tunnel",
                "peer": {
                    "peer-b": {"address": "203.0.113.20", "port": "51820", "allowed-ips": ["0.0.0.0/0"]}
                },
            },
        },
    },
    "firewall": {
        "group": {
            "address-group": {
                "tunnel-a-clients": {"address": ["10.20.10.43", "10.20.10.44", "10.20.10.45"]},
                "tunnel-b-download": {"address": ["10.20.10.60", "10.20.10.70-10.20.10.72"]},
            },
        },
        "ipv4": {
            "name": {
                "LAN-WAN": {
                    "default-action": "accept",
                    "rule": {
                        "10": {
                            "action": "drop",
                            "description": "no breakout for tunnel b",
                            "source": {"group": {"address-group": "tunnel-b-download"}},
                            "outbound-interface": {"name": "eth0"},
                        }
                    },
                }
            }
        },
        "zone": {
            "LAN": {"default-action": "drop", "member": {"interface": ["eth1", "eth1.10", "eth1.210"]}},
            "WAN": {
                "default-action": "drop",
                "member": {"interface": ["eth0", "wg0", "wg44"]},
                "from": {"LAN": {"firewall": {"name": "LAN-WAN"}}},
            },
        },
    },
    "policy": {
        "route": {
            "VPN-PBR": {
                "interface": ["eth1.10"],
                "rule": {
                    "10": LOCAL_RULE,
                    "20": {
                        "source": {"group": {"address-group": "tunnel-a-clients"}},
                        "set": {"table": "100"},
                    },
                    "30": {
                        "source": {"group": {"address-group": "tunnel-b-download"}},
                        "set": {"table": "144"},
                    },
                },
            },
            "VPN-PBR-DEDICATED": {
                "interface": ["eth1.210"],
                "rule": {
                    "10": LOCAL_RULE,
                    "20": {"source": {"address": RANGE}, "set": {"table": "100"}},
                },
            },
        },
    },
    "protocols": {
        "static": {
            "route": {"0.0.0.0/0": {"interface": {"eth0": {}}}},
            "table": {
                "100": {"route": {"0.0.0.0/0": {"interface": {"wg0": {}}}}},
                "144": {"route": {"0.0.0.0/0": {"interface": {"wg44": {}}}}},
            },
        }
    },
}

VERSION = "Version:          VyOS 1.5-rolling-202607150020\nHardware S/N:     PBRAPP1\n"
LINKS = [
    {"ifname": "eth0", "address": "aa:bb:cc:00:00:01"},
    {"ifname": "eth1", "address": "aa:bb:cc:00:00:02"},
]


def batch(patch: Callable[[dict[str, Any]], None] | None = None) -> Batch:
    """The collector's batch of CONFIG, after `patch` edits a copy of it."""
    cfg = copy.deepcopy(CONFIG)
    if patch is not None:
        patch(cfg)
    return normalize_vyos({"config": cfg, "version_text": VERSION, "links": LINKS}, l3dom="home")


class BatchGraph:
    """A graph session over one batch that answers the generator tools'
    reads, every object at the one run the session is pinned to."""

    cts = 4000

    def __init__(self, source: Batch) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        for node in source.nodes:
            entry = self.nodes.setdefault(node.uid, {"uid": node.uid, "labels": set()})
            entry["labels"].add(node.label)
            entry.update(node.props)
        self.rels = [(rel.rel_type, rel.start_uid, rel.end_uid, dict(rel.props)) for rel in source.rels]
        self.queries: list[str] = []
        self.answer = {
            tools._NODE: self._node,
            tools._TUNNEL_INTERFACES: self._tunnel_interfaces,
            tools._INTERFACE_ROUTES: self._interface_routes,
            tools._TABLE_ROUTES: self._table_routes,
            tools._REDIRECTING_POLICIES: self._redirecting,
            pbr.POLICY_RULES: self._policy_rules,
            tools._POLICY_BINDINGS: self._bindings,
            netobjects.RULE_OBJECTS: self._rule_objects,
            netobjects.NET_OBJECTS: self._net_objects,
            firewall._RULEBASE_RULES: self._rulebase_rules,
            leak_guard._RULEBASE_SCOPE: self._rulebase_scope,
            leak_guard._DEVICE_INTERFACES: self._device_interfaces,
            leak_guard._DEVICE_NAMES: self._device_names,
            pbr._DEVICE_PBR_POLICIES: self._device_pbr_policies,
            pbr._DEFAULT_TABLE_QUERY: self._default_table,
            _ROUTES_QUERY: self._table_route_rows,
            _IFACE_BY_NAME_QUERY: self._iface_by_name,
            _VRF_NAME_QUERY: self._vrf_name,
            routing._CONNECTED_LOCAL_QUERY: self._connected_local,
            routing._CONNECTED_INGRESS_QUERY: self._connected_ingress,
            routing._CONNECTED_REMOTE_QUERY: self._connected_remote,
        }

    # the session protocol `path._read` uses
    def execute_read(self, work: Callable[[Any], Any]) -> Any:
        return work(self)

    def run(self, query: str, **params: Any) -> Any:
        self.queries.append(query)
        rows = self.answer[query](**params)
        return SimpleNamespace(data=lambda: rows)

    @contextlib.contextmanager
    def opened(self, *_args: Any, **_kwargs: Any) -> Iterator[BatchGraph]:
        yield self

    # graph walking

    def has(self, uid: str | None, label: str) -> bool:
        return uid in self.nodes and label in self.nodes[uid]["labels"]

    def out(self, uid: str, *types: str) -> list[tuple[str, str, dict[str, Any]]]:
        return [(kind, end, props) for kind, start, end, props in self.rels if start == uid and kind in types]

    def into(self, uid: str, *types: str) -> list[tuple[str, str, dict[str, Any]]]:
        return [(kind, start, props) for kind, start, end, props in self.rels if end == uid and kind in types]

    def get(self, uid: str, key: str) -> Any:
        return self.nodes.get(uid, {}).get(key)

    # the reads

    def _node(self, uid: str, snap: int) -> list[dict[str, Any]]:
        node = self.nodes.get(uid)
        if node is None:
            return []
        name = next((node[k] for k in ("name", "hostname", "fqdn", "code") if node.get(k)), uid)
        return [
            {
                "labels": [*sorted(node["labels"]), "Obj"],
                "name": name,
                "address": node.get("ip") or node.get("cidr"),
            }
        ]

    def _tunnel_interfaces(self, uid: str, snap: int) -> list[dict[str, Any]]:
        return sorted(
            ({"uid": end, "name": self.get(end, "name")} for _k, end, _p in self.out(uid, "ENDPOINT")),
            key=lambda row: row["uid"],
        )

    def _routes(
        self, tables: list[str] | None, ifs: list[str] | None, optional: bool
    ) -> list[dict[str, Any]]:
        rows = []
        for kind, table, prefix, props in self.rels:
            if kind not in ("STATIC_ROUTE", "LEARNED_ROUTE") or (tables is not None and table not in tables):
                continue
            vias = [
                end
                for _k, end, via in self.out(prefix, "VIA")
                if self.has(end, "Interface") and via.get("vrf", table) == table
            ]
            if ifs is not None:
                vias = [end for end in vias if end in ifs]
            for end in vias or ([None] if optional else []):
                rows.append(
                    {
                        "table_uid": table,
                        "table_name": self.get(table, "name"),
                        "cidr": self.get(prefix, "cidr"),
                        "if_uid": end,
                        "if_name": self.get(end, "name") if end else None,
                        "next_hop": props.get("next_hop"),
                    }
                )
        return sorted(rows, key=lambda row: (row["table_uid"], row["cidr"], row["if_uid"] or ""))

    def _interface_routes(self, ifs: list[str], snap: int) -> list[dict[str, Any]]:
        return self._routes(None, ifs, optional=False)

    def _table_routes(self, uid: str, snap: int) -> list[dict[str, Any]]:
        return self._routes([uid], None, optional=True)

    def _rules(self, pol: str) -> list[str]:
        rules = [end for _k, end, _p in self.out(pol, "HAS_RULE") if self.get(end, "enabled")]
        return sorted(rules, key=lambda uid: self.get(uid, "position"))

    def _redirecting(self, tables: list[str], snap: int) -> list[dict[str, Any]]:
        found = {
            start
            for kind, start, rule, _p in self.rels
            if kind == "HAS_RULE" and self.has(start, "PbrPolicy") and self.get(rule, "enabled")
            for _k, table, _q in self.out(rule, "REDIRECTS_VIA")
            if table in tables
        }
        return [{"uid": uid} for uid in sorted(found)]

    def _side(self, rule: str, rel: str) -> dict[str, list[Any]]:
        objects = [end for _k, end, _p in self.out(rule, rel) if self.has(end, "NetObject")]
        targets = [end for obj in objects for _k, end, _p in self.out(obj, "RESOLVES_TO")]
        return {
            "cidrs": [self.get(t, "cidr") for t in targets if self.get(t, "cidr")],
            "ips": [self.get(t, "ip") for t in targets if self.get(t, "ip")],
            "ranges": [self.get(obj, "ranges") for obj in objects if self.get(obj, "ranges")],
        }

    def _policy_rules(self, pol_uids: list[str], snap: int) -> list[dict[str, Any]]:
        rows = []
        for pol in sorted(pol_uids, key=lambda uid: self.get(uid, "name")):
            rules = self._rules(pol)
            for rule in rules or [None]:
                row: dict[str, Any] = {"pol_uid": pol, "pol_name": self.get(pol, "name"), "rule_uid": rule}
                if rule is not None:
                    src, dst = self._side(rule, "SRC"), self._side(rule, "DST")
                    svc = [end for _k, end, _p in self.out(rule, "SVC")]
                    table = next((end for _k, end, _p in self.out(rule, "REDIRECTS_VIA")), None)
                    row.update(
                        pos=self.get(rule, "position"),
                        rule_name=self.get(rule, "name"),
                        src_cidrs=src["cidrs"],
                        src_ips=src["ips"],
                        src_ranges=src["ranges"],
                        dst_cidrs=dst["cidrs"],
                        dst_ips=dst["ips"],
                        dst_ranges=dst["ranges"],
                        table_uid=table,
                        table_name=self.get(table, "name") if table else None,
                        svc_obj_count=len(svc),
                        svc_protos=[self.get(s, "proto") for s in svc],
                        svc_port_specs=[self.get(s, "ports") for s in svc],
                        svc_opaque=any(self.get(s, "opaque") for s in svc),
                        svc_opaque_reasons=[
                            self.get(s, "opaque_reason") for s in svc if self.get(s, "opaque_reason")
                        ],
                        svc_src_port=any(self.get(s, "src_port") for s in svc),
                        svc_src_ports=[self.get(s, "src_port") for s in svc],
                    )
                rows.append(row)
        return rows

    def _bindings(self, pol_uids: list[str], snap: int) -> list[dict[str, Any]]:
        rows = []
        for pol in sorted(pol_uids):
            starts = [start for _k, start, _p in self.into(pol, "ENFORCES")]
            rows.append(
                {
                    "uid": pol,
                    "name": self.get(pol, "name"),
                    "interfaces": [
                        {"uid": s, "name": self.get(s, "name")} for s in starts if self.has(s, "Interface")
                    ],
                    "devices": [
                        {"uid": s, "name": self.get(s, "hostname") or self.get(s, "name") or s}
                        for s in starts
                        if self.has(s, "Device")
                    ],
                }
            )
        return rows

    def _rule_objects(self, rules: list[str], snap: int) -> list[dict[str, Any]]:
        rows = [
            {"rule_uid": rule, "side": kind, "uid": end}
            for rule in rules
            for kind, end, _p in self.out(rule, "SRC", "DST")
            if self.has(end, "NetObject")
        ]
        return sorted(rows, key=lambda row: (row["rule_uid"], row["side"], row["uid"]))

    def _net_objects(self, uids: list[str], snap: int) -> list[dict[str, Any]]:
        rows = []
        for uid in sorted(uids):
            if not self.has(uid, "NetObject"):
                continue
            targets = [
                {
                    "uid": end,
                    "labels": [*sorted(self.nodes[end]["labels"]), "Obj"],
                    "ip": self.get(end, "ip"),
                    "cidr": self.get(end, "cidr"),
                }
                for _k, end, _p in self.out(uid, "RESOLVES_TO")
            ]
            rows.append(
                {
                    "uid": uid,
                    "name": self.get(uid, "name"),
                    "kind": self.get(uid, "kind"),
                    "ranges": self.get(uid, "ranges"),
                    "opaque": bool(self.get(uid, "opaque")),
                    "opaque_reason": self.get(uid, "opaque_reason"),
                    "targets": targets,
                }
            )
        return rows

    # the reads of the leak guard analysis

    def _rulebase_rules(self, rb: str, snap: int) -> list[dict[str, Any]]:
        rows = []
        for rule in self._rules(rb):
            src, dst = self._side(rule, "SRC"), self._side(rule, "DST")
            svc = [end for _k, end, _p in self.out(rule, "SVC")]
            row: dict[str, Any] = {
                "uid": rule,
                "pos": self.get(rule, "position"),
                "action": self.get(rule, "action"),
                "name": self.get(rule, "name"),
                "out_if": self.get(rule, "out_interface"),
                "in_if": self.get(rule, "in_interface"),
                "out_if_group": self.get(rule, "out_interface_group"),
                "in_if_group": self.get(rule, "in_interface_group"),
                "states": self.get(rule, "states") or [],
                "states_opaque": bool(self.get(rule, "states_opaque")),
                "states_opaque_reason": self.get(rule, "states_opaque_reason"),
                "svc_any": False,
                "src_negate": False,
                "dst_negate": False,
                "svc_negate": False,
                "protos": [self.get(s, "proto") for s in svc],
                "ports": [self.get(s, "ports") for s in svc],
                "svc_opaque": any(self.get(s, "opaque") for s in svc),
                "svc_opaque_reasons": [
                    self.get(s, "opaque_reason") for s in svc if self.get(s, "opaque_reason")
                ],
                "svc_src_port": any(self.get(s, "src_port") for s in svc),
                "src_ports": [self.get(s, "src_port") for s in svc],
                "svc_obj_count": len(svc),
            }
            for side, found, rel in (("src", src, "SRC"), ("dst", dst, "DST")):
                objects = [end for _k, end, _p in self.out(rule, rel) if self.has(end, "NetObject")]
                row.update(
                    {
                        f"{side}_any": bool(self.get(rule, f"{side}_any")),
                        f"{side}_cidrs": found["cidrs"],
                        f"{side}_ips": found["ips"],
                        f"{side}_ranges": found["ranges"],
                        f"{side}_obj_count": len(objects),
                        f"{side}_opaque": any(self.get(o, "opaque") for o in objects),
                        f"{side}_opaque_reasons": [
                            self.get(o, "opaque_reason") for o in objects if self.get(o, "opaque_reason")
                        ],
                    }
                )
            rows.append(row)
        return rows

    def _device_of(self, interface: str) -> str | None:
        return next((end for _k, end, _p in self.out(interface, "ON") if self.has(end, "Device")), None)

    def _zone_members(self, rb: str, rel: str) -> list[dict[str, Any]]:
        return [
            {"uid": member, "zone": self.get(zone, "name"), "device": self._device_of(member)}
            for _k, zone, _p in self.out(rb, rel)
            for _c, member, _q in self.out(zone, "CONTAINS")
            if self.has(member, "Interface")
        ]

    def _rulebase_scope(self, rb: str, snap: int) -> list[dict[str, Any]]:
        if not self.has(rb, "FwRulebase"):
            return []
        return [
            {
                "name": self.get(rb, "name"),
                "af": self.get(rb, "af"),
                "chain": self.get(rb, "chain"),
                "kind": self.get(rb, "kind"),
                "match_context": self.get(rb, "match_context"),
                "zone_bound": bool(self.out(rb, "FROM_ZONE", "TO_ZONE")),
                "from_ifs": self._zone_members(rb, "FROM_ZONE"),
                "to_ifs": self._zone_members(rb, "TO_ZONE"),
                "enforced": [s for _k, s, _p in self.into(rb, "ENFORCES") if self.has(s, "Device")],
                "bindings": [
                    {
                        "uid": s,
                        "name": self.get(s, "name"),
                        "direction": p.get("direction"),
                        "device": self._device_of(s),
                    }
                    for _k, s, p in self.into(rb, "PROTECTED_BY")
                ],
            }
        ]

    def _device_interfaces(self, dev: str, snap: int) -> list[dict[str, Any]]:
        rows = []
        for _k, uid, _p in self.into(dev, "ON"):
            if not self.has(uid, "Interface"):
                continue
            rows.append(
                {
                    "uid": uid,
                    "name": self.get(uid, "name"),
                    "description": self.get(uid, "description"),
                    "zones": [self.get(z, "name") for _c, z, _q in self.into(uid, "CONTAINS")],
                    "tunnels": [
                        {"uid": t, "name": self.get(t, "name")} for _e, t, _q in self.into(uid, "ENDPOINT")
                    ],
                }
            )
        return sorted(rows, key=lambda row: row["uid"])

    def _device_names(self, uids: list[str], snap: int) -> list[dict[str, Any]]:
        return [
            {"uid": uid, "name": self.get(uid, "hostname") or self.get(uid, "name")}
            for uid in sorted(uids)
            if self.has(uid, "Device")
        ]

    def _device_pbr_policies(self, dev: str, snap: int) -> list[dict[str, Any]]:
        rows = [
            {"pol_uid": pol, "if_uid": interface}
            for _k, interface, _p in self.into(dev, "ON")
            if self.has(interface, "Interface")
            for _e, pol, _q in self.out(interface, "ENFORCES")
            if self.has(pol, "PbrPolicy")
        ]
        return sorted(rows, key=lambda row: row["pol_uid"])

    def _default_table(self, if_uid: str, snap: int) -> list[dict[str, Any]]:
        tables = sorted(end for _k, end, _p in self.out(if_uid, "IN_VRF") if self.has(end, "VrfInstance"))
        return [{"uid": tables[0]}] if tables else []

    def _table_route_rows(self, vrf: str, snap: int) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for kind, start, prefix, props in self.rels:
            if start != vrf or kind not in ("STATIC_ROUTE", "LEARNED_ROUTE", "ORIGINATES"):
                continue
            ifname = props.get("interface") or props.get("rib_interface")
            egress = next(
                (
                    end
                    for _k, end, via in self.out(prefix, "VIA")
                    if via.get("vrf") == vrf and self.get(end, "name") == ifname
                ),
                None,
            )
            row = {
                "uid": prefix,
                "cidr": self.get(prefix, "cidr"),
                "kind": kind,
                "next_hop": props.get("next_hop"),
                "ifname": ifname,
                "egress_uid": egress,
                "egress_name": self.get(egress, "name") if egress else None,
                "derived": props.get("derived"),
                "via_rt": props.get("via_rt"),
                "rib": props.get("rib_confirmed"),
                "next_hop_vrf": props.get("next_hop_vrf"),
                "discard": props.get("discard"),
            }
            if row not in rows:
                rows.append(row)
        return rows

    def _iface_by_name(self, name: str, dev: str, vrf: str | None, snap: int) -> list[dict[str, Any]]:
        found = [
            uid
            for _k, uid, _p in self.into(dev, "ON")
            if self.has(uid, "Interface")
            and self.get(uid, "name") == name
            and (vrf is None or any(end == vrf for _v, end, _q in self.out(uid, "IN_VRF")))
        ]
        return [{"uid": found[0], "name": name}] if len(found) == 1 else []

    def _vrf_name(self, u: str, snap: int) -> list[dict[str, Any]]:
        return [{"n": self.get(u, "name")}] if self.has(u, "VrfInstance") else []

    def _gateways(self, prefix: str) -> list[str]:
        """The interfaces GATEWAY_FOR a connected prefix. The reasoner writes
        the edge, so the batch does not hold it: these are the interfaces its
        gateway rule takes, the ones holding an address IN the prefix."""
        return sorted(
            {
                interface
                for _k, address, _p in self.into(prefix, "IN")
                for _h, interface, _q in self.into(address, "HAS_IP")
                if self.has(interface, "Interface")
            }
        )

    def _connected_local(self, p: str, dev: str, in_if: str, snap: int) -> list[dict[str, Any]]:
        found = [i for i in self._gateways(p) if i != in_if and self._device_of(i) == dev]
        return [{"uid": found[0], "name": self.get(found[0], "name")}] if found else []

    def _connected_ingress(self, p: str, in_if: str, snap: int) -> list[dict[str, Any]]:
        return [{"uid": in_if, "name": self.get(in_if, "name")}] if in_if in self._gateways(p) else []

    def _connected_remote(self, p: str, snap: int) -> list[dict[str, Any]]:
        return [{"uid": i, "name": self.get(i, "name")} for i in self._gateways(p)]
