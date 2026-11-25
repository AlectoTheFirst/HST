"""The configuration section of one interface in the raw payload of a device,
and the sections of the device for version, routing, ACLs and NAT (`device_sections`).

The raw payload maps each command to its answer. IOS-XE and NX-OS answer with the running-config
interface stanzas, VyOS with its whole configuration as JSON. IOS-XR collects no interface
configuration and has no section. A UniFi payload holds the controller's `stat/device`,
`rest/networkconf` and `rest/portconf` for every device of the site.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from hst.core.redaction import is_secret_key, redact

# The commands whose answers hold the interface stanzas, per collector family.
STANZA_COMMANDS = ("show running-config | section ^interface", "show running-config interface")
VYOS_CONFIG = "show configuration json"

# The configuration fields of a UniFi `port_table` entry that the section shows.
UNIFI_PORT_CONFIG = (
    "autoneg",
    "dot1x_ctrl",
    "excluded_networkconf_ids",
    "forward",
    "isolation",
    "native_networkconf_id",
    "op_mode",
    "poe_mode",
    "portconf_id",
    "stp_port_mode",
    "tagged_networkconf_ids",
    "tagged_vlan_mgmt",
)
_UNIFI_INTERNAL = frozenset({"_id", "site_id", "port_idx"})


def _stanza(text: str, name: str) -> str | None:
    """The stanza `interface <name>` and its indented lines."""
    header = f"interface {name}".lower()
    out: list[str] = []
    for line in text.split("\n"):
        if out:
            if not line[:1].isspace() or not line.strip():
                break
            out.append(line.rstrip())
        elif line.rstrip().lower() == header:
            out.append(line.rstrip())
    return "\n".join(out) if out else None


def _vyos_text(node: Any) -> str:
    """A VyOS configuration node as JSON, with the value of every credential key cleared
    (`redaction.redact`), such as a MACsec `cak` or an SNMP community that is itself a key."""
    return json.dumps(redact(node), indent=2, sort_keys=True)


def _vyos(config: Mapping[str, Any], name: str) -> tuple[str, str] | None:
    interfaces = config.get("interfaces")
    if not isinstance(interfaces, Mapping):
        return None
    for kind, members in sorted(interfaces.items()):
        if isinstance(members, Mapping) and name in members:
            node = members[name]
            return f"{VYOS_CONFIG} interfaces {kind} {name}", _vyos_text(node)
    return None


def is_unifi(payload: Mapping[str, Any]) -> bool:
    return isinstance(payload.get("devices"), list) and isinstance(payload.get("networks"), list)


def _mac(value: Any) -> str:
    return re.sub(r"[^0-9a-f]", "", str(value or "").lower())


def _rows(value: Any) -> list[Mapping[str, Any]]:
    return [r for r in value if isinstance(r, Mapping)] if isinstance(value, list) else []


def _unifi_device(devices: Any, device: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """The payload device with the graph Device's `mac`, else its `serial` (the collector's serial or mac)."""
    mac, serial = _mac(device.get("mac")), device.get("serial")
    rows = _rows(devices)
    found = next((d for d in rows if mac and _mac(d.get("mac")) == mac), None)
    return found or next((d for d in rows if serial and (d.get("serial") or d.get("mac")) == serial), None)


def _unifi_port(d: Mapping[str, Any], name: str) -> Mapping[str, Any] | None:
    """The one port named `name` as the collector names it, else the one whose uid ends in `name`."""
    table = [p for p in _rows(d.get("port_table")) if p.get("port_idx") is not None]
    if not table and d.get("type") == "uap":
        table = [{"port_idx": 0, "name": "eth0"}]
    found = [p for p in table if (p.get("name") or f"Port {p['port_idx']}") == name]
    index = re.fullmatch(r"port(\d+)", name)
    if not found and index:
        found = [p for p in table if str(p["port_idx"]) == index.group(1)]
    return found[0] if len(found) == 1 else None


def _network(n: Mapping[str, Any]) -> str:
    label = str(n.get("name") or n["_id"])
    return f"{label} (vlan {n['vlan']})" if n.get("vlan") else label


def _named(names: Mapping[str, str], value: Any) -> Any:
    return names.get(value, value) if isinstance(value, str) else value


def _resolved(value: Any, networks: Mapping[str, str], profiles: Mapping[str, str]) -> Any:
    """`value` without internal ids and credentials, its network and profile ids replaced by their names."""
    if isinstance(value, list):
        return [_resolved(v, networks, profiles) for v in value]
    if not isinstance(value, Mapping):
        return value
    out: dict[str, Any] = {}
    for k, v in value.items():
        if k in _UNIFI_INTERNAL or k.startswith("attr_") or is_secret_key(k) or "key" in k.lower():
            continue
        if k.endswith("networkconf_id"):
            out[k.removesuffix("conf_id")] = _named(networks, v)
        elif k.endswith("networkconf_ids") and isinstance(v, list):
            out[k.removesuffix("conf_ids") + "s"] = [_named(networks, i) for i in v]
        elif k == "portconf_id":
            out["portconf"] = _named(profiles, v)
        else:
            out[k] = _resolved(v, networks, profiles)
    return out


def _unifi(payload: Mapping[str, Any], name: str, device: Mapping[str, Any]) -> tuple[str, str] | None:
    d = _unifi_device(payload.get("devices"), device)
    port = _unifi_port(d, name) if d is not None else None
    if d is None or port is None:
        return None
    idx = port["port_idx"]
    networks = {n["_id"]: _network(n) for n in _rows(payload.get("networks")) if n.get("_id")}
    by_id = {p["_id"]: p for p in _rows(payload.get("port_profiles")) if p.get("_id")}
    profiles = {k: str(p.get("name") or k) for k, p in by_id.items()}
    override = next((o for o in _rows(d.get("port_overrides")) if o.get("port_idx") == idx), None)
    ifname = port.get("ifname")
    ethernet = next(
        (o for o in _rows(d.get("ethernet_overrides")) if ifname and o.get("ifname") == ifname), None
    )
    parts = {
        "port_overrides": override,
        "ethernet_overrides": ethernet,
        "port_table": {k: port[k] for k in UNIFI_PORT_CONFIG if k in port},
        "portconf": by_id.get((override or {}).get("portconf_id") or port.get("portconf_id")),
    }
    used = {k: _resolved(v, networks, profiles) for k, v in parts.items() if v}
    head = {"device": d.get("name"), "name": port.get("name") or f"Port {idx}", "port_idx": idx}
    text = json.dumps({**head, **used}, indent=2, sort_keys=True)
    return ("unifi " + " + ".join(used) if used else "unifi stat/device"), text


# The device sections, in the order they are shown. A command's answer goes to the first section whose
# pattern matches the command, in the order of DEVICE_SECTIONS. An ACL or NAT command is matched
# before routing.
SECTION_ORDER = ("version", "routing", "acls", "nat")
SECTION_TITLES = {"version": "Version", "routing": "Routing", "acls": "ACLs", "nat": "NAT"}
DEVICE_SECTIONS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("version", re.compile(r"^show version\b")),
    ("acls", re.compile(r"access-list")),
    ("nat", re.compile(r"\bnat\b")),
    (
        "routing",
        re.compile(
            r"running-config.*\b(bgp|ospf|eigrp|isis|rip|rpm|route-map"
            r"|prefix-li\w*|router|static|ip route)\b"
        ),
    ),
)
# The top-level nodes of a VyOS configuration that hold each section.
VYOS_SECTIONS = (("routing", "protocols"), ("routing", "policy"), ("acls", "firewall"), ("nat", "nat"))


def _readable(text: str) -> str:
    """A JSON answer (NX-OS `| json`) indented for reading. Any other answer is returned without
    trailing whitespace."""
    stripped = text.strip()
    if stripped[:1] in ("{", "["):
        try:
            return json.dumps(json.loads(stripped), indent=2, sort_keys=True)
        except ValueError:
            pass
    return text.rstrip()


# `show ip access-lists | json` on NX-OS, shown as the lines of the access lists (`_nxos_acl_lines`).
NXOS_ACL_COMMAND = "show ip access-lists | json"
# The ACE columns that the lines show in NX-OS syntax. Any other column with a value is kept at the
# end of its line.
_SIDE_COLUMNS = ("any", "ip_prefix", "addrgrp", "port_op", "port1_num", "port1_str", "port2_num", "port2_str")
_ACE_COLUMNS = frozenset(
    {"seqno", "permitdeny", "proto", "proto_str", "ip", "remark", "established", "log", "timerange"}
    | {"icmp_type", "icmp_str", "port_grp", "match_count"}
    | {f"{side}_{c}" for side in ("src", "dest") for c in _SIDE_COLUMNS}
)


def _nxos_rows(table: Any, name: str) -> list[Mapping[str, Any]]:
    """The `ROW_<name>` entries of a `TABLE_<name>` wrapper. One row comes as an object, more rows
    come as a list."""
    wrapper = table.get(f"TABLE_{name}") if isinstance(table, Mapping) else None
    rows = wrapper.get(f"ROW_{name}") if isinstance(wrapper, Mapping) else None
    return _rows(rows) if isinstance(rows, list) else [rows] if isinstance(rows, Mapping) else []


def _ace_side(ace: Mapping[str, Any], side: str) -> list[str]:
    """One side of an ACE in NX-OS syntax, with its address and its port match."""
    if ace.get(f"{side}_any"):
        out = ["any"]
    elif ace.get(f"{side}_ip_prefix"):
        out = [str(ace[f"{side}_ip_prefix"])]
    elif ace.get(f"{side}_addrgrp"):
        out = ["addrgroup", str(ace[f"{side}_addrgrp"])]
    else:
        out = []
    op = ace.get(f"{side}_port_op")
    if op:
        # the port name where NX-OS gives one, as `show ip access-lists` prints it
        first = ace.get(f"{side}_port1_str") or ace.get(f"{side}_port1_num")
        second = ace.get(f"{side}_port2_str") or ace.get(f"{side}_port2_num")
        out += [str(op), *(str(v) for v in (first, second) if v not in (None, ""))]
    return out


def _ace_line(ace: Mapping[str, Any]) -> str:
    """One ACE as NX-OS writes it, for example `10 permit tcp 10.0.0.0/24 203.0.113.10/32 eq 443`.
    An IP rule has its protocol in the `ip` column, every other rule in `proto_str`."""
    words = [str(ace.get("seqno", "")).strip()]
    if ace.get("remark"):
        return " ".join([*words, "remark", str(ace["remark"])]).strip()
    words += [
        str(ace.get("permitdeny") or ""),
        str(ace.get("proto_str") or ace.get("proto") or ace.get("ip") or ""),
    ]
    words += _ace_side(ace, "src") + _ace_side(ace, "dest")
    if ace.get("port_grp"):
        words += ["portgroup", str(ace["port_grp"])]
    if ace.get("icmp_str") or ace.get("icmp_type"):
        words.append(str(ace.get("icmp_str") or ace["icmp_type"]))
    if ace.get("established"):
        words.append("established")
    if ace.get("timerange"):
        words += ["time-range", str(ace["timerange"])]
    if ace.get("log"):
        words.append("log")
    if ace.get("match_count") not in (None, ""):
        words.append(f"[match={ace['match_count']}]")
    extra = [
        f"{k}={v}" for k, v in sorted(ace.items()) if k not in _ACE_COLUMNS and v not in (None, "", [], {})
    ]
    return " ".join(w for w in [*words, *(f"[{e}]" for e in extra)] if w)


def _nxos_acl_lines(answer: str) -> str | None:
    """The access lists of `show ip access-lists | json` as lines, each list under its
    `ip access-list <name>` head. None when the answer does not have that shape."""
    try:
        doc = json.loads(answer)
    except ValueError:
        return None
    lists = _nxos_rows(doc, "ip_ipv6_mac")
    if not lists:
        return None
    out: list[str] = []
    for acl in lists:
        out.append(f"{acl.get('op') or 'ip'} access-list {acl.get('acl_name') or '?'}")
        out += [f"  {_ace_line(ace)}" for ace in _nxos_rows(acl, "seqno")]
    return "\n".join(out)


def _answer_text(command: str, answer: str) -> str:
    """The answer as the section shows it. NX-OS access lists are shown as their lines, and other
    JSON is indented."""
    if command == NXOS_ACL_COMMAND:
        lines = _nxos_acl_lines(answer)
        if lines is not None:
            return lines
    return _readable(answer)


def device_sections(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The unredacted version, routing, ACL and NAT sections of the payload of a device, in
    SECTION_ORDER. The result has one `{key, title, parts}` per section that has a part, and each
    part is a `{command, text}`. A VyOS configuration is cut at its top-level nodes. A UniFi payload
    has no such section. A command that failed (an answer that is not text) gives no part."""
    parts: dict[str, list[dict[str, str]]] = {}
    if not is_unifi(payload):
        for command, answer in sorted(payload.items()):
            if not isinstance(answer, str) or not answer.strip():
                continue
            key = next((k for k, pattern in DEVICE_SECTIONS if pattern.search(command)), None)
            if key is not None:
                parts.setdefault(key, []).append({"command": command, "text": _answer_text(command, answer)})
        config = payload.get("config")
        if isinstance(config, Mapping):
            for key, node in VYOS_SECTIONS:
                if node in config:
                    text = _vyos_text(config[node])
                    parts.setdefault(key, []).append({"command": f"{VYOS_CONFIG} {node}", "text": text})
    return [{"key": k, "title": SECTION_TITLES[k], "parts": parts[k]} for k in SECTION_ORDER if k in parts]


def section(
    payload: Mapping[str, Any], name: str, device: Mapping[str, Any] | None = None
) -> tuple[str, str] | None:
    """The command and the unredacted configuration of interface `name`, or None when the payload has none.

    A UniFi payload needs `device`, the graph Device's `mac` and `serial`, to pick the device of the port.
    """
    for command in STANZA_COMMANDS:
        text = payload.get(command)
        found = _stanza(text, name) if isinstance(text, str) else None
        if found is not None:
            return command, found
    config = payload.get("config")
    if isinstance(config, Mapping):
        return _vyos(config, name)
    return _unifi(payload, name, device) if device is not None and is_unifi(payload) else None
