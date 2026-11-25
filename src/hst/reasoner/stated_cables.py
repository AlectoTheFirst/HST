"""The stated-cable rules, resolved in Python."""

from __future__ import annotations

import re
from typing import Any

from hst.core import uid as uidmod
from hst.core.loader import CHUNK
from hst.core.normalize import IfNameResolver, normalize_hostname

# Each rule resolves the Port that the stated chassis MAC and port id identify.

# Every switch Port that has a stated neighbor fact, with its device. The fact
# is a chassis MAC (the 2 MAC-resolved rules), or a neighbor name or serial
# (cable-from-neighbor-name).
FETCH_STATED_CABLE_PORTS = """
MATCH (swp:Port:Obj)-[swon:ON]->(swdev:Device)
WHERE (swp.uplink_mac IS NOT NULL OR swp.lldp_neighbor_mac IS NOT NULL
       OR swp.lldp_neighbor_name IS NOT NULL OR swp.cdp_neighbor_name IS NOT NULL
       OR swp.cdp_neighbor_serial IS NOT NULL)
  AND NOT swp:Retired AND NOT swdev:Retired AND swon._retired_at IS NULL
  AND swp.collection_ts = $cts
RETURN swp.uid AS swp_uid, swdev.uid AS swdev_uid,
       swp.uplink_mac AS uplink_mac, swp.uplink_remote_port AS uplink_remote_port,
       swp.lldp_neighbor_mac AS lldp_neighbor_mac, swp.lldp_neighbor_port AS lldp_neighbor_port,
       swp.lldp_neighbor_name AS lldp_neighbor_name,
       swp.cdp_neighbor_name AS cdp_neighbor_name, swp.cdp_neighbor_port AS cdp_neighbor_port,
       swp.cdp_neighbor_serial AS cdp_neighbor_serial
"""

# Every (mac, owning device) pair of a Port, an Interface or the Device
# itself. A chassis MAC resolves the device through this join before a Port
# is chosen. `Device.mac` is the chassis MAC that a controller-managed device
# reports for itself. `collectors/unifi.py` writes it. A UniFi device has no
# Interface node, and its Port nodes have no MAC.
FETCH_MAC_OWNERS = """
MATCH (p:Port:Obj)-[pon:ON]->(d:Device)
WHERE p.mac IS NOT NULL AND NOT p:Retired AND NOT d:Retired AND pon._retired_at IS NULL
  AND p.collection_ts = $cts
RETURN DISTINCT p.mac AS mac, d.uid AS device_uid
UNION
MATCH (i:Interface:Obj)-[ion:ON]->(d:Device)
WHERE i.mac IS NOT NULL AND NOT i:Retired AND NOT d:Retired AND ion._retired_at IS NULL
  AND i.collection_ts = $cts
RETURN DISTINCT i.mac AS mac, d.uid AS device_uid
UNION
MATCH (d:Device:Obj)
WHERE d.mac IS NOT NULL AND NOT d:Retired
  AND d.collection_ts = $cts
RETURN DISTINCT d.mac AS mac, d.uid AS device_uid
"""

# Every device's own Ports, for the sole-Port fallback, the "Port N" index
# candidate, and the MAC-named-port match within one resolved device.
FETCH_DEVICE_PORTS = """
MATCH (p:Port:Obj)-[don:ON]->(d:Device)
WHERE NOT p:Retired AND NOT d:Retired AND don._retired_at IS NULL
  AND p.collection_ts = $cts
RETURN d.uid AS device_uid, p.uid AS port_uid, p.mac AS mac, p.name AS name,
       d.hostname AS hostname, d.identities AS identities, d.serial AS serial
"""

# Every Interface REALIZED_BY a Port.
FETCH_REALIZED_PORTS = """
MATCH (i:Interface:Obj)-[rb:REALIZED_BY]->(p:Port)
WHERE NOT i:Retired AND NOT p:Retired AND rb._retired_at IS NULL
  AND i.collection_ts = $cts
RETURN i.uid AS if_uid, p.uid AS port_uid
"""

# `$edges` is the resolved (a, z, source, rule) list, one chunk per statement.
STATED_CABLE_WRITE = """
UNWIND $edges AS e
MATCH (a:Port:Obj {uid: e.a, collection_ts: $cts}) WHERE NOT a:Retired
MATCH (z:Port:Obj {uid: e.z, collection_ts: $cts}) WHERE NOT z:Retired
MERGE (a)-[c:CONNECTED_TO {source: e.source}]->(z)
SET c.derived = false, c.rule = e.rule,
    c._scope = 'reasoner', c.collection_ts = $cts, c.collected_at = $ts
RETURN e.rule AS rule, count(*) AS n
"""

# Matches a UniFi remote port id or an LLDP port id that gives a port by
# index. "Port 19" is port index 19, and "local Port 3" is port index 3.
_PORT_INDEX_RE = re.compile(r"(?i)^(?:local\s+)?port\s*(\d+)$")


def _canonical_mac_or_none(value: str | None) -> str | None:
    """`uid.norm_mac`'s canonical form when `value` parses as a MAC, None
    otherwise."""
    if not value:
        return None
    try:
        return uidmod.norm_mac(value)
    except ValueError:
        return None


def _resolve_port_by_id(
    device_uid: str,
    port_id: str | None,
    *,
    device_ports: set[str],
    port_macs: dict[str, str],
    realized_by: dict[str, str],
    port_names: _PortNames | None = None,
) -> str | None:
    """The single Port on `device_uid` that one LLDP or uplink port id
    identifies, or None.

    A port id has one of 3 spellings.

    - A MAC (`aa:bb:...`) resolves against `port_macs` (the Ports of this
      device only).
    - A UniFi "Port N" or "local Port N" index resolves against the
      `<device_uid>/port/port<N>` uid that `collectors/unifi.py` gives that
      Port.
    - Any other text is an interface or port name (VyOS "eth0", a Cisco
      name). It resolves through the slug of `uid.port` first. If that gives
      no Port, it resolves through `uid.interface` and `realized_by` (the
      Port that realizes that Interface). If that gives no Port either
      (`Fi1/0/1` on a device whose Port is `FiveGigabitEthernet1/0/1`,
      `BE10` for `Bundle-Ether10`), it resolves against the names of the
      Ports of the device (`port_names`).

    A `port_id` that is not a string resolves to None.
    """
    if not port_id or not isinstance(port_id, str):
        return None
    port_id = port_id.strip()
    if not port_id:
        return None
    mac = _canonical_mac_or_none(port_id)
    if mac is not None:
        matches = [p for p, m in port_macs.items() if m == mac]
        return matches[0] if len(matches) == 1 else None
    m = _PORT_INDEX_RE.match(port_id)
    if m:
        candidate = f"{device_uid}/port/port{int(m.group(1))}"
        return candidate if candidate in device_ports else None
    port_candidate = uidmod.port(device_uid, port_id)
    if port_candidate in device_ports:
        return port_candidate
    if_candidate = uidmod.interface(device_uid, port_id)
    realized = realized_by.get(if_candidate)
    if realized in device_ports:
        return realized
    if port_names is not None:
        return port_names.resolve(port_id)
    return None


class _PortNames:
    """One device's Port names, for a port id printed in an abbreviated form."""

    def __init__(self, port_by_name: dict[str, str]) -> None:
        self._port_by_name = port_by_name
        self._resolver = IfNameResolver(port_by_name)

    def resolve(self, port_id: str) -> str | None:
        found = self._resolver(port_id)
        return self._port_by_name.get(found) if found else None


def _resolve_neighbor_port(
    device_uid: str,
    *,
    chassis_mac: str,
    lldp_port_id: str | None,
    lldp_mac: str | None,
    uplink_mac: str | None,
    uplink_remote_port: Any,
    device_ports: set[str],
    port_macs: dict[str, str],
    realized_by: dict[str, str],
    port_names: _PortNames | None = None,
) -> str | None:
    """The Port on `device_uid` that is the end of a stated cable.

    The precedence is:

    1. The LLDP port id, when this switch port has one and the 2 stated
       chassis MACs on it (of the LLDP record and of the uplink record) are
       equal. One MAC alone counts as equal.
    2. The remote port index of the uplink record, when it is stated (a
       UniFi peer) and the chassis MAC of the uplink record is the MAC from
       which `device_uid` was resolved (`chassis_mac`).
    3. The sole Port of the device.

    The MAC-named port is not used as the cable end.
    """
    macs_agree = uplink_mac is None or lldp_mac is None or uplink_mac == lldp_mac
    if lldp_port_id and macs_agree:
        resolved = _resolve_port_by_id(
            device_uid,
            lldp_port_id,
            device_ports=device_ports,
            port_macs=port_macs,
            realized_by=realized_by,
            port_names=port_names,
        )
        if resolved is not None:
            return resolved
    if uplink_remote_port is not None and uplink_mac is not None and uplink_mac == chassis_mac:
        try:
            idx = int(uplink_remote_port)
        except (TypeError, ValueError):
            idx = None
        if idx is not None:
            candidate = f"{device_uid}/port/port{idx}"
            if candidate in device_ports:
                return candidate
    if len(device_ports) == 1:
        return next(iter(device_ports))
    return None


def resolve_stated_cables(
    switch_ports: list[dict[str, Any]],
    mac_owners: list[dict[str, Any]],
    device_ports_rows: list[dict[str, Any]],
    realized_rows: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Resolve cable-from-uplink-record, cable-from-lldp-record and
    cable-from-neighbor-name.

    For every switch Port with a neighbor chassis MAC, the 2 MAC-resolved
    rules resolve the neighbor Device that owns the MAC, then the Port on it
    (`_resolve_neighbor_port`).

    The function is pure. The inputs are plain dict rows in the shapes that
    `FETCH_STATED_CABLE_PORTS`, `FETCH_MAC_OWNERS`, `FETCH_DEVICE_PORTS` and
    `FETCH_REALIZED_PORTS` return. The result has one entry per rule:
    `{"edges": [{"a", "z", "source", "rule"}, ...], "unresolved": n, "ambiguous": n}`.
    `_run_stated_cable_rules` writes `edges` through `STATED_CABLE_WRITE`.

    A chassis MAC that no Device owns counts as `unresolved`. A chassis MAC
    that more than one Device owns counts as `ambiguous`. A MAC of exactly
    one Device also counts as `unresolved` when `_resolve_neighbor_port`
    gives no Port for it.

    cable-from-uplink-record is resolved first and wins a pair that both
    MAC-resolved rules would state.

    cable-from-neighbor-name runs last of the 3, over the same switch ports.
    It resolves the neighbor Device by the serial of the hint
    (`cdp_neighbor_serial`, against the `serial` and `identities` in the
    device port rows) or by its name (`cdp_neighbor_name`,
    `lldp_neighbor_name`, against the `hostname` and `identities`). It then
    resolves the Port by the port id of the hint, or takes the sole Port of
    the device. It skips a pair that a MAC-resolved rule stated.
    """
    mac_to_devices: dict[str, set[str]] = {}
    for row in mac_owners:
        mac_to_devices.setdefault(row["mac"], set()).add(row["device_uid"])

    device_ports: dict[str, set[str]] = {}
    port_macs_by_device: dict[str, dict[str, str]] = {}
    port_by_name: dict[str, dict[str, str]] = {}
    for row in device_ports_rows:
        device_ports.setdefault(row["device_uid"], set()).add(row["port_uid"])
        if row.get("name"):
            port_by_name.setdefault(row["device_uid"], {})[str(row["name"])] = row["port_uid"]
        if row.get("mac"):
            port_macs_by_device.setdefault(row["device_uid"], {})[row["port_uid"]] = row["mac"]
    names = _device_name_index(device_ports_rows)

    realized_by = {row["if_uid"]: row["port_uid"] for row in realized_rows}
    port_names_of: dict[str, _PortNames] = {}

    def port_names(device_uid: str) -> _PortNames | None:
        names_of = port_by_name.get(device_uid)
        if not names_of:
            return None
        found = port_names_of.get(device_uid)
        if found is None:
            found = port_names_of[device_uid] = _PortNames(names_of)
        return found

    report: dict[str, dict[str, Any]] = {
        "cable-from-uplink-record": {"edges": [], "unresolved": 0, "ambiguous": 0},
        "cable-from-lldp-record": {"edges": [], "unresolved": 0, "ambiguous": 0},
        "cable-from-neighbor-name": {"edges": [], "unresolved": 0, "ambiguous": 0},
    }
    stated_pairs: set[tuple[str, str]] = set()

    def resolve_one(swp_uid: str, chassis_mac: str, row: dict[str, Any]) -> tuple[str | None, str | None]:
        devices = mac_to_devices.get(chassis_mac, set())
        if not devices:
            return None, "unresolved"
        if len(devices) > 1:
            return None, "ambiguous"
        device_uid = next(iter(devices))
        resolved = _resolve_neighbor_port(
            device_uid,
            chassis_mac=chassis_mac,
            lldp_port_id=row.get("lldp_neighbor_port"),
            lldp_mac=row.get("lldp_neighbor_mac"),
            uplink_mac=row.get("uplink_mac"),
            uplink_remote_port=row.get("uplink_remote_port"),
            device_ports=device_ports.get(device_uid, set()),
            port_macs=port_macs_by_device.get(device_uid, {}),
            realized_by=realized_by,
            port_names=port_names(device_uid),
        )
        if resolved is None or resolved == swp_uid:
            return None, "unresolved"
        return resolved, None

    for row in switch_ports:
        if row.get("uplink_mac") is None:
            continue
        swp_uid = row["swp_uid"]
        resolved, failure = resolve_one(swp_uid, row["uplink_mac"], row)
        bucket = report["cable-from-uplink-record"]
        if resolved is None:
            bucket[failure or "unresolved"] += 1
            continue
        pair = tuple(sorted((swp_uid, resolved)))
        stated_pairs.add(pair)
        bucket["edges"].append(
            {"a": pair[0], "z": pair[1], "source": "unifi-uplink", "rule": "cable-from-uplink-record"}
        )

    for row in switch_ports:
        if row.get("lldp_neighbor_mac") is None:
            continue
        swp_uid = row["swp_uid"]
        resolved, failure = resolve_one(swp_uid, row["lldp_neighbor_mac"], row)
        bucket = report["cable-from-lldp-record"]
        if resolved is None:
            bucket[failure or "unresolved"] += 1
            continue
        pair = tuple(sorted((swp_uid, resolved)))
        if pair in stated_pairs:
            continue
        stated_pairs.add(pair)
        bucket["edges"].append(
            {"a": pair[0], "z": pair[1], "source": "unifi-lldp", "rule": "cable-from-lldp-record"}
        )

    bucket = report["cable-from-neighbor-name"]
    for row in switch_ports:
        swp_uid = row["swp_uid"]
        for proto in ("cdp", "lldp"):
            serial = row.get(f"{proto}_neighbor_serial")
            name = row.get(f"{proto}_neighbor_name")
            if serial is None and name is None:
                continue
            devices = names.resolve(serial=serial, name=name)
            if not devices:
                bucket["unresolved"] += 1
                continue
            if len(devices) > 1:
                bucket["ambiguous"] += 1
                continue
            device_uid = next(iter(devices))
            ports = device_ports.get(device_uid, set())
            resolved = _resolve_port_by_id(
                device_uid,
                row.get(f"{proto}_neighbor_port"),
                device_ports=ports,
                port_macs=port_macs_by_device.get(device_uid, {}),
                realized_by=realized_by,
                port_names=port_names(device_uid),
            )
            if resolved is None and len(ports) == 1:
                resolved = next(iter(ports))
            if resolved is None or resolved == swp_uid:
                bucket["unresolved"] += 1
                continue
            pair = tuple(sorted((swp_uid, resolved)))
            if pair in stated_pairs:
                continue
            stated_pairs.add(pair)
            bucket["edges"].append(
                {"a": pair[0], "z": pair[1], "source": proto, "rule": "cable-from-neighbor-name"}
            )

    return report


class _DeviceNames:
    """The names and serials in the device port rows, indexed for
    cable-from-neighbor-name.

    The 3 indexes map a serial, a full name and a short name to devices. The
    `serial` of a device and every entry of its `identities` are serials, as
    slugs. Its `hostname` and every entry of its `identities` are names. Each
    name goes through `normalize_hostname`. Case and a trailing dot do not
    affect a match. A name with a domain is indexed under its full spelling
    and under its short spelling."""

    def __init__(self) -> None:
        self.by_serial: dict[str, set[str]] = {}
        self.by_fqdn: dict[str, set[str]] = {}
        self.by_short: dict[str, set[str]] = {}

    def add(self, device_uid: str, *, serials: list[Any], names: list[Any]) -> None:
        for serial in serials:
            if isinstance(serial, str) and serial.strip():
                self.by_serial.setdefault(uidmod.slug(serial), set()).add(device_uid)
        for raw in names:
            if not isinstance(raw, str) or not raw.strip():
                continue
            h = normalize_hostname(raw)
            self.by_short.setdefault(h.short, set()).add(device_uid)
            if h.fqdn:
                self.by_fqdn.setdefault(h.fqdn, set()).add(device_uid)

    def resolve(self, *, serial: Any, name: Any) -> set[str]:
        """The devices that match a hint. The serial of the hint is used when
        a device owns it, else the full name, else the short name."""
        if isinstance(serial, str) and serial.strip():
            found = self.by_serial.get(uidmod.slug(serial))
            if found:
                return found
        if not isinstance(name, str) or not name.strip():
            return set()
        h = normalize_hostname(name)
        if h.fqdn and h.fqdn in self.by_fqdn:
            return self.by_fqdn[h.fqdn]
        return self.by_short.get(h.short, set())


def _device_name_index(device_ports_rows: list[dict[str, Any]]) -> _DeviceNames:
    index = _DeviceNames()
    seen: set[str] = set()
    for row in device_ports_rows:
        device_uid = row["device_uid"]
        if device_uid in seen:
            continue
        seen.add(device_uid)
        identities = row.get("identities")
        others = identities if isinstance(identities, list) else []
        index.add(device_uid, serials=[row.get("serial"), *others], names=[row.get("hostname"), *others])
    return index


def _run_stated_cable_rules(session: Any, *, ts: int, cts: int) -> dict[str, dict[str, Any]]:
    """Fetch the rows, call `resolve_stated_cables` and write the edges.

    The result has one entry per rule in the per-rule shape of `run()`:
    `{"cable-from-uplink-record": {"edges": n, "unresolved": n, "ambiguous": n},
    "cable-from-lldp-record": {...}, "cable-from-neighbor-name": {...}}`.

    The 4 fetches share one read transaction. The resolution runs with no
    transaction open. The edges are written CHUNK at a time, each chunk in a
    transaction of its own.
    """

    def fetch(tx: Any) -> tuple[list[dict[str, Any]], ...]:
        return (
            tx.run(FETCH_STATED_CABLE_PORTS, cts=cts).data(),
            tx.run(FETCH_MAC_OWNERS, cts=cts).data(),
            tx.run(FETCH_DEVICE_PORTS, cts=cts).data(),
            tx.run(FETCH_REALIZED_PORTS, cts=cts).data(),
        )

    def write(tx: Any, chunk: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return tx.run(STATED_CABLE_WRITE, edges=chunk, ts=ts, cts=cts).data()

    report = resolve_stated_cables(*session.execute_read(fetch))
    edges = [e for bucket in report.values() for e in bucket["edges"]]
    counts: dict[str, int] = {}
    for i in range(0, len(edges), CHUNK):
        for row in session.execute_write(lambda tx, chunk=edges[i : i + CHUNK]: write(tx, chunk)):
            counts[row["rule"]] = counts.get(row["rule"], 0) + row["n"]
    return {
        name: {
            "edges": counts.get(name, 0),
            "unresolved": bucket["unresolved"],
            "ambiguous": bucket["ambiguous"],
        }
        for name, bucket in report.items()
    }
