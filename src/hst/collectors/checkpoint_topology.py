"""Member-local VSX interface realization from Linux link observations."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from hst.core import uid

from .util import GraphBuilder, canonical_mac


def topology(
    builder: GraphBuilder,
    value: Mapping[str, Any],
    *,
    device: str,
    context: str,
    interfaces: Mapping[str, str],
    fabric: str,
) -> list[str]:
    links = {
        row["ifname"]: row
        for row in value.get("links", ()) or ()
        if isinstance(row, Mapping) and isinstance(row.get("ifname"), str)
    }
    indices = {row["ifindex"]: name for name, row in links.items() if isinstance(row.get("ifindex"), int)}
    gaps: list[str] = []
    ports: dict[str, str] = {}

    def reference(row: Mapping[str, Any], field: str) -> str | None:
        ref = row.get(field)
        if isinstance(ref, str) and ref in links:
            return ref
        return indices.get(ref) if isinstance(ref, int) else None

    for name, row in links.items():
        interface = interfaces.get(name)
        info = row.get("linkinfo") or {}
        kind = info.get("info_kind") if isinstance(info, Mapping) else None
        if name.startswith(("wrp", "wrpj")):
            if interface:
                builder.node("Interface", interface, kind="warp")
            continue
        if kind == "bridge":
            bridge = builder.node("BridgeDomain", f"vsx-bridge:{context}:{uid.slug(name)}", name=name)
            if interface:
                builder.rel("IN_BD", "Interface", interface, "BridgeDomain", bridge)
        elif kind == "bond":
            lag = builder.node("Lag", uid.lag(device, name), name=name)
            builder.rel("ON", "Lag", lag, "Device", device)
            if interface:
                builder.rel("REALIZED_BY", "Interface", interface, "Lag", lag)
        elif not kind and row.get("link_type") == "ether":
            port = builder.node(
                "Port",
                uid.port(device, name),
                name=name,
                kind="physical",
                mac=canonical_mac(row.get("address")),
            )
            ports[name] = port
            builder.rel("ON", "Port", port, "Device", device)
            if interface:
                builder.rel("REALIZED_BY", "Interface", interface, "Port", port)

    for name, row in links.items():
        interface = interfaces.get(name)
        info = row.get("linkinfo") or {}
        kind = info.get("info_kind") if isinstance(info, Mapping) else None
        parent = reference(row, "link") or reference(row, "link_index")
        if kind == "vlan" and interface:
            data = info.get("info_data") or {}
            vid = data.get("id") if isinstance(data, Mapping) else None
            if not isinstance(vid, int) or not 1 <= vid <= 4094 or not parent:
                gaps.append(f"{name}: VLAN tag or parent not captured")
                continue
            vlan = builder.node("VlanInstance", uid.vlan(device, vid), vid=vid)
            bridge = builder.node("BridgeDomain", uid.bridge_domain(fabric, vid))
            builder.rel("REALIZES", "VlanInstance", vlan, "BridgeDomain", bridge)
            builder.rel("BOUND_TO", "Interface", interface, "VlanInstance", vlan)
            if parent in interfaces:
                builder.node("Interface", interface, parent_interface_uid=interfaces[parent], kind="vlan")
            if parent in ports:
                builder.rel("REALIZED_BY", "Interface", interface, "Port", ports[parent])
                builder.rel("CARRIES", "Port", ports[parent], "VlanInstance", vlan, native=False)
            elif (links[parent].get("linkinfo") or {}).get("info_kind") == "bond":
                builder.rel("REALIZED_BY", "Interface", interface, "Lag", uid.lag(device, parent))
        master = reference(row, "master")
        if not master:
            continue
        master_kind = (links[master].get("linkinfo") or {}).get("info_kind")
        if master_kind == "bond" and name in ports:
            builder.rel(
                "MEMBER_OF",
                "Port",
                ports[name],
                "Lag",
                uid.lag(device, master),
                state=str(row.get("operstate", "unknown")).lower(),
            )
        elif master_kind == "bridge" and interface:
            builder.rel(
                "IN_BD", "Interface", interface, "BridgeDomain", f"vsx-bridge:{context}:{uid.slug(master)}"
            )
    return gaps


def bridge_members(text: str) -> dict[str, list[str]]:
    """Parse Linux brctl show, including continuation interface rows."""
    groups: dict[str, list[str]] = {}
    current = None
    for line in text.splitlines():
        fields = line.split()
        if not fields or fields[:2] == ["bridge", "name"]:
            continue
        if len(fields) >= 3 and fields[2] in {"yes", "no"} and "." in fields[1]:
            current = fields[0]
            groups[current] = fields[3:]
        elif len(fields) == 1 and line[:1].isspace() and current:
            groups[current].append(fields[0])
    return groups


def connect_virtual_devices(
    builder: GraphBuilder,
    raw: Mapping[str, Any],
    *,
    device: str,
    contexts: Mapping[int, tuple[str, str, Mapping[str, str]]],
) -> list[str]:
    """Join explicit warp endpoints and switching membership, within one member.

    Two warp interfaces pair when each states the other as its kernel peer.
    Equal numeric suffixes form no pair. A pair of the management export must
    reference interfaces observed on both contexts. An ambiguous or
    contradictory pairing produces no forwarding edge.
    """
    from .checkpoint_evidence import VsxEvidence

    gaps: list[str] = []
    evidence = raw.get("vsx_evidence") or {}
    pairs: list[tuple[tuple[int, str], tuple[int, str], str]] = []
    groups: list[tuple[int, str, list[str], str]] = []
    if evidence:
        model = VsxEvidence.model_validate({k: v for k, v in evidence.items() if k != "sha256"})
        pairs += [
            ((p.a.vsid, p.a.interface), (p.b.vsid, p.b.interface), p.evidence_uid) for p in model.warp_links
        ]
        groups += [(g.vsid, g.name, list(g.interfaces), g.evidence_uid) for g in model.bridge_groups]
    refs = {(vsid, name): node for vsid, (_, _, names) in contexts.items() for name, node in names.items()}
    rows: dict[tuple[int, str], Mapping[str, Any]] = {}
    for key, value in (raw.get("contexts") or {}).items():
        if not isinstance(value, Mapping):
            continue
        try:
            vsid = int(value.get("vsid", key))
        except (ValueError, TypeError):
            gaps.append(f"invalid virtual context {key}")
            continue
        if vsid not in contexts:
            continue
        context, kind, names = contexts[vsid]
        links = {r["ifname"]: r for r in value.get("links", ()) if isinstance(r, Mapping) and "ifname" in r}
        rows.update({(vsid, name): row for name, row in links.items() if name in names})
        parsed = bridge_members(str(value.get("bridge_members", "")))
        for name, members in parsed.items():
            groups.append((vsid, name, members, "brctl-show"))
        masters: dict[str, list[str]] = {}
        indices = {r.get("ifindex"): name for name, r in links.items()}
        for name, row in links.items():
            master = row.get("master")
            master = indices.get(master) if isinstance(master, int) else master
            if master and (links.get(master, {}).get("linkinfo") or {}).get("info_kind") == "bridge":
                masters.setdefault(master, []).append(name)
        groups += [(vsid, name, members, "netlink-master") for name, members in masters.items()]
        if kind == "virtual-switch" and not any(group[0] == vsid for group in groups):
            members = [n for n in names if n != "lo" and links.get(n, {}).get("link_type") != "loopback"]
            groups.append((vsid, "virtual-switch", members, "vsx-device-type"))
    for endpoint, row in rows.items():
        if not endpoint[1].startswith("wrp"):
            continue
        peer_name = row.get("link")
        candidates = [
            other
            for other, peer in rows.items()
            if other[0] != endpoint[0]
            and other[1] == peer_name
            and peer.get("link") == endpoint[1]
            and other[1].startswith("wrp")
        ]
        if len(candidates) == 1:
            pairs.append((endpoint, candidates[0], "reciprocal-netlink-peer"))
    partners: dict[tuple[int, str], set[tuple[int, str]]] = {}
    for a, b, _ in pairs:
        partners.setdefault(a, set()).add(b)
        partners.setdefault(b, set()).add(a)
    paired: set[tuple[int, str]] = set()
    emitted = set()
    for a, b, source in pairs:
        if a not in refs or b not in refs or a[0] == b[0] or len(partners[a]) != 1 or len(partners[b]) != 1:
            gaps.append(f"unresolved or conflicting warp endpoints {a} -> {b}")
            continue
        if not (a[1].startswith("wrp") and b[1].startswith("wrp")):
            gaps.append(f"non-warp interface in warp evidence {a} -> {b}")
            continue
        pair_key = tuple(sorted((a, b)))
        if pair_key in emitted:
            continue
        emitted.add(pair_key)
        builder.rel(
            "CONNECTED_TO",
            "Interface",
            refs[a],
            "Interface",
            refs[b],
            source="vsx-warp",
            evidence_uid=source,
            member_uid=device,
        )
        paired.update((a, b))
    for endpoint, node in refs.items():
        if endpoint[1].startswith("wrp"):
            complete = endpoint in paired
            builder.node("Interface", node, vsx_topology_complete=complete)
            if not complete:
                gaps.append(f"VS {endpoint[0]} {endpoint[1]}: warp peer not captured")
    bridged: set[int] = set()
    memberships: dict[tuple[int, str], set[frozenset[str]]] = {}
    for vsid, name, members, _ in groups:
        memberships.setdefault((vsid, name), set()).add(frozenset(members))
    conflicting = {key for key, variants in memberships.items() if len(variants) != 1}
    for left, lsets in memberships.items():
        for right, rsets in memberships.items():
            if left < right and left[0] == right[0] and any(a & b for a in lsets for b in rsets):
                conflicting.update((left, right))
    for vsid, name, members, source in groups:
        if (vsid, name) in conflicting:
            gaps.append(f"VS {vsid} bridge {name}: conflicting interface membership")
            continue
        if vsid not in contexts or len(set(members)) < 2 or any((vsid, n) not in refs for n in members):
            gaps.append(f"VS {vsid} bridge {name}: incomplete interface membership")
            continue
        context, kind, _ = contexts[vsid]
        domain = builder.node("BridgeDomain", f"vsx-bridge:{context}:{uid.slug(name)}", name=name)
        for member in members:
            builder.rel("IN_BD", "Interface", refs[vsid, member], "BridgeDomain", domain)
        for i, left in enumerate(sorted(set(members))):
            for right in sorted(set(members))[i + 1 :]:
                builder.rel(
                    "BRIDGED_TO",
                    "Interface",
                    refs[vsid, left],
                    "Interface",
                    refs[vsid, right],
                    key={"bridge": domain},
                    source="vsx-bridge",
                    evidence_uid=source,
                    context_uid=context,
                    policy_required=kind == "bridge",
                )
        bridged.add(vsid)
    for vsid, (_, kind, _) in contexts.items():
        if kind in {"bridge", "virtual-switch"} and vsid not in bridged:
            gaps.append(f"VS {vsid}: forwarding membership not captured")
    return sorted(set(gaps))
