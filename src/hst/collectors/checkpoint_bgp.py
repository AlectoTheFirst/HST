"""Gaia configuration parsing, scoped to one member/virtual routing context."""

from __future__ import annotations

import ipaddress
import json
import shlex
from collections import defaultdict
from typing import Any

from hst.core import uid

from .util import GraphBuilder


def route_maps(text: str) -> dict[str, list[dict[str, Any]]]:
    maps: dict[str, dict[int, dict[str, Any]]] = defaultdict(dict)
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        words = shlex.split(line)
        if len(words) < 6 or words[:1] != ["set"] or words[1] != "routemap" or words[3] != "id":
            raise ValueError(f"unrecognized Gaia route-map command: {line}")
        name, sequence = words[2], (10 if words[4] == "default" else int(words[4]))
        if not 1 <= sequence <= 65535:
            raise ValueError("Gaia route-map sequence out of range")
        entry = maps[name].setdefault(
            sequence,
            {"seq": sequence, "kind": "gaia-clause", "enabled": False, "action": "unknown", "terms": []},
        )
        tail = words[5:]
        if tail == ["off"]:
            maps[name].pop(sequence, None)
        elif tail in (["on"], ["inactive"]):
            entry["enabled"] = tail == ["on"]
        elif tail in (["allow"], ["restrict"]):
            entry["enabled"] = True
            entry["action"] = "permit" if tail == ["allow"] else "deny"
        else:
            entry["terms"].append(tail)
    return {name: [entries[n] for n in sorted(entries)] for name, entries in maps.items()}


def peers(text: str, asn: int) -> tuple[dict[str, dict[str, Any]], list[str]]:
    result: dict[str, dict[str, Any]] = {}
    pending: list[tuple[int, list[str]]] = []
    gaps = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        words = shlex.split(line)
        if words[:3] == ["set", "bgp", "external"] and len(words) > 5 and words[3] == "remote-as":
            remote, tail = int(words[4]), words[5:]
        elif words[:3] == ["set", "bgp", "internal"]:
            remote, tail = asn, words[3:]
        else:
            gaps.append(line)
            continue
        if not 1 <= remote <= 4294967295:
            raise ValueError("BGP AS out of range")
        if tail[:1] != ["peer"]:
            pending.append((remote, tail))
            continue
        if len(tail) < 3:
            gaps.append(line)
            continue
        address = str(ipaddress.ip_address(tail[1]))
        peer = result.setdefault(address, {"peer_ip": address, "peer_asn": remote, "bindings": [], "raw": []})
        if peer["peer_asn"] != remote:
            raise ValueError(f"conflicting remote AS for {address}")
        peer["raw"].append(tail[2:])
    for peer in result.values():
        for tail in [t for remote, t in pending if remote == peer["peer_asn"]] + peer.pop("raw"):
            if tail == ["on"] or tail == ["off"]:
                peer["shutdown"] = tail == ["off"]
            elif tail[:1] in (["import-routemap"], ["export-routemap"]):
                direction = "in" if tail[0] == "import-routemap" else "out"
                if len(tail) == 3 and tail[2] == "off":
                    peer["bindings"] = [b for b in peer["bindings"] if b[0] != direction or b[2] != tail[1]]
                    continue
                if len(tail) not in {5, 7} or tail[2] != "preference" or tail[-1] != "on":
                    gaps.append("unsupported route-map attachment: " + " ".join(tail))
                    continue
                family = tail[5] if len(tail) == 7 and tail[4] == "family" else "inet"
                families = {"inet": (4,), "inet6": (6,), "inet-and-inet6": (4, 6)}.get(family)
                if families is None or not 1 <= int(tail[3]) <= 65535:
                    raise ValueError("invalid Gaia route-map preference or family")
                peer["bindings"] = [b for b in peer["bindings"] if b[0] != direction or b[2] != tail[1]]
                peer["bindings"].append((direction, int(tail[3]), tail[1], families))
            elif len(tail) in {2, 3} and tail[0] in {"local-address", "local-address-ipv6"}:
                peer["local_address"] = None if tail[-1] == "off" else str(ipaddress.ip_address(tail[1]))
            elif tail[:1] in (["keepalive"], ["holdtime"], ["authtype"], ["comment"]):
                continue
            else:
                gaps.append("peer " + peer["peer_ip"] + " " + " ".join(tail))
    return result, gaps


def project(
    builder: GraphBuilder,
    value: dict[str, Any],
    *,
    process: str,
    context: str,
    asn: int,
    observed: list[dict[str, Any]],
    vsid: int,
) -> list[str]:
    gaps: list[str] = []
    try:
        maps = route_maps(str(value.get("bgp_routemaps", "")))
        configured, gaps = peers(str(value.get("bgp_config", "")), asn)
    except (ValueError, TypeError) as error:
        maps, configured = {}, {}
        gaps.append(str(error))
    if not value.get("bgp_config"):
        gaps.append("BGP peer configuration was not captured")
    policy_uids = {}
    exported = {
        name
        for peer in configured.values()
        for direction, _, name, _ in peer["bindings"]
        if direction == "out"
    }
    protocols: set[str] = set()
    for name, entries in maps.items():
        policy = builder.node(
            "RoutePolicy",
            uid.route_policy(context, "gaia-route-map", name),
            name=name,
            kind="gaia-route-map",
            platform="checkpoint-gaia",
            context_uid=context,
        )
        policy_uids[name] = policy
        for entry in entries:
            terms = entry["terms"]
            for term in terms:
                if (
                    name in exported
                    and entry["enabled"]
                    and entry["action"] == "permit"
                    and term[:2] == ["match", "protocol"]
                    and len(term) == 3
                ):
                    protocols.add("connected" if term[2] == "direct" else term[2])
            node = builder.node(
                "RoutePolicyEntry",
                uid.route_policy_entry(policy, entry["seq"]),
                **{k: v for k, v in entry.items() if k != "terms"},
                gaia_terms=json.dumps(terms),
                context_uid=context,
            )
            builder.rel("HAS_RULE", "RoutePolicy", policy, "RoutePolicyEntry", node)
    observed_by_ip = {peer["peer_ip"]: peer for peer in observed}
    for address in sorted(set(configured) | set(observed_by_ip)):
        config = configured.get(address, {})
        observation = observed_by_ip.get(address, {})
        remote = observation.get("peer_asn", config.get("peer_asn"))
        if observation and config and observation.get("peer_asn") != config.get("peer_asn"):
            gaps.append(f"peer {address}: observed/configured AS mismatch")
        node = builder.node(
            "BgpSession",
            uid.bgp_session(process, address, context),
            peer_ip=address,
            peer_asn=remote,
            local_asn=asn,
            af=ipaddress.ip_address(address).version,
            state=observation.get("state", "shutdown" if config.get("shutdown") else "unknown"),
            local_address=config.get("local_address"),
            context_uid=context,
            vsid=vsid,
            platform="checkpoint-gaia",
        )
        builder.rel("HAS", "RoutingProcess", process, "BgpSession", node)
        for direction in ("in", "out"):
            bindings = sorted(
                (preference, name, families)
                for d, preference, name, families in config.get("bindings", [])
                if d == direction
            )
            if not bindings:
                gaps.append(
                    f"peer {address}: {direction} route-map absent; legacy routing policy not established"
                )
                continue
            if len({preference for preference, _, _ in bindings}) != len(bindings):
                gaps.append(f"peer {address}: ambiguous route-map preference in {direction}")
            names = [name for _, name, _ in bindings]
            chain_name = f"{address}:{direction}"
            chain = builder.node(
                "RoutePolicy",
                uid.route_policy(context, "gaia-chain", chain_name),
                name=chain_name,
                kind="gaia-chain",
                policy_names=names,
                context_uid=context,
            )
            for sequence, name in enumerate(names):
                child = builder.node(
                    "RoutePolicyEntry",
                    uid.route_policy_entry(chain, sequence),
                    seq=sequence,
                    kind="gaia-chain-member",
                    policy_name=name,
                    address_families=list(bindings[sequence][2]),
                )
                builder.rel("HAS_RULE", "RoutePolicy", chain, "RoutePolicyEntry", child)
            builder.node(
                "BgpSession",
                node,
                **{
                    ("import" if direction == "in" else "export") + "_policy_name": chain_name,
                    ("import" if direction == "in" else "export") + "_policy_kind": "gaia-chain",
                },
            )
            builder.rel("FILTERED_BY", "BgpSession", node, "RoutePolicy", chain, key={"direction": direction})
            for name in names:
                if name in policy_uids:
                    builder.rel("REFERENCES", "RoutePolicy", chain, "RoutePolicy", policy_uids[name])
                else:
                    gaps.append(f"peer {address}: route-map {name} not captured")
    # An origination candidate must exist in the main RIB.
    builder.node(
        "RoutingProcess",
        process,
        origin_config_recorded=bool(value.get("bgp_config")) and not gaps,
        origin_afs=[4, 6],
        origin_context_gaps=gaps,
        redistribute_protocols=sorted(protocols - {"bgp", "ibgp"}),
    )
    return gaps
