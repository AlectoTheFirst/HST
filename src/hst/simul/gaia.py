"""Gaia ordered route maps.

An unsupported clause ends the route map with a model error.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from typing import Any

from . import policy as p


def match(term: list[str], route: Any, peer_as: int | None = None) -> tuple[str, bool] | None:
    if term[:1] != ["match"] or len(term) < 3:
        return None
    kind, values = term[1], term[2:]
    if kind == "protocol" and len(values) == 1:
        protocol = "connected" if values[0] == "direct" else values[0]
        return kind, (route.src_protocol or route.protocol) == protocol
    if kind == "network" and len(values) >= 2:
        network, prefix = ipaddress.ip_network(values[0]), ipaddress.ip_network(route.prefix)
        if network.version != prefix.version:
            return kind, False
        mode = values[1:]
        within = int(prefix.network_address) >= int(network.network_address) and int(
            prefix.broadcast_address
        ) <= int(network.broadcast_address)
        if mode == ["exact"]:
            return kind, prefix == network
        if mode == ["all"]:
            return kind, within
        if mode == ["refines"]:
            return kind, within and prefix.prefixlen > network.prefixlen
        if len(mode) == 4 and mode[0] == "between" and mode[2] == "and":
            return kind, within and int(mode[1]) <= prefix.prefixlen <= int(mode[3])
    if kind == "metric" and len(values) == 2 and values[0] == "value":
        return kind, route.effective_med == int(values[1])
    if kind in {"tag", "as", "nexthop", "community"} and values[-1] in {"on", "off"}:
        if values[-1] == "off":
            return None
        if kind == "tag" and len(values) == 2:
            return kind, route.tag == int(values[0])
        if kind == "as" and len(values) == 2:
            return kind, peer_as == int(values[0])
        if kind == "nexthop" and len(values) == 2:
            return kind, route.next_hop == str(ipaddress.ip_address(values[0]))
        if kind == "community":
            if values[0] in {"exact", "none"}:
                if values[0] == "none":
                    return kind, not route.communities
                raise ValueError("community exact set requires combined matching")
            community = f"{values[2]}:{values[0]}" if len(values) == 4 and values[1] == "as" else values[0]
            if len(values) in {2, 4}:
                return kind, community in route.communities
    raise ValueError("unsupported Gaia match: " + " ".join(term))


def action(term: list[str], route: Any):
    if term[:1] != ["action"]:
        return route
    values = term[1:]
    if len(values) == 2 and values[0] == "localpref":
        return route.with_(local_pref=int(values[1]))
    if len(values) == 3 and values[0] == "metric":
        value = int(values[2])
        if values[1] == "add":
            value += route.effective_med
        elif values[1] == "subtract":
            value = max(0, route.effective_med - value)
        elif values[1] != "value":
            raise ValueError("unsupported metric operation")
        return route.with_(med=value)
    if len(values) == 3 and values[:2] in (["nexthop", "ip"], ["nexthop", "ipv6"]):
        return route.with_(next_hop=str(ipaddress.ip_address(values[2])))
    if values[:1] == ["community"] and values[-1] in {"on", "off"} and len(values) in {3, 5}:
        if values[1] in {"append", "delete", "replace", "none"}:
            raise ValueError("community list action mode requires combined evaluation")
        community = f"{values[3]}:{values[1]}" if len(values) == 5 and values[2] == "as" else values[1]
        communities = set(route.communities)
        if values[-1] == "on":
            communities.add(community)
        else:
            communities.discard(community)
        return route.with_(communities=frozenset(communities))
    raise ValueError("unsupported Gaia action: " + " ".join(term))


@dataclass(frozen=True)
class RouteMap:
    name: str
    entries: tuple[dict[str, Any], ...]

    def execute(self, env: p.Environment) -> p.Result:
        for entry in sorted(self.entries, key=lambda e: int(e["seq"])):
            if not entry.get("enabled"):
                continue
            try:
                terms = json.loads(entry.get("gaia_terms", "[]"))
                matches: dict[str, list[bool]] = {}
                for term in terms:
                    result = match(term, env.original_route, env.peer_as)
                    if result is not None:
                        matches.setdefault(result[0], []).append(result[1])
                    elif term[:1] not in (["match"], ["action"]):
                        raise ValueError("unsupported Gaia statement: " + " ".join(term))
                if not all(any(values) for values in matches.values()):
                    continue
                if entry["action"] not in {"permit", "deny"}:
                    raise ValueError("Gaia route-map disposition was not captured")
                if entry["action"] == "deny":
                    return p.Result(exit=True)
                output = env.output_route
                for term in terms:
                    output = action(term, output)
                env.output_route = output
                return p.Result(boolean_value=True, exit=True)
            except (ValueError, TypeError, KeyError) as error:
                env.error = True
                env.errors.report("gaia-route-map-unsupported", str(error), self.name)
                return p.Result(exit=True)
        return p.Result(fall_through=True)


@dataclass(frozen=True)
class Chain:
    names: tuple[str, ...]
    families: tuple[tuple[int, ...], ...] = ()

    def execute(self, env: p.Environment) -> p.Result:
        for index, name in enumerate(self.names):
            if (
                self.families
                and ipaddress.ip_network(env.original_route.prefix).version not in self.families[index]
            ):
                continue
            policy = env.policies.get(name)
            if policy is None:
                env.error = True
                env.errors.report("gaia-route-map-missing", f"route map {name} was not captured", name)
                return p.Result(exit=True)
            result = p.call(policy, env)
            if not result.fall_through:
                return result
        return p.Result(exit=True)
