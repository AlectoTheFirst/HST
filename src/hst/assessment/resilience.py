"""Declared failure domains and the evaluation of service failure scenarios."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

from hst import path as pathmod
from hst.assessment.failure_routing import address, transform_routing
from hst.assessment.search import FAILS, HOLDS, UNKNOWN, SearchLimits, enumerate_subsets
from hst.impact.evaluate import GraphGates, Interface, Network
from hst.path.state import Effect, FlowRegion, Transition

_BROKER_FAILURE_TARGET = """
MATCH (n:Obj {uid: $uid, collection_ts: $snap})
WHERE NOT n:Retired
  AND (n:ZpaAppConnector OR EXISTS {
    MATCH (connector:ZpaAppConnector)-[r:RUNS_ON]->(n)
    WHERE connector.collection_ts = $snap AND r.collection_ts = $snap
  })
RETURN n.uid AS uid LIMIT 1
"""


def expand_domains(
    targets: Sequence[Mapping[str, Any]],
    domains: Sequence[Mapping[str, Any]] = (),
    *,
    evidence: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    """Expand the declarations into their physical effects and refuse a cyclic membership.

    `evidence` is the result of `validate_failure_evidence`. It supplies
    `evidence_complete` and `provenance_validated` of each entry. An
    ``observed`` label of the caller is a declaration.
    """
    entries = {str(t["id"]): dict(t) for t in targets}
    domain_map = {str(d["id"]): dict(d) for d in domains}
    if len(entries) != len(targets) or len(domain_map) != len(domains) or set(entries) & set(domain_map):
        raise ValueError("failure target and domain IDs must be unique")
    physical: dict[tuple[str, str], frozenset[str]] = {}
    for target in entries.values():
        if target.get("kind") not in {"device", "interface", "link", "tunnel"} or not target.get("uid"):
            raise ValueError("failure targets need a supported kind and explicit UID")
        if target["kind"] in {"link", "tunnel"} and not target.get("interfaces"):
            raise ValueError("link/tunnel failures need explicit modeled endpoint interface UIDs")
        key = (target["kind"], target["uid"])
        endpoints = frozenset(target.get("interfaces", []))
        if key in physical and physical[key] != endpoints:
            raise ValueError("aliases of the same physical failure must use identical endpoint interfaces")
        physical[key] = endpoints
    expanded: dict[str, dict[str, Any]] = {}
    evidence = evidence or {}

    def visit(uid: str, stack: frozenset[str]) -> dict[str, Any]:
        if uid in stack:
            raise ValueError(f"cyclic failure-domain membership at {uid}")
        if uid in expanded:
            return expanded[uid]
        if uid in entries:
            verified = evidence.get(uid, {})
            result = {
                "effects": [entries[uid]],
                "domains": [],
                "evidence_complete": verified.get("evidence_complete") is True,
                "provenance_validated": verified.get("provenance_validated") is True,
                "evidence": dict(verified),
            }
        elif uid in domain_map:
            domain = domain_map[uid]
            if not domain.get("members"):
                raise ValueError(f"failure domain {uid} must have members")
            children = [visit(str(member), stack | {uid}) for member in domain["members"]]
            physical = {(e["kind"], e["uid"]): e for c in children for e in c["effects"]}
            verified = evidence.get(uid, {})
            result = {
                "effects": [physical[key] for key in sorted(physical)],
                "domains": [uid, *(d for child in children for d in child["domains"])],
                "evidence_complete": verified.get("evidence_complete") is True
                and all(c["evidence_complete"] for c in children),
                "provenance_validated": verified.get("provenance_validated") is True,
                "evidence": dict(verified),
                "supplied_provenance": {
                    "source": domain.get("source"),
                    "evidence_status": domain.get("evidence_status", "unknown"),
                },
            }
        else:
            raise ValueError(f"unknown failure-domain member {uid}")
        expanded[uid] = result
        return result

    for uid in sorted(set(entries) | set(domain_map)):
        visit(uid, frozenset())
    return expanded


def search_resilience(
    targets: Sequence[Mapping[str, Any]],
    domains: Sequence[Mapping[str, Any]],
    oracle: Callable[[list[dict[str, Any]]], str | Mapping[str, Any]],
    limits: SearchLimits | None = None,
    *,
    selected: Sequence[str] | None = None,
    cancelled: Callable[[], bool] | None = None,
    evidence: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    expanded = expand_domains(targets, domains, evidence=evidence)
    ids = list(selected) if selected is not None else sorted(expanded)
    if not set(ids) <= set(expanded):
        raise ValueError("selected failure IDs must belong to the declared universe")
    cache: dict[tuple[Any, ...], str | Mapping[str, Any]] = {}

    def evaluate(group: tuple[str, ...]) -> Mapping[str, Any]:
        effects = {(e["kind"], e["uid"]): e for uid in group for e in expanded[uid]["effects"]}
        key = tuple(sorted(effects))
        if key not in cache:
            cache[key] = oracle([effects[k] for k in key])
        raw = cache[key]
        return {
            **(dict(raw) if isinstance(raw, Mapping) else {"verdict": raw}),
            "effects": [effects[k] for k in key],
            "domain_failures": [uid for uid in group if expanded[uid]["domains"]],
            "domain_evidence_complete": bool(group)
            and all(expanded[uid]["evidence_complete"] for uid in group),
            "provenance_validated": bool(group)
            and all(expanded[uid]["provenance_validated"] for uid in group),
        }

    result = enumerate_subsets(ids, evaluate, limits, target=FAILS, cancelled=cancelled)
    baseline = next((t["verdict"] for t in result["trials"] if not t["candidates"]), UNKNOWN)
    singles = [t for t in result["trials"] if len(t["candidates"]) == 1]
    result.update(
        {
            "kind": "resilience",
            # The baseline is the answer with no failure. The run writes it as
            # `baseline.result` when the result leaves the engine.
            "baseline": {"verdict": baseline},
            "expanded_domains": expanded,
            "unique_physical_scenarios": len(cache),
            "survives_all_single_failures": baseline == HOLDS
            and len(singles) == len(ids)
            and all(t["verdict"] == HOLDS for t in singles),
            "domain_coverage_established": bool(domains)
            and all(expanded[uid]["evidence_complete"] for uid in ids),
            "independent_diversity_established": bool(evidence)
            and (evidence or {}).get("_summary", {}).get("independent_diversity_established") is True,
            "evidence_validation": {
                "verdict": HOLDS
                if evidence and all(expanded[uid]["evidence_complete"] for uid in ids)
                else UNKNOWN,
                "provenance_validated": bool(evidence)
                and all(expanded[uid]["provenance_validated"] for uid in ids),
                "reason": "Recorded membership, source, observation and validity are checked "
                "against the pinned evidence. "
                "Unverified declarations do not establish physical diversity."
                if evidence
                else "Failure-domain membership and provenance remain unverified operator declarations.",
                "details": dict(evidence or {}),
            },
            "scope": "Steady-state connectivity conditional on the declared failure universe; "
            "independent provider, power and physical diversity are not established. "
            "Capacity and failover timing excluded.",
        }
    )
    return result


@dataclass(frozen=True)
class _FailureTransition:
    denied: bool = True

    def apply(self, region: FlowRegion) -> list[tuple[FlowRegion, Effect]]:
        return [
            (
                region,
                Effect(
                    "deny" if self.denied else "pass",
                    "failure",
                    terminal=self.denied,
                    reason="explicit modeled failure" if self.denied else None,
                ),
            )
        ]


class _FailureGates:
    def __init__(
        self,
        gates: Any,
        devices: set[str],
        interfaces: set[str],
        tunnels: set[str],
        addresses: set[str] | None = None,
    ) -> None:
        self.inner = gates
        self.devices, self.interfaces, self.failed_tunnels = devices, interfaces, tunnels
        self.addresses = addresses or set()

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    def _down(self, device: str, *interfaces: Interface | None) -> bool:
        return device in self.devices or any(i is not None and i.uid in self.interfaces for i in interfaces)

    def coverage(self, branch: Any, stage: Any, out_if: Interface | None, *, preflight: bool) -> Transition:
        # The coverage gate runs before NAT, local output, filtering and the established session state.
        if self._down(branch.device_uid, branch.in_if, out_if):
            return _FailureTransition()
        factory = getattr(self.inner, "coverage", None)
        return factory(branch, stage, out_if, preflight=preflight) if factory else _FailureTransition(False)

    def dnat(self, device: str, in_if: Interface | None) -> Transition:
        return _FailureTransition() if self._down(device, in_if) else self.inner.dnat(device, in_if)

    def filter(self, device: str, in_if: Interface | None, out_if: Interface | None) -> Transition:
        return (
            _FailureTransition()
            if self._down(device, in_if, out_if)
            else self.inner.filter(device, in_if, out_if)
        )

    def snat(self, device: str, in_if: Interface | None, out_if: Interface | None) -> Transition:
        return (
            _FailureTransition()
            if self._down(device, in_if, out_if)
            else self.inner.snat(device, in_if, out_if)
        )

    def local_filter(self, device: str, in_if: Interface | None) -> Transition:
        return _FailureTransition() if self._down(device, in_if) else self.inner.local_filter(device, in_if)

    def reply_filter(
        self, device: str, in_if: Interface | None, out_if: Interface | None, established: bool | None
    ) -> Transition:
        return (
            _FailureTransition()
            if self._down(device, in_if, out_if)
            else self.inner.reply_filter(device, in_if, out_if, established)
        )

    def output_filter(
        self, device: str, out_if: Interface | None, established: bool | None = False
    ) -> Transition:
        if self._down(device, out_if):
            return _FailureTransition()
        return (
            self.inner.output_filter(device, out_if, established=established)
            if isinstance(self.inner, GraphGates)
            else self.inner.output_filter(device, out_if)
        )

    def local_reply_filter(
        self, device: str, in_if: Interface | None, established: bool | None
    ) -> Transition:
        return (
            _FailureTransition()
            if self._down(device, in_if)
            else self.inner.local_reply_filter(device, in_if, established)
        )

    def broker(self, identity_uid: str, segment_uid: str) -> Transition:
        from hst.path.gates.zpa import ZpaTransition

        transition = self.inner.broker(identity_uid, segment_uid)
        if isinstance(transition, ZpaTransition):
            return replace(
                transition, session=_FailureBrokerSession(transition.session, self.devices, self.addresses)
            )
        return transition

    def load_balancer(self, device: str, address: str) -> Transition | None:
        return _FailureTransition() if device in self.devices else self.inner.load_balancer(device, address)

    def with_changes(self, changes: Any) -> _FailureGates:
        return type(self)(
            self.inner.with_changes(changes),
            self.devices,
            self.interfaces,
            self.failed_tunnels,
            self.addresses,
        )

    def tunnels(self, out_if: Interface, region: FlowRegion) -> tuple[Any, ...]:
        factory = getattr(self.inner, "tunnels", None)
        if factory is None:
            return ()
        return tuple(
            replace(leg, status="down", evidence=(*leg.evidence, "explicit tunnel failure"))
            if leg.tunnel_uid in self.failed_tunnels or leg.peer_tunnel_uid in self.failed_tunnels
            else leg
            for leg in factory(out_if, region)
        )


class _FailureBrokerSession:
    """A broker session whose overlay removes the addresses of failed connector hosts
    and marks failed connectors as down."""

    def __init__(self, session: Any, devices: set[str], addresses: set[str]) -> None:
        self.inner, self.devices, self.addresses = session, devices, addresses

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    def overlay(self, query: str, params: dict, rows: Any) -> Any:
        from hst.path.gates.zpa import (
            _CONNECTOR_ADDRESS_QUERY,
            _CONNECTOR_PRIVATE_IP_QUERY,
            _CONNECTOR_QUERY,
        )

        existing = getattr(self.inner, "overlay", None)
        rows = existing(query, params, rows) if existing else rows
        if query == _CONNECTOR_ADDRESS_QUERY:
            return [
                row
                for row in rows
                if row.get("host_uid") not in self.devices and address(row.get("ip")) not in self.addresses
            ]
        if query == _CONNECTOR_PRIVATE_IP_QUERY:
            return [row for row in rows if address(row.get("private_ip")) not in self.addresses]
        if query != _CONNECTOR_QUERY:
            return rows
        result = []
        for row in rows:
            hosts = pathmod._read(self.inner, _CONNECTOR_ADDRESS_QUERY, connector=row["uid"])
            down = row["uid"] in self.devices or any(host.get("host_uid") in self.devices for host in hosts)
            ips = {address(host.get("ip")) for host in hosts if host.get("ip")}
            if not ips:
                own = pathmod._read(self.inner, _CONNECTOR_PRIVATE_IP_QUERY, connector=row["uid"])
                ips = {address(r.get("private_ip")) for r in own if r.get("private_ip")}
            down |= bool(ips) and ips <= self.addresses
            result.append(
                {**row, "health": "down", "failure_reason": "connector host or all modeled interfaces failed"}
                if down
                else row
            )
        return result


class _FailureGraphGates(_FailureGates, GraphGates):
    """The failure gates over `GraphGates`.

    The evaluator uses the address-set and established-state gate semantics
    for an instance of `GraphGates`. Session reads go to the pinned session of
    the inner gates through `__getattr__`.
    """


def _require_modeled(network: Network, effects: Sequence[Mapping[str, Any]], devices: set[str]) -> None:
    """Refuse the failure of an element that has only L2 forwarding.

    The evaluator walks routed hops. The failure of an element with no routing
    context, address, prefix, route or PBR binding removes nothing from the walk.
    """
    by_uid = {i.uid: i for i in network.interfaces}
    route_refs = {
        (row.get("context_uid"), row.get("interface"))
        for row in (*network.routing.connected, *network.routing.static)
    }
    pbr_devices = {row.get("device_uid") for row in network.routing.pbr}
    pbr_interfaces = {row.get("if_uid") for row in network.routing.pbr}
    context_devices = {
        str(d)
        for c in network.routing.contexts
        for d in (c.get("device_uids") or ([c["device_uid"]] if c.get("device_uid") else ()))
    }

    def routed(interface: Interface) -> bool:
        return bool(
            interface.context_uid
            or interface.addresses
            or interface.prefixes
            or interface.uid in pbr_interfaces
            or (interface.context_uid, interface.uid) in route_refs
            or (interface.context_uid, interface.name) in route_refs
        )

    for effect in effects:
        kind, uid = effect["kind"], str(effect["uid"])
        if kind == "tunnel":
            continue
        if kind == "device":
            if uid not in devices or uid in context_devices or uid in pbr_devices:
                continue  # a broker connector, or a device with routing state
            members = [i for i in network.interfaces if i.device_uid == uid]
        else:
            names = [uid] if kind == "interface" else [str(i) for i in effect["interfaces"]]
            members = [by_uid[name] for name in names if name in by_uid]
        if not any(routed(i) for i in members):
            element = f"{kind} {uid}" + (f" ({', '.join(i.uid for i in members)})" if kind == "link" else "")
            raise ValueError(
                f"failure of {element} is not modeled: it carries only L2 forwarding "
                "(no routing context, address, prefix, route or PBR binding), "
                "and L2 failure is not modeled"
            )


def apply_failures(network: Network, effects: Sequence[Mapping[str, Any]]) -> Network:
    """Return the network after the failures of `effects`.

    The gates of a failed device or interface deny. The interfaces of a failed
    device stay in the model, and a flow that enters a failed device is a
    proven denial. The routing input loses the failed origins and the routes
    that use a failed next hop or egress interface. The engine recomputes the
    recursive resolution and the backup routes.
    """
    if not effects:
        return network
    devices: set[str] = set()
    interfaces: set[str] = set()
    tunnels: set[str] = set()
    known_devices = {i.device_uid for i in network.interfaces} | {
        str(c["device_uid"]) for c in network.routing.contexts if c.get("device_uid")
    }
    known_interfaces = {i.uid for i in network.interfaces}
    for effect in effects:
        kind, uid = effect["kind"], str(effect["uid"])
        if kind == "device":
            if uid not in known_devices:
                session = getattr(network.gates, "session", None)
                if session is None or not pathmod._read(session, _BROKER_FAILURE_TARGET, uid=uid):
                    raise ValueError(f"unknown modeled device or broker connector {uid}")
            devices.add(uid)
        elif kind == "interface":
            interfaces.add(uid)
        elif kind in {"link", "tunnel"}:
            if not effect.get("interfaces"):
                raise ValueError("link/tunnel failures require modeled endpoint interfaces")
            interfaces.update(effect["interfaces"])
            if kind == "tunnel":
                tunnels.add(uid)
        else:
            raise ValueError(f"unsupported failure kind {kind}")
    if not interfaces <= known_interfaces:
        raise ValueError("failure scope includes an unknown modeled interface")
    _require_modeled(network, effects, devices & known_devices)
    interfaces.update(i.uid for i in network.interfaces if i.device_uid in devices)
    down_interfaces = [i for i in network.interfaces if i.uid in interfaces]
    down_ips = {str(address(ip)) for i in down_interfaces for ip in i.addresses}
    routing = transform_routing(network.routing, network.interfaces, devices, interfaces)
    return replace(
        network,
        routing=routing,
        gates=(_FailureGraphGates if isinstance(network.gates, GraphGates) else _FailureGates)(
            network.gates, devices, interfaces, tunnels, down_ips
        ),
        baseline=network.baseline or network,
    )
