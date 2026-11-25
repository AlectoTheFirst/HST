"""The firewall rules of one device that match one flow, computed in the
analysis child.

`execute_match` runs inside the child process of `run_isolated`, as
`rule_explain.execute_explain` does. It loads the pinned graph and builds the
configured policy of each access rulebase that governs the device. These are
the rulebases that the device enforces, that a redundancy group of the device
enforces, or that are bound to a zone that contains an interface of the device.
Each policy is built as a rule explanation builds it
(`rule_explain.rulebase_policy`) and compiled with the symbolic backend.
`CompiledPolicy.evaluate` decides the flow.

The decision is `permit` when every packet of the flow is proven permitted,
`deny` when no packet of it can be permitted, `mixed` when the flow is decided
with part permitted and part denied, and `indeterminate` when some packet of
it is not decided.

The candidate rules are the rules that packets of the flow may arrive at and
match, in policy order. A candidate is `definite` when some packet of the flow
must arrive at the rule and match it, and `possible` otherwise. The deciding
rule is the first candidate that every packet of the flow must arrive at and
match, when its action is the decision.

A Check Point rulebase is bound to the device when the device is a gateway
Device that enforces it. The install-on column of its rules then names the
device. Otherwise the column is not bound, and the rulebase is indeterminate
with the gap INSTALLATION_UNKNOWN.

When the caller names the interfaces that the flow enters and leaves the
device by, each rulebase is normalized for their names, and a rule scoped to
an interface is decided. A rulebase that does not receive the flow is
`not_applicable`. This applies to a zone pair whose source or destination zone
does not contain the named interface, to an interface ACL bound to neither
interface, and to an input or output chain (VyOS, a UniFi LOCAL ruleset) for a
flow forwarded between two interfaces. A rulebase that records the other
address family (`rule_explain.rulebase_family`) is `not_applicable` for any
flow, as the firewall gate of the tracer skips it. A rulebase that records no
family judges both families. `receives` states whether the rulebase receives
the flow, and is null when an unnamed interface leaves it open. When both
named interfaces are in zones and no ruleset of the family of the flow binds
that zone pair, one more entry gives the zone policy that the zone gate of the
tracer applies (`zone_policy`).

The flow is evaluated as first fragments (fragment offset 0). A failure that
the caller can act on is returned as an `error` document. The child passes no
exception text to its parent.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal

from hst.assessment.rule_explain import (
    _KNOWN_FIELDS,
    _entering,
    _error,
    _gateways,
    _raw,
    rulebase_family,
    rulebase_policy,
)

# One answer evaluates at most MAX_RULEBASES rulebases and lists at most
# MAX_CANDIDATE_RULES candidate rules per rulebase.
MAX_RULEBASES = 20
MAX_CANDIDATE_RULES = 50
MAX_GAPS = 200


def execute_match(settings: Any, inputs: dict, *, cancelled: Callable[[], bool] | None = None) -> dict:
    """Load the pinned graph in the child and match one flow.

    The load starts with the per-device objects of the named device and widens
    to the devices that the match reads (`load_scoped`). The match runs while
    the session is open, and the scoped graph looks nodes up through it."""
    from hst.analysis_model.graph import (
        DEFAULT_MEMORY_MB,
        GraphInventory,
        GraphTooLarge,
        load_graph,
        load_scoped,
    )
    from hst.analysis_model.read import ReadError
    from hst.core import db
    from hst.core import snapshot as snapshotmod

    reference = inputs["snapshot"]
    device = str(inputs["device"])
    memory_mb = int(getattr(settings, "analysis_memory_mb", DEFAULT_MEMORY_MB))
    with db.session(settings, access_mode="READ") as session:
        snap = snapshotmod.resolve(session, settings, int(reference["snapshot"]))

        def load(scope: frozenset[str] | None) -> GraphInventory:
            return load_graph(
                session,
                snap,
                reference["manifest_sha256"],
                memory_mb=memory_mb,
                devices=scope,
                cancelled=cancelled,
            )

        def use(graph: GraphInventory) -> dict:
            return match(
                graph,
                str(reference["estate"]),
                device,
                inputs.get("rulebase"),
                inputs["flow"],
                int(inputs["address_family"]),  # type: ignore[arg-type]
                ingress=inputs.get("ingress_interface"),
                egress=inputs.get("egress_interface"),
            )

        try:
            return load_scoped(load, use, frozenset({device}))
        except GraphTooLarge as exc:
            return _error("limit_exceeded", str(exc))
        except ReadError as exc:
            return _error("engine_unavailable", f"the pinned graph could not be loaded: {exc}")


def _device_interface(graph: Any, device_uid: str, ref: str, field: str) -> str | dict[str, Any]:
    """The name of the device interface `ref` names by uid or by name, or
    the refusal."""
    interfaces = [node for node in graph.sources(device_uid, "ON") if "Interface" in node.labels]
    exact = [node for node in interfaces if node.uid == ref] or [
        node for node in interfaces if node.props.get("name") == ref
    ]
    if not exact:
        return _error("not_found", f"device {device_uid} has no interface {ref!r} in this snapshot", field)
    if len(exact) > 1:
        return _error(
            "ambiguous",
            f"{len(exact)} interfaces of device {device_uid} are named {ref!r}; pass one uid from candidates",
            field,
            [{"uid": node.uid, "name": node.props.get("name")} for node in exact[:10]],
        )
    name = exact[0].props.get("name")
    if not name:
        return _error("not_found", f"interface {exact[0].uid} has no name in this snapshot", field)
    return str(name)


def receives(graph: Any, rulebase_uid: str, ingress: str | None, egress: str | None) -> bool | None:
    """Whether the rulebase receives a flow that enters by interface
    `ingress` and leaves by `egress`. Both are interface names, and None means
    that the interface is not named. The result is None when an unnamed
    interface, or data that the graph does not hold, leaves the answer open."""
    from hst.assessment.rule_scope import acl_bindings, zone_side
    from hst.policy.graph import LOCAL_INTERFACE

    base = graph.nodes[rulebase_uid]
    props = base.props
    context = props.get("match_context")
    if context == "zone-pair":
        sides: list[bool | None] = []
        for kind, named in (("FROM_ZONE", ingress), ("TO_ZONE", egress)):
            members, _zone, gap = zone_side(graph, rulebase_uid, kind)
            if named is None or gap is not None or members is None:
                sides.append(None)
            else:
                sides.append(named in members and named != LOCAL_INTERFACE)
        if False in sides:
            return False
        return True if sides == [True, True] else None
    if context == "interface-acl":
        # a list that records the forward chain (a UniFi LAN_IN) never sees a
        # packet the device terminates or emits
        if props.get("chain") == "forward" and LOCAL_INTERFACE in (ingress, egress):
            return False
        inbound, outbound = acl_bindings(graph, base)
        if (ingress is not None and ingress in inbound) or (egress is not None and egress in outbound):
            return True
        open_in = ingress is None and bool(inbound)
        open_out = egress is None and bool(outbound)
        return None if open_in or open_out else False
    if props.get("chain") in ("forward", "input", "output"):
        chain = props["chain"]
        # A packet to or from the router names the pseudo-interface LOCAL_INTERFACE.
        if chain == "input" and egress is not None:
            return egress == LOCAL_INTERFACE
        if chain == "output" and ingress is not None:
            return ingress == LOCAL_INTERFACE
        if chain == "forward" and ingress is not None and egress is not None:
            return True
        return None
    return None


def device_rulebases(graph: Any, device_uid: str) -> list[str]:
    """The access rulebases that govern traffic through the device, in uid
    order. They are the rulebases that the device or a group of the device
    enforces, and the rulebases bound to a zone that contains an interface of
    the device."""

    def access(node: Any) -> bool:
        return "FwRulebase" in node.labels and (node.props.get("kind") or "access") == "access"

    found: set[str] = set()
    owners = [device_uid, *(node.uid for node in graph.targets(device_uid, "MEMBER_OF"))]
    for owner in owners:
        found.update(node.uid for node in graph.targets(owner, "ENFORCES") if access(node))
    for interface in graph.sources(device_uid, "ON"):
        if "Interface" not in interface.labels:
            continue
        for zone in graph.sources(interface.uid, "CONTAINS"):
            if "Zone" not in zone.labels:
                continue
            for relation in ("FROM_ZONE", "TO_ZONE"):
                found.update(node.uid for node in graph.sources(zone.uid, relation) if access(node))
    return sorted(found)


def _zone_containing(graph: Any, device_uid: str, name: str) -> Any:
    """The zone that contains the device interface named `name`, the first by
    name as the tracer's `_zone_of` reads it, or None."""
    zones = [
        zone
        for interface in graph.sources(device_uid, "ON")
        if "Interface" in interface.labels and interface.props.get("name") == name
        for zone in graph.sources(interface.uid, "CONTAINS")
        if "Zone" in zone.labels
    ]
    return min(zones, key=lambda zone: str(zone.props.get("name") or zone.uid), default=None)


def zone_policy(
    graph: Any, device_uid: str, family: int, ingress: str | None, egress: str | None
) -> dict[str, Any] | None:
    """The zone policy entry for a flow between two named interfaces whose
    zone pair binds no ruleset of the family of the flow.

    The entry follows the zone gate of the tracer
    (`gates.firewall._zone_pair_verdict`). Inside one zone the entry is the
    intra-zone filtering of the zone. Between two zones it is the
    default-action of the destination zone. A value that the graph does not
    record leaves the entry indeterminate with a named gap. The result is None
    when an interface is not named or is in no zone, when a ruleset of the
    family of the flow binds the pair, or when the flow stays inside a zone
    that records no intra-zone filtering (UniFi, a graph without the marker).
    The gate gives no zone verdict for such a zone."""
    from hst.path.verdict import DENY, PERMIT, classify_action
    from hst.policy.graph import LOCAL_INTERFACE

    if ingress is None or egress is None or LOCAL_INTERFACE in (ingress, egress):
        return None
    source, destination = (
        _zone_containing(graph, device_uid, ingress),
        _zone_containing(graph, device_uid, egress),
    )
    if source is None or destination is None:
        return None
    bound = [
        node
        for node in graph.sources(source.uid, "FROM_ZONE")
        if "FwRulebase" in node.labels
        and any(zone.uid == destination.uid for zone in graph.targets(node.uid, "TO_ZONE"))
    ]
    if any(rulebase_family(node) in (None, family) for node in bound):
        return None
    source_name = str(source.props.get("name") or source.uid)
    destination_name = str(destination.props.get("name") or destination.uid)
    action: Any
    reason: str | None = None
    gap: str | None = None
    if source.uid == destination.uid:
        recorded = source.props.get("intra_zone_filtering")
        action, by = source.props.get("intra_zone_action"), "intra-zone-filtering"
        uid, name = f"zone-pair:{source_name}->{source_name}#intra", f"{source_name} intra-zone policy"
        if recorded is None and not bound:
            return None
        if not action and not recorded and not bound:
            action, by = "accept", "intra-zone default"
        elif not action:
            gap = "ZONE_INTRA_POLICY_UNKNOWN"
            reason = (
                f"zone {source_name} filters traffic within it by a ruleset for the other address family only"
            )
    else:
        uid = f"zone-pair:{source_name}->{destination_name}#unbound"
        name = f"{source_name}→{destination_name} zone policy (no ruleset bound)"
        action, by = destination.props.get("default_action"), "default-action"
        if not action:
            gap = "ZONE_DEFAULT_UNKNOWN"
            reason = f"zone {destination_name} records no default-action"
    outcome = classify_action(action) if action else None
    if gap is None and outcome not in (PERMIT, DENY):
        gap, reason = "ZONE_ACTION_UNKNOWN", f"zone action {action!r} is not modeled"
    return {
        "uid": uid,
        "name": name,
        "zones": f"{source_name}→{destination_name}",
        "vendor": source.props.get("vendor"),
        "firewall": None,
        "qualified": True,
        "receives": True,
        "decision": "indeterminate" if gap else ("permit" if outcome == PERMIT else "deny"),
        "by": by,
        "reason": reason,
        "deciding_rule": None,
        "candidate_rules": [],
        "candidate_rules_truncated": False,
        "gaps": [{"code": gap, "subject": destination.uid, "detail": reason}] if gap else [],
    }


def request_predicate(flow: dict[str, Any]) -> Any:
    """The flow as a header predicate of first fragments. `flow` holds address
    and port intervals as `[low, high]` pairs and protocol numbers. A service
    dimension that is None is not constrained."""
    from hst.policy.ir import AllOf, AnyOf, Atom

    def ranges(field: str, values: list[list[int]]) -> Any:
        return AnyOf(tuple(Atom(field, "range", int(low), int(high)) for low, high in values))

    terms: list[Any] = [
        ranges("source_address", flow["sources"]),
        ranges("destination_address", flow["destinations"]),
        Atom("fragment_offset", "eq", 0),
    ]
    if flow.get("protocols") is not None:
        terms.append(AnyOf(tuple(Atom("protocol", "eq", int(value)) for value in flow["protocols"])))
    if flow.get("destination_ports") is not None:
        terms.append(ranges("destination_port", flow["destination_ports"]))
    if flow.get("source_ports") is not None:
        terms.append(ranges("source_port", flow["source_ports"]))
    return AllOf(tuple(terms))


def match(
    graph: Any,
    estate: str,
    device_uid: str,
    rulebase_uid: str | None,
    flow: dict[str, Any],
    family: Literal[4, 6],
    *,
    ingress: str | None = None,
    egress: str | None = None,
) -> dict[str, Any]:
    """The decision and the candidate rules of each rulebase that governs the
    device, or of the one rulebase `rulebase_uid` names. `ingress` and
    `egress` name the device interfaces the flow enters and leaves by, by uid
    or by name."""
    from hst.symbolic import HeaderSchema, SymbolicManager

    device = graph.nodes.get(device_uid)
    if device is None or "Device" not in device.labels:
        return _error("not_found", f"no device {device_uid} in this snapshot", "device")
    names: dict[str, str | None] = {}
    for field, ref in (("ingress_interface", ingress), ("egress_interface", egress)):
        if ref is None:
            names[field] = None
            continue
        resolved = _device_interface(graph, device_uid, str(ref), field)
        if isinstance(resolved, dict):
            return resolved
        names[field] = resolved
    rulebases = device_rulebases(graph, device_uid)
    if rulebase_uid is not None:
        if rulebase_uid not in rulebases:
            return _error(
                "not_found",
                f"{rulebase_uid} is not an access rulebase that governs device {device_uid}",
                "rulebase",
                [{"uid": uid, "name": graph.nodes[uid].props.get("name")} for uid in rulebases[:10]],
            )
        rulebases = [rulebase_uid]
    # The rulebases of the family of the flow sort first. The first MAX_RULEBASES
    # rulebases are evaluated, and a rulebase of the other family is not applicable.
    rulebases.sort(key=lambda uid: rulebase_family(graph.nodes[uid]) not in (None, family))
    predicate = request_predicate(flow)
    items: list[dict[str, Any]] = []
    with SymbolicManager(HeaderSchema(family)) as manager:
        for uid in rulebases[:MAX_RULEBASES]:
            item = _rulebase(
                graph,
                estate,
                device_uid,
                uid,
                family,
                manager,
                predicate,
                names["ingress_interface"],
                names["egress_interface"],
            )
            if "error" in item:
                return item
            items.append(item)
    # The zone entry is added to the evaluated rulebases and to `rulebase_count`.
    zone_entries = 0
    if rulebase_uid is None:
        zone = zone_policy(graph, device_uid, family, names["ingress_interface"], names["egress_interface"])
        if zone is not None:
            items.append(zone)
            zone_entries = 1
    return {
        "device": device_uid,
        "address_family": family,
        "rulebases": items,
        "rulebase_count": len(rulebases) + zone_entries,
        "rulebases_truncated": len(rulebases) > MAX_RULEBASES,
    }


def _rule_ids(graph: Any, policy: Any, checkpoint: bool) -> dict[tuple[str, str], tuple[str, Any, str]]:
    """A map from (layer uid, rule uid), as the policy names them, to the graph
    rule uid, its position and the graph uid of its rulebase. A Check Point
    policy names layers and rules by their envelope uids. Any other policy
    names them by graph uid."""
    out: dict[tuple[str, str], tuple[str, Any, str]] = {}
    if not checkpoint:
        for layer in policy.layers:
            for rule in layer.rules:
                node = graph.nodes.get(rule.uid)
                out[layer.uid, rule.uid] = (rule.uid, node.props.get("position") if node else None, layer.uid)
        return out
    layers = {layer.uid for layer in policy.layers}
    for rulebase_uid in graph.labels.get("FwRulebase", ()):
        raw = _raw(graph.nodes[rulebase_uid])
        if raw is None or raw not in layers:
            continue
        for node in graph.targets(rulebase_uid, "HAS_RULE"):
            rule_raw = _raw(node)
            if rule_raw is not None:
                out[raw, rule_raw] = (node.uid, node.props.get("position"), rulebase_uid)
    return out


def _rulebase(
    graph: Any,
    estate: str,
    device_uid: str,
    uid: str,
    family: Literal[4, 6],
    manager: Any,
    predicate: Any,
    ingress: str | None = None,
    egress: str | None = None,
) -> dict[str, Any]:
    """The decision and the candidate rules of one rulebase, for a flow
    through the named interfaces."""
    from hst.policy.compile import PolicyCompiler

    node = graph.nodes[uid]
    vendor = node.props.get("vendor")
    entry: dict[str, Any] = {
        "uid": uid,
        "name": node.props.get("name"),
        "vendor": vendor,
        "firewall": None,
        "qualified": True,
        "decision": "indeterminate",
        "deciding_rule": None,
        "candidate_rules": [],
        "candidate_rules_truncated": False,
        "gaps": [],
    }
    recorded = rulebase_family(node)
    if recorded is not None and recorded != family:
        return {**entry, "receives": False, "decision": "not_applicable", "address_family": recorded}
    if vendor != "checkpoint":
        received = receives(graph, uid, ingress, egress)
        entry["receives"] = received
        if received is False:
            return {**entry, "decision": "not_applicable"}
    gateway: str | None = None
    if vendor == "checkpoint":
        if device_uid not in _gateways(graph, uid):
            return {
                **entry,
                "installation_unknown": True,
                "gaps": [{"code": "INSTALLATION_UNKNOWN", "subject": uid}],
            }
        gateway = entry["firewall"] = device_uid
    policy, context, checkpoint = rulebase_policy(
        graph, estate, uid, family, gateway, ingress=ingress, egress=egress
    )
    if policy is None:
        return {
            **entry,
            "qualified": False,
            "gaps": [{"code": "CHECKPOINT_CAPTURE_UNQUALIFIED", "subject": uid}],
        }
    compiler = PolicyCompiler(manager, context, _KNOWN_FIELDS)
    compiled = compiler.compile(policy)
    request = compiler.predicates.compile(predicate).bounds.lower
    if request.is_empty():
        return _error("invalid_argument", "the flow holds no packet of its address family", "flow")
    decision = compiled.evaluate(request)
    lower, upper = decision.bounds.lower, decision.bounds.upper
    if not upper.subtract(lower).is_empty():
        verdict = "indeterminate"
    elif request.subtract(lower).is_empty():
        verdict = "permit"
    elif upper.is_empty():
        verdict = "deny"
    else:
        verdict = "mixed"
    gaps = list(dict.fromkeys((gap.reason.code, gap.reason.subject) for gap in decision.gaps))
    candidates, truncated = _candidates(graph, compiler, compiled, policy, request, checkpoint)
    deciding = next(
        (item for item in candidates if item["whole_flow"] and item["action"] == verdict),
        None,
    )
    return {
        **entry,
        "decision": verdict,
        "deciding_rule": (
            None
            if deciding is None
            else {key: deciding[key] for key in ("uid", "position", "action", "rulebase")}
        ),
        "candidate_rules": candidates,
        "candidate_rules_truncated": truncated,
        "gaps": [{"code": code, "subject": subject} for code, subject in gaps[:MAX_GAPS]],
    }


def _candidates(
    graph: Any, compiler: Any, compiled: Any, policy: Any, request: Any, checkpoint: bool
) -> tuple[list[dict[str, Any]], bool]:
    """The rules that packets of `request` may arrive at and match, in policy
    order, and whether more than `MAX_CANDIDATE_RULES` of them exist.

    The attribution of a rule covers its own layer. The function intersects
    it with the packets that enter the layer, as a rule explanation does."""
    ids = _rule_ids(graph, policy, checkpoint)
    installed = compiler.predicates.compile(policy.installation).bounds.lower
    entering: dict[str, tuple[Any, Any]] = {}
    out: list[dict[str, Any]] = []
    for layer in policy.layers:
        for rule in layer.rules:
            if not rule.enabled:
                continue
            if compiler.predicates.compile(rule.predicate).bounds.upper.intersect(request).is_empty():
                continue
            try:
                attribution = compiled.explain_rule(layer.uid, rule.uid)
            except KeyError:
                continue
            if layer.uid not in entering:
                entering[layer.uid] = _entering(compiler, compiled, policy, layer.uid, frozenset())
            entry_lower, entry_upper = entering[layer.uid]
            upper = attribution.bounds.upper.intersect(entry_upper).intersect(request)
            if upper.is_empty():
                continue
            if len(out) >= MAX_CANDIDATE_RULES:
                return out, True
            lower = attribution.bounds.lower.intersect(entry_lower).intersect(installed).intersect(request)
            uid, position, rulebase = ids.get((layer.uid, rule.uid), (rule.uid, None, layer.uid))
            out.append(
                {
                    "uid": uid,
                    "position": position,
                    "rulebase": rulebase,
                    "action": rule.action,
                    "match": "possible" if lower.is_empty() else "definite",
                    "whole_flow": request.subtract(lower).is_empty(),
                }
            )
    return out, False
