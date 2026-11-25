"""The interfaces and connection states a rule explanation is evaluated over.

A rule can be scoped to the interface that a flow enters or leaves by (VyOS
`inbound-interface`/`outbound-interface`, the bindings of a Cisco ACL) and to
its connection state. Its rulebase receives only some flows.

- A zone pair receives the flows that enter through an interface of its source
  zone and leave through an interface of its destination zone.
- An interface ACL receives the flows that enter through an interface it is
  bound inbound to or leave through an interface it is bound outbound to.
- An `input` chain (a VyOS chain, a UniFi LOCAL ruleset) receives the flows
  addressed to the router itself.
- No rulebase receives the states that a VyOS global state policy decides first.

These conditions are not header fields, and the explanation is computed once
per scope. A scope is an ingress class, an egress class and a state class. A
class is a set of interface names (or states) that every condition of the
rulebase, up to and including the explained rule, treats alike. One
representative stands for the class.

The interface names of a side are the names that the graph holds. They are the
members of the zone, the interfaces of the device that enforces the rulebase,
and the names that the conditions spell. When the device is not known the side
also has the class "(other)", which is any interface that the snapshot does
not name. A wildcard condition on that side makes such a name undecidable. The
side is then not evaluated, and the interface condition of the rule stays the
gap GRAPH_RULE_INTERFACE_UNKNOWN.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product
from typing import Any

from hst.policy.graph import LOCAL_INTERFACE, interface_scope_matches

STATES = ("new", "established", "related", "invalid")
OTHER_INTERFACE = "(other)"
# Above this count of scopes, the explanation is computed once with the interfaces unresolved.
MAX_SCOPES = 64


@dataclass(frozen=True, slots=True)
class SideClass:
    """Names that every condition treats alike. The representative is None
    for a side that is not evaluated."""

    representative: str | None
    members: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ScopeSpace:
    ingress: tuple[SideClass, ...]
    egress: tuple[SideClass, ...]
    states: tuple[SideClass, ...]
    entry: dict[str, Any]
    gaps: tuple[tuple[str, str], ...]
    combinations: tuple[tuple[int, int, int], ...]


_UNEVALUATED = (SideClass(None, ()),)


def _names(nodes: Any) -> list[str]:
    return [
        str(node.props["name"]) for node in nodes if "Interface" in node.labels and node.props.get("name")
    ]


def _rules_through(graph: Any, rulebase_uid: str, rule_uid: str) -> list[Any]:
    """The rules of the rulebase up to and including the explained rule. When a
    position is not an integer, the result is all rules of the rulebase."""
    rules = graph.targets(rulebase_uid, "HAS_RULE")
    target = next((rule for rule in rules if rule.uid == rule_uid), None)
    position = target.props.get("position") if target is not None else None
    positions = [rule.props.get("position") for rule in rules]
    if type(position) is not int or any(type(value) is not int for value in positions):
        return list(rules)
    return [rule for rule in rules if rule.props["position"] <= position]


def _called(graph: Any, rules: list[Any]) -> tuple[list[Any], list[Any]]:
    """The rules and the rulebases of the named rulesets that `rules` jump to,
    and those they jump to in turn, as the policy builds the called layers
    (`GraphPolicyNormalizer.policy`). The conditions of these rules also split
    the classes."""
    called_rules: list[Any] = []
    bases: list[Any] = []
    seen: set[str] = set()
    pending = [
        str(rule.props["jump_target"])
        for rule in rules
        if str(rule.props.get("action", "")).lower() == "jump" and rule.props.get("jump_target")
    ]
    while pending:
        uid = pending.pop()
        node = graph.nodes.get(uid)
        if uid in seen or node is None or "FwRulebase" not in node.labels:
            continue
        seen.add(uid)
        bases.append(node)
        members = list(graph.targets(uid, "HAS_RULE"))
        called_rules.extend(members)
        pending.extend(
            str(rule.props["jump_target"])
            for rule in members
            if str(rule.props.get("action", "")).lower() == "jump" and rule.props.get("jump_target")
        )
        if str(node.props.get("default_action", "")).lower() == "jump" and node.props.get(
            "default_jump_target"
        ):
            pending.append(str(node.props["default_jump_target"]))
    return called_rules, bases


def _device_interfaces(graph: Any, rulebase_uid: str) -> list[str] | None:
    """The interface names of the one device the rulebase acts on, or None
    when the graph does not name exactly one device with interfaces."""
    devices: set[str] = set()

    def device_of(interface_uid: str) -> None:
        devices.update(node.uid for node in graph.targets(interface_uid, "ON") if "Device" in node.labels)

    devices.update(node.uid for node in graph.sources(rulebase_uid, "ENFORCES") if "Device" in node.labels)
    for kind in ("FROM_ZONE", "TO_ZONE"):
        for zone in graph.targets(rulebase_uid, kind):
            devices.update(
                node.uid for node in graph.targets(zone.uid, "OWNED_BY") if "Device" in node.labels
            )
            for interface in graph.targets(zone.uid, "CONTAINS"):
                device_of(interface.uid)
    for interface in graph.sources(rulebase_uid, "PROTECTED_BY"):
        device_of(interface.uid)
    if len(devices) != 1:
        return None
    names = sorted(set(_names(graph.sources(next(iter(devices)), "ON"))))
    return names or None


def acl_bindings(graph: Any, base: Any) -> tuple[set[str], set[str]]:
    inbound: set[str] = set()
    outbound: set[str] = set()
    for relation in graph.incoming.get((base.uid, "PROTECTED_BY"), ()):
        interface = graph.nodes.get(relation.start)
        direction = relation.props.get("direction")
        if interface is not None and "Interface" in interface.labels and interface.props.get("name"):
            if direction == "in":
                inbound.add(str(interface.props["name"]))
            elif direction == "out":
                outbound.add(str(interface.props["name"]))
    unreported = base.props.get("unreported_bindings")
    for entry in unreported if isinstance(unreported, (list, tuple)) else ():
        spelled, _sep, side = str(entry).rpartition(" ")
        if spelled and side == "in":
            inbound.add(spelled)
        elif spelled and side == "out":
            outbound.add(spelled)
    return inbound, outbound


def zone_side(graph: Any, base_uid: str, kind: str) -> tuple[list[str] | None, str | None, str | None]:
    """The names a zone pair side ranges over, the zone's name, and the gap
    when the graph does not hold them."""
    zones = [zone for zone in graph.targets(base_uid, kind) if "Zone" in zone.labels]
    if len(zones) != 1:
        return None, None, "GRAPH_ZONE_PAIR_UNKNOWN"
    zone = zones[0]
    name = str(zone.props.get("name") or zone.uid)
    if zone.props.get("local_zone") is True:
        return [LOCAL_INTERFACE], name, None
    members = sorted(set(_names(graph.targets(zone.uid, "CONTAINS"))))
    if not members:
        return None, name, "GRAPH_ZONE_MEMBERS_MISSING"
    return members, name, None


def _classes(candidates: list[str], conditions: list[Any]) -> tuple[SideClass, ...]:
    groups: dict[tuple[bool, ...], list[str]] = {}
    for name in candidates:
        groups.setdefault(tuple(condition(name) for condition in conditions), []).append(name)
    return tuple(SideClass(members[0], tuple(members)) for members in groups.values())


def _side_conditions(
    rules: list[Any], side: str, bound: set[str] | None
) -> tuple[list[Any], list[str], bool]:
    """The conditions on one side, the literal names they spell, and whether
    one of them is a wildcard."""
    conditions: list[Any] = []
    spelled: list[str] = []
    wildcard = False
    for rule in rules:
        scope = rule.props.get(f"{side}_interface")
        if scope:
            text = str(scope)
            conditions.append(lambda name, text=text: interface_scope_matches(text, name))
            pattern = text[1:].strip() if text.startswith("!") else text
            if pattern.endswith("*"):
                wildcard = True
            elif pattern:
                spelled.append(pattern)
        values = rule.props.get(f"{side}_interfaces")
        if isinstance(values, (list, tuple)):
            listed = tuple(str(value) for value in values)
            conditions.append(lambda name, listed=listed: name in listed)
            spelled.extend(listed)
    if bound is not None:
        frozen = frozenset(bound)
        conditions.append(lambda name: name in frozen)
        spelled.extend(bound)
    return conditions, spelled, wildcard


def _bound(graph: Any, rulebase_uid: str) -> bool:
    """Whether the graph holds an edge that hands flows to the rulebase. The
    edge is an ENFORCES, PROTECTED_BY, FROM_ZONE or TO_ZONE edge of the rulebase."""
    return any(graph.incoming.get((rulebase_uid, kind)) for kind in ("ENFORCES", "PROTECTED_BY")) or any(
        graph.targets(rulebase_uid, kind) for kind in ("FROM_ZONE", "TO_ZONE")
    )


def _jump_callers(graph: Any, rulebase_uid: str) -> list[str]:
    """The uids of the rules whose jump target, and of the rulebases whose
    default jump target, is the rulebase, in uid order, at most ten."""
    callers = [
        uid
        for label, key in (("FwRule", "jump_target"), ("FwRulebase", "default_jump_target"))
        for uid in graph.labels.get(label, ())
        if graph.nodes[uid].props.get(key) == rulebase_uid
    ]
    return sorted(callers)[:10]


def scope_space(graph: Any, rulebase_uid: str, rule_uid: str) -> ScopeSpace:
    """The scopes the rule is explained over and what its rulebase receives."""
    base = graph.nodes[rulebase_uid]
    props = base.props
    rules = _rules_through(graph, rulebase_uid, rule_uid)
    called_rules, called_bases = _called(graph, rules)
    # The classes are split by the conditions of the rules up to the explained rule
    # and of the rules of the rulesets that they jump to.
    rules = [*rules, *called_rules]
    context = props.get("match_context")
    gaps: list[tuple[str, str]] = []
    entry: dict[str, Any] = {"kind": "unbound", "evaluated": False}
    device = _device_interfaces(graph, rulebase_uid)
    sides: dict[str, list[str] | None] = {"in": device, "out": device}
    # The names of a fixed side are the names of its zone or the local interface.
    # The names that the conditions spell are not added.
    fixed = {"in": False, "out": False}
    acl_in: set[str] | None = None
    acl_out: set[str] | None = None
    if context == "zone-pair":
        ingress, source, source_gap = zone_side(graph, rulebase_uid, "FROM_ZONE")
        egress, destination, destination_gap = zone_side(graph, rulebase_uid, "TO_ZONE")
        gaps.extend((gap, rulebase_uid) for gap in dict.fromkeys((source_gap, destination_gap)) if gap)
        sides = {"in": ingress, "out": egress}
        fixed = {"in": True, "out": True}
        entry = {
            "kind": "zone-pair",
            "evaluated": ingress is not None and egress is not None,
            "from_zone": source,
            "to_zone": destination,
        }
    elif context == "interface-acl":
        acl_in, acl_out = acl_bindings(graph, base)
        entry = {
            "kind": "interface-acl",
            "evaluated": True,
            "inbound": sorted(acl_in),
            "outbound": sorted(acl_out),
        }
    elif props.get("chain") in ("forward", "input", "output"):
        chain = props["chain"]
        if chain == "input":
            sides["out"], fixed["out"] = [LOCAL_INTERFACE], True
        elif chain == "output":
            sides["in"], fixed["in"] = [LOCAL_INTERFACE], True
        entry = {"kind": "chain", "evaluated": device is not None, "chain": chain}
    elif props.get("vendor") == "vyos" and not _bound(graph, rulebase_uid):
        # A VyOS named ruleset with no zone pair and no chain receives only the
        # flows that the jump rules of other rulesets hand to it. No flow is known
        # to arrive at it.
        gaps.append(("GRAPH_RULEBASE_ENTRY_UNBOUND", rulebase_uid))
        entry["jump_callers"] = _jump_callers(graph, rulebase_uid)

    classes: dict[str, tuple[SideClass, ...]] = {}
    for side, bound in (("in", acl_in), ("out", acl_out)):
        conditions, spelled, wildcard = _side_conditions(rules, side, bound)
        candidates = sides[side]
        names: list[str] | None
        if fixed[side]:
            names = candidates
        elif candidates is not None:
            names = list(dict.fromkeys([*candidates, *spelled]))
        elif wildcard:
            # a wildcard cannot be decided for an interface the snapshot does not name
            names = None
        else:
            names = list(dict.fromkeys([*spelled, OTHER_INTERFACE]))
        classes[side] = _classes(names, conditions) if names else _UNEVALUATED
    entry["ingress"] = _side(classes["in"], list(range(len(classes["in"]))))
    entry["egress"] = _side(classes["out"], list(range(len(classes["out"]))))
    decided = sorted(
        {
            str(item).partition("=")[0]
            for item in props.get("global_state_policy") or ()
            if str(item).partition("=")[0] in STATES
        }
    )
    entering = [state for state in STATES if state not in decided]
    state_conditions = [
        (lambda state, values=tuple(rule.props["states"]): state in values)
        for rule in rules
        if isinstance(rule.props.get("states"), (list, tuple)) and rule.props.get("states")
    ]
    if any(base.props.get("established_default_unknown") for base in called_bases):
        # a called ruleset's default is open for a reply (`_state_rules_default`)
        state_conditions.append(lambda state, values=("established", "related"): state in values)
    states = _classes(entering, state_conditions)
    entry["states"] = entering
    if decided:
        entry["state_policy"] = sorted(str(item) for item in props.get("global_state_policy") or ())

    combinations = []
    for i, e, s in product(range(len(classes["in"])), range(len(classes["out"])), range(len(states))):
        if acl_in is not None and acl_out is not None:
            # an interface ACL receives a flow that enters through an interface it is
            # bound inbound to or leaves through one it is bound outbound to
            ingress_rep, egress_rep = classes["in"][i].representative, classes["out"][e].representative
            if (
                ingress_rep is not None
                and egress_rep is not None
                and ingress_rep not in acl_in
                and egress_rep not in acl_out
            ):
                continue
        combinations.append((i, e, s))
    if len(combinations) > MAX_SCOPES:
        # Above MAX_SCOPES the rule is evaluated once, with the interfaces unresolved
        # and the state `new`.
        gaps.append(("RULE_SCOPE_LIMIT", rulebase_uid))
        entry.update({"evaluated": False, "ingress": None, "egress": None, "states": ["new"]})
        new = SideClass("new", ("new",))
        return ScopeSpace(_UNEVALUATED, _UNEVALUATED, (new,), entry, tuple(gaps), ((0, 0, 0),))
    return ScopeSpace(classes["in"], classes["out"], states, entry, tuple(gaps), tuple(combinations))


def describe(space: ScopeSpace, triples: list[tuple[int, int, int]]) -> list[dict[str, Any]]:
    """The scopes of one result as few products of ingress, egress and state
    names as the triples allow."""
    by_ingress: dict[int, set[tuple[int, int]]] = {}
    for i, e, s in triples:
        by_ingress.setdefault(i, set()).add((e, s))
    merged: dict[frozenset[tuple[int, int]], list[int]] = {}
    for i, pairs in sorted(by_ingress.items()):
        merged.setdefault(frozenset(pairs), []).append(i)
    out: list[dict[str, Any]] = []
    for scope_pairs, ingress in merged.items():
        by_egress: dict[int, set[int]] = {}
        for e, s in scope_pairs:
            by_egress.setdefault(e, set()).add(s)
        grouped: dict[frozenset[int], list[int]] = {}
        for e, state_set in sorted(by_egress.items()):
            grouped.setdefault(frozenset(state_set), []).append(e)
        for states, egress in grouped.items():
            out.append(
                {
                    "ingress": _side(space.ingress, ingress),
                    "egress": _side(space.egress, egress),
                    "states": [
                        state for state in STATES if any(state in space.states[s].members for s in states)
                    ],
                }
            )
    return out


def _side(classes: tuple[SideClass, ...], indexes: list[int]) -> list[str] | None:
    if any(classes[index].representative is None for index in indexes):
        return None
    names = {name for index in indexes for name in classes[index].members}
    return sorted(names, key=lambda name: (name in (LOCAL_INTERFACE, OTHER_INTERFACE), name))
