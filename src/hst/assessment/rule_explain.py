"""Rule attribution for one firewall rule, computed in the analysis child.

`execute_explain` runs inside the child process of `run_isolated`. It loads
the pinned graph and normalizes the rulebase of the rule into policy IR as the
configuration comparison does (`hst.assessment.native_verification`). A
Check Point rulebase is normalized through its qualified package. Any other
rulebase is normalized on its own. The policy is compiled with the symbolic
backend. `CompiledPolicy.explain_rule` gives the packets that must arrive at
the rule and match it (the lower bound) and the packets that may (the upper
bound) inside the layer of the rule.

The interface and connection-state conditions of a rule, and the zone pair,
ACL bindings or chain that hand flows to its rulebase, are not header fields.
A rulebase of any vendor other than Check Point is explained once per scope of
`rule_scope.scope_space`. A scope is an ingress class, an egress class and a
state class. Scopes with the same result are reported together. A NAT rulebase
is refused. Its rules are translations.

`explain_rule` leaves the packets that enter the layer to its caller, and this
module applies them. An ordered layer receives the packets that every earlier
ordered layer permits. An inline layer receives the packets that arrive at and
match a rule that calls it. The installation condition of the policy bounds
the lower bound.

The install-on column of a Check Point rule names gateways. The policy of the
rule is built for one gateway Device that enforces the rulebase. This is the
gateway that the caller names, or the only gateway. With several gateways and
none named, the answer is `ambiguous` when one package lists the rulebase. A
rulebase that no single package lists cannot be qualified for any gateway, and
this answer comes before `ambiguous`. With no gateway the install-on column
cannot be bound and no flow is settled.

The collector links a package to the ordered layers that it lists. An inline
layer has no package. A rule of an inline layer is answered with the gap
`CHECKPOINT_INLINE_LAYER` and the rules that call the layer. Those rules are
explained in the policy of their own package.

Each set is rendered as flow rectangles of first fragments (fragment offset
0), a page at a time. The definite rectangles come first, and the rectangles
that possibly match follow. Each rectangle has the scope it applies in.
`summary` states the result in one sentence. A failure that the caller can act
on is returned as an `error` document. The child passes no exception text to
its parent.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any, Literal

from hst.assessment.rule_scope import OTHER_INTERFACE, STATES, describe, scope_space
from hst.policy.graph import LOCAL_INTERFACE

MAX_RECTANGLES = 1000

# `_LEGACY_FIELDS` are the header fields of a rectangle. `_KNOWN_FIELDS` are the
# fields that the compiler knows. A port predicate also constrains the fragment
# offset. The fragment offset is fixed to the first fragment before rendering.
_LEGACY_FIELDS = ("source_address", "destination_address", "protocol", "destination_port", "source_port")
_KNOWN_FIELDS = frozenset((*_LEGACY_FIELDS, "fragment_offset"))


def _error(
    code: str, message: str, field: str | None = None, candidates: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "field": field, "candidates": candidates or []}}


def execute_explain(settings: Any, inputs: dict, *, cancelled: Callable[[], bool] | None = None) -> dict:
    """Load the pinned graph in the child and explain one rule.

    The load starts with the per-device objects of the named firewall and
    widens to the devices that the explanation reads (`load_scoped`). The
    explanation runs while the session is open, and the scoped graph looks
    nodes up through it."""
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
    firewall = inputs.get("firewall")
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
            return explain(
                graph,
                str(reference["estate"]),
                str(inputs["rulebase"]),
                str(inputs["rule"]),
                None if inputs.get("address_family") is None else int(inputs["address_family"]),  # type: ignore[arg-type]
                firewall=firewall,
                offset=int(inputs["offset"]),
                limit=int(inputs["limit"]),
            )

        try:
            return load_scoped(load, use, frozenset({str(firewall)} if firewall else ()))
        except GraphTooLarge as exc:
            return _error("limit_exceeded", str(exc))
        except ReadError as exc:
            return _error("engine_unavailable", f"the pinned graph could not be loaded: {exc}")


def rulebase_family(node: Any) -> int | None:
    """The address family that a rulebase judges, as the firewall gate of the
    tracer reads it (`path.gates.firewall._rb_af`). It is the `af` that the
    collector wrote, else 6 for a uid of the form `fw:ipv6:<name>`, else None.
    A rulebase with None judges both families."""
    af = node.props.get("af")
    if af in (4, 6, "4", "6"):
        return int(af)
    return 6 if ":ipv6" in str(node.uid) else None


def _raw(node: Any) -> str | None:
    from hst.analysis_model.checkpoint_graph import _envelope, _raw_uid

    try:
        return _raw_uid(_envelope(node))
    except (TypeError, ValueError):
        return None


def _gateways(graph: Any, rulebase_uid: str) -> list[str]:
    """The Device uids that enforce the rulebase. These are the gateway
    identities a Check Point install-on column is bound to."""
    return sorted(
        {
            relation.start
            for relation in graph.incoming.get((rulebase_uid, "ENFORCES"), ())
            if relation.start in graph.nodes and "Device" in graph.nodes[relation.start].labels
        }
    )


def _inline_callers(graph: Any, rulebase_uid: str) -> list[str]:
    """The uids of the Check Point rules of the rulebase's management domain
    that call it as an inline layer, in uid order."""
    from hst.analysis_model.checkpoint_graph import _envelope, _raw_uid

    raw = _raw(graph.nodes[rulebase_uid])
    if raw is None or not rulebase_uid.endswith(raw):
        return []
    prefix = rulebase_uid[: -len(raw)]
    callers = []
    for uid in sorted(graph.labels.get("FwRule", ())):
        if not uid.startswith(prefix):
            continue
        try:
            envelope = _envelope(graph.nodes[uid])
        except (TypeError, ValueError):
            continue
        if _raw_uid(envelope.get("inline-layer")) == raw:
            callers.append(uid)
    return callers


def rulebase_policy(
    graph: Any,
    estate: str,
    rulebase_uid: str,
    family: Literal[4, 6],
    gateway: str | None = None,
    *,
    ingress: str | None = None,
    egress: str | None = None,
    state: str = "new",
) -> tuple[Any, Any, bool]:
    """The configured policy of the rulebase, its execution context, and
    whether it is a Check Point policy. A Check Point policy names its layers
    and rules by their envelope uids. The firewall instance of the context is
    `gateway`, which binds a Check Point install-on column. Without `gateway`
    it is the rulebase uid, which binds nothing. The policy is None for a
    Check Point rulebase whose capture cannot be qualified. `ingress`, `egress`
    and `state` are the interfaces and the connection state that any other
    rulebase is normalized for (`rule_scope`)."""
    from hst.analysis_model.checkpoint_graph import checkpoint_bound, checkpoint_policy, checkpoint_scope
    from hst.policy.graph import GraphPolicyNormalizer
    from hst.policy.ir import Constant, ExecutionContext

    scope = checkpoint_scope(graph, rulebase_uid)
    authority, domain = scope if scope else ("configuration", "configuration")
    context = ExecutionContext(estate, authority, domain, gateway or rulebase_uid, "configuration", family)
    policy = checkpoint_policy(graph, (rulebase_uid,), context, Constant(True))
    if policy is not None:
        return policy, context, True
    if checkpoint_bound(graph, (rulebase_uid,)):
        return None, context, True
    normalized = GraphPolicyNormalizer(graph, context).policy(
        (rulebase_uid,), installation=Constant(True), ingress=ingress, egress=egress, state=state
    )
    return normalized, context, False


def _policy(
    graph: Any,
    estate: str,
    rulebase_uid: str,
    rule_uid: str,
    family: Literal[4, 6],
    gateway: str | None = None,
) -> Any:
    """The policy of the rulebase, its execution context, and the layer and
    rule uids the policy names them by (`rulebase_policy`)."""
    policy, context, checkpoint = rulebase_policy(graph, estate, rulebase_uid, family, gateway)
    if policy is None:
        return None, context, None, None
    if checkpoint:
        return policy, context, _raw(graph.nodes[rulebase_uid]), _raw(graph.nodes[rule_uid])
    return policy, context, rulebase_uid, rule_uid


def _entering(
    compiler: Any, compiled: Any, policy: Any, layer_uid: str, seen: frozenset[str]
) -> tuple[Any, Any]:
    """The packets that must and that may enter `layer_uid`."""
    from hst.policy.ir import Constant

    universe = compiler.universe
    empty = universe.subtract(universe)
    if layer_uid in policy.ordered_layers:
        index = policy.ordered_layers.index(layer_uid)
        if index == 0:
            return universe, universe
        prefix = compiler.compile(
            replace(policy, ordered_layers=policy.ordered_layers[:index], installation=Constant(True))
        )
        return prefix.bounds.lower, prefix.bounds.upper
    if layer_uid in seen or len(seen) >= 64:
        return empty, universe
    lower, upper = empty, empty
    for layer in policy.layers:
        for rule in layer.rules:
            if rule.called_layer != layer_uid or not rule.enabled:
                continue
            try:
                calling = compiled.explain_rule(layer.uid, rule.uid)
            except KeyError:
                continue
            entry_lower, entry_upper = _entering(compiler, compiled, policy, layer.uid, seen | {layer_uid})
            lower = lower.union(calling.bounds.lower.intersect(entry_lower))
            upper = upper.union(calling.bounds.upper.intersect(entry_upper))
    return lower, upper


@dataclass(frozen=True, slots=True)
class _Scoped:
    """The attribution of the rule in one scope. It holds the packets that must
    and the packets that may arrive at the rule and match it, the gaps that
    leave the difference open, and whether the predicate of the rule matches
    no packet."""

    lower: Any
    upper: Any
    gaps: dict[tuple[str, str], None]
    matches_nothing: bool


def _evaluate(compiler: Any, policy: Any, layer_uid: str, rule_uid: str) -> _Scoped:
    """The rule's attribution in `policy`. Raises KeyError when the policy
    does not evaluate the layer or the rule."""
    compiled = compiler.compile(policy)
    attribution = compiled.explain_rule(layer_uid, rule_uid)
    entry_lower, entry_upper = _entering(compiler, compiled, policy, layer_uid, frozenset())
    installed = compiler.predicates.compile(policy.installation)
    lower = attribution.bounds.lower.intersect(entry_lower).intersect(installed.bounds.lower)
    upper = attribution.bounds.upper.intersect(entry_upper)
    possible = upper.subtract(lower)
    gaps = {
        (gap.reason.code, gap.reason.subject): None
        for gap in compiled.gaps
        if not gap.packets.intersect(possible).is_empty()
    }
    if not possible.is_empty():
        gaps.update(((reason.code, reason.subject), None) for reason in installed.gaps)
    layer = next(item for item in policy.layers if item.uid == layer_uid)
    rule = next(item for item in layer.rules if item.uid == rule_uid)
    own = compiler.predicates.compile(rule.predicate) if rule.enabled else None
    return _Scoped(lower, upper, gaps, own is None or own.bounds.upper.is_empty())


def _first_fragments(manager: Any, packets: Any) -> Any:
    from hst.symbolic import header

    first = packets.intersect(header(manager, {"fragment_offset": 0}).as_predicate())
    return first.project(_LEGACY_FIELDS).intersect(manager.validity())


def rectangles(manager: Any, packets: Any) -> list[dict[str, Any]]:
    """Raises the error of `packet_set_to_flow_region` when `packets` does not fit
    `MAX_RECTANGLES` rectangles."""
    from hst.app.agent.traffic import _rect_body
    from hst.symbolic.legacy_adapter import LegacyAdapterLimits, packet_set_to_flow_region

    if packets.is_empty():
        return []
    projected = _first_fragments(manager, packets)
    if projected.is_empty():
        return []
    region = packet_set_to_flow_region(projected, limits=LegacyAdapterLimits(max_rectangles=MAX_RECTANGLES))
    return [_rect_body(rect) for rect in region.rects]


def listed(manager: Any, packets: Any) -> tuple[list[dict[str, Any]], int | None]:
    """`packets` as flow rectangles, with None. For a set that does not fit
    `MAX_RECTANGLES` rectangles, the result is the first `MAX_RECTANGLES`
    disjoint pieces of the set, with the count of its pieces. Each piece is an
    exact part of the set."""
    from hst.app.agent.traffic import _rect_body
    from hst.symbolic.legacy_adapter import LegacyLimitError, partial_flow_region

    try:
        return rectangles(manager, packets), None
    except LegacyLimitError:
        region, pieces = partial_flow_region(
            _first_fragments(manager, packets), max_rectangles=MAX_RECTANGLES
        )
        return [_rect_body(rect) for rect in region.rects], pieces


def explain(
    graph: Any,
    estate: str,
    rulebase_uid: str,
    rule_uid: str,
    family: Literal[4, 6] | None,
    *,
    firewall: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> dict[str, Any]:
    """One page of the rule's attribution over `graph`. `firewall` names the
    gateway Device a Check Point rulebase is explained for. A `family` of
    None is the family that the rulebase records, or 4 when it records none.
    A rulebase that records the other family is refused."""
    from hst.symbolic import HeaderSchema, SymbolicManager
    from hst.symbolic.legacy_adapter import LegacyAdapterError

    base = graph.nodes.get(rulebase_uid)
    if base is None or "FwRulebase" not in base.labels:
        return _error("not_found", f"no rulebase {rulebase_uid} in this snapshot", "rulebase")
    if not any(node.uid == rule_uid for node in graph.targets(rulebase_uid, "HAS_RULE")):
        return _error("not_found", f"no rule {rule_uid} in rulebase {rulebase_uid}", "rule")
    if base.props.get("kind") == "nat" or "FwRule" not in graph.nodes[rule_uid].labels:
        return _error(
            "invalid_argument",
            f"rulebase {rulebase_uid} is a NAT rulebase; explain_rule explains the rules of an "
            "access rulebase",
            "rulebase",
        )
    recorded = rulebase_family(base)
    if family is None:
        family = 6 if recorded == 6 else 4
    elif recorded is not None and recorded != family:
        return _error(
            "invalid_argument",
            f"rulebase {rulebase_uid} is an IPv{recorded} rulebase and judges no IPv{family} flow; "
            f"explain its rules with address_family {recorded}",
            "address_family",
        )
    checkpoint = base.props.get("vendor") == "checkpoint"
    gateway: str | None = None
    packaged = True
    if checkpoint:
        from hst.analysis_model.checkpoint_graph import checkpoint_scope

        # Without one package that lists the rulebase, the capture cannot be
        # qualified for any gateway. The answer `ambiguous` is then not returned.
        packaged = checkpoint_scope(graph, rulebase_uid) is not None
        gateways = _gateways(graph, rulebase_uid)
        candidates = [
            {"uid": uid, "hostname": graph.nodes[uid].props.get("hostname")} for uid in gateways[:10]
        ]
        if firewall is not None and firewall not in gateways:
            return _error(
                "not_found",
                f"{firewall} is not a gateway Device that enforces rulebase {rulebase_uid}",
                "firewall",
                candidates,
            )
        if firewall is None and len(gateways) > 1 and packaged:
            return _error(
                "ambiguous",
                f"{len(gateways)} gateways enforce rulebase {rulebase_uid} and the install-on column of "
                "its rules depends on the gateway; pass firewall, one uid from candidates",
                "firewall",
                candidates,
            )
        gateway = firewall or (gateways[0] if len(gateways) == 1 else None)
    policy, context, layer_uid, policy_rule_uid = _policy(
        graph, estate, rulebase_uid, rule_uid, family, gateway
    )
    document: dict[str, Any] = {
        "rulebase": rulebase_uid,
        "rule": rule_uid,
        "address_family": family,
        "vendor": "checkpoint" if checkpoint else None,
        "firewall": gateway,
        "qualified": policy is not None,
    }
    unsettled: dict[str, Any] = {
        "items": [],
        "definite_count": None,
        "possible_count": None,
        "next_offset": None,
    }
    if policy is None:
        callers = _inline_callers(graph, rulebase_uid) if checkpoint and not packaged else []
        label = _label(graph, rulebase_uid, rule_uid)
        if callers:
            return {
                **document,
                **unsettled,
                "action": "unknown",
                "inline_layer_callers": callers[:10],
                "gaps": [{"code": "CHECKPOINT_INLINE_LAYER", "subject": rulebase_uid}],
                "summary": f"{label} belongs to a Check Point inline layer that no package lists, so it is "
                "not settled; explain the rule that calls the layer.",
            }
        return {
            **document,
            **unsettled,
            "action": "unknown",
            "gaps": [{"code": "CHECKPOINT_CAPTURE_UNQUALIFIED", "subject": rulebase_uid}],
            "summary": "The Check Point capture of this rulebase cannot be qualified, so "
            f"{_lowered(graph, rulebase_uid, rule_uid)} is not settled.",
        }
    if layer_uid is None:
        return _error(
            "not_found",
            f"rulebase {rulebase_uid} has no Check Point envelope, so the policy of its package "
            "does not name it",
            "rulebase",
        )
    if policy_rule_uid is None:
        return _error(
            "not_found",
            f"rule {rule_uid} has no Check Point envelope, so the policy of its rulebase does not name it",
            "rule",
        )
    layer = next((item for item in policy.layers if item.uid == layer_uid), None)
    rule = next((item for item in layer.rules if item.uid == policy_rule_uid), None) if layer else None
    if rule is None:
        return _error("not_found", f"rule {rule_uid} is not part of the policy of its rulebase", "rule")
    if checkpoint and gateway is None:
        return {
            **document,
            **unsettled,
            "action": rule.action,
            "called_layer": rule.called_layer,
            "enabled": rule.enabled,
            "installation_unknown": True,
            "gaps": [{"code": "INSTALLATION_UNKNOWN", "subject": rulebase_uid}],
            "summary": "No gateway in this snapshot enforces this Check Point rulebase, so "
            f"{_lowered(graph, rulebase_uid, rule_uid)} is not settled.",
        }
    from hst.policy.compile import PolicyCompiler

    with SymbolicManager(HeaderSchema(family)) as manager:
        compiler = PolicyCompiler(manager, context, _KNOWN_FIELDS)
        space = None if checkpoint else scope_space(graph, rulebase_uid, rule_uid)
        evaluated: list[tuple[tuple[int, int, int], _Scoped]] = []
        try:
            if space is None:
                evaluated.append(((0, 0, 0), _evaluate(compiler, policy, layer_uid, policy_rule_uid)))
            else:
                for i, e, s in space.combinations:
                    scoped, _context, _checkpoint = rulebase_policy(
                        graph,
                        estate,
                        rulebase_uid,
                        family,
                        ingress=space.ingress[i].representative,
                        egress=space.egress[e].representative,
                        state=str(space.states[s].representative),
                    )
                    evaluated.append(((i, e, s), _evaluate(compiler, scoped, layer_uid, policy_rule_uid)))
        except KeyError:
            return _error(
                "not_found",
                f"rulebase {rulebase_uid} is not evaluated by the policy of its package",
                "rulebase",
            )
        # With entry gaps, the graph holds no zone or binding that hands flows to
        # the rulebase. The lower bound is then empty, and every match is possible only.
        entry_gaps = space.gaps if space is not None else ()
        groups: list[dict[str, Any]] = []
        for triple, result in evaluated:
            lower = result.lower.subtract(result.lower) if entry_gaps else result.lower
            if result.upper.is_empty():
                continue
            group = next(
                (g for g in groups if g["lower"].equivalent(lower) and g["upper"].equivalent(result.upper)),
                None,
            )
            if group is None:
                group = {"lower": lower, "upper": result.upper, "triples": [], "gaps": {}}
                groups.append(group)
            group["triples"].append(triple)
            group["gaps"].update(result.gaps)
            if entry_gaps:
                group["gaps"].update(dict.fromkeys(entry_gaps))
        gaps: dict[tuple[str, str], None] = {}
        for group in groups:
            if not group["upper"].subtract(group["lower"]).is_empty():
                gaps.update(group["gaps"])
        document.update(
            {
                "action": rule.action,
                "called_layer": rule.called_layer,
                "enabled": rule.enabled,
                "matches_nothing": all(result.matches_nothing for _triple, result in evaluated),
                "lower_empty": all(group["lower"].is_empty() for group in groups),
                "possible_empty": all(group["upper"].subtract(group["lower"]).is_empty() for group in groups),
                "gaps": [{"code": code, "subject": subject} for code, subject in list(gaps)[:200]],
            }
        )
        if space is not None:
            document["entry"] = space.entry
        try:
            listings = [
                (listed(manager, group["lower"]), listed(manager, group["upper"].subtract(group["lower"])))
                for group in groups
            ]
        except LegacyAdapterError as exc:
            return {
                **document,
                "render_error": str(exc),
                "summary": f"{_label(graph, rulebase_uid, rule_uid)} is evaluated, but the flows it "
                "matches are too fragmented to list as flow rectangles.",
                "items": [],
                "definite_count": None,
                "possible_count": None,
                "next_offset": None,
            }
    rendered = [(definite, maybe) for (definite, _d), (maybe, _m) in listings]
    scopes = []
    for group, ((definite, definite_pieces), (maybe, possible_pieces)) in zip(groups, listings, strict=True):
        scope: dict[str, Any] = {
            "applies_when": describe(space, group["triples"])
            if space is not None
            else [{"ingress": None, "egress": None, "states": None}],
            "definite_count": len(definite),
            "possible_count": len(maybe),
        }
        # For a region that is listed in part, the scope holds the count of its pieces.
        if definite_pieces is not None:
            scope["definite_pieces"] = definite_pieces
        if possible_pieces is not None:
            scope["possible_pieces"] = possible_pieces
        scopes.append(scope)
    if any("definite_pieces" in scope or "possible_pieces" in scope for scope in scopes):
        document["listed_in_part"] = True
    items = [
        {"match": "definite", "scope": index, **rect}
        for index, (definite, _maybe) in enumerate(rendered)
        for rect in definite
    ] + [
        {"match": "possible", "scope": index, **rect}
        for index, (_definite, maybe) in enumerate(rendered)
        for rect in maybe
    ]
    definite_count = sum(len(definite) for definite, _maybe in rendered)
    possible_count = sum(len(maybe) for _definite, maybe in rendered)
    document["scopes"] = scopes
    document["summary"] = summary(
        graph,
        rulebase_uid,
        rule_uid,
        document,
        [(scope, definite) for scope, (definite, _maybe) in zip(scopes, rendered, strict=True)],
        family,
    )
    end = offset + limit
    return {
        **document,
        "items": items[offset:end],
        "definite_count": definite_count,
        "possible_count": possible_count,
        "next_offset": end if end < len(items) else None,
    }


# --- the one-sentence summary ---------------------------------------------------------------

_VERBS = {
    "accept": "accepts",
    "permit": "permits",
    "allow": "allows",
    "drop": "drops",
    "deny": "denies",
    "reject": "rejects",
    "block": "blocks",
}
_PROTOCOLS = {1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp", 58: "icmpv6", 132: "sctp"}
_PORTED = {6, 17, 33, 132}


def _label(graph: Any, rulebase_uid: str, rule_uid: str) -> str:
    rule, base = graph.nodes[rule_uid].props, graph.nodes[rulebase_uid].props
    position, name = rule.get("position"), base.get("name")
    if type(position) is int and name:
        return f"Rule {position} of {name}"
    return f"Rule {rule_uid}"


def _lowered(graph: Any, rulebase_uid: str, rule_uid: str) -> str:
    label = _label(graph, rulebase_uid, rule_uid)
    return label[0].lower() + label[1:]


def _verb(graph: Any, rule_uid: str, action: str | None) -> str:
    raw = str(graph.nodes[rule_uid].props.get("action") or "").lower()
    if action == "call":
        return "passes to its inline layer"
    return (
        _VERBS.get(raw) or _VERBS.get(str(action or "")) or "applies an action the engine does not model to"
    )


def _join(values: list[str], word: str = "and") -> str:
    return values[0] if len(values) == 1 else ", ".join(values[:-1]) + f" {word} " + values[-1]


# A summary spells out an address list or a protocol list of at most `_SPELLED` entries.
_SPELLED = 4


def _addresses(values: list[str], side: str, family: int) -> str | None:
    if values == ["0.0.0.0/0" if family == 4 else "::/0"]:
        return f"any {side}"
    return _join(values) if len(values) <= _SPELLED else None


def _any_service(rects: list[dict[str, Any]]) -> bool:
    protocols: set[int] = set()
    for rect in rects:
        listed = set(rect["protocols"]) if rect["protocols"] is not None else set(range(256))
        if listed & _PORTED and (rect["destination_ports"] != "0-65535" or rect["source_ports"] != "0-65535"):
            return False
        protocols |= listed
    return protocols == set(range(256))


def _service(rects: list[dict[str, Any]]) -> str | None:
    if _any_service(rects):
        return "any protocol and port"
    parts = []
    for rect in rects:
        protocols = rect["protocols"]
        if protocols is None or len(protocols) > _SPELLED:
            return None
        name = "/".join(_PROTOCOLS.get(number, f"protocol {number}") for number in protocols)
        for side in ("destination", "source"):
            port = rect.get(f"{side}_ports")
            # A protocol without ports has the canonical port 0 of the validity mask.
            if port is None or port == "0-65535" or not set(protocols) & _PORTED:
                continue
            # The phrase is None when a port applies and one of the protocols has no ports.
            if not set(protocols) <= _PORTED:
                return None
            name += f" {side} port {port}"
        parts.append(name)
    return _join(parts, "or") if len(parts) <= 2 else None


def _flows(rects: list[dict[str, Any]], family: int) -> str | None:
    """The flows of `rects` as one phrase, when they share their addresses
    and the phrase stays short."""
    pairs = {(tuple(rect["sources"]), tuple(rect["destinations"])) for rect in rects}
    if len(pairs) != 1:
        return None
    sources, destinations = next(iter(pairs))
    source = _addresses(list(sources), "source", family)
    destination = _addresses(list(destinations), "destination", family)
    service = _service(rects)
    if source is None or destination is None or service is None:
        return None
    return f"from {source} to {destination} on {service}"


def _interfaces(names: list[str]) -> str:
    named = [name for name in names if name not in (LOCAL_INTERFACE, OTHER_INTERFACE)]
    if OTHER_INTERFACE in names:
        named.append("an interface the snapshot does not name")
    return _join(named, "or")


def _where(scope: dict[str, Any], entry: dict[str, Any]) -> str:
    """Where the flows of one scope enter and leave the device. A side that
    covers every name its rulebase receives is left out, or named by its zone."""
    parts = []
    zone = entry.get("kind") == "zone-pair"
    for key, verb, local, zone_key in (
        ("ingress", "enters", "the router itself sends", "from_zone"),
        ("egress", "leaves", "is addressed to the router itself", "to_zone"),
    ):
        names = scope.get(key)
        if not names:
            continue
        if names == [LOCAL_INTERFACE]:
            parts.append(local)
        elif names == entry.get(key):
            if zone:
                parts.append(f"{verb} through zone {entry.get(zone_key)} ({_interfaces(names)})")
        else:
            parts.append(f"{verb} through {_interfaces(names)}")
    return "that " + " and ".join(parts) if parts else ""


def _states(scope: dict[str, Any]) -> str:
    states = scope.get("states")
    if not states or list(states) == list(STATES):
        return ""
    return _join(list(states), "or") + " "


def summary(
    graph: Any,
    rulebase_uid: str,
    rule_uid: str,
    document: dict[str, Any],
    definite: list[tuple[dict[str, Any], list[dict[str, Any]]]],
    family: int,
) -> str:
    """One plain sentence on what the rule does to the flows its rulebase
    receives, for the assistant to repeat."""
    label = _label(graph, rulebase_uid, rule_uid)
    if document.get("enabled") is False:
        return f"{label} is disabled and matches no flow."
    verb = _verb(graph, rule_uid, document.get("action"))
    entry = document.get("entry") or {}
    codes = sorted({gap["code"] for gap in document.get("gaps") or ()})
    decided = sorted(
        str(item).partition("=")[0] for item in entry.get("state_policy") or () if "=" in str(item)
    )
    policy = (
        f"; the global state policy decides {_join(decided)} flows before the rulebase" if decided else ""
    )
    clauses = []
    for scope, rects in definite:
        if not rects:
            continue
        pieces = scope.get("definite_pieces")
        flows = None if pieces is not None else _flows(rects, family)
        for applies in scope["applies_when"]:
            where = _where(applies, entry)
            if flows:
                text = f"every {_states(applies)}flow {flows}"
            elif pieces is not None:
                text = (
                    f"every {_states(applies)}flow in a region of {pieces} disjoint rectangles, the first "
                    f"{len(rects)} listed as definite"
                )
            else:
                text = (
                    f"every {_states(applies)}flow in the "
                    + ("rectangle" if len(rects) == 1 else f"{len(rects)} rectangles")
                    + " listed as definite"
                )
            clauses.append(text + (f" {where}" if where else ""))
    if len(clauses) > 3:
        sentence = f"{label} {verb} the flows of {len(clauses)} interface and state scopes listed in scopes"
    elif clauses:
        sentence = f"{label} {verb} " + "; and ".join(clauses)
    elif document.get("possible_empty"):
        if document.get("matches_nothing"):
            return f"{label} matches no flow that its rulebase receives{policy}."
        lowered = _lowered(graph, rulebase_uid, rule_uid)
        return f"Earlier rules take every flow that {lowered} matches, so no flow arrives at it{policy}."
    else:
        return (
            f"{label} may match flows, but the snapshot does not settle which ({', '.join(codes)}); "
            "the possible matches are listed as possible_only."
        )
    if not document.get("possible_empty"):
        sentence += f"; more flows may match it where the snapshot is incomplete ({', '.join(codes)})"
    return sentence + policy + "."
