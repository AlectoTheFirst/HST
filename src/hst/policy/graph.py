"""Builds the policy IR from the graph tables. A shared object stays one definition that rules reference."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from ipaddress import ip_address, ip_network
from typing import Any, Literal

from hst.analysis_model.graph import GraphInventory, GraphNode
from hst.path.addrsets import _iface_name_matches, _ports, _protoset

from .ir import (
    Action,
    AllOf,
    AnyOf,
    Atom,
    Constant,
    ExecutionContext,
    Layer,
    Not,
    ObjectDefinition,
    ObjectKey,
    Policy,
    Predicate,
    Ref,
    Rule,
    Unknown,
)

# The interface value for the side of a flow that is the router itself. That
# side is the egress of a flow addressed to the router (a VyOS `local-zone`,
# the `input` chain) or the ingress of a flow that the router sends. No
# interface scope matches it, with or without a negation. The gate treats an
# unresolved interface the same way (`hst.path.addrsets._iface_name_matches`).
# No interface name has parentheses.
LOCAL_INTERFACE = "(local)"

# A bound uid `<zone uid>#intra` is the layer of the intra-zone filtering of
# the zone. The layer applies to a flow between 2 interfaces of one zone that
# no (Z, Z) ruleset of the address family receives
# (`analysis_model.network._bindings`).
INTRA_ZONE = "#intra"
# A bound uid with this prefix and the device uid has no node. The zone by
# which a packet enters the zoned device is not known. The layer of this uid
# is unknown.
ZONE_INGRESS_UNKNOWN = "zone-ingress-unknown:"

# Rule properties that have no match semantics.
# `rule_uid` and `rulebase_uid` are the vendor identities of the rule and of
# its rulebase.
# `checkpoint_envelope` is the payload that the Check Point normalizer reads,
# and `checkpoint_envelope_sha` is its digest. collectors/checkpoint.py keeps
# the payload in the side store.
# `states_opaque_reason` is the reason for an opaque state column
# (`states_opaque`).
# `unmodeled_fields` lists the vendor fields that a normalizer does not model.
# `_rule` adds an unknown term for a non-empty list.
# The loader writes `collected_at` and `carried` on every node of a published
# snapshot (core/loader.py).
_RULE_METADATA = frozenset(
    {
        "rule_uid",
        "rulebase_uid",
        "checkpoint_envelope",
        "checkpoint_envelope_sha",
        "states_opaque_reason",
        "unmodeled_fields",
        "collected_at",
        "carried",
    }
)

# Vendors whose collector writes no SVC edge and no `svc_any` for a rule that
# has no protocol, port or port group. VyOS writes a service object only for a
# rule that states one (collectors/vyos.py `add_ruleset`). A VyOS rule without
# a service object matches every protocol and port.
_SERVICE_ABSENT_IS_ANY = frozenset({"vyos"})

# Maps the `default-action` of a zone to the default of a layer.
_ZONE_DEFAULTS: dict[str, Literal["permit", "deny", "unknown"]] = {
    "accept": "permit",
    "permit": "permit",
    "deny": "deny",
    "drop": "deny",
    "reject": "deny",
}


def _intra_zone_default(props: Mapping[str, Any]) -> Literal["permit", "deny", "unknown"]:
    """The verdict of a zone on traffic between 2 of its interfaces.

    A recorded `intra_zone_action` gives the verdict. A zone without
    intra-zone filtering permits the traffic (the documented VyOS default). A
    zone that filters the traffic by a ruleset that the address family does
    not bind gives unknown. The tracer reads the zone the same way
    (`gates.firewall._intra_zone_verdict`)."""
    action = props.get("intra_zone_action")
    if action:
        return _ZONE_DEFAULTS.get(str(action).lower(), "unknown")
    return "unknown" if props.get("intra_zone_filtering") else "permit"


def interface_scope_matches(scope: str, observed: str) -> bool:
    """Whether a rule's interface scope (a name, a trailing-'*' wildcard, a
    leading-'!' negation or both) covers the interface a flow uses."""
    return False if observed == LOCAL_INTERFACE else _iface_name_matches(scope, observed)


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    return value


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(_plain(value), sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def _state_rules_default(
    default: Literal["permit", "deny", "return", "unknown"], props: Mapping[str, Any], state: str
) -> Literal["permit", "deny", "return", "unknown"]:
    """The default of a layer for a packet of `state`.

    UniFi does not report the predefined connection-state rules of a rulebase
    or a zone (`established_default_unknown`). Those rules can admit a reply
    before the default applies. For an established or related packet on such a
    layer, a default other than permit becomes unknown. The tracer reads the
    default the same way (`gates.firewall._fallthrough`)."""
    if (
        state in ("established", "related")
        and props.get("established_default_unknown")
        and default != "permit"
    ):
        return "unknown"
    return default


class GraphPolicyNormalizer:
    """Builds the policy of one execution context from the graph. Rules reference a shared object by key."""

    def __init__(self, graph: GraphInventory, context: ExecutionContext):
        self.graph, self.context = graph, context
        self.objects: dict[ObjectKey, ObjectDefinition] = {}
        self.pending: list[tuple[str, str]] = []

    def _key(self, uid: str, dimension: str) -> ObjectKey:
        return ObjectKey(self.context.authority, self.context.domain, _digest((uid, dimension)))

    def reference(self, uid: str, dimension: str) -> Predicate:
        key = self._key(uid, dimension)
        if key not in self.objects:
            self.objects[key] = ObjectDefinition(key, "pending", Unknown("GRAPH_OBJECT_PENDING", uid))
            self.pending.append((uid, dimension))
        return Ref(key)

    def _address(self, value: Any, field: str, subject: str) -> Predicate:
        if not isinstance(value, str) or not value:
            return Unknown("GRAPH_ADDRESS_MISSING", subject)
        try:
            if "-" in value:
                left, right = (ip_address(part.strip()) for part in value.split("-", 1))
                if left.version != right.version or int(left) > int(right):
                    raise ValueError("invalid address range")
                return (
                    Atom(field, "range", int(left), int(right))
                    if left.version == self.context.address_family
                    else Constant(False)
                )
            network = ip_network(value, strict=False)
            if network.version != self.context.address_family:
                return Constant(False)
            return Atom(field, "mask", int(network.network_address), int(network.netmask))
        except ValueError:
            return Unknown("GRAPH_ADDRESS_UNPARSED", subject)

    def _service(self, props: Mapping[str, Any], uid: str) -> Predicate:
        terms: list[Predicate] = []
        proto, ports, sport = props.get("proto"), props.get("ports"), props.get("src_port")
        if proto is not None and proto != "":
            try:
                protocols = _protoset([str(proto)])
                if protocols is None:
                    raise ValueError("protocol is not explicit")
                terms.append(AnyOf(tuple(Atom("protocol", "eq", number) for number in sorted(protocols))))
            except ValueError:
                terms.append(Unknown("GRAPH_SERVICE_PROTOCOL_UNKNOWN", uid))
        for value, field in ((ports, "destination_port"), (sport, "source_port")):
            if value is None or value == "":
                continue
            try:
                intervals = _ports(value)
                if not intervals:
                    raise ValueError("empty service port expression")
                terms.append(AnyOf(tuple(Atom(field, "range", lo, hi) for _af, lo, hi in intervals)))
            except (ValueError, TypeError):
                terms.append(Unknown("GRAPH_SERVICE_PORT_UNKNOWN", uid))
        return AllOf(tuple(terms)) if terms else Unknown("GRAPH_SERVICE_MEMBERSHIP_MISSING", uid)

    def _object(self, uid: str, dimension: str) -> Predicate:
        node = self.graph.nodes.get(uid)
        if node is None:
            return Unknown("GRAPH_OBJECT_MISSING", uid)
        props = node.props
        members = self.graph.sources(uid, "MEMBER_OF")
        terms: list[Predicate] = [self.reference(member.uid, dimension) for member in members]
        if dimension == "service":
            if (
                props.get("proto") not in (None, "")
                or props.get("ports") not in (None, "")
                or props.get("src_port") not in (None, "")
            ):
                terms.append(self._service(props, uid))
        else:
            for key in ("cidr", "ip"):
                if key in props:
                    terms.append(self._address(props[key], dimension, uid))
            ranges = props.get("ranges")
            if isinstance(ranges, (tuple, list)):
                terms.extend(self._address(value, dimension, uid) for value in ranges)
            elif ranges is not None:
                terms.append(Unknown("GRAPH_OBJECT_RANGE_SHAPE", uid))
            terms.extend(
                self.reference(target.uid, dimension) for target in self.graph.targets(uid, "RESOLVES_TO")
            )
        if props.get("opaque") is True:
            terms.append(Unknown("GRAPH_OBJECT_OPAQUE", uid, (str(props.get("opaque_reason") or uid),)))
        elif "opaque" in props and type(props["opaque"]) is not bool:
            return Unknown("GRAPH_OBJECT_OPACITY_UNKNOWN", uid)
        return AnyOf(tuple(terms)) if terms else Unknown("GRAPH_OBJECT_MEMBERSHIP_MISSING", uid)

    def _column(
        self, node: GraphNode, kind: str, field: str, prefix: str, *, absent_is_any: bool = False
    ) -> Predicate:
        props = node.props
        all_values = props.get(prefix + "_any")
        targets = self.graph.targets(node.uid, kind)
        if all_values is True or (absent_is_any and all_values is None and not targets):
            value: Predicate = Constant(True)
        elif targets:
            value = AnyOf(tuple(self.reference(target.uid, field) for target in targets))
        else:
            value = Unknown("GRAPH_RULE_COLUMN_MISSING", node.uid + "/" + kind)
        negate = props.get(prefix + "_negate", False)
        if type(negate) is not bool:
            return Unknown("GRAPH_RULE_NEGATION_UNKNOWN", node.uid + "/" + kind)
        return Not(value) if negate else value

    def _binding_scope(
        self, base: GraphNode, rules: tuple[GraphNode, ...], *, ingress: str | None, egress: str | None
    ) -> Predicate | None:
        """An `unreported_bindings` entry is "<name> <direction>" for an interface the device did not
        report."""
        pairs: list[tuple[str | None, str]] = []
        for relation in self.graph.incoming.get((base.uid, "PROTECTED_BY"), ()):
            interface = self.graph.nodes.get(relation.start)
            direction = relation.props.get("direction")
            if interface is not None and "Interface" in interface.labels and direction in ("in", "out"):
                pairs.append((interface.props.get("name"), str(direction)))
        unreported = base.props.get("unreported_bindings")
        for entry in unreported if isinstance(unreported, (list, tuple)) else ():
            spelled, _sep, side = str(entry).rpartition(" ")
            if spelled and side in ("in", "out"):
                pairs.append((spelled, side))
        if not pairs and any(r.props.get("in_interface") or r.props.get("out_interface") for r in rules):
            return None
        terms: list[Predicate] = []
        for name, direction in pairs:
            observed = ingress if direction == "in" else egress
            terms.append(
                Constant(name == observed and observed != LOCAL_INTERFACE)
                if observed is not None
                else Unknown("GRAPH_RULE_INTERFACE_UNKNOWN", base.uid)
            )
        return AnyOf(tuple(terms)) if terms else Constant(False)

    def _rule(
        self,
        node: GraphNode,
        *,
        ingress: str | None,
        egress: str | None,
        state: str,
        scope: Predicate | None = None,
        service_absent_is_any: bool = False,
    ) -> Rule:
        props = node.props
        # A FwRule property outside `known` adds the unknown term GRAPH_RULE_UNSUPPORTED_FIELD.
        known = {
            "uid",
            "position",
            "action",
            "enabled",
            "default_action",
            "src_any",
            "dst_any",
            "svc_any",
            "src_negate",
            "dst_negate",
            "svc_negate",
            "in_interface",
            "out_interface",
            "in_interface_group",
            "out_interface_group",
            "in_interfaces",
            "out_interfaces",
            "states",
            "states_opaque",
            "qualifier_reason",
            "implied",
            "disabled",
            "comment",
            "name",
            "kind",
            "layer",
            "package",
            "domain",
            "authority",
            "revision",
            "collection_ts",
            "source",
            "raw_uid",
            *_RULE_METADATA,
        }
        # VyOS writes an empty `jump_target` on a rule that is not a jump. On a
        # jump, `jump_target` is the layer that the rule calls. A non-empty
        # `jump_target` on any other action is an unsupported field.
        verb = str(props.get("action", "")).lower()
        unsupported = sorted(
            str(field)
            for field in props
            if field not in known
            and not str(field).startswith("_")
            and not (field == "jump_target" and (not props[field] or verb == "jump"))
        )
        terms: list[Predicate] = [
            self._column(node, "SRC", "source_address", "src"),
            self._column(node, "DST", "destination_address", "dst"),
            self._column(node, "SVC", "service", "svc", absent_is_any=service_absent_is_any),
        ]
        if unsupported:
            terms.append(Unknown("GRAPH_RULE_UNSUPPORTED_FIELD", node.uid, tuple(unsupported)))
        # A vendor field that the collector did not model narrows the match.
        # The term for it is unknown. The gate reads it the same way.
        unmodeled = props.get("unmodeled_fields")
        if unmodeled:
            names = tuple(map(str, unmodeled)) if isinstance(unmodeled, (list, tuple)) else (str(unmodeled),)
            terms.append(Unknown("GRAPH_RULE_UNMODELED_FIELD", node.uid, names))
        if scope is not None:
            terms.append(scope)
        for field, observed in (("in_interface", ingress), ("out_interface", egress)):
            if props.get(field):
                terms.append(
                    Constant(interface_scope_matches(str(props[field]), observed))
                    if observed is not None
                    else Unknown("GRAPH_RULE_INTERFACE_UNKNOWN", node.uid)
                )
        for field, observed in (("in_interfaces", ingress), ("out_interfaces", egress)):
            if field in props:
                values = props[field]
                terms.append(
                    Constant(False)
                    if isinstance(values, (tuple, list)) and not values
                    else Constant(observed in values)
                    if observed is not None and isinstance(values, (tuple, list))
                    else Unknown("GRAPH_RULE_INTERFACE_UNKNOWN", node.uid)
                )
        for field in ("in_interface_group", "out_interface_group", "states_opaque", "qualifier_reason"):
            if props.get(field):
                terms.append(Unknown("GRAPH_RULE_QUALIFIER_UNKNOWN", node.uid + "/" + field))
        states = props.get("states", ())
        if isinstance(states, (tuple, list)):
            if states:
                terms.append(Constant(state in states))
        else:
            terms.append(Unknown("GRAPH_RULE_STATE_UNKNOWN", node.uid))
        enabled = props.get("enabled")
        if type(enabled) is not bool:
            enabled = True
            terms.append(Unknown("GRAPH_RULE_ENABLED_UNKNOWN", node.uid))
        target = props.get("jump_target")
        if verb == "jump" and target:
            # VyOS `action jump` evaluates the named ruleset for the flows that
            # the rule matches. The rule calls the layer of that ruleset. The
            # gate reads the rules of the target in the place of the rule
            # (gates/firewall.py `_expand_jumps`). The compiler takes a permit
            # or a deny of the called layer as the verdict. After a return it
            # continues with the next rule. A missing layer, a loop or a chain
            # that is too deep stays undecided.
            return Rule(
                node.uid,
                AllOf(tuple(terms)),
                "call",
                enabled=enabled,
                called_layer=str(target),
                evidence=(node.uid,),
            )
        # `return` ends a called ruleset for the flows that the rule matches. A
        # jump without a target has the action `unknown`.
        action: Action = {
            "accept": "permit",
            "permit": "permit",
            "drop": "deny",
            "deny": "deny",
            "reject": "deny",
            "return": "return",
        }.get(verb, "unknown")  # type: ignore[assignment]
        return Rule(node.uid, AllOf(tuple(terms)), action, enabled=enabled, evidence=(node.uid,))

    def _rulebase_layer(
        self, uid: str, base: GraphNode, *, ingress: str | None, egress: str | None, state: str
    ) -> Layer:
        """The layer of one FwRulebase, with its rules in position order and its
        default-action."""
        # A `continue` rule passes the flow to the next rule without a verdict.
        # The layer omits it. The gate omits it too (`_expand_jumps`).
        rules = tuple(
            rule
            for rule in self.graph.targets(uid, "HAS_RULE")
            if str(rule.props.get("action", "")).lower() != "continue"
        )
        positions = [rule.props.get("position") for rule in rules]
        invalid_order = any(type(position) is not int for position in positions) or len(
            set(positions)
        ) != len(positions)
        ordered = sorted(
            rules,
            key=lambda item: (
                item.props.get("position", 0) if type(item.props.get("position")) is int else 0,
                item.uid,
            ),
        )
        # The rules of an interface ACL hold no interface. The bindings of the ACL scope every rule.
        scope = (
            self._binding_scope(base, rules, ingress=ingress, egress=egress)
            if base.props.get("match_context") == "interface-acl"
            else None
        )
        service_absent_is_any = base.props.get("vendor") in _SERVICE_ABSENT_IS_ANY
        normalized = tuple(
            self._rule(
                rule,
                ingress=ingress,
                egress=egress,
                state=state,
                scope=scope,
                service_absent_is_any=service_absent_is_any,
            )
            for rule in ordered
        )
        if invalid_order:
            normalized = (Rule(uid + "/order-gap", Constant(True), "unknown"), *normalized)
        defaults: dict[str, Literal["permit", "deny", "return", "unknown"]] = {
            "accept": "permit",
            "permit": "permit",
            "deny": "deny",
            "drop": "deny",
            "reject": "deny",
            # After the `return` of a called ruleset, the evaluation continues after the jump rule.
            "return": "return",
        }
        verb = str(base.props.get("default_action", "")).lower()
        jump = base.props.get("default_jump_target")
        if verb == "jump" and jump:
            # `default-action jump` passes a flow that no rule matched to another
            # named ruleset. A return of that ruleset is a return of this layer.
            normalized = (
                *normalized,
                Rule(uid + "/default-jump", Constant(True), "call", called_layer=str(jump), evidence=(uid,)),
            )
            return Layer(uid, normalized, "return")
        default = defaults.get(verb, "unknown")
        return Layer(uid, normalized, _state_rules_default(default, base.props, state))

    def policy(
        self,
        rulebase_uids: tuple[str, ...],
        *,
        installation: Predicate,
        ingress: str | None = None,
        egress: str | None = None,
        state: str = "new",
    ) -> Policy:
        layers: list[Layer] = []
        for uid in rulebase_uids:
            base = self.graph.nodes.get(uid)
            zone = self.graph.nodes.get(uid.removesuffix(INTRA_ZONE)) if uid.endswith(INTRA_ZONE) else None
            if zone is not None and "Zone" in zone.labels:
                layers.append(Layer(uid, (), _intra_zone_default(zone.props)))
                continue
            if base is not None and "Zone" in base.labels:
                # The `default_action` of the zone is the layer default for a
                # flow between 2 zones that no ruleset of the address family
                # binds. A zone without a `default_action` gives unknown. The
                # path gate reads the zone the same way.
                zone_default = base.props.get("default_action")
                layers.append(
                    Layer(
                        uid,
                        (),
                        _state_rules_default(
                            _ZONE_DEFAULTS.get(str(zone_default).lower(), "unknown")
                            if zone_default
                            else "unknown",
                            base.props,
                            state,
                        ),
                    )
                )
                continue
            if base is None or "FwRulebase" not in base.labels:
                layers.append(Layer(uid, (), "unknown"))
                continue
            layers.append(self._rulebase_layer(uid, base, ingress=ingress, egress=egress, state=state))
        ordered = tuple(layer.uid for layer in layers)
        # A named ruleset that a rule calls (`_rule`) becomes a layer outside
        # `ordered`. The loop also follows the calls of each called layer.
        built = set(ordered)
        unread = list(layers)
        while unread:
            for rule in unread.pop().rules:
                called = rule.called_layer
                node = self.graph.nodes.get(called) if called else None
                if called is None or called in built or node is None or "FwRulebase" not in node.labels:
                    continue
                built.add(called)
                layer = self._rulebase_layer(called, node, ingress=ingress, egress=egress, state=state)
                layers.append(layer)
                unread.append(layer)
        while self.pending:
            uid, dimension = self.pending.pop()
            key = self._key(uid, dimension)
            node = self.graph.nodes.get(uid)
            self.objects[key] = ObjectDefinition(
                key, _digest(node.props if node else None), self._object(uid, dimension), evidence=(uid,)
            )
        if not layers:
            layers = [Layer("no-policy", (), "permit")]
            ordered = ("no-policy",)
        return Policy(
            _digest(rulebase_uids),
            self.graph.fingerprint,
            self.context,
            tuple(layers),
            ordered,
            tuple(self.objects.values()),
            installation=installation,
            manifest_digest=self.graph.manifest_digest,
        )
