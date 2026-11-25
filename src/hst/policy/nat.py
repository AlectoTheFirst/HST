"""Normalize graph NAT rules into ordered symbolic predicates and rewrites.

The rule builder of the hop tracer (`path.gates.nat._nat_stage_rules`) reads
each rule. Both engines use the same stage, the same match and the same
translation of a rule.

- A dNAT or sNAT rule matches both its original source and its original
  destination.
- A static rule (VyOS `nat static`, Cisco `static`, Check Point automatic
  static NAT) translates in both directions.
- A Check Point rule without a kind takes its stage from its method and its
  translated columns.
- A Cisco rule bound by interface role follows the collected role.

The tracer reads a rule as opaque for an original object without an address,
an approximate rulebase, a role that is not collected, metadata that is not
modeled or a translation that it cannot map. An opaque rule sends its packets
to an unknown terminal.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Literal

from hst.analysis_model.graph import GraphInventory, GraphNode
from hst.analysis_model.model import RangeRewriteSpec
from hst.policy.ir import AllOf, AnyOf, Atom, Constant, Predicate, Unknown

# The NatRule properties that the rule query of the tracer returns under the same name.
_ROW_PROPS = (
    "af",
    "auto_generated",
    "kind",
    "method",
    "translation",
    "translation_port",
    "direction",
    "orig_src_port",
    "orig_dst_port",
    "orig_port",
    "xlate_port",
    "protocol",
    "orig_service",
    "xlate_service",
    "service_unknown",
    "in_if",
    "out_if",
    "translation_interface",
    "match_acl",
    "match_route_map",
    "pool",
    "pool_start",
    "pool_end",
    "approximate_reason",
)


@dataclass(frozen=True, slots=True)
class NatRuleSpec:
    uid: str
    position: int
    stage: Literal["dnat", "snat"]
    predicate: Predicate
    rewrites: tuple[tuple[str, int], ...] = ()
    ranges: tuple[RangeRewriteSpec, ...] = ()
    exclude: bool = False
    gap_code: str | None = None
    # True for a masquerade. The device picks the source port, and no snapshot
    # holds it. The rewrite keeps the source port of the packet. The result
    # holds for every port if no state after the rule compares the source
    # port. The model builder checks this (`network._free_source_ports`).
    free_source_port: bool = False


def normalize_nat_rules(
    graph: GraphInventory,
    device_uid: str,
    *,
    ingress_interface_uid: str | None,
    egress_interface_uid: str | None,
    address_family: int,
) -> tuple[NatRuleSpec, ...]:
    rulebases = _bound_rulebases(graph, device_uid)
    roles = (_nat_role(graph, ingress_interface_uid), _nat_role(graph, egress_interface_uid))
    result = []
    for rulebase in rulebases:
        approximate = bool(rulebase.props.get("approximate"))
        # The management object uids of the gateways that bind this rulebase to
        # the device. The install-on column of a Check Point rule holds these uids.
        owners = {
            str(graph.nodes[relation.start].props.get("cp_raw_uid"))
            for relation in graph.incoming.get((rulebase.uid, "ENFORCES"), ())
            if relation.start in graph.nodes
            and relation.start in {device_uid, *(t.uid for t in graph.targets(device_uid, "MEMBER_OF"))}
            and graph.nodes[relation.start].props.get("cp_raw_uid")
        }
        for relation in graph.outgoing.get((rulebase.uid, "HAS_RULE"), ()):
            rule = graph.nodes.get(relation.end)
            if rule is None or "NatRule" not in rule.labels or rule.props.get("enabled", True) is False:
                continue
            row = _row(graph, rulebase, rule, approximate, owners)
            for stage in ("dnat", "snat"):
                spec = _rule(
                    graph,
                    device_uid,
                    row,
                    stage,
                    ingress=ingress_interface_uid,
                    egress=egress_interface_uid,
                    roles=roles,
                    af=address_family,
                )
                if spec is not None:
                    result.append(spec)
    return tuple(sorted(result, key=lambda item: (item.stage, item.position, item.uid)))


def _bound_rulebases(graph: GraphInventory, device_uid: str) -> tuple[GraphNode, ...]:
    owners = {device_uid}
    owners.update(target.uid for target in graph.targets(device_uid, "MEMBER_OF"))
    values = []
    for owner in owners:
        for relation in graph.outgoing.get((owner, "ENFORCES"), ()):
            node = graph.nodes.get(relation.end)
            if node and "FwRulebase" in node.labels and node.props.get("kind") == "nat":
                values.append(node)
    return tuple({node.uid: node for node in values}.values())


def _nat_role(graph: GraphInventory, interface_uid: str | None) -> str | None:
    """The collected Cisco `ip nat inside|outside` role of an interface, or
    None when it was never collected."""
    node = graph.nodes.get(interface_uid) if interface_uid else None
    role = node.props.get("nat_role") if node is not None else None
    return str(role) if role else None


def _target_addresses(graph: GraphInventory, node: GraphNode) -> list[str]:
    """The addresses of one ORIG_* or XLATE_* target, as the query of the
    tracer reads them (`_NAT_RULES_QUERY`).

    The addresses are the cidr, ip, cidr6 and ip6 of the target, the cidr or
    ip of each RESOLVES_TO target of a group or network object, and the
    ranges of an address range object."""
    values = [str(node.props[key]) for key in ("cidr", "ip", "cidr6", "ip6") if node.props.get(key)]
    for target in graph.targets(node.uid, "RESOLVES_TO"):
        address = target.props.get("cidr") or target.props.get("ip")
        if address:
            values.append(str(address))
    ranges = node.props.get("ranges")
    if isinstance(ranges, (list, tuple)):
        values.extend(str(value) for value in ranges if value)
    return values


def _row(
    graph: GraphInventory, rulebase: GraphNode, node: GraphNode, approximate: bool, owners: set[str]
) -> dict[str, Any]:
    """The NatRule as one row of the tracer's rule query (`_NAT_RULES_QUERY`)."""
    props = node.props
    row: dict[str, Any] = {key: props.get(key) for key in _ROW_PROPS}
    row.update(
        uid=node.uid,
        rb_uid=rulebase.uid,
        rb_name=rulebase.props.get("name"),
        pos=_position(props),
        approximate=approximate,
        enabled=True,
        exclude=bool(props.get("exclude", False)),
        static_flag=bool(props.get("static", False)),
        orig_src_raw=props.get("orig_src"),
        orig_dst_raw=props.get("orig_dst"),
        xlate_src_original=bool(props.get("xlate_src_original", False)),
        xlate_dst_original=bool(props.get("xlate_dst_original", False)),
        rule_approximate=bool(props.get("approximate", False)),
        overload=bool(props.get("overload", False)),
        owners=sorted(owners),
        install_on=list(props.get("install_on") or ()),
        install_on_unresolved=bool(props.get("install_on_unresolved", False)),
    )
    for column, relation in (
        ("orig_src", "ORIG_SRC"),
        ("orig_dst", "ORIG_DST"),
        ("xlate_src", "XLATE_SRC"),
        ("xlate_dst", "XLATE_DST"),
    ):
        targets = graph.targets(node.uid, relation)
        row[f"{column}_present"] = bool(targets)
        row[f"{column}_addrs"] = [
            address for target in targets for address in _target_addresses(graph, target)
        ]
        row[f"{column}_opaque"] = any(target.props.get("opaque") is True for target in targets)
    return row


def _rule(
    graph: GraphInventory,
    device_uid: str,
    row: dict[str, Any],
    stage: Literal["dnat", "snat"],
    *,
    ingress: str | None,
    egress: str | None,
    roles: tuple[str | None, str | None],
    af: int,
) -> NatRuleSpec | None:
    """The rule's spec in one stage, or None when the tracer leaves it out of
    that stage (a plain sNAT rule in the dNAT stage, a static rule with no
    public side, a Cisco rule whose collected role does not match)."""
    from hst.path.addrsets import _iface_name_matches
    from hst.path.gates.nat import (
        _nat_binding,
        _nat_installed,
        _nat_match_set,
        _nat_rule_kind,
        _nat_stage_rules,
    )

    # With `iface` None, `_nat_stage_rules` keeps the rule whatever its
    # interface binding. The code below checks the binding.
    resolved = _nat_stage_rules([row], stage, None, ingress_role=roles[0], egress_role=roles[1])
    if not resolved:
        return None
    rule = resolved[0]
    uid, position = str(row["uid"]), int(row["pos"])
    if rule.get("af") in (4, 6) and rule["af"] != af:
        # `rule["af"]` is the family as the tracer reads it (`_nat_rule_af`).
        # It is the collected af, or the one family of the addresses of the
        # rule. The rule matches no flow of the other family.
        return NatRuleSpec(uid, position, stage, Constant(False))
    # `_nat_binding` gives the binding as the tracer reads it. `any` binds no
    # interface. The source translation of a VyOS static rule is bound to its
    # inbound interface.
    interface = _nat_binding(row, _nat_rule_kind(row), stage)
    selected = ingress if stage == "dnat" else egress
    if interface and not selected:
        return NatRuleSpec(
            uid,
            position,
            stage,
            Unknown("NAT_INTERFACE_BINDING_UNKNOWN", uid),
            gap_code="NAT_INTERFACE_BINDING_UNKNOWN",
        )
    selected_node = graph.nodes.get(selected) if selected else None
    selected_name = selected_node.props.get("name") if selected_node is not None else None
    names = {selected, selected_name}
    # A VyOS binding can be a wildcard (`eth*`) or a negation (`!eth1`). Such
    # a binding is matched against the name of the interface.
    pattern = bool(interface) and (str(interface).startswith("!") or str(interface).endswith("*"))
    if interface and selected and pattern and selected_name is None:
        return NatRuleSpec(
            uid,
            position,
            stage,
            Unknown("NAT_INTERFACE_BINDING_UNKNOWN", uid),
            gap_code="NAT_INTERFACE_BINDING_UNKNOWN",
        )
    if (
        interface
        and selected
        and interface not in names
        and not (pattern and _iface_name_matches(str(interface), selected_name))
    ):
        return NatRuleSpec(uid, position, stage, Constant(False))

    def unknown(terms: list[Predicate], code: str) -> NatRuleSpec:
        return NatRuleSpec(uid, position, stage, AllOf((*terms, Unknown(code, uid))), gap_code=code)

    terms: list[Predicate] = [
        _address_predicate("source_address", rule["match_src"], af),
        _address_predicate("destination_address", rule["match_dst"], af),
    ]
    service = _service_predicate(rule)
    if service is None:
        return unknown(terms, "NAT_SERVICE_UNKNOWN")
    terms.extend(service)
    if stage == "snat" and rule.get("checkpoint_manual"):
        dnat = _nat_stage_rules([row], "dnat", None, ingress_role=roles[0], egress_role=roles[1])
        if dnat and not dnat[0].get("exclude"):
            # Check Point selects a manual rule once, on the original tuple
            # at ingress. At the sNAT stage the destination is already
            # translated. The rule that the ingress selected is not known at
            # this stage. The spec matches the translated destination and has
            # the gap NAT_RULE_SELECTION_UNKNOWN.
            return unknown(
                [terms[0], _address_predicate("destination_address", dnat[0].get("xlate") or [], af)],
                "NAT_RULE_SELECTION_UNKNOWN",
            )
    if rule.get("opaque_without_src_port", rule.get("opaque")) or rule.get("strict_opaque"):
        unresolved = any(
            row.get(f"{column}_present")
            and (
                row.get(f"{column}_opaque")
                or not _nat_match_set(row.get(f"{column}_raw"), row[f"{column}_addrs"])
            )
            for column in ("orig_src", "orig_dst")
        )
        if row.get("approximate"):
            code = "NAT_RULEBASE_APPROXIMATE"
        elif rule.get("service_unknown"):
            code = "NAT_SERVICE_UNKNOWN"
        elif row.get("rule_approximate"):
            code = "NAT_RULEBASE_APPROXIMATE"
        elif unresolved:
            code = "NAT_MATCH_OBJECT_UNRESOLVED"
        elif (placed := _nat_installed(row)) is not None and (
            placed.get("install_on") or placed.get("install_on_unresolved")
        ):
            # The install-on column holds a target that is not resolved to this gateway.
            code = "NAT_INSTALL_ON_UNKNOWN"
        elif rule.get("role_note"):
            code = "NAT_INTERFACE_ROLE_UNKNOWN"
        elif rule.get("strict_opaque"):
            code = "NAT_RULE_METADATA_UNMODELED"
        else:
            code = "NAT_POOL_ALLOCATION_UNKNOWN"
        return unknown(terms, code)
    predicate = AllOf(tuple(terms))
    if rule.get("exclude"):
        return NatRuleSpec(uid, position, stage, predicate, exclude=True)
    field = "destination_address" if rule["rewrite"] == "dst" else "source_address"
    matched = _intervals(rule["match_dst"] if rule["rewrite"] == "dst" else rule["match_src"], af)
    targets = _intervals(rule.get("xlate") or [], af)
    rewrites: list[tuple[str, int]] = []
    ranges: list[RangeRewriteSpec] = []
    if rule.get("masquerade") and stage == "snat" and _true_masquerade(row, rule):
        # The translated source is the one collected address of the family on
        # the egress interface (the tracer: `_snat` with
        # `_NAT_IFACE_ADDR_QUERY`). The device picks the port, and the spec
        # leaves the port free.
        if _filtered_after_translation(graph, device_uid, egress):
            # An outbound interface ACL runs after the translation (the IOS
            # order, `_apply_egress_acl` in the tracer). The model evaluates
            # the ACL before the source NAT, on the untranslated packet.
            return unknown(terms, "NAT_EGRESS_FILTER_AFTER_TRANSLATION")
        address = _egress_address(graph, egress, af)
        if address is None:
            return unknown(terms, "NAT_MASQUERADE_ADDRESS_UNKNOWN")
        return NatRuleSpec(
            uid, position, stage, predicate, (("source_address", address),), free_source_port=True
        )
    if rule.get("masquerade") or not targets:
        # A masquerade that reaches this branch has no resolved egress interface address.
        return unknown(terms, "NAT_POOL_ALLOCATION_UNKNOWN")
    if len(targets) == 1 and targets[0][0] == targets[0][1]:
        rewrites.append((field, targets[0][0]))
    elif (
        # A range or a pool gives a connection any one of its addresses
        # (`_translation_pool`). The offset mapping does not apply to it.
        not rule.get("xlate_pool")
        and len(matched) == 1
        and len(targets) == 1
        and matched[0][1] - matched[0][0] == targets[0][1] - targets[0][0]
    ):
        # A network maps onto a network of the same size, address by offset.
        ranges.append(RangeRewriteSpec(field, matched[0][0], matched[0][1], targets[0][0]))
    else:
        return unknown(terms, "NAT_POOL_ALLOCATION_UNKNOWN")
    port = _port_translation(rule)
    if port is None:
        return unknown(terms, "NAT_POOL_ALLOCATION_UNKNOWN")
    rewrites.extend(item for item in port if isinstance(item, tuple))
    ranges.extend(item for item in port if isinstance(item, RangeRewriteSpec))
    return NatRuleSpec(uid, position, stage, predicate, tuple(rewrites), tuple(ranges))


def _true_masquerade(row: dict[str, Any], rule: dict[str, Any]) -> bool:
    """Whether the rule is a plain masquerade or interface overload.

    Such a rule is a dynamic source NAT to the address of the egress
    interface. It has no port mapping, and neither the rule nor its rulebase
    is approximate."""
    from hst.path.gates.nat import _nat_rule_kind

    return not (
        _nat_rule_kind(row) == "static"
        or row.get("translation_port")
        or row.get("xlate_port")
        or rule.get("xlate_src_port_spec")
        or rule.get("xlate_port")
        or row.get("approximate")
        or row.get("rule_approximate")
    )


def _filtered_after_translation(graph: GraphInventory, device_uid: str, egress: str | None) -> bool:
    """Whether a filter that the device evaluates after source NAT can judge
    the packets that leave by `egress`.

    Such a filter is an interface ACL bound outbound to `egress` (the
    tracer's `_apply_egress_acl`, for every vendor), or an outbound binding
    of an interface ACL of the device that the collector could not tie to an
    interface. A VyOS or UniFi zone filter runs before source NAT, and the
    model places it there."""
    for relation in graph.outgoing.get((egress, "PROTECTED_BY"), ()) if egress else ():
        base = graph.nodes.get(relation.end)
        if (
            base is not None
            and base.props.get("match_context") == "interface-acl"
            and relation.props.get("direction") in ("out", None)
        ):
            return True
    owners = {device_uid, *(target.uid for target in graph.targets(device_uid, "MEMBER_OF"))}
    for owner in owners:
        for relation in graph.outgoing.get((owner, "ENFORCES"), ()):
            base = graph.nodes.get(relation.end)
            if base is None or base.props.get("match_context") != "interface-acl":
                continue
            unreported = base.props.get("unreported_bindings")
            if any(
                str(entry).endswith(" out")
                for entry in (unreported if isinstance(unreported, (list, tuple)) else ())
            ):
                return True
    return False


def _egress_address(graph: GraphInventory, egress: str | None, af: int) -> int | None:
    """The one address of family `af` on the egress interface.

    The tracer reads the address of a masquerade the same way
    (`_NAT_IFACE_ADDR_QUERY`). The result is None if the interface is not
    known, if a HAS_IP address does not parse, or if the count of distinct
    HAS_IP addresses of the family is not 1."""
    if not egress:
        return None
    found: set[int] = set()
    for node in graph.targets(egress, "HAS_IP"):
        text = node.props.get("ip")
        if not text:
            continue
        try:
            address = ipaddress.ip_address(str(text).split("/")[0])
        except ValueError:
            return None
        if address.version == af:
            found.add(int(address))
    return next(iter(found)) if len(found) == 1 else None


def _intervals(values: list[tuple[int, int, int]], af: int) -> list[tuple[int, int]]:
    return [(low, high) for family, low, high in values if family == af]


def _address_predicate(field: str, values: list[tuple[int, int, int]], af: int) -> Predicate:
    """A rule column as a predicate. An empty column matches any address. A
    column that only has addresses of the other family matches no address."""
    if not values:
        return Constant(True)
    return AnyOf(tuple(Atom(field, "range", low, high) for low, high in _intervals(values, af)))


def _service_predicate(rule: dict[str, Any]) -> list[Predicate] | None:
    """The terms for the protocol, the destination port and the source port
    that a rule matches. None if a spec of the rule does not parse."""
    from hst.path.addrsets import _ALL_PROTOS, _ports, _protoset
    from hst.path.gates.nat import _nat_proto_member

    terms: list[Predicate] = []
    try:
        spec = _nat_proto_member(rule.get("protos") or [])
        protocols = _protoset([spec]) if spec is not None else None
        if protocols is not None and protocols != _ALL_PROTOS:
            terms.append(AnyOf(tuple(Atom("protocol", "eq", value) for value in sorted(protocols))))
        # The tracer does not decide a source port match. The symbolic packet has a source port.
        source = rule.get("src_port_spec") or (
            rule.get("orig_src_port") if rule.get("src_port_scoped") else None
        )
        for field, raw in (("destination_port", rule.get("port_spec")), ("source_port", source)):
            ports = _ports(raw)
            if ports:
                terms.append(AnyOf(tuple(Atom(field, "range", low, high) for _family, low, high in ports)))
    except ValueError:
        return None
    return terms


def _port_translation(rule: dict[str, Any]) -> list[tuple[str, int] | RangeRewriteSpec] | None:
    """The port rewrites of a rule, as `_translate_port` maps them.

    A dNAT rule rewrites the destination port. An sNAT rule rewrites the
    source port (a static port mapping outbound, an sNAT translation port).
    Each rewrite is one translated port, or one translated range of the same
    size as the one matched range. None if a spec does not parse, or if a
    translated range does not have the size of one matched range."""
    from hst.path.addrsets import _ports

    result: list[tuple[str, int] | RangeRewriteSpec] = []
    for field, spec, target in (
        ("destination_port", rule.get("port_spec"), rule.get("xlate_port_spec") or rule.get("xlate_port")),
        ("source_port", rule.get("src_port_spec"), rule.get("xlate_src_port_spec")),
    ):
        if target in (None, ""):
            continue
        try:
            matched, translated = _ports(spec), _ports(target)
        except ValueError:
            return None
        if len(translated) == 1 and translated[0][1] == translated[0][2]:
            result.append((field, translated[0][1]))
            continue
        if len(matched) == 1 and len(translated) == 1:
            (_, low, high), (_, target_low, target_high) = matched[0], translated[0]
            if high - low == target_high - target_low:
                result.append(RangeRewriteSpec(field, low, high, target_low))
                continue
        return None
    return result


def _position(props: Any) -> int:
    value = props.get("position", 0)
    return value if type(value) is int else 0
