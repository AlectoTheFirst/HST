from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from typing import Literal, cast

from .ir import AllOf, AnyOf, Atom, Constant, ExecutionContext, Layer, Not, Policy, Rule, Unknown

_PROTOCOLS = {"icmp": 1, "tcp": 6, "udp": 17, "icmpv6": 58, "ipv6-icmp": 58}
_RULE_FIELDS = frozenset(
    {
        "uid",
        "position",
        "action",
        "enabled",
        "src_any",
        "dst_any",
        "src",
        "dst",
        "source",
        "destination",
        "src_wildcard",
        "dst_wildcard",
        "source_wildcard",
        "destination_wildcard",
        "proto",
        "protocol",
        "svc_any",
        "ports",
        "destination_ports",
        "src_port",
        "source_ports",
        "states",
        "established",
        "tcp_flags",
        "tcp_flags_mask",
        "dscp",
        "icmp_type",
        "icmp_code",
        "fragments",
        "evidence",
        "in_interface",
        "out_interface",
        "pipeline",
        "qualifier_reason",
        "svc_opaque_reason",
        "src_opaque_reason",
        "dst_opaque_reason",
        # The collected ACE fields outside the collector's allow-list. A
        # non-empty list is an unknown match term (`_rule`).
        "unmodeled_fields",
    }
)


@dataclass(frozen=True, slots=True)
class AclBinding:
    rulebase_uid: str
    interface: str | None
    direction: str | None
    pipeline: str | None
    applicability: Constant | Unknown


@dataclass(frozen=True, slots=True)
class RouterAclPolicy:
    policy: Policy
    bindings: tuple[AclBinding, ...]
    _entries: tuple[tuple[AclBinding, Layer, Constant | Unknown | AllOf], ...]
    _installation: Constant | Unknown | AllOf

    def policy_for_binding(
        self, interface: str, direction: str, pipeline: str, *, manifest_digest: str = ""
    ) -> Policy:
        """An absent or ambiguous binding is unknown."""
        selected = tuple(
            entry for entry in self._entries if _binding_may_apply(entry[0], interface, direction, pipeline)
        )
        if not selected:
            return _unknown_policy(self.policy, Unknown("ACL_BINDING_NOT_FOUND", interface), manifest_digest)
        # one access list selected through two of its bindings is still one layer
        layers = tuple({entry[1].uid: entry[1] for entry in selected}.values())
        guards = [
            self._installation,
            *(entry[2] for entry in selected),
        ]
        return Policy(
            f"{self.policy.uid}:{interface}:{direction}:{pipeline}",
            self.policy.revision,
            self.policy.context,
            layers,
            tuple(layer.uid for layer in layers),
            installation=_all(guards),
            manifest_digest=manifest_digest,
        )


def compile_cisco_interface_acl(record: Mapping[str, object]) -> RouterAclPolicy:
    """The ``rules`` of each rulebase are in device order."""
    uid = _required_text(record, "uid")
    revision = _required_text(record, "revision")
    context = _context(record.get("context"))
    raw_bases = record.get("rulebases")
    if not isinstance(raw_bases, Sequence) or isinstance(raw_bases, str) or not raw_bases:
        raise ValueError("rulebases must be a nonempty sequence of collected rulebase records")
    bindings: list[AclBinding] = []
    entries: list[tuple[AclBinding, Layer, Constant | Unknown | AllOf]] = []
    layers: list[Layer] = []
    unbound: list[Unknown] = []
    installation = _truth(record.get("installed"), "INSTALLATION_UNKNOWN", uid)
    for raw_base in raw_bases:
        if not isinstance(raw_base, Mapping):
            raise TypeError("each rulebase must be a mapping")
        base_uid = _required_text(raw_base, "uid")
        rules_raw = raw_base.get("rules")
        if not isinstance(rules_raw, Sequence) or isinstance(rules_raw, str):
            raise TypeError("rulebase rules must be a sequence")
        base_bindings = [_binding(base_uid, scope, rules_raw) for scope in _binding_scopes(raw_base)]
        bindings.extend(base_bindings)
        family = raw_base.get("af")
        family_term: Constant | Unknown
        if family == context.address_family:
            family_term = Constant(True)
        elif family in (4, 6):
            # A record from another family does not establish that this layer
            # governs this single-family evaluation. Its implicit deny cannot
            # become a cross-family deny.
            family_term = Unknown("ADDRESS_FAMILY_MISMATCH", base_uid)
        else:
            family_term = Unknown("ADDRESS_FAMILY_UNKNOWN", base_uid)
        compiled: list[Rule] = []
        for rule_index, raw_rule in enumerate(rules_raw):
            if not isinstance(raw_rule, Mapping):
                raise TypeError("each ACL rule must be a mapping")
            compiled.append(_rule(raw_rule, base_uid, rule_index, context.address_family))
        default: Literal["deny", "unknown"] = (
            "deny" if raw_base.get("default_action", "deny") == "deny" else "unknown"
        )
        if raw_base.get("default_action", "deny") != "deny":
            compiled.append(
                Rule(f"{base_uid}:default-evidence", Unknown("DEFAULT_ACTION_UNKNOWN", base_uid), "deny")
            )
        layer = Layer(base_uid, tuple(compiled), default)
        layers.append(layer)
        installed = _truth(raw_base.get("installed"), "INSTALLATION_UNKNOWN", base_uid)
        entries.extend(
            (binding, layer, _all((binding.applicability, installed, family_term)))
            for binding in base_bindings
        )
        if not base_bindings:
            # a list bound to no interface the record holds is selected by no binding
            unbound.append(Unknown("ACL_BINDING_NOT_FOUND", base_uid))
    inventory = Policy(
        uid,
        revision,
        context,
        tuple(layers),
        tuple(layer.uid for layer in layers),
        installation=(
            _all((installation, *(entry[2] for entry in entries), *unbound))
            if len({(entry[0].interface, entry[0].direction, entry[0].pipeline) for entry in entries}) <= 1
            else Unknown("ACL_BINDING_SELECTION_REQUIRED", uid)
        ),
    )
    return RouterAclPolicy(
        inventory,
        tuple(bindings),
        tuple(entries),
        installation,
    )


def _context(value: object) -> ExecutionContext:
    if not isinstance(value, Mapping):
        raise TypeError("context must be a mapping")
    family = value.get("address_family")
    if family not in (4, 6):
        raise ValueError("context address_family must be 4 or 6")
    return ExecutionContext(
        _required_text(value, "estate"),
        _required_text(value, "authority"),
        _required_text(value, "domain"),
        _required_text(value, "firewall_instance"),
        _required_text(value, "vrf"),
        family,
    )


def _binding_scopes(base: Mapping[str, object]) -> list[Mapping[str, object]]:
    """The bindings of one rulebase record, each as an interface/direction/pipeline mapping."""
    raw = base.get("bindings")
    if raw is None:
        return [base]
    if not isinstance(raw, Sequence) or isinstance(raw, str):
        raise TypeError("rulebase bindings must be a sequence")
    scopes: list[Mapping[str, object]] = []
    for item in raw:
        if not isinstance(item, Mapping):
            raise TypeError("each ACL binding must be a mapping")
        scopes.append({"pipeline": base.get("pipeline"), **item})
    return scopes


def _binding(uid: str, base: Mapping[str, object], rules: Sequence[object]) -> AclBinding:
    interface = _text_or_none(base.get("interface"))
    direction = _text_or_none(base.get("direction"))
    pipeline = _text_or_none(base.get("pipeline"))
    scoped = {
        pair
        for rule in rules
        if isinstance(rule, Mapping)
        for pair in (
            ("in", _text_or_none(rule.get("in_interface"))),
            ("out", _text_or_none(rule.get("out_interface"))),
        )
        if pair[1] is not None
    }
    inferred = next(iter(scoped)) if len(scoped) == 1 else None
    rule_pipelines = {
        _text_or_none(rule.get("pipeline"))
        for rule in rules
        if isinstance(rule, Mapping) and rule.get("pipeline")
    }
    conflicting = len(scoped) > 1 or (
        inferred is not None
        and (
            (interface is not None and interface != inferred[1])
            or (direction is not None and direction != inferred[0])
        )
    )
    conflicting = (
        conflicting
        or len(rule_pipelines) > 1
        or (pipeline is not None and bool(rule_pipelines) and pipeline not in rule_pipelines)
    )
    if (interface is None or direction is None) and len(scoped) == 1:
        direction, interface = next(iter(scoped))
    applicable: Constant | Unknown
    if conflicting:
        applicable = Unknown("ACL_BINDING_CONFLICT", uid)
    elif interface is not None and direction in {"in", "out"} and pipeline is not None:
        applicable = Constant(True)
    else:
        applicable = Unknown("ACL_BINDING_UNKNOWN", uid)
    return AclBinding(uid, interface, direction, pipeline, applicable)


def _binding_may_apply(binding: AclBinding, interface: str, direction: str, pipeline: str) -> bool:
    if isinstance(binding.applicability, Unknown) and binding.applicability.code == "ACL_BINDING_CONFLICT":
        return True
    return all(
        observed is None or observed == requested
        for observed, requested in (
            (binding.interface, interface),
            (binding.direction, direction),
            (binding.pipeline, pipeline),
        )
    )


def _rule(raw: Mapping[str, object], base_uid: str, index: int, family: int) -> Rule:
    uid = _text_or_none(raw.get("uid")) or f"{base_uid}:{index + 1}"
    unknown_fields = sorted(set(raw) - _RULE_FIELDS)
    try:
        terms: list[object] = [_truth(raw.get("enabled"), "RULE_ENABLED_UNKNOWN", uid)]
        terms.extend(_address(raw, "src", "source_address", uid, family))
        terms.extend(_address(raw, "dst", "destination_address", uid, family))
        terms.extend(_protocol(raw, uid))
        terms.extend(_ports(raw, "destination", uid))
        terms.extend(_ports(raw, "source", uid))
        terms.extend(_qualifiers(raw, uid))
    except _RuleUnsupported as error:
        return _opaque_rule(uid, index, error.code, error.evidence)
    if unknown_fields:
        return Rule(
            uid,
            AnyOf((Unknown("UNMODELED_ACL_FIELD", uid, tuple(unknown_fields)), _all(terms))),
            "unknown",
            evidence=("UNMODELED_ACL_FIELD", *unknown_fields),
            source_position=(index + 1,),
        )
    for key in ("qualifier_reason", "svc_opaque_reason", "src_opaque_reason", "dst_opaque_reason"):
        if raw.get(key):
            terms.append(Unknown("UNMODELED_ACL_QUALIFIER", f"{uid}:{key}", (str(raw[key]),)))
    unmodeled = raw.get("unmodeled_fields")
    if unmodeled:
        names = tuple(map(str, unmodeled)) if isinstance(unmodeled, (list, tuple)) else (str(unmodeled),)
        terms.append(Unknown("UNMODELED_ACL_FIELD", uid, names))
    action: Literal["permit", "deny", "unknown"] = str(raw.get("action", "unknown")).lower()  # type: ignore[assignment]
    if action not in {"permit", "deny"}:
        action = "unknown"
    evidence_raw = raw.get("evidence", ())
    evidence = (
        tuple(item for item in evidence_raw if isinstance(item, str))
        if isinstance(evidence_raw, Sequence) and not isinstance(evidence_raw, str)
        else ()
    )
    return Rule(
        uid,
        _all(terms),
        action,
        evidence=evidence,
        source_position=(cast(int, raw["position"]) if isinstance(raw.get("position"), int) else index + 1,),
    )


@dataclass(frozen=True, slots=True)
class _RuleUnsupported(Exception):
    code: str
    evidence: tuple[str, ...] = ()


def _opaque_rule(uid: str, index: int, code: str, evidence: tuple[str, ...]) -> Rule:
    return Rule(
        uid,
        Unknown(code, uid, evidence),
        "unknown",
        evidence=(code, *evidence),
        source_position=(index + 1,),
    )


def _address(raw: Mapping[str, object], short: str, field: str, uid: str, family: int) -> list[object]:
    if raw.get(f"{short}_any") is True:
        return []
    value = raw.get(short, raw.get("source" if short == "src" else "destination"))
    wildcard = raw.get(
        f"{short}_wildcard", raw.get("source_wildcard" if short == "src" else "destination_wildcard")
    )
    if not isinstance(value, str):
        raise _RuleUnsupported("ADDRESS_UNKNOWN", (short,))
    try:
        if wildcard is not None:
            address, wild = int(ip_address(value)), int(ip_address(str(wildcard)))
            if family != 4 or ip_address(value).version != 4 or ip_address(str(wildcard)).version != 4:
                raise ValueError("IPv4 wildcard family mismatch")
            return [Atom(field, "mask", address, ((1 << 32) - 1) ^ wild)]
        network = ip_network(value, strict=False)
        if network.version != family:
            raise ValueError("address family mismatch")
        bits = network.max_prefixlen
        mask = ((1 << bits) - 1) ^ ((1 << (bits - network.prefixlen)) - 1)
        return [Atom(field, "mask", int(network.network_address), mask)]
    except ValueError:
        raise _RuleUnsupported("ADDRESS_UNSUPPORTED", (short, value)) from None


def _protocol(raw: Mapping[str, object], uid: str) -> list[object]:
    value = raw.get("proto", raw.get("protocol"))
    if value in ("ip", "ipv4", "ipv6", "any"):
        return []
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 255:
        return [Atom("protocol", "eq", value)]
    if value in (None, ""):
        if raw.get("svc_any") is True:
            return []
        raise _RuleUnsupported("PROTOCOL_UNKNOWN")
    number = _PROTOCOLS.get(str(value).lower())
    if number is None:
        raise _RuleUnsupported("PROTOCOL_UNSUPPORTED", (str(value),))
    return [Atom("protocol", "eq", number)]


def _ports(raw: Mapping[str, object], side: str, uid: str) -> list[object]:
    key = "ports" if side == "destination" else "src_port"
    value = raw.get(key, raw.get(f"{side}_ports"))
    if value in (None, "", "any"):
        return []
    field = f"{side}_port"
    try:
        if isinstance(value, int) and not isinstance(value, bool):
            if not 0 <= value <= 65535:
                raise ValueError("port outside range")
            return [Atom(field, "eq", value)]
        text = str(value)
        if "-" in text:
            low, high = (int(part) for part in text.split("-", 1))
            if not 0 <= low <= high <= 65535:
                raise ValueError("port range outside bounds")
            return [Atom(field, "range", low, high)]
        number = int(text)
        if not 0 <= number <= 65535:
            raise ValueError("port outside range")
        return [Atom(field, "eq", number)]
    except (TypeError, ValueError):
        raise _RuleUnsupported("PORT_UNSUPPORTED", (side, str(value))) from None


def _qualifiers(raw: Mapping[str, object], uid: str) -> list[object]:
    result: list[object] = []
    states = raw.get("states")
    if raw.get("established") is True or states == ["established"]:
        result.extend(
            (
                Atom("protocol", "eq", 6),
                AnyOf((Atom("tcp_flags", "mask", 0x10, 0x10), Atom("tcp_flags", "mask", 0x04, 0x04))),
            )
        )
    elif states not in (None, [], ()):
        result.append(Unknown("STATE_UNSUPPORTED", uid, (str(states),)))
    if raw.get("tcp_flags") is not None:
        try:
            flags = _integer(raw["tcp_flags"])
            mask = _integer(raw.get("tcp_flags_mask", 0xFF))
            if not 0 <= flags <= 255 or not 0 <= mask <= 255:
                raise ValueError("TCP flags outside byte")
            result.extend((Atom("protocol", "eq", 6), Atom("tcp_flags", "mask", flags, mask)))
        except (TypeError, ValueError):
            raise _RuleUnsupported("TCP_FLAGS_UNSUPPORTED", (str(raw["tcp_flags"]),)) from None
    if raw.get("dscp") is not None:
        try:
            dscp = _integer(raw["dscp"])
            if not 0 <= dscp <= 63:
                raise ValueError("DSCP outside six bits")
            result.append(Atom("dscp", "eq", dscp))
        except (TypeError, ValueError):
            raise _RuleUnsupported("DSCP_UNSUPPORTED", (str(raw["dscp"]),)) from None
    if raw.get("icmp_type") is not None:
        try:
            result.append(Atom("icmp_type", "eq", _integer(raw["icmp_type"])))
        except (TypeError, ValueError):
            raise _RuleUnsupported("ICMP_TYPE_UNSUPPORTED") from None
    if raw.get("icmp_code") is not None:
        try:
            result.append(Atom("icmp_code", "eq", _integer(raw["icmp_code"])))
        except (TypeError, ValueError):
            raise _RuleUnsupported("ICMP_CODE_UNSUPPORTED") from None
    if raw.get("fragments") is True:
        result.append(Not(Atom("fragment_offset", "eq", 0)))
    elif raw.get("fragments") not in (None, False):
        result.append(Unknown("FRAGMENTS_UNSUPPORTED", uid))
    return result


def _truth(value: object, code: str, subject: str) -> Constant | Unknown:
    return Constant(value) if type(value) is bool else Unknown(code, subject)


def _integer(value: object) -> int:
    if isinstance(value, bool):
        raise ValueError("boolean is not an ACL number")
    return int(cast(str | bytes | bytearray | int, value))


def _unknown_policy(template: Policy, reason: Unknown, manifest_digest: str = "") -> Policy:
    layer = Layer(
        f"{template.uid}:unknown", (Rule(f"{template.uid}:unknown", Constant(True), "unknown"),), "unknown"
    )
    return Policy(
        f"{template.uid}:unknown",
        template.revision,
        template.context,
        (layer,),
        (layer.uid,),
        installation=reason,
        manifest_digest=manifest_digest,
    )


def _all(terms: Sequence[object]) -> Constant | Unknown | AllOf:
    useful = tuple(term for term in terms if term != Constant(True))
    if not useful:
        return Constant(True)
    if len(useful) == 1:
        return useful[0]  # type: ignore[return-value]
    return AllOf(useful)  # type: ignore[arg-type]


def _required_text(value: Mapping[str, object], key: str) -> str:
    result = _text_or_none(value.get(key))
    if result is None:
        raise ValueError(f"{key} must be a nonempty string")
    return result


def _text_or_none(value: object) -> str | None:
    return value if isinstance(value, str) and value and value.strip() == value else None
