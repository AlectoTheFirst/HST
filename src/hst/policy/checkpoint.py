"""Strict Check Point R81.20 filtering normalization into the shared policy IR.

The input is full captured package/layer/object JSON.
Capture, installed-policy evidence and implied-rule coverage are independent facts.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from typing import Any, Literal

from hst.collectors.checkpoint_policy import PolicyCapture

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
from .profiles import (
    CONTEXT_FIELDS,
    METADATA,
    OBJECT_FIELDS,
    OBJECT_STAGE_METADATA,
    RULE_FIELDS,
    CheckpointProfile,
    FieldAudit,
)


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


@dataclass(frozen=True, slots=True)
class NormalizedCheckpoint:
    policy: Policy
    profile: CheckpointProfile
    audit: tuple[FieldAudit, ...]
    source_digest: str


def _uid(value: Any) -> str | None:
    result = value.get("uid") if isinstance(value, Mapping) else value
    return result if isinstance(result, str) and result and result.strip() == result else None


class _Normalizer:
    def __init__(
        self,
        context: ExecutionContext,
        objects: Sequence[Mapping[str, Any]],
        target_bindings: Mapping[str, tuple[str, ...]],
    ):
        self.context = context
        for target_uid, targets in target_bindings.items():
            if (
                _uid(target_uid) is None
                or not isinstance(targets, tuple)
                or any(_uid(t) is None for t in targets)
            ):
                raise ValueError("install target bindings require canonical UIDs and explicit tuples")
        self.targets = target_bindings
        self.raw: dict[ObjectKey, Mapping[str, Any]] = {}
        self.by_uid: dict[str, list[ObjectKey]] = {}
        self.conflicts: set[ObjectKey] = set()
        self.definitions: dict[ObjectKey, ObjectDefinition] = {}
        self.pending: list[tuple[ObjectKey, str]] = []
        self.audit: list[FieldAudit] = []
        for obj in objects:
            uid, domain = _uid(obj), _uid(obj.get("domain"))
            if uid is None or domain is None:
                self.audit.append(
                    FieldAudit(
                        uid or "object",
                        "domain/uid",
                        "unsupported",
                        "authoritative object namespace is missing",
                    )
                )
                continue
            key = ObjectKey(context.authority, domain, uid)
            if key in self.raw:
                if _digest(self.raw[key]) != _digest(obj):
                    self.conflicts.add(key)
            else:
                self.raw[key] = obj
                self.by_uid.setdefault(uid, []).append(key)

    def gap(self, code: str, subject: str) -> Unknown:
        return Unknown(code, subject, (subject,))

    def fields(
        self,
        raw: Mapping[str, Any],
        subject: str,
        supported: frozenset[str],
        metadata: frozenset[str] = METADATA,
    ) -> bool:
        unclassified = False
        for field in raw:
            kind: Literal["supported", "metadata", "unsupported", "unclassified"]
            if field in supported:
                kind, reason = "supported", "handled by the selected filtering profile"
            elif field in metadata:
                kind, reason = "metadata", "does not change this initial filtering predicate"
            else:
                kind, reason = "unclassified", "field has no selected semantic interpretation"
                unclassified = True
            self.audit.append(FieldAudit(subject, field, kind, reason))
        return unclassified

    def resolve(self, value: Any) -> ObjectKey | None:
        uid = _uid(value)
        if uid is None:
            return None
        domain = _uid(value.get("domain")) if isinstance(value, Mapping) else None
        if isinstance(value, Mapping) and "domain" in value and domain is None:
            return None
        if domain is not None:
            key = ObjectKey(self.context.authority, domain, uid)
            return key if key in self.raw else None
        candidates = self.by_uid.get(uid, [])
        # A UID without a domain resolves only when exactly one object has it.
        return candidates[0] if len(candidates) == 1 else None

    def reference(self, value: Any, dimension: str) -> Predicate:
        key = self.resolve(value)
        if key is None:
            return self.gap("CP_OBJECT_MISSING_OR_AMBIGUOUS", _uid(value) or "object")
        derived = ObjectKey(
            key.authority, key.domain, json.dumps((key.uid, dimension), separators=(",", ":"))
        )
        if derived not in self.definitions:
            # The definition is reserved before its members are traversed. A
            # cycle resolves to a Ref to the reserved definition.
            self.definitions[derived] = ObjectDefinition(
                derived, _digest(self.raw[key]), self.gap("CP_OBJECT_PENDING", key.uid)
            )
            self.pending.append((key, dimension))
        return Ref(derived)

    def column(self, raw: Any, dimension: str, subject: str) -> Predicate:
        if not isinstance(raw, (list, tuple)) or not raw:
            return self.gap("CP_MATCH_COLUMN_MISSING", subject)
        return AnyOf(tuple(self.reference(item, dimension) for item in raw))

    def any_only(self, values: Any) -> bool:
        return (
            isinstance(values, (tuple, list))
            and bool(values)
            and all(
                (key := self.resolve(value)) is not None
                and key not in self.conflicts
                and self.raw[key].get("type") == "CpmiAnyObject"
                and not set(self.raw[key]) - METADATA
                for value in values
            )
        )

    def ports(self, value: Any, field: str, subject: str) -> Predicate:
        if not isinstance(value, str) or not value.strip():
            return self.gap("CP_SERVICE_PORT_MISSING", subject)
        terms: list[Predicate] = []
        for token in value.split(","):
            match = re.fullmatch(r"\s*(?:(<=|>=|<|>)\s*)?(\d+)(?:\s*-\s*(\d+))?\s*", token)
            if match is None:
                return self.gap("CP_SERVICE_PORT_UNSUPPORTED", subject)
            operator, left, right = match.groups()
            low, high = int(left), int(right or left)
            if low > high or high > 65535 or (operator and right):
                return self.gap("CP_SERVICE_PORT_INVALID", subject)
            if operator in (">", ">="):
                low, high = low + (operator == ">"), 65535
            elif operator in ("<", "<="):
                low, high = 0, low - (operator == "<")
            terms.append(Constant(False) if low > high else Atom(field, "range", low, high))
        return AnyOf(tuple(terms))

    def object_predicate(self, key: ObjectKey, dimension: str) -> Predicate:
        raw, subject = self.raw[key], key.uid
        kind = raw.get("type")
        if key in self.conflicts:
            return self.gap("CP_OBJECT_CONFLICT", subject)
        if not isinstance(kind, str) or kind not in OBJECT_FIELDS:
            self.fields(raw, subject, frozenset())
            return self.gap("CP_OBJECT_TYPE_UNSUPPORTED", subject)
        if self.fields(raw, subject, OBJECT_FIELDS[kind], METADATA | OBJECT_STAGE_METADATA):
            return self.gap("CP_OBJECT_FIELD_UNCLASSIFIED", subject)
        if kind == "CpmiAnyObject":
            return Constant(True)
        if kind in {"group", "service-group"}:
            if (kind == "service-group") != (dimension == "service"):
                return self.gap("CP_OBJECT_DIMENSION_MISMATCH", subject)
            members = raw.get("members")
            if not isinstance(members, (tuple, list)):
                return self.gap("CP_GROUP_MEMBERS_MISSING", subject)
            return AnyOf(tuple(self.reference(member, dimension) for member in members))
        if kind == "group-with-exclusion" and dimension != "service":
            return AllOf(
                (
                    self.reference(raw.get("include"), dimension),
                    Not(self.reference(raw.get("except"), dimension)),
                )
            )
        if dimension == "service":
            if kind in {"service-tcp", "service-udp"}:
                terms: list[Predicate] = [
                    Atom("protocol", "eq", 6 if kind == "service-tcp" else 17),
                    self.ports(raw.get("port"), "destination_port", subject),
                ]
                if raw.get("source-port") != "":
                    terms.append(self.ports(raw.get("source-port"), "source_port", subject))
                if (
                    raw.get("protocol") not in ("", "None")
                    or raw.get("match-by-protocol-signature") is not False
                ):
                    terms.append(self.gap("CP_SERVICE_PROTOCOL_INSPECTION", subject))
                return AllOf(tuple(terms))
            if kind in {"service-icmp", "service-icmp6"}:
                if (kind == "service-icmp") != (self.context.address_family == 4):
                    return Constant(False)
                terms = [Atom("protocol", "eq", 1 if kind == "service-icmp" else 58)]
                for raw_field, field in (("icmp-type", "icmp_type"), ("icmp-code", "icmp_code")):
                    value = raw.get(raw_field)
                    if value is None and raw.get("strata-unconstrained-icmp-fields") is True:
                        continue
                    terms.append(
                        Atom(field, "eq", value)
                        if type(value) is int and 0 <= value <= 255
                        else self.gap("CP_ICMP_FIELD_UNKNOWN", subject)
                    )
                return AllOf(tuple(terms))
            return self.gap("CP_OBJECT_DIMENSION_MISMATCH", subject)
        family = self.context.address_family
        try:
            if kind == "host":
                value = raw.get(f"ipv{family}-address")
                if value:
                    if not isinstance(value, str):
                        raise ValueError("address must be text")
                    address = ip_address(value)
                    if address.version != family:
                        raise ValueError("address family mismatch")
                    return Atom(dimension, "eq", int(address))
            elif kind == "network":
                value, length = raw.get(f"subnet{family}"), raw.get(f"mask-length{family}")
                if value is not None and type(length) is int:
                    network = ip_network(f"{value}/{length}", strict=True)
                    if network.version != family:
                        raise ValueError("network family mismatch")
                    if family == 4 and "subnet-mask" in raw and str(network.netmask) != raw["subnet-mask"]:
                        raise ValueError("subnet mask contradicts prefix length")
                    return Atom(dimension, "mask", int(network.network_address), int(network.netmask))
            elif kind == "address-range":
                low, high = raw.get(f"ipv{family}-address-first"), raw.get(f"ipv{family}-address-last")
                if low is not None and high is not None:
                    if not isinstance(low, str) or not isinstance(high, str):
                        raise ValueError("range endpoints must be text")
                    left, right = ip_address(low), ip_address(high)
                    if left.version != family or right.version != family:
                        raise ValueError("range family mismatch")
                    return Atom(dimension, "range", int(left), int(right))
            else:
                return self.gap("CP_OBJECT_DIMENSION_MISMATCH", subject)
        except (ValueError, TypeError):
            return self.gap("CP_ADDRESS_INVALID", subject)
        # Missing same-family companion fields are malformed.
        other = 6 if family == 4 else 4
        if not any(
            raw.get(name) is not None
            for name in (
                f"ipv{family}-address",
                f"subnet{family}",
                f"ipv{family}-address-first",
                f"ipv{family}-address-last",
            )
        ) and any(
            raw.get(name) for name in (f"ipv{other}-address", f"subnet{other}", f"ipv{other}-address-first")
        ):
            try:
                if kind == "host":
                    valid_other = ip_address(raw[f"ipv{other}-address"]).version == other
                elif kind == "network":
                    valid_other = (
                        ip_network(
                            f"{raw[f'subnet{other}']}/{raw[f'mask-length{other}']}", strict=True
                        ).version
                        == other
                    )
                else:
                    first = ip_address(raw[f"ipv{other}-address-first"])
                    last = ip_address(raw[f"ipv{other}-address-last"])
                    valid_other = first.version == last.version == other and int(first) <= int(last)
                if valid_other:
                    return Constant(False)
            except (KeyError, ValueError, TypeError):
                pass
        return self.gap("CP_ADDRESS_MISSING", subject)

    def install_on(self, values: Any, subject: str) -> Predicate:
        if not isinstance(values, (tuple, list)) or not values:
            return self.gap("CP_INSTALL_ON_UNKNOWN", subject)
        terms: list[Predicate] = []
        for value in values:
            uid = _uid(value)
            terms.append(
                Constant(self.context.firewall_instance in self.targets[uid])
                if uid is not None and uid in self.targets
                else self.gap("CP_INSTALL_TARGET_UNRESOLVED", uid or subject)
            )
        return AnyOf(tuple(terms))

    def action(self, value: Any) -> str | None:
        key = self.resolve(value)
        if key is None or key in self.conflicts:
            return None
        raw = self.raw[key]
        if raw.get("type") != "RulebaseAction" or self.fields(raw, key.uid, frozenset()):
            return None
        return str(raw.get("name", "")).lower()

    def rule(self, raw: Mapping[str, Any], position: tuple[int, ...]) -> Rule:
        uid = _uid(raw)
        if uid is None:
            raise ValueError("captured access rule has no authoritative UID")
        unclassified = self.fields(raw, uid, RULE_FIELDS | CONTEXT_FIELDS, METADATA | {"track"})
        terms: list[Predicate] = []
        for column, dimension in (
            ("source", "source_address"),
            ("destination", "destination_address"),
            ("service", "service"),
        ):
            predicate = self.column(raw.get(column), dimension, uid + "/" + column)
            negate = raw.get(column + "-negate")
            if type(negate) is not bool:
                predicate = self.gap("CP_NEGATION_UNKNOWN", uid + "/" + column)
            elif negate:
                predicate = Not(predicate)
            terms.append(predicate)
        terms.append(self.install_on(raw.get("install-on"), uid))
        for field in ("time", "vpn", "content"):
            if not self.any_only(raw.get(field)):
                terms.append(self.gap("CP_CONTEXT_PREDICATE_UNKNOWN", uid + "/" + field))
                self.audit.append(FieldAudit(uid, field, "unsupported", "constrained context is not modeled"))
        if raw.get("user-check") not in (None, {}, "") or raw.get("action-settings") not in (None, {}):
            terms.append(self.gap("CP_ACTION_SETTINGS_UNSUPPORTED", uid))
        action = self.action(raw.get("action"))
        called = _uid(raw.get("inline-layer"))
        normalized_action: Action
        if called is not None and action in {"apply layer", "inline layer"}:
            normalized_action = "call"
        elif called is not None:
            normalized_action, called = "unknown", None
        else:
            actions: dict[str, Action] = {"accept": "permit", "drop": "deny", "reject": "deny"}
            normalized_action = actions.get(action or "", "unknown")
        enabled = raw.get("enabled")
        if type(enabled) is not bool:
            enabled = True
            terms.append(self.gap("CP_RULE_ENABLED_UNKNOWN", uid))
        if "implied" in raw and type(raw["implied"]) is not bool:
            unclassified = True
        if unclassified:
            terms = [self.gap("CP_RULE_FIELD_UNCLASSIFIED", uid)]
            normalized_action, called = "unknown", None
        return Rule(
            uid,
            AllOf(tuple(terms)),
            normalized_action,
            enabled=enabled,
            called_layer=called,
            evidence=(uid,),
            source_position=position,
            implied=raw.get("implied") is True,
        )


def normalize_checkpoint_policy(
    *,
    profile: CheckpointProfile,
    context: ExecutionContext,
    manifest_digest: str,
    package: Mapping[str, Any],
    layers: Mapping[str, Mapping[str, Any]],
    rulebases: Mapping[str, Sequence[Mapping[str, Any]]],
    objects: Sequence[Mapping[str, Any]],
    installation: Predicate,
    target_bindings: Mapping[str, tuple[str, ...]],
    capture_complete: bool,
    implied_complete: bool,
) -> NormalizedCheckpoint:
    """Normalize a qualified full capture. The boolean arguments are explicit evidence claims.

    ``rulebases`` contains ordered rule/section items (pages already validated by
    acquisition). ``implied_complete`` asserts effective implied rules are included
    in their observed positions. Plain management access-rulebase pages do not
    establish that assertion. ``installation`` comes from authoritative gateway joins.
    """
    if type(capture_complete) is not bool or type(implied_complete) is not bool:
        raise TypeError("capture and implied-rule completeness must be explicit booleans")
    if not re.fullmatch(r"[0-9a-f]{64}", manifest_digest):
        raise ValueError("manifest must be a pinned SHA-256 digest")
    uid = _uid(package)
    if uid is None or _uid(package.get("domain")) != context.domain:
        raise ValueError("package must have an authoritative UID in the selected domain")
    normalizer = _Normalizer(context, objects, target_bindings)
    package_unknown = normalizer.fields(
        package,
        uid,
        frozenset({"access-layers", "installation-targets"}),
        METADATA | {"access", "threat-prevention", "nat-policy"},
    )
    order = package.get("access-layers")
    if not isinstance(order, (tuple, list)) or not order or any(_uid(item) is None for item in order):
        raise ValueError("package has no authoritative ordered access-layer list")
    ordered_uids = tuple(value for item in order if (value := _uid(item)) is not None)
    normalized: list[Layer] = []
    for layer_uid, metadata in layers.items():
        if _uid(metadata) != layer_uid:
            raise ValueError("layer UID disagrees with capture key")
        unsupported = normalizer.fields(
            metadata,
            layer_uid,
            frozenset({"implicit-cleanup-action"}),
            METADATA
            | {
                "firewall",
                "applications-and-url-filtering",
                "content-awareness",
                "mobile-access",
                "shared",
                "add-default-rule",
                "permissions-profiles",
            },
        )
        if _uid(metadata.get("domain")) != context.domain:
            # A shared layer of another domain is unsupported.
            unsupported = True
        rules: list[Rule] = []
        if layer_uid not in rulebases or unsupported:
            rules.append(Rule("capture-gap/" + layer_uid, Constant(True), "unknown", evidence=(layer_uid,)))
        pending: list[tuple[Mapping[str, Any], tuple[int, ...]]] = [
            (item, (index,)) for index, item in reversed(tuple(enumerate(rulebases.get(layer_uid, ()))))
        ]
        while pending:
            raw, position = pending.pop()
            if len(position) > 32:
                raise ValueError("rule section depth limit exceeded")
            if not isinstance(raw, Mapping):
                rules.append(Rule("item-gap/" + _digest(position), Constant(True), "unknown"))
            elif raw.get("type") == "access-section":
                section_unknown = normalizer.fields(
                    raw, _uid(raw) or layer_uid, frozenset({"rulebase", "from", "to"})
                )
                children = raw.get("rulebase")
                if section_unknown or not isinstance(children, (tuple, list)):
                    rules.append(Rule("section-gap/" + _digest(position), Constant(True), "unknown"))
                if isinstance(children, (tuple, list)):
                    pending.extend(
                        (item, (*position, index)) for index, item in reversed(tuple(enumerate(children)))
                    )
            elif raw.get("type") == "access-rule":
                rules.append(normalizer.rule(raw, position))
            else:
                rules.append(Rule("item-gap/" + _digest(position), Constant(True), "unknown"))
        defaults: dict[str, Literal["permit", "deny", "unknown"]] = {"accept": "permit", "drop": "deny"}
        default = defaults.get(str(metadata.get("implicit-cleanup-action", "")).lower(), "unknown")
        normalized.append(Layer(layer_uid, tuple(rules), default))
    while normalizer.pending:
        key, dimension = normalizer.pending.pop()
        derived = ObjectKey(
            key.authority, key.domain, json.dumps((key.uid, dimension), separators=(",", ":"))
        )
        normalizer.definitions[derived] = ObjectDefinition(
            derived,
            _digest(normalizer.raw[key]),
            normalizer.object_predicate(key, dimension),
            evidence=(key.uid,),
        )
    guards = [installation]
    if not capture_complete:
        guards.append(normalizer.gap("CP_CAPTURE_INCOMPLETE", uid))
    if not implied_complete:
        guards.append(normalizer.gap("CP_IMPLIED_RULES_NOT_CAPTURED", uid))
    if package_unknown:
        guards.append(normalizer.gap("CP_PACKAGE_FIELD_UNCLASSIFIED", uid))
    source_digest = _digest(
        (profile.version, package, layers, rulebases, objects, capture_complete, implied_complete)
    )
    policy = Policy(
        uid,
        source_digest,
        context,
        tuple(normalized),
        ordered_uids,
        tuple(normalizer.definitions.values()),
        AllOf(tuple(guards)),
        semantic_profile="explicit-filter-v1",
        evidence=(uid, profile.version),
        manifest_digest=manifest_digest,
    )
    return NormalizedCheckpoint(policy, profile, tuple(normalizer.audit), source_digest)


def normalize_checkpoint_capture(
    capture: PolicyCapture,
    *,
    profile: CheckpointProfile,
    context: ExecutionContext,
    installation: Predicate,
    target_bindings: Mapping[str, tuple[str, ...]],
    implied_complete: bool = False,
) -> NormalizedCheckpoint:
    """Implied-rule completeness does not override a gap reported by acquisition."""
    if (capture.envelope.authority_uid, capture.envelope.domain_uid) != (context.authority, context.domain):
        raise ValueError("capture belongs to another management authority/domain")
    bundle = capture.bundle
    package, raw_layers, objects, rulebases = (
        bundle.get("package"),
        bundle.get("layers"),
        bundle.get("objects"),
        bundle.get("rulebases"),
    )
    if (
        not isinstance(package, Mapping)
        or not isinstance(raw_layers, Mapping)
        or not isinstance(objects, Mapping)
        or not isinstance(rulebases, Mapping)
    ):
        raise ValueError("capture has no usable package/layer/object/rulebase mappings")
    if _uid(package) != capture.package_uid:
        raise ValueError("capture package UID disagrees with its envelope")
    layers: dict[str, Mapping[str, Any]] = {}
    for uid, layer in raw_layers.items():
        if not isinstance(layer, Mapping) or not isinstance(layer.get("metadata"), Mapping):
            raise ValueError("captured layer metadata is missing")
        layers[uid] = layer["metadata"]
    guards: list[Predicate] = [installation]
    guards.extend(
        Unknown(
            "CP_CAPTURE_" + gap.code.upper().replace("-", "_"),
            gap.subject,
            (capture.envelope.manifest_digest,),
        )
        for gap in capture.gaps
    )
    return normalize_checkpoint_policy(
        profile=profile,
        context=context,
        manifest_digest=capture.envelope.manifest_digest,
        package=package,
        layers=layers,
        rulebases=rulebases,
        objects=tuple(objects.values()),
        installation=AllOf(tuple(guards)),
        target_bindings=target_bindings,
        capture_complete=capture.complete,
        implied_complete=implied_complete,
    )
