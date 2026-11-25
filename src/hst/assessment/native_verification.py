"""Compare ordered configuration predicates without flattening object groups."""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from hst.analysis_model.checkpoint_graph import (
    checkpoint_bound,
    checkpoint_policy,
    checkpoint_scope,
    unknown_checkpoint_policy,
)
from hst.analysis_model.graph import GraphInventory
from hst.policy.graph import GraphPolicyNormalizer
from hst.policy.ir import Constant, ExecutionContext, Predicate
from hst.policy.nat import normalize_nat_rules
from hst.policy.predicates import PredicateCompiler
from hst.symbolic import HeaderSchema, SymbolicManager


def compare_configuration(
    expected: GraphInventory,
    actual: GraphInventory,
    targets: dict[str, set[str]],
    *,
    estate: str,
    checkpoint: Callable[[], bool],
) -> dict:
    """Compare the predicates of each rule in rule order, without the assigned rule IDs.

    The caller checks the completeness of the installation. A predicate whose
    lower and upper bounds differ leaves its scope unresolved.
    """
    checked, differences, unresolved = [], [], []
    for family, target_ids in targets.items():
        for target in sorted(target_ids):
            families: tuple[Literal[4, 6], ...] = (4, 6)
            for address_family in families:
                if not checkpoint():
                    return {
                        "state": "not-decided",
                        "reason": "Configuration comparison budget exhausted.",
                    }
                scope = {"family": family, "target": target, "address_family": address_family}
                state = _compare(expected, actual, family, target, address_family, estate, checkpoint)
                checked.append(scope)
                if state == "differs":
                    differences.append(scope)
                elif state == "unknown":
                    unresolved.append(scope)
    return {
        "state": "differs" if differences else "not-decided" if unresolved else "matches",
        "scope": "ordered compiled firewall and NAT configuration predicates",
        "checked": checked,
        "differences": differences,
        "unresolved": unresolved,
        "reason": "Compared captured configuration predicates, actions and translations in rule order.",
    }


def _compare(
    expected: GraphInventory,
    actual: GraphInventory,
    family: str,
    target: str,
    address_family: Literal[4, 6],
    estate: str,
    checkpoint: Callable[[], bool],
) -> str:
    with SymbolicManager(HeaderSchema(address_family)) as manager:
        known = frozenset(manager.schema.field_names)
        left, right = PredicateCompiler(manager, known), PredicateCompiler(manager, known)

        def predicate(a: Predicate, b: Predicate) -> Literal["matches", "differs", "unknown"]:
            x, y = left.compile(a).bounds, right.compile(b).bounds
            if not x.lower.equivalent(x.upper) or not y.lower.equivalent(y.upper):
                return "unknown"
            return "matches" if x.lower.equivalent(y.lower) else "differs"

        if family == "firewall":
            expected_scope = checkpoint_scope(expected, target)
            actual_scope = checkpoint_scope(actual, target)
            if expected_scope != actual_scope:
                return "differs"
            context = ExecutionContext(
                estate, "configuration", "configuration", target, "configuration", address_family
            )
            if expected_scope:
                context = ExecutionContext(
                    estate,
                    expected_scope[0],
                    expected_scope[1],
                    target,
                    "configuration",
                    address_family,
                )
            before = checkpoint_policy(expected, (target,), context, Constant(True))
            if before is None:
                before = (
                    unknown_checkpoint_policy(expected, context, Constant(True))
                    if checkpoint_bound(expected, (target,))
                    else GraphPolicyNormalizer(expected, context).policy(
                        (target,), installation=Constant(True)
                    )
                )
            after = checkpoint_policy(actual, (target,), context, Constant(True))
            if after is None:
                after = (
                    unknown_checkpoint_policy(actual, context, Constant(True))
                    if checkpoint_bound(actual, (target,))
                    else GraphPolicyNormalizer(actual, context).policy((target,), installation=Constant(True))
                )
            left.update(before.objects)
            right.update(after.objects)
            installation_state = predicate(before.installation, after.installation)
            if installation_state == "differs":
                return "differs"
            before_layers = {layer.uid: layer for layer in before.layers}
            after_layers = {layer.uid: layer for layer in after.layers}
            if len(before.ordered_layers) != len(after.ordered_layers):
                return "differs"
            unknown = installation_state == "unknown"
            pending_layers = list(zip(before.ordered_layers, after.ordered_layers, strict=True))
            seen_layers: set[tuple[str, str]] = set()
            while pending_layers:
                before_uid, after_uid = pending_layers.pop(0)
                if (before_uid, after_uid) in seen_layers:
                    continue
                seen_layers.add((before_uid, after_uid))
                a, b = before_layers.get(before_uid), after_layers.get(after_uid)
                if a is None or b is None:
                    return "unknown"
                if a.default != b.default or len(a.rules) != len(b.rules):
                    return "differs"
                unknown |= a.default == "unknown"
                for x, y in zip(a.rules, b.rules, strict=True):
                    if not checkpoint():
                        return "unknown"
                    if x.action == "unknown" or y.action == "unknown":
                        unknown = True
                        continue
                    if (x.action, x.enabled, x.called_layer, x.install_targets) != (
                        y.action,
                        y.enabled,
                        y.called_layer,
                        y.install_targets,
                    ):
                        return "differs"
                    if x.called_layer is not None and y.called_layer is not None:
                        pending_layers.append((x.called_layer, y.called_layer))
                    state = predicate(x.predicate, y.predicate)
                    if state == "differs":
                        return state
                    unknown |= state == "unknown" or x.action == "unknown"
            return "unknown" if unknown else "matches"
        if family != "nat":
            raise ValueError("unsupported native configuration family")
        before_nat, after_nat = (
            normalize_nat_rules(
                graph,
                target,
                ingress_interface_uid=None,
                egress_interface_uid=None,
                address_family=address_family,
            )
            for graph in (expected, actual)
        )
        if len(before_nat) != len(after_nat):
            return "differs"
        unknown = False
        for nat_left, nat_right in zip(before_nat, after_nat, strict=True):
            if not checkpoint():
                return "unknown"
            if nat_left.gap_code is not None or nat_right.gap_code is not None:
                unknown = True
                continue
            if (nat_left.stage, nat_left.exclude, nat_left.rewrites, nat_left.ranges) != (
                nat_right.stage,
                nat_right.exclude,
                nat_right.rewrites,
                nat_right.ranges,
            ):
                return "differs"
            state = predicate(nat_left.predicate, nat_right.predicate)
            if state == "differs":
                return state
            unknown |= state == "unknown" or nat_left.gap_code is not None or nat_right.gap_code is not None
        return "unknown" if unknown else "matches"
