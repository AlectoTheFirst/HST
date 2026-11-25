"""Finite firewall proposal generation and whole-requirement constraint search."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from itertools import product
from math import prod
from typing import Any

from hst.assessment.regression import rule_as_add
from hst.assessment.search import FAILS, HOLDS, UNKNOWN, SearchLimits, enumerate_subsets, verdict
from hst.simul.fw_overlay import FW_KINDS


def generate_firewall_candidates(
    rules: Mapping[str, Sequence[Mapping[str, Any]]],
    allowed_targets: Mapping[str, str],
    scope: Mapping[str, Any],
    allowed_kinds: Sequence[str] = tuple(sorted(FW_KINDS)),
    *,
    max_candidates: int = 256,
) -> dict[str, Any]:
    """Generate the candidate rule edits for the allowed rulebases.

    `policy_partitions` splits the scope into address, protocol and port cells.
    An added rule matches one cell with the action `accept` or `drop`, at each
    existing rule position and after the last position. A modification changes
    the action of a rule. A rule that `rule_as_add` cannot express has no remove
    or modify candidate and is listed in `excluded`.
    """
    if not 1 <= max_candidates <= 10000:
        raise ValueError("generator max_candidates must be between 1 and 10000")
    if not allowed_targets or not set(allowed_targets) <= set(rules):
        raise ValueError("allowed targets must name existing rulebases and devices")
    if any(not rb or not dev for rb, dev in allowed_targets.items()):
        raise ValueError("each allowed rulebase needs an explicit device UID")
    if not set(allowed_kinds) <= FW_KINDS or not allowed_kinds:
        raise ValueError("allowed kinds must be a nonempty subset of supported firewall edits")
    dimensions = []
    for key in ("source", "destination", "protocols", "ports"):
        values = scope.get(key)
        if not isinstance(values, list) or not values or len(values) > 16:
            raise ValueError(f"repair scope {key} must contain 1 to 16 explicit values")
        dimensions.append(sorted({str(v) for v in values}))
    from hst.assessment.partitions import policy_partitions

    partitions = policy_partitions(scope, [row for rb in sorted(allowed_targets) for row in rules[rb]])
    dimensions = [partitions[key] for key in ("source", "destination", "protocols", "ports")]
    if prod(map(len, dimensions)) * len(allowed_targets) > 4096:
        raise ValueError("repair scope exceeds the finite generator limit")
    cells = list(product(*dimensions))
    candidates: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    generated_count = 0

    def add(rb: str, intent: dict[str, Any]) -> None:
        nonlocal generated_count
        generated_count += 1
        if len(candidates) >= max_candidates:
            return
        digest = hashlib.sha256(json.dumps(intent, sort_keys=True).encode()).hexdigest()[:16]
        if intent["kind"] == "fw_rule.add":
            intent["params"]["uid"] = f"fw:repair:{digest}"
        candidates.append(
            {"id": f"repair:{digest}", "intents": [intent], "device": allowed_targets[rb], "rulebase": rb}
        )

    for rb in sorted(allowed_targets):
        rows = list(rules[rb])
        positions = sorted({int(r["pos"]) for r in rows if r.get("pos") is not None})
        positions = [*positions, positions[-1] + 1] if positions else [1]
        if len(candidates) + len(positions) * len(cells) * 2 > 10000:
            raise ValueError("repair generator exceeds 10000 candidates; narrow the scope")
        if "fw_rule.add" in allowed_kinds:
            for source, destination, protocol, port in cells:
                for position, action in product(positions, ("accept", "drop")):
                    params = {
                        "rulebase": rb,
                        "source": [source],
                        "destination": [destination],
                        "protocols": [protocol],
                        "ports": [port],
                        "position": position,
                        "action": action,
                    }
                    add(rb, {"kind": "fw_rule.add", "params": params})
        for row in rows:
            try:
                rule_as_add(rb, row)
            except ValueError as exc:
                excluded.append({"rulebase": rb, "rule": row.get("uid"), "reason": str(exc)})
                continue
            if "fw_rule.remove" in allowed_kinds:
                add(rb, {"kind": "fw_rule.remove", "params": {"rulebase": rb, "rule": row["uid"]}})
            if "fw_rule.modify" in allowed_kinds:
                for action in ("accept", "drop"):
                    if row["action"] != action:
                        add(
                            rb,
                            {
                                "kind": "fw_rule.modify",
                                "params": {"rulebase": rb, "rule": row["uid"], "action": action},
                            },
                        )
    # An excluded rule has no remove or modify candidate, and its opaque objects add
    # no cell boundary. `universe_complete` is false when a rule is excluded, as in
    # `symbolic_repair.generate_candidates`.
    return {
        "candidates": candidates,
        "excluded": excluded,
        "universe_complete": generated_count == len(candidates) and not excluded,
        "generated_count": generated_count,
        "generation_truncated": generated_count > len(candidates),
        "allowed_targets": dict(allowed_targets),
        "allowed_kinds": list(allowed_kinds),
        "scope": dict(scope),
        "partitions": partitions,
        "generator_version": "literal-firewall-policy-partitions-v2",
        "family": "literal cell additions, representable rule action changes and removals",
    }


def search_repairs(
    generated: Mapping[str, Any],
    oracle: Callable[[list[dict[str, Any]]], Mapping[str, Any]],
    limits: SearchLimits | None = None,
    *,
    cancelled: Callable[[], bool] | None = None,
    cost_oracle: Callable[[list[dict[str, Any]]], Mapping[str, Any]] | None = None,
    cost_order: Sequence[str] = ("devices", "newly_permitted_scope", "rule_edits"),
) -> dict[str, Any]:
    """Search the candidate subsets that verify the desired requirement and every protection.

    The oracle returns the three-valued verdicts `desired` and `protected`, and
    optionally `newly_permitted_scope`, the count of newly permitted flows in
    the declared scope. An unknown verdict leaves a subset unverified. Without
    `newly_permitted_scope` the ranking is devices and then edit count, and no
    finding has a `minimum_cost` claim. An isolation oracle must prove that the
    possible upper bound is empty. With `cost_oracle` the search is `ordered_repairs`.
    """
    limits = limits or SearchLimits()
    if cost_oracle is not None:
        from hst.assessment.cost_search import ordered_repairs

        return ordered_repairs(generated, oracle, cost_oracle, limits, cost_order, cancelled)
    if tuple(cost_order) != ("devices", "newly_permitted_scope", "rule_edits"):
        raise ValueError("operator-selected cost ordering requires the explicit scope cost oracle")
    by_id = {c["id"]: c for c in generated["candidates"]}
    targets = generated["allowed_targets"]

    def evaluate(ids: tuple[str, ...]) -> Mapping[str, Any]:
        intents = [i for uid in ids for i in by_id[uid]["intents"]]
        changed_rules: set[tuple[str, str]] = set()
        for intent in intents:
            p = intent["params"]
            if p.get("rulebase") not in targets or intent["kind"] not in generated["allowed_kinds"]:
                return {"verdict": FAILS, "reason": "outside-allowed-targets-or-kinds"}
            if p.get("rule"):
                key = (p["rulebase"], p["rule"])
                if key in changed_rules:
                    return {"verdict": FAILS, "reason": "conflicting-edits-to-one-rule"}
                changed_rules.add(key)
        raw = dict(oracle(intents))
        desired = verdict(raw.get("desired", UNKNOWN))
        protected = raw.get("protected", {})
        if not isinstance(protected, Mapping):
            raise ValueError("protected oracle outcomes must be a requirement-to-verdict mapping")
        states = [desired, *(verdict(value) for value in protected.values())]
        combined = FAILS if FAILS in states else UNKNOWN if UNKNOWN in states else HOLDS
        devices = len({by_id[uid]["device"] for uid in ids})
        scope = raw.get("newly_permitted_scope")
        if scope is not None and (not isinstance(scope, int) or scope < 0):
            raise ValueError("newly_permitted_scope must be a nonnegative exact cardinality")
        return {
            **raw,
            "verdict": combined,
            "intents": intents,
            "cost": [devices, scope, len(intents)],
            "protected_count": len(protected),
        }

    result = enumerate_subsets(
        list(by_id),
        evaluate,
        limits,
        universe_complete=bool(generated["universe_complete"]),
        cancelled=cancelled,
    )
    verified = [trial for trial in result["trials"] if trial["verdict"] == HOLDS]
    measured = all(
        trial["evaluation"].get("cost", [0, None])[1] is not None
        for trial in result["trials"]
        if "reason" not in trial["evaluation"]
    )

    def cost_key(trial: Mapping[str, Any]) -> tuple[Any, ...]:
        cost = trial["evaluation"]["cost"]
        return cost[0], cost[1] if cost[1] is not None else 0, cost[2], trial["candidates"]

    verified.sort(key=cost_key)
    proposals = []
    for trial in verified[: limits.max_results]:
        lower_unknown = any(
            t["verdict"] == UNKNOWN and cost_key(t) < cost_key(trial) for t in result["trials"]
        )
        proposals.append(
            {
                **trial,
                **trial["evaluation"],
                "verified": True,
                "minimum_cost": result["search_complete"]
                and measured
                and not lower_unknown
                and cost_key(trial)[:3] == cost_key(verified[0])[:3],
            }
        )
    result.update(
        {
            "kind": "repair",
            "findings": proposals,
            "finding_count": len(verified),
            "findings_truncated": len(verified) > len(proposals),
            "candidates": list(by_id.values()),
            "excluded": generated["excluded"],
            "generator_version": generated["generator_version"],
            "cost_order": ["devices", "newly_permitted_scope", "rule_edits"]
            if measured
            else ["devices", "rule_edits"],
            "scope_cost_measured": measured,
            "proved_infeasible": result["search_complete"] and result["unknown"] == 0 and not verified,
        }
    )
    return result
