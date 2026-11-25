"""Bounded proposal generation for large immutable policy catalogs."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from itertools import islice, product
from math import prod
from typing import Any

from hst.assessment.partitions import policy_partitions
from hst.assessment.regression import rule_as_add
from hst.simul.intents import FW_KINDS


def generate_candidates(
    rules: Mapping[str, Sequence[Mapping[str, Any]]],
    allowed_targets: Mapping[str, str],
    allowed_kinds: Sequence[str],
    scope: Mapping[str, list[str]],
    *,
    max_candidates: int,
    cancelled: Callable[[], bool] | None = None,
) -> dict:
    if not 1 <= max_candidates <= 10000 or not allowed_targets:
        raise ValueError("repair requires a bounded candidate budget and allowed targets")
    if not set(allowed_targets) <= rules.keys() or not set(allowed_kinds) <= FW_KINDS or not allowed_kinds:
        raise ValueError("repair targets and edit kinds must belong to the declared policy scope")
    fields = ("source", "destination", "protocols", "ports")
    if any(not scope.get(field) or len(scope[field]) > 16 for field in fields):
        raise ValueError("each repair scope field needs 1 to 16 explicit values")
    rows = [row for target in sorted(allowed_targets) for row in rules[target]]
    partition_complete = True
    try:
        partitions = policy_partitions(scope, rows)
    except ValueError as error:
        if "exceeds 4096" not in str(error):
            raise
        partitions = {field: sorted(set(scope[field])) for field in fields}
        partition_complete = False
    dimensions = [partitions[field] for field in fields]
    cell_count = prod(map(len, dimensions))
    candidates: list[dict] = []
    excluded: list[dict] = []
    excluded_count = generated_count = 0
    stopped = False

    def add(rulebase: str, intent: dict) -> None:
        if len(candidates) >= max_candidates:
            return
        identity = hashlib.sha256(json.dumps(intent, sort_keys=True).encode()).hexdigest()[:24]
        if intent["kind"] == "fw_rule.add":
            intent["params"]["uid"] = f"fw:repair:{identity}"
        candidates.append(
            {
                "id": f"repair:{identity}",
                "intents": [intent],
                "device": allowed_targets[rulebase],
                "rulebase": rulebase,
            }
        )

    for target in sorted(allowed_targets):
        if cancelled and cancelled():
            stopped = True
            break
        positions = sorted({int(row["pos"]) for row in rules[target] if row.get("pos") is not None})
        positions.append(positions[-1] + 1 if positions else 1)
        if "fw_rule.add" in allowed_kinds:
            generated_count += cell_count * len(positions) * 2
            remaining = max_candidates - len(candidates)
            proposals = product(*dimensions, positions, ("accept", "drop"))
            for source, destination, protocol, port, position, action in islice(proposals, remaining):
                add(
                    target,
                    {
                        "kind": "fw_rule.add",
                        "params": {
                            "rulebase": target,
                            "source": [source],
                            "destination": [destination],
                            "protocols": [protocol],
                            "ports": [port],
                            "position": position,
                            "action": action,
                        },
                    },
                )
        for index, row in enumerate(rules[target]):
            if index % 256 == 0 and cancelled and cancelled():
                stopped = True
                break
            try:
                rule_as_add(target, row)
            except ValueError as error:
                excluded_count += 1
                if len(excluded) < 250:
                    excluded.append({"rulebase": target, "rule": row.get("uid"), "reason": str(error)})
                continue
            if "fw_rule.remove" in allowed_kinds:
                generated_count += 1
                add(target, {"kind": "fw_rule.remove", "params": {"rulebase": target, "rule": row["uid"]}})
            if "fw_rule.modify" in allowed_kinds:
                for action in ("accept", "drop"):
                    if action != row["action"]:
                        generated_count += 1
                        add(
                            target,
                            {
                                "kind": "fw_rule.modify",
                                "params": {
                                    "rulebase": target,
                                    "rule": row["uid"],
                                    "action": action,
                                },
                            },
                        )
        if stopped:
            break
    complete = (
        partition_complete and not stopped and not excluded_count and generated_count == len(candidates)
    )
    return {
        "candidates": candidates,
        "excluded": excluded,
        "excluded_count": excluded_count,
        "excluded_truncated": excluded_count > len(excluded),
        "universe_complete": complete,
        "generated_count": generated_count,
        "generated_count_complete": not stopped,
        "generation_truncated": not complete,
        "partition_complete": partition_complete,
        "allowed_targets": dict(allowed_targets),
        "allowed_kinds": list(allowed_kinds),
        "scope": dict(scope),
        "partitions": partitions,
        "generator_version": "symbolic-policy-candidates-v1",
        "family": "literal cell additions, representable rule action changes and removals",
    }
