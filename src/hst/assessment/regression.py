"""The reversal of observed firewall edits between 2 snapshots.

A changed rule is reversible when its gate row is expressible as an overlay
rule and its rulebase exists in both snapshots. The caller supplies the
rulebases whose policy sections are complete in both pinned manifests. A
changed rule of another rulebase is excluded.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from hst.assessment.search import FAILS, HOLDS, SearchLimits, enumerate_subsets
from hst.simul.fw_overlay import PROPOSABLE_ACTIONS

SEMANTIC_FIELDS = (
    "pos",
    "action",
    "in_if",
    "out_if",
    "in_if_group",
    "out_if_group",
    "states",
    "states_opaque",
    "src_any",
    "dst_any",
    "svc_any",
    "src_negate",
    "dst_negate",
    "svc_negate",
    "src_cidrs",
    "src_ips",
    "src_ranges",
    "dst_cidrs",
    "dst_ips",
    "dst_ranges",
    "protos",
    "ports",
    "src_ports",
    "svc_src_port",
    "src_opaque",
    "dst_opaque",
    "svc_opaque",
    "src_obj_count",
    "dst_obj_count",
    "svc_obj_count",
    # The install-on scope of a Check Point rule. A move of a rule to other
    # gateways changes its decision on each gateway.
    "install_on",
    "install_on_unresolved",
)


def rule_as_add(rulebase: str, row: Mapping[str, Any]) -> dict[str, Any]:
    """Express a resolved gate row as a `fw_rule.add` intent of the overlay.

    `ValueError` is raised for a row that the overlay cannot express.
    """
    for field in (
        "in_if_group",
        "out_if_group",
        "states",
        "states_opaque",
        "src_negate",
        "dst_negate",
        "svc_negate",
        "src_opaque",
        "dst_opaque",
        "svc_opaque",
        "svc_src_port",
        # the overlay vocabulary has no install-on scope
        "install_on",
        "install_on_unresolved",
    ):
        if row.get(field):
            raise ValueError(f"rule {row.get('uid')} uses unsupported {field}")
    if any(row.get("src_ports") or ()):
        raise ValueError("source-port policy cannot be regenerated")
    if row.get("action") not in PROPOSABLE_ACTIONS or row.get("pos") is None or not row.get("uid"):
        raise ValueError("rule needs a supported action, UID and explicit position")
    params: dict[str, Any] = {
        "rulebase": rulebase,
        "uid": str(row["uid"]),
        "position": int(row["pos"]),
        "action": row["action"],
    }
    for side, name in (("src", "source"), ("dst", "destination")):
        values = [
            value for suffix in ("cidrs", "ips", "ranges") for value in row.get(f"{side}_{suffix}") or ()
        ]
        # A value is one range or a list of ranges per object.
        values = [item for value in values for item in (value if isinstance(value, list) else [value])]
        if row.get(f"{side}_any"):
            params[name] = ["any"]
        elif values:
            params[name] = sorted(set(values))
        else:
            raise ValueError(f"{name} has no complete resolved address match")
    if not row.get("svc_any"):
        protos, ports = list(row.get("protos") or ()), list(row.get("ports") or ())
        if len(protos) != len(ports) or not protos:
            raise ValueError("service member pairs are incomplete")
        pairs = set(zip(protos, ports, strict=True))
        protocols, port_values = {p for p, _ in pairs}, {p for _, p in pairs}
        if pairs != {(p, q) for p in protocols for q in port_values}:
            raise ValueError("service union is not expressible as one literal overlay rule")
        if (None in protocols and len(protocols) > 1) or (None in port_values and len(port_values) > 1):
            raise ValueError("mixed unconstrained service dimensions are unsupported")
        if pairs == {(None, None)}:
            raise ValueError("service is unresolved")
        params["protocols"] = sorted(p for p in protocols if p is not None)
        params["ports"] = sorted(p for p in port_values if p is not None)
    for column, name in (("in_if", "in_interface"), ("out_if", "out_interface")):
        if row.get(column):
            params[name] = row[column]
    return {"kind": "fw_rule.add", "params": params}


def _semantic(row: Mapping[str, Any] | None) -> dict[str, Any] | None:
    return {key: row.get(key) for key in SEMANTIC_FIELDS} if row is not None else None


def semantic_firewall_diff(
    before: Mapping[str, Sequence[Mapping[str, Any]]],
    after: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    complete_rulebases: Sequence[str],
) -> dict[str, Any]:
    """Return the reversible edits and the excluded changed rules, each with its reason.

    A rulebase in `complete_rulebases` has complete policy sections with their
    resolved objects in both snapshots.
    """
    edits: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    complete = set(complete_rulebases)
    for rb in sorted(set(before) | set(after)):
        left = {str(r["uid"]): r for r in before.get(rb, ())}
        right = {str(r["uid"]): r for r in after.get(rb, ())}
        if len(left) != len(before.get(rb, ())) or len(right) != len(after.get(rb, ())):
            excluded.append({"rulebase": rb, "reason": "duplicate rule UID"})
            continue
        for uid in sorted(set(left) | set(right)):
            old, new = left.get(uid), right.get(uid)
            if _semantic(old) == _semantic(new):
                continue
            reason = None
            if rb not in before or rb not in after:
                reason = "rulebase creation/deletion is outside the reversible family"
            elif rb not in complete:
                reason = "policy/object completeness is not established on both snapshots"
            reverse: list[dict[str, Any]] = []
            try:
                if new is not None:
                    rule_as_add(rb, new)
                    reverse.append({"kind": "fw_rule.remove", "params": {"rulebase": rb, "rule": uid}})
                if old is not None:
                    reverse.append(rule_as_add(rb, old))
            except ValueError as exc:
                reason = reason or str(exc)
            # The collected order of rules with equal positions cannot be reproduced.
            if old is not None and sum(r.get("pos") == old.get("pos") for r in left.values()) > 1:
                reason = reason or "equal rule positions have no reversible ordering precondition"
            identity = hashlib.sha256(f"{rb}\0{uid}".encode()).hexdigest()[:16]
            entry = {
                "id": f"fw-edit:{identity}",
                "rulebase": rb,
                "rule": uid,
                "before": dict(old) if old else None,
                "after": dict(new) if new else None,
            }
            if reason:
                excluded.append({**entry, "reason": reason})
            else:
                edits.append({**entry, "reverse_intents": reverse, "precondition": _semantic(new)})
    return {
        "edits": edits,
        "excluded": excluded,
        "universe_complete": not excluded,
        "family": "resolved-firewall-rules-on-existing-rulebases",
    }


def analyze_regression(
    difference: Mapping[str, Any],
    oracle: Callable[[list[dict[str, Any]]], str | Mapping[str, Any]],
    limits: SearchLimits | None = None,
    *,
    before_verdict: str,
    after_verdict: str,
    cancelled: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    by_id = {edit["id"]: edit for edit in difference["edits"]}

    def evaluate(ids: tuple[str, ...]) -> str | Mapping[str, Any]:
        intents = [intent for uid in ids for intent in by_id[uid]["reverse_intents"]]
        return oracle(intents)

    result = enumerate_subsets(
        list(by_id),
        evaluate,
        limits,
        universe_complete=bool(difference["universe_complete"]),
        cancelled=cancelled,
    )
    result.update(
        {
            "kind": "regression",
            "before_verdict": before_verdict,
            "after_verdict": after_verdict,
            "confirmed_modeled_regression": before_verdict == HOLDS and after_verdict == FAILS,
            "edits": list(by_id.values()),
            "excluded": difference["excluded"],
            "claim": "Modeled reversal restores the requirement; this does not establish incident cause.",
        }
    )
    result["universe_digest"] = hashlib.sha256(json.dumps(difference, sort_keys=True).encode()).hexdigest()
    return result


def analyze_model_regression(
    difference: Mapping[str, Any],
    reverse_oracle: Callable[[list[dict[str, Any]]], str | Mapping[str, Any]],
    limits: SearchLimits | None = None,
    *,
    before_verdict: str,
    after_verdict: str,
    forward_oracle: Callable[[list[dict[str, Any]]], str | Mapping[str, Any]] | None = None,
    semantic_stream: Mapping[str, Any] | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Search the edits whose reversal on B restores the requirement, and replay each finding on A.

    `forward_oracle` evaluates the edits of a finding on A. A finding without a
    forward evaluation has the forward verdict unknown. The reverse and the
    forward evaluations count against `limits.max_evaluations`. The result holds
    `semantic_stream`, and an incomplete stream makes the universe incomplete.
    """
    import time

    from hst.assessment.search import UNKNOWN, verdict
    from hst.assessment.semantic import digest

    limits = limits or SearchLimits()
    started = time.monotonic()
    by_id = {edit["id"]: edit for edit in difference["edits"]}
    result = enumerate_subsets(
        list(by_id),
        lambda ids: reverse_oracle([by_id[uid] for uid in ids]),
        limits,
        universe_complete=bool(difference["universe_complete"])
        and (semantic_stream is None or bool(semantic_stream.get("complete"))),
        cancelled=cancelled,
    )
    reverse_count = result["evaluated"]
    for finding in result["findings"]:
        edits = [by_id[uid] for uid in finding["candidates"]]
        reason = (
            "forward-replay-unavailable"
            if forward_oracle is None
            else "cancelled"
            if cancelled and cancelled()
            else "evaluation-limit"
            if result["evaluated"] >= limits.max_evaluations
            else "time-limit"
            if time.monotonic() - started >= limits.max_seconds
            else None
        )
        if reason is None and forward_oracle is not None:
            raw = forward_oracle(edits)
            result["evaluated"] += 1
        else:
            raw = {"verdict": UNKNOWN, "reason": reason}
        state = verdict(raw)
        finding["forward_replay"] = {
            "verdict": state,
            "reproduces_failure": state == FAILS,
            "independent": forward_oracle is not None,
            "evaluation": dict(raw) if isinstance(raw, Mapping) else {"verdict": state},
        }
    result["reverse_evaluations"] = reverse_count
    result["forward_evaluations"] = result["evaluated"] - reverse_count
    result["elapsed_seconds"] = time.monotonic() - started
    result.update(
        {
            "kind": "regression",
            "before_verdict": before_verdict,
            "after_verdict": after_verdict,
            "confirmed_modeled_regression": before_verdict == HOLDS and after_verdict == FAILS,
            "edits": list(by_id.values()),
            "excluded": difference["excluded"],
            "semantic_stream": dict(semantic_stream) if semantic_stream is not None else None,
            "universe_digest": digest(difference),
            "claim": (
                "Modeled reversal restores the requirement; independent forward replay tests reproduction. "
                "Neither establishes incident cause."
            ),
            "universe_scope": (
                "reversible model inputs; observation and collection changes remain separately reported"
            ),
        }
    )
    return result
