"""Typed reasoning gaps keyed by producer codes, independent of display prose."""

from collections.abc import Mapping
from typing import Any

# The stage/kind pairs that impact.evaluate emits.
_GAPS = {
    ("route", "no-context"): ("not-collected", "routing-context-missing", "routing-context"),
    ("route", "not-computed"): ("not-modeled", "routing-context-not-computed", "routing"),
    ("route", "incomplete"): ("unclassified", "routing-inputs-incomplete", "routing"),
    ("route", "resolution-incomplete"): ("unclassified", "recursive-route-incomplete", "routing"),
    ("entry", "unattached"): ("not-collected", "source-attachment-missing", "interface"),
    ("entry", "unowned"): ("not-collected", "source-ownership-missing", "interface"),
    ("next-hop", "unowned"): ("not-collected", "next-hop-ownership-missing", "interface"),
    ("next-hop", "duplicated"): ("unclassified", "next-hop-context-conflict", "routing-context"),
    ("forwarding", "beyond-interface"): ("not-modeled", "interface-forwarding-unmodeled", "topology"),
    ("pbr", "unknown-predicate"): ("unsupported", "pbr-predicate-unsupported", "policy"),
    ("pbr", "missing-table"): ("not-modeled", "pbr-table-unmodeled", "routing"),
    ("output-filter", "missing"): ("not-modeled", "output-filter-unmodeled", "policy"),
    ("snat", "masquerade"): ("not-collected", "nat-egress-address-missing", "interface"),
    ("snat", "ambiguous-egress-address"): ("unclassified", "nat-egress-selection-unknown", "nat"),
    ("tunnel", "missing-endpoint"): ("not-modeled", "tunnel-endpoint-unmodeled", "tunnel"),
    ("tunnel", "carrier-unknown"): ("unclassified", "tunnel-carrier-unknown", "tunnel"),
    ("budget", "exhausted"): ("not-modeled", "evaluation-budget-exhausted", "execution"),
    ("device", "hop-limit"): ("not-modeled", "evaluation-hop-limit", "execution"),
    ("session", "unrestored-tuple"): ("unclassified", "session-tuple-unrestored", "session"),
}


def gap_from_step(step: Mapping[str, Any]) -> dict[str, Any]:
    """One explicit unknown terminal step as a typed, non-executable gap."""
    stage = str(step.get("stage", "processing")).removeprefix("carrier/")
    event = str(step.get("kind", "unknown"))
    kind, code, dimension = _GAPS.get((stage, event), ("unclassified", f"{stage}.{event}", stage))
    return {
        "code": code,
        "kind": kind,
        "dimension": dimension,
        "subject": step.get("device_uid"),
        "detail": str(step.get("detail", "")),
        "producer": {"stage": stage, "kind": event},
        "recipe_id": None,
    }


def gap_from_effect(effect: Any, *, stage: str, device: str, context: str | None) -> dict[str, Any]:
    """The gap of an unknown transition, built from the evidence gaps that the
    gate supplies in the effect data.

    Without a supplied gap, the gap has the code
    `<gate>-decision-not-established`. Its kind is `unsupported` for the
    firewall, nat, zpa, aci and pbr gates and `unclassified` for every other
    gate.
    """
    data = effect.data
    supplied = data.get("evidence_gaps") or ([data["evidence_gap"]] if data.get("evidence_gap") else [])
    references = sorted({str(data[k]) for k in ("uid", "rule_uid", "rb_uid") if data.get(k)})
    for key in ("rule", "member", "vs", "connector"):
        item = data.get(key)
        if isinstance(item, Mapping) and item.get("uid"):
            references.append(str(item["uid"]))
    if supplied:
        base = dict(supplied[0])
    else:
        base = {
            "code": f"{effect.gate}-decision-not-established",
            "kind": "unsupported"
            if effect.gate in {"firewall", "nat", "zpa", "aci", "pbr"}
            else "unclassified",
            "dimension": effect.gate,
        }
    return {
        **base,
        "subject": base.get("subject") or device,
        "context_uid": context,
        "detail": effect.reason or base.get("detail", "The gate could not establish its decision."),
        "producer": {"stage": stage, "gate": effect.gate, "kind": effect.kind},
        "unknown_dimensions": sorted(effect.unknown),
        "evidence_refs": references,
        "related_gaps": [dict(gap) for gap in supplied[1:]],
        "recipe_id": None,
    }
