"""Reversible edits of the observed model inputs, with preconditions.

Policy rows use the same gate read hook as proposals. A routing edit replaces
configuration records. Observation tables, captured paths and LSDB rows stay
those of the receiving snapshot. Derived routes are recomputed.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import Any

from hst.assessment.semantic import digest
from hst.impact.evaluate import Network
from hst.simul import certainty
from hst.simul.fw_overlay import Catalog, ChangeSet

_ROUTING_KEYS = {
    "contexts": ("uid",),
    "connected": ("context_uid", "prefix"),
    "static": ("context_uid", "prefix"),
    "pbr": ("if_uid",),
    "rt_pairs": ("importer", "exporter", "via_rt"),
    "bgp.processes": ("uid",),
    "bgp.sessions": ("uid",),
    "bgp.policies": ("uid", "name", "kind"),
    "bgp.local_routes": ("process_uid", "prefix"),
    "ospf": ("uid",),
    "interfaces": ("uid",),
}
_OBSERVED_OSPF = {"rows", "model", "coverage", "observed_ms"}


def _records(network: Network, family: str) -> list[dict[str, Any]]:
    if family == "interfaces":
        return [
            {
                "uid": i.uid,
                "name": i.name,
                "device_uid": i.device_uid,
                "context_uid": i.context_uid,
                "prefixes": list(i.prefixes),
                "addresses": list(i.addresses),
            }
            for i in network.interfaces
        ]
    if family.startswith("bgp."):
        value = getattr(network.routing.bgp, family[4:], ()) if network.routing.bgp is not None else ()
    else:
        value = getattr(network.routing, family)
    return [
        {k: copy.deepcopy(v) for k, v in row.items() if family != "ospf" or k not in _OBSERVED_OSPF}
        for row in value
    ]


def _key(row: Mapping[str, Any], family: str) -> tuple[str, ...]:
    return tuple(str(row.get(k, "")) for k in _ROUTING_KEYS[family])


def model_changes(
    before: Network,
    after: Network,
    before_policy: Mapping[str, Mapping[str, Sequence[Mapping[str, Any]]]],
    after_policy: Mapping[str, Mapping[str, Sequence[Mapping[str, Any]]]],
    *,
    complete_fw: Sequence[str],
    complete_nat: Sequence[str],
    complete_contexts: Sequence[str],
) -> dict[str, Any]:
    """Create reversible firewall, NAT, interface and routing input edits.

    A grouped route prefix is one edit even with ECMP alternatives.
    """
    edits: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []

    def emit(family: str, selector: list[str], old: list[dict], new: list[dict], complete: bool) -> None:
        if old == new:
            return
        row = {
            "id": "model-edit:" + digest([family, selector])[:24],
            "family": family,
            "selector": selector,
            "before": old,
            "after": new,
            "preconditions": {"forward": digest(old), "reverse": digest(new)},
        }
        if family in {"firewall", "nat"}:
            bundle_ids = {
                str(bundle_id)
                for policy_row in old + new
                for bundle_id in (policy_row.get("graph_object_bundle_ids") or ())
            }
            registries = (
                before_policy.get("graph_object_bundles", {}),
                after_policy.get("graph_object_bundles", {}),
            )
            row["graph_object_bundles"] = {
                bundle_id: registry[bundle_id]
                for bundle_id in sorted(bundle_ids)
                for registry in registries
                if bundle_id in registry
            }
            if set(row["graph_object_bundles"]) != bundle_ids:
                raise ValueError("policy edit object bundle registry is incomplete")
        if complete:
            edits.append(row)
        else:
            excluded.append(
                {**row, "reason": "Input ownership/completeness is not established on both snapshots."}
            )

    complete = set(complete_contexts)
    for family in _ROUTING_KEYS:
        left: dict[tuple[str, ...], list[dict]] = {}
        right: dict[tuple[str, ...], list[dict]] = {}
        for network, indexed in ((before, left), (after, right)):
            for row in _records(network, family):
                indexed.setdefault(_key(row, family), []).append(row)
        for key in sorted(left.keys() | right.keys()):
            old, new = left.get(key, []), right.get(key, [])
            contexts = {str(r["context_uid"]) for r in old + new if r.get("context_uid")}
            if family == "pbr":
                contexts.update(
                    str(i.context_uid)
                    for network in (before, after)
                    for i in network.interfaces
                    if i.uid in key and i.context_uid
                )
            if family == "contexts":
                contexts.update(str(r["uid"]) for r in old + new)
            if family.startswith("bgp."):
                for network in (before, after):
                    if network.routing.bgp:
                        contexts.update(
                            str(p["context_uid"])
                            for p in network.routing.bgp.processes
                            if p.get("context_uid")
                        )
            if family == "rt_pairs":
                contexts.update(str(r[k]) for r in old + new for k in ("importer", "exporter"))
            emit(
                family,
                list(key),
                sorted(old, key=digest),
                sorted(new, key=digest),
                bool(contexts) and contexts <= complete,
            )
    for family, allowed in (("firewall", set(complete_fw)), ("nat", set(complete_nat))):
        left_policy, right_policy = before_policy.get(family, {}), after_policy.get(family, {})
        for target in sorted(left_policy.keys() | right_policy.keys()):
            old_rows = list(left_policy.get(target, ()))
            new_rows = list(right_policy.get(target, ()))
            old_policy = {str(row["uid"]): dict(row) for row in old_rows}
            new_policy = {str(row["uid"]): dict(row) for row in new_rows}
            ambiguous = any(
                len({row["uid"] for row in rows}) != len(rows)
                or len({row.get("pos") for row in rows}) != len(rows)
                for rows in (old_rows, new_rows)
            )
            if ambiguous:
                excluded.append(
                    {
                        "family": family,
                        "selector": [target],
                        "reason": (
                            "Duplicate rule identity or tied order prevents exact independent inversion."
                        ),
                    }
                )
                continue
            for uid in sorted(old_policy.keys() | new_policy.keys()):
                emit(
                    family,
                    [target, uid],
                    [old_policy[uid]] if uid in old_policy else [],
                    [new_policy[uid]] if uid in new_policy else [],
                    target in allowed and target in left_policy and target in right_policy,
                )
    return {
        "edits": edits,
        "excluded": excluded,
        "universe_complete": not excluded,
        "family": "observed-configured-model-inputs",
        "observations_reused": "receiving snapshot only",
    }


class _PolicyEdits(ChangeSet):
    def __init__(self, edits: Sequence[Mapping[str, Any]], direction: str) -> None:
        super().__init__([], catalog=Catalog())
        self.edits = list(edits)
        self.direction = direction

    def rewrite(self, query: str, params: Mapping[str, Any], rows: Any) -> Any:
        from hst.simul.fw_overlay import _gate_queries

        # A rule read of the gates is matched by the identity of its query, as
        # `ChangeSet.rewrite` matches it. The jump-target read and the rulebase-scope
        # read name the same rulebase and read no rule.
        if query in _gate_queries()[0]:
            family, target = "firewall", params.get("rb")
        elif "NatRule" in query and "dev" in params:
            from hst.path.gates.nat import _NAT_RULES_QUERY, _NAT_RULES_QUERY_STRICT

            if query not in {_NAT_RULES_QUERY, _NAT_RULES_QUERY_STRICT}:
                return rows
            family, target = "nat", params["dev"]
        else:
            return rows
        out = [dict(row) for row in rows]
        for edit in self.edits:
            if edit["family"] != family or edit["selector"][0] != target:
                continue
            uid = edit["selector"][1]
            current = [row for row in out if row.get("uid") == uid]
            if digest(current) != edit["preconditions"][self.direction]:
                raise ValueError(f"Policy edit precondition failed for {target}/{uid}")
            replacement = edit["before"] if self.direction == "reverse" else edit["after"]
            out = [row for row in out if row.get("uid") != uid] + copy.deepcopy(replacement)
            out.sort(key=lambda row: (row.get("pos") is None, row.get("pos", 0), str(row.get("uid", ""))))
        return out


def apply_model_edits(
    network: Network, edits: Sequence[Mapping[str, Any]], *, direction: str = "reverse"
) -> Network:
    """Apply the edit records to a copy of the model.

    Each record is checked against its precondition. The observations of `network` are kept.
    """
    if direction not in {"reverse", "forward"}:
        raise ValueError("direction must be reverse or forward")
    routing = copy.deepcopy(network.routing)
    interfaces = network.interfaces
    roots: set[str] = set()
    policy = []
    for edit in edits:
        family = edit["family"]
        if family in {"firewall", "nat"}:
            policy.append(edit)
            continue
        if family not in _ROUTING_KEYS:
            raise ValueError(f"unsupported model input edit family {family}")
        current_network = replace(network, routing=routing, interfaces=interfaces)
        rows = _records(current_network, family)
        selected = sorted((row for row in rows if list(_key(row, family)) == edit["selector"]), key=digest)
        if digest(selected) != edit["preconditions"][direction]:
            raise ValueError(f"Model edit precondition failed for {family}/{edit['selector']}")
        replacement = copy.deepcopy(edit["before"] if direction == "reverse" else edit["after"])
        rewritten = [row for row in rows if list(_key(row, family)) != edit["selector"]] + replacement
        roots.update(str(row["context_uid"]) for row in selected + replacement if row.get("context_uid"))
        if family == "contexts":
            roots.update(str(row["uid"]) for row in selected + replacement)
        if family == "rt_pairs":
            roots.update(str(row[k]) for row in selected + replacement for k in ("importer", "exporter"))
        if family == "interfaces":
            from hst.impact.evaluate import Interface

            mtu_by_uid = {interface.uid: interface.mtu_observations_json for interface in interfaces}
            segments_by_uid = {interface.uid: interface.segments for interface in interfaces}
            interfaces = tuple(
                Interface(
                    **{
                        **row,
                        "prefixes": tuple(row["prefixes"]),
                        "addresses": tuple(row["addresses"]),
                        "mtu_observations_json": mtu_by_uid.get(row["uid"], ()),
                        "segments": segments_by_uid.get(row["uid"], ()),
                    }
                )
                for row in rewritten
            )
        elif family.startswith("bgp."):
            from hst.simul.propagate import SimulationInput

            bgp = routing.bgp or SimulationInput(platform=routing.platform)
            routing = replace(routing, bgp=replace(bgp, **{family[4:]: rewritten}))
            roots.update(str(p["context_uid"]) for p in bgp.processes if p.get("context_uid"))
        elif family == "ospf":
            observed = {
                str(row["uid"]): {k: v for k, v in row.items() if k in _OBSERVED_OSPF} for row in routing.ospf
            }
            routing = replace(
                routing, ospf=[{**row, **observed.get(str(row["uid"]), {})} for row in rewritten]
            )
        else:
            routing = replace(routing, **{family: rewritten})
    # A policy edit supersedes the dependency closure of every routing context.
    if policy:
        roots.update(str(c["uid"]) for c in routing.contexts)
    changed = (
        certainty.closure(routing, roots) | certainty.closure(network.routing, roots)
        if roots
        else frozenset()
    )
    routing = replace(routing, superseded_contexts=routing.superseded_contexts | changed)
    gates = network.gates.with_changes(_PolicyEdits(policy, direction)) if policy else network.gates
    return replace(
        network, routing=routing, interfaces=interfaces, gates=gates, baseline=network.baseline or network
    )
