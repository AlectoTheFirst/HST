"""The evidence gaps of an evaluation and the collection actions for them."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from hst.collectors.recipes import routing_recipe, section_recipe
from hst.impact.gaps import gap_from_step
from hst.path.addrsets import _intervals, _merge


def stable_id(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode()).hexdigest()[:24]


def _gap_id(gap: Mapping[str, Any]) -> str:
    return stable_id(
        *(
            json.dumps(gap.get(key), sort_keys=True)
            for key in ("code", "subject", "dimension", "section", "source", "host", "producer")
        )
    )


def _unknown(result: Mapping[str, Any]) -> bool:
    verdict = result.get("verdict")
    if verdict in {"holds", "does-not-hold"}:
        return False
    after = (result.get("not_established") or {}).get("after")
    if isinstance(after, Mapping):
        return bool(after.get("count"))
    return verdict == "not-established" or any(
        item.get("side") != "before" and item.get("outcome") == "not-established"
        for item in (result.get("evidence") or {}).get("items", ())
    )


def rank_actions(actions: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Merge the actions of one device into one action and rank the merged actions.

    A device is one source and host. The priority of a merged action is the sum
    of the priorities of its distinct requirements. `recipe_id` is the recipe of
    the first action, and `recipe_ids` lists the recipe of every merged action.
    `affected_source_addresses` is a count of source addresses.
    """
    combined: dict[tuple[str, str], dict[str, Any]] = {}
    for action in actions:
        key = (action["source"], action["host"])
        if key not in combined:
            combined[key] = {
                **action,
                "requirements": [],
                "recipe_ids": [],
                "sections": [],
                "commands": [],
                "tables": [],
                "gap_ids": [],
                "origins": [],
                "requirement_priorities": {},
                "request_regions": [],
            }
        held = combined[key]
        priorities = action.get("requirement_priorities") or {
            name: action.get("priority", 1) for name in action.get("requirements", ())
        }
        for name, value in priorities.items():
            held["requirement_priorities"][name] = max(value, held["requirement_priorities"].get(name, 0))
        for field, values in (
            ("requirements", action.get("requirements", ())),
            ("recipe_ids", action.get("recipe_ids", [action["recipe_id"]])),
            ("sections", action.get("sections", [action["section"]])),
            ("commands", action.get("commands", ())),
            ("tables", action.get("tables", ())),
            ("gap_ids", action.get("gap_ids", ())),
            ("origins", action.get("origins", ())),
            ("request_regions", action.get("request_regions", ())),
        ):
            for value in values:
                if value not in held[field]:
                    held[field].append(value)
    for (source, host), action in combined.items():
        action["id"] = stable_id(source, host, "device-collection")
        action["priority"] = sum(action["requirement_priorities"].values())
        per_requirement: dict[str, list[tuple[int, int, int]]] = {}
        for region in action["request_regions"]:
            sources = region.get("sources") or region.get("src") or ()
            if sources and isinstance(sources[0], (list, tuple)):
                intervals = [tuple(item) for item in sources]
            else:
                intervals = _intervals(list(sources))
            per_requirement.setdefault(region.get("requirement", ""), []).extend(intervals)
        action["affected_source_addresses"] = sum(
            hi - lo + 1 for intervals in per_requirement.values() for _af, lo, hi in _merge(intervals)
        )
        action["ranking"] = {
            "distinct_requirement_priority": action["priority"],
            "affected_source_addresses": action["affected_source_addresses"],
            "collection_actions": 1,
            "cost_class": action.get("cost_class", "device-fetch"),
        }
    return sorted(
        combined.values(),
        key=lambda a: (-a["priority"], -a["affected_source_addresses"], a.get("cost_rank", 1), a["id"]),
    )


def troubleshoot(
    result: dict,
    manifest: Any,
    request: dict,
    *,
    priority: int = 1,
    device_uids: set[str] | None = None,
    requirement_id: str | None = None,
) -> dict:
    """The evidence gaps of one evaluation result and the collection actions for them.

    A RIB collection action requires a not-established part that ends in a
    routing gap, or a `not-observed` gap of the result. The detail of a routing
    gap separates an incomplete read from a RIB side table that is unavailable
    after a complete read. A gap whose collector has no recipe, or whose section
    or table is `unsupported`, has no action. After a collection, a gap closes
    only when the collected data is published.
    """
    name = requirement_id or request["name"]
    base = {
        "gaps": [],
        "actions": [],
        "missing_evidence": result.get("missing_evidence", []),
        "evaluation": result,
        "scope": "Evidence-scoped devices; source/VRF scope remains conservative where absent.",
    }
    if not _unknown(result):
        return base
    if priority < 0:
        raise ValueError("requirement priority must be nonnegative")
    gaps: dict[str, dict[str, Any]] = {}
    routing_devices: set[str] = set()
    routing_unknown = False
    regions_by_device: dict[str, list[dict[str, Any]]] = {}
    for item in (result.get("evidence") or {}).get("items", ()):
        if item.get("side") == "before" or item.get("outcome") != "not-established":
            continue
        steps = item.get("steps") or ()
        if not steps:
            continue
        terminal = steps[-1]
        gap = dict(terminal.get("evidence_gap") or gap_from_step(terminal))
        region = {**item.get("request_region", {}), "requirement": name, "member": item.get("member")}
        if not region.get("sources") and not region.get("src"):
            region["sources"] = request["sources"]
            region["coverage_scope"] = "whole requirement; exact explanation region unavailable"
        gap.update(
            {"affected_requirements": [name], "request_regions": [region], "source": None, "host": None}
        )
        gap["id"] = _gap_id(gap)
        if gap["id"] in gaps:
            gaps[gap["id"]]["request_regions"].append(region)
        else:
            gaps[gap["id"]] = gap
        for related in gap.get("related_gaps", []):
            related = {
                **related,
                "affected_requirements": [name],
                "request_regions": [region],
                "source": None,
                "host": None,
            }
            related["id"] = _gap_id(related)
            gaps[related["id"]] = related
        if gap["code"] in {"routing-inputs-incomplete", "recursive-route-incomplete"}:
            routing_unknown = True
            device = terminal.get("device_uid")
            if device:
                routing_devices.add(device)
                regions_by_device.setdefault(device, []).append(region)
    for item in result.get("gaps", ()):
        code = str(item.get("code") or item.get("kind") or "unclassified")
        kind = item.get("gap_kind", item.get("kind"))
        if kind not in {"not-collected", "unsupported", "not-modeled"}:
            kind = "unclassified"
        gap = {
            "code": code,
            "kind": kind,
            "subject": item.get("context_uid") or item.get("subject"),
            "dimension": item.get("protocol", "routing"),
            "detail": item.get("detail", ""),
            "affected_requirements": [name],
            "recipe_id": None,
            "source": None,
            "host": None,
        }
        gap["id"] = _gap_id(gap)
        gaps[gap["id"]] = gap
        if code == "not-observed":
            routing_unknown = True
    # A missing-evidence line can be the detail of a gap with its subject as a
    # prefix ("tunnel on <device>: <detail>"). A line that ends with the detail of
    # a gap adds no gap.
    covered_text = {d for g in gaps.values() if (d := g.get("detail", ""))}
    for text in result.get("missing_evidence", ()):
        if not any(text.endswith(d) for d in covered_text):
            gap = {
                "id": stable_id(text),
                "code": "legacy-evidence-gap",
                "kind": "unclassified",
                "subject": None,
                "dimension": "processing",
                "detail": text,
                "affected_requirements": [name],
                "recipe_id": None,
                "source": None,
                "host": None,
            }
            gaps[gap["id"]] = gap
    actions = []
    source_types = {source.name: source.type for source in manifest.sources}
    families = {af for af, _lo, _hi in _intervals(request["sources"])}
    for device in manifest.devices if routing_unknown else ():
        subjects = set(device.device_uids)
        if device_uids is not None and not subjects.intersection(device_uids):
            continue
        if routing_devices and not subjects.intersection(routing_devices):
            continue
        collector = source_types.get(device.source, "")
        for af in sorted(families):
            recipe = routing_recipe(collector, af)
            section = recipe.section if recipe else f"rib-ipv{af}"
            observed = device.sections.get(section)
            table = device.tables.get("rib")
            section_status = observed.status if observed else None
            table_status = table.status if table else None
            sub_sections = {
                key: value.status
                for key, value in device.sections.items()
                if key.startswith(f"{section}_table_")
            }
            section_complete = section_status in {"ok", "empty"} and all(
                status in {"ok", "empty"} for status in sub_sections.values()
            )
            table_complete = table_status in {"complete", "complete-empty", "unchanged"}
            if recipe and section_complete and table_complete:
                continue
            runnable = (
                recipe is not None and section_status != "unsupported" and table_status != "unsupported"
            )
            detail = "Required routing observation is absent or incomplete."
            if not recipe:
                detail = "This collector has no supported RIB read for the requested address family."
            elif not runnable:
                detail = (
                    "Collection reports this feature unavailable; "
                    "repeating the read is not a supported remedy."
                )
            elif section_complete and not table_complete:
                detail = (
                    "The read completed, but the RIB side table is unavailable; inspect publication failures."
                )
            gap = {
                "code": "routing-observation-missing",
                "kind": "not-collected",
                "subject": list(device.device_uids),
                "dimension": f"ipv{af}-rib",
                "source": device.source,
                "host": device.host,
                "detail": detail,
                "affected_requirements": [name],
                "recipe_id": recipe.id if runnable and recipe is not None else None,
                "collection_status": {
                    "section": section_status,
                    "table": table_status,
                    "subsections": sub_sections,
                },
                "freshness": {"carried": device.carried, "observed_ms": table.observed_ms if table else None},
                "collection_capability": "supported" if runnable else "unavailable",
            }
            gap["id"] = _gap_id(gap)
            gaps[gap["id"]] = gap
            if not runnable or recipe is None:
                continue
            regions = [region for uid in sorted(subjects) for region in regions_by_device.get(uid, ())]
            if not regions:
                regions = [
                    {"requirement": name, "sources": request["sources"], "coverage_scope": "conservative"}
                ]
            actions.append(
                {
                    "id": stable_id(device.source, device.host, recipe.id),
                    "recipe_id": recipe.id,
                    "source": device.source,
                    "host": device.host,
                    "section": section,
                    "tables": ["rib"],
                    "commands": list(recipe.commands),
                    "scope": "device",
                    "requirements": [name],
                    "priority": priority,
                    "state": "available",
                    "request_regions": regions,
                    "prerequisites": list(recipe.prerequisites),
                    "cost_class": recipe.cost_class,
                    "reason": "Collect the whole device, await a committed snapshot, then reevaluate.",
                }
            )
    # A `not-collected` gap of the policy, interface or topology dimension gets one
    # action per missing section of its collector. A section with the status
    # `unsupported` gets no action.
    from hst.path.gates.coverage import _POLICY_SECTIONS

    observation_gaps = [
        g
        for g in gaps.values()
        if g.get("kind") == "not-collected" and g.get("dimension") in {"policy", "interface", "topology"}
    ]
    for gap in observation_gaps:
        subject = gap.get("subject")
        subjects = {subject} if isinstance(subject, str) else set(subject or ())
        for device in manifest.devices:
            if subjects and not subjects.intersection(device.device_uids):
                continue
            if device_uids is not None and not set(device.device_uids).intersection(device_uids):
                continue
            collector = source_types.get(device.source, "")
            sections = (
                _POLICY_SECTIONS.get(collector, ())
                if gap["dimension"] == "policy"
                else ("addrs", "links", "config")
                if collector == "vyos"
                else ("interfaces", "neighbors", "arp")
                if collector in {"nxos", "iosxe", "iosxr"}
                else ("endpoint",)
                if collector == "apic"
                else ("devices", "networks", "clients")
            )
            for section in sorted(sections):
                status = device.sections.get(section)
                if status is not None and status.status in {"ok", "empty", "unsupported"}:
                    continue
                recipe = section_recipe(collector, section)
                if recipe is None:
                    continue
                derived = {
                    **gap,
                    "source": device.source,
                    "host": device.host,
                    "section": section,
                    "recipe_id": recipe.id,
                    "collection_status": status.model_dump() if status else None,
                    "evidence_refs": [
                        f.path for f in manifest.files if f.source == device.source and f.host == device.host
                    ],
                }
                derived["id"] = _gap_id(derived)
                gaps[derived["id"]] = derived
                actions.append(
                    {
                        "id": stable_id(device.source, device.host, recipe.id),
                        "recipe_id": recipe.id,
                        "source": device.source,
                        "host": device.host,
                        "section": section,
                        "tables": list(recipe.tables),
                        "commands": list(recipe.commands),
                        "scope": recipe.scope,
                        "requirements": [name],
                        "priority": priority,
                        "state": "available",
                        "request_regions": gap.get("request_regions", []),
                        "gap_ids": [derived["id"]],
                        "prerequisites": list(recipe.prerequisites),
                        "cost_class": recipe.cost_class,
                        "reason": "Collect the complete collector input and reevaluate after publication.",
                    }
                )
    return {**base, "gaps": list(gaps.values()), "actions": rank_actions(actions)}


def portfolio(results: Sequence[tuple[str, int, dict]]) -> dict:
    """Rank the actions of the saved troubleshooting results together."""
    actions = []
    for identifier, priority, result in results:
        for action in result.get("actions", []):
            actions.append(
                {
                    **action,
                    "requirements": [identifier],
                    "requirement_priorities": {identifier: priority},
                    "request_regions": [
                        {**r, "requirement": identifier} for r in action.get("request_regions", [])
                    ],
                }
            )
    return {
        "actions": rank_actions(actions),
        "assessments": [identifier for identifier, _, _ in results],
        "ranking": (
            "Sum of distinct saved requirement priorities, affected source coverage, then collection cost."
        ),
    }
