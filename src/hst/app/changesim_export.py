"""The change-simulation export renders one policy simulation as three files."""

from __future__ import annotations

import csv
import io
import json
import zipfile
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from hst import path as pathmod

# The one bound on the file, in CSV detail rows (path rows and prefix rows).
MAX_DETAIL_ROWS = 50_000

_ZIP_DATE = (1980, 1, 1, 0, 0, 0)

_CSV_COLUMNS = [
    "section",
    "flow_src",
    "flow_dst",
    "flow_port",
    "flow_proto",
    "destination",
    "route_prefix",
    "egress",
    "next_hop",
    "routing_table",
    "before",
    "before_decided_by",
    "before_rulebase",
    "after",
    "after_decided_by",
    "after_rulebase",
    "changed",
    # For a flow with `basis_uncertain`, `changed` reads "not established".
    "not_established_because",
    "note",
    # Set only for a flow with an MTU request.
    "mtu_before_outcome",
    "mtu_before_ceiling",
    "mtu_before_bottleneck",
    "mtu_after_outcome",
    "mtu_after_ceiling",
    "mtu_after_bottleneck",
    "mtu_uncovered_after",
    "context_uid",
    "prefix",
    "level",
    "no_next_hop_left",
    "no_next_hop_left_at_level",
    "next_hops_before",
    "next_hops_after",
    "withdrawn_next_hops",
]

# Every Device the change set alters, with the sources of its `_sources` stamp (core/loader.py).
_DEVICE_SOURCES = """
MATCH (d:Device:Obj)
WHERE d.uid IN $devices AND NOT d:Retired
  AND d.collection_ts = $snap
RETURN d.uid AS uid, d.hostname AS hostname, d._sources AS sources
ORDER BY d.uid"""


def sources_for(session: Any, devices: Sequence[str]) -> list[str]:
    """The sources that reported the devices this change set alters. The
    session must be pinned.
    """
    if not devices:
        return []
    names: set[str] = set()
    for row in pathmod._read(session, _DEVICE_SOURCES, devices=list(devices)):
        for name in row.get("sources") or ():
            if name:
                names.add(str(name))
    return sorted(names)


# --- the header of both files ---------------------------------------------


def _collection_date(snapshot: int | None) -> str:
    """The run's collection timestamp as an ISO date, or a statement that the
    graph has no run pointer."""
    if snapshot is None:
        return "no recorded collection date"
    return datetime.fromtimestamp(snapshot / 1000, tz=UTC).isoformat(timespec="seconds")


def _sources_phrase(sources: Sequence[str]) -> str:
    if not sources:
        return "no source recorded on the devices this change alters"
    if len(sources) == 1:
        return f"the source {sources[0]}"
    return "the sources " + ", ".join(sources)


def _intent_summary(intents: Sequence[Mapping[str, Any]]) -> str:
    parts = []
    for intent in intents:
        params = intent.get("params") or {}
        target = params.get("rulebase") or params.get("device") or params.get("zone") or ""
        parts.append(f"{intent.get('kind')}{f' on {target}' if target else ''}")
    return "; ".join(parts) if parts else "none"


def _walk_sentence(walk: Mapping[str, Any] | None) -> str:
    """Whether a limit stopped the walk, in one sentence."""
    if not walk:
        return "Walk: the change set denies no address any recorded route uses as a next hop."
    levels = walk.get("levels_walked", 0)
    if walk.get("complete", True):
        return f"Walk: ran to level {levels}, and no limit stopped it."
    named = {
        "depth": (
            f"the depth limit of {walk.get('depth')}, with "
            f"{walk.get('prefixes_not_followed_at_the_depth_limit', 0)} prefix(es) stranded at the "
            "last level whose own dependents were not followed"
        ),
        "site_boundary": (
            "the site boundary, with "
            f"{walk.get('prefixes_not_followed_at_the_site_boundary', 0)} prefix(es) outside the "
            "selected sites that lose a recorded next hop"
        ),
    }
    cut = [named[limit] for limit in walk.get("limits") or () if limit in named]
    return (
        f"Walk: ran to level {levels} and a limit stopped it: "
        + " and ".join(cut)
        + ". This file is part of the consequence, not all of it."
    )


def header_lines(
    body: Mapping[str, Any],
    *,
    snapshot: int | None,
    sources: Sequence[str],
    sites_requested: Sequence[str] | None,
    trimmed: int,
) -> list[str]:
    """The header sentences of both files, in a fixed order."""
    walk = ((body.get("routing_consequence") or {}).get("walk")) or None
    scope = (body.get("routing_consequence") or {}).get("site_scope") or {}
    intents = body.get("intents") or []
    run = "none recorded" if snapshot is None else str(snapshot)

    if walk:
        depth_line = (
            f"Depth: {walk.get('depth')} level(s) of the route dependency chain, "
            f"of a cap of {walk.get('depth_cap')}."
        )
        if walk.get("depth_clamped"):
            depth_line += f" A depth of {walk.get('depth_requested')} was asked for and run at the cap."
    else:
        depth_line = "Depth: no routing walk was run, so no depth applied."

    if sites_requested:
        site_line = f"Site filter: {', '.join(sites_requested)}."
        not_found = scope.get("sites_not_found") or []
        if not_found:
            site_line += f" {', '.join(not_found)} matched no site in this snapshot."
    else:
        site_line = "Site filter: none, so the walk covered the whole estate."

    if trimmed:
        detail_line = (
            f"Detail: trimmed at {MAX_DETAIL_ROWS} rows by this file's own guard; "
            f"{trimmed} further row(s) are not in it."
        )
    else:
        detail_line = f"Detail: complete; the guard of {MAX_DETAIL_ROWS} rows trimmed nothing."

    return [
        "HST change simulation.",
        (
            f"Impact stated as of the collection date {_collection_date(snapshot)}, from "
            f"{_sources_phrase(sources)}, run id {run}."
        ),
        depth_line,
        site_line,
        f"Intents ({len(intents)}): {_intent_summary(intents)}.",
        _walk_sentence(walk),
        detail_line,
        (
            "Computed from an imported snapshot and from the configuration that run recorded, "
            "not from device state."
        ),
    ]


# --- the tabular half -----------------------------------------------------


def _side_word(side: Mapping[str, Any] | None) -> str:
    """What one side of a compared path decided. A side that is absent is a path
    only the other trace walked."""
    if not side:
        return "no path"
    if side.get("blocked"):
        return "blocked"
    if side.get("indeterminate"):
        return "not decided"
    return "permitted"


def _hop_text(hop: Mapping[str, Any]) -> str:
    kind = "static" if hop.get("kind") == "STATIC_ROUTE" else (hop.get("protocol") or "learned")
    return f"{hop.get('next_hop')} ({kind})"


def _hop_list(hops: Sequence[Mapping[str, Any]]) -> str:
    return "; ".join(_hop_text(h) for h in hops) if hops else "none"


def _withdrawn_list(hops: Sequence[Mapping[str, Any]]) -> str:
    if not hops:
        return "none"
    return "; ".join(
        f"{_hop_text(h)}: {h['withdrawn_because']}" if h.get("withdrawn_because") else _hop_text(h)
        for h in hops
    )


def _uid_list(uids: Sequence[str]) -> str:
    return "; ".join(uids)


def _mtu_row_fields(prefix: str, side: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return `mtu_{prefix}_outcome`, `mtu_{prefix}_ceiling` and
    `mtu_{prefix}_bottleneck` for one side of one path row.

    The result is empty for a side without `mtu_outcome`."""
    if not side or "mtu_outcome" not in side:
        return {}
    return {
        f"mtu_{prefix}_outcome": side.get("mtu_outcome"),
        f"mtu_{prefix}_ceiling": side.get("mtu_known_ceiling_bytes"),
        f"mtu_{prefix}_bottleneck": _uid_list(side.get("mtu_bottleneck") or ()),
    }


_NOT_ESTABLISHED = "not established"


def _reasons_text(entry: Mapping[str, Any]) -> str:
    """The flow's `basis_uncertain_reasons`, joined, or a stated absence."""
    reasons = [str(r) for r in entry.get("basis_uncertain_reasons") or ()]
    return "; ".join(reasons) if reasons else "no reason was recorded"


def detail_rows(body: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Every row of the CSV, in file order and before the guard.

    The path rows come first, flow by flow in the order of the trace. The
    affected prefixes follow, VRF by VRF. Both come from a `detail=True` run
    and are not grouped and not capped.

    A path row whose flow had an MTU request also has the seven `mtu_*`
    columns (`_mtu_row_fields`).
    """
    rows: list[dict[str, Any]] = []
    for entry in body.get("flows") or ():
        flow = entry.get("flow") or {}
        uncertain = bool(entry.get("basis_uncertain"))
        for path in entry.get("path_rows") or ():
            before = path.get("before")
            after = path.get("after")
            row = {
                "section": "flow_path",
                "flow_src": flow.get("src"),
                "flow_dst": flow.get("dst"),
                "flow_port": flow.get("port"),
                "flow_proto": flow.get("proto"),
                "destination": path.get("destination"),
                "route_prefix": path.get("route_prefix"),
                "egress": path.get("egress"),
                "next_hop": path.get("next_hop"),
                "routing_table": path.get("table"),
                "before": _side_word(before),
                "before_decided_by": (before or {}).get("decided_by"),
                "before_rulebase": (before or {}).get("rulebase"),
                "after": _side_word(after),
                "after_decided_by": (after or {}).get("decided_by"),
                "after_rulebase": (after or {}).get("rulebase"),
                "changed": _NOT_ESTABLISHED if uncertain else path.get("changed"),
                "not_established_because": _reasons_text(entry) if uncertain else None,
                "note": path.get("note"),
            }
            row.update(_mtu_row_fields("before", before))
            after_fields = _mtu_row_fields("after", after)
            if after_fields:
                after_fields["mtu_uncovered_after"] = _uid_list((after or {}).get("mtu_uncovered") or ())
            row.update(after_fields)
            rows.append(row)

    withdrawal = (body.get("routing_consequence") or {}).get("next_hop_withdrawal") or {}
    for vrf in withdrawal.get("vrfs") or ():
        for prefix in vrf.get("prefixes") or ():
            rows.append(
                {
                    "section": "withdrawn_prefix",
                    "context_uid": vrf.get("context_uid"),
                    "prefix": prefix.get("prefix"),
                    "level": prefix.get("level"),
                    "no_next_hop_left": prefix.get("no_next_hop_left"),
                    "no_next_hop_left_at_level": prefix.get("no_next_hop_left_at_level"),
                    "next_hops_before": _hop_list(prefix.get("next_hops_before") or []),
                    "next_hops_after": _hop_list(prefix.get("next_hops_after") or []),
                    "withdrawn_next_hops": _withdrawn_list(prefix.get("withdrawn_next_hops") or []),
                }
            )
    return rows


def _csv_text(header: Sequence[str], rows: Sequence[Mapping[str, Any]]) -> str:
    out = io.StringIO(newline="")
    for line in header:
        out.write(f"# {line}\n")
    writer = csv.DictWriter(out, fieldnames=_CSV_COLUMNS, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: _cell(row.get(k)) for k in _CSV_COLUMNS})
    return out.getvalue()


# The first characters that make a spreadsheet read a cell as a formula.
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def _cell(value: Any) -> str:
    """The text of one cell. A text that starts with a character of
    `_FORMULA_START` gets a leading apostrophe. A number keeps its sign."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, str) and value.startswith(_FORMULA_START):
        return f"'{value}"
    return str(value)


# --- the prose half -------------------------------------------------------


def _md_intents(body: Mapping[str, Any]) -> list[str]:
    lines = ["## Intents", ""]
    intents = body.get("intents") or []
    if not intents:
        lines.append("None were evaluated.")
        return [*lines, ""]
    lines.append("The change set that was evaluated, in the order it was applied.")
    lines.append("")
    for i, intent in enumerate(intents, start=1):
        params = ", ".join(f"{k}: {v}" for k, v in sorted((intent.get("params") or {}).items()))
        lines.append(f"{i}. `{intent.get('kind')}`: {params or 'no params'}")
    return [*lines, ""]


def _md_rulebases(body: Mapping[str, Any]) -> list[str]:
    derived = body.get("rulebases_derived") or []
    if not derived:
        return []
    lines = ["## Rulebases derived from the device", ""]
    if body.get("rulebase_derivation"):
        lines += [str(body["rulebase_derivation"]), ""]
    for report in derived:
        lines.append(f"### Intent {report.get('intent_index')} on {report.get('device')}")
        lines.append("")
        lines.append(f"Basis: {report.get('basis')}")
        lines.append("")
        lines.append(
            "Bound to the device: " + (", ".join(report.get("rulebases_bound_to_the_device") or []) or "none")
        )
        lines.append("")
        for rulebase in report.get("rulebases") or []:
            name = rulebase.get("name")
            lines.append(f"- `{rulebase.get('uid')}`{f' ({name})' if name else ''}")
            for bound in rulebase.get("bound_by") or []:
                side = bound.get("side") or "either side"
                interface = bound.get("interface") or "no interface named"
                lines.append(f"  - {bound.get('binding')}: {side}, {interface}")
        serving = report.get("interfaces_serving_the_stated_addresses") or {}
        for side, interfaces in serving.items():
            for interface in interfaces:
                served = ", ".join(interface.get("serves") or [])
                lines.append(f"- {side} side: `{interface.get('uid')}` serves {served}")
        if report.get("model_error"):
            lines.append(f"- Model error: {report['model_error']}")
        lines.append("")
    return lines


# --- the per-flow prose: groups and the MTU outcome ------------------------


def _device_of_subject(uid: str) -> str | None:
    """Return the device of a subject uid (an Interface or a Port, `mtu_subjects`).

    The device is the part before the `/if/` or `/port/` segment. The result
    is `None` for a uid without such a segment."""
    for sep in ("/if/", "/port/"):
        if sep in uid:
            return uid.split(sep, 1)[0]
    return None


def _mtu_outcome_changed(entry: Mapping[str, Any]) -> bool:
    """Return whether the MTU outcome of any group of this flow differs
    between before and after. A `None` on one side only is a difference."""
    for group in (entry.get("paths") or {}).get("groups") or ():
        before = group.get("mtu_before")
        after = group.get("mtu_after")
        if before is None and after is None:
            continue
        if (before or {}).get("outcome") != (after or {}).get("outcome"):
            return True
    return False


_MTU_OUTCOME_WORDS = {
    "pass": "pass",
    "fail": "fail",
    "fragmentation_required": "fragmentation required",
    "conditional": "conditional",
    "fits_known_limits": "fits known limits",
    "unknown": "unknown",
    "not_assessed": "not assessed",
}


def _mtu_side_phrase(side: Mapping[str, Any] | None) -> str | None:
    """Return one side of the MTU outcome of one group, in words.

    The phrase holds the outcome, the place of the decision and the ceiling
    bytes there, with `"frame"` appended when the bottleneck is a Port. The
    result is `None` for a side without an MTU result."""
    if not side:
        return None
    outcome = _MTU_OUTCOME_WORDS.get(str(side.get("outcome")), str(side.get("outcome")))
    bottleneck = list(side.get("bottleneck") or ())
    where = "; ".join(bottleneck) if bottleneck else "no named subject"
    ceiling = side.get("known_ceiling_bytes")
    if ceiling is None:
        size = "unknown size"
    else:
        frame = " frame" if any("/port/" in b for b in bottleneck) else ""
        size = f"{ceiling:,} B{frame}"
    return f"{outcome} at {where} ({size})"


def _mtu_line(group: Mapping[str, Any]) -> str | None:
    parts = []
    before = _mtu_side_phrase(group.get("mtu_before"))
    if before:
        parts.append(f"{before} before")
    after = _mtu_side_phrase(group.get("mtu_after"))
    if after:
        parts.append(f"{after} after")
    return "MTU: " + "; ".join(parts) if parts else None


def _md_group(group: Mapping[str, Any], *, uncertain: bool = False) -> str:
    destinations = list(group.get("destinations") or ())
    extra = group.get("destination_count", 0) - len(destinations)
    dest_text = ", ".join(destinations) or "no destination"
    if extra > 0:
        dest_text += f" (+{extra} more)"
    next_hops = ", ".join(group.get("next_hops") or ()) or "none"
    note = f"; {group['note']}" if group.get("note") else ""
    changed = f" ({_NOT_ESTABLISHED})" if uncertain else " (changed)" if group.get("changed") else ""
    return (
        f"- {group.get('path_count', 0)} path(s) to {dest_text} via {next_hops}, "
        f"egress {group.get('egress') or 'none'}: {_side_word(group.get('before'))} before, "
        f"{_side_word(group.get('after'))} after{changed}{note}"
    )


def _md_flows(body: Mapping[str, Any]) -> list[str]:
    """Return one subsection per flow.

    A subsection holds the groups of the flow (`fw_overlay.compare_paths`, the
    grouping of the pane). For a flow with an MTU request, one `MTU:` line
    follows, read from the first group with an MTU outcome.
    """
    flows = body.get("flows") or ()
    if not flows:
        return []
    lines = ["## Flows", ""]
    for i, entry in enumerate(flows, start=1):
        flow = entry.get("flow") or {}
        port = f", port {flow['port']}" if flow.get("port") else ""
        lines.append(f"### {i}. {flow.get('src')} to {flow.get('dst')}{port}/{flow.get('proto') or 'tcp'}")
        lines.append("")
        groups = (entry.get("paths") or {}).get("groups") or ()
        uncertain = bool(entry.get("basis_uncertain"))
        for group in groups:
            lines.append(_md_group(group, uncertain=uncertain))
        lines.append("")
        if uncertain:
            lines.append(f"Comparison {_NOT_ESTABLISHED}: {_reasons_text(entry)}")
            lines.append("")
        mtu_line = next(filter(None, (_mtu_line(g) for g in groups)), None)
        if mtu_line:
            lines.append(mtu_line)
            lines.append("")
    return lines


def _md_counts(body: Mapping[str, Any]) -> list[str]:
    lines = ["## Counts", ""]
    lines.append(f"- Flows traced: {body.get('flow_count', 0)}")
    lines.append(f"- Flows whose result changed: {body.get('results_changed', 0)}")
    if body.get("results_not_established"):
        lines.append(f"- Flows whose comparison is not established: {body['results_not_established']}")
    flows = body.get("flows") or ()
    lines.append(f"- Flows whose MTU outcome changed: {sum(1 for e in flows if _mtu_outcome_changed(e))}")
    lines.append(f"- Paths before: {body.get('path_count_before', 0)}")
    lines.append(f"- Paths after: {body.get('path_count_after', 0)}")
    lines.append(f"- Paths blocked before: {body.get('paths_blocked_before', 0)}")
    lines.append(f"- Paths blocked after: {body.get('paths_blocked_after', 0)}")
    lines.append(f"- Paths changed: {body.get('paths_changed', 0)}")
    # An `interface.set_mtu` intent binds to an interface, and the devices of
    # its `mtu_subjects` are added to `changed_devices` here.
    mtu_devices = {d for uid in body.get("mtu_subjects") or () for d in [_device_of_subject(uid)] if d}
    devices = sorted({*(body.get("changed_devices") or ()), *mtu_devices})
    lines.append(f"- Devices the change set alters: {', '.join(devices) or 'none'}")
    if body.get("flows_derived"):
        lines.append(f"- Flows derived by the tool: {body.get('flows_derived_count', 0)}")
        lines.append(f"- Further derived candidates not traced: {body.get('flows_derived_not_traced', 0)}")
    return [*lines, ""]


def _md_routing(body: Mapping[str, Any]) -> list[str]:
    routing = body.get("routing_consequence")
    if not routing:
        return [
            "## Routing consequence",
            "",
            "The change set denies no address any recorded route uses as a next hop, and no "
            "recorded peering sits inside the denied set.",
            "",
        ]
    lines = ["## Routing consequence", "", str(routing.get("headline") or ""), ""]
    for label, key in (("Basis", "basis"), ("Direction rule", "direction_rule")):
        if routing.get(key):
            lines += [f"{label}: {routing[key]}", ""]
    denied = routing.get("denied_addresses") or {}
    lines.append(f"- Traffic denied to: {', '.join(denied.get('traffic_to') or []) or 'none'}")
    lines.append(f"- Traffic denied from: {', '.join(denied.get('traffic_from') or []) or 'none'}")
    withdrawal = routing.get("next_hop_withdrawal") or {}
    lines.append(f"- Prefixes that lose a recorded next hop: {withdrawal.get('prefix_count', 0)}")
    lines.append(
        f"- Prefixes left with no recorded next hop: {withdrawal.get('prefixes_with_no_next_hop_left', 0)}"
    )
    lines.append(f"- Route edges withdrawn: {withdrawal.get('withdrawn_route_edge_count', 0)}")
    lines.append(f"- Recorded routes through a denied next hop: {routing.get('recorded_route_count', 0)}")
    lines.append(
        "- Recorded peerings to a denied address: "
        f"{len(routing.get('bgp_sessions_to_a_denied_address') or [])}"
    )
    lines.append("")
    lines.append("The prefixes themselves are the `withdrawn_prefix` rows of the CSV beside this file.")
    lines.append("")
    if routing.get("bgp_prediction"):
        lines += ["### The BGP prediction beside it", "", str(routing["bgp_prediction"]), ""]
        lines.append(
            f"- Prefixes predicted withdrawn: {len(routing.get('predicted_prefixes_withdrawn') or [])}"
        )
        lines.append(f"- Prefixes predicted added: {len(routing.get('predicted_prefixes_added') or [])}")
        lines.append(f"- Rows whose best path changed: {len(routing.get('predicted_rows_changed') or [])}")
        lines.append("")
    return lines


def _md_walk(body: Mapping[str, Any]) -> list[str]:
    routing = body.get("routing_consequence") or {}
    walk = routing.get("walk")
    if not walk:
        return []
    lines = ["## How far the withdrawal was followed", ""]
    lines.append(str(walk.get("definition") or ""))
    lines.append("")
    lines.append(
        f"- Depth asked for: {walk.get('depth_requested')}; depth it ran at: {walk.get('depth')}; "
        f"cap: {walk.get('depth_cap')}"
    )
    lines.append(f"- Levels walked: {walk.get('levels_walked')}")
    lines.append(f"- Complete: {'yes' if walk.get('complete') else 'no'}")
    lines.append(f"- Limits: {', '.join(walk.get('limits') or []) or 'none'}")
    lines.append("")
    levels = walk.get("levels") or []
    if levels:
        lines.append("| Level | Prefixes | No next hop left | Route edges withdrawn | VRFs |")
        lines.append("| --- | --- | --- | --- | --- |")
        for level in levels:
            lines.append(
                f"| {level.get('level')} | {level.get('prefix_count')} | "
                f"{level.get('prefixes_with_no_next_hop_left')} | "
                f"{level.get('withdrawn_route_edge_count')} | {level.get('vrf_count')} |"
            )
        lines.append("")
    if walk.get("note"):
        lines += [str(walk["note"]), ""]

    scope = routing.get("site_scope")
    if scope:
        lines += ["### The site filter", ""]
        lines.append(f"- Asked for: {', '.join(scope.get('sites_requested') or []) or 'none'}")
        lines.append(f"- Resolved: {', '.join(scope.get('sites_resolved') or []) or 'none'}")
        lines.append(
            f"- Named but not in this snapshot: {', '.join(scope.get('sites_not_found') or []) or 'none'}"
        )
        lines.append(f"- VRFs inside the filter: {scope.get('vrfs_in_scope', 0)}")
        lines.append(f"- VRFs outside it: {scope.get('vrfs_outside_the_selected_sites', 0)}")
        lines.append(f"- Prefixes not followed at the boundary: {scope.get('prefixes_not_followed', 0)}")
        lines.append("")
        if scope.get("note"):
            lines += [str(scope["note"]), ""]
    return lines


def _md_caveats(body: Mapping[str, Any]) -> list[str]:
    """Every caveat and model error the run named, in one section."""
    lines = ["## Caveats and model errors", ""]
    errors = body.get("model_errors") or []
    if errors:
        for error in errors:
            subject = error.get("subject")
            lines.append(
                f"- **{error.get('kind')}**: {error.get('detail')}" + (f" ({subject})" if subject else "")
            )
    else:
        lines.append("- The run named no model error.")
    lines.append("")

    warned = [
        (entry.get("flow") or {}, side, warning)
        for entry in body.get("flows") or ()
        for side in ("before", "after")
        for warning in (entry.get(side) or {}).get("warnings") or ()
    ]
    if warned:
        lines += ["### Tracer warnings, per flow", ""]
        for flow, side, warning in warned:
            lines.append(f"- {flow.get('src')} to {flow.get('dst')} ({side}): {warning}")
        lines.append("")

    if body.get("flows_derived"):
        lines += ["### How the flows were chosen", "", str(body["flows_derived"]), ""]
    return lines


def markdown_report(header: Sequence[str], body: Mapping[str, Any]) -> str:
    lines = ["# HST change simulation", ""]
    lines += [f"- {line}" for line in header]
    lines.append("")
    lines += _md_intents(body)
    lines += _md_rulebases(body)
    lines += _md_counts(body)
    lines += _md_flows(body)
    lines += _md_routing(body)
    lines += _md_walk(body)
    lines += _md_caveats(body)
    return "\n".join(lines).rstrip() + "\n"


# --- the two files together -----------------------------------------------


def render(
    body: Mapping[str, Any],
    *,
    snapshot: int | None,
    sources: Sequence[str],
    sites_requested: Sequence[str] | None = None,
) -> tuple[str, str, bool]:
    """The CSV and the Markdown for one simulation, and whether the guard
    trimmed rows."""
    rows = detail_rows(body)
    trimmed = max(len(rows) - MAX_DETAIL_ROWS, 0)
    header = header_lines(
        body,
        snapshot=snapshot,
        sources=sources,
        sites_requested=sites_requested,
        trimmed=trimmed,
    )
    return _csv_text(header, rows[:MAX_DETAIL_ROWS]), markdown_report(header, body), bool(trimmed)


def basename(snapshot: int | None) -> str:
    """The name of every entry in the archive, run id included."""
    return f"hst-change-simulation-{'unpinned' if snapshot is None else snapshot}"


def json_report(body: Mapping[str, Any]) -> str:
    """The full `simulate_change(detail=True)` body, as the zip's third file."""
    return json.dumps(body, sort_keys=True, indent=2, default=str)


def archive(csv_text: str, markdown_text: str, json_text: str, *, snapshot: int | None) -> bytes:
    """All three files of one run in one zip."""
    name = basename(snapshot)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as bundle:
        for suffix, text in ((".csv", csv_text), (".md", markdown_text), (".json", json_text)):
            info = zipfile.ZipInfo(f"{name}{suffix}", date_time=_ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            bundle.writestr(info, text)
    return buffer.getvalue()
