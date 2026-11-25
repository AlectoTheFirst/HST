"""Authenticate declared failure membership against one collected snapshot.

The metadata of the caller is not evidence. The graph supplies the provenance
and the membership. The signed manifest supplies the source, the raw record and
the observation window. A manual inventory is a declaration.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from hst import path
from hst.core.manifest import SnapshotManifest

_RECORDS = """
MATCH (n:Obj) WHERE n.uid IN $uids AND n.collection_ts = $snap
OPTIONAL MATCH (member:Obj)-[membership:MEMBER_OF]->(n)
WHERE member.collection_ts = $snap AND membership.collection_ts = $snap
WITH n, collect({uid:member.uid, props:properties(membership)}) AS members
OPTIONAL MATCH (n)-[endpoint:ENDPOINT]->(iface:Interface)
WHERE iface.collection_ts = $snap AND endpoint.collection_ts = $snap
RETURN n.uid AS uid, labels(n) AS labels, properties(n) AS props,
       EXISTS { MATCH (connector:ZpaAppConnector)-[r:RUNS_ON]->(n)
                WHERE connector.collection_ts = $snap AND r.collection_ts = $snap } AS broker_host,
       members, collect(iface.uid) AS interfaces
LIMIT 1025
"""


def validate_failure_evidence(
    session: Any,
    manifest: SnapshotManifest | None,
    targets: Sequence[Mapping[str, Any]],
    domains: Sequence[Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Validate the target and domain declarations and return the gaps of each.

    At most 1024 entries are validated. A domain references its collected graph
    record by ``uid``. The direct MEMBER_OF set of the record must equal the
    declared member set. The validity window is checked at the pinned snapshot.
    """
    entries = [*targets, *domains]
    if len(entries) > 1024:
        raise ValueError("failure evidence validation is limited to 1024 entries")
    identities = {str(item["id"]): str(item.get("uid") or "") for item in entries}
    if len(identities) != len(entries):
        raise ValueError("failure evidence IDs must be unique")
    if manifest is not None and getattr(session, "cts", None) != manifest.snapshot_key:
        raise ValueError("failure evidence manifest and graph must use the same pinned snapshot")
    rows = path._read(session, _RECORDS, uids=sorted(set(identities.values()) - {""})) if manifest else []
    if len(rows) > 1024:
        raise ValueError("failure evidence query exceeded its bound")
    records = {row["uid"]: row for row in rows}
    sources = {s.name: s for s in manifest.sources} if manifest else {}
    domain_ids = {str(d["id"]) for d in domains}
    result: dict[str, dict[str, Any]] = {}
    for item in entries:
        uid = identities[str(item["id"])]
        record = records.get(uid, {})
        props = record.get("props", {})
        missing = []
        refs: list[dict[str, Any]] = []
        if not record:
            missing.append("The referenced object is absent from the pinned graph.")
        expected = (
            "FailureDomain"
            if str(item["id"]) in domain_ids
            else {"device": "Device", "interface": "Interface", "link": "WanLink", "tunnel": "Tunnel"}.get(
                str(item.get("kind"))
            )
        )
        broker_target = item.get("kind") == "device" and (
            "ZpaAppConnector" in record.get("labels", []) or record.get("broker_host") is True
        )
        if expected not in record.get("labels", []) and not broker_target:
            missing.append("The referenced graph object has a different or missing kind.")
        if str(item["id"]) not in domain_ids:
            units = (
                [
                    unit
                    for unit in manifest.devices
                    if unit.source in props.get("_sources", [])
                    and unit.effective_run == props.get("_run_id")
                    and sources.get(unit.source) is not None
                    and sources[unit.source].type != "manual"
                    and (item.get("kind") != "device" or uid in unit.device_uids or broker_target)
                ]
                if manifest
                else []
            )
            # `carried` means that this run wrote no raw file for the unit. A unit with
            # the outcome `collected`, `partial` or `unchanged` was fetched in this run.
            # `unchanged` means that the hash matched. A carried unit with another
            # outcome was observed in an earlier run.
            stale = [u for u in units if u.carried and u.outcome not in {"collected", "partial", "unchanged"}]
            if stale:
                missing.append(
                    "The target inventory is carried from an earlier run "
                    "and was not observed in this snapshot."
                )
            units = [unit for unit in units if unit not in stale]
            for unit in units:
                refs.extend(
                    {
                        "source": unit.source,
                        "collector": sources[unit.source].type,
                        "origin": "collected",
                        "host": unit.host,
                        "run_id": unit.effective_run,
                        "reference": file.path,
                        "sha256": file.sha256,
                        "observed_ms": unit.fetch_started_ms,
                    }
                    for file in (manifest.files if manifest else [])
                    if file.source == unit.source
                    and file.host == unit.host
                    and file.run_id == unit.effective_run
                )
            if not refs:
                missing.append("The target inventory has no matching collected manifest evidence.")
            if item.get("kind") in {"link", "tunnel"} and set(item.get("interfaces", [])) != set(
                record.get("interfaces", [])
            ):
                missing.append("Declared endpoint interfaces differ from recorded ENDPOINT membership.")
            result[str(item["id"])] = {
                "uid": uid,
                "provenance_validated": bool(refs),
                "evidence_complete": not missing,
                "evidence_refs": refs,
                "missing": missing,
            }
            continue
        source_name = props.get("source")
        source = sources.get(source_name)
        independent = bool(
            source
            and source.type != "manual"
            and props.get("collector") == source.type
            and props.get("origin") == "observed"
            and source_name in props.get("_sources", [])
        )
        if not independent:
            missing.append(
                "Independent collector/source provenance is absent; declarations remain conditional."
            )
        section = props.get("evidence_section")
        reference = props.get("evidence_reference")
        observed = props.get("observed_ms")
        start, end = props.get("valid_from_ms"), props.get("valid_until_ms")
        if not (
            manifest
            and isinstance(start, int)
            and isinstance(end, int)
            and start <= manifest.snapshot_key < end
            and isinstance(observed, int)
            and start <= observed <= manifest.snapshot_key
        ):
            missing.append("The recorded observation/validity window does not cover this snapshot.")
        units = (
            [
                d
                for d in manifest.devices
                if d.source == source_name
                and d.effective_run == props.get("_run_id")
                and d.host == props.get("evidence_host")
            ]
            if manifest
            else []
        )
        for unit in units:
            outcome = unit.sections.get(section)
            files = (
                [
                    f
                    for f in manifest.files
                    if f.source == unit.source and f.host == unit.host and f.run_id == unit.effective_run
                ]
                if manifest
                else []
            )
            if (
                outcome
                and outcome.status == "ok"
                and isinstance(observed, int)
                and unit.fetch_started_ms is not None
                and unit.fetch_finished_ms is not None
                and unit.fetch_started_ms <= observed <= unit.fetch_finished_ms
                and reference
                and any(reference in (f.path, f.sha256) for f in files)
            ):
                refs.append(
                    {
                        "source": unit.source,
                        "collector": source.type if source else None,
                        "origin": props.get("origin"),
                        "host": unit.host,
                        "run_id": unit.effective_run,
                        "section": section,
                        "reference": reference,
                        "observed_ms": observed,
                    }
                )
        if not refs:
            missing.append(
                "No successful manifest section and raw/file reference authenticates this observation."
            )
        if str(item["id"]) in domain_ids:
            wanted = {identities.get(str(m), "") for m in item.get("members", [])}
            members = [m for m in record.get("members", []) if m.get("uid")]
            if not wanted or "" in wanted or wanted != {m["uid"] for m in members}:
                missing.append(
                    "Declared domain membership differs from the complete recorded direct membership."
                )
            if any(m.get("props", {}).get("_run_id") != props.get("_run_id") for m in members):
                missing.append("Membership edges and the domain lack a common recorded evidence run.")
        elif item.get("kind") in {"link", "tunnel"} and set(item.get("interfaces", [])) != set(
            record.get("interfaces", [])
        ):
            missing.append("Declared endpoint interfaces differ from recorded ENDPOINT membership.")
        result[str(item["id"])] = {
            "uid": uid,
            "provenance_validated": independent and bool(refs),
            "evidence_complete": not missing,
            "evidence_refs": refs,
            "validity": {
                "observed_ms": observed,
                "valid_from_ms": start,
                "valid_until_ms": end,
                "snapshot_ms": manifest.snapshot_key if manifest else None,
            },
            "missing": missing,
        }
    # The validated memberships are recorded correlated failures. A correlation
    # that is not recorded stays unknown.
    result["_summary"] = {
        "independent_diversity_established": False,
        "scope": "Validated recorded failure memberships; unrecorded domains remain unknown.",
    }
    return result
