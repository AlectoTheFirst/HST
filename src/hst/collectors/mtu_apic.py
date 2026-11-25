"""APIC configured MTU evidence, scoped inheritance and conservative joins.

The physical MTU size basis and the active aggregate membership are not
verified. The observations hold configured values. They do not establish the
deployed state, the exact receive capacity or a spine/IPN path.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from hst.core import uid
from hst.core.identity import DeviceResolver, resolve_chassis
from hst.core.model import SectionOutcome
from hst.core.mtu import MtuObservation, canonical_json
from hst.core.mtu_profiles import emit_observation, observation_from_raw
from hst.core.normalize import iface_slug

from .base import RAW_OUTCOMES_KEY
from .util import GraphBuilder

MTU_POLICY_PATH = "/api/mo/uni/fabric/l2pol-default.json"
MTU_POLICY_DN = "uni/fabric/l2pol-default"
MTU_CLASSES = ("l2InstPol", "l3extRsPathL3OutAtt", "l3extVirtualLIfP", "pcRsMbrIfs")
MTU_OUTCOME_KEYS = tuple(f"mtu:{cls}" for cls in MTU_CLASSES)
MTU_MAX_PAGES = 100
_PATH = re.compile(
    r"^topology/pod-(?P<pod>\d+)/(?:paths-(?P<single>\d+)|protpaths-(?P<a>\d+)-(?P<b>\d+))"
    r"/pathep-\[(?P<port>[^\[\]]+)\]$"
)
_OUT = re.compile(r"^(uni/tn-[^/]+/out-[^/]+)(?:/|$)")


class MtuCaptureError(ValueError):
    def __init__(self, status: str, detail: str):
        super().__init__(detail)
        self.status = status


def validate_capture(rows: Any, cls: str) -> list[dict[str, Any]]:
    """Return `rows` when every row is a managed object of `cls` with a DN.
    An answer with HTTP success can hold an APIC error. `MtuCaptureError` is
    raised for it."""
    if not isinstance(rows, list):
        raise MtuCaptureError("malformed", f"{cls}: imdata is not a list")
    for mo in rows:
        if not isinstance(mo, dict):
            raise MtuCaptureError("malformed", f"{cls}: malformed managed object")
        if "error" in mo:
            attrs = mo["error"].get("attributes", {})
            code, detail = str(attrs.get("code", "")), str(attrs.get("text", "APIC error"))
            status = "unauthorized" if code in {"401", "403"} else "failed"
            if code == "122" and "unknown managed object class" in detail.lower():
                status = "unsupported"
            raise MtuCaptureError(status, detail)
        item = mo.get(cls)
        if not isinstance(item, dict) or not isinstance(item.get("attributes"), dict):
            raise MtuCaptureError("malformed", f"{cls}: unexpected managed object shape")
        if not isinstance(item["attributes"].get("dn"), str):
            raise MtuCaptureError("malformed", f"{cls}: missing DN")
    return rows


def _rows(raw: Mapping[str, Any], cls: str) -> list[dict[str, Any]]:
    outcome = raw.get(RAW_OUTCOMES_KEY, {}).get(f"mtu:{cls}", {})
    if outcome.get("status") in {"unauthorized", "unsupported", "failed", "malformed"}:
        return []
    try:
        return [mo[cls]["attributes"] for mo in validate_capture(raw.get(cls, []), cls)]
    except MtuCaptureError:
        return []


def mtu_sections(raw: Mapping[str, Any]) -> dict[str, SectionOutcome]:
    sections: dict[str, SectionOutcome] = {}
    outcomes = raw.get(RAW_OUTCOMES_KEY, {})
    for cls in MTU_CLASSES:
        key = f"mtu:{cls}"
        if key in outcomes:
            sections[key] = SectionOutcome.model_validate(outcomes[key])
        elif cls in raw:
            try:
                rows = validate_capture(raw[cls], cls)
                sections[key] = SectionOutcome(status="ok" if rows else "empty", row_count=len(rows))
            except MtuCaptureError as exc:
                sections[key] = SectionOutcome.model_validate({"status": exc.status, "detail": str(exc)})
        else:
            sections[key] = SectionOutcome(status="unknown", detail="not captured; enable capture_mtu")
    sections["mtu:operational"] = SectionOutcome(
        status="unsupported", detail="operational MTU/MRU API property semantics not validated"
    )
    sections["mtu:member_state"] = SectionOutcome(
        status="unsupported", detail="configured membership does not establish active forwarding members"
    )
    return sections


def _observation(
    *,
    fabric: str,
    subject: str,
    cls: str,
    attrs: Mapping[str, Any],
    field: str = "mtu",
    profile_id: str = "unknown",
    metric: str = "unknown",
    scope: str = "interface",
    enforcement: str = "unknown",
    **extra: Any,
) -> MtuObservation:
    return observation_from_raw(
        subject_uid=subject,
        source="apic",
        source_target=fabric,
        source_field=f"{cls}.{field}",
        raw_value=attrs.get(field),
        profile_id=profile_id,
        metric=metric,
        direction="both" if profile_id == "ip_packet" else "unknown",
        bound_kind="ceiling" if profile_id == "ip_packet" else "unknown",
        enforcement=enforcement,
        scope=scope,
        assertion_kind="configured",
        collector_version="2",
        raw_evidence_ref=f"{cls}:{attrs['dn']}:{field}",
        **extra,
    )


def node_device_uid(a: Mapping[str, Any], fabric: str, resolver: DeviceResolver) -> str:
    """Return the Device uid of one fabricNode. Every APIC stage (apic.py
    `_device_uid`) and this module use it. The registry resolves the serial of
    the node. The registry resolves the ref `<fabric>:<node dn>` when the node
    reports no serial, a placeholder serial, or a serial that another device
    holds in this run (`resolve_chassis`)."""
    return resolve_chassis(resolver, a.get("serial"), ("ref", f"{fabric}:{a['dn']}"), a.get("name"))


def _base_inventory(
    raw: Mapping[str, Any], fabric: str, resolver: DeviceResolver
) -> tuple[dict[str, str], dict[tuple[str, str], str]]:
    # apic.py `_device_uid` uses the same function. The subjects are the Device
    # nodes of the fabric stage.
    devices = {
        a["dn"]: node_device_uid(a, fabric, resolver) for a in _rows(raw, "fabricNode") if a.get("serial")
    }
    ports = {}
    for cls in ("l1PhysIf", "pcAggrIf"):
        for a in _rows(raw, cls):
            node_dn = "/".join(a["dn"].split("/")[:3])
            if node_dn in devices and a.get("id"):
                ports[(node_dn, iface_slug(a["id"]))] = f"{devices[node_dn]}/port/{uid.slug(a['id'])}"
    return devices, ports


def _physical(
    b: GraphBuilder,
    raw: Mapping[str, Any],
    fabric: str,
    devices: dict[str, str],
) -> None:
    physical_by_dn: dict[str, str] = {}
    lag_by_dn: dict[str, str] = {}
    for cls in ("l1PhysIf", "pcAggrIf"):
        for a in _rows(raw, cls):
            node_dn = "/".join(a["dn"].split("/")[:3])
            duid = devices.get(node_dn)
            if not duid or not a.get("id"):
                continue
            puid = f"{duid}/port/{uid.slug(a['id'])}"
            if cls == "pcAggrIf":
                lu = b.node(
                    "Lag",
                    uid.lag(duid, a["id"]),
                    name=a["id"],
                    dn=a["dn"],
                    member_state="unknown",
                    membership_basis="configured",
                )
                b.rel("ON", "Lag", lu, "Device", duid)
                b.rel("REALIZED_BY", "Lag", lu, "Port", puid)
                lag_by_dn[a["dn"]] = lu
            else:
                physical_by_dn[a["dn"]] = puid
            if "mtu" in a:
                emit_observation(
                    b,
                    "Port",
                    _observation(
                        fabric=fabric,
                        subject=puid,
                        cls=cls,
                        attrs=a,
                        enforcement="l2",
                        selector_json=canonical_json(
                            {"version": 1, "platform": "aci", "scope": "physical", "semantics": "pending"}
                        ),
                    ),
                )
    for a in _rows(raw, "pcRsMbrIfs"):
        # A member exists only when the relationship references two collected DNs.
        # No member/active state is inferred from an eth/po name or config protocol.
        parent = a["dn"].split("/rsmbrIfs-[", 1)[0]
        lag = lag_by_dn.get(parent)
        member = physical_by_dn.get(a.get("tDn", ""))
        if lag and member:
            b.rel(
                "MEMBER_OF",
                "Port",
                member,
                "Lag",
                lag,
                basis="configured",
                membership_state="unknown",
                forwarding_eligible="unknown",
                evidence_ref=a["dn"],
            )


def _fabric_default(
    b: GraphBuilder,
    raw: Mapping[str, Any],
    fabric: str,
) -> dict[int, MtuObservation]:
    rows = [a for a in _rows(raw, "l2InstPol") if a["dn"] == MTU_POLICY_DN]
    if len(rows) != 1 or "fabricMtu" not in rows[0]:
        return {}  # A duplicate or missing policy does not establish inheritance.
    a = rows[0]
    defaults = {}
    for af in (4, 6):
        obs = _observation(
            fabric=fabric,
            subject=uid.fabric(fabric),
            cls="l2InstPol",
            attrs=a,
            field="fabricMtu",
            profile_id="ip_packet",
            metric=f"ipv{af}_mtu_bytes",
            scope="fabric-l3out-default",
            enforcement="l3",
            policy_ref=MTU_POLICY_DN,
            enforcement_key="aci-l3out-ip",
            selector_json=canonical_json(
                {"version": 1, "applies_to": "l3out-inherit", "physical_fabric_capacity": "unresolved"}
            ),
        )
        emit_observation(b, "Fabric", obs)
        defaults[af] = obs
    return defaults


def _attachment_targets(
    attrs: Mapping[str, Any],
    cls: str,
    devices: Mapping[str, str],
    ports: Mapping[tuple[str, str], str],
) -> tuple[list[str], list[str], bool]:
    if cls == "l3extVirtualLIfP":
        dev = devices.get(attrs.get("nodeDn", ""))
        return [dev] if dev else [], [], False  # The anchor node is not a confirmed physical carrier.
    match = _PATH.fullmatch(attrs.get("tDn", ""))
    if match is None:
        return [], [], False
    nodes = [match["single"]] if match["single"] else [match["a"], match["b"]]
    dns = [f"topology/pod-{match['pod']}/node-{n}" for n in nodes]
    devs = [devices[dn] for dn in dns if dn in devices]
    known = [ports[(dn, iface_slug(match["port"]))] for dn in dns if (dn, iface_slug(match["port"])) in ports]
    return devs, known, len(devs) == len(nodes) and len(known) == len(nodes)


def _attachments(
    b: GraphBuilder,
    raw: Mapping[str, Any],
    fabric: str,
    devices: dict[str, str],
    ports: dict[tuple[str, str], str],
    defaults: dict[int, MtuObservation],
) -> None:
    outs = {a["dn"] for a in _rows(raw, "l3extOut")}
    for cls in ("l3extRsPathL3OutAtt", "l3extVirtualLIfP"):
        for a in _rows(raw, cls):
            parents = _OUT.match(a["dn"])
            if parents is None or parents[1] not in outs:
                continue
            devs, carriers, resolved = _attachment_targets(a, cls, devices, ports)
            iu = b.node(
                "Interface",
                uid.aci(fabric, a["dn"]),
                dn=a["dn"],
                name=a.get("ifInstT") or cls,
                kind="l3out-floating" if cls == "l3extVirtualLIfP" else "l3out-attachment",
                address=a.get("addr"),
                encap=a.get("encap"),
                path_dn=a.get("tDn"),
                attachment_resolved=resolved,
                attachment_basis="configured",
                mtu_operational_state="unknown",
                mtu_receive_state="unknown",
                ip_fragmentation="unsupported",
                ip_fragmentation_basis="documented-aci",
            )
            b.rel("PART_OF", "Interface", iu, "L3Out", uid.aci(fabric, parents[1]))
            if len(devs) == 1:
                b.rel("ON", "Interface", iu, "Device", devs[0])
            for pu in carriers:
                b.rel(
                    "BOUND_TO",
                    "Interface",
                    iu,
                    "Port",
                    pu,
                    basis="configured",
                    evidence_ref=a["dn"],
                    physical_path_known=False,
                )
            for af in (4, 6):
                inherited = a.get("mtu") == "inherit"
                policy = defaults.get(af)
                obs = _observation(
                    fabric=fabric,
                    subject=iu,
                    cls=cls,
                    attrs=a,
                    profile_id="ip_packet",
                    metric=f"ipv{af}_mtu_bytes",
                    enforcement="l3",
                    enforcement_key="aci-l3out-ip",
                    policy_ref=policy.uid if inherited and policy else None,
                    selector_json=canonical_json(
                        {
                            "version": 1,
                            "attachment_class": cls,
                            "attachment_resolved": resolved,
                            "fragmentation": "unsupported",
                        }
                    ),
                )
                if inherited:
                    props = obs.model_dump()
                    props["dependency_uids"] = [policy.uid] if policy else []
                    if policy and policy.normalized_value is not None:
                        props.update(
                            normalized_value=policy.normalized_value, resolution_state="inherited", gaps=[]
                        )
                    else:
                        props.update(gaps=["MTU_POLICY_UNRESOLVED"], resolution_state="unknown")
                    obs = MtuObservation.model_validate(props)
                emit_observation(b, "Interface", obs)


def normalize_mtu_apic(
    b: GraphBuilder, raw: Mapping[str, Any], fabric: str, resolver: DeviceResolver
) -> None:
    devices, ports = _base_inventory(raw, fabric, resolver)
    _physical(b, raw, fabric, devices)
    defaults = _fabric_default(b, raw, fabric)
    _attachments(b, raw, fabric, devices, ports, defaults)
