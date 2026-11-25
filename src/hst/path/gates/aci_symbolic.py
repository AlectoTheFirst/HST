"""Strict symbolic ACI contract evaluation over complete flow rectangles."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import hst.path as _path
from hst.core.aci_filter import (
    contract_bypass,
    endpoint_identity,
    filter_applies,
    filter_entry,
    reverse_contract_gap,
    vrf_enforcement,
)

from ..addrsets import _intersect, _ports
from ..state import Effect, FlowRegion, Rect

_ENDPOINTS = """
MATCH (e:Endpoint:Obj {collection_ts: $snap})-[h:HAS_IP]->(ip:IpAddress)
MATCH (e)-[ie:IN_EPG]->(epg:Epg)
WHERE NOT e:Retired AND NOT ip:Retired AND NOT epg:Retired
  AND h._retired_at IS NULL AND ie._retired_at IS NULL
  AND e.collection_ts = $snap
  AND ip.collection_ts = $snap
  AND epg.collection_ts = $snap
OPTIONAL MATCH (epg)-[ib:IN_BD]->(bd:BridgeDomain)-[iv:IN_VRF]->(vrf:VrfInstance)
WHERE ib._retired_at IS NULL AND iv._retired_at IS NULL
  AND NOT bd:Retired AND NOT vrf:Retired
  AND bd.collection_ts = $snap
  AND vrf.collection_ts = $snap
RETURN ip.ip AS ip, epg.uid AS epg_uid, epg.name AS epg_name,
       vrf.uid AS vrf_uid, vrf.pc_enf_pref AS pc_enf_pref,
       vrf.contract_bypass AS contract_bypass
ORDER BY ip.ip, epg.uid, vrf.uid
"""

_CONTRACTS = """
MATCH (src:Epg:Obj)-[cons:CONSUMES]->(contract:Contract)<-[prov:PROVIDES]-(dst:Epg)
WHERE cons._retired_at IS NULL AND prov._retired_at IS NULL
  AND NOT src:Retired AND NOT dst:Retired AND NOT contract:Retired
  AND src.collection_ts = $snap
  AND dst.collection_ts = $snap
  AND contract.collection_ts = $snap
OPTIONAL MATCH (contract)-[hs:HAS]->(subject:ContractSubject)
WHERE hs._retired_at IS NULL AND NOT subject:Retired
  AND subject.collection_ts = $snap
OPTIONAL MATCH (subject)-[uf:USES_FILTER]->(filter:AciFilter)-[he:HAS]->(entry:FilterEntry)
WHERE uf._retired_at IS NULL AND he._retired_at IS NULL
  AND NOT filter:Retired AND NOT entry:Retired
  AND filter.collection_ts = $snap
  AND entry.collection_ts = $snap
OPTIONAL MATCH (subject)-[ag:APPLIES_GRAPH]->(graph:ServiceGraphTemplate)
WHERE ag._retired_at IS NULL AND NOT graph:Retired
  AND graph.collection_ts = $snap
RETURN src.uid AS src_epg, dst.uid AS dst_epg,
       contract.uid AS contract_uid, contract.name AS contract_name,
       subject.uid AS subject_uid, entry.uid AS entry_uid,
       coalesce(entry.proto, entry.prot) AS proto,
       coalesce(entry.ether_type, entry.ether_t) AS ether_type,
       entry.s_from_port AS s_from_port, entry.s_to_port AS s_to_port,
       entry.d_from_port AS d_from_port, entry.d_to_port AS d_to_port,
       entry.tcp_rules AS tcp_rules, entry.apply_to_frag AS apply_to_frag,
       uf.action AS action, uf.directives AS directives, uf.direction AS direction,
       graph.uid AS graph_uid, graph.name AS graph_name
ORDER BY src.uid, dst.uid, contract.uid, subject.uid, entry.uid
"""

_ACI_CONTEXT = """
MATCH (vrf:VrfInstance {uid: $context})
WHERE NOT vrf:Retired AND vrf:Obj AND vrf.collection_ts = $snap
OPTIONAL MATCH (bd:BridgeDomain)-[iv:IN_VRF]->(vrf)
WHERE NOT bd:Retired AND iv._retired_at IS NULL
  AND bd.collection_ts = $snap
OPTIONAL MATCH (iface:Interface)-[iiv:IN_VRF]->(vrf)
OPTIONAL MATCH (iface)-[on:ON]->(device:Device)
WHERE NOT iface:Retired AND NOT device:Retired
  AND iiv._retired_at IS NULL AND on._retired_at IS NULL
  AND iface.collection_ts = $snap
  AND device.collection_ts = $snap
RETURN DISTINCT bd.uid AS bd_uid, bd._sources AS sources, vrf._sources AS vrf_sources,
       device._sources AS device_sources
ORDER BY bd_uid
"""

_GOOD_EVIDENCE = {"ok", "empty", "complete", "complete-empty"}


def _point(value: str) -> tuple[tuple[int, int, int], ...]:
    from ..addrsets import _intervals

    return tuple(_intervals([value]))


def _split_points(rect: Rect, dim: str, points: list[str]) -> list[Rect]:
    cells = [rect]
    for value in points:
        wanted = _point(value)
        nxt: list[Rect] = []
        for cell in cells:
            overlap = tuple(_intersect(list(getattr(cell, dim)), list(wanted)))
            if not overlap:
                nxt.append(cell)
                continue
            claimed = cell.narrow(**{dim: overlap})
            nxt.append(claimed)
            nxt.extend(cell.subtract(claimed))
        cells = nxt
    return cells


def _single_ip(values: tuple[tuple[int, int, int], ...]) -> str | None:
    if len(values) != 1 or values[0][1] != values[0][2]:
        return None
    import ipaddress

    family, value, _ = values[0]
    return str(ipaddress.IPv4Address(value) if family == 4 else ipaddress.IPv6Address(value))


def _entry_claim(rect: Rect, entry: dict[str, Any]) -> tuple[Rect | None, frozenset[str]]:
    """The part of `rect` one filter entry claims, read by core/aci_filter.py,
    and the dimensions on which that claim is not known."""
    spec = filter_entry(
        ether_type=entry.get("ether_type"),
        proto=entry.get("proto"),
        s_from_port=entry.get("s_from_port"),
        s_to_port=entry.get("s_to_port"),
        d_from_port=entry.get("d_from_port"),
        d_to_port=entry.get("d_to_port"),
        tcp_rules=entry.get("tcp_rules"),
        apply_to_frag=entry.get("apply_to_frag"),
    )
    if not spec.families or ("af" not in spec.unknown and rect.af not in spec.families):
        return None, frozenset()
    dims: dict[str, Any] = {}
    unknown: set[str] = set(spec.unknown)
    if spec.protocol is not None:
        if rect.proto is None:
            unknown.add("proto")
        else:
            overlap = rect.proto & frozenset({spec.protocol})
            if not overlap:
                return None, frozenset()
            dims["proto"] = overlap
    for dim, ports in (("sport", spec.source_ports), ("dport", spec.destination_ports)):
        if ports is None:
            continue
        current = getattr(rect, dim)
        if current is None:
            unknown.add(dim)
            continue
        port_overlap = tuple(_intersect(list(current), list(_ports(f"{ports[0]}-{ports[1]}"))))
        if not port_overlap:
            return None, frozenset()
        dims[dim] = port_overlap
    return rect.narrow(**dims), frozenset(unknown)


def _action(entry: dict[str, Any]) -> str:
    if entry.get("missing"):
        return "unknown"
    if entry.get("directives"):
        return "unknown"
    raw = entry.get("action")
    key = str(raw).strip().lower() if raw is not None else ""
    if key in ("", "permit"):
        return "permit"
    if key == "deny":
        return "deny"
    return "unknown"


@dataclass
class AciTransition:
    """Cached ACI endpoint and contract relation for strict path proofs."""

    session: Any
    context_uid: str | None = None
    _endpoint_cache: dict[str, tuple[dict[str, Any], ...]] | None = field(default=None, init=False)
    _contract_cache: dict[tuple[str, str], tuple[dict[str, Any], ...]] | None = field(
        default=None, init=False
    )
    _context_sources: tuple[str, ...] | None = field(default=None, init=False)
    _aci_context_observed: bool = field(default=False, init=False)

    def _endpoints(self) -> dict[str, tuple[dict[str, Any], ...]]:
        if self._endpoint_cache is None:
            grouped: dict[str, list[dict[str, Any]]] = {}
            for row in _path._read(self.session, _ENDPOINTS):
                if row.get("ip") and row.get("epg_uid"):
                    grouped.setdefault(str(row["ip"]), []).append(row)
            self._endpoint_cache = {ip: tuple(dict(row) for row in rows) for ip, rows in grouped.items()}
        return self._endpoint_cache

    def _contracts(self) -> dict[tuple[str, str], tuple[dict[str, Any], ...]]:
        if self._contract_cache is None:
            grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
            for row in _path._read(self.session, _CONTRACTS):
                grouped.setdefault((row["src_epg"], row["dst_epg"]), []).append(row)
            self._contract_cache = {key: tuple(rows) for key, rows in grouped.items()}
        return self._contract_cache

    def apply(self, region: FlowRegion) -> list[tuple[FlowRegion, Effect]]:
        endpoints = self._endpoints()
        evidence_problem = self._evidence_problem(require_policy=True)
        if evidence_problem:
            return [self._effect(rect, "indeterminate", evidence_problem) for rect in region]
        points = sorted(endpoints)
        out: list[tuple[FlowRegion, Effect]] = []
        for original in region:
            for src_cell in _split_points(original, "src", points):
                for cell in _split_points(src_cell, "dst", points):
                    out.extend(self._pair(cell, endpoints))
        return out

    def _aci_sources(self) -> tuple[str, ...]:
        if self._context_sources is not None:
            return self._context_sources
        if not self.context_uid or getattr(self.session, "snapshot", None) is None:
            self._context_sources = ()
            return self._context_sources
        names: set[str] = set()
        rows = _path._read(self.session, _ACI_CONTEXT, context=self.context_uid)
        self._aci_context_observed = bool(rows)
        for row in rows:
            names.update(str(value) for value in (row.get("sources") or ()) if value)
            names.update(str(value) for value in (row.get("vrf_sources") or ()) if value)
            names.update(str(value) for value in (row.get("device_sources") or ()) if value)
        self._context_sources = tuple(sorted(names))
        return self._context_sources

    def _evidence_problem(self, *, require_policy: bool) -> str | None:
        snapshot = getattr(self.session, "snapshot", None)
        if snapshot is None:
            return None
        sources = self._aci_sources()
        if not self._aci_context_observed:
            return None
        if not sources:
            return "the ACI context lacks collected source provenance"
        manifest = getattr(snapshot, "manifest", None)
        if manifest is None:
            return "no published manifest proves ACI endpoint observation for this context"
        source_types = {entry.name: str(entry.type).lower() for entry in manifest.sources}
        unmapped_sources = sorted(set(sources) - source_types.keys())
        if unmapped_sources:
            return "the context provenance cannot be mapped to manifest source(s): " + ", ".join(
                unmapped_sources
            )
        apic_sources = {name for name in sources if source_types.get(name) == "apic"}
        if not apic_sources:
            return None
        entries = [entry for entry in manifest.devices if entry.source in apic_sources]
        represented = {entry.source for entry in entries}
        missing_sources = sorted(apic_sources - represented)
        if missing_sources:
            return "ACI context lacks manifest device evidence for source(s): " + ", ".join(missing_sources)
        if not entries:
            return "the ACI context has no APIC collection evidence in the manifest"
        required = {"endpoint", "policy"} if require_policy else {"endpoint"}
        for entry in entries:
            if entry.outcome == "failed" or (entry.carried and not entry.effective_run):
                return f"APIC collection outcome is {entry.outcome} for source {entry.source}"
            for section in sorted(required):
                outcome = entry.sections.get(section)
                if outcome is None:
                    return f"APIC manifest lacks {section} observation for source {entry.source}"
                if outcome.status not in _GOOD_EVIDENCE:
                    return f"APIC {section} observation is {outcome.status} for source {entry.source}"
        return None

    def _identity(
        self, values: tuple[tuple[int, int, int], ...], endpoints: dict[str, tuple[dict[str, Any], ...]]
    ) -> tuple[dict[str, Any] | None, str | None]:
        ip = _single_ip(values)
        return endpoint_identity(endpoints.get(ip or "", ()), (self.context_uid,))

    def _pair(
        self, rect: Rect, endpoints: dict[str, tuple[dict[str, Any], ...]]
    ) -> list[tuple[FlowRegion, Effect]]:
        src, src_problem = self._identity(rect.src, endpoints)
        dst, dst_problem = self._identity(rect.dst, endpoints)
        if src_problem or dst_problem:
            return [self._effect(rect, "indeterminate", src_problem or dst_problem)]
        if src is None and dst is None:
            return [self._effect(rect, "pass", "neither endpoint belongs to ACI")]
        if src is None or dst is None:
            return [self._effect(rect, "indeterminate", "only one endpoint belongs to an ACI EPG")]
        if src["epg_uid"] == dst["epg_uid"]:
            return [self._effect(rect, "indeterminate", "intra-EPG isolation is not collected")]
        src_vrf, dst_vrf = src.get("vrf_uid"), dst.get("vrf_uid")
        if not src_vrf or not dst_vrf or src_vrf != dst_vrf:
            return [self._effect(rect, "indeterminate", "cross-VRF or missing ACI enforcement context")]
        # `vrf_enforcement` is the pcEnfPref reading of the trace and of the model gate.
        enforcement = vrf_enforcement(src_vrf, dst_vrf, src.get("pc_enf_pref"))
        if enforcement == "unenforced":
            return [self._effect(rect, "permit", "the governing VRF is unenforced", src=src, dst=dst)]
        if enforcement != "enforced":
            return [self._effect(rect, "indeterminate", "ACI VRF enforcement is not known", src=src, dst=dst)]
        evidence_problem = self._evidence_problem(require_policy=True)
        if evidence_problem:
            return [self._effect(rect, "indeterminate", evidence_problem, src=src, dst=dst)]
        contracts = self._contracts()
        rows = list(contracts.get((src["epg_uid"], dst["epg_uid"]), ()))
        reverse = {
            row.get("contract_name") or row["contract_uid"]
            for row in contracts.get((dst["epg_uid"], src["epg_uid"]), ())
        }
        gaps = [
            gap for gap in (reverse_contract_gap(reverse), contract_bypass(src.get("contract_bypass"))) if gap
        ]
        return self._contract_regions(rect, rows, src, dst, "; ".join(gaps) or None)

    def _contract_regions(
        self,
        rect: Rect,
        rows: list[dict[str, Any]],
        src: dict[str, Any],
        dst: dict[str, Any],
        implicit_gap: str | None = None,
    ) -> list[tuple[FlowRegion, Effect]]:
        if not rows:
            if implicit_gap:
                return [
                    self._effect(
                        rect,
                        "indeterminate",
                        f"no consumed/provided contract; {implicit_gap}",
                        src=src,
                        dst=dst,
                    )
                ]
            return [self._effect(rect, "deny", "no consumed/provided contract", True, src, dst)]
        contract_uids = {row["contract_uid"] for row in rows}
        present = {row["contract_uid"] for row in rows if row.get("entry_uid")}
        # A vzOutTerm filter governs provider-to-consumer traffic. Its entries
        # are not in `entries`, and its contract counts as collected in `present`.
        entries = [row for row in rows if row.get("entry_uid") and filter_applies(row.get("direction"))]
        entries.extend(
            {
                "contract_uid": uid,
                "contract_name": next(r.get("contract_name") for r in rows if r["contract_uid"] == uid),
                "missing": True,
            }
            for uid in contract_uids - present
        )
        cells: list[tuple[Rect, list[tuple[dict[str, Any], frozenset[str]]]]] = [(rect, [])]
        for entry in entries:
            nxt: list[tuple[Rect, list[tuple[dict[str, Any], frozenset[str]]]]] = []
            for cell, claims in cells:
                claimed, unknown = _entry_claim(cell, entry)
                if claimed is None:
                    nxt.append((cell, claims))
                    continue
                nxt.append((claimed, [*claims, (entry, unknown)]))
                nxt.extend((rest, claims) for rest in cell.subtract(claimed))
            cells = nxt
        out: list[tuple[FlowRegion, Effect]] = []
        for cell, claims in cells:
            if not claims:
                if implicit_gap:
                    reason = f"no collected contract filter matches; {implicit_gap}"
                    out.append(self._effect(cell, "indeterminate", reason, src=src, dst=dst))
                else:
                    out.append(
                        self._effect(cell, "deny", "no collected contract filter matches", True, src, dst)
                    )
                continue
            unknown = frozenset().union(*(dims for _entry, dims in claims))
            graphs = [entry for entry, _dims in claims if entry.get("graph_uid") or entry.get("graph_name")]
            actions = {_action(entry) for entry, _dims in claims}
            data = {"src_epg": src, "dst_epg": dst, "entries": [entry for entry, _ in claims]}
            if graphs:
                effect = Effect(
                    "indeterminate",
                    "aci",
                    unknown=unknown,
                    reason="a matching contract subject applies an unevaluated service graph",
                    data=data,
                )
            elif actions == {"permit"} and any(not dims for _entry, dims in claims):
                # An entry that matches the whole cell permits the cell. A
                # permit entry with an unknown claim on the cell does not
                # change the verdict.
                effect = Effect(
                    "permit", "aci", reason="matching contract filter permits this region", data=data
                )
            elif unknown or "unknown" in actions:
                effect = Effect(
                    "indeterminate",
                    "aci",
                    unknown=unknown,
                    reason="matching contract fields are missing or opaque",
                    data=data,
                )
            elif len(actions) > 1:
                effect = Effect(
                    "indeterminate",
                    "aci",
                    reason="matching permit and deny filters have no collected precedence",
                    data=data,
                )
            else:
                action = next(iter(actions))
                effect = Effect(
                    action,
                    "aci",
                    terminal=action == "deny",
                    reason=f"matching contract filter {action}s this region",
                    data=data,
                )
            out.append((FlowRegion.single(cell), effect))
        return out

    @staticmethod
    def _effect(
        rect: Rect,
        kind: str,
        reason: str | None,
        terminal: bool = False,
        src: dict[str, Any] | None = None,
        dst: dict[str, Any] | None = None,
    ) -> tuple[FlowRegion, Effect]:
        return (
            FlowRegion.single(rect),
            Effect(kind, "aci", terminal=terminal, reason=reason, data={"src_epg": src, "dst_epg": dst}),
        )
