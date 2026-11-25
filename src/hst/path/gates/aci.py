"""ACI contract verdicts, evaluated EPG to EPG.

An unenforced governing VRF permits the traffic of an EPG pair before any contract is
read. The contracts are evaluated if the VRF is enforced or its mode cannot be
determined.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import hst.path as _path
from hst.core.aci_filter import (
    contract_bypass,
    endpoint_identity,
    entry_match,
    filter_applies,
    filter_entry,
    protocol_number,
    reverse_contract_gap,
    vrf_enforcement,
)

from ..verdict import DENY, INDETERMINATE, PERMIT


def aci_contract_verdict(
    session: Any,
    src_ip: str,
    dst_ip: str,
    port: int | None,
    proto: str | None,
    contexts: Iterable[str | None] = (),
) -> dict[str, Any] | None:
    """Whether an ACI contract permits this flow, EPG to EPG.

    The verdict is evaluated on the endpoints of the flow.

    A contract permits a flow when the destination EPG provides the contract, the
    source EPG consumes it, and no filter entry that matches the protocol and the
    destination port of the flow has a service graph redirect or an explicit deny. An
    unenforced governing VRF permits the traffic of the pair before any contract is
    read. Otherwise every contract between the pair is decided (`_contracts_verdict`).
    Contracts that agree decide. Contracts that disagree or cannot decide are
    indeterminate. With no contract matching, the verdict is a deny when the VRF is
    enforced, as in ACI. It is indeterminate when the enforcement mode cannot be
    determined for this pair. It is indeterminate when the destination EPG consumes a
    contract that the source EPG provides, whose provider-to-consumer direction is not
    evaluated. It is indeterminate when the VRF uses vzAny contracts, the preferred
    group or ESGs, or when that use was not collected (core/aci_filter.py
    `contract_bypass`). The uids of the examined contracts are reported
    (`contract_uid`, `contract_uids`).

    Returns None when neither endpoint is an ACI endpoint, and an indeterminate verdict
    when only one is.

    `contexts` scopes an address that is in more than one EPG (core/aci_filter.py
    `endpoint_identity`). `contexts` holds the routing contexts that the trace drew the
    flow through. ACI lets tenants and VRFs reuse an address, and the EPG in one of
    those VRFs is the endpoint. An address that stays in more than one EPG is
    indeterminate.
    """
    found, problems = _endpoint_epgs(session, src_ip, dst_ip, contexts)
    verdict_notes: list[str] = []
    if problems:
        names = [found[ip]["epg_name"] if ip in found else "?" for ip in (src_ip, dst_ip)]
        return {
            "action": INDETERMINATE,
            "epgs": "→".join(names),
            "contract": None,
            "contract_uid": None,
            "reason": "; ".join(problems),
            "notes": verdict_notes,
        }
    if not found:
        return None
    src_epg, dst_epg = found.get(src_ip), found.get(dst_ip)
    if not src_epg or not dst_epg:
        return _half_resolved_verdict(src_epg, dst_epg, verdict_notes)
    if src_epg["epg_uid"] == dst_epg["epg_uid"]:
        # ACI permits intra-EPG traffic unless intra-EPG isolation is set. The
        # isolation setting is not collected.
        return {
            "action": INDETERMINATE,
            "epgs": f"{src_epg['epg_name']} (intra-EPG)",
            "contract": None,
            "contract_uid": None,
            "reason": "intra-EPG flow; intra-EPG isolation is not collected",
            "notes": verdict_notes,
        }
    both = _contract_rows(session, src_epg["epg_uid"], dst_epg["epg_uid"])
    rows = [row for row in both if row.get("orientation", "forward") == "forward"]
    reverse = [row["name"] or row["uid"] for row in both if row.get("orientation") == "reverse"]
    label = f"{src_epg['epg_name']}→{dst_epg['epg_name']}"
    enforcement = _vrf_enforcement(src_epg, dst_epg)
    family = 6 if ":" in dst_ip else 4
    # The inputs that can permit the pair outside its consumer-to-provider
    # contracts. With a gap, the implicit deny of an enforced VRF is indeterminate.
    gaps = [
        gap for gap in (reverse_contract_gap(reverse), contract_bypass(src_epg.get("contract_bypass"))) if gap
    ]
    return _contracts_verdict(
        rows, label, port, proto, verdict_notes, enforcement, family, "; ".join(gaps) or None
    )


def _endpoint_epgs(
    session: Any, src_ip: str, dst_ip: str, contexts: Iterable[str | None] = ()
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """One EPG row per flow endpoint, plus the reason for each endpoint whose
    EPG cannot be chosen (core/aci_filter.py `endpoint_identity`).

    The result is empty when neither endpoint resolves to an EPG. The endpoint is
    found through its HAS_IP edge. apic.py writes no Endpoint.ip.

    Each row also holds the governing VRF of the EPG and its enforcement mode
    (`vrf_uid`, `pc_enf_pref`), read through the IN_BD and IN_VRF edges that apic.py
    writes.
    """
    ends = _path._read(
        session,
        """
UNWIND [$src, $dst] AS ip
OPTIONAL MATCH (e:Endpoint:Obj)-[h:HAS_IP]->(ia:IpAddress {ip: ip})
WHERE NOT e:Retired AND NOT ia:Retired AND h._retired_at IS NULL
  AND e.collection_ts = $snap
OPTIONAL MATCH (e)-[r:IN_EPG]->(g:Epg)
WHERE NOT g:Retired AND r._retired_at IS NULL
OPTIONAL MATCH (g)-[bdr:IN_BD]->(bd:BridgeDomain)-[vr:IN_VRF]->(vrf:VrfInstance)
WHERE NOT bd:Retired AND NOT vrf:Retired AND bdr._retired_at IS NULL AND vr._retired_at IS NULL
RETURN ip AS ip, g.uid AS epg_uid, g.name AS epg_name,
       vrf.uid AS vrf_uid, vrf.pc_enf_pref AS pc_enf_pref,
       vrf.contract_bypass AS contract_bypass""",
        src=src_ip,
        dst=dst_ip,
    )
    by_ip: dict[str, list[dict[str, Any]]] = {}
    for row in sorted(ends, key=lambda r: (r["ip"] or "", r["epg_uid"] or "")):
        if row["epg_uid"]:
            by_ip.setdefault(row["ip"], []).append(row)
    scope = tuple(contexts)
    found: dict[str, dict[str, Any]] = {}
    problems: list[str] = []
    for ip, rows_ in by_ip.items():
        identity, problem = endpoint_identity(rows_, scope)
        if problem:
            problems.append(problem)
        elif identity is not None:
            found[ip] = identity
    return found, problems


def _half_resolved_verdict(
    src_epg: dict[str, Any] | None,
    dst_epg: dict[str, Any] | None,
    verdict_notes: list[str],
) -> dict[str, Any]:
    """The indeterminate verdict for a pair with only one end in an EPG."""
    src_name = src_epg["epg_name"] if src_epg else "?"
    dst_name = dst_epg["epg_name"] if dst_epg else "?"
    known = src_name if src_epg else dst_name
    return {
        "action": INDETERMINATE,
        "epgs": f"{src_name}→{dst_name}",
        "contract": None,
        "contract_uid": None,
        "reason": (
            f"only one end of this flow resolves to an ACI EPG ({known}); the other is not a known endpoint"
        ),
        "notes": verdict_notes,
    }


def _vrf_enforcement(src_epg: dict[str, Any], dst_epg: dict[str, Any]) -> str:
    """The VRF enforcement mode governing this EPG pair: "enforced", "unenforced",
    or "unknown".

    "unknown" covers either side's VRF not resolving (missing IN_BD/IN_VRF edges,
    or a snapshot collected without pc_enf_pref), the two EPGs resolving to
    different VRFs (a cross-VRF/shared-services contract), and a pc_enf_pref
    value that is neither "enforced" nor "unenforced".
    """
    return vrf_enforcement(src_epg.get("vrf_uid"), dst_epg.get("vrf_uid"), src_epg.get("pc_enf_pref"))


def _classify_filter_action(action: Any) -> tuple[str, str | None]:
    """Classify the USES_FILTER.action of one filter entry.

    The default of the APIC MO attribute vzRsSubjFiltAtt.action is permit. A missing
    or empty value classifies as permit. An explicit "deny" classifies as deny. Any
    other value is indeterminate.

    Returns ("permit", None), ("deny", None), or ("indeterminate", the raw value).
    """
    normalized = str(action).strip().lower() if action else ""
    if normalized in ("", "permit"):
        return "permit", None
    if normalized == "deny":
        return "deny", None
    return "indeterminate", str(action)


def _contract_rows(session: Any, src_uid: str, dst_uid: str) -> list[dict[str, Any]]:
    """Contracts the destination EPG provides and the source EPG consumes
    (`orientation` "forward"), each with its collected filter entries, and
    the contracts the source EPG provides and the destination EPG consumes
    ("reverse"), whose provider-to-consumer direction is not evaluated.

    `proto` and `ether_type` are the schema names that apic.py writes. The coalesce
    also reads `prot` and `ether_t`. Each entry also holds its source ports, tcpRules
    and applyToFrag, the `action` and `direction` of the USES_FILTER relationship (a
    vzInTerm or vzOutTerm attachment), and the name of the service graph redirect of
    its subject, if any."""
    return _path._read(
        session,
        """
UNWIND [[$src, $dst, 'forward'], [$dst, $src, 'reverse']] AS pair
MATCH (src:Epg {uid: pair[0]})-[c:CONSUMES]->(k:Contract)<-[p:PROVIDES]-(dst:Epg {uid: pair[1]})
WHERE NOT k:Retired AND c._retired_at IS NULL AND p._retired_at IS NULL
  AND src:Obj AND src.collection_ts = $snap AND dst:Obj AND dst.collection_ts = $snap
  AND k.collection_ts = $snap
OPTIONAL MATCH (k)-[:HAS]->(subj:ContractSubject)-[uf:USES_FILTER]->(:AciFilter)-[:HAS]->(fe:FilterEntry)
OPTIONAL MATCH (subj)-[:APPLIES_GRAPH]->(sg:ServiceGraphTemplate)
RETURN pair[2] AS orientation, k.uid AS uid, k.name AS name,
       collect(DISTINCT {proto: coalesce(fe.proto, fe.prot), from_port: fe.d_from_port,
                         to_port: fe.d_to_port, ether: coalesce(fe.ether_type, fe.ether_t),
                         s_from_port: fe.s_from_port, s_to_port: fe.s_to_port,
                         tcp_rules: fe.tcp_rules, apply_to_frag: fe.apply_to_frag,
                         action: uf.action, direction: uf.direction, graph: sg.name}) AS entries
ORDER BY orientation, uid""",
        src=src_uid,
        dst=dst_uid,
    )


def _contracts_verdict(
    rows: list[dict[str, Any]],
    label: str,
    port: int | None,
    proto: str | None,
    verdict_notes: list[str],
    enforcement: str,
    family: int | None = None,
    implicit_gap: str | None = None,
) -> dict[str, Any]:
    """Examine every contract between the pair and settle the verdict.

    ACI does not apply contracts in an unenforced VRF. When `enforcement` is
    "unenforced", the function returns PERMIT before it reads the rows.

    Otherwise each contract is decided on its own (`_contract_outcome`). Every
    contract of the pair is decided, in contract uid order. Contracts that
    agree decide. The verdict is indeterminate when one contract denies and
    another permits, or when a contract cannot decide next to a deciding one. A
    contract cannot decide with a service graph redirect, an action that is
    neither permit nor deny, a filter entry that cannot be evaluated, or no
    collected filter entries. The precedence between two contracts is not
    collected, and the undecided contract can hold the deny.

    Only the entries of filters that apply from the consumer to the provider
    are evaluated (core/aci_filter.py `filter_applies`). A vzOutTerm filter
    governs the other direction. A contract whose collected filters are all
    vzOutTerm filters has collected entries, and none of them matches this
    flow.

    With no contract matching, the outcome follows the VRF enforcement mode.
    Enforced denies. Unknown is indeterminate. `implicit_gap` is the text of an
    input that can permit the pair outside these contracts (a vzAny contract,
    the preferred group, an ESG, a contract in the reverse orientation,
    core/aci_filter.py). With `implicit_gap`, the implicit deny of the enforced
    VRF is indeterminate.
    """
    examined = [row["uid"] for row in rows]

    def verdict(action: str, row: dict[str, Any] | None, reason: str) -> dict[str, Any]:
        out: dict[str, Any] = {
            "action": action,
            "epgs": label,
            "contract": row["name"] if row else None,
            "contract_uid": row["uid"] if row else None,
            "reason": reason,
            "notes": verdict_notes,
        }
        if rows:
            out["contract_uids"] = examined
        return out

    if enforcement == "unenforced":
        out = verdict(
            PERMIT,
            None,
            "the governing VRF is unenforced; ACI permits this EPG pair's traffic regardless of contracts",
        )
        out["contract_uids"] = examined
        return out
    if not rows:
        reason = "no contract is provided by the destination EPG and consumed by the source EPG"
        if enforcement == "unknown":
            out = verdict(
                INDETERMINATE,
                None,
                f"{reason}, and the governing VRF's enforcement mode could not be determined for this pair",
            )
            out["contract_uids"] = examined
            return out
        if implicit_gap:
            out = verdict(INDETERMINATE, None, f"{reason}; {implicit_gap}")
            out["contract_uids"] = examined
            return out
        return verdict(DENY, None, reason)
    ordered = sorted(rows, key=lambda row: str(row["uid"]))
    decided = [
        (row, outcome)
        for row in ordered
        if (outcome := _contract_outcome(row, port, proto, family)) is not None
    ]
    if decided:
        actions = {action for _row, (action, _reason) in decided}
        if actions in ({PERMIT}, {DENY}):
            row, (action, reason) = decided[0]
            return verdict(action, row, reason)
        undecided = next(((row, o) for row, o in decided if o[0] == INDETERMINATE), None)
        if undecided is not None:
            row, (_action, reason) = undecided
            others = [r["name"] for r, (a, _) in decided if a != INDETERMINATE]
            if others:
                reason = f"{reason}; it may decide against contract {', '.join(others)}"
            return verdict(INDETERMINATE, row, reason)
        deny_row = next(row for row, (action, _reason) in decided if action == DENY)
        permit_row = next(row for row, (action, _reason) in decided if action == PERMIT)
        return verdict(
            INDETERMINATE,
            deny_row,
            (
                f"contract {deny_row['name']} denies and contract {permit_row['name']} permits "
                f"{proto or 'any'}/{port or 'any'}; the precedence between two contracts is not collected"
            ),
        )
    names = [row["name"] for row in ordered]
    reason = (
        f"contract {names[0]} applies but no filter entry matches {proto or 'any'}/{port or 'any'}"
        if len(rows) == 1
        else (
            f"{len(rows)} contracts apply ({', '.join(names)}) but no filter entry "
            f"matches {proto or 'any'}/{port or 'any'}"
        )
    )
    if enforcement == "unknown":
        return verdict(
            INDETERMINATE,
            ordered[0],
            f"{reason}, and the governing VRF's enforcement mode could not be determined for this pair",
        )
    if implicit_gap:
        return verdict(INDETERMINATE, ordered[0], f"{reason}; {implicit_gap}")
    return verdict(DENY, ordered[0], reason)


def _contract_outcome(
    row: dict[str, Any], port: int | None, proto: str | None, family: int | None
) -> tuple[str, str] | None:
    """The verdict of one contract on the flow as (action, reason), or None
    when no entry of the contract can match.

    A contract with no collected filter entries is indeterminate. Otherwise
    the entries decide in this order:

    1. A service graph redirect on an entry that matches or that cannot be
       evaluated makes the contract indeterminate. The reason has the name of
       the graph. The L4-L7 device of the redirect is not evaluated.
    2. An explicit deny wins over a permit of the same contract that also
       matches.
    3. An action that is neither permit nor deny is indeterminate. The reason
       quotes the value.
    4. The contract permits if an entry matches and every entry that cannot be
       evaluated has the action permit.
    5. In every other case the contract is indeterminate.

    An entry cannot be evaluated with an unreadable field, a question without
    a port or a protocol, tcpRules, applyToFrag or a source-port range."""
    name = row["name"]
    flow = f"{proto or 'any'}/{port or 'any'}"
    collected = [e for e in row["entries"] if e.get("proto") or e.get("ether")]
    if not collected:
        return INDETERMINATE, f"contract {name} has no collected filter entries"
    entries = [e for e in collected if filter_applies(e.get("direction"))]
    outcomes = [(e, _aci_entry_matches(e, port, proto, family)) for e in entries]
    matches = [e for e, outcome in outcomes if outcome == "match"]
    unknown = [e for e, outcome in outcomes if outcome == "unknown"]
    if not matches and not unknown:
        return None
    graph = next((e["graph"] for e in matches + unknown if e.get("graph")), None)
    if graph:
        return INDETERMINATE, (
            f"contract {name} redirects {flow} through service graph {graph}; "
            "service graph redirect not evaluated"
        )
    actions = [_classify_filter_action(e.get("action")) for e in matches]
    if any(kind == "deny" for kind, _raw in actions):
        # ACI programs an explicit deny filter of a contract subject ahead of
        # a permit filter. A deny match wins over a permit entry of the same
        # contract that also matches. This priority is an assumption from the
        # Cisco APIC documentation of contracts and zoning rules. No captured
        # payload confirms it.
        return DENY, (
            f"contract {name} denies {flow}: a deny filter matches and takes precedence "
            "over a co-matching permit filter"
        )
    raw_action = next((raw for kind, raw in actions if kind == "indeterminate"), None)
    if raw_action is not None:
        return INDETERMINATE, (
            f"contract {name} has a matching filter entry with action {raw_action!r}, "
            "which is neither permit nor deny"
        )
    if matches and all(_classify_filter_action(e.get("action"))[0] == "permit" for e in unknown):
        return PERMIT, f"contract {name} permits {flow}"
    return INDETERMINATE, f"contract {name} has a filter entry that cannot be evaluated against {flow}"


def _aci_entry_matches(entry: dict[str, Any], port: int | None, proto: str | None, family: int | None) -> str:
    """One vzEntry against the flow: "match", "miss" or "unknown" (core/aci_filter.py).

    The flow of the trace has no source port. An entry is unknown if it
    constrains the source port, if its source ports were not collected, or if
    it sets tcpRules or applyToFrag."""
    spec = filter_entry(
        ether_type=entry.get("ether"),
        proto=entry.get("proto"),
        s_from_port=entry.get("s_from_port"),
        s_to_port=entry.get("s_to_port"),
        d_from_port=entry.get("from_port"),
        d_to_port=entry.get("to_port"),
        tcp_rules=entry.get("tcp_rules"),
        apply_to_frag=entry.get("apply_to_frag"),
    )
    return entry_match(
        spec,
        family=family,
        protocol=protocol_number(proto) if proto else None,
        destination_port=port,
    )
