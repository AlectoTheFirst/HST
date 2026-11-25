"""Failure transformations of the routing calculation input.

The transformation withdraws the failed origins and adjacencies. The RIB engine
then computes SPF, BGP propagation, redistribution, route leaking and PBR on the
transformed input. A collected FIB is not edited.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import replace
from typing import Any

from hst.impact.evaluate import Interface
from hst.simul import certainty, ospf, rib
from hst.simul.errors import ErrorSink


def address(value: Any) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_interface(str(value)).ip)
    except ValueError:
        return str(value)


def failed_lsdb(
    model: ospf.LsdbModel, routers: set[str], interfaces: Mapping[str, Sequence[Interface]]
) -> ospf.LsdbModel:
    """Construct the settled topology after the withdrawal of routers and interfaces.

    A surviving broadcast segment keeps its pseudonode. When the advertising
    router of the pseudonode failed, the first surviving router in sorted
    order represents the segment. This representative is not the result of a
    DR election. The attachment set of the segment and every router edge are
    recomputed together. RFC 2328 sections 12.4.1, 12.4.2 and 16.1 define this
    topology.
    """
    changed = model.copy()
    detached: dict[tuple[str | None, str], set[str]] = {}
    lost_p2p: set[tuple[str | None, str, str]] = set()
    for lsa in list(changed.lsas.values()):
        if lsa.lsa_type != ospf.ROUTER:
            continue
        owner = lsa.adv_router
        down = interfaces.get(owner, ())
        ips = {address(a) for interface in down for a in interface.addresses}
        prefixes = {
            str(ipaddress.ip_network(p, strict=False)) for interface in down for p in interface.prefixes
        }
        kept = []
        for link in lsa.links:
            match = owner in routers or address(link.link_data) in ips
            if link.link_type == ospf.STUB:
                with suppress(ValueError):
                    match |= (
                        str(ipaddress.ip_network(f"{link.link_id}/{link.link_data}", strict=False))
                        in prefixes
                    )
            if link.link_type in {ospf.POINT_TO_POINT, ospf.VIRTUAL} and link.link_id in routers:
                match = True
            if match:
                if link.link_type == ospf.TRANSIT:
                    detached.setdefault((lsa.area, link.link_id), set()).add(owner)
                if link.link_type in {ospf.POINT_TO_POINT, ospf.VIRTUAL}:
                    lost_p2p.add((lsa.area, owner, link.link_id))
            else:
                kept.append(link)
        changed.lsas[lsa.key] = replace(lsa, links=tuple(kept))
    for lsa in list(changed.lsas.values()):
        if lsa.lsa_type == ospf.ROUTER:
            changed.lsas[lsa.key] = replace(
                lsa,
                links=tuple(
                    link for link in lsa.links if (lsa.area, link.link_id, lsa.adv_router) not in lost_p2p
                ),
            )
        elif lsa.lsa_type == ospf.NETWORK:
            remaining = tuple(
                r
                for r in lsa.attached_routers
                if r not in routers | detached.get((lsa.area, lsa.lsid), set())
            )
            if remaining == lsa.attached_routers and lsa.adv_router not in routers:
                continue
            changed.lsas.pop(lsa.key, None)
            if len(remaining) >= 2:
                representative = lsa.adv_router if lsa.adv_router in remaining else sorted(remaining)[0]
                network = replace(lsa, adv_router=representative, attached_routers=remaining)
                changed.lsas[network.key] = network
            else:
                for owner in remaining:
                    router = changed.router_lsa(str(lsa.area), owner)
                    if router is not None:
                        changed.lsas[router.key] = replace(router, links=ospf._restubbed(router.links, lsa))
    # The filter also removes the type 3, 4, 5 and 7 advertisements of failed originators.
    changed.lsas = {key: lsa for key, lsa in changed.lsas.items() if lsa.adv_router not in routers}
    return changed


def transform_routing(
    original: rib.RibInput,
    all_interfaces: Sequence[Interface],
    devices: set[str],
    failed_interfaces: set[str],
) -> rib.RibInput:
    down = [i for i in all_interfaces if i.uid in failed_interfaces or i.device_uid in devices]
    down_names = {(i.context_uid, name) for i in down for name in (i.uid, i.name)}
    owners = {
        str(c["uid"]): set(c.get("device_uids") or ([c["device_uid"]] if c.get("device_uid") else ()))
        | {i.device_uid for i in all_interfaces if i.context_uid == c["uid"]}
        for c in original.contexts
    }
    down_contexts = {uid for uid, members in owners.items() if members and members <= devices}
    affected = down_contexts | {str(i.context_uid) for i in down if i.context_uid}

    def lost_address(context: Any, value: Any, *, local: bool = False) -> bool:
        ip = address(value)
        if ip is None:
            return False
        for interface in down:
            if ip not in {address(a) for a in interface.addresses}:
                continue
            if interface.context_uid == context:
                return True
            if not local and any(
                set(peer.prefixes) & set(interface.prefixes)
                for peer in all_interfaces
                if peer.context_uid == context
            ):
                return True
        return False

    def kept(row: Mapping[str, Any]) -> bool:
        return (
            row.get("context_uid") not in down_contexts
            and row.get("next_hop_context_uid") not in down_contexts
            and (row.get("context_uid"), row.get("interface")) not in down_names
            and not lost_address(row.get("context_uid"), row.get("next_hop"))
        )

    router_ids = {
        str(p["router_id"])
        for p in original.ospf
        if p.get("router_id") and p.get("context_uid") in down_contexts
    }
    router_interfaces: dict[str, list[Interface]] = {}
    for process in original.ospf:
        if process.get("router_id"):
            router_interfaces.setdefault(str(process["router_id"]), []).extend(
                i for i in down if i.context_uid == process.get("context_uid")
            )
    ospf_entries = []
    changed_ospf = False
    for process in original.ospf:
        if process.get("context_uid") in down_contexts:
            continue
        model = rib._ospf_model(process, ErrorSink())
        changed = failed_lsdb(model, router_ids, router_interfaces)
        if changed.lsas != model.lsas:
            changed_ospf = True
            affected.add(str(process["context_uid"]))
        ospf_entries.append({**process, "model": changed})
    ospf_entries, summary_gaps = _refresh_summaries(ospf_entries) if changed_ospf else (ospf_entries, [])
    result = replace(
        original,
        connected=[dict(row) for row in original.connected if kept(row)],
        static=[dict(row) for row in original.static if kept(row)],
        ospf=ospf_entries,
        rt_pairs=[
            dict(row)
            for row in original.rt_pairs
            if row.get("importer") not in down_contexts and row.get("exporter") not in down_contexts
        ],
        pbr=[
            dict(row)
            for row in original.pbr
            if row.get("device_uid") not in devices and row.get("if_uid") not in failed_interfaces
        ],
        superseded_contexts=original.superseded_contexts | certainty.closure(original, affected),
        observation_gaps=[*original.observation_gaps, *summary_gaps],
    )
    if original.bgp is None:
        return result
    process_context = certainty.process_contexts(original)
    # Each failed process keeps its process record.
    result.bgp = replace(
        original.bgp,
        local_routes=[
            dict(row)
            for row in original.bgp.local_routes
            if process_context.get(str(row.get("process_uid"))) not in down_contexts
        ],
    )
    shut = set()
    for session in original.bgp.sessions:
        context = process_context.get(str(session["process_uid"]))
        if (
            context in down_contexts
            or lost_address(context, session.get("local_ip"), local=True)
            or lost_address(context, session.get("peer_ip"))
        ):
            shut.add(str(session["uid"]))
    # A BGP session also depends on the IGP and static transport after the failure.
    # A missing transport route shuts the session only when the transport model is complete.
    transport_input = replace(result, bgp=None, observed_paths=(), session_state={}, direction_status={})
    transport = rib.compute(transport_input, validate_observed=False)
    gaps = list(result.observation_gaps)
    contexts = {str(c["uid"]): c for c in result.contexts}
    for session in original.bgp.sessions:
        uid = str(session["uid"])
        context = process_context.get(str(session["process_uid"]), "")
        if uid in shut or context not in result.superseded_contexts or not session.get("peer_ip"):
            continue
        device = contexts.get(context, {}).get("device_uid")
        routes = transport.fib.lpm(str(device or ""), context, str(session["peer_ip"]))
        if routes and any(not row.get("discard") for row in routes):
            continue
        incomplete = any(gap.get("context_uid") == context for gap in transport.gaps) or bool(
            transport.model_errors
        )
        if incomplete:
            gaps.append(
                {
                    "kind": "not-observed",
                    "context_uid": context,
                    "subject": uid,
                    "detail": "Post-failure BGP transport cannot be established "
                    "from the recorded routing inputs.",
                }
            )
        else:
            shut.add(uid)
    for uid in sorted(shut):
        result = rib.shut_session(result, uid)
    if result.bgp is None:
        raise RuntimeError("BGP input disappeared during session shutdown")
    shutdown_ids = {
        str(s["uid"]) for s in result.bgp.sessions if str(s.get("state", "")).lower() == "shutdown"
    }
    return replace(
        result,
        observation_gaps=gaps,
        observed_paths=[
            dict(row) for row in result.observed_paths if str(row.get("session_uid")) not in shutdown_ids
        ],
        session_state={
            uid: {**state, "state": "shutdown"} if uid in shutdown_ids else dict(state)
            for uid, state in result.session_state.items()
        },
    )


def _refresh_summaries(entries: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Recompute the recorded ABR summaries from the surviving areas of each ABR.

    The summary of an ABR without a collected process is kept, and a
    `not-observed` gap is added. The function changes the metric of a summary
    or removes the summary. It adds no summary.
    """
    processes = {str(p["router_id"]): p for p in entries if p.get("router_id")}
    gaps = []
    for entry in entries:
        model = entry["model"]
        for summary in list(model.lsas.values()):
            if summary.lsa_type not in {ospf.SUMMARY, ospf.ASBR_SUMMARY}:
                continue
            producer = processes.get(summary.adv_router)
            if producer is None:
                gaps.append(
                    {
                        "kind": "not-observed",
                        "context_uid": entry["context_uid"],
                        "subject": summary.adv_router,
                        "detail": "Post-failure ABR summary depends on an uncollected originating process.",
                    }
                )
                continue
            other = producer["model"].copy()
            other.lsas = {
                k: v
                for k, v in other.lsas.items()
                if v.area != summary.area and v.lsa_type in {ospf.ROUTER, ospf.NETWORK}
            }
            if not other.areas():
                gaps.append(
                    {
                        "kind": "not-observed",
                        "context_uid": entry["context_uid"],
                        "subject": summary.adv_router,
                        "detail": "The ABR's other-area link-state evidence is absent.",
                    }
                )
                continue
            calculation = ospf.calculate(other, summary.adv_router, platform=producer.get("platform", "nxos"))
            if calculation.gaps or calculation.model_errors:
                gaps.append(
                    {
                        "kind": "not-observed",
                        "context_uid": entry["context_uid"],
                        "subject": summary.adv_router,
                        "detail": "The ABR summary calculation has incomplete link-state evidence.",
                    }
                )
                continue
            if summary.lsa_type == ospf.ASBR_SUMMARY:
                costs = [
                    cost for (_, router), cost in calculation.router_costs.items() if router == summary.lsid
                ]
            else:
                network = ipaddress.IPv4Network(str(summary.prefix), strict=False)
                costs = [
                    route.metric
                    for route in calculation.routes
                    if ipaddress.IPv4Network(route.prefix).subnet_of(network)
                ]
                # `calculate()` omits the stubs that are attached to the calculating
                # router. These stubs are part of its advertised range.
                for own in other.of_type(ospf.ROUTER):
                    if own.adv_router != summary.adv_router:
                        continue
                    for link in own.links:
                        if link.link_type == ospf.STUB:
                            with suppress(ValueError):
                                if ipaddress.IPv4Network(f"{link.link_id}/{link.link_data}").subnet_of(
                                    network
                                ):
                                    costs.append(link.metric)
            if costs:
                model.lsas[summary.key] = replace(summary, metric=max(costs))
            else:
                model.lsas.pop(summary.key, None)
    return entries, gaps
