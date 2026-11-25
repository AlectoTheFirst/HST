"""Map routing model uncertainty to the forwarding contexts it can affect."""

from __future__ import annotations

import ipaddress
from collections import defaultdict, deque
from collections.abc import Mapping, Sequence
from typing import Any

from . import certainty
from .compile import policy_scoped
from .rib import RibInput

# The ErrorSink kinds whose fallback behavior is a modeled vendor semantic,
# or that name a requested change with no effect.
DIAGNOSTIC_KINDS = frozenset(
    {
        "undefined-prefix-list",
        "undefined-neighbor-prefix-list",
        "undefined-neighbor-route-map",
        "undefined-policy-call",
        "invalid-continue-target",
        "undefined-continue-target",
        "undefined-redistribute-route-map",
        "ospf-next-hop-unresolved",
        "ospf-change-no-effect",
        "unknown-bgp-session",
        # The NX-OS documentation states that route filtering ignores the match
        # lines of policy-based routing. The engine ignores them.
        "pbr-only-match",
    }
)

UNCERTAIN_KINDS = frozenset(
    {
        "unresolved-platform-profile",
        "unknown-platform",
        "seed-without-session",
        "unpaired-bgp-session",
        "unknown-origination-process",
        "unknown-seed-process",
        "no-routing-fixed-point",
        "no-rib-fixed-point",
        "malformed-route",
        "ospf-router-id-unknown",
        "redistribution-not-modeled",
        "malformed-lsa",
        "unknown-lsa-type",
        "ospf-ambiguous-next-hop",
        "ospf-unnumbered-link",
        "ospf-virtual-link-not-modeled",
        "rib-route-mismatch",
        "ospf-route-mismatch",
        # The snapshot does not hold the community list or the AS-path list. A
        # snapshot whose collector did not read these lists holds none of them
        # (compile.py `_LIST_KEYS`).
        "undefined-community-list",
        "undefined-as-path-list",
        # The engine does not model a match, set or list line that the collector
        # kept. The match result of the entry or the attributes that it sets are unknown.
        "unsupported-match",
        "unsupported-set",
        "unsupported-policy",
        "unsupported-list-entry",
        # The sessions of an iBGP process do not record route-reflector-client. The
        # routes that the process reflects are unknown (propagate._report_unknown_reflection).
        "bgp-reflection-unknown",
        # The engine denies every route in the direction of a neighbor AS-path
        # filter-list (bestpath.apply_attached_policy).
        "neighbor-filter-list-not-modeled",
        # The collector wrote no session for a configured neighbor. The routes of
        # that neighbor are unknown (app/simul_read.py, `session_gaps`).
        "bgp-session-not-recorded",
        # A process refers to a route policy outside the namespace in which it
        # resolves names, for example the route map of a virtual system from
        # another context. The policy that the name selects is unknown
        # (app/simul_read.py).
        "policy-context-ambiguous",
    }
)

KNOWN_ERROR_KINDS = DIAGNOSTIC_KINDS | UNCERTAIN_KINDS


def _text(value: Any) -> str:
    return str(value or "").strip()


def _policy_references(node: Mapping[str, Any]) -> set[str]:
    refs: set[str] = set()
    for entry in node.get("entries") or ():
        for key in (
            "calls_policy",
            "match_prefix_lists",
            "match_community_lists",
            "match_as_path_lists",
            "match_policies",
            "set_comm_list_delete",
        ):
            value = entry.get(key)
            if isinstance(value, str):
                refs.add(value)
            else:
                refs.update(_text(item) for item in value or () if _text(item))
    return refs


def _redistribution_maps(process: Mapping[str, Any]) -> set[str]:
    names = {
        _text(value)
        for key, value in process.items()
        if key.startswith("redist_") and key.endswith("_route_map") and _text(value)
    }
    names.update(
        _text(item.get("route_map"))
        for item in process.get("redistribute") or ()
        if _text(item.get("route_map"))
    )
    return names


class _Dependencies:
    def __init__(self, inp: RibInput) -> None:
        self.inp = inp
        self.contexts = {_text(row.get("uid")) for row in inp.contexts if _text(row.get("uid"))}
        self.device_contexts: dict[str, set[str]] = defaultdict(set)
        self.process_context: dict[str, str] = {}
        self.session_context: dict[str, str] = {}
        # Maps (policy namespace, policy name) to the contexts that the policy
        # reaches. The namespace is the device, or the context of the Check Point
        # virtual system, that defines the policy (`compile.resolving_namespace`).
        self.policy_contexts: dict[certainty.PolicyKey, set[str]] = defaultdict(set)
        self.platform_contexts: dict[str, set[str]] = defaultdict(set)
        self.ospf_contexts = {_text(row.get("context_uid")) for row in inp.ospf}
        self.bgp_contexts: set[str] = set()
        for row in inp.contexts:
            self.device_contexts[_text(row.get("device_uid"))].add(_text(row.get("uid")))
        bgp = inp.bgp
        processes = list(bgp.processes) if bgp is not None else []
        for row in (*processes, *inp.ospf):
            uid, context = _text(row.get("uid")), _text(row.get("context_uid"))
            if uid and context:
                self.process_context[uid] = context
            if context and _text(row.get("platform")):
                self.platform_contexts[_text(row.get("platform")).lower()].add(context)
        self.bgp_contexts = {
            _text(row.get("context_uid")) for row in processes if _text(row.get("context_uid"))
        }
        sessions = list(bgp.sessions) if bgp is not None else []
        scope = certainty.policy_scope(inp)
        process_row = {_text(row.get("uid")): row for row in processes}
        for row in sessions:
            context = self.process_context.get(_text(row.get("process_uid")), "")
            if context:
                self.session_context[_text(row.get("uid"))] = context
                owner = scope(process_row.get(_text(row.get("process_uid")), {}), None)
                for key in certainty.SESSION_POLICY_KEYS:
                    if _text(row.get(key)):
                        self.policy_contexts[(owner, _text(row[key]))].add(context)
        for process in processes:
            for name in _redistribution_maps(process):
                self.policy_contexts[(scope(process, None), name)].add(_text(process.get("context_uid")))
        for process in inp.ospf:
            context = _text(process.get("context_uid"))
            for name in _redistribution_maps(process):
                self.policy_contexts[(scope(process, context), name)].add(context)
        policies = list(bgp.policies) if bgp is not None else []
        scoped = policy_scoped(policies)
        callers: dict[certainty.PolicyKey, set[certainty.PolicyKey]] = defaultdict(set)
        for policy in policies:
            pkey = certainty.policy_key(policy, scoped)
            for ref in _policy_references(policy):
                callers[(pkey[0], ref)].add(pkey)
        changed = True
        while changed:
            changed = False
            for referenced, names in callers.items():
                inherited = set().union(*(self.policy_contexts.get(name, set()) for name in names))
                before = len(self.policy_contexts[referenced])
                self.policy_contexts[referenced].update(inherited)
                changed |= len(self.policy_contexts[referenced]) != before
        # An error holds the bare name of a policy. The name maps to the contexts
        # of every namespace that has a policy of that name.
        self.policy_name_contexts: dict[str, set[str]] = defaultdict(set)
        for (_owner, name), contexts in self.policy_contexts.items():
            self.policy_name_contexts[name] |= contexts
        self.lsa_contexts: dict[str, set[str]] = defaultdict(set)
        for process in inp.ospf:
            context = _text(process.get("context_uid"))
            uid = _text(process.get("uid"))
            if uid:
                self.lsa_contexts[uid].add(context)
            for row in process.get("rows") or ():
                lsa_type = _text(row.get("lsa_type")) or "?"
                lsid = _text(row.get("lsid")) or "?"
                adv = _text(row.get("adv_router")) or "?"
                self.lsa_contexts[f"{lsa_type} LSA {lsid} from {adv}"].add(context)
                for value in (row.get("lsid"), row.get("adv_router")):
                    if _text(value):
                        self.lsa_contexts[_text(value)].add(context)
        self.dependencies: dict[str, set[str]] = defaultdict(set)
        for pair in inp.rt_pairs:
            importer, exporter = _text(pair.get("importer")), _text(pair.get("exporter"))
            if importer and exporter:
                self.dependencies[exporter].add(importer)
        # The context of each side of a peering depends on the context of the
        # other side. The context of a session in `certainty.observed_sessions`
        # does not depend on the far end. The calculation takes the received
        # paths of that session from the observation.
        observed = certainty.observed_sessions(inp)
        by_endpoints = {(_text(row.get("local_ip")), _text(row.get("peer_ip"))): row for row in sessions}
        for row in sessions:
            far = by_endpoints.get((_text(row.get("peer_ip")), _text(row.get("local_ip"))))
            left = self.process_context.get(_text(row.get("process_uid")))
            right = self.process_context.get(_text((far or {}).get("process_uid")))
            if left and right and far is not None:
                if _text(row.get("uid")) not in observed:
                    self.dependencies[right].add(left)
                if _text(far.get("uid")) not in observed:
                    self.dependencies[left].add(right)

    def malformed_route_contexts(self) -> set[str]:
        affected: set[str] = set()
        for row in (*self.inp.connected, *self.inp.static):
            try:
                ipaddress.ip_network(_text(row.get("prefix")), strict=False)
            except ValueError:
                if _text(row.get("context_uid")):
                    affected.add(_text(row.get("context_uid")))
        return affected

    def direct(self, error: Mapping[str, Any]) -> set[str]:
        kind, subject = _text(error.get("kind")), _text(error.get("subject"))
        if subject in self.contexts:
            return {subject}
        if subject in self.process_context:
            return {self.process_context[subject]}
        if subject in self.session_context:
            return {self.session_context[subject]}
        if subject in self.device_contexts:
            return set(self.device_contexts[subject])
        if subject in self.policy_name_contexts:
            return set(self.policy_name_contexts[subject])
        if subject in self.lsa_contexts:
            return set(self.lsa_contexts[subject])
        if kind == "malformed-route":
            return self.malformed_route_contexts()
        if kind.startswith("ospf-") or kind in {"malformed-lsa", "unknown-lsa-type"}:
            return set(self.ospf_contexts)
        if kind in {
            "seed-without-session",
            "unpaired-bgp-session",
            "unknown-origination-process",
            "unknown-seed-process",
        }:
            return set(self.bgp_contexts)
        if kind in {"unknown-platform", "unresolved-platform-profile"}:
            raw = subject.lower()
            matched = {
                _text(row.get("uid"))
                for row in self.inp.contexts
                if _text(row.get("platform") or self.inp.platform).lower() == raw
            }
            matched.update(self.platform_contexts.get(raw, ()))
            return matched or set(self.contexts)
        return set(self.contexts)

    def closure(self, roots: set[str]) -> set[str]:
        out = set(roots)
        queue = deque(roots)
        while queue:
            for dependent in self.dependencies.get(queue.popleft(), ()):
                if dependent not in out:
                    out.add(dependent)
                    queue.append(dependent)
        return out


def affected_contexts(
    inp: RibInput, model_errors: Sequence[Mapping[str, Any]]
) -> dict[str, list[dict[str, str | None]]]:
    """Insufficient-knowledge errors grouped by every dependent context.

    Values retain the ErrorSink ``kind``, ``detail``, and ``subject`` fields.
    Known deterministic diagnostics are omitted. A kind outside
    `KNOWN_ERROR_KINDS` is attached to every context.
    """
    dependencies = _Dependencies(inp)
    affected: dict[str, list[dict[str, str | None]]] = defaultdict(list)
    seen: set[tuple[str, str, str, str | None]] = set()
    for error in model_errors:
        kind = _text(error.get("kind"))
        if kind in DIAGNOSTIC_KINDS:
            continue
        detail = _text(error.get("detail"))
        subject = None if error.get("subject") is None else str(error.get("subject"))
        held = {
            "kind": kind,
            "detail": detail,
            "subject": subject,
        }
        for context in sorted(dependencies.closure(dependencies.direct(error))):
            key = (context, kind, detail, subject)
            if key not in seen:
                seen.add(key)
                affected[context].append(held)
    return dict(affected)
