"""One device and one packet through the firewall gate of the hop tracer and
through the access policy of the symbolic model.

The tracer side is `_firewall_verdict` (`path/gates/firewall.py`) on a pinned
session. The symbolic side is the policy that `_access_policy`
(`analysis_model/network.py`) binds for the same device and interfaces, read
for one packet by `ir_outcome`.

`symbolic_policy` passes the egress interface as the model builder does
(`analysis_model/network.py`). The egress is None unless a bound rulebase
decides by the egress interface.

`ir_outcome` applies the rules of `policy/compile.py` in Python. A rule whose
match is undecided gives its own outcome and the outcome of the rules after it.
Every ordered layer must permit. A call that returns resumes after the calling
rule. A return of an ordered layer is undecided. A policy whose installation is
not established is undecided.

`compiled_outcomes` runs `PolicyCompiler` on the packet set that
`member_packets` builds for the probe. It needs the native backend `dd.cudd`.

A probe states no source port. A predicate on a field that the probe does not
state is undecided.

`_firewall_verdict` reads no state policy of the device and no NAT.
`_apply_firewall` reads them, and it is not under test here.

`answer_verdicts` gives one request to `impact.evaluate.answer` and to
`SymbolicEvaluation.answer_network`. It needs the native backend.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from typing import Any

import hst.path as path
from hst.analysis_model.graph import GraphInventory
from hst.analysis_model.network import _access_policy, _context, _egress_scoped
from hst.impact.evaluate import Member, RequestSet, Service, member
from hst.path.addrsets import _intervals, _ports, _rule_intervals_status
from hst.path.gates import firewall as fw
from hst.path.verdict import DENY, INDETERMINATE, PERMIT, classify_action
from hst.policy.ir import AllOf, AnyOf, Atom, Constant, Not, Policy, Ref, Unknown

PROTOCOLS = {"tcp": 6, "udp": 17, "icmp": 1}
# Outside every address and port that a case states.
OUTSIDE_SOURCE = "198.18.0.1"
OUTSIDE_DESTINATION = "198.18.0.2"
OUTSIDE_PORT = 1
MAX_PROBES = 4000

# No rulebase governs the device for the packet.
UNGOVERNED = "ungoverned"
# The compiler permits one part of the packets of the probe and denies the rest.
SPLIT = "split"


@dataclass(frozen=True, slots=True)
class Probe:
    source: str
    destination: str
    protocol: str
    port: int | None
    state: str = "new"

    def packet(self) -> dict[str, int]:
        """The header fields that the probe states."""
        fields = {
            "source_address": int(ipaddress.ip_address(self.source)),
            "destination_address": int(ipaddress.ip_address(self.destination)),
            "protocol": PROTOCOLS[self.protocol],
        }
        if self.port is not None:
            fields["destination_port"] = self.port
        return fields


@dataclass(frozen=True, slots=True)
class Outcome:
    verdict: str
    # The tracer side holds the reason text of the gate. The symbolic side holds
    # the gap codes of the IR, joined by a comma.
    detail: str = ""


@dataclass(frozen=True, slots=True)
class Difference:
    case: str
    vendor: str
    probe: Probe
    tracer: Outcome
    # The decision of the policy, with its installation.
    symbolic: Outcome
    # The decision of the layers of the policy, without its installation.
    rules: Outcome

    @property
    def kind(self) -> str:
        """`installation` is a decision of the layers that equals the decision
        of the gate and that the symbolic side withholds for the installation
        evidence. `conflict` is a permit against a deny. `binding` is a
        governed device against an ungoverned one. `precision` is a decided
        verdict against an undecided one."""
        if self.rules.verdict == self.tracer.verdict:
            return "installation"
        verdicts = {self.tracer.verdict, self.rules.verdict}
        if verdicts == {PERMIT, DENY}:
            return "conflict"
        return "binding" if UNGOVERNED in verdicts else "precision"

    @property
    def cause(self) -> tuple[str, str, str, str, str, str]:
        """The key that groups differences with one origin."""
        kind = self.kind
        symbolic = self.symbolic if kind == "installation" else self.rules
        return (
            kind,
            self.vendor,
            self.tracer.verdict,
            symbolic.verdict,
            re.sub(r"\d+", "N", self.tracer.detail),
            symbolic.detail,
        )


# --- the tracer side ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Hop:
    """The device under test and the interfaces that the packet crosses."""

    device: str
    context: str
    ingress: str
    egress: str | None


def tracer_outcome(session: Any, hop: Hop, probe: Probe) -> Outcome:
    """The gate's decision for a forwarded packet of the probe."""
    verdict = fw._firewall_verdict(
        session,
        hop.device,
        hop.ingress,
        hop.egress,
        _intervals([probe.source]),
        _intervals([probe.destination]),
        probe.port,
        probe.protocol,
        conn_state=probe.state,
    )
    if verdict is None:
        return Outcome(UNGOVERNED)
    if isinstance(verdict, list):
        raise TypeError("a point probe returned regions")
    return Outcome(classify_action(verdict["action"]), str(verdict.get("indeterminate_reason") or ""))


# --- the symbolic side ----------------------------------------------------------------


def symbolic_policy(graph: GraphInventory, hop: Hop, state: str = "new") -> Policy | None:
    """The access policy that the symbolic model binds for the hop, or None when it binds none."""
    context = _context({}, graph, hop.context, "estate", 4, hop.device)
    scoped = any(
        relation.props.get("egress_interface_uid") not in (None, "*")
        for relation in graph.outgoing.get((context.firewall_instance, "ENFORCES"), ())
    ) or _egress_scoped(graph, context, hop.ingress, 4)
    egress = hop.egress if scoped else None
    return _access_policy(graph, context, hop.device, hop.ingress, egress, 4, state)


def _truth(
    predicate: Any, packet: Mapping[str, int], objects: Mapping[Any, Any]
) -> tuple[bool | None, set[str]]:
    """Kleene truth of a predicate for one packet, with the codes that leave it undecided."""
    if isinstance(predicate, Constant):
        return predicate.value, set()
    if isinstance(predicate, Unknown):
        return None, {predicate.code}
    if isinstance(predicate, Ref):
        definition = objects.get(predicate.key)
        if definition is None:
            return None, {"OBJECT_NOT_DEFINED"}
        return _truth(definition.predicate, packet, objects)
    if isinstance(predicate, Atom):
        value = packet.get(predicate.field)
        if value is None:
            return None, {f"PROBE_STATES_NO_{predicate.field.upper()}"}
        if predicate.operation == "eq":
            return value == predicate.value, set()
        other = int(predicate.other or 0)
        if predicate.operation == "range":
            return predicate.value <= value <= other, set()
        return value & other == predicate.value & other, set()
    if isinstance(predicate, Not):
        inner, codes = _truth(predicate.term, packet, objects)
        return (None if inner is None else not inner), codes
    if not isinstance(predicate, (AllOf, AnyOf)):
        raise TypeError(f"unsupported predicate {type(predicate).__name__}")
    decisive = not isinstance(predicate, AllOf)
    codes: set[str] = set()
    undecided = False
    for term in predicate.terms:
        value, term_codes = _truth(term, packet, objects)
        if value is decisive:
            return decisive, set()
        if value is None:
            undecided = True
            codes |= term_codes
    return (None, codes) if undecided else (not decisive, set())


_EVERY_OUTCOME = frozenset({"permit", "deny", "return"})


def _layer(
    policy: Policy, uid: str, packet: Mapping[str, int], stack: tuple[str, ...] = ()
) -> tuple[set[str], set[str]]:
    """The outcomes that a layer can have for the packet, with the codes that
    leave it undecided. A rule whose match is undecided gives its own outcome
    and the outcome of the rules after it, as `_block` composes them."""
    layers = {layer.uid: layer for layer in policy.layers}
    objects = {definition.key: definition for definition in policy.objects}
    if uid in stack:
        return set(_EVERY_OUTCOME), {"LAYER_CALL_CYCLE"}
    if uid not in layers:
        return set(_EVERY_OUTCOME), {"LAYER_MISSING"}
    outcomes: set[str] = set()
    codes: set[str] = set()
    for rule in layers[uid].rules:
        if not rule.enabled:
            continue
        if rule.install_targets and policy.context.firewall_instance not in rule.install_targets:
            continue
        matched, match_codes = _truth(rule.predicate, packet, objects)
        if matched is True and rule.install_targets is None:
            matched, match_codes = None, {"INSTALL_ON_UNKNOWN"}
        if matched is False:
            continue
        if matched is None:
            codes |= match_codes
        resumes = False
        if rule.action == "call":
            called, called_codes = _layer(policy, str(rule.called_layer), packet, (*stack, uid))
            codes |= called_codes
            outcomes |= called - {"return"}
            resumes = "return" in called
        elif rule.action == "unknown":
            outcomes |= _EVERY_OUTCOME
            codes.add("ACTION_UNKNOWN")
        else:
            outcomes.add(rule.action)
        if matched is True and not resumes:
            return outcomes, codes
    default = layers[uid].default
    if default == "unknown":
        return outcomes | _EVERY_OUTCOME, codes | {"LAYER_DEFAULT_UNKNOWN"}
    return outcomes | {default}, codes


def rules_outcome(policy: Policy, probe: Probe) -> Outcome:
    """The decision of the layers of the policy for the probe, without the
    installation. A packet is permitted when every ordered layer can only
    permit it. A packet is denied when one ordered layer can only deny it."""
    packet = probe.packet()
    certain, possible = True, True
    codes: set[str] = set()
    for uid in policy.ordered_layers:
        outcomes, layer_codes = _layer(policy, uid, packet)
        certain = certain and outcomes == {"permit"}
        possible = possible and bool(outcomes & {"permit", "return"})
        if len(outcomes) > 1:
            codes |= layer_codes
        if "return" in outcomes:
            codes.add("TOP_LEVEL_RETURN")
    if certain:
        return Outcome(PERMIT)
    if not possible:
        return Outcome(DENY)
    return Outcome(INDETERMINATE, ",".join(sorted(codes)))


def ir_outcome(policy: Policy | None, probe: Probe) -> Outcome:
    """The decision of the policy for the probe. A policy whose installation is
    not established decides no packet."""
    if policy is None:
        return Outcome(UNGOVERNED)
    installed, codes = _truth(policy.installation, probe.packet(), {})
    if installed is not True:
        return Outcome(INDETERMINATE, ",".join(sorted(codes)) or "POLICY_NOT_INSTALLED")
    return rules_outcome(policy, probe)


def ir_outcomes(policy: Policy | None, asked: Iterable[Probe]) -> dict[Probe, tuple[Outcome, Outcome]]:
    """The decision of the policy and the decision of its layers for each probe."""
    return {
        probe: (
            (decided := ir_outcome(policy, probe)),
            rules_outcome(policy, probe) if policy is not None else decided,
        )
        for probe in asked
    }


def _request(probe: Probe) -> tuple[RequestSet, Member]:
    def point(text: str) -> tuple[tuple[int, int, int], ...]:
        value = int(ipaddress.ip_address(text))
        return ((4, value, value),)

    target = Member("probe", point(probe.destination))
    # A port interval has the family 0 (`path.addrsets._ports`).
    service = Service(
        frozenset({PROTOCOLS[probe.protocol]}),
        None if probe.port is None else ((0, probe.port, probe.port),),
    )
    return RequestSet("probe", point(probe.source), "probe", (target,), member("probe"), service), target


def compiled_outcomes(policy: Policy | None, asked: Iterable[Probe]) -> dict[Probe, tuple[Outcome, Outcome]]:
    """`ir_outcomes` by `PolicyCompiler`. The decision of the layers is the
    decision of the policy with an established installation."""
    from hst.assessment.symbolic_evaluation import member_packets
    from hst.policy.compile import PolicyCompiler
    from hst.symbolic import HeaderSchema, SymbolicManager

    if policy is None:
        return {probe: (Outcome(UNGOVERNED), Outcome(UNGOVERNED)) for probe in asked}
    installed = replace(policy, installation=Constant(True))
    out: dict[Probe, tuple[Outcome, Outcome]] = {}
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        compiled: dict[frozenset[str], tuple[Any, Any]] = {}
        for probe in asked:
            packets = member_packets(manager, *_request(probe))
            mask = packets.known_fields
            if mask not in compiled:
                compiled[mask] = tuple(
                    PolicyCompiler(manager, policy.context, mask).compile(item)
                    for item in (policy, installed)
                )
            decided = []
            for item in compiled[mask]:
                decision = item.evaluate(packets)
                lower, upper = decision.bounds.lower, decision.bounds.upper
                if packets.subtract(lower).is_empty():
                    decided.append(Outcome(PERMIT))
                elif upper.is_empty():
                    decided.append(Outcome(DENY))
                elif upper.subtract(lower).is_empty():
                    decided.append(Outcome(SPLIT))
                else:
                    codes = sorted({gap.reason.code for gap in decision.gaps})
                    decided.append(Outcome(INDETERMINATE, ",".join(codes)))
            out[probe] = (decided[0], decided[1])
    return out


# --- the probes -----------------------------------------------------------------------


def _edges(intervals: Iterable[tuple[int, int, int]], floor: int, ceiling: int) -> set[int]:
    values: set[int] = set()
    for _family, low, high in intervals:
        values |= {low, high, low - 1, high + 1}
    return {value for value in values if floor <= value <= ceiling}


def probes(rows: list[dict[str, Any]], states: tuple[str, ...] = ("new",)) -> list[Probe]:
    """The probes of one rulebase. Each address interval and each port interval
    of a rule gives its first value, its last value and the 2 values next to
    it. `OUTSIDE_SOURCE`, `OUTSIDE_DESTINATION` and `OUTSIDE_PORT` are added."""
    sides: dict[str, set[int]] = {"src": set(), "dst": set()}
    ports: set[int] = {OUTSIDE_PORT}
    for row in rows:
        for side in ("src", "dst"):
            intervals, _unparsed = _rule_intervals_status(
                row.get(f"{side}_cidrs") or [], row.get(f"{side}_ips") or [], row.get(f"{side}_ranges") or []
            )
            sides[side] |= _edges((item for item in intervals if item[0] == 4), 1, 2**32 - 2)
        for spec in row.get("ports") or []:
            try:
                ports |= _edges(_ports(str(spec).lstrip("!")) if spec else [], 1, 65535)
            except (TypeError, ValueError):
                continue
    sources = sorted({str(ipaddress.ip_address(v)) for v in sides["src"]} | {OUTSIDE_SOURCE})
    destinations = sorted({str(ipaddress.ip_address(v)) for v in sides["dst"]} | {OUTSIDE_DESTINATION})
    out = [
        Probe(source, destination, protocol, None if protocol == "icmp" else port, state)
        for state in states
        for source in sources
        for destination in destinations
        for protocol in PROTOCOLS
        for port in (sorted(ports) if protocol != "icmp" else [OUTSIDE_PORT])
    ]
    if len(out) > MAX_PROBES:
        step = -(-len(out) // MAX_PROBES)
        out = out[::step]
    return out


# --- the comparison -------------------------------------------------------------------

_ACCESS_RULEBASES = """
MATCH (rb:FwRulebase:Obj)
WHERE rb.collection_ts = $snap AND NOT rb:Retired AND coalesce(rb.kind, '') <> 'nat'
RETURN rb.uid AS uid, rb.vendor AS vendor ORDER BY rb.uid
"""


def differences(
    session: Any,
    graph: GraphInventory,
    hop: Hop,
    *,
    case: str,
    states: tuple[str, ...] = ("new",),
) -> tuple[list[Probe], list[Difference]]:
    """The probes of one hop and the probes that the 2 sides decide
    differently. The probes come from the rules of every access rulebase of
    the pinned run."""
    rulebases = path._read(session, _ACCESS_RULEBASES)
    vendor = ",".join(sorted({str(row["vendor"] or "") for row in rulebases}))
    rows = [rule for row in rulebases for rule in fw._rule_rows(session, row["uid"])]
    asked = probes(rows, states)
    decided: dict[Probe, tuple[Outcome, Outcome]] = {}
    for state in states:
        decided |= ir_outcomes(symbolic_policy(graph, hop, state), [p for p in asked if p.state == state])
    out: list[Difference] = []
    for probe in asked:
        tracer = tracer_outcome(session, hop, probe)
        symbolic, rules = decided[probe]
        if tracer.verdict != symbolic.verdict:
            out.append(Difference(case, vendor, probe, tracer, symbolic, rules))
    return asked, out


def causes(found: Iterable[Difference]) -> dict[tuple[str, str, str, str, str, str], list[Difference]]:
    grouped: dict[tuple[str, str, str, str, str, str], list[Difference]] = {}
    for difference in found:
        grouped.setdefault(difference.cause, []).append(difference)
    return dict(sorted(grouped.items()))


# --- the answers ----------------------------------------------------------------------


def flow_request(source: str, destination: str, port: int) -> RequestSet:
    """A TCP request from one source address to one destination address and port."""
    request, _target = _request(Probe(source, destination, "tcp", port))
    return request


def answer_verdicts(
    session: Any, graph: GraphInventory, request: RequestSet, mode: str = "possible"
) -> tuple[str, str]:
    """The verdict of `impact.evaluate.answer` and the verdict of
    `SymbolicEvaluation.answer_network` for the request, each by the outcome
    function of its engine (`assessment/service.py`, `network_outcome`)."""
    from hst.assessment import evaluation
    from hst.assessment.symbolic_evaluation import SymbolicEvaluation
    from hst.assessment.symbolic_results import outcome
    from hst.impact.evaluate import answer

    network = evaluation.load_network(session, request)
    legacy = evaluation.outcome(answer(network, request, mode))["verdict"]
    with SymbolicEvaluation(graph, "estate") as engine:
        symbolic = outcome(engine.answer_network(network, request, mode))["verdict"]
    return legacy, symbolic
