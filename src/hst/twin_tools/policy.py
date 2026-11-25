"""The security policy tool `policy_evaluate`.

`mode: explain_rule` explains one firewall rule with the symbolic-v2 engine.
The answer lists the flow rectangles whose first match is the rule
(first_match) and the flow rectangles that the snapshot does not decide
(not_decided). `summary.lines` is the explanation for an engineer. It states
what the rule does and on which exits, the policy route and tunnel that the
rule stands behind, and the exits that the rule does not cover. The rule is
explained in the configured policy of its rulebase, after the earlier rules
and layers of that policy have taken the flows that they decide, for the flows
that the rulebase receives in each interface and connection-state scope
(`hst.assessment.rule_scope`). `match_detail` holds the sentence of the
engine. The computation runs in the analysis child process through
`run_isolated`, as the result pages of an assessment do, and shares its
process slot. It needs the symbolic-v2 analysis engine, its native backend,
and a run with an evidence manifest.

`mode: match_flow` decides one flow against the access rulebases of one
device and lists the rules that match it. With the symbolic-v2 prerequisites
(the engine, its native backend and a run with an evidence manifest) the
child decides the flow in each configured policy
(`hst.assessment.flow_match`). Without them the match is derived from a
trace. The firewall gate of the path engine judges the flow between the
ingress and egress interfaces of the device. The caller names these
interfaces, or a trace of the flow crosses them. Without the prerequisites and
without an ingress interface the answer is `engine_unavailable`. Rulebases
page with the cursor.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, RootModel

from hst import path as pathmod
from hst.app.ai.registry import ToolContext, ToolError, ToolErrorCode, ToolRegistry
from hst.core import db as dbmod
from hst.path import leak_guard
from hst.results.words import (
    Missing as WordsMissing,
)
from hst.results.words import (
    Result,
    decided,
    decided_first_line,
    from_engine,
    not_covered_line,
    not_decided_line,
    rule_does_line,
    rule_role_line,
)
from hst.twin_tools import selectors
from hst.twin_tools.envelope import (
    Bounds,
    Call,
    Evidence,
    ItemEvidence,
    Missing,
    catalogue_spec,
    gap_list,
    http_error,
    jsonable,
    missing_of,
    whole_result,
)
from hst.twin_tools.reach import TraceFlow

ENGINE = "symbolic-v2"
LEGACY_ENGINE = "legacy-v1"

# Interface pairs one trace-derived match judges.
MAX_INTERFACE_PAIRS = 8

_DEVICE_INTERFACES = """
MATCH (i:Interface:Obj)-[o:ON]->(:Device:Obj {uid: $dev, collection_ts: $snap})
WHERE NOT i:Retired AND o._retired_at IS NULL AND i.collection_ts = $snap
  AND (i.uid IN $uids OR ($name IS NOT NULL AND i.name = $name))
RETURN i.uid AS uid, i.name AS name
ORDER BY uid LIMIT 33"""


class ExplainRuleInput(selectors.PagedInput):
    """The flows that arrive at one firewall rule and match it."""

    mode: Literal["explain_rule"] = Field(
        description="explain_rule gives the flows that arrive at one rule and match it."
    )
    rulebase: str = Field(min_length=1, max_length=512, description="The FwRulebase uid.")
    rule: str = Field(min_length=1, max_length=512, description="The FwRule uid, a rule of the rulebase.")
    address_family: Literal[4, 6] | None = Field(
        default=None,
        description=(
            "The address family the flows are in. By default the family the rulebase records, or 4 when it "
            "records none; a rulebase of the other family is refused."
        ),
    )
    firewall: str | None = Field(
        default=None,
        min_length=1,
        max_length=512,
        description=(
            "For a Check Point rulebase, the uid of the gateway Device the rulebase is explained for; the "
            "install-on column of each rule is bound to it. Needed when more than one gateway enforces the "
            "rulebase. Other rulebases have no install-on column and ignore it."
        ),
    )


class MatchFlowInput(selectors.PagedInput):
    """The firewall rules of one device that match one flow."""

    mode: Literal["match_flow"] = Field(
        description="match_flow decides one flow against the access rulebases of one device."
    )
    device: selectors.DeviceRef
    flow: TraceFlow
    rulebase: str | None = Field(
        default=None,
        min_length=1,
        max_length=512,
        description="Only this FwRulebase uid, one of the rulebases that govern the device.",
    )
    ingress_interface: str | None = Field(
        default=None,
        min_length=1,
        max_length=512,
        description=(
            "The uid or name of the device interface the flow arrives on. Omitted, a trace of the flow "
            "derives it when the symbolic-v2 prerequisites are missing."
        ),
    )
    egress_interface: str | None = Field(
        default=None,
        min_length=1,
        max_length=512,
        description="The uid or name of the device interface the flow leaves by.",
    )


class PolicyEvaluateInput(
    RootModel[Annotated[ExplainRuleInput | MatchFlowInput, Field(discriminator="mode")]]
):
    """mode: explain_rule explains one rule; mode: match_flow matches one flow on one device."""


class PolicyEvaluateResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    mode: Literal["explain_rule", "match_flow"]
    rulebase: str | None = None
    rule: str | None = None
    firewall: str | None = Field(
        default=None, description="the gateway Device the install-on column of a Check Point rule is bound to"
    )
    action: str | None = None
    summary: dict[str, Any] | None = Field(
        default=None,
        description=(
            "explain_rule: the explanation of the rule. lines is the answer, in order: what the rule does "
            "and on which exits; the policy routes and tunnel it stands behind, when there are any; the "
            "exits of the rulebase it does not cover, when there are any; and what is not decided. does, "
            "role and not_covered are the same facts as fields"
        ),
    )
    match_detail: str | None = Field(
        default=None,
        description=(
            "explain_rule: the engine's sentence on the flows the rule matches, with the interface and "
            "connection state scopes; for a question about the match detail"
        ),
    )
    first_match: list[dict[str, Any]] | None = Field(
        default=None, description="flow rectangles whose first match is the rule, on this page"
    )
    not_decided: list[dict[str, Any]] | None = Field(
        default=None,
        description="flow rectangles the snapshot does not decide for the rule, beyond the first_match ones",
    )
    first_match_count: int | None = None
    not_decided_count: int | None = None
    entry: dict[str, Any] | None = Field(
        default=None,
        description=(
            "explain_rule: the flows the rulebase receives: its zone pair, ACL bindings or chain, the "
            "ingress and egress interface names ('(local)' is the router itself), the connection states, "
            "and the global state policy that decides the other states first; evaluated is false when the "
            "graph does not hold them"
        ),
    )
    scopes: list[dict[str, Any]] | None = Field(
        default=None,
        description=(
            "explain_rule: the interface and state scopes the rule matches flows in; each rectangle's "
            "scope is an index into this list, and applies_when lists the ingress interfaces, egress "
            "interfaces and states ('(other)' is an interface the snapshot does not name; null is not "
            "evaluated); first_match_count and not_decided_count are its rectangles, and "
            "first_match_pieces or not_decided_pieces is the number of disjoint rectangles of a region "
            "listed in part"
        ),
    )
    intent: dict[str, Any] | None = Field(
        default=None,
        description=(
            "explain_rule: the policy routes a drop rule stands behind, as records. A record names the "
            "tunnel a policy route sends the rule's hosts into, the policy routes, the hosts, the rule's "
            "own exits, the exits of the rulebase the normal routing table uses without the policy routes "
            "(exits_covered when the rule blocks the hosts there, exits_not_covered when it does not), "
            "decided (false with missing when a step is open) and line. leak_guards holds the records with "
            "covered exits, guard_gaps those with exits not covered; detail holds the routes, tables, zones "
            "and object membership"
        ),
    )
    device: str | None = Field(default=None, description="match_flow: the device uid")
    engine: str | None = Field(default=None, description="match_flow: the engine that decided the flow")
    rulebases: list[dict[str, Any]] | None = Field(
        default=None,
        description=(
            "match_flow: per rulebase on this page, the decision (permit, deny, partly, open, or "
            "not_applicable when the rulebase does not receive a flow through the named interfaces), "
            "whether it receives the flow (null when an unnamed interface leaves it open), "
            "the deciding rule and the candidate rules, with evidence"
        ),
    )


def explanation(
    facts: dict[str, Any] | None, intent: Mapping[str, Any], sentence: str | None = None
) -> dict[str, Any]:
    """The summary of one rule explanation.

    Line 1 states what the rule does, from `facts` (`leak_guard.rule_facts`).
    It is the `sentence` of the engine when the rule has no facts (a disabled
    rule, addresses that are not modeled). Line 2 holds the policy routes and
    tunnels of the leak guard records. Line 3 holds the exits that the rule
    does not cover. The last line states what is not decided."""
    records = [*(intent.get("leak_guards") or ()), *(intent.get("guard_gaps") or ())]
    lines = [rule_does_line(**facts)] if facts else ([sentence] if sentence else [])
    role: dict[str, Any] | None = None
    not_covered: list[str] = []
    if facts and records:
        hosts = facts["hosts"]
        tunnels = list(dict.fromkeys(str((r.get("tunnel") or {}).get("interface")) for r in records))
        routes = sorted(
            {
                (str(route["policy"]["name"]), route["rule"]["position"])
                for r in records
                for route in (r.get("detail") or {}).get("policy_routes") or ()
            },
            key=lambda item: (item[0], str(item[1])),
        )
        role = {"tunnels": tunnels, "policy_routes": [f"{name} rule {position}" for name, position in routes]}
        if routes:
            lines.append(
                rule_role_line(
                    position=facts["position"],
                    hosts=hosts,
                    tunnels=tunnels,
                    policy_routes=role["policy_routes"],
                )
            )
        not_covered = sorted({str(e) for r in records for e in r.get("exits_not_covered") or ()})
        if not_covered:
            lines.append(not_covered_line(not_covered, hosts))
        for r in records:
            for first in r.get("exits_decided_first") or ():
                line = decided_first_line(str(first["rule"]), list(first["exits"]))
                if line not in lines:
                    lines.append(line)
        missing = [
            WordsMissing(**m) for r in records if not r.get("decided", True) for m in r.get("missing") or ()
        ]
        if missing:
            lines.append(not_decided_line(missing))
    if not records and intent.get("missing"):
        # Without records, the missing entries of the intent give the last line.
        lines.append(not_decided_line([WordsMissing(**m) for m in intent["missing"]]))
    return {"does": facts, "role": role, "not_covered": not_covered, "lines": lines}


# The names of a scope's counts in the tool's answer.
_SCOPE_NAMES = {
    "definite_count": "first_match_count",
    "possible_count": "not_decided_count",
    "definite_pieces": "first_match_pieces",
    "possible_pieces": "not_decided_pieces",
}


def _scopes(scopes: Any) -> Any:
    """The scopes of an explanation, with their counts named as the tool's
    first_match and not_decided lists are."""
    if not isinstance(scopes, list):
        return scopes
    return [
        {_SCOPE_NAMES.get(key, key): value for key, value in scope.items()}
        if isinstance(scope, dict)
        else scope
        for scope in scopes
    ]


def explain_result(document: dict[str, Any]) -> Result:
    """The answer of one explanation.

    The first match of the rule is decided when the engine settled the whole
    region, also when the region is empty. An unqualified capture, a Check
    Point rulebase that no gateway enforces, and a region with rectangles that
    the snapshot does not decide are not decided."""
    if not document.get("qualified"):
        missing = [
            Missing(code="capture-not-qualified", detail="the capture of this rulebase is not qualified")
        ]
    elif document.get("installation_unknown"):
        missing = [
            Missing(
                code="installation-not-bound", detail="no gateway in this snapshot enforces this rulebase"
            )
        ]
    elif document.get("possible_empty"):
        return decided("rule-first-match", "true")
    else:
        missing = missing_of(document.get("gaps") or ()) or [
            Missing(
                code="match-not-decided", detail="the match depends on an object the compiler did not resolve"
            )
        ]
    return from_engine("rule-first-match", "not-established", missing=missing)


def policy_evaluate(ctx: ToolContext, params: ExplainRuleInput | MatchFlowInput) -> str:
    if isinstance(params, MatchFlowInput):
        return _match_flow(ctx, params)
    return _explain_rule(ctx, params)


def _child_error(document: dict[str, Any]) -> ToolError:
    error = document["error"]
    return ToolError(
        cast(ToolErrorCode, error["code"]),
        str(error["message"]),
        field=error.get("field"),
        candidates=error.get("candidates") or (),
    )


def _explain_rule(ctx: ToolContext, params: ExplainRuleInput) -> str:
    from fastapi import HTTPException

    from hst.assessment.direct import run_isolated
    from hst.symbolic import backend_available
    from hst.twin_tools.apps import published_reference

    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "policy_evaluate", params, session)
        configured = getattr(ctx.settings, "analysis_engine", "legacy-v1") or "legacy-v1"
        if configured != ENGINE:
            raise ToolError(
                "engine_unavailable",
                f"explain_rule needs the {ENGINE} analysis engine; this server runs {configured} "
                "(the analysis_engine setting)",
                field="mode",
            )
        if not backend_available():
            raise ToolError(
                "engine_unavailable", f"the {ENGINE} native backend is not installed on this server"
            )
        reference = published_reference(ctx, call.snapshot)
        try:
            document = run_isolated(
                ctx.settings,
                {
                    "analysis": {"kind": "symbolic-explain-rule"},
                    "snapshot": reference,
                    "rulebase": params.rulebase,
                    "rule": params.rule,
                    **(
                        {"address_family": params.address_family} if params.address_family is not None else {}
                    ),
                    **({"firewall": params.firewall} if params.firewall is not None else {}),
                    "offset": call.pager.offset,
                    "limit": params.limit,
                },
            )
        except HTTPException as exc:
            raise http_error(exc) from None
        document = jsonable(document)
        if "error" in document:
            raise _child_error(document)
        open_on = missing_of(document.get("gaps") or ()) or [
            Missing(
                code="match-not-decided", detail="the match depends on an object the compiler did not resolve"
            )
        ]
        evidence = {
            "definite": ItemEvidence.of(
                from_engine("rule-first-match", "holds"), basis="computed"
            ).model_dump(mode="json"),
            "possible": ItemEvidence.of(
                from_engine("rule-first-match", "not-established", missing=open_on), basis="computed"
            ).model_dump(mode="json"),
        }
        window = [
            (
                item.get("match"),
                {
                    **{key: value for key, value in item.items() if key != "match"},
                    "evidence": evidence[item.get("match")],
                },
            )
            for item in document.get("items") or ()
            if item.get("match") in evidence
        ]
        definite_count, possible_count = document.get("definite_count"), document.get("possible_count")
        counted = isinstance(definite_count, int) and isinstance(possible_count, int)
        next_offset = document.get("next_offset")
        taken, page = call.pager.take(
            window,
            total=definite_count + possible_count if counted else None,
            more=next_offset is not None,
        )
        definite = [item for match, item in taken if match == "definite"]
        possible = [item for match, item in taken if match == "possible"]
        firewall = document.get("firewall")
        entry = document.get("entry") or {}
        if entry.get("evaluated"):
            received = (
                "the rule is explained in the configured policy of its rulebase, for the flows the rulebase "
                "receives (entry); each rectangle names the scope, the interfaces and connection states, "
                "it applies in"
            )
        elif entry:
            received = (
                "the rule is explained in the configured policy of its rulebase; which traffic the device "
                "hands to the rulebase (its interfaces and zones) is not evaluated"
            )
        else:
            received = (
                "the rule is explained in the configured policy of its rulebase; which traffic a firewall "
                "hands to the rulebase (its interfaces, zones and installation) is not evaluated"
            )
        unknowns = [received, "the rectangles describe first fragments (fragment offset 0)"]
        if firewall:
            unknowns.append(f"the install-on column of each rule is bound to gateway {firewall}")
        callers = document.get("inline_layer_callers")
        if callers:
            unknowns.append(
                "this Check Point rulebase is an inline layer, which no package lists, so nothing is "
                f"settled; explain the rule that calls it: {', '.join(callers)}"
            )
        elif not document.get("qualified"):
            unknowns.append(
                "the Check Point capture of this rulebase cannot be qualified, so nothing is settled"
            )
        elif document.get("installation_unknown"):
            unknowns.append(
                "no gateway in this snapshot enforces this Check Point rulebase, so the install-on column "
                "of its rules is not bound and nothing is settled"
            )
        elif document.get("lower_empty") and document.get("possible_empty"):
            if document.get("enabled") is False:
                unknowns.append("the rule is disabled and matches no flow")
            elif document.get("matches_nothing") and firewall:
                unknowns.append(
                    f"the rule matches no flow of this address family on gateway {firewall}: its install-on "
                    "or match columns exclude every flow"
                )
            elif document.get("matches_nothing"):
                unknowns.append(
                    "the rule matches no flow of this address family: its match columns exclude every flow"
                )
            else:
                unknowns.append(
                    "no flow arrives at the rule and matches it: earlier rules take every flow it matches"
                )
        if document.get("listed_in_part"):
            unknowns.append(
                "a region too fragmented to list whole is listed in part: its first disjoint rectangles, "
                "each an exact part of it, with the number of them in the scope (first_match_pieces, "
                "not_decided_pieces); the counts and pages cover the listed rectangles"
            )
        if document.get("render_error"):
            unknowns.append(f"the match region is not listed as rectangles: {document['render_error']}")
        # The family in which the child explained the rule. It is the family of the
        # document, else the requested family, else 4.
        family = int(document.get("address_family") or params.address_family or 4)
        pinned = pathmod.pinned(session, call.snapshot)
        intent = leak_guard.leak_guards(
            pinned,
            params.rulebase,
            params.rule,
            family,
            rib=lambda: ctx.readers.rib(call.snapshot),
        )
        if intent["leak_guards"] or intent["guard_gaps"] or intent.get("missing"):
            unknowns.append(
                "the leak guards and guard gaps are derived from the policy routes, routing tables and "
                "rulebase scope of the snapshot; whether each tunnel is up is not observed"
            )
        facts = leak_guard.rule_facts(pinned, params.rulebase, params.rule, family)
        if document.get("enabled") is False:
            facts = None
        gaps, gaps_truncated = gap_list(document.get("gaps") or ())
        result = {
            "mode": "explain_rule",
            "rulebase": params.rulebase,
            "rule": params.rule,
            "address_family": family,
            "vendor": document.get("vendor"),
            "firewall": firewall,
            "qualified": document.get("qualified"),
            "action": document.get("action"),
            "called_layer": document.get("called_layer"),
            "enabled": document.get("enabled"),
            "summary": explanation(facts, intent, document.get("summary")),
            "match_detail": document.get("summary"),
            "entry": document.get("entry"),
            "scopes": _scopes(document.get("scopes")),
            "first_match": definite,
            "not_decided": possible,
            "first_match_count": definite_count,
            "not_decided_count": possible_count,
            "intent": intent,
        }
        return call.finish(
            session,
            result=result,
            evidence=Evidence(
                result=explain_result(document),
                bounds=(
                    Bounds(
                        unit="flow-rectangles",
                        lower_count=definite_count,
                        upper_count=definite_count + possible_count,
                        open_count=possible_count,
                    )
                    if counted
                    else None
                ),
                gaps=gaps,
                gaps_truncated=gaps_truncated,
                unknowns=unknowns,
            ),
            page=page,
            engine=ENGINE,
            engine_function="hst.policy.compile.CompiledPolicy.explain_rule",
        )


# --- match_flow ----------------------------------------------------------------------------


class _Flow:
    """One parsed flow with the trace arguments and the header sets."""

    def __init__(self, flow: TraceFlow) -> None:
        from hst.app.routes.path import _parse_port, _parse_proto
        from hst.path.addrsets import _intervals
        from hst.path.gates.firewall import _as_portset, _as_protoset

        def port(value: str | int | None) -> Any:
            return _parse_port(None if value is None else str(value))

        try:
            self.port, self.src_port = port(flow.port), port(flow.src_port)
            # The protocol is a name, a comma list or a number set.
            self.proto: Any = _parse_proto(flow.proto)
            self.protocols = _as_protoset(self.proto)[0]
            self.destination_ports = _as_portset(self.port)[0]
            self.source_ports = _as_portset(self.src_port)[0]
        except ValueError as exc:
            raise ToolError("invalid_argument", str(exc), field="flow") from None
        self.src, self.dst = flow.src, flow.dst
        self.sources, self.destinations = _intervals([flow.src]), _intervals([flow.dst])
        if not self.sources or not self.destinations:
            raise ToolError(
                "invalid_argument",
                "flow src and dst must each be an address, a prefix or an address range",
                field="flow",
            )
        families = {af for af, _, _ in (*self.sources, *self.destinations)}
        if len(families) != 1:
            raise ToolError(
                "invalid_argument", "flow src and dst must be in one address family", field="flow"
            )
        self.family: Literal[4, 6] = 6 if families == {6} else 4

    def document(self) -> dict[str, Any]:
        """The header sets as the analysis child takes them."""

        def pairs(values: Any) -> list[list[int]] | None:
            return None if values is None else [[low, high] for _, low, high in values]

        return {
            "sources": pairs(self.sources),
            "destinations": pairs(self.destinations),
            "protocols": None if self.protocols is None else sorted(self.protocols),
            "destination_ports": pairs(self.destination_ports),
            "source_ports": pairs(self.source_ports),
        }


def _rule_cause(entry: Mapping[str, Any]) -> str:
    """The deciding rule in the form "rule 10 of LAN-WAN"."""
    rulebase = entry.get("name") or entry.get("uid") or "the rulebase"
    deciding = entry.get("deciding_rule") or {}
    position = deciding.get("position")
    if position is not None:
        return f"rule {position} of {rulebase}"
    return f"{rulebase}"


# Maps an engine decision word to the word of the tool.
_DECISION_WORDS = {"mixed": "partly", "indeterminate": "open"}
# Maps the engine match word of a candidate rule to the word of the
# explain_rule lists.
_MATCH_WORDS = {"definite": "first_match", "possible": "not_decided"}


def _entry_words(entry: dict[str, Any]) -> None:
    """Rewrite a rulebase entry of either engine into the words of the tool,
    in place.

    The decision `mixed` becomes `partly`, and `indeterminate` becomes `open`.
    The `by` value `mixed` becomes `several`. The match of each candidate rule
    becomes `first_match` or `not_decided`."""
    decision = entry.get("decision")
    entry["decision"] = _DECISION_WORDS.get(str(decision), decision)
    if entry.get("by") == "mixed":
        entry["by"] = "several"
    for rule in entry.get("candidate_rules") or ():
        if isinstance(rule, dict) and rule.get("match") in _MATCH_WORDS:
            rule["match"] = _MATCH_WORDS[rule["match"]]


def _decision_evidence(entry: Mapping[str, Any], basis: Any) -> dict[str, Any]:
    """The evidence of the statement "the rulebase permits the flow", from the
    decision of the entry.

    The statement is permitted, blocked by the deciding rule, partly permitted
    when part of the flow is permitted and part is blocked, not applicable
    when the rulebase does not receive the flow between the named interfaces,
    or not decided with the gaps of the entry."""
    decision = str(entry.get("decision"))
    if decision == "permit":
        result = from_engine("rule-permits", "holds")
    elif decision == "deny":
        result = from_engine("rule-permits", "does-not-hold", cause=_rule_cause(entry))
    elif decision == "partly":
        result = decided("rule-permits", "partly")
    elif decision == "not_applicable":
        result = decided("rule-permits", "not-applicable")
    else:
        open_on = missing_of(entry.get("gaps") or ()) or [
            Missing(
                code="rule-not-decided",
                subject=str(entry.get("name") or entry.get("uid") or ""),
                detail=str(
                    entry.get("reason") or "a rule of this rulebase could not be decided for the flow"
                ),
            )
        ]
        result = from_engine("rule-permits", "not-established", missing=open_on)
    return ItemEvidence.of(result, basis=basis).model_dump(mode="json")


def _symbolic_missing(ctx: ToolContext, call: Call) -> tuple[str | None, dict[str, Any] | None]:
    """Why the symbolic-v2 prerequisites are missing, or the published
    reference of the run when they are all present."""
    from hst.symbolic import backend_available
    from hst.twin_tools.apps import published_reference

    configured = getattr(ctx.settings, "analysis_engine", "legacy-v1") or "legacy-v1"
    if configured != ENGINE:
        return f"this server runs the {configured} analysis engine (the analysis_engine setting)", None
    if not backend_available():
        return f"the {ENGINE} native backend is not installed on this server", None
    try:
        return None, published_reference(ctx, call.snapshot)
    except ToolError as exc:
        return exc.message, None


def _device_interface(pinned: Any, device_uid: str, ref: str, field: str) -> str:
    """The uid of the device interface `ref` names by uid or by name."""
    rows = pathmod._read(pinned, _DEVICE_INTERFACES, dev=device_uid, uids=[ref], name=ref)
    exact = [row for row in rows if row["uid"] == ref] or rows
    if not exact:
        raise ToolError(
            "not_found", f"device {device_uid} has no interface {ref!r} in this snapshot", field=field
        )
    if len(exact) > 1:
        raise ToolError(
            "ambiguous",
            f"{len(exact)} interfaces of device {device_uid} are named {ref!r}; pass one uid from candidates",
            field=field,
            candidates=[{"uid": row["uid"], "name": row.get("name")} for row in exact[:10]],
        )
    return str(exact[0]["uid"])


def _trace_interfaces(
    ctx: ToolContext, pinned: Any, call: Call, device_uid: str, flow: _Flow
) -> tuple[list[str], list[str]]:
    """The interfaces of the device a trace of the flow enters by and leaves
    by, in trace order."""
    kwargs: dict[str, Any] = {} if flow.src_port is None else {"src_port": flow.src_port}
    try:
        body = pathmod.trace(
            pinned,
            flow.src,
            flow.dst,
            port=flow.port,
            proto=flow.proto,
            rib=ctx.readers.rib(call.snapshot),
            **kwargs,
        )
    except pathmod.NoRun as exc:
        raise ToolError("snapshot_not_published", str(exc)) from None
    except ValueError as exc:
        raise ToolError("invalid_argument", str(exc), field="flow") from None
    hops = [hop for hop in body.get("hops") or () if isinstance(hop, dict) and hop.get("kind") == "Interface"]
    seen = list(dict.fromkeys(str(hop["uid"]) for hop in hops if hop.get("uid")))
    if not seen:
        return [], []
    rows = pathmod._read(pinned, _DEVICE_INTERFACES, dev=device_uid, uids=seen, name=None)
    own = {row["uid"] for row in rows}

    def at(stage: str) -> list[str]:
        return list(
            dict.fromkeys(str(h["uid"]) for h in hops if h.get("stage") == stage and h.get("uid") in own)
        )

    return at("INGRESS_IF"), at("EGRESS_IF")


def _legacy_entries(verdict: Any, ingress: str, egress: str | None) -> list[dict[str, Any]]:
    """The rulebase verdicts of the firewall gate as match entries. A verdict
    over a range is a list of regions. The regions of one rulebase give one
    entry."""
    from hst.path.verdict import DENY, INDETERMINATE, PERMIT, classify_action

    grouped: dict[str | None, list[dict[str, Any]]] = {}
    for region in verdict if isinstance(verdict, list) else [verdict]:
        for model in region.get("models") or [region]:
            grouped.setdefault(model.get("rb_uid"), []).append(model)
    entries = []
    for rb_uid, models in grouped.items():
        outcomes = {classify_action(model.get("action")) for model in models}
        partial = any(model.get("partial") for model in models)
        if INDETERMINATE in outcomes or partial:
            decision = "indeterminate"
        elif outcomes == {PERMIT}:
            decision = "permit"
        elif outcomes == {DENY}:
            decision = "deny"
        else:
            decision = "mixed"
        rules = list(
            dict.fromkeys(
                (model["rule_uid"], model.get("pos"), model.get("action"))
                for model in models
                if model.get("rule_uid")
            )
        )
        certain = decision != "indeterminate"
        by = {model.get("by") for model in models}
        deciding = (
            {"uid": rules[0][0], "position": rules[0][1], "action": rules[0][2], "rulebase": rb_uid}
            if certain and len(rules) == 1 and by == {"rule"} and decision in ("permit", "deny")
            else None
        )
        reason = next(
            (model["indeterminate_reason"] for model in models if model.get("indeterminate_reason")), None
        )
        entries.append(
            {
                "uid": rb_uid,
                "name": models[0].get("rb_name"),
                "zones": models[0].get("zones"),
                "decision": decision,
                "by": by.pop() if len(by) == 1 else "mixed",
                "deciding_rule": deciding,
                "candidate_rules": [
                    {
                        "uid": uid,
                        "position": position,
                        "rulebase": rb_uid,
                        "action": action,
                        "match": "first_match" if certain else "not_decided",
                    }
                    for uid, position, action in rules
                ],
                "ingress_interface": ingress,
                "egress_interface": egress,
                "partial": partial,
                "reason": reason,
                "regions": len(models) if isinstance(verdict, list) else None,
            }
        )
    return entries


def _match_flow(ctx: ToolContext, params: MatchFlowInput) -> str:
    from fastapi import HTTPException

    from hst.assessment.direct import run_isolated
    from hst.twin_tools.inventory import _resolve_device

    flow = _Flow(params.flow)
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "policy_evaluate", params, session)
        pinned = pathmod.pinned(session, call.snapshot)
        device_uid = _resolve_device(pinned, params.device)
        missing, reference = _symbolic_missing(ctx, call)
        unknowns: list[str] = []
        gap_entries: list[dict[str, Any]] = []
        if reference is not None:
            engine, basis = ENGINE, "computed"
            try:
                document = run_isolated(
                    ctx.settings,
                    {
                        "analysis": {"kind": "symbolic-match-flow"},
                        "snapshot": reference,
                        "device": device_uid,
                        "rulebase": params.rulebase,
                        "flow": flow.document(),
                        "address_family": flow.family,
                        **{
                            name: getattr(params, name)
                            for name in ("ingress_interface", "egress_interface")
                            if getattr(params, name) is not None
                        },
                    },
                )
            except HTTPException as exc:
                raise http_error(exc) from None
            document = jsonable(document)
            if "error" in document:
                raise _child_error(document)
            entries = list(document.get("rulebases") or ())
            for entry in entries:
                gap_entries.extend(entry.get("gaps") or ())
                if entry.get("installation_unknown"):
                    unknowns.append(
                        f"device {device_uid} is not a gateway Device that enforces Check Point rulebase "
                        f"{entry['uid']}, so the install-on column of its rules is not bound"
                    )
                elif entry.get("qualified") is False:
                    unknowns.append(f"the Check Point capture of rulebase {entry['uid']} cannot be qualified")
            open_entry = [entry["uid"] for entry in entries if entry.get("receives") is None]
            if open_entry:
                unknowns.append(
                    "each rulebase is decided in its configured policy; whether the device hands the flow "
                    f"to {', '.join(open_entry[:10])} (receives is null) is not evaluated: name "
                    "ingress_interface and egress_interface"
                )
            unknowns.append("the flow is evaluated as first fragments (fragment offset 0)")
            if document.get("rulebases_truncated"):
                unknowns.append(
                    f"only the first {len(entries)} of {document.get('rulebase_count')} rulebases are "
                    "evaluated; name one with rulebase"
                )
            if any(entry.get("candidate_rules_truncated") for entry in entries):
                unknowns.append("candidate rules past the first 50 of a rulebase are not listed")
            engine_function = "hst.policy.compile.CompiledPolicy.evaluate"
            interfaces: list[dict[str, Any]] = []
        else:
            engine, basis = LEGACY_ENGINE, "derived"
            entries, interfaces = _legacy_match(ctx, pinned, call, device_uid, params, flow, missing)
            unknowns += [
                f"the {ENGINE} prerequisites are missing ({missing}); the match is the one the firewall gate "
                "of the path engine gives between the interfaces listed",
                "the match names the rule that decides the flow in each rulebase; other rules that may match "
                "are not listed",
            ]
            if params.rulebase is not None:
                entries = [entry for entry in entries if entry["uid"] == params.rulebase]
                if not entries:
                    unknowns.append(
                        f"rulebase {params.rulebase} gives no decision for the flow between these interfaces"
                    )
            if any(entry["partial"] for entry in entries):
                unknowns.append(
                    "a rule covers only part of the flow's addresses; narrow the flow for one decision"
                )
            engine_function = "hst.path.gates.firewall._firewall_verdict"
        for entry in entries:
            _entry_words(entry)
            entry["evidence"] = _decision_evidence(entry, basis)
        if not entries:
            unknowns.append(f"no access rulebase of device {device_uid} gives a decision for this flow")
        taken, page = call.pager.take(entries[call.pager.offset :], total=len(entries))
        gaps, gaps_truncated = gap_list(gap_entries)
        result = {
            "mode": "match_flow",
            "device": device_uid,
            "rulebase": params.rulebase,
            "engine": engine,
            "flow": params.flow.model_dump(mode="json"),
            "address_family": flow.family,
            "interfaces": interfaces,
            "rulebases": taken,
        }
        return call.finish(
            session,
            result=result,
            evidence=Evidence(
                result=whole_result((entry["evidence"]["result"] for entry in entries), unknowns=unknowns),
                gaps=gaps,
                gaps_truncated=gaps_truncated,
                unknowns=unknowns[:100],
            ),
            page=page,
            engine=engine,
            engine_function=engine_function,
        )


def _legacy_match(
    ctx: ToolContext,
    pinned: Any,
    call: Call,
    device_uid: str,
    params: MatchFlowInput,
    flow: _Flow,
    missing: str | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The match derived from a trace. The firewall gate judges the flow
    between each pair of device interfaces that the caller names or that a
    trace of the flow crosses."""
    from hst.path.gates import firewall as fwmod

    egress = (
        None
        if params.egress_interface is None
        else _device_interface(pinned, device_uid, params.egress_interface, "egress_interface")
    )
    derived = params.ingress_interface is None
    if not derived:
        ingresses = [
            _device_interface(pinned, device_uid, str(params.ingress_interface), "ingress_interface")
        ]
        egresses = [egress] if egress is not None else []
    else:
        ingresses, egresses = _trace_interfaces(ctx, pinned, call, device_uid, flow)
        if egress is not None:
            egresses = [egress]
    if not ingresses:
        raise ToolError(
            "engine_unavailable",
            f"match_flow needs the {ENGINE} prerequisites, which are missing ({missing}), or the interface "
            f"the flow enters device {device_uid} by, and a trace of the flow does not enter the device; "
            "pass ingress_interface",
            field="ingress_interface",
        )
    outs: list[str | None] = [*egresses] or [None]
    pairs = [(ingress, out) for ingress in ingresses for out in outs]
    entries: list[dict[str, Any]] = []
    interfaces = []
    for ingress, out in pairs[:MAX_INTERFACE_PAIRS]:
        interfaces.append({"ingress": ingress, "egress": out, "derived": derived})
        verdict = fwmod._firewall_verdict(
            pinned,
            device_uid,
            ingress,
            out,
            list(flow.sources),
            list(flow.destinations),
            flow.port,
            flow.proto,
            [],
            src_port=flow.src_port,
        )
        if verdict:
            entries.extend(_legacy_entries(verdict, ingress, out))
    return entries, interfaces


def register(registry: ToolRegistry) -> None:
    registry.register(
        catalogue_spec(
            name="policy_evaluate",
            description=(
                "Evaluate firewall policy over one run. mode: explain_rule takes a FwRulebase uid and one "
                "of its FwRule uids and returns summary.lines, the explanation of the rule to give in "
                "order: what the rule does and on which exits, the policy routes and tunnel it stands "
                "behind, the exits of the rulebase it does not cover, and what is not decided. The match "
                "detail is under match_detail, entry, scopes and the flow rectangles (sources, "
                "destinations, protocols, ports): first_match ones have the rule as their first match, "
                "not_decided ones depend on data the snapshot does not decide. The earlier rules and "
                "layers of the rulebase's policy take their flows first. The rulebase receives the flows "
                "its zone pair, ACL bindings or chain hand it (entry), and each rectangle names the "
                "ingress and egress interfaces and connection states it applies in (scopes). "
                "A Check Point rulebase is explained for one gateway that enforces it, named by firewall "
                "when there are several (otherwise ambiguous, with the candidates). Needs the symbolic-v2 "
                "analysis engine and a run with an evidence manifest, otherwise engine_unavailable or "
                "snapshot_not_published. Rectangles page with the cursor, first_match ones first. "
                "For a drop rule, intent holds the records behind lines 2 and 3: the tunnel a policy route "
                "sends the rule's hosts into, and the exits the normal routing table uses without it. "
                "mode: match_flow takes a device and a flow and returns, per access rulebase of the "
                "device, the decision (permit, deny, partly, open, or not_applicable when the "
                "rulebase does not receive the flow), the deciding rule and the candidate rules that may "
                "match. With the symbolic-v2 prerequisites every rulebase is decided in its configured "
                "policy for the flow through ingress_interface and egress_interface (uid or name), which "
                "decide interface-scoped rules, zone pairs and ACL bindings; without them the firewall "
                "gate of the path engine judges the flow between ingress_interface and "
                "egress_interface, or between the device interfaces a trace of the flow crosses. "
                "Without either, engine_unavailable. Rulebases page with the cursor."
            ),
            input_model=PolicyEvaluateInput,
            result_model=PolicyEvaluateResult,
            run=policy_evaluate,
            version=4,
        )
    )
