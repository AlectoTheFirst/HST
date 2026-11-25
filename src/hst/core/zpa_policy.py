"""The ZPA first-match reader shared by the path gate and the impact engine.

It reads rule rows that a caller has fetched (uid, name, position, action,
applies_to_all_identities, conditions and identity_named) and does no graph
read. `first_match` picks the winning rule by ZPA rule order. `access_decision`
maps the action of that rule to a decided allow or deny. Every undecided answer
has the rule or the segment in its reason and has one gap code.
"""

from __future__ import annotations

import json
from typing import Any, NamedTuple

from hst.core.labels import ZPA_RULE_SCOPES  # noqa: F401 - the vocabulary of rule_scope and _may_match

# A GRANTS/DENIES/FOR reading is valid for one condition shape. The shape has at
# most one identity block (SCIM_GROUP operands) and at most one application
# block (APP or APP_GROUP operands), with OR within each block and AND between
# the blocks.
#
# The edges cannot express any other shape.
IDENTITY_OPERAND_TYPES = frozenset({"SCIM_GROUP"})
APPLICATION_OPERAND_TYPES = frozenset({"APP", "APP_GROUP"})
CONDITION_OPERATORS = frozenset({"AND", "OR"})
# The operand types for attributes of the request. They do not limit the identities of a rule.
REQUEST_ATTRIBUTE_OPERAND_TYPES = frozenset(
    {"CLIENT_TYPE", "POSTURE", "TRUSTED_NETWORK", "COUNTRY_CODE", "PLATFORM"}
)


# The states of a segment for the brokered stage.
# disabled: the segment or its segment group is switched off.
# bypass: bypass_type is ALWAYS, and ZPA does not broker the segment.
# bypass-on-net: bypass_type is ON_NET, and ZPA brokers the segment only off the trusted network.
# active: ZPA brokers the segment.
SEGMENT_STATES = ("disabled", "bypass", "bypass-on-net", "active")


def segment_state(row: dict[str, Any] | None) -> str:
    """The state of a segment from its `enabled`, its `bypass_type` and its
    group's `enabled` (`group_enabled`). A segment that the read did not
    return is read as active."""
    if not row:
        return "active"
    if row.get("enabled") is False or row.get("group_enabled") is False:
        return "disabled"
    bypass = str(row.get("bypass_type") or "").upper()
    if bypass == "ALWAYS":
        return "bypass"
    if bypass == "ON_NET":
        return "bypass-on-net"
    return "active"


def segment_state_reason(segment_uid: str, state: str) -> str:
    return {
        "disabled": f"{segment_uid}: the segment or its segment group is disabled",
        "bypass": f"{segment_uid}: bypass_type ALWAYS, so ZPA does not broker this segment",
        "bypass-on-net": f"{segment_uid}: bypass_type ON_NET, and the request states no client network",
    }.get(state, "")


def condition_blocks(conditions: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """The stored condition JSON of a rule payload. A block is `operator` and
    `operands`, plus `negated: true` only when the payload negates it. An
    operand is `type` and `rhs` (or `name` when rhs is absent), plus `lhs` only
    when the payload sends a non-empty one."""
    blocks = []
    for cond in conditions or []:
        operands = []
        for op in cond.get("operands") or []:
            operand: dict[str, Any] = {
                "type": op.get("objectType"),
                "rhs": op.get("rhs") if op.get("rhs") is not None else op.get("name"),
            }
            if op.get("lhs"):
                operand["lhs"] = op["lhs"]
            operands.append(operand)
        block: dict[str, Any] = {"operator": cond.get("operator"), "operands": operands}
        if cond.get("negated") is True:
            block["negated"] = True
        blocks.append(block)
    return blocks


def _operand_text(op: dict[str, Any]) -> str | None:
    kind, rhs, lhs = op.get("type"), op.get("rhs"), op.get("lhs")
    if not kind or rhs is None or rhs == "":
        return None
    if lhs and lhs != "id" and kind != "SCIM_GROUP":
        return f"{kind}[{lhs}]={rhs}"
    return f"{kind}={rhs}"


def conditions_summary(blocks: list[dict[str, Any]], operator: str | None) -> str:
    """One line for the rule's conditions. A negated block reads `NOT ...`.
    Blocks join with `; `, or with ` OR ` under a rule-level OR."""
    parts = []
    for block in blocks:
        texts = [t for t in (_operand_text(op) for op in block.get("operands") or []) if t]
        if not texts:
            continue
        text = "; ".join(texts)
        if block.get("negated"):
            text = f"NOT ({text})" if len(texts) > 1 else f"NOT {text}"
        parts.append(text)
    joiner = " OR " if (operator or "").upper() == "OR" and len(parts) >= 2 else "; "
    return joiner.join(parts)


def rule_scope(blocks: list[dict[str, Any]], operator: str | None) -> tuple[str, str]:
    """`(identity_scope, app_scope)`, each a value of ZPA_RULE_SCOPES
    (core/labels.py)."""
    and_joined = (operator or "AND").upper() == "AND" or len(blocks) <= 1
    types = [op.get("type") for b in blocks for op in b.get("operands") or []]

    def positive_only(allowed: frozenset[str]) -> bool:
        return any(
            not b.get("negated")
            and b.get("operands")
            and all(op.get("type") in allowed for op in b.get("operands") or [])
            for b in blocks
        )

    not_identity = APPLICATION_OPERAND_TYPES | REQUEST_ATTRIBUTE_OPERAND_TYPES
    if all(t in not_identity for t in types):
        identity = "any"
    elif and_joined and positive_only(IDENTITY_OPERAND_TYPES):
        identity = "listed"
    else:
        identity = "other"
    if not any(t in APPLICATION_OPERAND_TYPES for t in types):
        app = "any"
    elif and_joined and positive_only(APPLICATION_OPERAND_TYPES):
        app = "listed"
    else:
        app = "other"
    return identity, app


def parse_disabled(value: Any) -> tuple[bool | None, str | None]:
    """`(enabled, disabled_raw)` from the payload's `disabled`. An unknown value
    keeps its text in disabled_raw and leaves enabled unset."""
    if value is None:
        return None, None
    if value in ("0", 0) or value is False:
        return True, None
    if value in ("1", 1) or value is True:
        return False, None
    return None, str(value)


GAP_NO_RULE_MATCHES_IDENTITY = "ZPA_NO_RULE_MATCHES_IDENTITY"
GAP_RULE_ORDER_UNKNOWN = "ZPA_RULE_ORDER_UNKNOWN"
GAP_RULE_CONDITIONS_UNSUPPORTED = "ZPA_RULE_CONDITIONS_UNSUPPORTED"
GAP_RULE_ACTION_UNKNOWN = "ZPA_RULE_ACTION_UNKNOWN"


def rule_label(row: dict[str, Any]) -> str:
    return str(row.get("name") or row["uid"])


def unsupported_condition_shape(conditions_json: Any, operator: Any = None) -> str | None:
    """A description of why a rule's collected `conditions` are outside the
    flat shape this evaluator reads, or None when they are inside it.
    `operator` is the rule-level operator, absent on rules collected without
    it."""
    rule_operator = str(operator).strip().upper() if operator else ""
    if rule_operator and rule_operator not in CONDITION_OPERATORS:
        return f"the rule operator {operator!r} is not read by this engine"
    if not conditions_json:
        return None
    try:
        conditions = json.loads(conditions_json)
    except (TypeError, ValueError):
        return "the collected conditions are not readable"
    if not isinstance(conditions, list):
        return "the collected conditions are not a list of condition blocks"
    if rule_operator == "OR" and len(conditions) >= 2:
        return (
            f"the rule joins {len(conditions)} condition blocks with OR; "
            "this engine reads AND between blocks only"
        )
    if any(isinstance(cond, dict) and cond.get("negated") for cond in conditions):
        return "a negated condition block is not evaluated by this engine"
    identity_blocks = 0
    application_blocks = 0
    for cond in conditions:
        if not isinstance(cond, dict):
            return "a condition block is not readable"
        operator = cond.get("operator")
        operator_key = str(operator).strip().upper() if operator else ""
        if operator_key not in CONDITION_OPERATORS:
            return f"a condition block carries operator {operator!r}, which this engine does not read"
        operands = cond.get("operands") or []
        if not operands:
            return "a condition block carries no operands"
        if any(not isinstance(op, dict) or not op.get("type") for op in operands):
            return "a condition block carries an operand with no type"
        types = {str(op["type"]) for op in operands}
        unknown = sorted(types - IDENTITY_OPERAND_TYPES - APPLICATION_OPERAND_TYPES)
        if unknown:
            return f"condition operand type(s) {', '.join(unknown)} are not evaluated by this engine"
        if types & IDENTITY_OPERAND_TYPES and types & APPLICATION_OPERAND_TYPES:
            return "a condition block mixes identity and application operands"
        if len(operands) > 1 and operator_key != "OR":
            return f"a condition block joins {len(operands)} operands with {operator_key}, not OR"
        if types & IDENTITY_OPERAND_TYPES:
            identity_blocks += 1
        elif types & APPLICATION_OPERAND_TYPES:
            application_blocks += 1
    if identity_blocks > 1:
        return (
            f"{identity_blocks} identity condition blocks are AND-ed; the GRANTS/DENIES edges cannot say so"
        )
    if application_blocks > 1:
        return f"{application_blocks} application condition blocks are AND-ed; the FOR edges cannot say so"
    return None


def rule_position(row: dict[str, Any]) -> int | None:
    """The `position` of a rule as an integer, or None when it is not an integer.

    `collectors/zpa.py` casts it from `ruleOrder` at collection time and
    skips a rule whose ruleOrder is not numeric.
    """
    position = row.get("position")
    if isinstance(position, bool) or position is None:
        return None
    if isinstance(position, int):
        return position
    try:
        return int(str(position).strip())
    except (TypeError, ValueError):
        return None


def _may_match(row: dict[str, Any]) -> bool:
    """False when the scope of the row rules out a match. A row that may match
    stays a candidate, and the checks on the winner make it undecided."""
    identity_scope = row.get("identity_scope")
    if identity_scope is None:
        identity_ok = bool(row.get("identity_named") or row.get("applies_to_all_identities"))
    elif identity_scope == "listed":
        identity_ok = bool(row.get("identity_named"))
    else:
        # `any` matches. `other` and a value outside ZPA_RULE_SCOPES may match.
        identity_ok = True
    segment_named = row.get("segment_named", True) is not False
    app_scope = row.get("app_scope")
    # `listed` and an absent scope need the segment named. `any`, `other` and
    # an unknown value may match.
    app_ok = segment_named if app_scope in (None, "listed") else True
    return identity_ok and app_ok


class RuleMatch(NamedTuple):
    """The answer of `first_match`.

    `rule` is the winning row when one is established. An indeterminate
    result whose reason is the `disabled` value or the condition shape of the
    rule also has it. `gap` is None only when `indeterminate` is False.
    """

    rule: dict[str, Any] | None
    indeterminate: bool
    reason: str | None
    gap: str | None


def first_match(
    rows: list[dict[str, Any]],
    identity_uid: str,
    segment_uid: str,
    *,
    label: str = "ZpaAccessRule",
    noun: str = "access rule",
) -> RuleMatch:
    """The rule with the lowest position among `rows` that names `identity_uid`
    (`identity_named`) or has `applies_to_all_identities`.

    `rows` are every rule FOR `segment_uid`. The result is indeterminate, with
    a reason, when
    - there are no rows,
    - no row may match this identity,
    - the position of a candidate is not an integer,
    - 2 or more candidates tie at the winning position,
    - the collected `disabled` value of the winning rule is neither 0 nor 1, or
    - the conditions of the winning rule have a shape that this evaluator does
      not read.
    """
    if not rows:
        return RuleMatch(None, True, f"no {label} applies to {segment_uid}", GAP_NO_RULE_MATCHES_IDENTITY)
    candidates = [r for r in rows if r.get("enabled") is not False and _may_match(r)]
    if not candidates:
        return RuleMatch(
            None,
            True,
            f"no {label} that applies to {segment_uid} matches {identity_uid}",
            GAP_NO_RULE_MATCHES_IDENTITY,
        )
    ordered: list[tuple[int, dict[str, Any]]] = []
    unordered: list[dict[str, Any]] = []
    for row in candidates:
        position = rule_position(row)
        if position is None:
            unordered.append(row)
        else:
            ordered.append((position, row))
    if unordered:
        names = ", ".join(sorted(rule_label(r) for r in unordered))
        return RuleMatch(
            None,
            True,
            f"{noun} position is not an integer, so first-match order is not established: {names}",
            GAP_RULE_ORDER_UNKNOWN,
        )
    ordered.sort(key=lambda pair: (pair[0], str(pair[1]["uid"])))
    top_position = ordered[0][0]
    tied = [r for position, r in ordered if position == top_position]
    if len(tied) > 1:
        names = ", ".join(sorted(rule_label(r) for r in tied))
        return RuleMatch(
            None,
            True,
            f"{len(tied)} {noun}s tie at position {top_position} for {segment_uid}/{identity_uid}: {names}",
            GAP_RULE_ORDER_UNKNOWN,
        )
    winner = tied[0]
    if winner.get("enabled") is None and winner.get("disabled_raw") is not None:
        return RuleMatch(
            winner,
            True,
            f"{rule_label(winner)}: the collected disabled value {winner['disabled_raw']!r} "
            "is neither 0 nor 1; the match is not determined",
            GAP_RULE_CONDITIONS_UNSUPPORTED,
        )
    unsupported = unsupported_condition_shape(winner.get("conditions"), winner.get("operator"))
    if unsupported:
        return RuleMatch(
            winner,
            True,
            f"{rule_label(winner)}: {unsupported}; the match is not determined",
            GAP_RULE_CONDITIONS_UNSUPPORTED,
        )
    return RuleMatch(winner, False, None, None)


class AccessDecision(NamedTuple):
    """`access_decision`'s answer. `action` is "allow" or "deny" only when
    `indeterminate` is False, and `gap` is None exactly then."""

    rule: dict[str, Any] | None
    action: str | None
    indeterminate: bool
    reason: str | None
    gap: str | None


def access_decision(rows: list[dict[str, Any]], identity_uid: str, segment_uid: str) -> AccessDecision:
    """The first match over the ZpaAccessRule rows, with the action of the winning rule."""
    match = first_match(rows, identity_uid, segment_uid)
    winner = match.rule
    if match.indeterminate or winner is None:
        return AccessDecision(match.rule, None, True, match.reason, match.gap)
    action = (winner.get("action") or "").strip().lower()
    if action == "require_approval":
        return AccessDecision(
            winner,
            None,
            True,
            f"{rule_label(winner)}: action require_approval grants access only after an approval, "
            "and the snapshot holds no approval state",
            GAP_RULE_ACTION_UNKNOWN,
        )
    if action not in ("allow", "deny"):
        shown = winner.get("action_raw") or winner.get("action")
        return AccessDecision(
            winner,
            None,
            True,
            f"{rule_label(winner)}: action {shown!r} is not recognized",
            GAP_RULE_ACTION_UNKNOWN,
        )
    return AccessDecision(winner, action, False, None, None)


GAP_NOT_BROKERED = "ZPA_NOT_BROKERED"


class ForwardingDecision(NamedTuple):
    """`forwarding_decision`'s answer. `action` is intercept, bypass or
    intercept_accessible when decided. `go_on` is True when the access rule is
    read next. `note` is set when no forwarding rule applies or matches, and
    the flow is then read as intercepted."""

    rule: dict[str, Any] | None
    action: str | None
    go_on: bool
    reason: str | None
    gap: str | None
    note: str | None = None


def forwarding_decision(
    rows: list[dict[str, Any]], identity_uid: str, segment_uid: str
) -> ForwardingDecision:
    """The first match over the ZpaClientForwardingRule rows, which decides
    whether ZCC sends the flow to ZPA. `bypass` ends the leg as not brokered,
    with the rule in the reason. `intercept` and `intercept_accessible` go on
    to the access rule."""
    if not rows:
        note = f"no ZpaClientForwardingRule applies to {segment_uid}; the flow is read as intercepted"
        return ForwardingDecision(None, "intercept", True, None, None, note)
    match = first_match(
        rows, identity_uid, segment_uid, label="ZpaClientForwardingRule", noun="client forwarding rule"
    )
    if match.rule is None and match.gap == GAP_NO_RULE_MATCHES_IDENTITY:
        # ZPA intercepts a flow that no forwarding rule matches
        note = (
            f"no ZpaClientForwardingRule matches {identity_uid} for {segment_uid}; "
            "the flow is read as intercepted"
        )
        return ForwardingDecision(None, "intercept", True, None, None, note)
    if match.indeterminate or match.rule is None:
        return ForwardingDecision(match.rule, None, False, match.reason, match.gap)
    action = str(match.rule.get("action") or "").strip().lower()
    if action == "bypass":
        return ForwardingDecision(
            match.rule,
            action,
            False,
            f"{rule_label(match.rule)}: bypass, so ZPA does not broker this flow",
            GAP_NOT_BROKERED,
        )
    if action in ("intercept", "intercept_accessible"):
        return ForwardingDecision(match.rule, action, True, None, None)
    shown = match.rule.get("action_raw") or match.rule.get("action")
    return ForwardingDecision(
        match.rule,
        None,
        False,
        f"{rule_label(match.rule)}: action {shown!r} is not recognized",
        GAP_RULE_ACTION_UNKNOWN,
    )
