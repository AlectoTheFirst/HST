"""Compile `RoutePolicy` node dicts into the evaluation primitives of `policy.py`.

The input is the normalized schema shape. A `RoutePolicy` has `name` and
`kind`. Its `HAS_RULE` children are `RoutePolicyEntry` dicts (`kind` `"clause"`
or `"statement"`), `PrefixListEntry` dicts, or, for a `community-list` or
`as-path-list`, `MatchListEntry` dicts.

The compiler has three conversion shapes.

  * `kind="clause"`, IOS-XE: the clauses nest as `If`s from the highest
    sequence down. When a clause has `continue`, each clause is a sub-policy
    and `CallStatement` links the sub-policies.
  * `kind="clause"`, NX-OS: the map is partitioned into intervals at every
    `continue` target. Each interval is a sub-policy. The top-level policy
    returns the result of the first interval through `callInContext`.
  * `kind="statement"`, IOS-XR RPL: the statements compile in order. Each
    disposition branches on the call context. The branches of one
    `if`/`elseif`/`else` compile to one chained `If`. One synthetic terminator
    follows the body.

Every dangling reference is evaluated and reported.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from . import matchlist
from . import platforms as plat
from . import policy as p
from .errors import ErrorSink

COMMUNITY_LIST = "community-list"
AS_PATH_LIST = "as-path-list"
LIST_KINDS = (COMMUNITY_LIST, AS_PATH_LIST)


@dataclass(frozen=True)
class MatchLists:
    """The community lists and the AS-path lists of the input by name, as `matchlist.Line` tuples.

    Each list is a RoutePolicy of kind `community-list` or `as-path-list` with
    `MatchListEntry` children.
    """

    community: Mapping[str, tuple[matchlist.Line, ...]] = field(default_factory=dict)
    as_path: Mapping[str, tuple[matchlist.Line, ...]] = field(default_factory=dict)


def match_lists(policies: Sequence[Mapping[str, Any]]) -> MatchLists:
    """Every community list and AS-path list in `policies`."""
    community: dict[str, tuple[matchlist.Line, ...]] = {}
    as_path: dict[str, tuple[matchlist.Line, ...]] = {}
    for node in policies:
        kind = str(node.get("kind", "")).lower()
        if kind not in LIST_KINDS:
            continue
        lines = tuple(
            sorted((matchlist.Line.of(e) for e in node.get("entries") or [] if e), key=lambda line: line.seq)
        )
        (community if kind == COMMUNITY_LIST else as_path)[str(node["name"])] = lines
    return MatchLists(community=community, as_path=as_path)


# An undefined community list or AS-path list is left out of its disjunction.
# A match with only undefined lists is false. Each undefined name is reported.
# The error kind is in `proof.UNCERTAIN_KINDS`.
_LIST_KEYS = {
    "match_community_lists": COMMUNITY_LIST,
    "match_as_path_lists": AS_PATH_LIST,
}


def _seq(entry: Mapping[str, Any]) -> int:
    return int(entry["seq"])


def _names(entry: Mapping[str, Any], key: str) -> list[str]:
    value = entry.get(key) or []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value]


def _prefix_list_guard(
    names: Sequence[str],
    prefix_lists: Mapping[str, Any],
    platform: str,
    errors: ErrorSink,
    subject: str,
) -> p.BooleanExpr:
    """The guard of `match ip address prefix-list` or `destination in`.

    On NX-OS a `match ip address prefix-list` with only undefined names matches
    every route. On IOS-XE, IOS-XR and FRR a match with only undefined names is
    false. Each undefined name is reported.
    """
    resolved = [n for n in names if n in prefix_lists]
    for name in names:
        if name not in prefix_lists:
            errors.report(
                "undefined-prefix-list",
                f"{subject} names prefix list {name!r}, which no RoutePolicy node defines",
                name,
            )
    if resolved:
        return p.Disjunction(tuple(p.MatchPrefixList(n) for n in resolved))
    if platform == plat.NXOS:
        return p.TRUE
    return p.FALSE


def _list_match(
    name: str,
    kind: str,
    lists: MatchLists,
    errors: ErrorSink,
    subject: str,
    *,
    every: bool = False,
) -> p.BooleanExpr | None:
    """One named community list or AS-path list as a match.

    Returns None and reports the name when the input holds no list of that
    name. A line that the engine cannot evaluate matches no route and is
    reported under the name of the list.
    """
    table = lists.community if kind == COMMUNITY_LIST else lists.as_path
    label = "community list" if kind == COMMUNITY_LIST else "AS-path list"
    lines = table.get(name)
    if lines is None:
        errors.report(
            "undefined-community-list" if kind == COMMUNITY_LIST else "undefined-as-path-list",
            f"{subject} names {label} {name!r}, which is not in the snapshot; "
            "the name drops out of the match",
            name,
        )
        return None
    _report_unsupported_lines(name, kind, lines, errors)
    if kind == COMMUNITY_LIST:
        return p.MatchCommunityList(name, lines, every=every)
    return p.MatchAsPathList(name, lines)


def _report_unsupported_lines(
    name: str,
    kind: str,
    lines: Sequence[matchlist.LineLike],
    errors: ErrorSink,
    *,
    subject: str | None = None,
) -> None:
    """Reports every line of a list that the engine cannot evaluate.

    The subject of the report is the name of the list, or `subject` for an
    inline set.
    """
    for line in lines:
        if not matchlist.line_supported(line, kind):
            errors.report(
                "unsupported-list-entry",
                f"{kind} {name} line {line.get('seq')} ({line.get('match_type')} {line.get('value')!r}) "
                "is a form the engine does not evaluate; the line never matches",
                subject or name,
            )


def _guard(
    entry: Mapping[str, Any],
    prefix_lists: Mapping[str, Any],
    platform: str,
    errors: ErrorSink,
    subject: str,
    policy: str,
    lists: MatchLists | None = None,
) -> p.BooleanExpr:
    """The match lines of one entry as a guard.

    The kinds are combined with AND. The values of one kind are combined with
    OR. IOS-XE and NX-OS share this rule. The IOS-XE `match ip address` form is
    one of the `match_unsupported` lines.

    An IOS-XR guard has `match_expr` when the flat `match_*` fields cannot
    express it (`or`, `not`, parentheses, an inline set, a repeated kind, a
    comparison other than equality). `_expression_guard` compiles `match_expr`
    as the whole guard.

    A `match_unsupported` line is a condition that the collector kept and the
    schema cannot express. The entry evaluates false and is reported as
    `unsupported-match` under the name of the policy. The error kind is in
    `proof.UNCERTAIN_KINDS`.

    A `match_ignored` line has no effect on route filtering by the platform
    documentation (the NX-OS policy-based-routing matches). It adds no
    condition and is reported as a diagnostic.
    """
    lists = lists if lists is not None else MatchLists()
    if entry.get("match_expr"):
        return _expression_guard(entry, prefix_lists, platform, errors, subject, policy, lists)

    conjuncts: list[p.BooleanExpr] = []

    unsupported = _names(entry, "match_unsupported")
    if unsupported:
        errors.report(
            "unsupported-match",
            f"{subject} sequence {_seq(entry)} matches on {', '.join(map(repr, unsupported))}, "
            "which the engine does not model; the entry evaluates false",
            policy,
        )
        conjuncts.append(p.FALSE)

    ignored = _names(entry, "match_ignored")
    if ignored:
        errors.report(
            "pbr-only-match",
            f"{subject} sequence {_seq(entry)} matches on {', '.join(map(repr, ignored))}, which the "
            "platform applies to policy-based routing only; route filtering ignores it",
            policy,
        )

    prefix_lists_named = _names(entry, "match_prefix_lists")
    if prefix_lists_named:
        conjuncts.append(_prefix_list_guard(prefix_lists_named, prefix_lists, platform, errors, subject))

    for key, kind in _LIST_KEYS.items():
        named = _names(entry, key)
        if named:
            found = [_list_match(n, kind, lists, errors, subject) for n in named]
            resolved = tuple(m for m in found if m is not None)
            conjuncts.append(p.Disjunction(resolved) if resolved else p.FALSE)

    tags = entry.get("match_tags") or []
    if tags:
        conjuncts.append(p.Disjunction(tuple(p.MatchTag(int(t)) for t in tags)))

    if entry.get("match_metric") is not None:
        conjuncts.append(p.MatchMetric(int(entry["match_metric"])))

    protocols = entry.get("match_protocols") or []
    if protocols:
        conjuncts.append(p.MatchProtocol(tuple(str(x).lower() for x in protocols)))

    return p.Conjunction(tuple(conjuncts))


# --- IOS-XR guard expressions ---------------------------------------------
#
# `match_expr` is the JSON tree that `guard_expression` in
# collectors/iosxr_bgp.py writes. Its nodes are `and`/`or` (lists), `not`, a
# named or inline prefix set
# (`prefix_list`/`prefixes`), community set (`community_list`/`communities`,
# with `every` for matches-every), AS-path set (`as_path_list`/`as_path`), a
# numeric comparison (`compare`, `op`, `value`), `origin`, `apply` in boolean
# position (`call`), a documented constant (`const`), and `unsupported` for any
# atom the collector could not read.


def _unsupported_atoms(node: Any) -> list[str]:
    if not isinstance(node, Mapping):
        return ["malformed guard expression"]
    if "unsupported" in node:
        return [str(node["unsupported"])]
    out: list[str] = []
    for key in ("and", "or"):
        for child in node.get(key) or ():
            out.extend(_unsupported_atoms(child))
    if "not" in node:
        out.extend(_unsupported_atoms(node["not"]))
    if "prefixes" in node:
        out.extend(
            f"destination in element {t!r}" for t in node["prefixes"] if _inline_prefix(str(t)) is None
        )
    return out


def _inline_prefix(text: str) -> tuple[str, int, int] | None:
    """One `destination in (...)` element, `<prefix> [ge N] [le M] [eq N]`, as
    `(prefix, min_len, max_len)`.

    An element of length L without a length qualifier matches `[L, 32]`. An
    IPv6 element returns None.
    """
    tokens = text.split()
    if not tokens:
        return None
    try:
        net = ipaddress.ip_network(tokens[0], strict=False)
    except ValueError:
        return None
    if net.version != 4:
        return None
    rest = tokens[1:]
    if len(rest) % 2:
        return None
    values: dict[str, int] = {}
    for i in range(0, len(rest), 2):
        if rest[i] not in {"ge", "le", "eq"} or not rest[i + 1].isdigit():
            return None
        values[rest[i]] = int(rest[i + 1])
    lo, hi = values.get("ge", net.prefixlen), values.get("le", 32)
    if "eq" in values:
        lo = hi = values["eq"]
    return str(net), lo, hi


def _inline_lines(pairs: Sequence[Sequence[Any]]) -> tuple[matchlist.Line, ...]:
    return tuple(
        matchlist.Line(seq=i, action="permit", match_type=str(t).lower(), value=str(v))
        for i, (t, v) in enumerate(pairs)
    )


def _expression(
    node: Mapping[str, Any],
    prefix_lists: Mapping[str, Any],
    platform: str,
    errors: ErrorSink,
    subject: str,
    lists: MatchLists,
    policy: str,
) -> p.BooleanExpr:
    if "and" in node:
        return p.Conjunction(
            tuple(_expression(c, prefix_lists, platform, errors, subject, lists, policy) for c in node["and"])
        )
    if "or" in node:
        return p.Disjunction(
            tuple(_expression(c, prefix_lists, platform, errors, subject, lists, policy) for c in node["or"])
        )
    if "not" in node:
        return p.Not(_expression(node["not"], prefix_lists, platform, errors, subject, lists, policy))
    if "prefix_list" in node:
        return _prefix_list_guard([str(node["prefix_list"])], prefix_lists, platform, errors, subject)
    if "prefixes" in node:
        elements = (_inline_prefix(str(t)) for t in node["prefixes"])
        return p.MatchInlinePrefixes(tuple(e for e in elements if e is not None))
    if "community_list" in node:
        found = _list_match(
            str(node["community_list"]), COMMUNITY_LIST, lists, errors, subject, every=bool(node.get("every"))
        )
        return found if found is not None else p.FALSE
    if "communities" in node:
        lines = _inline_lines(node["communities"])
        _report_unsupported_lines(f"(inline, {subject})", COMMUNITY_LIST, lines, errors, subject=policy)
        return p.MatchCommunityList("(inline)", lines, every=bool(node.get("every")))
    if "as_path_list" in node:
        found = _list_match(str(node["as_path_list"]), AS_PATH_LIST, lists, errors, subject)
        return found if found is not None else p.FALSE
    if "as_path" in node:
        lines = _inline_lines(node["as_path"])
        _report_unsupported_lines(f"(inline, {subject})", AS_PATH_LIST, lines, errors, subject=policy)
        return p.MatchAsPathList("(inline)", lines)
    if "compare" in node:
        return p.MatchCompare(str(node["compare"]), str(node["op"]), int(node["value"]))
    if "origin" in node:
        return p.MatchOrigin(str(node["origin"]).lower())
    if "call" in node:
        return p.CallExpr(str(node["call"]))
    if "const" in node:
        return p.TRUE if node["const"] else p.FALSE
    return p.FALSE


def _expression_guard(
    entry: Mapping[str, Any],
    prefix_lists: Mapping[str, Any],
    platform: str,
    errors: ErrorSink,
    subject: str,
    policy: str,
    lists: MatchLists,
) -> p.BooleanExpr:
    """`match_expr` as a boolean expression.

    When the engine cannot evaluate one atom, the whole guard evaluates false
    and is reported as `unsupported-match` under the name of the policy. A
    false atom under a `not` would evaluate true.
    """
    raw = entry.get("match_expr")
    try:
        node = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError:
        node = None
    unsupported = _unsupported_atoms(node)
    if unsupported or not isinstance(node, Mapping):
        errors.report(
            "unsupported-match",
            f"{subject} sequence {_seq(entry)} matches on {', '.join(map(repr, unsupported))}, "
            "which the engine does not model; the entry evaluates false",
            policy,
        )
        return p.FALSE
    return _expression(node, prefix_lists, platform, errors, subject, lists, policy)


def _asn(token: str) -> int | None:
    """An AS number in asplain (`65001`) or asdot (`1.10`) form, else None."""
    high, dot, low = token.partition(".")
    if not (high.isascii() and high.isdigit() and (not dot or (low.isascii() and low.isdigit()))):
        return None
    return int(high) * 65536 + int(low) if dot else int(high)


def _sets(
    entry: Mapping[str, Any],
    *,
    prepend_last: bool,
    errors: ErrorSink | None = None,
    subject: str = "",
    policy: str = "",
    lists: MatchLists | None = None,
) -> list[p.Statement]:
    """The `set` clauses of the entry as statements.

    `set comm-list delete` runs before `set community` in the same entry. With
    `prepend_last`, `set as-path prepend` is the last statement. The IOS-XE
    path without `continue` uses this order. Without `prepend_last`,
    `set as-path prepend` is the first statement.

    A `set_unsupported` line is a set or statement line that the collector kept
    and the engine does not model. The other statements of the entry still
    run. The line is reported as `unsupported-set` under the name of the
    policy. The error kind is in `proof.UNCERTAIN_KINDS`.

    An AS-path prepend is read token by token across the stored items (VyOS
    keeps `65001 65001` as one string). A token is an AS number in asplain or
    asdot form. A prepend with any other token (the `last-as` form) is reported
    as `unsupported-set` and is left out.
    """
    errors = errors if errors is not None else ErrorSink()
    lists = lists if lists is not None else MatchLists()
    unsupported = _names(entry, "set_unsupported")
    tokens = [t for a in entry.get("set_as_path_prepend") or [] for t in str(a).split()]
    prepend = [a for a in (_asn(t) for t in tokens) if a is not None]
    if len(prepend) != len(tokens):
        unsupported.append("set as-path prepend " + " ".join(tokens))
        prepend = []
    if unsupported:
        errors.report(
            "unsupported-set",
            f"{subject} sequence {_seq(entry)} runs {', '.join(map(repr, unsupported))}, which the engine "
            "does not model; the route's attributes after this entry may differ",
            policy or subject,
        )

    out: list[p.Statement] = []
    if entry.get("set_comm_list_delete"):
        name = str(entry["set_comm_list_delete"])
        lines = lists.community.get(name)
        if lines is not None:
            _report_unsupported_lines(name, COMMUNITY_LIST, lines, errors)
        out.append(p.DeleteCommunities(name, lines))
    if entry.get("set_communities"):
        out.append(
            p.SetCommunities(
                frozenset(str(c) for c in entry["set_communities"]),
                additive=bool(entry.get("set_communities_additive")),
            )
        )
    if entry.get("set_local_pref") is not None:
        out.append(p.SetAttribute("local_pref", int(entry["set_local_pref"])))
    if entry.get("set_metric") is not None:
        out.append(p.SetAttribute("med", int(entry["set_metric"])))
    if entry.get("set_origin") is not None:
        out.append(p.SetAttribute("origin", str(entry["set_origin"]).lower()))
    if entry.get("set_tag") is not None:
        out.append(p.SetTag(int(entry["set_tag"])))
    if entry.get("set_weight") is not None:
        out.append(p.SetAttribute("weight", int(entry["set_weight"])))
    if entry.get("set_next_hop") is not None:
        out.append(p.SetAttribute("next_hop", str(entry["set_next_hop"])))

    if prepend:
        statement: p.Statement = p.PrependAsPath(tuple(prepend))
        if prepend_last:
            out.append(statement)
        else:
            out.insert(0, statement)
    return out


# --- route-map (kind="clause") --------------------------------------------


def _continue_target(
    entry: Mapping[str, Any], seqs: Sequence[int], errors: ErrorSink, subject: str
) -> int | None:
    """The sequence that a matched `continue` jumps to.

    Returns None when the entry has no usable `continue`. A bare `continue`
    goes to the next higher sequence and returns None on the highest clause. A
    target at or below the sequence of the clause is reported and returns None.
    A target without a clause returns -1.
    """
    if not entry.get("continues"):
        return None
    own = _seq(entry)
    later = [s for s in seqs if s > own]
    target = entry.get("continue_seq")
    if target is None:
        return later[0] if later else None
    target = int(target)
    if target <= own:
        errors.report(
            "invalid-continue-target",
            f"{subject} sequence {own} continues to {target}, which is not a later "
            "clause; the continue was ignored",
            subject,
        )
        return None
    if target not in seqs:
        return -1  # Each caller applies the platform rule for a target without a clause.
    return target


def _clause_terminal(action: str, flavor: str) -> p.Statement:
    """The terminal statement of a matched clause.

    IOS-XE exits. NX-OS returns, and the top-level policy of the map converts
    the return into an exit.
    """
    permit = action == "permit"
    if flavor == plat.NXOS:
        return p.Static(p.RETURN_TRUE if permit else p.RETURN_FALSE)
    return p.Static(p.EXIT_ACCEPT if permit else p.EXIT_REJECT)


def _compile_iosxe_route_map(
    name: str,
    entries: Sequence[Mapping[str, Any]],
    prefix_lists: Mapping[str, Any],
    platform: str,
    errors: ErrorSink,
    out: dict[str, p.Policy],
    lists: MatchLists,
) -> p.Policy:
    ordered = sorted(entries, key=_seq)
    seqs = [_seq(e) for e in ordered]
    has_continue = any(e.get("continues") for e in ordered)

    if not has_continue:
        # The chain is built from the highest sequence down. The false branch of a
        # clause is the next higher clause. The false branch of the highest clause
        # is the implicit deny.
        nested: tuple[p.Statement, ...] = (p.Static(p.RETURN_LOCAL_DEFAULT_ACTION),)
        for entry in reversed(ordered):
            action = str(entry.get("action") or "permit").lower()
            true_statements = (
                *_sets(
                    entry,
                    prepend_last=True,
                    errors=errors,
                    subject=f"route-map {name}",
                    policy=name,
                    lists=lists,
                ),
                _clause_terminal(action, plat.IOSXE),
            )
            nested = (
                p.If(
                    _guard(entry, prefix_lists, platform, errors, f"route-map {name}", name, lists),
                    true_statements,
                    nested,
                ),
            )
        policy = p.Policy(name=name, statements=nested)
        out[name] = policy
        return policy

    # A map with a `continue` compiles to one sub-policy per clause. `CallStatement`
    # links the sub-policies.
    def sub(seq: int) -> str:
        return f"{name}~clause{seq}"

    for index, entry in enumerate(ordered):
        own = _seq(entry)
        action = str(entry.get("action") or "permit").lower()
        body: list[p.Statement] = _sets(
            entry, prepend_last=False, errors=errors, subject=f"route-map {name}", policy=name, lists=lists
        )
        target = _continue_target(entry, seqs, errors, f"route-map {name}")
        if action == "permit" and target is not None and target != -1:
            # A taken `continue` sets the default action of the environment to accept.
            # `CallStatement` does not restore it. Every later fall-through of the
            # evaluation accepts.
            body.append(p.Static(p.SET_DEFAULT_ACTION_ACCEPT))
            body.append(p.CallStatement(sub(target)))
        else:
            if target == -1:
                errors.report(
                    "undefined-continue-target",
                    f"route-map {name} sequence {own} continues to a sequence with no "
                    "clause; the continue was treated as absent",
                    name,
                )
            body.append(_clause_terminal(action, plat.IOSXE))
        false_branch: tuple[p.Statement, ...] = (
            (p.CallStatement(sub(seqs[index + 1])),)
            if index + 1 < len(ordered)
            else (p.Static(p.RETURN_LOCAL_DEFAULT_ACTION),)
        )
        out[sub(own)] = p.Policy(
            name=sub(own),
            statements=(
                p.If(
                    _guard(entry, prefix_lists, platform, errors, f"route-map {name}", name, lists),
                    tuple(body),
                    false_branch,
                ),
            ),
        )

    policy = p.Policy(name=name, statements=(p.CallStatement(sub(seqs[0])),))
    out[name] = policy
    return policy


def _compile_nxos_route_map(
    name: str,
    entries: Sequence[Mapping[str, Any]],
    prefix_lists: Mapping[str, Any],
    platform: str,
    errors: ErrorSink,
    out: dict[str, p.Policy],
    lists: MatchLists,
) -> p.Policy:
    ordered = sorted(entries, key=_seq)
    seqs = [_seq(e) for e in ordered]
    targets = {
        t
        for t in (_continue_target(e, seqs, errors, f"route-map {name}") for e in ordered)
        if t is not None and t != -1
    }

    def interval_name(seq: int) -> str:
        return f"{name}~from{seq}"

    # A new interval starts at the first clause and at each continue target.
    intervals: list[list[Mapping[str, Any]]] = []
    for entry in ordered:
        if not intervals or _seq(entry) in targets:
            intervals.append([])
        intervals[-1].append(entry)

    for position, interval in enumerate(intervals):
        start = _seq(interval[0])
        body: list[p.Statement] = []
        if position == 0:
            # The first interval sets the local default action to reject.
            body.append(p.Static(p.SET_LOCAL_DEFAULT_ACTION_REJECT))
        for entry in interval:
            action = str(entry.get("action") or "permit").lower()
            matched: list[p.Statement] = _sets(
                entry,
                prepend_last=False,
                errors=errors,
                subject=f"route-map {name}",
                policy=name,
                lists=lists,
            )
            target = _continue_target(entry, seqs, errors, f"route-map {name}")
            if target == -1:
                # On NX-OS a continue to a sequence without a clause denies the route.
                errors.report(
                    "undefined-continue-target",
                    f"route-map {name} sequence {_seq(entry)} continues to a sequence "
                    "with no clause; NX-OS denies the route there",
                    name,
                )
                matched.append(p.Static(p.RETURN_FALSE))
            elif target is not None:
                matched.append(
                    p.Static(
                        p.SET_LOCAL_DEFAULT_ACTION_ACCEPT
                        if action == "permit"
                        else p.SET_LOCAL_DEFAULT_ACTION_REJECT
                    )
                )
                matched.append(p.CallStatement(interval_name(target)))
            else:
                matched.append(_clause_terminal(action, plat.NXOS))
            body.append(
                p.If(
                    _guard(entry, prefix_lists, platform, errors, f"route-map {name}", name, lists),
                    tuple(matched),
                )
            )
        body.append(p.Static(p.RETURN_LOCAL_DEFAULT_ACTION))
        out[interval_name(start)] = p.Policy(name=interval_name(start), statements=tuple(body))

    first = interval_name(seqs[0])
    policy = p.Policy(
        name=name,
        statements=(
            p.If(
                p.CallExpr(first),
                (_call_in_context(accept=True),),
                (_call_in_context(accept=False),),
            ),
        ),
    )
    out[name] = policy
    return policy


def _call_in_context(*, accept: bool) -> p.Statement:
    """The `callInContext` statement.

    A called route-map returns. A top-level route-map exits.
    """
    if accept:
        return p.If(p.CALL_EXPR_CONTEXT, (p.Static(p.RETURN_TRUE),), (p.Static(p.EXIT_ACCEPT),))
    return p.If(p.CALL_EXPR_CONTEXT, (p.Static(p.RETURN_FALSE),), (p.Static(p.EXIT_REJECT),))


def _empty_route_map(name: str, flavor: str, out: dict[str, p.Policy]) -> p.Policy:
    """A route-map without clauses denies every route in each call context.

    On IOS-XE the policy is one `ReturnLocalDefaultAction`. The local default
    action starts false.
    """
    statement = (
        _call_in_context(accept=False) if flavor == plat.NXOS else p.Static(p.RETURN_LOCAL_DEFAULT_ACTION)
    )
    policy = p.Policy(name=name, statements=(statement,))
    out[name] = policy
    return policy


# --- RPL (kind="statement") -----------------------------------------------

# The terminator after the body of every converted RPL policy. It returns the
# local default action inside a `CallExpr`. It returns inside a `CallStatement`.
# Otherwise it exits with the default action.
_RPL_TERMINATOR = p.If(
    p.CALL_EXPR_CONTEXT,
    (p.Static(p.RETURN_LOCAL_DEFAULT_ACTION),),
    (
        p.If(
            p.CALL_STATEMENT_CONTEXT,
            (p.Static(p.RETURN),),
            (p.Static(p.DEFAULT_ACTION),),
        ),
    ),
)

# `pass` sets the default action to accept, or the local default action inside a
# `CallExpr`. It does not end the evaluation. An entry with a `set` clause also
# gets one.
_RPL_PASS = p.If(
    p.CALL_EXPR_CONTEXT,
    (p.Static(p.SET_LOCAL_DEFAULT_ACTION_ACCEPT),),
    (p.Static(p.SET_DEFAULT_ACTION_ACCEPT),),
)

# `done` and `drop` end the evaluation. Inside a boolean `apply` they return.
_RPL_DONE = p.If(p.CALL_EXPR_CONTEXT, (p.Static(p.RETURN_TRUE),), (p.Static(p.EXIT_ACCEPT),))
_RPL_DROP = p.If(p.CALL_EXPR_CONTEXT, (p.Static(p.RETURN_FALSE),), (p.Static(p.EXIT_REJECT),))


def _rpl_guarded(entry: Mapping[str, Any]) -> bool:
    """Whether an RPL entry is an `if` or `elseif` branch.

    An `else` branch and a run of plain statements have no guard.
    """
    return bool(
        entry.get("match_expr")
        or entry.get("match_prefix_lists")
        or entry.get("match_tags")
        or entry.get("match_metric") is not None
        or entry.get("match_protocols")
        or entry.get("match_community_lists")
        or entry.get("match_as_path_lists")
        or entry.get("match_unsupported")
    )


def _parent(entry: Mapping[str, Any]) -> int | None:
    value = entry.get("parent_seq")
    return None if value is None else int(value)


def _compile_rpl(
    name: str,
    entries: Sequence[Mapping[str, Any]],
    prefix_lists: Mapping[str, Any],
    platform: str,
    errors: ErrorSink,
    out: dict[str, p.Policy],
    lists: MatchLists,
) -> p.Policy:
    """Compile an IOS-XR route-policy from the flattened entries that
    collectors/iosxr_bgp.py writes.

    An `if ... elseif ... else ... endif` is one entry per branch. `continues`
    and `continue_seq` chain each branch to the next branch. The chain compiles
    to the chained `If` of Batfish, `If(g1, body1, [If(g2, body2, else_body)])`.
    A later branch and the `else` run only when every earlier guard is false.
    The `else` branch has no guard. An entry nested inside a branch (a nested
    `if`, or the statements around one) holds the sequence of that branch in
    `parent_seq` and compiles into the body of the branch in `seq` order.

    `pass` (`passes`), every `set` clause and every comment line set the
    default action to accept. `done` and `drop` (`action` permit and deny) end
    the evaluation. The synthetic terminator after the body reads the default
    action.
    """
    subject = f"route-policy {name}"
    ordered = sorted(entries, key=_seq)
    seqs = {_seq(e) for e in ordered}
    children: dict[int | None, list[Mapping[str, Any]]] = {}
    for entry in ordered:
        parent = _parent(entry)
        if parent is not None and parent not in seqs:
            errors.report(
                "unsupported-match",
                f"{subject} sequence {_seq(entry)} is nested in sequence {parent}, which the policy does "
                "not hold; the entry was compiled at the top level",
                name,
            )
            parent = None
        children.setdefault(parent, []).append(entry)

    def entry_body(entry: Mapping[str, Any]) -> list[p.Statement]:
        inner: list[p.Statement] = _sets(
            entry, prepend_last=False, errors=errors, subject=subject, policy=name, lists=lists
        )
        if inner or entry.get("passes"):
            inner.append(_RPL_PASS)
        if entry.get("calls_policy"):
            inner.append(p.CallStatement(str(entry["calls_policy"])))
        inner.extend(block(children.get(_seq(entry), [])))
        action = (entry.get("action") or "").lower()
        if action == "permit":
            inner.append(_RPL_DONE)
        elif action == "deny":
            inner.append(_RPL_DROP)
        return inner

    def block(items: Sequence[Mapping[str, Any]]) -> list[p.Statement]:
        by_seq = {_seq(e): e for e in items}
        consumed: set[int] = set()
        statements: list[p.Statement] = []
        for entry in items:
            if _seq(entry) in consumed:
                continue
            chain = [entry]
            consumed.add(_seq(entry))
            current = entry
            while current.get("continues") and current.get("continue_seq") is not None:
                target = int(current["continue_seq"])
                if target not in by_seq or target in consumed or target <= _seq(current):
                    break
                current = by_seq[target]
                chain.append(current)
                consumed.add(target)
            tail: tuple[p.Statement, ...] = ()
            for branch in reversed(chain):
                body = tuple(entry_body(branch))
                if _rpl_guarded(branch):
                    guard = _guard(branch, prefix_lists, platform, errors, subject, name, lists)
                    tail = (p.If(guard, body, tail),)
                else:
                    # The branch is the `else` branch or a run of plain statements.
                    tail = body
            statements.extend(tail)
        return statements

    body = block(children.get(None, []))
    body.append(_RPL_TERMINATOR)
    policy = p.Policy(name=name, statements=tuple(body))
    out[name] = policy
    return policy


# --- policy scope ---------------------------------------------------------


def policy_namespace(policy: Mapping[str, Any]) -> str | None:
    """The namespace of the name of one `RoutePolicy` row.

    A route policy name is unique per device. Two devices that both define
    `RM-WAN-OUT` hold two policies. A policy row holds the owning device in
    `device_uid`. A Check Point virtual system defines its route maps in its
    routing context. Such a row also has `context_uid`, and the context is the
    namespace. Two virtual systems of one gateway that both define `out` hold
    two policies.
    """
    owner = policy.get("context_uid") or policy.get("device_uid")
    return str(owner) if owner else None


def policy_scoped(policies: Sequence[Mapping[str, Any]]) -> bool:
    """Whether a policy of the input has a namespace (`policy_namespace`).

    An input without a namespace on any policy (an input built by hand) is one
    namespace keyed by name.
    """
    return any(policy_namespace(node) for node in policies)


def context_namespaces(policies: Sequence[Mapping[str, Any]]) -> frozenset[str]:
    """The routing contexts some policy row is defined in (`policy_namespace`)."""
    return frozenset(str(node["context_uid"]) for node in policies if node.get("context_uid"))


def resolving_namespace(contexts: Collection[str], device_uid: Any, context_uid: Any) -> str | None:
    """The namespace in which a node of `device_uid` in `context_uid` resolves policy names.

    The namespace is the context when a policy row is defined in that context
    (`contexts`, from `context_namespaces`). Otherwise the namespace is the
    device.
    """
    if context_uid and str(context_uid) in contexts:
        return str(context_uid)
    return str(device_uid) if device_uid else None


def scoped_policies(policies: Sequence[Mapping[str, Any]], namespace: Any) -> list[Mapping[str, Any]]:
    """The policies in which a node with the namespace `namespace` (`resolving_namespace`)
    resolves its names.

    The result is the policies defined in `namespace`, or every policy when the
    input is not scoped. A node without a namespace resolves in the policies
    without a namespace.
    """
    if not policy_scoped(policies):
        return list(policies)
    return [node for node in policies if policy_namespace(node) == (str(namespace) if namespace else None)]


# --- entry point ----------------------------------------------------------


def compile_policies(
    policies: Sequence[Mapping[str, Any]], platform: str, errors: ErrorSink
) -> tuple[dict[str, p.Policy], dict[str, list[dict[str, Any]]]]:
    """Compile every `RoutePolicy` node into a `Policy` and return the prefix-list table with the policies.

    Prefix lists stay as their entry dicts, and `prefixlist.py` evaluates them.
    Community lists and AS-path lists (`match_lists`) are compiled into the
    match and delete statements that reference them.
    """
    prefix_lists: dict[str, list[dict[str, Any]]] = {}
    for node in policies:
        if str(node.get("kind", "")).lower() == "prefix-list":
            prefix_lists[str(node["name"])] = [dict(e) for e in node.get("entries") or []]

    lists = match_lists(policies)
    compiled: dict[str, p.Policy] = {}
    flavor = plat.route_map_flavor(platform)
    for node in policies:
        kind = str(node.get("kind", "")).lower()
        if kind == "prefix-list" or kind in LIST_KINDS:
            continue
        name = str(node["name"])
        if kind in {"gaia-route-map", "gaia-chain"}:
            from .gaia import Chain, RouteMap

            entries = sorted(node.get("entries") or [], key=_seq)
            statement = (
                Chain(
                    tuple(e["policy_name"] for e in entries),
                    tuple(tuple(e.get("address_families", [4])) for e in entries),
                )
                if kind == "gaia-chain"
                else RouteMap(name, tuple(dict(e) for e in entries))
            )
            compiled[name] = p.Policy(name, (statement,))
            continue
        entries = list(node.get("entries") or [])
        if not entries:
            _empty_route_map(name, flavor, compiled)
            continue
        entry_kind = str(entries[0].get("kind", "clause")).lower()
        try:
            if kind == "rpl" or entry_kind == "statement":
                _compile_rpl(name, entries, prefix_lists, platform, errors, compiled, lists)
            elif flavor == plat.NXOS:
                _compile_nxos_route_map(name, entries, prefix_lists, platform, errors, compiled, lists)
            else:
                _compile_iosxe_route_map(name, entries, prefix_lists, platform, errors, compiled, lists)
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            # A policy whose stored values do not parse denies every route.
            errors.report(
                "unsupported-policy",
                f"policy {name!r} could not be compiled ({type(exc).__name__}: {exc}); it denies every route",
                name,
            )
            _empty_route_map(name, flavor, compiled)
    return compiled, prefix_lists
