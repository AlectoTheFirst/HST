"""The route-policy evaluation core.

The primitives are the four-flag
`Result`, the `RoutingPolicy.call()` loop outcomes,
`If`/`CallStatement`/the static statements,
`CallExpr`/`Conjunction`/`Disjunction`/`FirstMatchChain`/`ConjunctionChain`,
the `Environment` state and the acceptance rule.
`compile.py` compiles the vendor constructs into these primitives.
Vendor-specific conversion belongs in `compile.py`.

`Result.ret` holds the `return` flag.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Protocol

from . import matchlist
from .errors import ErrorSink
from .prefixlist import evaluate as prefix_list_permits
from .route import Route

# --- Result ---------------------------------------------------------------


@dataclass(frozen=True)
class Result:
    """The four flags of an evaluation. `exit` and `ret` are never both true."""

    boolean_value: bool = False
    exit: bool = False
    ret: bool = False
    fall_through: bool = False

    def cleared_return(self) -> Result:
        """Returns the result with `ret` cleared and every other flag unchanged.

        `RoutingPolicy.call()`, `CallStatement`, `CallExpr`, both chains and
        both boolean combinators apply it to the result of a callee before they
        return the result.
        """
        return self if not self.ret else replace(self, ret=False)


# --- Environment ----------------------------------------------------------


@dataclass
class Environment:
    """The state of one evaluation.

    The Batfish flag `use_output_attributes` is fixed false. Match expressions
    read `original_route`.
    """

    original_route: Route
    output_route: Route
    direction: str = "in"
    policies: dict[str, Policy] = field(default_factory=dict)
    prefix_lists: dict[str, list[dict[str, object]]] = field(default_factory=dict)
    errors: ErrorSink = field(default_factory=ErrorSink)
    default_action: bool = False
    local_default_action: bool = False
    default_policy: str | None = None
    suppressed: bool | None = None
    error: bool = False
    tag_explicitly_set: bool = False
    call_expr_context: bool = False
    call_statement_context: bool = False
    # The session type is "ebgp" or "ibgp".
    session_type: str = "ebgp"
    peer_as: int | None = None


# --- Statements and expressions -------------------------------------------


class Statement(Protocol):
    def execute(self, env: Environment) -> Result: ...


class BooleanExpr(Protocol):
    def evaluate(self, env: Environment) -> Result: ...


@dataclass(frozen=True)
class Policy:
    """A named, ordered list of statements."""

    name: str
    statements: tuple[Statement, ...] = ()


def call(policy: Policy, env: Environment) -> Result:
    """The statement loop of `RoutingPolicy.call()`.

    An exit result ends the loop. A return result ends the loop with `ret`
    cleared. A policy without an exit or a return falls through with the
    default action as its boolean value.
    """
    for statement in policy.statements:
        result = statement.execute(env)
        if result.exit:
            return result
        if result.ret:
            return result.cleared_return()
    return Result(boolean_value=env.default_action, fall_through=True)


def process(policy: Policy, env: Environment) -> bool:
    """The acceptance rule of `RoutingPolicy.process()`.

    A route is accepted when the boolean value is true and the route is not
    suppressed.
    """
    result = call(policy, env)
    return result.boolean_value and env.suppressed is not True


# --- Static statements --------------------------------

EXIT_ACCEPT = "ExitAccept"
EXIT_REJECT = "ExitReject"
DEFAULT_ACTION = "DefaultAction"
FALL_THROUGH = "FallThrough"
RETURN = "Return"
RETURN_FALSE = "ReturnFalse"
RETURN_TRUE = "ReturnTrue"
RETURN_LOCAL_DEFAULT_ACTION = "ReturnLocalDefaultAction"
SET_DEFAULT_ACTION_ACCEPT = "SetDefaultActionAccept"
SET_DEFAULT_ACTION_REJECT = "SetDefaultActionReject"
SET_LOCAL_DEFAULT_ACTION_ACCEPT = "SetLocalDefaultActionAccept"
SET_LOCAL_DEFAULT_ACTION_REJECT = "SetLocalDefaultActionReject"
SUPPRESS = "Suppress"
UNSUPPRESS = "Unsuppress"
REMOVE_PRIVATE_AS = "RemovePrivateAs"

# The private AS ranges of RFC 6996 and RFC 1930. `RemovePrivateAs` removes them from the AS path.
_PRIVATE_AS_RANGES = ((64512, 65534), (4200000000, 4294967294))


def _is_private_as(asn: int) -> bool:
    return any(lo <= asn <= hi for lo, hi in _PRIVATE_AS_RANGES)


@dataclass(frozen=True)
class Static:
    """One variant of the `Statements` enum.

    A variant that sets state returns `Result()`, and the enclosing statement
    loop continues.
    """

    kind: str

    def execute(self, env: Environment) -> Result:
        k = self.kind
        if k == EXIT_ACCEPT:
            return Result(boolean_value=True, exit=True)
        if k == EXIT_REJECT:
            return Result(boolean_value=False, exit=True)
        if k == DEFAULT_ACTION:
            return Result(boolean_value=env.default_action, exit=True)
        if k == FALL_THROUGH:
            return Result(boolean_value=False, ret=True, fall_through=True)
        if k in (RETURN, RETURN_FALSE):
            return Result(boolean_value=False, ret=True)
        if k == RETURN_TRUE:
            return Result(boolean_value=True, ret=True)
        if k == RETURN_LOCAL_DEFAULT_ACTION:
            return Result(boolean_value=env.local_default_action, ret=True)
        if k == SET_DEFAULT_ACTION_ACCEPT:
            env.default_action = True
        elif k == SET_DEFAULT_ACTION_REJECT:
            env.default_action = False
        elif k == SET_LOCAL_DEFAULT_ACTION_ACCEPT:
            env.local_default_action = True
        elif k == SET_LOCAL_DEFAULT_ACTION_REJECT:
            env.local_default_action = False
        elif k == SUPPRESS:
            env.suppressed = True
        elif k == UNSUPPRESS:
            env.suppressed = False
        elif k == REMOVE_PRIVATE_AS:
            path = tuple(a for a in env.output_route.as_path if not _is_private_as(a))
            env.output_route = env.output_route.with_(as_path=path)
        return Result()


# --- Control flow ---------------------------------------------------------


@dataclass(frozen=True)
class If:
    """An `If` whose branch does not exit or return falls through with a false boolean value."""

    guard: BooleanExpr
    true_statements: tuple[Statement, ...] = ()
    false_statements: tuple[Statement, ...] = ()

    def execute(self, env: Environment) -> Result:
        guard = self.guard.evaluate(env)
        if guard.exit:
            return guard
        branch = self.true_statements if guard.boolean_value else self.false_statements
        for statement in branch:
            result = statement.execute(env)
            if result.exit or result.ret:
                return result
        return Result(fall_through=True)


@dataclass(frozen=True)
class CallStatement:
    """`CallStatement` saves and restores `call_statement_context`.

    It keeps the `default_action` and the `local_default_action` that the callee set.
    """

    name: str

    def execute(self, env: Environment) -> Result:
        policy = env.policies.get(self.name)
        if policy is None:
            env.error = True
            env.errors.report(
                "undefined-policy-call",
                f"a policy calls {self.name!r}, which no RoutePolicy node defines; the call evaluates false",
                self.name,
            )
            return Result(boolean_value=False)
        saved = env.call_statement_context
        env.call_statement_context = True
        try:
            result = call(policy, env)
        finally:
            env.call_statement_context = saved
        return result.cleared_return()


@dataclass(frozen=True)
class CallExpr:
    """`CallExpr` saves and restores `call_expr_context` and `local_default_action`."""

    name: str

    def evaluate(self, env: Environment) -> Result:
        policy = env.policies.get(self.name)
        if policy is None:
            env.error = True
            env.errors.report(
                "undefined-policy-call",
                f"a policy calls {self.name!r}, which no RoutePolicy node defines; the call evaluates false",
                self.name,
            )
            return Result()
        saved_context = env.call_expr_context
        saved_local_default = env.local_default_action
        env.call_expr_context = True
        try:
            result = call(policy, env)
        finally:
            env.call_expr_context = saved_context
            env.local_default_action = saved_local_default
        return result.cleared_return()


# --- Boolean combinators --------------------------------------------------


@dataclass(frozen=True)
class Conjunction:
    """An empty conjunct list is true."""

    conjuncts: tuple[BooleanExpr, ...] = ()

    def evaluate(self, env: Environment) -> Result:
        for conjunct in self.conjuncts:
            result = conjunct.evaluate(env)
            if result.exit:
                return result
            if not result.boolean_value:
                return result.cleared_return()
        return Result(boolean_value=True)


@dataclass(frozen=True)
class Disjunction:
    """An empty disjunct list is false."""

    disjuncts: tuple[BooleanExpr, ...] = ()

    def evaluate(self, env: Environment) -> Result:
        for disjunct in self.disjuncts:
            result = disjunct.evaluate(env)
            if result.exit:
                return result
            if result.boolean_value:
                return result.cleared_return()
        return Result()


@dataclass(frozen=True)
class Not:
    expr: BooleanExpr

    def evaluate(self, env: Environment) -> Result:
        result = self.expr.evaluate(env)
        if result.exit:
            return result
        return Result(boolean_value=not result.boolean_value)


@dataclass(frozen=True)
class BooleanLiteral:
    value: bool

    def evaluate(self, env: Environment) -> Result:
        return Result(boolean_value=self.value)


TRUE = BooleanLiteral(True)
FALSE = BooleanLiteral(False)


@dataclass(frozen=True)
class MatchCallExprContext:
    """`BooleanExprs.CALL_EXPR_CONTEXT`. IOS-XR's dispositions and NX-OS's
    `callInContext` both branch on it."""

    def evaluate(self, env: Environment) -> Result:
        return Result(boolean_value=env.call_expr_context)


@dataclass(frozen=True)
class MatchCallStatementContext:
    def evaluate(self, env: Environment) -> Result:
        return Result(boolean_value=env.call_statement_context)


CALL_EXPR_CONTEXT = MatchCallExprContext()
CALL_STATEMENT_CONTEXT = MatchCallStatementContext()


# --- Chains ---------------------------------------------------------------


class DefaultPolicyNotSet(Exception):
    """Raised where Batfish raises `BatfishException("Default policy is not set")`."""


def _default_policy_result(env: Environment) -> Result:
    if env.default_policy is None:
        raise DefaultPolicyNotSet("Default policy is not set")
    return CallExpr(env.default_policy).evaluate(env).cleared_return()


@dataclass(frozen=True)
class FirstMatchChain:
    """Returns the result of the first subroutine that does not fall through.

    When every subroutine falls through, the default policy gives the result.
    """

    subroutines: tuple[BooleanExpr, ...] = ()

    def evaluate(self, env: Environment) -> Result:
        for subroutine in self.subroutines:
            result = subroutine.evaluate(env)
            if result.exit:
                return result
            if not result.fall_through:
                return result.cleared_return()
        return _default_policy_result(env)


@dataclass(frozen=True)
class ConjunctionChain:
    """Returns the first result that rejects without a fall-through.

    Without such a result, the chain returns the result of the last subroutine
    when that result does not fall through. An empty chain and a chain whose
    last subroutine falls through use the default policy.
    """

    subroutines: tuple[BooleanExpr, ...] = ()

    def evaluate(self, env: Environment) -> Result:
        last = Result(fall_through=True)
        for subroutine in self.subroutines:
            result = subroutine.evaluate(env)
            if result.exit:
                return result
            if not result.fall_through and not result.boolean_value:
                return result.cleared_return()
            last = result
        if not last.fall_through:
            return last.cleared_return()
        return _default_policy_result(env)


# --- Match expressions over the schema's normalized property forms ---------


@dataclass(frozen=True)
class MatchPrefixList:
    """`MatchPrefixSet(DestinationNetwork, NamedPrefixSet(name))`.

    Matches the prefix of the route against one named prefix list.
    """

    name: str

    def evaluate(self, env: Environment) -> Result:
        entries = env.prefix_lists.get(self.name)
        if entries is None:
            env.error = True
            env.errors.report(
                "undefined-prefix-list",
                f"prefix list {self.name!r} has no PrefixListEntry nodes; the match evaluates false",
                self.name,
            )
            return Result()
        return Result(boolean_value=prefix_list_permits(entries, env.original_route.prefix))


@dataclass(frozen=True)
class MatchInlinePrefixes:
    """The inline prefix set of IOS-XR `destination in (10.0.0.0/8 le 24, ...)`.

    Each element is `(prefix, min_len, max_len)`. The route matches when one
    element matches. The test is the containment and length test of a
    prefix-list line (`prefixlist.py`).
    """

    elements: tuple[tuple[str, int, int], ...]

    def evaluate(self, env: Environment) -> Result:
        entries = [
            {"seq": i, "action": "permit", "prefix": prefix, "min_len": lo, "max_len": hi}
            for i, (prefix, lo, hi) in enumerate(self.elements)
        ]
        return Result(boolean_value=prefix_list_permits(entries, env.original_route.prefix))


@dataclass(frozen=True)
class MatchTag:
    value: int

    def evaluate(self, env: Environment) -> Result:
        return Result(boolean_value=env.original_route.tag == self.value)


@dataclass(frozen=True)
class MatchMetric:
    value: int

    def evaluate(self, env: Environment) -> Result:
        return Result(boolean_value=env.original_route.effective_med == self.value)


@dataclass(frozen=True)
class MatchProtocol:
    protocols: tuple[str, ...]

    def evaluate(self, env: Environment) -> Result:
        src = (env.original_route.src_protocol or env.original_route.protocol).lower()
        return Result(boolean_value=src in self.protocols)


@dataclass(frozen=True)
class MatchCommunityList:
    """`match community <list>` or `community matches-any|matches-every <set>`.

    Matches the communities of the route against the lines of one community
    list (`matchlist.py`). `every` selects the IOS-XR `matches-every` test.
    """

    name: str
    lines: tuple[matchlist.Line, ...]
    every: bool = False

    def evaluate(self, env: Environment) -> Result:
        communities = env.original_route.communities
        if self.every:
            return Result(boolean_value=matchlist.community_set_matches_every(self.lines, communities))
        return Result(boolean_value=matchlist.community_list_permits(self.lines, communities))


@dataclass(frozen=True)
class MatchAsPathList:
    """`match as-path <list>` or `as-path in <set>`.

    Matches the AS path of the route against the lines of one AS-path list
    (`matchlist.py`).
    """

    name: str
    lines: tuple[matchlist.Line, ...]

    def evaluate(self, env: Environment) -> Result:
        return Result(boolean_value=matchlist.as_path_list_permits(self.lines, env.original_route.as_path))


# The IOS-XR comparison operators. `is` and `eq` are both equality.
_COMPARE = {
    "eq": lambda a, b: a == b,
    "is": lambda a, b: a == b,
    "ge": lambda a, b: a >= b,
    "le": lambda a, b: a <= b,
}


@dataclass(frozen=True)
class MatchCompare:
    """An IOS-XR numeric guard such as `med eq N`, `local-preference ge N`,
    `as-path length le N` or `tag is N`.

    `attribute` is one of `med`, `local_pref`, `as_path_length` or `tag`. A
    route without a tag matches no tag test.
    """

    attribute: str
    op: str
    value: int

    def evaluate(self, env: Environment) -> Result:
        route = env.original_route
        actual: int | None
        if self.attribute == "med":
            actual = route.effective_med
        elif self.attribute == "local_pref":
            actual = route.local_pref
        elif self.attribute == "as_path_length":
            actual = route.as_path_length
        else:
            actual = route.tag
        if actual is None:
            return Result()
        return Result(boolean_value=bool(_COMPARE[self.op](actual, self.value)))


@dataclass(frozen=True)
class MatchOrigin:
    """IOS-XR `origin is igp|egp|incomplete`."""

    origin: str

    def evaluate(self, env: Environment) -> Result:
        return Result(boolean_value=env.original_route.origin == self.origin)


# --- Set statements -------------------------------------------------------


@dataclass(frozen=True)
class SetAttribute:
    """Writes one scalar attribute of the output route.

    The statement returns `Result()`, and the statement loop continues.
    """

    attribute: str
    value: object

    def execute(self, env: Environment) -> Result:
        env.output_route = env.output_route.with_(**{self.attribute: self.value})
        return Result()


@dataclass(frozen=True)
class SetTag:
    """A written tag blocks a later `SetDefaultTag` in the same evaluation."""

    value: int

    def execute(self, env: Environment) -> Result:
        env.output_route = env.output_route.with_(tag=self.value)
        env.tag_explicitly_set = True
        return Result()


@dataclass(frozen=True)
class SetDefaultTag:
    """NX-OS's generated import policy tags an accepted route with the peer's AS.
    It writes only when no explicit `set tag` has
    run in this evaluation."""

    value: int

    def execute(self, env: Environment) -> Result:
        if not env.tag_explicitly_set:
            env.output_route = env.output_route.with_(tag=self.value)
        return Result()


@dataclass(frozen=True)
class PrependAsPath:
    asns: tuple[int, ...]

    def execute(self, env: Environment) -> Result:
        env.output_route = env.output_route.with_(as_path=self.asns + env.output_route.as_path)
        return Result()


@dataclass(frozen=True)
class SetCommunities:
    """`set community`, additive or replacing.

    On IOS-XE and NX-OS the replacing form removes the standard communities and
    keeps the extended and large communities. A community is an opaque string
    in the engine. The replacing form replaces every community of the route.
    """

    communities: frozenset[str]
    additive: bool = False

    def execute(self, env: Environment) -> Result:
        current = env.output_route.communities
        new = (current | self.communities) if self.additive else self.communities
        env.output_route = env.output_route.with_(communities=frozenset(new))
        return Result()


@dataclass(frozen=True)
class DeleteCommunities:
    """`set comm-list <name> delete` (IOS-XE, NX-OS) and `delete community in
    <set>` (IOS-XR).

    The statement removes every community that a permit line of the list
    matches. `lines` is None when no `community-list` RoutePolicy of that name
    is in the input. A delete with an undefined community list changes nothing
    and is reported.
    """

    name: str
    lines: tuple[matchlist.Line, ...] | None = None

    def execute(self, env: Environment) -> Result:
        if self.lines is None:
            env.errors.report(
                "undefined-community-list",
                f"community list {self.name!r} is not in the snapshot; "
                "`set comm-list delete` is a no-op for it",
                self.name,
            )
            return Result()
        kept = matchlist.delete_matching(self.lines, env.output_route.communities)
        env.output_route = env.output_route.with_(communities=kept)
        return Result()
