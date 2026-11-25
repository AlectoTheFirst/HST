"""Route-policy evaluation: the Result-flag decision tables."""

from hst.simul import policy as p
from hst.simul.errors import ErrorSink
from hst.simul.route import Route


def _env(**kwargs):
    route = Route(prefix="10.0.0.0/24")
    return p.Environment(original_route=route, output_route=route, errors=ErrorSink(), **kwargs)


def test_exit_unwinds_through_nested_calls():
    """An `exit` result propagates upward unmodified through every level."""
    inner = p.Policy("inner", (p.Static(p.EXIT_REJECT),))
    middle = p.Policy("middle", (p.CallStatement("inner"), p.Static(p.EXIT_ACCEPT)))
    outer = p.Policy(
        "outer",
        (p.If(p.TRUE, (p.CallStatement("middle"),)), p.Static(p.EXIT_ACCEPT)),
    )
    env = _env()
    env.policies = {"inner": inner, "middle": middle, "outer": outer}
    result = p.call(outer, env)
    assert result.exit and result.boolean_value is False
    assert p.process(outer, env) is False


def test_return_stops_only_the_called_policy_and_is_cleared():
    """`call()` catches `return`, clears it, and the
    caller's own statement loop carries on to its next statement."""
    inner = p.Policy("inner", (p.Static(p.RETURN_FALSE), p.Static(p.EXIT_ACCEPT)))
    outer = p.Policy("outer", (p.CallStatement("inner"), p.Static(p.EXIT_ACCEPT)))
    env = _env()
    env.policies = {"inner": inner, "outer": outer}
    result = p.call(outer, env)
    assert result.exit is True
    assert result.ret is False, "a policy.call() never returns return=true to its caller"
    assert result.boolean_value is True, "the caller continued past the callee's return"


def test_fall_through_reads_the_environment_default_action():
    """An exhausted statement list returns
    `fallThrough=true` with the environment's default action as its value."""
    env = _env()
    empty = p.Policy("empty", ())
    assert p.call(empty, env) == p.Result(boolean_value=False, fall_through=True)
    env.default_action = True
    assert p.call(empty, env) == p.Result(boolean_value=True, fall_through=True)


def test_if_fall_through_does_not_read_the_default_action():
    """`If`'s fall-through result leaves `booleanValue` false
    even when the environment default action is accept."""
    env = _env()
    env.default_action = True
    result = p.If(p.TRUE, ()).execute(env)
    assert result == p.Result(boolean_value=False, fall_through=True)


def test_default_action_statement_exits_with_the_environment_value():
    env = _env()
    env.default_action = True
    assert p.Static(p.DEFAULT_ACTION).execute(env) == p.Result(boolean_value=True, exit=True)


def test_call_statement_leaks_local_default_action_but_call_expr_does_not():
    """`CallStatement` never restores
    `localDefaultAction`; `CallExpr` restores it unconditionally."""
    setter = p.Policy("setter", (p.Static(p.SET_LOCAL_DEFAULT_ACTION_ACCEPT),))

    env = _env()
    env.policies = {"setter": setter}
    p.CallStatement("setter").execute(env)
    assert env.local_default_action is True

    env = _env()
    env.policies = {"setter": setter}
    p.CallExpr("setter").evaluate(env)
    assert env.local_default_action is False


def test_call_statement_context_is_saved_and_restored():
    env = _env()
    env.policies = {"probe": p.Policy("probe", (p.Static(p.EXIT_ACCEPT),))}
    p.CallStatement("probe").execute(env)
    assert env.call_statement_context is False


def test_missing_policy_sets_error_evaluates_false_and_is_reported():
    """A call to a missing policy evaluates false, sets the error state, is
    reported and stays non-terminal, so the caller's loop continues."""
    env = _env()
    result = p.CallStatement("absent").execute(env)
    assert result == p.Result(boolean_value=False)
    assert env.error is True
    assert [e.kind for e in env.errors.errors] == ["undefined-policy-call"]

    env = _env()
    assert p.CallExpr("absent").evaluate(env) == p.Result()
    assert env.error is True
    assert env.errors.errors, "a dangling call is never silent"


def test_conjunction_short_circuits_false_and_is_true_when_empty():
    env = _env()
    assert p.Conjunction(()).evaluate(env) == p.Result(boolean_value=True)
    assert p.Conjunction((p.TRUE, p.FALSE, p.TRUE)).evaluate(env).boolean_value is False


def test_conjunction_propagates_an_exit_unmodified():
    exiting = p.Policy("exiting", (p.Static(p.EXIT_ACCEPT),))
    env = _env()
    env.policies = {"exiting": exiting}
    result = p.Conjunction((p.CallExpr("exiting"), p.FALSE)).evaluate(env)
    assert result.exit is True and result.boolean_value is True


def test_disjunction_short_circuits_true_and_is_false_when_empty():
    env = _env()
    assert p.Disjunction(()).evaluate(env) == p.Result()
    assert p.Disjunction((p.FALSE, p.TRUE)).evaluate(env).boolean_value is True


def test_fall_through_statement_returns_and_marks_fall_through():
    env = _env()
    assert p.Static(p.FALL_THROUGH).execute(env) == p.Result(ret=True, fall_through=True)


def test_first_match_chain_takes_the_first_definite_answer():
    """The `FirstMatchChain` decision table."""
    falls = p.Policy("falls", ())
    denies = p.Policy("denies", (p.Static(p.RETURN_FALSE),))
    env = _env()
    env.policies = {"falls": falls, "denies": denies}
    result = p.FirstMatchChain((p.CallExpr("falls"), p.CallExpr("denies"))).evaluate(env)
    assert result.boolean_value is False and result.fall_through is False


def test_first_match_chain_falls_back_to_the_default_policy():
    falls = p.Policy("falls", ())
    fallback = p.Policy("fallback", (p.Static(p.RETURN_TRUE),))
    env = _env()
    env.policies = {"falls": falls, "fallback": fallback}
    env.default_policy = "fallback"
    assert p.FirstMatchChain((p.CallExpr("falls"),)).evaluate(env).boolean_value is True


def test_conjunction_chain_needs_every_opinion_to_accept():
    """The `ConjunctionChain` decision table: a definite reject short-circuits,
    a fall-through expresses no opinion."""
    accepts = p.Policy("accepts", (p.Static(p.RETURN_TRUE),))
    rejects = p.Policy("rejects", (p.Static(p.RETURN_FALSE),))
    falls = p.Policy("falls", ())
    env = _env()
    env.policies = {"accepts": accepts, "rejects": rejects, "falls": falls}
    assert (
        p.ConjunctionChain((p.CallExpr("falls"), p.CallExpr("accepts"))).evaluate(env).boolean_value is True
    )
    assert (
        p.ConjunctionChain((p.CallExpr("accepts"), p.CallExpr("rejects"))).evaluate(env).boolean_value
        is False
    )


def test_conjunction_chain_falls_to_the_default_policy_when_the_last_answer_was_no_opinion():
    """The running 'last result' remembers a fall-through too, so an accept
    followed by a no-opinion subroutine still ends at the default policy."""
    accepts = p.Policy("accepts", (p.Static(p.RETURN_TRUE),))
    falls = p.Policy("falls", ())
    fallback = p.Policy("fallback", (p.Static(p.RETURN_FALSE),))
    env = _env()
    env.policies = {"accepts": accepts, "falls": falls, "fallback": fallback}
    env.default_policy = "fallback"
    chain = p.ConjunctionChain((p.CallExpr("accepts"), p.CallExpr("falls")))
    assert chain.evaluate(env).boolean_value is False


def test_conjunction_chain_with_no_opinions_uses_the_default_policy():
    falls = p.Policy("falls", ())
    fallback = p.Policy("fallback", (p.Static(p.RETURN_TRUE),))
    env = _env()
    env.policies = {"falls": falls, "fallback": fallback}
    env.default_policy = "fallback"
    assert p.ConjunctionChain((p.CallExpr("falls"),)).evaluate(env).boolean_value is True
    assert p.ConjunctionChain(()).evaluate(env).boolean_value is True


def test_suppress_blocks_acceptance_and_unsuppress_clears_it():
    """Accepted is `booleanValue and not suppressed`."""
    suppressing = p.Policy("s", (p.Static(p.SUPPRESS), p.Static(p.EXIT_ACCEPT)))
    env = _env()
    assert p.process(suppressing, env) is False

    cleared = p.Policy("s", (p.Static(p.SUPPRESS), p.Static(p.UNSUPPRESS), p.Static(p.EXIT_ACCEPT)))
    env = _env()
    assert p.process(cleared, env) is True


def test_an_untouched_policy_is_never_suppressed():
    env = _env()
    assert env.suppressed is None
    assert p.process(p.Policy("a", (p.Static(p.EXIT_ACCEPT),)), env) is True


def test_explicit_set_tag_blocks_a_later_default_tag():
    """`SetDefaultTag` keeps a tag that `SetTag` set."""
    env = _env()
    p.SetTag(7).execute(env)
    p.SetDefaultTag(65000).execute(env)
    assert env.output_route.tag == 7

    env = _env()
    p.SetDefaultTag(65000).execute(env)
    assert env.output_route.tag == 65000


def test_remove_private_as_strips_only_private_asns():
    # 64500 is public, 64512-65534 is the 16-bit private range, 65535 is reserved.
    route = Route(prefix="10.0.0.0/24", as_path=(64500, 65001, 65535))
    env = p.Environment(original_route=route, output_route=route, errors=ErrorSink())
    p.Static(p.REMOVE_PRIVATE_AS).execute(env)
    assert env.output_route.as_path == (64500, 65535)
