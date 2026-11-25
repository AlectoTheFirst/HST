"""Vendor policy shapes compiled from the normalized schema nodes."""

import json

import pytest

from hst.simul import platforms
from hst.simul import policy as p
from hst.simul.compile import compile_policies
from hst.simul.errors import ErrorSink
from hst.simul.route import Route


def _prefix_list(name, prefix, **kwargs):
    entry = {"seq": 5, "action": "permit", "prefix": prefix, "min_len": None, "max_len": None}
    entry.update(kwargs)
    if entry["min_len"] is None:
        length = int(prefix.split("/")[1])
        entry["min_len"], entry["max_len"] = length, length
    return {"name": name, "kind": "prefix-list", "entries": [entry]}


def _clause(seq, action, **kwargs):
    return {"seq": seq, "kind": "clause", "action": action, **kwargs}


def _statement(seq, **kwargs):
    return {"seq": seq, "kind": "statement", **kwargs}


def _run(policies, name, prefix, platform=platforms.IOSXE, errors=None):
    errors = errors if errors is not None else ErrorSink()
    compiled, prefix_lists = compile_policies(policies, platform, errors)
    route = Route(prefix=prefix)
    env = p.Environment(
        original_route=route,
        output_route=route,
        policies=compiled,
        prefix_lists=prefix_lists,
        errors=errors,
    )
    return p.process(compiled[name], env), env


# --- route-map: sequencing, continue, implicit deny ------------------------


def test_route_map_clauses_are_tried_in_ascending_sequence_order():
    policies = [
        _prefix_list("PL_TEN", "10.0.0.0/8"),
        _prefix_list("PL_ANY", "0.0.0.0/0", min_len=0, max_len=32),
        {
            "name": "RM",
            "kind": "route-map",
            "entries": [
                _clause(10, "deny", match_prefix_lists=["PL_TEN"]),
                _clause(20, "permit", match_prefix_lists=["PL_ANY"]),
            ],
        },
    ]
    assert _run(policies, "RM", "10.0.0.0/8")[0] is False, "seq 10 denies first"
    assert _run(policies, "RM", "192.168.0.0/16")[0] is True


def test_a_route_matching_no_clause_is_denied():
    """The chain ends at `ReturnLocalDefaultAction`, which starts false."""
    policies = [
        _prefix_list("PL_TEN", "10.0.0.0/8"),
        {
            "name": "RM",
            "kind": "route-map",
            "entries": [_clause(10, "permit", match_prefix_lists=["PL_TEN"])],
        },
    ]
    assert _run(policies, "RM", "192.168.0.0/16")[0] is False


def test_a_clause_with_no_match_lines_matches_every_route():
    policies = [{"name": "RM", "kind": "route-map", "entries": [_clause(10, "permit")]}]
    assert _run(policies, "RM", "192.168.0.0/16")[0] is True


def test_a_route_map_defined_with_no_clauses_denies_everything():
    policies = [{"name": "RM", "kind": "route-map", "entries": []}]
    assert _run(policies, "RM", "10.0.0.0/8")[0] is False
    assert _run(policies, "RM", "10.0.0.0/8", platform=platforms.NXOS)[0] is False


def test_continue_applies_the_later_clauses_set_statements():
    """A matched `permit` clause with a usable `continue` runs the target clause
    and does not exit."""
    policies = [
        _prefix_list("PL_TEN", "10.0.0.0/8"),
        {
            "name": "RM",
            "kind": "route-map",
            "entries": [
                _clause(10, "permit", match_prefix_lists=["PL_TEN"], continues=True, set_local_pref=250),
                _clause(20, "permit", set_metric=42),
            ],
        },
    ]
    accepted, env = _run(policies, "RM", "10.0.0.0/8")
    assert accepted is True
    assert env.output_route.local_pref == 250
    assert env.output_route.med == 42, "the continue target's set clause also ran"


def test_a_taken_continue_changes_every_later_fall_through_in_the_evaluation():
    """`SetDefaultActionAccept` is environment-scoped and `CallStatement` never
    restores it, so a route that later runs off the end of a clause accepts."""
    policies = [
        _prefix_list("PL_TEN", "10.0.0.0/8"),
        _prefix_list("PL_NINE", "9.0.0.0/8"),
        {
            "name": "RM",
            "kind": "route-map",
            "entries": [
                _clause(10, "permit", match_prefix_lists=["PL_TEN"], continues=True),
                _clause(20, "permit", match_prefix_lists=["PL_NINE"]),
            ],
        },
    ]
    accepted, _ = _run(policies, "RM", "10.0.0.0/8")
    assert accepted is True


def test_continue_on_a_deny_clause_still_rejects():
    """`continue` is consulted only in the permit branch. A matched `deny` clause
    exits."""
    policies = [
        _prefix_list("PL_TEN", "10.0.0.0/8"),
        {
            "name": "RM",
            "kind": "route-map",
            "entries": [
                _clause(10, "deny", match_prefix_lists=["PL_TEN"], continues=True),
                _clause(20, "permit"),
            ],
        },
    ]
    assert _run(policies, "RM", "10.0.0.0/8")[0] is False


def test_a_backward_continue_target_is_reported_and_ignored():
    policies = [
        {
            "name": "RM",
            "kind": "route-map",
            "entries": [
                _clause(10, "permit"),
                _clause(20, "permit", continues=True, continue_seq=10),
            ],
        }
    ]
    errors = ErrorSink()
    _run(policies, "RM", "10.0.0.0/8", errors=errors)
    assert "invalid-continue-target" in {e.kind for e in errors.errors}


def test_nxos_denies_a_continue_to_an_undefined_sequence():
    """NX-OS denies the route on `continue <undefined sequence>`."""
    policies = [
        _prefix_list("PL_TEN", "10.0.0.0/8"),
        {
            "name": "RM",
            "kind": "route-map",
            "entries": [
                _clause(10, "permit", match_prefix_lists=["PL_TEN"], continues=True, continue_seq=99),
                _clause(20, "permit"),
            ],
        },
    ]
    errors = ErrorSink()
    accepted, _ = _run(policies, "RM", "10.0.0.0/8", platform=platforms.NXOS, errors=errors)
    assert accepted is False
    assert "undefined-continue-target" in {e.kind for e in errors.errors}


def test_iosxe_treats_a_continue_to_an_undefined_sequence_as_absent():
    policies = [
        _prefix_list("PL_TEN", "10.0.0.0/8"),
        {
            "name": "RM",
            "kind": "route-map",
            "entries": [
                _clause(10, "permit", match_prefix_lists=["PL_TEN"], continues=True, continue_seq=99),
                _clause(20, "deny"),
            ],
        },
    ]
    errors = ErrorSink()
    accepted, _ = _run(policies, "RM", "10.0.0.0/8", errors=errors)
    assert accepted is True
    assert "undefined-continue-target" in {e.kind for e in errors.errors}


def test_a_called_nxos_route_map_returns_to_its_caller():
    """A matched clause of a called route-map returns its answer, so the caller
    keeps evaluating."""
    policies = [
        _prefix_list("PL_TEN", "10.0.0.0/8"),
        {
            "name": "INNER",
            "kind": "route-map",
            "entries": [_clause(10, "deny", match_prefix_lists=["PL_TEN"])],
        },
        {
            "name": "OUTER",
            "kind": "route-map",
            "entries": [_clause(10, "permit")],
        },
    ]
    errors = ErrorSink()
    compiled, prefix_lists = compile_policies(policies, platforms.NXOS, errors)
    route = Route(prefix="10.0.0.0/8")
    env = p.Environment(
        original_route=route,
        output_route=route,
        policies=compiled,
        prefix_lists=prefix_lists,
        errors=errors,
    )
    inner = p.CallExpr("INNER").evaluate(env)
    assert inner.exit is False and inner.boolean_value is False


# --- RPL -------------------------------------------------------------------


def test_rpl_done_accepts_and_drop_rejects():
    policies = [
        _prefix_list("PS_TEN", "10.0.0.0/8"),
        {
            "name": "RP",
            "kind": "rpl",
            "entries": [
                _statement(1, match_prefix_lists=["PS_TEN"], action="deny"),
                _statement(2, action="permit"),
            ],
        },
    ]
    assert _run(policies, "RP", "10.0.0.0/8", platform=platforms.IOSXR)[0] is False
    assert _run(policies, "RP", "192.168.0.0/16", platform=platforms.IOSXR)[0] is True


def test_rpl_pass_defers_to_the_end_of_policy_terminator():
    """A `set` clause has an implicit `pass`, which only takes effect through the
    synthetic terminator."""
    policies = [
        {"name": "RP", "kind": "rpl", "entries": [_statement(1, set_local_pref=200)]},
    ]
    accepted, env = _run(policies, "RP", "10.0.0.0/8", platform=platforms.IOSXR)
    assert accepted is True, "the implicit pass set the default action, the terminator read it"
    assert env.output_route.local_pref == 200


def test_an_rpl_policy_with_no_disposition_denies():
    """Nothing sets the default action, so the terminator's `DefaultAction`
    exits false."""
    policies = [{"name": "RP", "kind": "rpl", "entries": [_statement(1, match_tags=[7])]}]
    assert _run(policies, "RP", "10.0.0.0/8", platform=platforms.IOSXR)[0] is False


def test_rpl_drop_inside_a_boolean_apply_only_ends_the_subroutine():
    """Inside a `CallExpr`, `drop` is `ReturnFalse`, which stops the subroutine but
    does not unwind the caller."""
    policies = [
        {"name": "SUB", "kind": "rpl", "entries": [_statement(1, action="deny")]},
    ]
    errors = ErrorSink()
    compiled, prefix_lists = compile_policies(policies, platforms.IOSXR, errors)
    route = Route(prefix="10.0.0.0/8")
    env = p.Environment(
        original_route=route,
        output_route=route,
        policies=compiled,
        prefix_lists=prefix_lists,
        errors=errors,
    )
    result = p.CallExpr("SUB").evaluate(env)
    assert result.exit is False and result.boolean_value is False


def test_rpl_apply_in_statement_position_leaks_the_callees_pass():
    """`apply` is a `CallStatement`, which does not restore `defaultAction`, so a
    callee's `pass` decides the caller's end."""
    policies = [
        {"name": "SUB", "kind": "rpl", "entries": [_statement(1, set_metric=5)]},
        {"name": "RP", "kind": "rpl", "entries": [_statement(1, calls_policy="SUB")]},
    ]
    accepted, env = _run(policies, "RP", "10.0.0.0/8", platform=platforms.IOSXR)
    assert accepted is True
    assert env.output_route.med == 5


# --- undefined references --------------------------------------------------


def test_iosxe_undefined_prefix_list_in_a_match_is_restrictive():
    """An IOS-XE `match ip prefix-list` with an undefined name is false."""
    policies = [
        {
            "name": "RM",
            "kind": "route-map",
            "entries": [_clause(10, "permit", match_prefix_lists=["ABSENT"])],
        }
    ]
    errors = ErrorSink()
    accepted, _ = _run(policies, "RM", "10.0.0.0/8", errors=errors)
    assert accepted is False
    assert "undefined-prefix-list" in {e.kind for e in errors.errors}


def test_nxos_undefined_prefix_list_in_a_match_matches_everything():
    """An NX-OS `match ip address prefix-list` with an undefined name matches
    everything."""
    policies = [
        {
            "name": "RM",
            "kind": "route-map",
            "entries": [_clause(10, "permit", match_prefix_lists=["ABSENT"])],
        }
    ]
    errors = ErrorSink()
    accepted, _ = _run(policies, "RM", "10.0.0.0/8", platform=platforms.NXOS, errors=errors)
    assert accepted is True
    assert "undefined-prefix-list" in {e.kind for e in errors.errors}


def test_one_resolvable_name_beside_an_undefined_one_still_decides_the_match():
    policies = [
        _prefix_list("PL_TEN", "10.0.0.0/8"),
        {
            "name": "RM",
            "kind": "route-map",
            "entries": [_clause(10, "permit", match_prefix_lists=["ABSENT", "PL_TEN"])],
        },
    ]
    errors = ErrorSink()
    assert _run(policies, "RM", "10.0.0.0/8", errors=errors)[0] is True
    assert _run(policies, "RM", "192.168.0.0/16")[0] is False


@pytest.mark.parametrize(
    ("key", "kind"),
    [
        ("match_community_lists", "undefined-community-list"),
        ("match_as_path_lists", "undefined-as-path-list"),
    ],
)
def test_community_and_as_path_list_matches_drop_out_of_the_disjunction(key, kind):
    """Undefined names drop out of the disjunction, which leaves it empty and
    false."""
    policies = [{"name": "RM", "kind": "route-map", "entries": [_clause(10, "permit", **{key: ["CL1"]})]}]
    errors = ErrorSink()
    accepted, _ = _run(policies, "RM", "10.0.0.0/8", errors=errors)
    assert accepted is False
    assert kind in {e.kind for e in errors.errors}


@pytest.mark.parametrize("platform", [platforms.IOSXE, platforms.NXOS])
def test_a_route_map_clause_with_an_unmodeled_match_is_not_unconditional(platform):
    """A `match ip address <acl>` deny clause kept in `match_unsupported` is
    not a clause with no match: it evaluates false and is reported under the
    policy's name, so the permit after it still decides."""
    policies = [
        {
            "name": "RM",
            "kind": "route-map",
            "entries": [
                _clause(10, "deny", match_unsupported=["match ip address 10"]),
                _clause(20, "permit"),
            ],
        }
    ]
    errors = ErrorSink()
    accepted, _ = _run(policies, "RM", "10.0.0.0/8", platform=platform, errors=errors)
    assert accepted is True
    assert [(e.kind, e.subject) for e in errors.errors] == [("unsupported-match", "RM")]


def test_an_rpl_statement_with_an_unmodeled_guard_is_not_unconditional():
    """`if not destination in BOGONS then drop`: the guard is kept whole in
    `match_unsupported`, so the drop is guarded, not applied to every route."""
    policies = [
        {
            "name": "RP",
            "kind": "rpl",
            "entries": [
                _statement(1, action="deny", match_unsupported=["not destination in BOGONS"]),
                _statement(2, action="permit"),
            ],
        }
    ]
    errors = ErrorSink()
    accepted, _ = _run(policies, "RP", "10.0.0.0/8", platform=platforms.IOSXR, errors=errors)
    assert accepted is True
    assert [(e.kind, e.subject) for e in errors.errors] == [("unsupported-match", "RP")]


def test_an_rpl_pass_branch_with_an_unmodeled_guard_is_reported():
    """`if not destination in BOGONS then pass else drop endif`: the `pass`
    branch compiles to nothing and the `else` drop runs unguarded."""
    policies = [
        {
            "name": "RP",
            "kind": "rpl",
            "entries": [
                _statement(
                    1, match_unsupported=["not destination in BOGONS"], continues=True, continue_seq=2
                ),
                _statement(2, action="deny"),
            ],
        }
    ]
    errors = ErrorSink()
    _run(policies, "RP", "8.8.8.0/24", platform=platforms.IOSXR, errors=errors)
    assert [(e.kind, e.subject) for e in errors.errors] == [("unsupported-match", "RP")]


def test_set_comm_list_delete_is_a_reported_no_op():
    """`set comm-list ... delete` with an undefined list is a no-op."""
    policies = [
        {
            "name": "RM",
            "kind": "route-map",
            "entries": [_clause(10, "permit", set_comm_list_delete="CL1")],
        }
    ]
    errors = ErrorSink()
    accepted, env = _run(policies, "RM", "10.0.0.0/8", errors=errors)
    assert accepted is True
    assert env.output_route.communities == frozenset()
    assert "undefined-community-list" in {e.kind for e in errors.errors}


def test_a_call_to_a_missing_policy_is_reported_and_evaluates_false():
    policies = [{"name": "RP", "kind": "rpl", "entries": [_statement(1, calls_policy="ABSENT")]}]
    errors = ErrorSink()
    accepted, _ = _run(policies, "RP", "10.0.0.0/8", platform=platforms.IOSXR, errors=errors)
    assert accepted is False
    assert "undefined-policy-call" in {e.kind for e in errors.errors}


# --- set clauses -----------------------------------------------------------


def test_set_community_replaces_unless_additive():
    policies = [
        {
            "name": "RM",
            "kind": "route-map",
            "entries": [_clause(10, "permit", set_communities=["65000:1"])],
        }
    ]
    compiled, prefix_lists = compile_policies(policies, platforms.IOSXE, ErrorSink())
    route = Route(prefix="10.0.0.0/8", communities=frozenset({"65000:9"}))
    env = p.Environment(
        original_route=route,
        output_route=route,
        policies=compiled,
        prefix_lists=prefix_lists,
        errors=ErrorSink(),
    )
    assert p.process(compiled["RM"], env) is True
    assert env.output_route.communities == frozenset({"65000:1"})

    policies[0]["entries"][0]["set_communities_additive"] = True
    compiled, prefix_lists = compile_policies(policies, platforms.IOSXE, ErrorSink())
    env = p.Environment(
        original_route=route,
        output_route=route,
        policies=compiled,
        prefix_lists=prefix_lists,
        errors=ErrorSink(),
    )
    assert p.process(compiled["RM"], env) is True
    assert env.output_route.communities == frozenset({"65000:1", "65000:9"})


def test_as_path_prepend_runs_last_in_the_no_continue_path():
    """Without any `continue` in the map, the conversion moves
    `set as-path prepend` to the end of the clause."""
    policies = [
        {
            "name": "RM",
            "kind": "route-map",
            "entries": [_clause(10, "permit", set_as_path_prepend=[65001], set_local_pref=150)],
        }
    ]
    accepted, env = _run(policies, "RM", "10.0.0.0/8")
    assert accepted is True
    assert env.output_route.as_path == (65001,)
    assert env.output_route.local_pref == 150


# --- if/else chains, guard expressions, collected lists --------------------


def _route_run(policies, name, route, platform=platforms.IOSXE, errors=None):
    """`_run` for a whole route, not only a prefix."""
    errors = errors if errors is not None else ErrorSink()
    compiled, prefix_lists = compile_policies(policies, platform, errors)
    env = p.Environment(
        original_route=route,
        output_route=route,
        policies=compiled,
        prefix_lists=prefix_lists,
        errors=errors,
    )
    return p.process(compiled[name], env), env


def _expr(node):
    return json.dumps(node)


_BOGONS = {
    "name": "BOGONS",
    "kind": "prefix-list",
    "entries": [
        {"seq": 1, "action": "permit", "prefix": "10.0.0.0/8", "min_len": 8, "max_len": 32},
        {"seq": 2, "action": "permit", "prefix": "192.168.0.0/16", "min_len": 16, "max_len": 32},
    ],
}


def _match_list(name, kind, *lines):
    return {
        "name": name,
        "kind": kind,
        "entries": [
            {"seq": seq, "action": action, "match_type": match_type, "value": value}
            for seq, (action, match_type, value) in enumerate(lines, start=1)
        ],
    }


def test_an_rpl_else_branch_runs_only_when_the_guard_fails():
    """`if not destination in BOGONS then pass else drop endif`: the `else`
    drop runs only for a bogon, so every other route is accepted through the
    `pass`, and nothing is reported."""
    policies = [
        _BOGONS,
        {
            "name": "RP",
            "kind": "rpl",
            "entries": [
                _statement(
                    1,
                    passes=True,
                    match_expr=_expr({"not": {"prefix_list": "BOGONS"}}),
                    match_prefix_lists=["BOGONS"],
                    continues=True,
                    continue_seq=2,
                ),
                _statement(2, action="deny"),
            ],
        },
    ]
    errors = ErrorSink()
    assert _run(policies, "RP", "8.8.8.0/24", platform=platforms.IOSXR, errors=errors)[0] is True
    assert _run(policies, "RP", "10.1.0.0/16", platform=platforms.IOSXR, errors=errors)[0] is False
    assert errors.errors == []


def test_an_rpl_elseif_chain_runs_the_first_branch_whose_guard_holds():
    """`if A then set lp 150 elseif B then set lp 200 else drop endif`: a route
    in both A and B takes A's branch only, and a route in A is not dropped by
    the `else`."""
    policies = [
        _prefix_list("A", "10.0.0.0/8", min_len=8, max_len=32),
        _prefix_list("B", "10.0.0.0/8", min_len=8, max_len=32),
        {
            "name": "RP",
            "kind": "rpl",
            "entries": [
                _statement(1, match_prefix_lists=["A"], set_local_pref=150, continues=True, continue_seq=2),
                _statement(2, match_prefix_lists=["B"], set_local_pref=200, continues=True, continue_seq=3),
                _statement(3, action="deny"),
            ],
        },
    ]
    accepted, env = _run(policies, "RP", "10.1.0.0/16", platform=platforms.IOSXR)
    assert accepted is True
    assert env.output_route.local_pref == 150
    assert _run(policies, "RP", "8.8.8.0/24", platform=platforms.IOSXR)[0] is False


def test_a_nested_rpl_if_runs_inside_its_branch_only():
    """Entries with `parent_seq` compile into their branch: the nested `if`
    and the `done` after it run only when the outer guard holds."""
    policies = [
        _prefix_list("A", "10.0.0.0/8", min_len=8, max_len=32),
        {
            "name": "RP",
            "kind": "rpl",
            "entries": [
                _statement(1, match_prefix_lists=["A"], continues=True, continue_seq=4),
                _statement(2, parent_seq=1, match_tags=[7], set_weight=9),
                _statement(3, parent_seq=1, action="permit"),
                _statement(4, action="deny"),
            ],
        },
    ]
    accepted, env = _route_run(policies, "RP", Route(prefix="10.1.0.0/16", tag=7), platform=platforms.IOSXR)
    assert accepted is True and env.output_route.weight == 9
    accepted, env = _route_run(policies, "RP", Route(prefix="10.1.0.0/16", tag=8), platform=platforms.IOSXR)
    assert accepted is True and env.output_route.weight == 0
    assert _run(policies, "RP", "8.8.8.0/24", platform=platforms.IOSXR)[0] is False


def test_rpl_guard_expressions_combine_or_and_not_and_comparisons():
    """`(destination in A or med ge 50) and not as-path length le 1`."""
    node = {
        "and": [
            {"or": [{"prefix_list": "A"}, {"compare": "med", "op": "ge", "value": 50}]},
            {"not": {"compare": "as_path_length", "op": "le", "value": 1}},
        ]
    }
    policies = [
        _prefix_list("A", "10.0.0.0/8", min_len=8, max_len=32),
        {
            "name": "RP",
            "kind": "rpl",
            "entries": [_statement(1, match_expr=_expr(node), match_prefix_lists=["A"], action="permit")],
        },
    ]

    def accepted(**route):
        return _route_run(policies, "RP", Route(**route), platform=platforms.IOSXR)[0]

    assert accepted(prefix="10.1.0.0/16", as_path=(1, 2)) is True
    assert accepted(prefix="8.8.8.0/24", med=60, as_path=(1, 2)) is True
    assert accepted(prefix="8.8.8.0/24", med=10, as_path=(1, 2)) is False
    assert accepted(prefix="10.1.0.0/16", as_path=(1,)) is False


def test_an_rpl_inline_prefix_set_matches_orlonger_by_default():
    """An inline `destination in (...)` element with no length qualifier matches
    orlonger."""
    node = {"prefixes": ["10.0.0.0/8", "172.16.0.0/12 eq 24"]}
    policies = [
        {"name": "RP", "kind": "rpl", "entries": [_statement(1, match_expr=_expr(node), action="permit")]}
    ]
    assert _run(policies, "RP", "10.1.2.0/24", platform=platforms.IOSXR)[0] is True
    assert _run(policies, "RP", "172.16.5.0/24", platform=platforms.IOSXR)[0] is True
    assert _run(policies, "RP", "172.16.0.0/16", platform=platforms.IOSXR)[0] is False


def test_an_rpl_guard_with_an_unreadable_atom_evaluates_false_and_is_reported():
    """Under a `not`, an unreadable atom read as false turns true."""
    node = {"not": {"unsupported": "rib-has-route in (10.0.0.0/8)"}}
    policies = [
        {
            "name": "RP",
            "kind": "rpl",
            "entries": [_statement(1, match_expr=_expr(node), action="permit")],
        }
    ]
    errors = ErrorSink()
    assert _run(policies, "RP", "8.8.8.0/24", platform=platforms.IOSXR, errors=errors)[0] is False
    assert [(e.kind, e.subject) for e in errors.errors] == [("unsupported-match", "RP")]


def test_rpl_community_matches_every_needs_each_element():
    policies = [
        _match_list(
            "CS", "community-list", ("permit", "standard", "65000:1"), ("permit", "wildcard", "65001:*")
        ),
        {
            "name": "RP",
            "kind": "rpl",
            "entries": [
                _statement(
                    1,
                    match_expr=_expr({"community_list": "CS", "every": True}),
                    match_community_lists=["CS"],
                    action="permit",
                )
            ],
        },
    ]

    def accepted(*communities):
        route = Route(prefix="8.8.8.0/24", communities=frozenset(communities))
        return _route_run(policies, "RP", route, platform=platforms.IOSXR)[0]

    assert accepted("65000:1", "65001:42") is True
    assert accepted("65000:1") is False


def test_the_finding_route_map_evaluates_its_community_and_as_path_lists():
    """`deny 10 match ip address 10` is unsupported and
    evaluates false (reported); `deny 20 match as-path 5` denies a route from
    AS 64512 through the collected AS-path list; `permit 30 match community 7`
    sets local preference 50 through the collected community list; `permit 40`
    accepts the rest."""
    policies = [
        _match_list("5", "as-path-list", ("permit", "expanded", "_64512_")),
        _match_list("7", "community-list", ("permit", "standard", "65000:7")),
        {
            "name": "FROM-ISP",
            "kind": "route-map",
            "entries": [
                _clause(10, "deny", match_unsupported=["match ip address 10"]),
                _clause(20, "deny", match_as_path_lists=["5"]),
                _clause(30, "permit", match_community_lists=["7"], set_local_pref=50),
                _clause(40, "permit"),
            ],
        },
    ]
    errors = ErrorSink()
    accepted, _ = _route_run(
        policies, "FROM-ISP", Route(prefix="8.8.8.0/24", as_path=(3356, 64512)), errors=errors
    )
    assert accepted is False
    accepted, env = _route_run(
        policies, "FROM-ISP", Route(prefix="8.8.8.0/24", as_path=(3356,), communities=frozenset({"65000:7"}))
    )
    assert accepted is True and env.output_route.local_pref == 50
    accepted, env = _route_run(policies, "FROM-ISP", Route(prefix="8.8.8.0/24", as_path=(3356,)))
    assert accepted is True and env.output_route.local_pref == 100
    assert [(e.kind, e.subject) for e in errors.errors] == [("unsupported-match", "FROM-ISP")]


def test_set_comm_list_delete_removes_what_the_collected_list_permits():
    policies = [
        _match_list(
            "DEL", "community-list", ("deny", "standard", "65000:2"), ("permit", "expanded", "^65000:")
        ),
        {"name": "RM", "kind": "route-map", "entries": [_clause(10, "permit", set_comm_list_delete="DEL")]},
    ]
    errors = ErrorSink()
    route = Route(prefix="8.8.8.0/24", communities=frozenset({"65000:1", "65000:2", "65001:1"}))
    accepted, env = _route_run(policies, "RM", route, errors=errors)
    assert accepted is True
    assert env.output_route.communities == frozenset({"65000:2", "65001:1"})
    assert errors.errors == []


def test_a_list_line_the_engine_cannot_read_never_matches_and_is_reported():
    policies = [
        _match_list("CL", "community-list", ("permit", "unsupported", "dfa-regex '65000:.*'")),
        {"name": "RM", "kind": "route-map", "entries": [_clause(10, "permit", match_community_lists=["CL"])]},
    ]
    errors = ErrorSink()
    route = Route(prefix="8.8.8.0/24", communities=frozenset({"65000:1"}))
    assert _route_run(policies, "RM", route, errors=errors)[0] is False
    assert [(e.kind, e.subject) for e in errors.errors] == [("unsupported-list-entry", "CL")]


@pytest.mark.parametrize("platform", [platforms.IOSXE, platforms.NXOS, platforms.IOSXR])
def test_an_unsupported_set_line_is_reported_under_the_policy(platform):
    entry = {"set_unsupported": ["set community none"], "set_local_pref": 200}
    if platform == platforms.IOSXR:
        policies = [{"name": "RP", "kind": "rpl", "entries": [_statement(1, action="permit", **entry)]}]
    else:
        policies = [{"name": "RP", "kind": "route-map", "entries": [_clause(10, "permit", **entry)]}]
    errors = ErrorSink()
    accepted, env = _run(policies, "RP", "8.8.8.0/24", platform=platform, errors=errors)
    assert accepted is True and env.output_route.local_pref == 200
    assert [(e.kind, e.subject) for e in errors.errors] == [("unsupported-set", "RP")]


def test_a_last_as_prepend_stored_as_a_list_is_reported_not_raised():
    """An NX-OS `set as-path prepend last-as 2` stored as ["last-as", "2"] is
    reported as `unsupported-set`."""
    policies = [
        {
            "name": "RM",
            "kind": "route-map",
            "entries": [_clause(10, "permit", set_as_path_prepend=["last-as", "2"])],
        }
    ]
    errors = ErrorSink()
    accepted, env = _run(policies, "RM", "8.8.8.0/24", platform=platforms.NXOS, errors=errors)
    assert accepted is True and env.output_route.as_path == ()
    assert [e.kind for e in errors.errors] == ["unsupported-set"]


def test_a_multi_asn_prepend_string_is_split_into_its_numbers():
    """VyOS stores `set as-path prepend 65001 65001` as one string; asdot parses too."""
    policies = [
        {
            "name": "RM",
            "kind": "route-map",
            "entries": [_clause(10, "permit", set_as_path_prepend=["65001 65001", "1.10"])],
        }
    ]
    errors = ErrorSink()
    accepted, env = _run(policies, "RM", "8.8.8.0/24", platform=platforms.IOSXE, errors=errors)
    assert accepted is True and env.output_route.as_path == (65001, 65001, 65546)
    assert errors.errors == []


@pytest.mark.parametrize("platform", [platforms.IOSXE, platforms.NXOS])
def test_one_policy_that_fails_to_compile_denies_and_leaves_the_others_intact(platform):
    """A value the compiler cannot read in one policy is reported, and that policy denies;
    the other policies in the scope still compile."""
    policies = [
        {"name": "BAD", "kind": "route-map", "entries": [_clause(10, "permit", set_local_pref="high")]},
        {"name": "GOOD", "kind": "route-map", "entries": [_clause(10, "permit", set_local_pref=200)]},
    ]
    errors = ErrorSink()
    accepted, _ = _run(policies, "BAD", "8.8.8.0/24", platform=platform, errors=errors)
    assert accepted is False
    assert [(e.kind, e.subject) for e in errors.errors] == [("unsupported-policy", "BAD")]
    accepted, env = _run(policies, "GOOD", "8.8.8.0/24", platform=platform, errors=ErrorSink())
    assert accepted is True and env.output_route.local_pref == 200


def test_an_nxos_pbr_only_match_adds_no_condition_and_is_a_diagnostic():
    """`match ip address <acl>` is ignored by route filtering, so the deny clause
    applies to every route."""
    policies = [
        {
            "name": "RM",
            "kind": "route-map",
            "entries": [
                _clause(10, "deny", match_ignored=["match ip address ACL-10"]),
                _clause(20, "permit"),
            ],
        }
    ]
    errors = ErrorSink()
    assert _run(policies, "RM", "8.8.8.0/24", platform=platforms.NXOS, errors=errors)[0] is False
    assert [(e.kind, e.subject) for e in errors.errors] == [("pbr-only-match", "RM")]
