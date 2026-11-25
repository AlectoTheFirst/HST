"""Prefix-list matching: `le`, `ge`, `eq`, first match wins, implicit deny.

The length-range defaults are the same for IOS-XE, NX-OS and IOS-XR. `eq` is
applied last and overrides `ge`/`le`.
"""

from hst.simul.prefixlist import evaluate, resolve_length_range


def _entry(seq, action, prefix, **kwargs):
    lo, hi = resolve_length_range(prefix, kwargs.get("ge"), kwargs.get("le"), kwargs.get("eq"))
    return {"seq": seq, "action": action, "prefix": prefix, "min_len": lo, "max_len": hi}


def test_no_qualifier_matches_the_exact_length_only():
    entries = [_entry(5, "permit", "10.0.0.0/24")]
    assert evaluate(entries, "10.0.0.0/24") is True
    assert evaluate(entries, "10.0.0.0/25") is False


def test_ge_alone_runs_to_the_maximum_length():
    assert resolve_length_range("10.0.0.0/8", 16, None, None) == (16, 32)
    entries = [_entry(5, "permit", "10.0.0.0/8", ge=16)]
    assert evaluate(entries, "10.1.0.0/16") is True
    assert evaluate(entries, "10.1.2.0/24") is True
    assert evaluate(entries, "10.0.0.0/8") is False


def test_le_alone_starts_at_the_configured_prefix_length():
    assert resolve_length_range("10.0.0.0/8", None, 24, None) == (8, 24)
    entries = [_entry(5, "permit", "10.0.0.0/8", le=24)]
    assert evaluate(entries, "10.0.0.0/8") is True
    assert evaluate(entries, "10.1.2.0/24") is True
    assert evaluate(entries, "10.1.2.0/25") is False


def test_ge_and_le_bound_both_ends():
    assert resolve_length_range("10.0.0.0/8", 16, 24, None) == (16, 24)


def test_eq_is_applied_last_and_overrides_ge_and_le():
    assert resolve_length_range("10.0.0.0/8", 16, 24, 20) == (20, 20)
    entries = [_entry(5, "permit", "10.0.0.0/8", ge=16, le=24, eq=20)]
    assert evaluate(entries, "10.1.0.0/20") is True
    assert evaluate(entries, "10.1.0.0/24") is False


def test_first_match_wins_in_ascending_sequence_order():
    entries = [
        _entry(10, "permit", "10.0.0.0/8", le=32),
        _entry(5, "deny", "10.1.0.0/16", le=32),
    ]
    assert evaluate(entries, "10.1.2.0/24") is False, "seq 5 is evaluated first"
    assert evaluate(entries, "10.2.2.0/24") is True


def test_a_prefix_matched_by_no_line_is_denied():
    entries = [_entry(5, "permit", "10.0.0.0/8", le=32)]
    assert evaluate(entries, "192.168.0.0/24") is False


def test_an_empty_list_denies():
    assert evaluate([], "10.0.0.0/24") is False


def test_a_line_matches_on_address_containment_not_subnet_equality():
    """A /8 line with `le 24` matches a /24 inside it: the test is that the
    candidate's network address falls in the line's block."""
    entries = [_entry(5, "permit", "10.0.0.0/8", le=24)]
    assert evaluate(entries, "10.255.255.0/24") is True
    assert evaluate(entries, "11.0.0.0/24") is False


def test_the_stored_resolved_range_is_used_when_present():
    """The engine reads `min_len`/`max_len`, not the raw vendor qualifiers:
    which default produced them is the collector's decision."""
    entries = [{"seq": 5, "action": "permit", "prefix": "10.0.0.0/8", "min_len": 8, "max_len": 32}]
    assert evaluate(entries, "10.4.5.0/24") is True
