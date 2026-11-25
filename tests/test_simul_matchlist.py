"""Community-list and AS-path-list evaluation (`simul/matchlist.py`): first
match wins, implicit deny, and the line forms the four collectors store."""

import pytest

from hst.simul import matchlist


def _line(seq, action, match_type, value):
    return {"seq": seq, "action": action, "match_type": match_type, "value": value}


def test_a_standard_line_needs_every_community_it_names():
    lines = [_line(1, "permit", "standard", "65000:1 65000:2")]
    assert matchlist.community_list_permits(lines, {"65000:1", "65000:2", "65001:1"}) is True
    assert matchlist.community_list_permits(lines, {"65000:1"}) is False


def test_first_match_wins_and_no_match_denies():
    lines = [_line(10, "deny", "standard", "65000:1"), _line(20, "permit", "standard", "internet")]
    assert matchlist.community_list_permits(lines, {"65000:1"}) is False
    assert matchlist.community_list_permits(lines, {"65000:9"}) is True
    assert matchlist.community_list_permits([_line(1, "permit", "standard", "65000:1")], set()) is False


def test_well_known_names_match_their_numbers():
    lines = [_line(1, "permit", "standard", "no-export")]
    assert matchlist.community_list_permits(lines, {"65535:65281"}) is True
    assert matchlist.community_list_permits(lines, {"no-export"}) is True


def test_an_expanded_line_matches_the_communities_as_one_string():
    lines = [_line(1, "permit", "expanded", "^65000:1 65000:2$")]
    assert matchlist.community_list_permits(lines, {"65000:2", "65000:1"}) is True
    assert matchlist.community_list_permits(lines, {"65000:1"}) is False


@pytest.mark.parametrize(
    ("pattern", "community", "expected"),
    [
        ("65000:*", "65000:7", True),
        ("*:100", "65001:100", True),
        ("[100..200]:5", "150:5", True),
        ("[100..200]:5", "250:5", False),
        ("65000:*", "65001:7", False),
    ],
)
def test_an_iosxr_wildcard_element(pattern, community, expected):
    lines = [_line(1, "permit", "wildcard", pattern)]
    assert matchlist.community_list_permits(lines, {community}) is expected


def test_the_cisco_underscore_matches_a_delimiter_or_either_end():
    lines = [_line(1, "permit", "expanded", "_64512_")]
    assert matchlist.as_path_list_permits(lines, (64512,)) is True
    assert matchlist.as_path_list_permits(lines, (3356, 64512, 1)) is True
    assert matchlist.as_path_list_permits(lines, (645120,)) is False


@pytest.mark.parametrize(
    ("match_type", "value", "path", "expected"),
    [
        ("neighbor-is", "3356 174", (3356, 174, 1), True),
        ("neighbor-is", "174", (3356, 174), False),
        ("originates-from", "64512", (3356, 64512), True),
        ("passes-through", "174 1", (3356, 174, 1, 2), True),
        ("passes-through", "1 174", (3356, 174, 1), False),
        ("length", "le 2", (1, 2), True),
        ("length", "ge 3", (1, 2), False),
    ],
)
def test_iosxr_as_path_set_elements(match_type, value, path, expected):
    lines = [_line(1, "permit", match_type, value)]
    assert matchlist.as_path_list_permits(lines, path) is expected


def test_matches_every_needs_each_element_of_the_set():
    lines = [_line(1, "permit", "standard", "65000:1"), _line(2, "permit", "wildcard", "65001:*")]
    assert matchlist.community_set_matches_every(lines, {"65000:1", "65001:3"}) is True
    assert matchlist.community_set_matches_every(lines, {"65000:1"}) is False


def test_delete_removes_each_community_a_permit_line_matches():
    lines = [_line(1, "deny", "standard", "65000:2"), _line(2, "permit", "expanded", "^65000:")]
    kept = matchlist.delete_matching(lines, {"65000:1", "65000:2", "65001:1"})
    assert kept == frozenset({"65000:2", "65001:1"})


@pytest.mark.parametrize(
    ("kind", "match_type", "value", "supported"),
    [
        ("community-list", "standard", "65000:1", True),
        ("community-list", "standard", "", False),
        ("community-list", "expanded", "65000:(", False),
        ("community-list", "wildcard", "65000:*", True),
        ("community-list", "unsupported", "dfa-regex '1'", False),
        ("as-path-list", "neighbor-is", "65000 [1..2]", False),
        ("as-path-list", "length", "le 3", True),
        ("as-path-list", "standard", "65000", False),
    ],
)
def test_line_supported(kind, match_type, value, supported):
    assert matchlist.line_supported(_line(1, "permit", match_type, value), kind) is supported


def test_an_unsupported_line_never_matches():
    lines = [_line(1, "permit", "unsupported", "dfa-regex '65000:.*'")]
    assert matchlist.community_list_permits(lines, {"65000:1"}) is False


def test_a_frozen_line_reads_like_its_entry():
    line = matchlist.Line.of(_line(3, "PERMIT", "Standard", "65000:1"))
    assert (line.seq, line.action, line.match_type, line.get("value")) == (3, "permit", "standard", "65000:1")
    assert matchlist.community_list_permits([line], {"65000:1"}) is True
