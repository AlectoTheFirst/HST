"""`rpl_pass_golden.json`: the IOS-XR parse records a route-policy `pass` as
the entry's `passes`."""

import json

import pytest
from tests.support.synthetic_payloads import (
    CASES,
    RPL_PASS_GOLDEN_PATH,
    case_payload,
    inter_digest,
    load_golden,
    route_session_change_taken_out,
    split_case,
    without_rpl_passes,
)

from hst.collectors import iosxr


def _overlay_cases():
    return json.loads(RPL_PASS_GOLDEN_PATH.read_text(encoding="utf-8"))["cases"]


def _passes(inter):
    return any(e.get("passes") for p in inter.get("xr_route_policies") or () for e in p["entries"])


def test_the_overlay_names_exactly_the_iosxr_cases_with_a_pass():
    with_pass = {
        key for key in CASES if split_case(key)[0] == "iosxr" and _passes(iosxr.parse(case_payload(key)))
    }
    assert set(_overlay_cases()) == with_pass
    assert all(set(fields) == {"inter"} for fields in _overlay_cases().values())


@pytest.mark.parametrize("key", sorted(_overlay_cases()))
def test_an_overlay_digest_is_the_one_without_it_once_passes_are_taken_out(key):
    # the route-session overlay (tests/test_route_session_golden.py) is
    # recorded over this one, so the parse runs with that change taken out
    with route_session_change_taken_out():
        inter = iosxr.parse(case_payload(key))
    assert inter_digest(inter) == _overlay_cases()[key]["inter"]
    assert inter_digest(without_rpl_passes(inter)) == load_golden(rpl_pass=False)["cases"][key]["inter"]
