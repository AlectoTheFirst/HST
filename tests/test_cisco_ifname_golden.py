"""The golden overlay of the interface name change.

The IOS-XE and IOS-XR parse keeps the interface names of its neighbor and FHRP
rows as the device printed them (`Gi1/0/1`, `Vl10`, `Fi1/0/1`, `BE10`), and the
graph stage resolves each against the device's own interface table
(`normalize.IfNameResolver`). `tests/support/ifname_golden.json` holds the `inter`
digest of every case whose payload holds such a row.

It is recorded over the ACL and port-description overlays
(`synthetic_payloads.load_golden`): each digest is that of the whole parse."""

from __future__ import annotations

import importlib
import json
from typing import Any

import pytest
from tests.support.synthetic_payloads import (
    CASES,
    IFNAME_GOLDEN_PATH,
    canonical_neighbor_names,
    case_payload,
    inter_digest,
    load_golden,
    route_session_change_taken_out,
    split_case,
)

_TEXT_FAMILIES = ("iosxe", "iosxr")


def _overlay() -> dict[str, Any]:
    document: dict[str, Any] = json.loads(IFNAME_GOLDEN_PATH.read_text(encoding="utf-8"))
    return document


def _overlay_cases() -> dict[str, Any]:
    cases: dict[str, Any] = _overlay()["cases"]
    return cases


def _parse(key: str) -> dict[str, Any]:
    # The route-session overlay (tests/test_route_session_golden.py) is recorded
    # over this one, so this one holds the parse with that change taken out.
    with route_session_change_taken_out():
        inter: dict[str, Any] = importlib.import_module(f"hst.collectors.{split_case(key)[0]}").parse(
            case_payload(key)
        )
    return inter


def test_the_respelling_changes_only_neighbor_and_fhrp_names() -> None:
    inter = {
        "interfaces": [{"name": "Vlan10"}],
        "neighbors": [
            {"local_port": "Gi1/0/1", "name": "core1", "mac": None, "port": "Te1/0/2", "proto": "cdp"}
        ],
        "fhrp": [{"interface": "Vl10", "kind": "hsrp", "group": 10, "vip": "10.10.10.254"}],
    }
    spelled = canonical_neighbor_names("iosxe", inter)
    assert spelled["neighbors"] == [
        {
            "local_port": "GigabitEthernet1/0/1",
            "name": "core1",
            "mac": None,
            "port": "TenGigabitEthernet1/0/2",
            "proto": "cdp",
        }
    ]
    assert spelled["fhrp"] == [{"interface": "VLAN10", "kind": "hsrp", "group": 10, "vip": "10.10.10.254"}]
    assert spelled["interfaces"] == inter["interfaces"]
    assert inter["neighbors"][0]["local_port"] == "Gi1/0/1"
    assert canonical_neighbor_names("nxos", inter) == inter
    assert canonical_neighbor_names("iosxr", {"interfaces": []}) == {"interfaces": []}


def test_the_overlay_records_the_inter_field() -> None:
    overlay = _overlay()
    assert overlay["fields"] == ["inter"]
    assert all(set(fields) == {"inter"} for fields in _overlay_cases().values())


def test_the_overlay_names_exactly_the_cases_whose_parse_holds_a_name_netutils_spells() -> None:
    touched = {
        key
        for key in CASES
        if split_case(key)[0] in _TEXT_FAMILIES
        and canonical_neighbor_names(split_case(key)[0], inter := _parse(key)) != inter
    }
    assert set(_overlay_cases()) == touched
    assert {split_case(key)[0] for key in _overlay_cases()} == {"iosxe"}


def test_the_name_overlay_cannot_be_left_in_under_another_one_left_out() -> None:
    for kwargs in ({"acl": False}, {"port_description": False}, {"acl": False, "port_description": False}):
        with pytest.raises(ValueError):
            load_golden(**kwargs)


@pytest.mark.parametrize("key", sorted(_overlay_cases()))
def test_an_overlay_digest_is_the_one_without_it_once_the_names_are_spelled(key: str) -> None:
    family = split_case(key)[0]
    inter = _parse(key)
    assert inter_digest(inter) == _overlay_cases()[key]["inter"]
    spelled = canonical_neighbor_names(family, inter)
    before = load_golden(acl=True, port_description=True, ifname=False)["cases"][key]["inter"]
    assert inter_digest(spelled) == before
    assert before != _overlay_cases()[key]["inter"]
    # the stack up to the overlay recorded over this one (`_parse`)
    assert load_golden(route_session=False)["cases"][key]["inter"] == _overlay_cases()[key]["inter"]
