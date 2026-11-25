"""The golden overlay of the interface ACL parse change.

The IOS-XE and NX-OS parse writes, beside each opaque reason of an ACE, the
short note the firewall table lists, and keeps the ICMP type an ACE names
(`synthetic_payloads.ACL_ACE_FIELDS`). That changes the `inter` digest of every
case whose payload holds such an ACE, and nothing else of the case.
`tests/support/acl_golden.json` replaces those digests. The tests below hold
the overlay to the cases and the one field the change touches, and each digest
to the one without the overlay once those ACE fields are taken out.

The port-description overlay is recorded over this one (`load_golden`). For a
case in both, the digest here is that of the parse with the interface
descriptions taken out, and the port-description digest is that of the whole
parse. The last tests hold that composition."""

from __future__ import annotations

import importlib
import json
from typing import Any

import pytest
from tests.support.synthetic_payloads import (
    ACL_GOLDEN_PATH,
    CASES,
    PORT_DESCRIPTION_GOLDEN_PATH,
    canonical_neighbor_names,
    case_payload,
    load_golden,
    route_session_change_taken_out,
    split_case,
    without_acl_ace_fields,
    without_descriptions,
)
from tests.test_family_stream_parity import inter_digest
from tests.test_nxos_stream_parity import _golden_inter_digest


def _overlay() -> dict[str, Any]:
    document: dict[str, Any] = json.loads(ACL_GOLDEN_PATH.read_text(encoding="utf-8"))
    return document


def _overlay_cases() -> dict[str, Any]:
    cases: dict[str, Any] = _overlay()["cases"]
    return cases


def _port_description_cases() -> dict[str, Any]:
    cases: dict[str, Any] = json.loads(PORT_DESCRIPTION_GOLDEN_PATH.read_text(encoding="utf-8"))["cases"]
    return cases


def _parse(key: str) -> dict[str, Any]:
    # The route-session overlay (tests/test_route_session_golden.py) is recorded
    # over this one, so this one holds the parse with that change taken out.
    with route_session_change_taken_out():
        inter: dict[str, Any] = importlib.import_module(f"hst.collectors.{split_case(key)[0]}").parse(
            case_payload(key)
        )
    return inter


def _digest(key: str, inter: dict[str, Any]) -> str:
    # each family's parity test reads the digest its own way
    return _golden_inter_digest(inter) if split_case(key)[0] == "nxos" else inter_digest(inter)


def test_the_strip_takes_out_only_the_added_ace_fields() -> None:
    ace = {
        "action": "permit",
        "src_any": False,
        "src": None,
        "src_opaque_reason": "the ACE matches object-group 'PARTNERS', which is not collected",
        "src_opaque_note": "object-group PARTNERS not collected",
        "proto": "icmp",
        "qualifier_reason": "the rule matches on the ICMP type 'echo'",
        "qualifier_note": "",
        "icmp_type": "echo",
    }
    inter = {"interfaces": [], "acl": {"lists": {"EDGE-IN": [ace]}, "bindings": [{"acl": "EDGE-IN"}]}}
    stripped = without_acl_ace_fields(inter)
    assert stripped["acl"]["lists"]["EDGE-IN"] == [
        {
            "action": "permit",
            "src_any": False,
            "src": None,
            "src_opaque_reason": "the ACE matches object-group 'PARTNERS', which is not collected",
            "proto": "icmp",
            "qualifier_reason": "the rule matches on the ICMP type 'echo'",
        }
    ]
    assert stripped["acl"]["bindings"] == inter["acl"]["bindings"]
    # the input is left as it was
    assert "src_opaque_note" in ace
    assert without_acl_ace_fields({"interfaces": []}) == {"interfaces": []}


def test_the_overlay_records_the_inter_field() -> None:
    overlay = _overlay()
    assert overlay["fields"] == ["inter"]
    assert all(set(fields) == {"inter"} for fields in _overlay_cases().values())


def test_the_overlay_names_exactly_the_cases_whose_parse_carries_an_added_ace_field() -> None:
    touched = {key for key in CASES if without_acl_ace_fields(inter := _parse(key)) != inter}
    assert set(_overlay_cases()) == touched
    assert {split_case(key)[0] for key in touched} == {"iosxe", "nxos"}


@pytest.mark.parametrize("key", sorted(_overlay_cases()))
def test_an_overlay_digest_is_the_one_without_it_once_the_added_ace_fields_are_taken_out(key: str) -> None:
    # the overlay digests hold the neighbor and FHRP names as netutils spells them
    inter = canonical_neighbor_names(split_case(key)[0], without_descriptions(_parse(key)))
    assert _digest(key, inter) == _overlay_cases()[key]["inter"]
    base = load_golden(acl=False, port_description=False, ifname=False)["cases"][key]["inter"]
    assert _digest(key, without_acl_ace_fields(inter)) == base


def test_the_acl_overlay_cannot_be_left_out_under_the_port_description_overlay() -> None:
    with pytest.raises(ValueError, match="leave out both"):
        load_golden(acl=False)


@pytest.mark.parametrize("key", sorted(set(_overlay_cases()) | set(_port_description_cases())))
def test_the_overlays_compose_to_the_digest_of_the_whole_parse(key: str) -> None:
    """Laid over each other, the two overlays give the digest of the parse as
    it is; without the port-description overlay, the case reads the digest of
    the ACL overlay where it has one. The parse runs with the route-session
    change taken out (`_parse`), so it is held to the stack below that
    overlay."""
    inter = _parse(key)
    assert load_golden(route_session=False)["cases"][key]["inter"] == _digest(key, inter)
    if key in _overlay_cases():
        assert (
            load_golden(port_description=False, ifname=False)["cases"][key]["inter"]
            == (_overlay_cases()[key]["inter"])
        )
