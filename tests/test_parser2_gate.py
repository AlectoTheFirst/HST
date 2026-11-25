"""The intermediate-shape gate of `gen_stream_golden.parser2_case`, and the
declarations it hashes under.

The parser version 2 overlay (`tests/support/parser2_golden.json`) records the
digest of the whole intermediate shape.

The overlay's digests are computed under `parser2_declarations`, so the
working tree reproduces them whatever change-hash declarations its collectors
carry.
"""

from __future__ import annotations

import copy
import importlib
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from tests.support import gen_stream_golden
from tests.support.gen_stream_golden import inter_key_digests, parser2_case, parser2_declarations
from tests.support.synthetic_payloads import (
    ACL_GOLDEN_PATH,
    BASE_OBSERVATION_RAW_KEYS,
    BASE_VOLATILE_RAW_KEYS,
    GOLDEN_PATH,
    IFNAME_GOLDEN_PATH,
    PARSER2_GOLDEN_PATH,
    PORT_DESCRIPTION_GOLDEN_PATH,
    RPL_PASS_GOLDEN_PATH,
    base_declarations,
    case_payload,
    route_session_change_taken_out,
    split_case,
)

from hst.collectors import iosxe, iosxr

_CASE = "iosxe/fixture/plain"
_PEER = "198.51.100.2"
_INTER: dict[str, Any] = {
    "interfaces": [{"name": "GigabitEthernet1", "description": "uplink"}],
    "bgp_observed": {
        "sessions": [{"peer_ip": _PEER, "state": "Established", "vrf": "default", "af": 4}],
        "routes": [{"prefix": "10.0.0.0/24", "next_hop": _PEER, "peer_ip": _PEER, "direction": "routes"}],
        "directions": [
            {
                "vrf": "default",
                "af": 4,
                "peer_ip": _PEER,
                "direction": "routes",
                "command": f"show ip bgp neighbors {_PEER} routes",
                "row_count": 1,
            }
        ],
    },
}


# A change made to the parse's intermediate shape, and a run of the gate with it.
_Change = Callable[[dict[str, Any]], None]
_Gate = Callable[[_Change], None]


def _changed(new: dict[str, str], old: dict[str, str]) -> list[str]:
    return sorted(name for name in new.keys() | old.keys() if new.get(name) != old.get(name))


# --- the digests -----------------------------------------------------------------------------


def test_the_digests_leave_out_the_bgp_paths_and_their_row_counts() -> None:
    inter = copy.deepcopy(_INTER)
    inter["bgp_observed"]["routes"] = iter([{"prefix": "10.9.0.0/16"}, {"prefix": "10.8.0.0/16"}])
    inter["bgp_observed"]["directions"][0]["row_count"] = 2
    assert inter_key_digests(inter) == inter_key_digests(_INTER)


def test_the_digests_cover_every_other_part_of_the_bgp_capture() -> None:
    before = inter_key_digests(_INTER)
    sessions = copy.deepcopy(_INTER)
    sessions["bgp_observed"]["sessions"][0]["state"] = "Idle"
    command = copy.deepcopy(_INTER)
    command["bgp_observed"]["directions"][0]["command"] = f"show ip bgp neighbors {_PEER} advertised-routes"
    uncounted = copy.deepcopy(_INTER)
    uncounted["bgp_observed"]["directions"][0]["row_count"] = None
    for inter in (sessions, command, uncounted):
        assert _changed(inter_key_digests(inter), before) == ["bgp_observed"]


def test_each_key_is_digested_on_its_own() -> None:
    inter = copy.deepcopy(_INTER)
    inter["interfaces"][0]["description"] = "uplink to core"
    assert _changed(inter_key_digests(inter), inter_key_digests(_INTER)) == ["interfaces"]


# --- the gate --------------------------------------------------------------------------------


class _PastTheGate(Exception):
    """Raised in place of `golden_case`, which `parser2_case` calls once the
    intermediate shape has passed the gate."""


def _describe_first_interface(inter: dict[str, Any]) -> None:
    inter["interfaces"][0]["description"] = "changed"


def _add_a_key(inter: dict[str, Any]) -> None:
    inter["extra"] = []


def _drop_a_key(inter: dict[str, Any]) -> None:
    del inter["fhrp"]


def _add_a_session(inter: dict[str, Any]) -> None:
    inter["bgp_observed"]["sessions"].append({"peer_ip": _PEER, "state": "Idle", "vrf": "default", "af": 4})


def _uncount_a_direction(inter: dict[str, Any]) -> None:
    inter["bgp_observed"]["directions"][0]["row_count"] = None


def _recount_the_paths(inter: dict[str, Any]) -> None:
    inter["bgp_observed"]["routes"] = []
    for entry in inter["bgp_observed"]["directions"]:
        entry["row_count"] = 0


@pytest.fixture
def gate(monkeypatch: pytest.MonkeyPatch) -> _Gate:
    """A run of `parser2_case` on `_CASE` with the IOS-XE parse changed by the
    run's argument. The unchanged working tree's parse is the reference, and
    `golden_case` raises `_PastTheGate`."""
    base = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))["cases"][_CASE]
    base_inter = {
        "payload_sha": base["payload_sha"],
        "inter": inter_key_digests(iosxe.parse(case_payload(_CASE))),
    }
    original = iosxe.parse

    def stop(*_args: Any, **_kwargs: Any) -> None:
        raise _PastTheGate

    monkeypatch.setattr(gen_stream_golden, "golden_case", stop)

    def run(change: _Change) -> None:
        def changed(payload: dict[str, Any]) -> dict[str, Any]:
            inter: dict[str, Any] = original(payload)
            change(inter)
            return inter

        monkeypatch.setattr(iosxe, "parse", changed)
        parser2_case(_CASE, base, base_inter, Path("unused"))

    return run


@pytest.mark.parametrize(
    ("change", "names"),
    [
        (_describe_first_interface, ["interfaces"]),
        (_add_a_key, ["extra"]),
        (_drop_a_key, ["fhrp"]),
        (_add_a_session, ["bgp_observed"]),
        (_uncount_a_direction, ["bgp_observed"]),
    ],
    ids=["changed-key", "added-key", "dropped-key", "bgp-session", "uncounted-direction"],
)
def test_the_gate_refuses_a_change_beside_the_bgp_paths(
    gate: _Gate, change: _Change, names: list[str]
) -> None:
    message = f"{_CASE}: the intermediate shape differs from the reference in {names}"
    with pytest.raises(SystemExit, match=re.escape(message)):
        gate(change)


def test_the_gate_passes_a_change_of_the_bgp_paths_alone(gate: _Gate) -> None:
    with pytest.raises(_PastTheGate):
        gate(_recount_the_paths)


# --- the declarations ------------------------------------------------------------------------

_COLLECTORS = {"iosxe": iosxe.IosxeCollector, "iosxr": iosxr.IosxrCollector}


@pytest.mark.parametrize("family", sorted(_COLLECTORS))
def test_the_declarations_are_the_base_records_with_the_current_parser_version(family: str) -> None:
    cls = _COLLECTORS[family]
    before = {name: getattr(cls, name) for name in base_declarations(family)}

    with parser2_declarations():
        assert BASE_VOLATILE_RAW_KEYS[family] == cls.VOLATILE_RAW_KEYS
        assert BASE_OBSERVATION_RAW_KEYS[family] == cls.OBSERVATION_RAW_KEYS
        assert cls.VOLATILE_RAW_KEY_PATTERN is None
        assert cls.OBSERVATION_RAW_KEY_PATTERN is None
        assert before["PARSER_VERSION"] == cls.PARSER_VERSION

    assert {name: getattr(cls, name) for name in before} == before


@pytest.mark.parametrize(
    "key",
    [f"{family}/fixture/{variant}" for family in sorted(_COLLECTORS) for variant in ("plain", "unicode")]
    + ["iosxe/small/plain", "iosxr/small/no_trailing_newline"],
)
def test_the_generator_reproduces_the_recorded_overlay(key: str, tmp_path: Path) -> None:
    family, _scale, _variant = split_case(key)
    base = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))["cases"][key]
    recorded = {
        **json.loads(PARSER2_GOLDEN_PATH.read_text(encoding="utf-8"))["cases"][key],
        **json.loads(ACL_GOLDEN_PATH.read_text(encoding="utf-8"))["cases"].get(key, {}),
        **json.loads(PORT_DESCRIPTION_GOLDEN_PATH.read_text(encoding="utf-8"))["cases"].get(key, {}),
        **json.loads(IFNAME_GOLDEN_PATH.read_text(encoding="utf-8"))["cases"].get(key, {}),
        **json.loads(RPL_PASS_GOLDEN_PATH.read_text(encoding="utf-8"))["cases"].get(key, {}),
    }
    parse = importlib.import_module(f"hst.collectors.{family}").parse

    with route_session_change_taken_out():
        base_inter = {
            "payload_sha": base["payload_sha"],
            "inter": inter_key_digests(parse(case_payload(key))),
        }
        with parser2_declarations():
            assert parser2_case(key, base, base_inter, tmp_path) == recorded
