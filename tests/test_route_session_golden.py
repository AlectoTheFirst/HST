"""`route_session_golden.json`: the Cisco RIB and BGP session changes alter
the golden fields of every IOS-XE, IOS-XR and NX-OS case."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from tests.support.gen_stream_golden import golden_case
from tests.support.synthetic_payloads import (
    CASES,
    ROUTE_SESSION_GOLDEN_PATH,
    load_golden,
    route_session_change_taken_out,
    split_case,
)


def _overlay() -> dict[str, Any]:
    document: dict[str, Any] = json.loads(ROUTE_SESSION_GOLDEN_PATH.read_text(encoding="utf-8"))
    return document


def _fields(entry: dict[str, Any], names: list[str]) -> dict[str, Any]:
    out = {}
    for field in names:
        name, _dot, table = field.partition(".")
        out[field] = entry[name][table] if table else entry[name]
    return out


def test_the_overlay_names_every_cisco_case_and_only_the_changed_fields():
    overlay = _overlay()
    assert overlay["fields"] == ["inter", "side_tables.rib", "parquet.rib", "parquet_layout.rib"]
    assert set(overlay["cases"]) == set(CASES)
    for key, fields in overlay["cases"].items():
        family, scale, _variant = split_case(key)
        assert set(fields) <= set(overlay["fields"]), key
        # every family's RIB rows carry the two columns
        assert "side_tables.rib" in fields, key
        # the NX-OS parse is unchanged; the IOS-XR files change where an
        # interface route held the word `connected` as its next hop
        assert ("inter" in fields) == (family != "nxos"), key
        connected = family == "iosxr" and scale != "fixture"
        assert ("parquet.rib" in fields) == ("parquet_layout.rib" in fields) == connected, key


def test_the_golden_is_the_rpl_pass_golden_with_the_overlay_laid_over_it():
    before = load_golden(route_session=False)["cases"]
    laid = load_golden()["cases"]
    for key in CASES:
        expected = json.loads(json.dumps(before[key]))
        for field, value in _overlay()["cases"].get(key, {}).items():
            name, _dot, table = field.partition(".")
            if table:
                expected[name] = {**expected[name], table: value}
            else:
                expected[name] = value
        assert laid[key] == expected, key
    with pytest.raises(ValueError):
        load_golden(rpl_pass=False, route_session=True)


@pytest.mark.parametrize("key", sorted(_overlay()["cases"]))
def test_an_overlay_value_is_the_one_without_it_once_the_change_is_taken_out(key: str, tmp_path: Path):
    names = sorted(_overlay()["cases"][key])
    assert _fields(golden_case(key, tmp_path / "now"), names) == _overlay()["cases"][key]
    with route_session_change_taken_out():
        before = _fields(golden_case(key, tmp_path / "before"), names)
    assert before == _fields(load_golden(route_session=False)["cases"][key], names)
