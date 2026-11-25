"""The golden reference file and the payload generator behind it agree."""

from __future__ import annotations

import re

import pytest
from tests.support.synthetic_payloads import (
    CASES,
    COLLECTOR_HOST,
    COLLECTOR_ROUTING_SCOPE,
    COLLECTOR_SITE,
    COLLECTOR_SOURCE,
    ROW_GROUP_ROWS,
    RUN_ID,
    SNAPSHOT_TS,
    base_spelling,
    case_payload,
    load_golden,
    make_collector,
    make_settings,
    payload_sha,
    raw_json_sha,
    split_case,
)
from tests.test_cisco_rib_volatility import base_digests, hash_as_base_record

from hst.collectors.base import obs_sha, raw_sha
from hst.collectors.ssh import sanitize_cli_text

GOLDEN = load_golden()

FIELDS = frozenset(
    {
        "payload_sha",
        "raw_sha",
        "obs_sha",
        "raw_json_sha",
        "textfsm",
        "inter",
        "sections",
        "table_outcomes",
        "side_tables",
        "parquet",
        "parquet_layout",
        "tables",
        "base_peak_bytes",
    }
)
_SHA = re.compile(r"[0-9a-f]{64}")
_LAYOUT_KEYS = frozenset({"row_groups", "schema_sha", "rows_sha"})


def _digest_pairs(value: object, *, empty_is_null: bool) -> bool:
    """A mapping of table or command to `[count, sha]`."""
    if not isinstance(value, dict) or not value:
        return False
    for count, sha in value.values():
        if not isinstance(count, int) or count < 0:
            return False
        if empty_is_null and count == 0:
            if sha is not None:
                return False
        elif not (isinstance(sha, str) and _SHA.fullmatch(sha)):
            return False
    return True


def _layouts(value: object, parquet: dict[str, list[object]]) -> bool:
    """A `parquet_layout` per `parquet` table: null where the table wrote no
    file, otherwise row groups of at most `ROW_GROUP_ROWS` rows that add up to
    the table's row count, and the schema and ordered-rows digests."""
    if not isinstance(value, dict) or set(value) != set(parquet):
        return False
    for table, layout in value.items():
        if parquet[table][0] == 0:
            if layout is not None:
                return False
            continue
        if not isinstance(layout, dict) or set(layout) != _LAYOUT_KEYS:
            return False
        groups = layout["row_groups"]
        if sum(groups) != parquet[table][0] or not all(0 < rows <= ROW_GROUP_ROWS for rows in groups):
            return False
        if not all(
            isinstance(layout[key], str) and _SHA.fullmatch(layout[key]) for key in ("schema_sha", "rows_sha")
        ):
            return False
    return True


def test_the_golden_file_names_every_case_and_its_configuration():
    assert sorted(GOLDEN["cases"]) == sorted(CASES)
    assert (GOLDEN["run_id"], GOLDEN["snapshot_ts"], GOLDEN["row_group_rows"]) == (
        RUN_ID,
        SNAPSHOT_TS,
        ROW_GROUP_ROWS,
    )
    assert GOLDEN["collector"] == {
        "host": COLLECTOR_HOST,
        "source_name": COLLECTOR_SOURCE,
        "site_code": COLLECTOR_SITE,
        "routing_scope": COLLECTOR_ROUTING_SCOPE,
        "capture_bgp": "all",
    }


@pytest.mark.parametrize("key", CASES)
def test_every_case_holds_every_field(key):
    family, scale, _variant = split_case(key)
    case = GOLDEN["cases"][key]

    assert set(case) == FIELDS
    for field in ("payload_sha", "raw_sha", "obs_sha", "raw_json_sha", "inter"):
        assert _SHA.fullmatch(case[field]), field
    if family == "nxos":
        assert case["textfsm"] is None
    else:
        assert _digest_pairs(case["textfsm"], empty_is_null=False)
    for field in ("sections", "table_outcomes", "tables"):
        assert case[field] and all("status" in outcome for outcome in case[field].values()), field
    assert _digest_pairs(case["side_tables"], empty_is_null=False)
    assert _digest_pairs(case["parquet"], empty_is_null=True)
    assert set(case["parquet"]) == set(case["side_tables"])
    assert _layouts(case["parquet_layout"], case["parquet"])
    if scale == "medium":
        assert isinstance(case["base_peak_bytes"], int) and case["base_peak_bytes"] > 0
    else:
        assert case["base_peak_bytes"] is None


@pytest.mark.parametrize("key", CASES)
def test_the_generator_still_builds_every_golden_payload(key):
    """The digests are of the payload in the spelling of the base record."""
    payload = case_payload(key)
    spelled = base_spelling(split_case(key)[0], payload)

    assert payload_sha(spelled) == GOLDEN["cases"][key]["payload_sha"]
    assert raw_json_sha(spelled) == GOLDEN["cases"][key]["raw_json_sha"]
    unsanitized = [
        command
        for command, text in payload.items()
        if isinstance(text, str) and sanitize_cli_text(text) != text
    ]
    assert unsanitized == []


@pytest.mark.parametrize("key", [key for key in CASES if split_case(key)[1] == "fixture"])
def test_the_fixture_cases_hash_to_the_digests_of_the_base_record(key, tmp_path, monkeypatch):
    """A stored `device_status` hash stays valid only while `raw_sha` and
    `obs_sha` return the same digest for the same payload and the same
    declarations. The collector hashes here with the declarations of the
    base record, the parser version included (`hash_as_base_record`), and
    the payload is in the spelling of the base record (`base_spelling`). The
    digests are those of the base record (`stream_golden.json`)."""
    family, _scale, _variant = split_case(key)
    collector = make_collector(family, make_settings(tmp_path))
    payload = base_spelling(family, case_payload(key))
    hash_as_base_record(monkeypatch, family)
    golden_raw, golden_obs = base_digests(key)

    assert raw_sha(collector, payload) == golden_raw
    assert obs_sha(collector, payload) == golden_obs
