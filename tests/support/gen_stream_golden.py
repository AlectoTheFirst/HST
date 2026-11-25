"""The golden fields of a case of `synthetic_payloads.py`, computed from the
working tree (`golden_case`), and the fields of an IOS-XE or IOS-XR case that
the column-position BGP path reader changes (`parser2_case`).

Nothing in the repository writes `stream_golden.json` or its overlays.
tests/test_route_session_golden.py holds `golden_case` to the last overlay,
and tests/test_parser2_gate.py holds `parser2_case` to the overlays before it.

Per case (`CASES`), `stream_golden.json` holds the following. The four digests
are of the payload in the spelling of the base record
(`synthetic_payloads.base_spelling`).

- `payload_sha`: `synthetic_payloads.payload_sha`, which proves the generator
  still builds the payload these values were computed from;
- `raw_sha`, `obs_sha`: `collectors.base.raw_sha`/`obs_sha` under
  `make_collector`;
- `raw_json_sha`: SHA-256 of `json.dumps(payload, default=str).encode()`, the
  JSON the raw store seals;
- `textfsm`: for IOS-XE and IOS-XR, `[count, sha]` from `rows_digest` of the
  records of every `cli_parse.parse` call the family parse makes, keyed by
  command. Null for NX-OS, which parses JSON;
- `inter`: `inter_digest` of the family module's `parse(payload)`;
- `sections`, `table_outcomes`: the collector's `sections` and
  `table_outcomes`, as `outcomes_json`;
- `side_tables`: `[count, sha]` from `rows_digest` per `side_tables` table;
- `parquet`: per table, `sidestore.write_table` with `RUN_ID`, `SNAPSHOT_TS`
  and `ROW_GROUP_ROWS`, then `manifest.sidestore_row_facts`: `[count,
  rows_sha]`, or `[0, null]` for a table with no rows;
- `parquet_layout`: per table, `parquet_layout` of the same file: its row
  groups, schema and row order, which `rows_sha` does not cover. Null for a
  table with no rows;
- `tables`: the outcomes `collectors.base._write_side_tables` returns for the
  same run id and snapshot, whose `path` is relative to the data directory;
- `base_peak_bytes`: for the medium cases only, a tracemalloc peak of
  `normalize` plus `_write_side_tables` on a fresh collector, with the payload
  already allocated and the batch kept alive across both, as `load_payload`
  keeps it. tests/test_family_stream_memory.py bounds the peak of a load by a
  share of it.

`parser2_golden.json` holds, for every IOS-XE and IOS-XR case, the fields the
column-position BGP path reader (parser version 2) changes (`PARSER2_FIELDS`),
which `synthetic_payloads.load_golden` lays over the values of
`stream_golden.json`. Its `raw_sha` and `obs_sha` are computed with the IOS-XE
and IOS-XR collectors under the change-hash declarations of the base record
and their own parser version (`parser2_declarations`). That `raw_sha` differs
from the one of the base record by the parser version alone, and that
`obs_sha` is the one of the base record. tests/test_cisco_rib_volatility.py
pins both digests under the working tree's own declarations.
"""

from __future__ import annotations

import contextlib
import importlib
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any
from unittest.mock import patch

from tests.support.synthetic_payloads import (
    COLLECTOR_HOST,
    COLLECTOR_SOURCE,
    ROW_GROUP_ROWS,
    RUN_ID,
    SCALES,
    SNAPSHOT_TS,
    base_declarations,
    base_spelling,
    case_payload,
    expected_ios_paths,
    held_mac_statement,
    inter_digest,
    make_collector,
    make_settings,
    outcomes_json,
    parquet_layout,
    payload_sha,
    raw_json_sha,
    rows_digest,
    split_case,
    without_added_sections,
)

# The golden fields the column-position BGP path reader may change: `raw_sha`
# through the parser version, the intermediate shape, the BGP path table's
# outcomes, rows and file. A dotted field is one table of the field.
PARSER2_FIELDS = (
    "raw_sha",
    "inter",
    "table_outcomes",
    "tables",
    "side_tables.bgp_session_routes",
    "parquet.bgp_session_routes",
    "parquet_layout.bgp_session_routes",
)
_BGP_ROUTES = "bgp_session_routes"


def golden_case(key: str, work: Path) -> dict[str, Any]:
    """The golden fields of one case, computed from the working tree: every
    field of `stream_golden.json` but `textfsm` and `base_peak_bytes`."""
    from hst.collectors import base as collectors_base
    from hst.core import manifest, sidestore

    family, _scale, _variant = split_case(key)
    payload = case_payload(key)
    collector = make_collector(family, make_settings(work / "data"))
    spelled = base_spelling(family, payload)
    entry: dict[str, Any] = {
        "payload_sha": payload_sha(spelled),
        "raw_json_sha": raw_json_sha(spelled),
        "raw_sha": collectors_base.raw_sha(collector, spelled),
        "obs_sha": collectors_base.obs_sha(collector, spelled),
    }
    del spelled
    inter = importlib.import_module(f"hst.collectors.{family}").parse(payload)
    entry["inter"] = inter_digest(inter)
    del inter
    # The base record holds no `ADDED_SINCE_BASE` section.
    entry["sections"] = without_added_sections(family, outcomes_json(collector.sections(payload)))[0]
    entry["table_outcomes"] = outcomes_json(
        held_mac_statement(family, collector.table_outcomes(payload), written=False)
    )
    side = collector.side_tables(payload)
    entry["side_tables"] = {table: list(rows_digest(rows)) for table, rows in sorted(side.items())}
    parquet: dict[str, list[Any]] = {}
    layout: dict[str, dict[str, Any] | None] = {}
    for table, rows in sorted(side.items()):
        path = sidestore.write_table(
            work / "parquet",
            table,
            COLLECTOR_SOURCE,
            COLLECTOR_HOST,
            RUN_ID,
            rows,
            snapshot_ts=SNAPSHOT_TS,
            row_group_rows=ROW_GROUP_ROWS,
        )
        parquet[table] = [0, None] if path is None else list(manifest.sidestore_row_facts(path))
        layout[table] = parquet_layout(path)
    entry["parquet"] = parquet
    entry["parquet_layout"] = layout
    del side
    source, host = collectors_base._identity(collector, None)
    entry["tables"] = outcomes_json(
        held_mac_statement(
            family,
            collectors_base._write_side_tables(
                collector, payload, source, host, run_id=RUN_ID, collection_ts=SNAPSHOT_TS, on_write=None
            ),
            written=True,
        )
    )
    return entry


def inter_key_digests(inter: Mapping[str, Any]) -> dict[str, str]:
    """`inter_digest` of each key of a family parse's intermediate shape on
    its own, keyed by the key, with what the column-position BGP path reader
    changes left out: `bgp_observed.routes`, and the value of the row count of
    every `bgp_observed.directions` entry. Whether an entry has a count stays
    in: none means its command is not in the payload, which no path reader
    changes."""
    digests: dict[str, str] = {}
    for name, value in inter.items():
        if name == "bgp_observed" and isinstance(value, Mapping):
            value = {field: part for field, part in value.items() if field != "routes"}
            if "directions" in value:
                value["directions"] = [
                    {
                        **{field: part for field, part in entry.items() if field != "row_count"},
                        "row_count": entry.get("row_count") is not None,
                    }
                    for entry in value["directions"]
                ]
        digests[name] = inter_digest({name: value})
    return dict(sorted(digests.items()))


def _check_inter_keys(key: str, new: dict[str, str], reference: dict[str, str]) -> None:
    """Stop unless every key of the working tree's intermediate shape, as
    `inter_key_digests` reads it, digests as `reference` does."""
    changed = _changed_names(new, reference)
    if changed:
        raise SystemExit(
            f"{key}: the intermediate shape differs from the reference in {changed},"
            " beside the BGP paths and their row counts"
        )


def _check_paths(key: str, observed: dict[str, Any]) -> None:
    """Stop unless the family parse's `observed` BGP capture reads, from every
    BGP path answer of a synthetic case, exactly the paths the generator
    printed."""
    _family, scale, _variant = split_case(key)
    if scale not in SCALES:
        return
    expected = expected_ios_paths(key)
    printed: list[dict[str, Any]] = []
    for entry in observed["directions"]:
        paths = expected[entry["command"]]
        if entry["row_count"] != len(paths):
            raise SystemExit(f"{key}: {entry['command']!r} read {entry['row_count']} paths, not {len(paths)}")
        printed.extend(paths)
    for index, (read, path) in enumerate(zip(observed["routes"], printed, strict=True)):
        if list(read.items()) != list(path.items()):
            raise SystemExit(f"{key}: path {index} reads {read}, not the printed {path}")


def _changed_names(new: dict[str, Any], old: dict[str, Any]) -> list[str]:
    """The names whose value differs between two mappings, or that one lacks."""
    return sorted(name for name in new.keys() | old.keys() if new.get(name) != old.get(name))


def parser2_case(key: str, base: dict[str, Any], base_inter: dict[str, Any], work: Path) -> dict[str, Any]:
    """The fields of one IOS-XE or IOS-XR case that the working tree computes
    differently from `base`, the case in `stream_golden.json`, as
    `load_golden` lays them over it. The caller runs it under
    `parser2_declarations`.

    `base_inter` holds the `payload_sha` and the `inter_key_digests` of a
    reference parse of the case. The function stops on a payload `base` was
    not computed from, on a key of the intermediate shape that differs from
    `base_inter` outside the BGP paths and the values of their row counts, on
    paths that differ from what the generator printed
    (`synthetic_payloads.expected_ios_paths`), and on a change outside
    `PARSER2_FIELDS` or outside the BGP path table."""
    family, _scale, _variant = split_case(key)
    payload = case_payload(key)
    if payload_sha(base_spelling(family, payload)) != base["payload_sha"]:
        raise SystemExit(f"{key}: the payload is not the one the base values were computed from")
    if base_inter["payload_sha"] != base["payload_sha"]:
        raise SystemExit(f"{key}: the reference parse read a payload the base values were not computed from")
    inter = importlib.import_module(f"hst.collectors.{family}").parse(payload)
    _check_paths(key, inter["bgp_observed"])
    _check_inter_keys(key, inter_key_digests(inter), base_inter["inter"])
    del inter, payload
    new = golden_case(key, work)
    changed: dict[str, Any] = {}
    for field, value in sorted(new.items()):
        if value == base[field]:
            continue
        if field in ("side_tables", "parquet", "parquet_layout"):
            tables = _changed_names(value, base[field])
            if tables != [_BGP_ROUTES]:
                raise SystemExit(f"{key}: {field} changes {tables}, not only {_BGP_ROUTES}")
            changed[f"{field}.{_BGP_ROUTES}"] = value[_BGP_ROUTES]
        elif field in ("table_outcomes", "tables"):
            names = _changed_names(value, base[field])
            other = [name for name in names if name != _BGP_ROUTES and not name.startswith(f"{_BGP_ROUTES}/")]
            if other:
                raise SystemExit(f"{key}: {field} changes {other} beside {_BGP_ROUTES}")
            changed[field] = value
        elif field in PARSER2_FIELDS:
            changed[field] = value
        else:
            raise SystemExit(f"{key}: {field} changes, and is not one of {PARSER2_FIELDS}")
    return changed


@contextlib.contextmanager
def parser2_declarations() -> Iterator[None]:
    """The IOS-XE and IOS-XR collector classes, while the block runs, with the
    change-hash declarations of the base record
    (`synthetic_payloads.base_declarations`) and their own parser version. The
    `raw_sha` and `obs_sha` of `parser2_golden.json` are computed under these
    declarations."""
    from hst.collectors.iosxe import IosxeCollector
    from hst.collectors.iosxr import IosxrCollector

    with contextlib.ExitStack() as stack:
        for family, cls in (("iosxe", IosxeCollector), ("iosxr", IosxrCollector)):
            declarations = {**base_declarations(family), "PARSER_VERSION": cls.PARSER_VERSION}
            stack.enter_context(patch.multiple(cls, **declarations))
        yield
