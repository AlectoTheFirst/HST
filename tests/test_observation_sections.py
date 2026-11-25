"""`load_observations` records the payload's sections (collectors/base.py).

The observation-only path writes a payload's side-store tables and leaves the
graph to the carry. The run judges the device it publishes by the rule a full
load is judged by (app/runs_exec.py `_completeness`), so the manifest it
returns carries the sections a full load of the same payload records: the
Cisco families read them from the same parse `side_tables` uses, and a
collector without `sections` records none.

The payloads are the synthetic golden cases (`tests/support/`), nothing
captured from real infrastructure.
"""

from __future__ import annotations

from typing import Any

import pytest
import textfsm
from tests.support.synthetic_payloads import (
    SNAPSHOT_TS,
    case_payload,
    make_collector,
    make_settings,
    outcomes_json,
)
from tests.test_collector_execute import FakeSession

from hst import collectors as coll
from hst.collectors import iosxe, iosxr, nxos
from hst.collectors.base import RAW_OUTCOMES_KEY, REGISTRY, Collector, SourceConfig
from hst.core import Settings
from hst.core.model import section_verdict

pytest.importorskip("pyarrow")

RUN_ID = "1700000000000-bbbbbbbb"


def _observe(collector: Any, raw: dict[str, Any]) -> Any:
    return coll.load_observations(
        collector, raw, collection_ts=SNAPSHOT_TS, run_id=RUN_ID, ts_ms=SNAPSHOT_TS, source_name="edge"
    )


def _load(collector: Any, raw: dict[str, Any]) -> Any:
    return coll.load_payload(
        collector,
        FakeSession(),
        raw,
        collection_ts=SNAPSHOT_TS,
        run_id=RUN_ID,
        ts_ms=SNAPSHOT_TS,
        source_name="edge",
    )


def _released(collector: Any) -> bool:
    return collector._parsed_for is None and collector._parsed is None


def _parquet_files(settings: Settings) -> list[str]:
    root = settings.sidestore_dir
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*.parquet")) if root.exists() else []


def test_the_sections_are_recorded_from_the_parse_the_tables_use(tmp_path, monkeypatch):
    settings = make_settings(tmp_path)
    collector = make_collector("iosxe", settings)
    payload = case_payload("iosxe/small/plain")
    expected = outcomes_json(make_collector("iosxe", None).sections(payload))
    parses: list[int] = []

    def counting(raw: dict[str, str]) -> dict[str, Any]:
        parses.append(id(raw))
        return iosxe.parse(raw)

    monkeypatch.setattr(iosxe.IosxeCollector, "_parse", staticmethod(counting))

    manifest = _observe(collector, payload)

    assert manifest.sections and outcomes_json(manifest.sections) == expected
    assert manifest.tables["rib"].status == "complete" and manifest.tables["rib"].row_count
    assert any(name.startswith("rib/") for name in _parquet_files(settings))
    assert len(parses) == 1, "sections and side_tables share one parse"
    assert _released(collector)


@pytest.mark.parametrize("command", [nxos.CMD_ROUTE, nxos.CMD_MAC], ids=["rib", "mac_table"])
def test_a_failed_authoritative_section_reads_as_a_full_load_reads_it(tmp_path, command):
    """The same payload through both load functions: the same sections, the
    same tables, and a verdict that fails the device."""
    payload = case_payload("nxos/small/plain")
    payload[command] = '{"unexpected": 1}'

    observed = _observe(make_collector("nxos", make_settings(tmp_path / "observed")), payload)
    loaded = _load(make_collector("nxos", make_settings(tmp_path / "loaded")), payload)

    assert outcomes_json(observed.sections) == outcomes_json(loaded.sections)
    assert outcomes_json(observed.tables) == outcomes_json(loaded.tables)
    assert section_verdict(observed.sections, nxos.NxosCollector.AUTHORITATIVE_SECTIONS) == "failed"


def test_a_required_answer_the_parse_cannot_read_raises_and_writes_nothing(tmp_path):
    settings = make_settings(tmp_path)
    collector = make_collector("iosxr", settings)
    payload = case_payload("iosxr/small/plain")
    payload[iosxr.CMD_INVENTORY] += "THIS IS NOT AN INVENTORY LINE\n"

    with pytest.raises(textfsm.TextFSMError):
        _observe(collector, payload)

    assert _parquet_files(settings) == []
    assert _released(collector)


class _Cfg(SourceConfig):
    host: str = ""


class _NoSections(Collector):
    """A collector that reads no sections apart from normalizing, as every
    collector but the three Cisco families."""

    name = "nosections"
    KIND = "group"
    ConfigModel = _Cfg
    SIDE_TABLES = ("arp",)

    def fetch(self) -> Any:
        return {}

    def normalize(self, raw: Any) -> Any:
        raise AssertionError("the observation path never normalizes")

    def probe(self) -> str:
        return "ok"

    def side_tables(self, raw: Any) -> dict[str, list[dict[str, Any]]]:
        return {"arp": [{"device_uid": "dev:r1", "ip": ip, "mac": mac} for ip, mac in raw["arp"]]}


def test_a_collector_without_sections_records_none(tmp_path):
    settings = make_settings(tmp_path)
    collector = _NoSections(_Cfg(host="r1", source_name="edge"), settings)

    manifest = _observe(collector, {"arp": [["10.0.0.9", "aa:bb:cc:dd:ee:ff"]]})

    assert manifest.sections == {}
    assert manifest.tables["arp"].status == "complete" and manifest.tables["arp"].row_count == 1


def test_a_refused_optional_command_makes_the_device_partial(tmp_path):
    payload = case_payload("iosxe/small/plain")
    payload[iosxe.CMD_ARP] = ""
    payload[RAW_OUTCOMES_KEY][iosxe.CMD_ARP] = {"status": "unauthorized", "detail": "% Authorization failed."}

    manifest = _observe(make_collector("iosxe", make_settings(tmp_path)), payload)

    assert manifest.sections["arp"].status == "unauthorized"
    assert section_verdict(manifest.sections, iosxe.IosxeCollector.AUTHORITATIVE_SECTIONS) == "partial"


def _reaches_the_observation_path(cls: type[Collector]) -> bool:
    """Whether a payload of this collector can take the observation-only
    path: its configuration hash has to match while its observation hash
    differs, which needs an observation key the configuration hash leaves
    out."""
    observed = set(cls.OBSERVATION_RAW_KEYS)
    return bool(observed & set(cls.VOLATILE_RAW_KEYS)) or cls.OBSERVATION_RAW_KEY_PATTERN is not None


def test_every_collector_that_can_take_the_observation_path_reads_its_sections():
    """The path judges a device by its sections, so a collector that records
    them only while it normalizes must not reach it. VyOS reaches it through
    its neighbor table and records its sections apart from normalize."""
    built_in = [cls for cls in REGISTRY.values() if cls.__module__.startswith("hst.collectors.")]
    reaching = sorted(cls.name for cls in built_in if _reaches_the_observation_path(cls))

    assert reaching == ["iosxe", "iosxr", "nxos", "vyos"]
    for cls in built_in:
        if _reaches_the_observation_path(cls):
            assert callable(getattr(cls, "sections", None)), cls.name


def test_a_vyos_observation_load_records_its_sections_and_writes_the_neighbor_table(tmp_path):
    """A VyOS payload whose neighbor table alone moved takes the path:
    it records the sections a full load records and writes the
    `arp` rows."""
    from tests.support import synthetic_vyos

    payload = synthetic_vyos.new_raw(synthetic_vyos.answers("fixture/plain"))
    payload["neigh"] = [
        {"dst": "10.0.0.9", "dev": "eth1", "lladdr": "aa:bb:cc:dd:ee:ff", "state": ["REACHABLE"]}
    ]
    payload[RAW_OUTCOMES_KEY]["neigh"] = {"status": "ok"}
    expected = outcomes_json(synthetic_vyos.make_collector(None).sections(payload))

    manifest = _observe(synthetic_vyos.make_collector(make_settings(tmp_path)), payload)

    assert outcomes_json(manifest.sections) == expected
    assert manifest.sections["neigh"].status == "ok"
    assert manifest.tables["arp"].status == "complete" and manifest.tables["arp"].row_count == 1
