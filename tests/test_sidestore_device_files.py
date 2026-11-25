"""The side-store files of the devices a derivation asks about."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

pa = pytest.importorskip("pyarrow")
pq = pytest.importorskip("pyarrow.parquet")
pytest.importorskip("duckdb")

from hst import reasoner  # noqa: E402
from hst.app.crypto import generate_key  # noqa: E402
from hst.core import Settings, manifest, sidestore  # noqa: E402
from hst.core.finalize import finalize_derivations  # noqa: E402
from hst.core.model import RunManifest  # noqa: E402


def _settings(tmp_path: Path) -> Settings:
    return Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())


def _arp(device: str, ip: str, mac: str) -> dict[str, Any]:
    return {"device_uid": device, "ip": ip, "mac": mac, "interface_name": "Vlan10"}


def _mac(device: str, mac: str, port: str) -> dict[str, Any]:
    return {"device_uid": device, "vlan": 10, "mac": mac, "port_name": port}


def _write(settings: Settings, table: str, host: str, rows: list[dict[str, Any]]) -> Path:
    path = sidestore.write_table(settings.sidestore_dir, table, "nxos", host, "run-1", rows, 1000)
    assert path is not None
    return path


def _index(settings: Settings, paths: list[Path]) -> manifest.SidestoreFiles:
    return manifest.SidestoreFiles(settings, [manifest.file_entry(settings, p) for p in paths])


def _full(settings: Settings, path: Path) -> Path:
    return settings.hst_data_dir / manifest.file_entry(settings, path).path


def test_a_written_file_records_the_devices_of_its_rows(tmp_path):
    settings = _settings(tmp_path)
    rows = [_arp("dev:b", "10.0.0.2", "aa"), _arp("dev:a", "10.0.0.1", "bb"), _arp("dev:b", "10.0.0.3", "cc")]
    path = _write(settings, "arp", "ctl", rows)

    assert sidestore.written_devices(path) == ("dev:a", "dev:b")
    assert manifest.file_entry(settings, path).device_uids == ["dev:a", "dev:b"]


def test_a_file_this_process_did_not_write_is_read_back_for_its_devices(tmp_path):
    settings = _settings(tmp_path)
    path = _write(settings, "arp", "ctl", [_arp("dev:a", "10.0.0.1", "aa")])
    sidestore._written.clear()

    assert sidestore.written_devices(path) is None
    assert manifest.file_entry(settings, path).device_uids == ["dev:a"]


def test_a_file_without_the_column_records_no_devices(tmp_path):
    path = tmp_path / "other" / "run-1.parquet"
    path.parent.mkdir(parents=True)
    pq.write_table(pa.Table.from_pylist([{"x": 1}], schema=pa.schema([pa.field("x", pa.int64())])), path)

    assert sidestore.file_devices(path) is None


def test_the_index_returns_the_files_of_the_devices_and_every_unlisted_file(tmp_path):
    settings = _settings(tmp_path)
    paths = {d: _write(settings, "mac", d[4:], [_mac(d, "aa", "Eth1")]) for d in ("dev:a", "dev:b", "dev:c")}
    entries = [manifest.file_entry(settings, p) for p in paths.values()]
    entries[2] = entries[2].model_copy(update={"device_uids": None})
    index = manifest.SidestoreFiles(settings, entries)

    unlisted = settings.hst_data_dir / entries[2].path
    assert index.files("mac", ["dev:a"]) == sorted([_full(settings, paths["dev:a"]), unlisted])
    assert index.files("arp", ["dev:a"]) == []
    assert index.files("mac", []) == [unlisted]


def test_query_reads_only_the_files_it_is_given(tmp_path):
    root = tmp_path / "side"
    one = sidestore.write_table(root, "mac", "nxos", "h1", "run-1", [_mac("dev:a", "aa", "Eth1")], 1000)
    sidestore.write_table(root, "mac", "nxos", "h2", "run-1", [_mac("dev:b", "bb", "Eth2")], 1000)
    assert one is not None

    rows = sidestore.query(root, "SELECT device_uid FROM mac", files={"mac": [one]})
    assert [r["device_uid"] for r in rows] == ["dev:a"]
    assert sidestore.query_files(root, "SELECT device_uid FROM mac", "mac", []) == []
    with pytest.raises(ValueError, match="outside the store"):
        sidestore.query(root, "SELECT * FROM mac", files={"mac": [tmp_path / "elsewhere.parquet"]})


class _Session:
    def __init__(self, addresses: list[dict[str, Any]], devices: list[str]) -> None:
        self.addresses, self.devices = addresses, devices

    def run(self, query: str, **params: Any) -> Any:
        outer = self

        class _R:
            def data(self) -> list[dict[str, Any]]:
                if "$edges" in query:
                    return [{"n": len(params["edges"])}]
                if "d.uid AS uid" in query:
                    return [{"uid": u} for u in outer.devices]
                return outer.addresses

        return _R()


_EDGE = [{"ip": "10.9.9.1", "if_uid": "edge:if1", "device_uid": "edge", "port_uid": None}]


def test_the_arp_cable_rule_opens_only_the_files_of_the_devices_in_the_run(tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    arp_a = _write(settings, "arp", "a", [_arp("dev:a", "10.9.9.1", "aabbcc000001")])
    arp_b = _write(settings, "arp", "b", [_arp("dev:b", "10.9.9.1", "aabbcc000001")])
    mac_a = _write(settings, "mac", "a", [_mac("dev:a", "aabbcc000001", "Ethernet1/7")])
    mac_b = _write(settings, "mac", "b", [_mac("dev:b", "aabbcc000001", "Ethernet1/9")])
    index = _index(settings, [arp_a, arp_b, mac_a, mac_b])
    opened: list[Path] = []
    real = sidestore.query

    def spy(base: Path, sql: str, tables: Any = None, files: Any = None) -> list[dict[str, Any]]:
        opened.extend(p for paths in (files or {}).values() for p in paths)
        return real(base, sql, tables, files)

    monkeypatch.setattr(sidestore, "query", spy)
    reasoner.derive_arp_cables(
        _Session(_EDGE, ["dev:a"]),
        collection_ts=1000,
        sidestore_dir=settings.sidestore_dir,
        sidestore_files=index,
    )

    assert sorted(opened) == sorted([_full(settings, arp_a), _full(settings, mac_a)])


def test_the_arp_cable_rule_runs_no_statement_for_devices_with_no_file(tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    index = _index(settings, [_write(settings, "arp", "b", [_arp("dev:b", "10.9.9.1", "aa")])])
    monkeypatch.setattr(sidestore, "query", lambda *a, **k: pytest.fail("a statement ran"))

    report = reasoner.derive_arp_cables(
        _Session(_EDGE, ["dev:a"]),
        collection_ts=1000,
        sidestore_dir=settings.sidestore_dir,
        sidestore_files=index,
    )

    assert report["edges"] == 0 and "not_evaluated" not in report


def test_the_mac_corroboration_reads_the_mac_files_of_the_devices_it_names(tmp_path):
    settings = _settings(tmp_path)
    index = _index(
        settings,
        [_write(settings, "mac", d[4:], [_mac(d, "aa", "Eth1")]) for d in ("dev:a", "dev:b", "dev:c")],
    )

    rows = reasoner.read_mac_rows(settings.sidestore_dir, ["dev:a", "dev:b"], 1000, index)

    assert {r["device_uid"] for r in rows} == {"dev:a", "dev:b"}
    assert reasoner.read_mac_rows(settings.sidestore_dir, ["dev:z"], 1000, index) == []


def test_finalize_hands_the_index_to_the_two_side_store_readers(tmp_path):
    seen: dict[str, Any] = {}

    class _Rules:
        def run(self, session: Any, collection_ts: int | None = None) -> list[dict]:
            return []

        def derive_arp_cables(
            self, session: Any, *, collection_ts: int, sidestore_dir: Any, sidestore_files: Any = None
        ) -> dict:
            seen["arp"] = sidestore_files
            return {"rule": "cable-from-arp-port", "edges": 0}

        def check_vlan_stretch(
            self, session: Any, *, collection_ts: int, sidestore_dir: Any = None, sidestore_files: Any = None
        ) -> dict:
            seen["stretch"] = sidestore_files
            return {"observations": [], "warnings": [], "unbound_ports": [], "uncarried": 0}

    class _RouteTargets:
        def execute_rt_domains(self, session: Any, settings: Settings, collection_ts: int | None = None):
            return RunManifest(run_id="rt-d", source="reasoner", scope="rt-domains")

        def execute_link_speed(self, session: Any, settings: Settings, collection_ts: int | None = None):
            return RunManifest(run_id="ls", source="reasoner", scope="link-speed")

    class _Cycle:
        def apply_site_assignments(self, session: Any, assigned: Any, cts: int | None = None) -> int:
            return 0

    settings = _settings(tmp_path)
    index = manifest.SidestoreFiles(settings, [])
    finalize_derivations(
        object(),
        settings,
        1000,
        {},
        rules=_Rules(),
        route_targets=_RouteTargets(),
        cycle=_Cycle(),
        sidestore_files=index,
    )

    assert seen == {"arp": index, "stretch": index}
