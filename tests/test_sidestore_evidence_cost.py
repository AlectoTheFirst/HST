"""What the side-store readers cost a request, in manifests read and manifest scans."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from hst.core import manifest as manifestmod
from hst.core import ribsource
from hst.core.ospfsource import OspfSource
from hst.core.ribsource import RibSource, snapshot_evidence


class _CountedList(list):
    """A file list that counts how often it is iterated."""

    scans = 0

    def __iter__(self):
        type(self).scans += 1
        return super().__iter__()


def _entry(source, host, run_id, *, carried=False, uids=(), status="complete", table="rib"):
    tables = {table: SimpleNamespace(status=status)} if status else {}
    return SimpleNamespace(
        source=source,
        host=host,
        effective_run=run_id,
        carried=carried,
        tables=tables,
        device_uids=list(uids),
    )


def _file(source, host, run_id, table="rib"):
    return SimpleNamespace(
        kind="sidestore",
        table=table,
        run_id=run_id,
        source=source,
        host=host,
        path=f"sidestore/{table}/{source}/{host}/{run_id}.parquet",
    )


def _record(key, parent, devices, files):
    return SimpleNamespace(snapshot_key=key, parent=parent, devices=devices, files=_CountedList(files))


def _settings(tmp_path: Path) -> Any:
    return SimpleNamespace(
        hst_data_dir=tmp_path,
        sidestore_dir=tmp_path / "sidestore",
        manifests_dir=tmp_path / "manifests",
    )


def _chain(monkeypatch, records: dict[int, Any]) -> list[int]:
    """Serve `records` as the manifests of the chain, and count the reads."""
    reads: list[int] = []

    def read(settings: Any, key: int) -> Any:
        reads.append(key)
        if key not in records:
            raise OSError(key)
        return records[key]

    monkeypatch.setattr(manifestmod, "read", read)
    return reads


def _history(depth: int, newest_devices: list[Any], newest_files: list[Any]) -> dict[int, Any]:
    """A chain of `depth` manifests, each the parent of the next; the older
    ones hold only a VyOS unit that publishes its rib every run."""
    records: dict[int, Any] = {}
    for key in range(1, depth):
        run = f"{key}-vyos"
        records[key] = _record(
            key, key - 1 if key > 1 else None, [_entry("vyos", "r1", run)], [_file("vyos", "r1", run)]
        )
    records[depth] = _record(depth, depth - 1, newest_devices, newest_files)
    return records


def _unifi_and_vyos(depth: int) -> tuple[dict[int, Any], Any]:
    run = f"{depth}-vyos"
    devices = [
        _entry("vyos", "r1", run, uids=["dev:vyos-r1"]),
        _entry("unifi", "ctl", f"{depth}-unifi", uids=["dev:unifi-gw"], status="unsupported"),
    ]
    records = _history(depth, devices, [_file("vyos", "r1", run)])
    return records, records[depth]


def test_a_device_with_no_rib_table_is_answered_without_reading_the_chain(monkeypatch, tmp_path):
    records, head = _unifi_and_vyos(50)
    reads = _chain(monkeypatch, records)
    evidence = snapshot_evidence(_settings(tmp_path), 50, manifest=head)
    rib = RibSource(tmp_path / "sidestore", as_of_ms=50, evidence=evidence)
    assert rib.coverage("dev:unifi-gw") == "unsupported"
    assert reads == []


def test_the_ospf_reader_answers_a_device_with_no_lsdb_without_reading_the_chain(monkeypatch, tmp_path):
    run = "50-vyos"
    devices = [
        _entry("vyos", "r1", run, uids=["dev:vyos-r1"], table="ospf_lsdb"),
        _entry("unifi", "ctl", "50-unifi", uids=["dev:unifi-gw"], status="unsupported", table="ospf_lsdb"),
    ]
    records = _history(50, devices, [_file("vyos", "r1", run, "ospf_lsdb")])
    reads = _chain(monkeypatch, records)
    evidence = snapshot_evidence(_settings(tmp_path), 50, manifest=records[50], table="ospf_lsdb")
    ospf = OspfSource(tmp_path / "sidestore", as_of_ms=50, evidence=evidence)
    assert ospf.coverage("dev:unifi-gw") == "unsupported"
    assert reads == []


def test_a_uid_two_units_list_answers_with_the_outcome_that_says_the_least_was_read(monkeypatch, tmp_path):
    """A Nautobot inventory unit and the CLI collector list the same device:
    the inventory unit's outcome must not mask a failed collection, whichever
    of the two the manifest lists last."""
    for order in (("vyos", "nautobot"), ("nautobot", "vyos")):
        statuses = {"vyos": "failed", "nautobot": "unsupported"}
        devices = [
            _entry(name, "h", f"60-{name}", uids=["dev:shared"], status=statuses[name]) for name in order
        ]
        records = {60: _record(60, None, devices, [])}
        _chain(monkeypatch, records)
        evidence = snapshot_evidence(_settings(tmp_path), 60, manifest=records[60])
        rib = RibSource(tmp_path / "sidestore", as_of_ms=60, evidence=evidence)
        assert rib.coverage("dev:shared") == "failed"


def test_an_entry_with_no_recorded_uids_is_joined_through_a_bounded_walk(monkeypatch, tmp_path):
    """The walk stops after `ORPHAN_WALK_MAX` manifests."""
    devices = [
        _entry("vyos", "r1", "50-vyos"),
        _entry("unifi", "ctl", "50-unifi", status="unsupported"),
    ]
    records = _history(50, devices, [_file("vyos", "r1", "50-vyos")])
    reads = _chain(monkeypatch, records)
    evidence = snapshot_evidence(_settings(tmp_path), 50, manifest=records[50])
    rib = RibSource(tmp_path / "sidestore", as_of_ms=50, evidence=evidence)
    monkeypatch.setattr(rib, "_connect", lambda: object())
    monkeypatch.setattr(rib, "_latest_run_id", lambda con, uid: None)
    monkeypatch.setattr(rib, "_device_uids", lambda con, path: [])
    reads.clear()
    assert rib.coverage("dev:unifi-gw") is None
    assert len(reads) <= ribsource.ORPHAN_WALK_MAX


def test_the_evidence_of_400_carried_devices_scans_each_manifest_once(monkeypatch, tmp_path):
    """D devices carried from the previous snapshot: the evidence reads the
    files of the pinned manifest and of its parent a fixed number of times,
    not once per device."""
    count = 400
    parent_devices = [_entry("s", f"h{i}", f"1-{i}") for i in range(count)]
    parent_files = [_file("s", f"h{i}", f"1-{i}") for i in range(count)]
    head_devices = [
        _entry("s", f"h{i}", f"1-{i}", carried=True, status="unchanged", uids=[f"dev:{i}"])
        for i in range(count)
    ]
    records = {
        1: _record(1, None, parent_devices, parent_files),
        2: _record(2, 1, head_devices, list(parent_files)),
    }
    _chain(monkeypatch, records)
    _CountedList.scans = 0
    evidence = snapshot_evidence(_settings(tmp_path), 2, manifest=records[2])
    assert evidence is not None
    assert len(evidence.devices) == count
    assert {d.outcome for d in evidence.devices} == {"missing"}
    assert _CountedList.scans <= 4


def test_the_bgp_evidence_of_400_devices_scans_the_manifest_files_once(tmp_path):
    """The BGP evidence of D devices scans the manifest's files a fixed number of times."""
    from hst.core import bgpsource

    count = 400
    devices = [
        _entry("s", f"h{i}", f"1-{i}", uids=[f"dev:{i}"], table=bgpsource.SESSIONS) for i in range(count)
    ]
    files = [_file("s", f"h{i}", f"1-{i}", bgpsource.SESSIONS) for i in range(count)]
    record = _record(1, None, devices, files)
    for entry in devices:
        entry.tables[bgpsource.ROUTES] = SimpleNamespace(status="unsupported")
    _CountedList.scans = 0

    evidence = bgpsource.snapshot_evidence(_settings(tmp_path), 1, manifest=record)

    assert evidence is not None
    assert len(evidence.devices[bgpsource.SESSIONS]) == count
    assert {d.outcome for d in evidence.devices[bgpsource.SESSIONS]} == {"missing"}
    assert _CountedList.scans <= 2


def test_a_snapshot_builds_its_completeness_and_each_evidence_once():
    from hst.core.snapshot import Snapshot

    entry = SimpleNamespace(
        source="s", host="h", outcome="collected", effective_run="1-a", carried=False, sections={}, tables={}
    )
    snapshot = Snapshot(7, SimpleNamespace(manifests_dir=None))
    snapshot._manifest, snapshot._manifest_read = SimpleNamespace(devices=[entry]), True

    assert snapshot.completeness() is snapshot.completeness()
    assert snapshot.device_completeness("s", "h") is snapshot.completeness()["s/h"]
    built = []
    assert snapshot.evidence("rib", lambda: built.append(1) or "x") == "x"
    assert snapshot.evidence("rib", lambda: built.append(1) or "y") == "x"
    assert built == [1]


def test_the_outcome_of_a_carried_device_is_the_collecting_runs(monkeypatch, tmp_path):
    parent = _record(1, None, [_entry("s", "h", "1-a", status="failed")], [_file("s", "h", "1-a")])
    carried = _entry("s", "h", "1-a", carried=True, status="unchanged")
    head = _record(2, 1, [carried], [_file("s", "h", "1-a")])
    _chain(monkeypatch, {1: parent, 2: head})
    evidence = snapshot_evidence(_settings(tmp_path), 2, manifest=head)
    assert evidence is not None
    [device] = evidence.devices
    assert device.outcome == "failed"


def _carried_for(depth: int, status: str = "partial") -> dict[int, Any]:
    """A device collected by the first run (with `status`) and carried by each
    of the `depth` - 1 runs after it, each of which copies its file entry."""
    collected = _entry("s", "h", "1-a", status=status, uids=["dev:a"])
    records = {1: _record(1, None, [collected], [_file("s", "h", "1-a")])}
    for key in range(2, depth + 1):
        carried = _entry("s", "h", "1-a", carried=True, status="unchanged", uids=["dev:a"])
        copied = SimpleNamespace(**vars(_file("s", "h", "1-a")), carried=True)
        records[key] = _record(key, key - 1, [carried], [copied])
    return records


def _on_disk(tmp_path: Path) -> None:
    path = tmp_path / _file("s", "h", "1-a").path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"")


def test_a_device_carried_beyond_the_walk_bound_reads_a_bounded_chain_and_is_unknown(monkeypatch, tmp_path):
    """The walk back to the collecting manifest stops at `EVIDENCE_WALK_MAX` manifests."""
    depth = ribsource.EVIDENCE_WALK_MAX + 100
    records = _carried_for(depth)
    reads = _chain(monkeypatch, records)
    _on_disk(tmp_path)
    evidence = snapshot_evidence(_settings(tmp_path), depth, manifest=records[depth])
    assert evidence is not None
    [device] = evidence.devices
    assert device.outcome == "unknown"
    assert device.path is not None
    assert "beyond" in device.detail
    assert len(reads) < ribsource.EVIDENCE_WALK_MAX


def test_a_device_carried_within_the_walk_bound_keeps_the_collecting_runs_outcome(monkeypatch, tmp_path):
    depth = ribsource.EVIDENCE_WALK_MAX
    records = _carried_for(depth)
    _chain(monkeypatch, records)
    _on_disk(tmp_path)
    evidence = snapshot_evidence(_settings(tmp_path), depth, manifest=records[depth])
    assert evidence is not None
    [device] = evidence.devices
    assert device.outcome == "partial"
