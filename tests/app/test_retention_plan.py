"""`retention.plan`: what every prune path keeps at one moment."""

from __future__ import annotations

from hst.app import retention
from hst.core import Settings
from hst.core import manifest as manifestmod


def _manifest(settings, key, *, files=(), devices=()):
    manifestmod.write(
        settings,
        manifestmod.SnapshotManifest(
            snapshot_key=key,
            kind="full",
            opened=manifestmod.iso(key),
            published=manifestmod.now_iso(),
            files=list(files),
            devices=list(devices),
        ),
    )


def _file(source, host, run_id):
    return manifestmod.FileEntry(
        kind="raw", path="x", sha256="0" * 64, bytes=1, source=source, host=host, run_id=run_id
    )


def test_a_run_is_kept_when_the_graph_an_assessment_or_a_reader_holds_it(tmp_path):
    settings = Settings(_env_file=None, hst_data_dir=tmp_path)
    for key in (10, 20, 30, 40):
        _manifest(settings, key)

    plan = retention.plan(settings, window=[40], refs=[30], leased=[20])

    assert plan.kept == {20, 30, 40}
    assert plan.keeps(30, ("s", "h", "x")) and plan.keeps(20, ("s", "h", "x"))
    assert not plan.keeps(10, ("s", "h", "x"))


def test_the_manifest_of_a_kept_run_protects_its_files_and_the_devices_it_stands_on(tmp_path):
    settings = Settings(_env_file=None, hst_data_dir=tmp_path)
    carried = manifestmod.DeviceEntry(
        source="Edge Router", host="10.0.0.1", outcome="carried", effective_run="5-aaaaaaaa", carried=True
    )
    _manifest(settings, 40, files=[_file("src", "h1", "7-bbbbbbbb")], devices=[carried])

    plan = retention.plan(settings, window=[40])

    assert plan.keeps(7, ("src", "h1", "7-bbbbbbbb"))
    # a device's source and host are slugged to the directory form a file carries
    assert plan.keeps(5, (retention.slug("Edge Router"), retention.slug("10.0.0.1"), "5-aaaaaaaa"))
    assert not plan.keeps(6, ("src", "h1", "6-cccccccc"))


def test_the_manifest_chain_behind_a_reference_protects_nothing(tmp_path):
    settings = Settings(_env_file=None, hst_data_dir=tmp_path)
    _manifest(settings, 10, files=[_file("src", "h1", "10-aaaaaaaa")])
    manifestmod.write(
        settings,
        manifestmod.SnapshotManifest(
            snapshot_key=20,
            kind="full",
            opened=manifestmod.iso(20),
            published=manifestmod.now_iso(),
            previous=manifestmod.PreviousLink(
                snapshot_key=10, sha256=manifestmod.digest_of(settings, 10), chain_index=1
            ),
        ),
    )

    _manifest(settings, 30)

    plan = retention.plan(settings, window=[30], refs=[20])

    assert not plan.keeps(10, ("src", "h1", "10-aaaaaaaa"))


def test_a_kept_run_without_a_manifest_protects_every_file_up_to_its_key(tmp_path):
    settings = Settings(_env_file=None, hst_data_dir=tmp_path)
    _manifest(settings, 30)

    plan = retention.plan(settings, window=[40, 30])

    assert plan.unmanifested == (40,)
    assert plan.floor == 40
    assert plan.keeps(35, ("s", "h", "x")) and plan.keeps(40, ("s", "h", "x"))


def test_a_file_above_the_newest_kept_run_belongs_to_a_run_in_flight(tmp_path):
    settings = Settings(_env_file=None, hst_data_dir=tmp_path)
    _manifest(settings, 30)

    plan = retention.plan(settings, window=[30])

    assert plan.ceiling == 30
    assert plan.keeps(31, ("s", "h", "x"))
    assert not plan.keeps(29, ("s", "h", "x"))


def test_an_empty_plan_keeps_nothing_and_names_no_ceiling(tmp_path):
    plan = retention.plan(Settings(_env_file=None, hst_data_dir=tmp_path), window=[])

    assert plan.kept == frozenset() and plan.ceiling is None and plan.floor is None
    assert not plan.keeps(1, ("s", "h", "x"))
