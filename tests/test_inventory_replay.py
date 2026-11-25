"""A v2 archive replays its captured identity and placement without current intent."""

from types import SimpleNamespace

import pytest
from tests.test_grapharchive import RestoreSession, SourceSession, _settings

from hst.app.crypto import dek, generate_key
from hst.core import grapharchive, manifest, replay


def test_inventory_archive_keeps_captured_routing_and_placement_after_current_defaults_change(
    tmp_path, monkeypatch
):
    settings = _settings(tmp_path).model_copy(update={"hst_secret_key": generate_key()})
    key = dek(settings)
    captured = {
        "resolver_version": "2",
        "placement_generation": 7,
        "placement_revisions": {"dev:one": 3},
        "sources": {
            "lab": {"profile_revision": 4, "credential_revision": 2, "routing_scope": "legacy-scope"}
        },
    }
    source = SourceSession(
        [
            {
                "uid": "dev:one",
                "labels": ["Device", "Obj"],
                "props": {"uid": "dev:one", "collection_ts": 100, "hostname": "one"},
            },
            {
                "uid": "prefix:legacy-scope:192.0.2.0/24",
                "labels": ["Prefix", "Obj"],
                "props": {"uid": "prefix:legacy-scope:192.0.2.0/24", "collection_ts": 100},
            },
        ],
        [],
    )
    entry = grapharchive.write(source, settings, 100, key, normalization_context=captured)
    archive = manifest.GraphArchiveEntry.model_validate(entry)
    monkeypatch.setattr(replay.manifestmod, "read", lambda *args: SimpleNamespace(graph_archive=archive))
    monkeypatch.setattr(replay, "_clear_target", lambda target: 0)
    monkeypatch.setattr(replay, "_publish", lambda *args, **kwargs: None)
    current_settings = settings.model_copy(update={"l2_fabrics": {"new-fabric": ["lab"]}})
    target = RestoreSession()
    result = replay.rebuild_from_manifest(
        current_settings,
        target,
        100,
        source_for=lambda name: pytest.fail("archive replay consulted current profile/configuration"),
    )
    assert result.exact
    assert archive.normalization_context == captured
    restored = [row for _, params in target.writes for row in params["rows"]]
    assert any(row.get("props", row).get("uid") == "prefix:legacy-scope:192.0.2.0/24" for row in restored)
