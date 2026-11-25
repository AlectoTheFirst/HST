"""Envelope keys and the raw snapshot store.

A snapshot is whatever the device returned. On VyOS `show configuration json` is the
entire running config, so snapshots are sealed under the data key.
"""

from __future__ import annotations

import json
import stat

import pytest

from hst.app.crypto import (
    DEK_FILENAME,
    SecretKeyError,
    decrypt_secrets,
    dek,
    encrypt_secrets,
    generate_key,
    rewrap_dek,
)
from hst.core import rawstore
from hst.core.config import Settings

SECRETS = {"auth.password": "hunter2", "auth.token": "abc123"}


def _settings(tmp_path, **kw) -> Settings:
    return Settings(_env_file=None, hst_data_dir=tmp_path, **kw)


# --- envelope: KEK unwraps DEK -----------------------------------------------------


def test_the_data_key_round_trips_secrets(tmp_path):
    key = dek(_settings(tmp_path, hst_secret_key=generate_key()))
    assert decrypt_secrets(key, encrypt_secrets(key, SECRETS)) == SECRETS


def test_first_use_creates_the_wrapped_key_file_privately(tmp_path):
    s = _settings(tmp_path, hst_secret_key=generate_key())
    first = dek(s)
    path = tmp_path / DEK_FILENAME
    assert path.is_file()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert dek(s) == first  # stable across calls


def test_the_kek_never_appears_in_the_wrapped_file(tmp_path):
    kek = generate_key()
    dek(_settings(tmp_path, hst_secret_key=kek))
    stored = (tmp_path / DEK_FILENAME).read_bytes()
    assert kek.encode() not in stored


def test_a_missing_key_fails_closed(tmp_path):
    with pytest.raises(SecretKeyError, match="HST_SECRET_KEY"):
        dek(_settings(tmp_path))


def test_a_short_key_fails_closed(tmp_path):
    with pytest.raises(SecretKeyError, match="32"):
        dek(_settings(tmp_path, hst_secret_key="too-short"))


def test_a_wrong_key_cannot_unwrap(tmp_path):
    dek(_settings(tmp_path, hst_secret_key=generate_key()))
    with pytest.raises(SecretKeyError):
        dek(_settings(tmp_path, hst_secret_key=generate_key()))


def test_the_key_can_come_from_a_file(tmp_path):
    kek = generate_key()
    created = dek(_settings(tmp_path, hst_secret_key=kek))
    key_file = tmp_path / "kek.txt"
    key_file.write_text(kek + "\n")  # trailing newline must not matter
    via_file = dek(_settings(tmp_path, hst_secret_key_file=str(key_file)))
    assert via_file == created


def test_the_file_wins_over_the_environment_value(tmp_path):
    kek = generate_key()
    created = dek(_settings(tmp_path, hst_secret_key=kek))
    key_file = tmp_path / "kek.txt"
    key_file.write_text(kek)
    s = _settings(tmp_path, hst_secret_key="wrong-but-ignored", hst_secret_key_file=str(key_file))
    assert dek(s) == created


def test_an_unreadable_key_file_fails_closed(tmp_path):
    s = _settings(tmp_path, hst_secret_key_file=str(tmp_path / "missing"))
    with pytest.raises(SecretKeyError, match="HST_SECRET_KEY_FILE"):
        dek(s)


def test_rotation_rewraps_the_dek_and_retires_the_old_kek(tmp_path):
    old_kek, new_kek = generate_key(), generate_key()
    s_old = _settings(tmp_path, hst_secret_key=old_kek)
    key = dek(s_old)
    blob = encrypt_secrets(key, SECRETS)

    rewrap_dek(s_old, new_kek)

    s_new = _settings(tmp_path, hst_secret_key=new_kek)
    assert dek(s_new) == key  # same data key: nothing needs re-encrypting
    assert decrypt_secrets(dek(s_new), blob) == SECRETS
    with pytest.raises(SecretKeyError):  # the old KEK no longer opens anything
        dek(s_old)


def test_rotation_refuses_a_short_new_key(tmp_path):
    s = _settings(tmp_path, hst_secret_key=generate_key())
    dek(s)
    with pytest.raises(SecretKeyError, match="32"):
        rewrap_dek(s, "short")


def test_encrypting_without_a_key_is_an_error_not_a_silent_plaintext_write():
    with pytest.raises(SecretKeyError):
        encrypt_secrets("", SECRETS)


# --- raw store ---------------------------------------------------------------------

PAYLOAD = {"config": {"interfaces": {"wireguard": {"wg0": {"private-key": "SECRET"}}}}}


def _key(tmp_path) -> str:
    return dek(_settings(tmp_path, hst_secret_key=generate_key()))


def test_a_snapshot_is_not_world_readable(tmp_path):
    path = rawstore.write(tmp_path, "vyos", "run-1", PAYLOAD, key=_key(tmp_path))
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700


def test_an_encrypted_snapshot_does_not_contain_the_secret(tmp_path):
    path = rawstore.write(tmp_path, "vyos", "run-1", PAYLOAD, key=_key(tmp_path))
    assert path.name.endswith(rawstore.SUFFIX)
    assert b"SECRET" not in path.read_bytes()
    assert b"wireguard" not in path.read_bytes()


def test_round_trip_through_the_key(tmp_path):
    key = _key(tmp_path)
    path = rawstore.write(tmp_path, "vyos", "run-1", PAYLOAD, key=key)
    assert rawstore.read(path, key) == PAYLOAD


def test_the_wrong_key_cannot_read_a_snapshot(tmp_path):
    path = rawstore.write(tmp_path, "vyos", "run-1", PAYLOAD, key=_key(tmp_path / "a"))
    with pytest.raises(SecretKeyError):
        rawstore.read(path, _key(tmp_path / "b"))


# --- run identity and file layout -------------------------------------------------


def test_two_devices_of_one_source_write_under_different_host_directories(tmp_path):
    key = _key(tmp_path)
    a = rawstore.write(tmp_path, "vyos1", "1000-aaaaaaaa", PAYLOAD, host="10.0.0.1", key=key)
    b = rawstore.write(tmp_path, "vyos1", "1000-bbbbbbbb", PAYLOAD, host="10.0.0.2", key=key)
    assert a == tmp_path / "vyos1" / "10.0.0.1" / "1000-aaaaaaaa.json.gz.enc"
    assert b == tmp_path / "vyos1" / "10.0.0.2" / "1000-bbbbbbbb.json.gz.enc"
    assert a.parent != b.parent


def test_two_sources_of_one_collector_type_write_under_different_source_directories(tmp_path):
    """`source` is the source ROW name, not the collector type: two rows of
    the same type (e.g. two vyos boxes configured as separate sources) never
    share a directory."""
    key = _key(tmp_path)
    a = rawstore.write(tmp_path, "vyos-hq", "1000-aaaaaaaa", PAYLOAD, key=key)
    b = rawstore.write(tmp_path, "vyos-branch", "1000-aaaaaaaa", PAYLOAD, key=key)
    assert a.parent != b.parent
    assert a == tmp_path / "vyos-hq" / "1000-aaaaaaaa.json.gz.enc"
    assert b == tmp_path / "vyos-branch" / "1000-aaaaaaaa.json.gz.enc"


def test_empty_host_collapses_the_directory_segment(tmp_path):
    """A controller-type source has no device to nest under; the host
    directory level does not exist."""
    path = rawstore.write(tmp_path, "apic1", "1000-aaaaaaaa", PAYLOAD, key=_key(tmp_path))
    assert path == tmp_path / "apic1" / "1000-aaaaaaaa.json.gz.enc"
    assert path.parent == tmp_path / "apic1"


def test_source_and_host_are_slugged_for_the_filesystem(tmp_path):
    path = rawstore.write(tmp_path, "VyOS HQ", "1000-aaaaaaaa", PAYLOAD, host="fd00::1", key=_key(tmp_path))
    assert "/" not in path.relative_to(tmp_path).parts[0]
    assert path == tmp_path / "vyos-hq" / "fd00-1" / "1000-aaaaaaaa.json.gz.enc"


# --- join sidecar and parking ------------------------------------------------------


def test_mark_joined_writes_the_snapshot_ts_sidecar(tmp_path):
    path = rawstore.write(tmp_path, "vyos1", "1000-aaaaaaaa", PAYLOAD, key=_key(tmp_path))
    rawstore.mark_joined(path, snapshot_ts=42)
    meta = path.with_name("1000-aaaaaaaa.meta.json")
    assert meta.is_file()
    assert json.loads(meta.read_text()) == {"snapshot_ts": 42}


def test_mark_joined_refuses_to_overwrite_an_existing_sidecar(tmp_path):
    path = rawstore.write(tmp_path, "vyos1", "1000-aaaaaaaa", PAYLOAD, key=_key(tmp_path))
    rawstore.mark_joined(path, snapshot_ts=42)
    with pytest.raises(FileExistsError):
        rawstore.mark_joined(path, snapshot_ts=99)
    meta = path.with_name("1000-aaaaaaaa.meta.json")
    assert json.loads(meta.read_text()) == {"snapshot_ts": 42}  # unchanged


def test_parked_finds_a_raw_file_with_no_sidecar_and_excludes_a_joined_one(tmp_path):
    key = _key(tmp_path)
    parked_path = rawstore.write(
        tmp_path, "vyos1", "1700000000000-aaaaaaaa", PAYLOAD, host="10.0.0.1", key=key
    )
    joined_path = rawstore.write(
        tmp_path, "vyos1", "1700000001000-bbbbbbbb", PAYLOAD, host="10.0.0.1", key=key
    )
    rawstore.mark_joined(joined_path, snapshot_ts=2000)

    out = rawstore.parked(tmp_path)
    assert [p.run_id for p in out] == ["1700000000000-aaaaaaaa"]
    only = out[0]
    assert only.path == parked_path
    assert only.source == "vyos1"
    assert only.host == "10.0.0.1"
    assert only.fetch_ts_ms == 1700000000000


def test_parked_filters_to_one_source_when_given(tmp_path):
    key = _key(tmp_path)
    rawstore.write(tmp_path, "vyos1", "1700000000000-aaaaaaaa", PAYLOAD, host="h1", key=key)
    rawstore.write(tmp_path, "vyos2", "1700000000000-bbbbbbbb", PAYLOAD, host="h1", key=key)

    assert [p.source for p in rawstore.parked(tmp_path, "vyos1")] == ["vyos1"]
    assert {p.source for p in rawstore.parked(tmp_path)} == {"vyos1", "vyos2"}


def test_parked_lists_a_host_less_controller_payload_a_fetch_parked(tmp_path):
    """A scheduled fetch of a controller-type source parks directly under the
    source directory, with the kind sidecar `park` writes: it is listed with
    host "" so the device-run builder joins it."""
    path = rawstore.write(tmp_path, "apic1", "1000-aaaaaaaa", PAYLOAD, key=_key(tmp_path))
    rawstore.mark_kind(path, rawstore.KIND_FULL)

    (found,) = rawstore.parked(tmp_path)
    assert (found.path, found.source, found.host, found.run_id) == (path, "apic1", "", "1000-aaaaaaaa")
    assert [p.path for p in rawstore.parked(tmp_path, "apic1")] == [path]

    rawstore.mark_joined(path, snapshot_ts=2000)
    assert rawstore.parked(tmp_path) == []


def test_parked_ignores_a_host_less_file_that_no_fetch_parked(tmp_path):
    """A cycle joins its own controller payload as it loads it, and the IPAdmin
    import seals its export directly under its source directory: neither
    carries the park-time kind sidecar, so neither is a parked fetch."""
    rawstore.write(tmp_path, "apic1", "1000-aaaaaaaa", PAYLOAD, key=_key(tmp_path))
    assert rawstore.parked(tmp_path) == []


def test_parked_skips_a_file_whose_stem_is_not_a_fetch_time_run_id(tmp_path):
    """A file sharing this directory tree for an unrelated reason (e.g.
    collectors/checkpoint.py's replay cache, which nests two levels deep the
    same way a real parked payload would) is never read as one:
    only a stem that parses as <fetch_ts_ms>-<nonce> counts."""
    directory = tmp_path / "checkpoint" / "replay-cache"
    directory.mkdir(parents=True)
    (directory / f"some-layer-uid{rawstore.SUFFIX}").write_bytes(b"not a real snapshot")
    assert rawstore.parked(tmp_path) == []


def test_parked_on_nonexistent_dir_returns_empty(tmp_path):
    assert rawstore.parked(tmp_path / "does-not-exist") == []
