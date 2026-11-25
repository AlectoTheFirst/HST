"""The raw store seals a payload without building its JSON whole, in the one
container every reader reads (core/rawstore.py `write`).

A raw file is one Fernet token over a gzip member whose content is
`json.dumps(payload, default=str)`. Every reader, the replay, and the evidence
checks read that container, so the streamed seal must decompress to exactly
those bytes: the golden `raw_json_sha` of every case pins them. The file is
written under a temporary name and renamed, so a failed or killed write never
leaves a truncated file under a name the readers list.
"""

from __future__ import annotations

import gc
import gzip
import hashlib
import json
import stat
import tracemalloc
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError
from tests.support.synthetic_payloads import (
    CASES,
    base_spelling,
    case_payload,
    iosxe_payload,
    load_golden,
    split_case,
)

from hst import collectors as coll
from hst.app.crypto import SecretKeyError, TokenWriter, decrypt, encrypt, generate_key
from hst.collectors.base import RAW_OUTCOMES_KEY, Collector, SourceConfig
from hst.collectors.util import GraphBuilder
from hst.core import Settings, rawstore

GOLDEN = load_golden()
KEY = Fernet.generate_key().decode()
RUN_ID = "1700000000000-aaaaaaaa"


def _content(path: Path) -> bytes:
    """The JSON bytes a sealed raw file holds."""
    return gzip.decompress(decrypt(KEY, path.read_bytes()))


class _Shown:
    """A value `json.dumps` encodes only through `default=str`."""

    def __str__(self) -> str:
        return "shown \u2603"


def _mixed_payload() -> dict[Any, Any]:
    return {
        "show version": (
            'Cisco IOS XE Z\xfcrich \u2603 \u03a9 \ufffd \U0001f600 \u2028 tab\t "q" back\\slash\r\n'
        ),
        "show clock": "",
        "seen": datetime(2026, 9, 1, 12, 30, tzinfo=UTC),
        "amount": Decimal("1.10"),
        "object": _Shown(),
        "nested": {"a": [1, 2.5, None, True, {"b": ["c", {"d": "\ufffd"}]}], "": "empty key", 7: "int key"},
        "tuple": (1, "two"),
        # A VyOS `show configuration json` answer is a parsed tree, not text.
        "config": {
            "interfaces": {
                "ethernet": {
                    "eth0": {"address": ["192.0.2.1/24", "2001:db8::1/64"], "description": "WAN \u2603"},
                    "eth1": {"address": ["dhcp"], "vif": {"10": {"address": ["10.0.10.1/24"]}}},
                },
                "wireguard": {
                    "wg0": {"private-key": "c2VjcmV0", "peer": {"hub": {"allowed-ips": ["0.0.0.0/0"]}}}
                },
            },
            "protocols": {"bgp": {"system-as": "65001", "neighbor": {"192.0.2.2": {"remote-as": "65002"}}}},
        },
        RAW_OUTCOMES_KEY: {"show clock": {"status": "ok"}},
    }


# --- the container ----------------------------------------------------------------------


def test_a_payload_of_every_kind_round_trips(tmp_path):
    payload = _mixed_payload()
    path = rawstore.write(tmp_path, "vyos1", RUN_ID, payload, host="r1", key=KEY)

    assert path == tmp_path / "vyos1" / "r1" / f"{RUN_ID}{rawstore.SUFFIX}"
    assert _content(path) == json.dumps(payload, default=str).encode()
    assert rawstore.read(path, KEY) == json.loads(json.dumps(payload, default=str))
    assert list(path.parent.iterdir()) == [path]


def test_a_payload_that_is_not_a_mapping_round_trips(tmp_path):
    payload = ["show version", {"b": "\ufffd"}, 3, None, datetime(2026, 1, 1, tzinfo=UTC)]
    path = rawstore.write(tmp_path, "src", RUN_ID, payload, key=KEY)

    assert _content(path) == json.dumps(payload, default=str).encode()
    assert rawstore.read(path, KEY) == json.loads(json.dumps(payload, default=str))


@pytest.mark.parametrize("key", CASES)
def test_every_golden_case_seals_its_golden_json(key, tmp_path):
    # the golden JSON is of the payload in the spelling of the base record
    payload = base_spelling(split_case(key)[0], case_payload(key))
    path = rawstore.write(tmp_path, "edge", RUN_ID, payload, host="edge1", key=KEY)

    content = _content(path)
    assert hashlib.sha256(content).hexdigest() == GOLDEN["cases"][key]["raw_json_sha"]
    assert content == json.dumps(payload, default=str).encode()


def test_the_container_is_one_fernet_token_over_one_gzip_member(tmp_path):
    payload = case_payload("iosxr/small/plain")
    path = rawstore.write(tmp_path, "edge", RUN_ID, payload, host="edge1", key=KEY)

    blob = decrypt(KEY, path.read_bytes())
    assert blob[:3] == b"\x1f\x8b\x08"  # gzip magic, deflate
    assert gzip.decompress(blob) == json.dumps(payload, default=str).encode()


def test_level_1_and_level_9_both_read_back_and_differ_in_size(tmp_path):
    payload = case_payload("iosxe/small/plain")
    fast = rawstore.write(tmp_path, "edge", "1700000000001-aaaaaaaa", payload, host="edge1", key=KEY, level=1)
    small = rawstore.write(
        tmp_path, "edge", "1700000000009-aaaaaaaa", payload, host="edge1", key=KEY, level=9
    )
    level_6 = rawstore.write(
        tmp_path, "edge", "1700000000006-aaaaaaaa", payload, host="edge1", key=KEY, level=6
    )
    default = rawstore.write(tmp_path, "edge", "1700000000010-aaaaaaaa", payload, host="edge1", key=KEY)

    assert rawstore.read(fast, KEY) == rawstore.read(small, KEY) == payload
    assert _content(fast) == _content(small) == _content(default)
    assert len(decrypt(KEY, fast.read_bytes())) > len(decrypt(KEY, small.read_bytes()))
    assert decrypt(KEY, default.read_bytes()) == decrypt(KEY, level_6.read_bytes())
    assert rawstore.DEFAULT_COMPRESS_LEVEL == 6


def test_a_token_over_gzip_compress_output_reads_back(tmp_path):
    """`read` opens one Fernet token over `gzip.compress` output at its default
    level as it opens a streamed write, and both hold the same JSON."""
    payload = _mixed_payload()
    old = tmp_path / "edge" / "edge1" / f"1690000000000-bbbbbbbb{rawstore.SUFFIX}"
    old.parent.mkdir(parents=True)
    old.write_bytes(encrypt(KEY, gzip.compress(json.dumps(payload, default=str).encode())))
    new = rawstore.write(tmp_path, "edge", RUN_ID, payload, host="edge1", key=KEY)

    assert rawstore.read(old, KEY) == rawstore.read(new, KEY) == json.loads(json.dumps(payload, default=str))
    assert _content(old) == _content(new)
    assert rawstore.latest_path(tmp_path, "edge", "edge1") == new


def test_the_file_and_its_directories_are_private(tmp_path):
    path = rawstore.write(tmp_path / "raw", "edge", RUN_ID, {"x": 1}, host="edge1", key=KEY)

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    for directory in (tmp_path / "raw", tmp_path / "raw" / "edge", path.parent):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700


# --- the compression level --------------------------------------------------------------


class _HostCfg(SourceConfig):
    host: str = ""


class _Device(Collector):
    name = "nxos"
    ConfigModel = _HostCfg

    def fetch(self):
        return {"seen": 1}

    def normalize(self, raw):
        b = GraphBuilder()
        b.node("Device", "dev:r1", hostname="r1", role="router")
        return b.batch("edge", "nxos:r1")

    def probe(self) -> str:
        return "ok"


class _Session:
    """Answers the loader's node upserts and ignores every other statement."""

    def execute_write(self, work):
        return work(self)

    def run(self, q, **p):
        rows = p.get("rows", [])

        class _Result:
            def data(self_inner):
                if "UNWIND $rows" in q and "MERGE (n" in q:
                    return [{"uid": r["uid"], "before": {}, "after": {**r["props"]}} for r in rows]
                return []

        return _Result()


def test_every_collection_path_seals_at_the_configured_level(tmp_path, monkeypatch):
    settings = Settings(
        _env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key(), raw_compress_level=1
    )
    device = _Device(_HostCfg(host="r1", source_name="edge"), settings)
    levels: list[int | None] = []
    write = rawstore.write

    def recording(*args: Any, **kwargs: Any) -> Path:
        levels.append(kwargs.get("level"))
        return write(*args, **kwargs)

    monkeypatch.setattr(rawstore, "write", recording)
    coll.park(device, {"seen": 1})
    coll.execute_observations(device, raw={"seen": 1}, collection_ts=1)
    coll.execute(device, _Session(), collection_ts=1, raw={"seen": 1})

    assert levels == [1, 1, 1]


def test_the_level_setting_defaults_to_6_and_is_bounded(tmp_path):
    assert Settings(_env_file=None, hst_data_dir=tmp_path).raw_compress_level == 6
    assert Settings(_env_file=None, hst_data_dir=tmp_path, raw_compress_level=1).raw_compress_level == 1
    for level in (0, 10):
        with pytest.raises(ValidationError):
            Settings(_env_file=None, hst_data_dir=tmp_path, raw_compress_level=level)


# --- a write that fails -----------------------------------------------------------------


def test_a_failure_mid_seal_leaves_neither_file(tmp_path, monkeypatch):
    """The encryption fails after some of the compressed pieces are already
    in the temporary file."""
    directory = tmp_path / "edge" / "edge1"
    tmp = directory / f"{RUN_ID}{rawstore.TMP_SUFFIX}"
    written: list[int] = []
    write = TokenWriter.write

    def fail_on_the_third(self: TokenWriter, data: bytes) -> None:
        if len(written) == 2:
            assert tmp.exists()
            raise RuntimeError("disk gone")
        written.append(len(data))
        write(self, data)

    monkeypatch.setattr(TokenWriter, "write", fail_on_the_third)
    with pytest.raises(RuntimeError, match="disk gone"):
        rawstore.write(tmp_path, "edge", RUN_ID, case_payload("iosxe/small/plain"), host="edge1", key=KEY)

    assert len(written) == 2
    assert not (directory / f"{RUN_ID}{rawstore.SUFFIX}").exists()
    assert not tmp.exists()
    assert list(directory.iterdir()) == []


def test_a_key_the_writer_refuses_leaves_neither_file(tmp_path):
    with pytest.raises(SecretKeyError):
        rawstore.write(tmp_path, "edge", RUN_ID, {"x": 1}, host="edge1", key="not-a-key")

    assert list((tmp_path / "edge" / "edge1").iterdir()) == []


def test_a_failed_rename_removes_the_temporary_file(tmp_path):
    """The final name is taken by a directory, so the rename fails after the
    token was written in full."""
    directory = tmp_path / "edge" / "edge1"
    (directory / f"{RUN_ID}{rawstore.SUFFIX}").mkdir(parents=True)

    with pytest.raises(OSError):
        rawstore.write(tmp_path, "edge", RUN_ID, {"x": 1}, host="edge1", key=KEY)

    assert [p.name for p in directory.iterdir()] == [f"{RUN_ID}{rawstore.SUFFIX}"]


def test_a_payload_json_rejects_raises_the_json_error_and_writes_nothing(tmp_path):
    payload: dict[str, Any] = {"show version": "x"}
    payload["self"] = payload

    with pytest.raises(ValueError, match="Circular reference detected"):
        json.dumps(payload, default=str)
    with pytest.raises(ValueError, match="Circular reference detected"):
        rawstore.write(tmp_path, "edge", RUN_ID, payload, host="edge1", key=KEY)
    assert list((tmp_path / "edge" / "edge1").iterdir()) == []


def test_a_stray_temporary_file_is_invisible_to_every_reader(tmp_path):
    """A killed write leaves `<run_id>.json.gz.enc.tmp`."""
    raw_dir = tmp_path / "raw"
    real = rawstore.write(raw_dir, "edge", RUN_ID, {"x": 1}, host="edge1", key=KEY)
    stray = real.with_name(f"1800000000000-cccccccc{rawstore.TMP_SUFFIX}")
    stray.write_bytes(real.read_bytes())

    assert rawstore.latest_path(raw_dir, "edge", "edge1") == real
    assert [f.path for f in rawstore.raw_files(raw_dir, "edge", 10)] == [real]
    assert [p.path for p in rawstore.parked(raw_dir)] == [real]
    assert [p.path for p in rawstore.parked(raw_dir, "edge")] == [real]


# --- memory -----------------------------------------------------------------------------


def _traced_peak(fn) -> tuple[Any, int]:
    """`fn()` and the tracemalloc peak of what it allocated beyond what was
    already live."""
    gc.collect()
    was_tracing = tracemalloc.is_tracing()
    if not was_tracing:
        tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        before = tracemalloc.get_traced_memory()[0]
        result = fn()
        peak = tracemalloc.get_traced_memory()[1] - before
    finally:
        if not was_tracing:
            tracemalloc.stop()
    return result, peak


def test_sealing_a_50_mb_payload_holds_neither_the_json_nor_the_token(tmp_path):
    """The JSON is compressed a chunk at a time and each compressed piece is
    encrypted and written as it comes, so the seal holds a chunk of JSON and a
    compressed piece with its ciphertext and base64, never the JSON, the
    compressed payload or the token whole. Its peak above the payload is a
    bounded constant that does not grow with the compressed size."""
    payload = iosxe_payload(routes=130_000, peers=2, paths=130_000, advertised=1_000, denied_received=False)
    size = len(json.dumps(payload))
    assert size > 50_000_000

    path, peak = _traced_peak(
        lambda: rawstore.write(tmp_path, "edge", RUN_ID, payload, host="edge1", key=KEY)
    )
    compressed = len(decrypt(KEY, path.read_bytes()))

    assert peak <= 16_000_000, (
        f"peak {peak / 1e6:.1f} MB over a {size / 1e6:.0f} MB payload, {compressed / 1e6:.1f} MB compressed"
    )
    assert _content(path) == json.dumps(payload, default=str).encode()
