"""New raw payload files are written at gzip level 6 unless the caller names a
level (core/rawstore.py `DEFAULT_COMPRESS_LEVEL`, core/config.py
`Settings.raw_compress_level`). The level decides only the size of the gzip
stream: the stream decompresses to the same JSON bytes at every level, and
`read` opens a file written at any level.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet
from tests.support.synthetic_payloads import case_payload

from hst import collectors as coll
from hst.app.crypto import decrypt, generate_key
from hst.collectors.base import Collector, SourceConfig
from hst.collectors.util import GraphBuilder
from hst.core import Settings, rawstore

KEY = Fernet.generate_key().decode()


def _blob(path: Path) -> bytes:
    """The gzip stream inside a sealed raw file."""
    return decrypt(KEY, path.read_bytes())


def test_the_setting_and_the_raw_store_default_to_level_6(tmp_path, monkeypatch):
    monkeypatch.delenv("RAW_COMPRESS_LEVEL", raising=False)

    assert Settings(_env_file=None, hst_data_dir=tmp_path).raw_compress_level == 6
    assert rawstore.DEFAULT_COMPRESS_LEVEL == 6


def test_a_write_without_a_level_is_the_level_6_stream(tmp_path):
    payload = case_payload("iosxe/small/plain")
    default = rawstore.write(tmp_path, "edge", "1700000000000-aaaaaaaa", payload, host="edge1", key=KEY)
    level_6 = rawstore.write(
        tmp_path, "edge", "1700000000006-aaaaaaaa", payload, host="edge1", key=KEY, level=6
    )
    level_1 = rawstore.write(
        tmp_path, "edge", "1700000000001-aaaaaaaa", payload, host="edge1", key=KEY, level=1
    )

    assert _blob(default) == _blob(level_6)
    assert gzip.decompress(_blob(default)) == gzip.decompress(_blob(level_1))
    assert gzip.decompress(_blob(default)) == json.dumps(payload, default=str).encode()
    assert len(_blob(default)) <= len(_blob(level_1))
    assert rawstore.read(default, KEY) == rawstore.read(level_1, KEY) == payload


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


def test_a_collection_on_default_settings_seals_at_level_6(tmp_path, monkeypatch):
    monkeypatch.delenv("RAW_COMPRESS_LEVEL", raising=False)
    settings = Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())
    device = _Device(_HostCfg(host="r1", source_name="edge"), settings)
    levels: list[int | None] = []
    write = rawstore.write

    def recording(*args: Any, **kwargs: Any) -> Path:
        levels.append(kwargs.get("level"))
        return write(*args, **kwargs)

    monkeypatch.setattr(rawstore, "write", recording)
    coll.park(device, {"seen": 1})

    assert levels == [6]
