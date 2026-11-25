"""The symbolic runtime closure records must match the versions uv.lock installs."""

from __future__ import annotations

import json
from pathlib import Path

from tools.check_symbolic_licenses import check_runtime_closure

ROOT = Path(__file__).resolve().parents[2]
BUILD_LOCK = ROOT / "third_party/symbolic/build-lock.json"
INVENTORY = ROOT / "third_party/symbolic/license-inventory.json"
UV_LOCK = ROOT / "uv.lock"


def bump_networkx_in_uv_lock(tmp_path: Path) -> Path:
    text = UV_LOCK.read_text(encoding="utf-8")
    old = 'name = "networkx"\nversion = "3.6.1"\n'
    assert text.count(old) == 1
    bumped = tmp_path / "uv.lock"
    bumped.write_text(text.replace(old, 'name = "networkx"\nversion = "3.7"\n'), encoding="utf-8")
    return bumped


def test_the_checked_in_records_match_uv_lock() -> None:
    assert check_runtime_closure(BUILD_LOCK, INVENTORY, UV_LOCK) == []


def test_a_uv_lock_version_change_alone_fails_the_check(tmp_path: Path) -> None:
    errors = check_runtime_closure(BUILD_LOCK, INVENTORY, bump_networkx_in_uv_lock(tmp_path))
    assert errors == [
        "networkx: build-lock.json runtime_closure records 3.6.1, uv.lock pins 3.7",
        "networkx: license-inventory.json records 3.6.1, uv.lock pins 3.7",
    ]


def test_a_changed_sdist_hash_fails_the_check(tmp_path: Path) -> None:
    lock = json.loads(BUILD_LOCK.read_text(encoding="utf-8"))
    lock["runtime_closure"]["ply"]["sha256"] = "0" * 64
    changed = tmp_path / "build-lock.json"
    changed.write_text(json.dumps(lock), encoding="utf-8")
    errors = check_runtime_closure(changed, INVENTORY, UV_LOCK)
    assert errors == ["ply: build-lock.json runtime_closure sha256 differs from the uv.lock sdist hash"]


def test_a_package_missing_from_uv_lock_fails_the_check(tmp_path: Path) -> None:
    text = UV_LOCK.read_text(encoding="utf-8").replace('name = "astutils"\n', 'name = "astutils-renamed"\n')
    changed = tmp_path / "uv.lock"
    changed.write_text(text, encoding="utf-8")
    errors = check_runtime_closure(BUILD_LOCK, INVENTORY, changed)
    assert errors == ["astutils: uv.lock has no entry"]
