#!/usr/bin/env python3
"""Verify the pinned symbolic backend attribution inventory and runtime closure pins."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INVENTORY = ROOT / "third_party/symbolic/license-inventory.json"
DEFAULT_SOURCE_LOCK = ROOT / "third_party/symbolic/2026-09-12-enterprise-symbolic-sources.json"
DEFAULT_BUILD_LOCK = ROOT / "third_party/symbolic/build-lock.json"
DEFAULT_UV_LOCK = ROOT / "uv.lock"
RUNTIME_CLOSURE = ("astutils", "networkx", "ply")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def check_inventory(inventory_path: Path, source_lock_path: Path) -> list[str]:
    inventory = load_json(inventory_path)
    source_lock = load_json(source_lock_path)
    errors: list[str] = []
    if inventory.get("format_version") != 1:
        errors.append("license inventory format_version must be 1")
    components = inventory.get("components")
    if not isinstance(components, list):
        return [*errors, "license inventory components must be a list"]
    base = inventory_path.parent
    names: set[str] = set()
    for component in components:
        if not isinstance(component, dict):
            errors.append("license inventory contains a non-object component")
            continue
        name = component.get("name")
        notice = component.get("notice")
        expected = component.get("sha256")
        if not isinstance(name, str) or not name:
            errors.append("license inventory component has no name")
            continue
        names.add(name)
        if name in {"Cython", "setuptools"}:
            continue
        if not isinstance(notice, str) or not isinstance(expected, str):
            errors.append(f"{name}: notice and sha256 are required")
            continue
        notice_path = base / notice
        if not notice_path.is_file():
            errors.append(f"{name}: missing notice {notice_path}")
        elif sha256(notice_path) != expected:
            errors.append(f"{name}: notice hash does not match inventory")
    required = {"dd", "CUDD", "Batfish selected ports", "astutils", "networkx", "ply"}
    missing = sorted(required - names)
    if missing:
        errors.append(f"inventory omits required components: {', '.join(missing)}")
    by_name = {item.get("name"): item for item in components if isinstance(item, dict)}
    source_names = (
        ("dd", "dd"),
        ("cudd", "CUDD"),
        ("batfish", "Batfish selected ports"),
    )
    for source_name, inventory_name in source_names:
        source = source_lock.get(source_name)
        item = by_name.get(inventory_name)
        if not isinstance(source, dict) or not isinstance(item, dict):
            errors.append(f"cannot compare {source_name} source-lock attribution")
            continue
        # CUDD's source lock pins the archive and has no license-file digest.
        expected = source.get("license_sha256")
        if expected is not None and item.get("sha256") != expected:
            errors.append(f"{inventory_name}: notice hash diverges from source lock")
    return errors


def uv_lock_packages(path: Path) -> dict[str, list[dict[str, object]]]:
    try:
        value = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    packages: dict[str, list[dict[str, object]]] = {}
    for package in value.get("package", []):
        if isinstance(package, dict) and isinstance(package.get("name"), str):
            packages.setdefault(package["name"], []).append(package)
    return packages


def check_runtime_closure(build_lock_path: Path, inventory_path: Path, uv_lock_path: Path) -> list[str]:
    """Compare the runtime closure records with the versions that uv.lock installs."""
    lock = load_json(build_lock_path)
    inventory = load_json(inventory_path)
    packages = uv_lock_packages(uv_lock_path)
    runtime = lock.get("runtime_closure")
    if not isinstance(runtime, dict):
        return ["build lock runtime_closure must be an object"]
    components = inventory.get("components")
    by_name = (
        {item.get("name"): item for item in components if isinstance(item, dict)}
        if isinstance(components, list)
        else {}
    )
    errors: list[str] = []
    for name in RUNTIME_CLOSURE:
        entries = packages.get(name, [])
        locked = sorted({str(entry.get("version")) for entry in entries})
        if not locked:
            errors.append(f"{name}: uv.lock has no entry")
            continue
        pins = ", ".join(locked)
        item = runtime.get(name)
        recorded = item.get("version") if isinstance(item, dict) else None
        if locked != [recorded]:
            errors.append(f"{name}: build-lock.json runtime_closure records {recorded}, uv.lock pins {pins}")
        elif isinstance(item, dict) and item.get("artifact_type") == "sdist":
            sdist_hashes = {
                str(entry["sdist"].get("hash")) for entry in entries if isinstance(entry.get("sdist"), dict)
            }
            if f"sha256:{item.get('sha256')}" not in sdist_hashes:
                errors.append(
                    f"{name}: build-lock.json runtime_closure sha256 differs from the uv.lock sdist hash"
                )
        component = by_name.get(name)
        attributed = component.get("version") if isinstance(component, dict) else None
        if locked != [attributed]:
            errors.append(f"{name}: license-inventory.json records {attributed}, uv.lock pins {pins}")
    return errors


def check_wheel(path: Path) -> list[str]:
    if not path.is_file():
        return [f"wheel does not exist: {path}"]
    try:
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
    except zipfile.BadZipFile as exc:
        return [f"invalid wheel {path}: {exc}"]
    errors: list[str] = []
    if "dd/CUDD_LICENSE" not in names:
        errors.append(f"{path.name}: missing bundled CUDD license")
    if not any(name.endswith(".dist-info/licenses/LICENSE") for name in names):
        errors.append(f"{path.name}: missing bundled dd license")
    if not any(name.startswith("dd/cudd.") and name.endswith(".so") for name in names):
        errors.append(f"{path.name}: missing native dd.cudd extension")
    return errors


def check_qualified_wheel(path: Path, build_lock_path: Path) -> list[str]:
    lock = load_json(build_lock_path)
    statuses = lock.get("target_status")
    if not isinstance(statuses, dict):
        return ["build lock target_status must be an object"]
    digest = sha256(path) if path.is_file() else ""
    matches = [
        name
        for name, status in statuses.items()
        if isinstance(status, dict)
        and status.get("status") == "qualified-private"
        and status.get("wheel") == path.name
        and status.get("wheel_sha256") == digest
    ]
    return [] if matches else [f"{path.name}: filename and sha256 are not qualified in build-lock.json"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--source-lock", type=Path, default=DEFAULT_SOURCE_LOCK)
    parser.add_argument("--wheel", type=Path, action="append", default=[])
    parser.add_argument("--build-lock", type=Path, default=DEFAULT_BUILD_LOCK)
    parser.add_argument("--uv-lock", type=Path, default=DEFAULT_UV_LOCK)
    parser.add_argument("--require-qualified-wheel", action="store_true")
    args = parser.parse_args()
    errors = check_inventory(args.inventory, args.source_lock)
    try:
        errors.extend(check_runtime_closure(args.build_lock, args.inventory, args.uv_lock))
    except ValueError as exc:
        errors.append(str(exc))
    for wheel in args.wheel:
        errors.extend(check_wheel(wheel))
        if args.require_qualified_wheel:
            errors.extend(check_qualified_wheel(wheel, args.build_lock))
    if errors:
        for error in errors:
            print(f"symbolic license check: {error}", file=sys.stderr)
        return 1
    print("symbolic license check: inventory, runtime closure pins and supplied wheels are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
