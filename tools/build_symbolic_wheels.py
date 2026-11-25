#!/usr/bin/env python3
# ruff: noqa: S310, S603
"""Build a hash-checked, CPU-neutral dd.cudd wheel from pinned sources."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
BUILD_LOCK = ROOT / "third_party/symbolic/build-lock.json"
PATCH = ROOT / "third_party/symbolic/patches/0001-dd-cpu-neutral-cudd-link.patch"
CPU_NEUTRAL_CFLAGS = "-fPIC -std=c99 -DBSD -DHAVE_IEEE_754 -pthread -fwrapv -fno-strict-aliasing -O3"


def load_lock(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("format_version") != 1:
        raise ValueError("unsupported symbolic build-lock format")
    if not isinstance(value.get("source_date_epoch"), int):
        raise ValueError("build-lock source_date_epoch must be an integer")

    def require_artifact(item: object, label: str) -> None:
        if not isinstance(item, dict):
            raise ValueError(f"{label} must be an object")
        for field in ("version", "url", "sha256"):
            if not isinstance(item.get(field), str) or not item[field]:
                raise ValueError(f"{label} is missing {field}")
        if not str(item["url"]).startswith("https://"):
            raise ValueError(f"{label} URL must use HTTPS")
        checksum = str(item["sha256"])
        if len(checksum) != 64 or any(character not in "0123456789abcdef" for character in checksum):
            raise ValueError(f"{label} sha256 must be lowercase hexadecimal")

    sources = value.get("sources")
    if not isinstance(sources, dict):
        raise ValueError("build-lock sources must be an object")
    for name in ("dd", "cudd"):
        require_artifact(sources.get(name), f"sources.{name}")
    tools = value.get("build_tools")
    if not isinstance(tools, dict):
        raise ValueError("build-lock build_tools must be an object")
    for name in ("cython", "setuptools"):
        tool = tools.get(name)
        require_artifact(tool, f"build_tools.{name}")
        if not isinstance(tool, dict) or not isinstance(tool.get("artifacts"), dict) or not tool["artifacts"]:
            raise ValueError(f"build_tools.{name} must pin build artifacts")
        for target, artifact in tool["artifacts"].items():
            if not isinstance(target, str) or not target:
                raise ValueError(f"build_tools.{name} has an invalid target")
            target_artifact = (
                {"version": tool["version"], **artifact} if isinstance(artifact, dict) else artifact
            )
            require_artifact(target_artifact, f"build_tools.{name}.{target}")
    runtime = value.get("runtime_closure")
    if not isinstance(runtime, dict):
        raise ValueError("build-lock runtime_closure must be an object")
    for name in ("astutils", "networkx", "ply"):
        item = runtime.get(name)
        require_artifact(item, f"runtime_closure.{name}")
        if (
            not isinstance(item, dict)
            or item.get("artifact_type") not in {"sdist", "wheel"}
            or not isinstance(item.get("filename"), str)
        ):
            raise ValueError(f"runtime_closure.{name} must declare type and filename")
    patches = value.get("patches")
    patches_are_valid = isinstance(patches, list) and all(
        isinstance(item, str) and (path.parent / item).is_file() for item in patches
    )
    if not patches_are_valid:
        raise ValueError("build-lock patches must name existing patch files")
    return value


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked_download(url: str, expected: str, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_file() and digest(destination) == expected:
        return destination
    temporary = destination.with_suffix(destination.suffix + ".part")
    with urlopen(url) as response, temporary.open("wb") as output:
        shutil.copyfileobj(response, output)
    if digest(temporary) != expected:
        temporary.unlink(missing_ok=True)
        raise ValueError(f"hash mismatch for {url}")
    temporary.replace(destination)
    return destination


def safe_extract(archive: Path, destination: Path) -> None:
    with tarfile.open(archive) as tar:
        root = destination.resolve()
        for member in tar.getmembers():
            target = (destination / member.name).resolve()
            if root not in (target, *target.parents):
                raise ValueError(f"unsafe archive member {member.name!r}")
        tar.extractall(destination, filter="data")


def run(command: list[str], *, cwd: Path, env: dict[str, str]) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=cwd, env=env, check=True)


def require_wheel_notices(wheel: Path) -> None:
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
    if "dd/CUDD_LICENSE" not in names:
        raise ValueError(f"{wheel.name} does not contain CUDD_LICENSE")
    if not any(name.endswith(".dist-info/licenses/LICENSE") for name in names):
        raise ValueError(f"{wheel.name} does not contain dd's license")


def canonicalize_wheel(wheel: Path, source_date_epoch: int) -> None:
    """Rewrite wheel ZIP metadata deterministically after the upstream build."""
    timestamp = time.gmtime(max(source_date_epoch, 315532800))[:6]
    with zipfile.ZipFile(wheel) as source:
        files = {name: source.read(name) for name in source.namelist() if not name.endswith("/")}
    temporary = wheel.with_suffix(".canonical.whl")
    with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, timestamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            output.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    temporary.replace(wheel)


def build(args: argparse.Namespace) -> Path:
    lock = load_lock(args.build_lock)
    sources = lock["sources"]
    tools = lock["build_tools"]
    if not isinstance(sources, dict) or not isinstance(tools, dict):
        raise ValueError("build-lock sources or build_tools have an invalid shape")
    work = (args.work_dir or Path(tempfile.mkdtemp(prefix="hst-symbolic-"))).resolve()
    args.out_dir = args.out_dir.resolve()
    args.source_cache = args.source_cache.resolve() if args.source_cache else None
    cache = args.source_cache or work / "cache"
    source_dir = work / "source"
    source_dir.mkdir(parents=True, exist_ok=True)
    build_venv = work / "build-venv"
    run(
        [str(args.python.resolve()), "-m", "venv", str(build_venv)],
        cwd=work,
        env=os.environ.copy(),
    )
    build_python = build_venv / "bin/python"
    environment = os.environ.copy()
    environment["SOURCE_DATE_EPOCH"] = str(lock["source_date_epoch"])
    path_maps = (
        f"-ffile-prefix-map={work}=/usr/src/hst-symbolic -fdebug-prefix-map={work}=/usr/src/hst-symbolic"
    )
    environment["CFLAGS"] = f"{CPU_NEUTRAL_CFLAGS} {path_maps}"
    environment["CXXFLAGS"] = f"-O3 {path_maps}"
    environment["DD_CUDD"] = "1"
    if sys.platform == "darwin" and "MACOSX_DEPLOYMENT_TARGET" not in environment:
        target = subprocess.check_output(
            [
                str(build_python),
                "-c",
                "import sysconfig; print(sysconfig.get_config_var('MACOSX_DEPLOYMENT_TARGET') or '')",
            ],
            text=True,
        ).strip()
        if target:
            environment["MACOSX_DEPLOYMENT_TARGET"] = target

    downloaded: dict[str, Path] = {}
    for name, input_lock in sources.items():
        if not isinstance(input_lock, dict):
            raise ValueError(f"source lock {name} must be an object")
        filename = Path(str(input_lock["url"])).name or f"{name}.tar.gz"
        if filename == "download":
            filename = f"{name}-{input_lock['version']}.tar.gz"
        downloaded[name] = checked_download(
            str(input_lock["url"]), str(input_lock["sha256"]), cache / filename
        )

    version = subprocess.check_output(
        [
            str(args.python.resolve()),
            "-c",
            "import sys; print(f'cp{sys.version_info.major}{sys.version_info.minor}')",
        ],
        text=True,
    ).strip()
    machine = platform.machine().lower()
    platform_name = "macos" if sys.platform == "darwin" else sys.platform
    architecture = "arm64" if machine in {"arm64", "aarch64"} else machine
    build_target = f"{version}-{platform_name}-{architecture}"
    for name, input_lock in tools.items():
        if not isinstance(input_lock, dict):
            raise ValueError(f"build tool lock {name} must be an object")
        artifacts = input_lock.get("artifacts")
        if not isinstance(artifacts, dict):
            raise ValueError(f"{name} has no pinned build artifacts")
        artifact = artifacts.get(build_target) or artifacts.get("universal")
        if not isinstance(artifact, dict):
            raise ValueError(f"{name} has no build artifact for {build_target}")
        filename = Path(str(artifact["url"])).name
        downloaded[name] = checked_download(str(artifact["url"]), str(artifact["sha256"]), cache / filename)

    # The locked setuptools and cython install into the private build venv.
    for name in ("setuptools", "cython"):
        if name == "cython" and downloaded[name].name.endswith((".tar.gz", ".zip")):
            environment["NO_CYTHON_COMPILE"] = "true"
        run(
            [
                str(build_python),
                "-m",
                "pip",
                "install",
                "--no-build-isolation",
                "--no-deps",
                str(downloaded[name]),
            ],
            cwd=work,
            env=environment,
        )
    safe_extract(downloaded["cudd"], source_dir)
    safe_extract(downloaded["dd"], source_dir)
    cudd = source_dir / f"cudd-{sources['cudd']['version']}"
    dd = source_dir / f"dd-{sources['dd']['version']}"
    run(["patch", "-p1", "-i", str(PATCH)], cwd=dd, env=environment)
    run(
        ["./configure", "--disable-shared", "--enable-dddmp"],
        cwd=cudd,
        env=environment,
    )
    run(["make", "-j4"], cwd=cudd, env=environment)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    run(
        [
            str(build_python),
            "setup.py",
            f"--cudd={cudd}",
            "bdist_wheel",
            "--dist-dir",
            str(args.out_dir),
        ],
        cwd=dd,
        env=environment,
    )
    wheels = sorted(args.out_dir.glob("dd-0.6.0-*.whl"), key=lambda item: item.stat().st_mtime)
    if not wheels:
        raise ValueError("dd build did not produce a wheel")
    wheel = wheels[-1]
    canonicalize_wheel(wheel, int(lock["source_date_epoch"]))
    require_wheel_notices(wheel)
    with zipfile.ZipFile(wheel) as archive:
        extensions = sorted(
            name
            for name in archive.namelist()
            if name.startswith("dd/cudd.") and name.endswith((".so", ".pyd"))
        )
        if len(extensions) != 1:
            raise ValueError(f"wheel must contain one dd.cudd extension, found {extensions}")
        extension_name = extensions[0]
        extension_sha256 = hashlib.sha256(archive.read(extension_name)).hexdigest()
    artifact = {
        "format_version": 1,
        "backend": "dd.cudd",
        "dd_version": str(sources["dd"]["version"]),
        "cudd_version": str(sources["cudd"]["version"]),
        "dd_source_sha256": str(sources["dd"]["sha256"]),
        "cudd_source_sha256": str(sources["cudd"]["sha256"]),
        "patches": {name: digest(args.build_lock.parent / name) for name in lock["patches"]},
        "python_abi": sys.implementation.cache_tag,
        "platform": f"{sys.platform}-{platform.machine().lower()}",
        "extension": extension_name,
        "extension_sha256": extension_sha256,
        "wheel": wheel.name,
        "sha256": digest(wheel),
        "wheel_sha256": digest(wheel),
        "base_python": str(args.python.resolve()),
    }
    (args.out_dir / "symbolic-artifacts.json").write_text(
        json.dumps(artifact, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(artifact, sort_keys=True))
    return wheel


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--source-cache", type=Path)
    parser.add_argument("--build-lock", type=Path, default=BUILD_LOCK)
    parser.add_argument(
        "--check-lock",
        action="store_true",
        help="validate lock JSON without downloading or building",
    )
    args = parser.parse_args()
    try:
        load_lock(args.build_lock)
        if args.check_lock:
            print(f"symbolic build lock is valid: {args.build_lock}")
            return 0
        if not args.python.is_file():
            raise ValueError(f"Python interpreter does not exist: {args.python}")
        build(args)
    except (OSError, ValueError, subprocess.CalledProcessError, tarfile.TarError) as exc:
        print(f"symbolic wheel build: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
