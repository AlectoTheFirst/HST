"""Static packaging gates of the native symbolic backend and of the Containerfiles."""

from __future__ import annotations

import json
from pathlib import Path

from tools.build_symbolic_wheels import load_lock
from tools.check_symbolic_licenses import check_qualified_wheel

ROOT = Path(__file__).resolve().parents[2]


def test_build_lock_has_6_targets_and_1_qualified_linux_target() -> None:
    lock = load_lock(ROOT / "third_party/symbolic/build-lock.json")
    statuses = lock["target_status"]
    assert isinstance(statuses, dict)
    assert set(statuses) == {
        "macos-arm64-cp312",
        "macos-arm64-cp314",
        "linux-amd64-cp312",
        "linux-amd64-cp314",
        "linux-arm64-cp312",
        "linux-arm64-cp314",
    }
    assert statuses["linux-amd64-cp314"]["status"] == "qualified-private"
    assert statuses["linux-amd64-cp314"]["wheel_sha256"] == (
        "a350c5b2ea82a0161f808c72106efe17b9b00225cbcb4eecf9cd7ff98e1f77d8"
    )
    for name in ("linux-amd64-cp312", "linux-arm64-cp312", "linux-arm64-cp314"):
        assert statuses[name]["status"] == "unqualified"


def test_unrecorded_wheel_cannot_pass_the_production_qualification_gate(tmp_path: Path) -> None:
    wheel = tmp_path / "dd-0.6.0-cp314-cp314-manylinux_2_34_x86_64.whl"
    wheel.write_bytes(b"not an approved artifact")
    errors = check_qualified_wheel(wheel, ROOT / "third_party/symbolic/build-lock.json")
    assert errors == [f"{wheel.name}: filename and sha256 are not qualified in build-lock.json"]


def test_production_image_builds_native_wheel_before_the_runtime_stage() -> None:
    recipe = (ROOT / "deploy/Containerfile").read_text(encoding="utf-8")
    assert "AS symbolic-build" in recipe
    assert "COPY --from=symbolic-build /wheelhouse/" in recipe
    assert "dd.cudd as c" in recipe
    assert recipe.index("AS symbolic-build") < recipe.index("AS runtime")
    assert (
        json.loads((ROOT / "third_party/symbolic/build-lock.json").read_text())["sources"]["dd"]["version"]
        == "0.6.0"
    )


def test_each_external_image_has_a_digest() -> None:
    for name in ("deploy/Containerfile", "deploy/symbolic/EnterpriseTest.Containerfile"):
        lines = (ROOT / name).read_text(encoding="utf-8").splitlines()
        stages = {line.split()[-1] for line in lines if line.startswith("FROM ") and " AS " in line}
        images = [line.split()[1] for line in lines if line.startswith("FROM ")]
        images += [
            word.removeprefix("--from=")
            for line in lines
            if line.startswith("COPY ")
            for word in line.split()
            if word.startswith("--from=")
        ]
        external = [image for image in images if image not in stages and image != "scratch"]
        assert external
        assert [image for image in external if "@sha256:" not in image] == []


def test_no_layer_of_the_product_runtime_image_holds_uv() -> None:
    recipe = (ROOT / "deploy/Containerfile").read_text(encoding="utf-8")
    assert recipe.count(" AS uv\n") == 1
    assert recipe.index(" AS uv\n") < recipe.index(" AS runtime\n")
    runtime = recipe[recipe.index(" AS runtime\n") :]
    assert "astral-sh/uv" not in runtime
    assert "--from=uv" not in runtime
    steps = [step for step in runtime.split("\nRUN ")[1:] if "uv export --" in step]
    assert len(steps) == 2
    for step in steps:
        assert step.startswith("--mount=type=bind,from=uv,source=/uv,target=/tmp/uv \\\n")
        assert "/tmp/uv export --frozen " in step
        assert " uv export --" not in step


def test_final_stage_of_the_product_image_sets_a_non_root_user() -> None:
    recipe = (ROOT / "deploy/Containerfile").read_text(encoding="utf-8")
    final = recipe[recipe.rindex("\nFROM ") :]
    assert "\nUSER hst\n" in final
