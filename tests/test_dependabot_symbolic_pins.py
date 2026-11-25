from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_dependabot_leaves_the_runtime_closure_to_a_manual_update() -> None:
    config = (ROOT / ".github/dependabot.yml").read_text(encoding="utf-8")
    uv_section = config.split("package-ecosystem: uv", 1)[1].split("package-ecosystem:", 1)[0]
    for name in ("astutils", "networkx", "ply"):
        assert f'dependency-name: "{name}"' in uv_section
