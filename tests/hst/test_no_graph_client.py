import ast
import json
import pathlib
import subprocess
import sys

import hst

FORBIDDEN = ("neo4j", "hst.core.db", "hst.core.snapshot", "hst.path.session")
# Tier 3 reads the graph on a warm run. The routes import it in one handler.
EXCLUDED = ("hst.map.tier3",)
SRC = pathlib.Path(hst.__file__).parent
SOURCES = [
    *sorted(p for p in (SRC / "map").rglob("*.py") if p.name != "tier3.py"),
    SRC / "app" / "routes" / "hst.py",
]

_PROBE = """
import importlib, json, pkgutil, sys
import hst.map
names = ["hst.map", "hst.app.routes.hst"]
found = pkgutil.walk_packages(hst.map.__path__, "hst.map.")
names += [m.name for m in found if m.name not in {excluded!r}]
for name in names:
    importlib.import_module(name)
forbidden = {forbidden!r}
loaded = sorted(m for m in sys.modules if any(m == f or m.startswith(f + ".") for f in forbidden))
print(json.dumps(loaded))
"""


def _is_forbidden(name: str) -> bool:
    return any(name == f or name.startswith(f + ".") for f in FORBIDDEN)


def test_importing_the_map_loads_no_graph_client() -> None:
    result = subprocess.run(
        [sys.executable, "-c", _PROBE.format(forbidden=FORBIDDEN, excluded=set(EXCLUDED))],
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(result.stdout.strip().splitlines()[-1]) == []


def test_only_tier3_is_excluded_and_it_exists() -> None:
    assert (SRC / "map" / "tier3.py").exists()
    assert all(p.name != "tier3.py" for p in SOURCES)


def test_map_sources_do_not_import_the_graph_client() -> None:
    assert len(SOURCES) >= 5
    found = []
    for path in SOURCES:
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                base = node.module or ""
                names = [base, *(f"{base}.{a.name}" for a in node.names)]
            else:
                continue
            found += [f"{path.name}: {n}" for n in names if _is_forbidden(n)]
    assert found == []
