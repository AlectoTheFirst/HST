"""The `hst mcp` tools, published from the catalogue registry."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

import hst
from hst.app.ai.mcp import register_mcp
from hst.app.ai.registry import Principal
from hst.twin_tools import catalogue_registry

# Modules of the `app` and `sidestore` extras. `hst mcp` runs with the base and `mcp` extras only.
_APP_EXTRA_MODULES = (
    "fastapi",
    "starlette",
    "uvicorn",
    "sqlalchemy",
    "asyncpg",
    "alembic",
    "authlib",
    "saml2",
    "argon2",
    "duckdb",
)


class _Server:
    def __init__(self) -> None:
        self.names: list[str] = []

    def tool(self):
        def register(fn):
            self.names.append(fn.__name__)
            return fn

        return register


def test_a_principal_is_published_the_tools_its_permissions_allow():
    pytest.importorskip("mcp")
    server = _Server()
    principal = Principal(user_id=1, role="reader", permissions=frozenset({"graph.read"}), origin="mcp")
    registry = catalogue_registry()

    register_mcp(server, registry, principal=principal)

    assert "query_cypher" not in server.names
    assert "ops_list_collection_runs" not in server.names
    assert server.names == [spec.name for spec in registry.specs() if spec.permission == "graph.read"]


def test_importing_the_mcp_server_loads_no_module_of_the_app_extra():
    """`hst mcp` runs where only the base and `mcp` extras are installed."""
    source = Path(hst.__file__).resolve().parents[1]
    code = (
        "import sys\n"
        "import hst.mcp_server\n"
        f"loaded = sorted({{name.split('.')[0] for name in sys.modules}} & set({_APP_EXTRA_MODULES!r}))\n"
        "print(','.join(loaded))\n"
    )
    env = {
        **os.environ,
        "PYTHONPATH": os.pathsep.join(filter(None, [str(source), os.environ.get("PYTHONPATH")])),
    }

    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, check=False)

    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == ""
