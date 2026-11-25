"""Repo-wide test guards."""

from __future__ import annotations

import functools
import inspect
import os
import pathlib
import re
from collections.abc import Callable
from contextlib import asynccontextmanager, contextmanager
from typing import Any

import pytest

from hst.core.config import Settings

MARKER_ENV = {"db": "NEO4J_TEST_URI", "pg": "HST_TEST_PG_DSN"}


class FakeSshSession:
    """Stands in for `ssh.session` so no socket is opened."""

    def __init__(
        self,
        outputs: Callable[[str], str] | dict[str, str],
        *,
        host_key: str = "k",
        jump_host_key: str = "",
    ) -> None:
        self._outputs = outputs
        self.host_key = host_key
        self.jump_host_key = jump_host_key
        self.commands: list[str] = []
        self.connections: list[dict[str, Any]] = []

    def run(self, command: str) -> str:
        self.commands.append(command)
        if callable(self._outputs):
            return self._outputs(command)
        return self._outputs[command]

    @property
    def connection(self) -> dict[str, Any]:
        """The single connection, for the common case of asserting on one fetch."""
        assert self.connections, "nothing connected"
        return self.connections[-1]

    def as_session(self):
        @contextmanager
        def _session(host, auth, **kwargs):
            self.connections.append({"host": host, "auth": auth, "seam": "paramiko", **kwargs})
            yield self

        return _session

    def as_async_session(self):
        fake = self

        class _AsyncView:
            host_key = fake.host_key
            jump_host_key = fake.jump_host_key

            async def run(self, command: str) -> str:
                return fake.run(command)

        @asynccontextmanager
        async def _session(host, auth, **kwargs):
            self.connections.append({"host": host, "auth": auth, "seam": "asyncssh", **kwargs})
            yield _AsyncView()

        return _session

    def install(self, monkeypatch: pytest.MonkeyPatch) -> FakeSshSession:
        """Patch the session entry point on both transport modules; every
        collector reaches one of the two through the shared scaffolding in
        cli_collector, so one install covers every transport value."""
        from hst.collectors import assh, ssh

        monkeypatch.setattr(ssh, "session", self.as_session())
        monkeypatch.setattr(assh, "session", self.as_async_session())
        return self


def _positively_selected(markexpr: str, marker: str) -> bool:
    """True when `-m` asks for the marker, not when it excludes it.

    `-m 'not db and not pg'` names both markers only to deselect them; no db-marked
    test is expected to run, so an unset NEO4J_TEST_URI is not a hole there.
    """
    tokens = re.findall(r"\w+|\S", markexpr)
    return any(
        token == marker and (index == 0 or tokens[index - 1] != "not") for index, token in enumerate(tokens)
    )


def pytest_configure(config: pytest.Config) -> None:
    if not os.environ.get("CI"):
        return
    selected = config.getoption("-m", default="") or ""
    for marker, var in MARKER_ENV.items():
        if _positively_selected(selected, marker) and not os.environ.get(var):
            raise pytest.UsageError(
                f"CI selected `-m {selected}` but {var} is unset, so every {marker}-marked "
                f"test would skip and the run would report success having tested nothing. "
                f"Set {var} or drop the marker from the workflow."
            )


@pytest.fixture(autouse=True)
def _no_dotenv(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """No test resolves HST_DATA_DIR against the real ./data."""
    monkeypatch.setitem(Settings.model_config, "env_file", None)
    monkeypatch.setenv("HST_DATA_DIR", str(tmp_path / "hst-data"))


@pytest.fixture(autouse=True)
def _no_real_vco_pacing(monkeypatch: pytest.MonkeyPatch) -> None:
    """VeloCloudCollector paces every request to poll_concurrency per second
    (collectors/velocloud.py `_throttle`)."""
    monkeypatch.setattr("hst.collectors.velocloud._pace", lambda seconds: None)


@pytest.fixture(autouse=True)
def _no_remembered_diffs() -> None:
    """`core/diff.py request_diff` remembers a comparison per run pair, and tests
    reuse the same run ids with different graphs."""
    from hst.core import diff

    diff._RESULTS.clear()


@functools.cache
def path_package_strings() -> tuple[str, ...]:
    """Every triple-quoted string in the hst.path package.

    The corpus for the source-scan invariants in test_path_determinism.py and
    the point-path half of test_time_travel.py. Scanned file by file, so an
    unpaired triple quote in one module cannot shift the string pairing in
    the others.
    """
    import hst.path as pathpkg

    root = pathlib.Path(inspect.getsourcefile(pathpkg)).parent
    out: list[str] = []
    for py in sorted(root.rglob("*.py")):
        out.extend(re.findall(r'"""(.*?)"""', py.read_text(), re.DOTALL))
    return tuple(out)


@functools.cache
def snap_guard_corpus_strings() -> tuple[str, ...]:
    """Every triple-quoted string in every module that can build Cypher against
    the versioned graph, not only hst.path."""
    import hst.app as apppkg
    import hst.core as corepkg
    import hst.demo as demo_mod
    import hst.mcp_server as mcp_server_mod
    import hst.queries as queries_mod
    import hst.reasoner as reasoner_mod
    import hst.twin_tools as twin_tools_pkg

    out: list[str] = list(path_package_strings())
    for pkg in (corepkg, apppkg, twin_tools_pkg, reasoner_mod):
        root = pathlib.Path(inspect.getsourcefile(pkg)).parent
        for py in sorted(root.rglob("*.py")):
            out.extend(re.findall(r'"""(.*?)"""', py.read_text(), re.DOTALL))
    for mod in (mcp_server_mod, queries_mod, demo_mod):
        py = pathlib.Path(inspect.getsourcefile(mod))
        out.extend(re.findall(r'"""(.*?)"""', py.read_text(), re.DOTALL))
    return tuple(out)
