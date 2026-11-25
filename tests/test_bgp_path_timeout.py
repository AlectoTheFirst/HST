"""A per-neighbor BGP path command that times out, on IOS-XE, IOS-XR and NX-OS.

When every command has a session of its own (an exec channel, or a fresh
connection per command), the timeout costs that command's direction: it is
recorded the way a refused command is, the fetch goes on, and the device
loads as a partial collection. One shell session sends nothing after a
timeout (`ssh.ShellSession.run`), so there the timeout fails the fetch. The
BGP summary keeps failing the fetch on a timeout on every channel.
"""

from __future__ import annotations

import importlib
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from tests.conftest import FakeSshSession
from tests.test_collector_execute import FakeSession

from hst import collectors as coll
from hst.app.crypto import generate_key
from hst.app.runs_exec import DeviceOutcome
from hst.collectors import ssh
from hst.collectors.auth import SshPassword
from hst.collectors.base import RAW_OUTCOMES_KEY
from hst.collectors.cli_collector import CiscoCliCollector, classify_command_failure
from hst.core import Settings, manifest
from hst.core.model import RunManifest, section_verdict, table_verdict

RUN_ID = "1700000000000-aaaaaaaa"
CTS = 1_700_000_000_000

FAMILY = pytest.mark.parametrize("family", ["iosxe", "iosxr", "nxos"])

# The peer whose `accepted` command times out: a direction that reads
# `complete` in a fetch of the family's base fixture, and a command with path
# commands on both sides of it.
PEER = {"iosxe": "10.0.0.2", "iosxr": "192.0.2.1", "nxos": "10.1.1.2"}
DIRECTION = "accepted"
# What each family's BGP loop stores for a command that gave no answer.
STAND_IN = {"iosxe": "", "iosxr": "", "nxos": "{}"}
PREFIX = {"iosxe": "Iosxe", "iosxr": "Iosxr", "nxos": "Nxos"}


def _module(family: str) -> ModuleType:
    return importlib.import_module(f"hst.collectors.{family}")


def _fixture(family: str) -> ModuleType:
    return importlib.import_module(f"tests.test_{family}")


def _path_command(family: str, peer: str, direction: str) -> str:
    mod = _module(family)
    if family == "nxos":
        return str(mod.bgp_route_command("CUST-A", peer, direction))
    return str(mod.bgp_route_command(peer, direction))


def _target(family: str) -> str:
    return _path_command(family, PEER[family], DIRECTION)


def _session_uid(family: str) -> str:
    return str(_fixture(family)._session_uid(PEER[family]))


def _exec_timeout(command: str) -> ssh.SshTimeout:
    """The exec channel's own words for a command that did not finish
    (`assh.AsyncSshSession.run`)."""
    return ssh.SshTimeout(f"{command!r} did not complete within 30s")


def _settings(data_dir: Path) -> Settings:
    return Settings(_env_file=None, hst_data_dir=data_dir, hst_secret_key=generate_key())


def _collector(family: str, settings: Settings | None = None, **config: Any) -> CiscoCliCollector:
    mod, base = _module(family), _fixture(family)
    cfg = getattr(mod, f"{PREFIX[family]}Config")(
        host=base.HOST,
        auth=SshPassword(username=base.USER, password="pw"),
        site_code="hq",
        l3dom="corp",
        capture_bgp="all",
        **config,
    )
    collector: CiscoCliCollector = getattr(mod, f"{PREFIX[family]}Collector")(cfg, settings)
    return collector


def _install(monkeypatch, family: str, failing: dict[str, Exception]) -> FakeSshSession:
    """The family's base fixture as the device; every command in `failing`
    raises its exception instead of answering."""
    outputs = _fixture(family).RAW

    def answer(command: str) -> str:
        if command in failing:
            raise failing[command]
        return str(outputs[command])

    return FakeSshSession(answer).install(monkeypatch)


def _clean_commands(monkeypatch, family: str) -> list[str]:
    """Every command a fetch of the base fixture sends when nothing fails."""
    fake = _install(monkeypatch, family, {})
    _collector(family).fetch()
    return fake.commands


def _path_commands(family: str, raw: dict[str, Any]) -> list[str]:
    observed = _module(family).parse(raw)["bgp_observed"]
    return [entry["command"] for entry in observed["directions"]]


def _load(collector: CiscoCliCollector, raw: dict[str, Any]) -> RunManifest:
    return coll.load_payload(collector, FakeSession(), raw, collection_ts=CTS, run_id=RUN_ID, ts_ms=CTS)


def _completeness(collector: CiscoCliCollector, loaded: RunManifest) -> str:
    """The device verdict `runs_exec` records for this load."""
    return DeviceOutcome(
        "edge",
        collector.config.host,
        True,
        sections=loaded.sections,
        authoritative=tuple(collector.AUTHORITATIVE_SECTIONS),
        tables=loaded.tables,
    ).completeness


# --- exec channel: the timeout costs its own command ------------------------------------


@FAMILY
@pytest.mark.parametrize(
    "config",
    [{}, {"channel": "shell", "fresh_connection_per_command": True}],
    ids=["exec", "fresh-connection-per-command"],
)
def test_a_timed_out_path_command_is_recorded_as_failed_and_the_fetch_goes_on(monkeypatch, family, config):
    clean = _clean_commands(monkeypatch, family)
    target = _target(family)
    timeout = _exec_timeout(target)
    fake = _install(monkeypatch, family, {target: timeout})

    raw = _collector(family, **config).fetch()

    assert classify_command_failure(timeout) == ("failed", str(timeout))
    assert raw[RAW_OUTCOMES_KEY][target] == {"status": "failed", "detail": str(timeout)}
    assert raw[target] == STAND_IN[family]
    assert fake.commands == clean
    paths = _path_commands(family, raw)
    assert target in paths[1:-1]
    assert all(raw[RAW_OUTCOMES_KEY][cmd] == {"status": "ok"} for cmd in paths if cmd != target)


@FAMILY
def test_the_device_loads_with_a_fresh_rib_and_reads_partial(monkeypatch, tmp_path, family):
    session_uid = _session_uid(family)
    _install(monkeypatch, family, {})
    clean_collector = _collector(family, _settings(tmp_path / "clean"))
    clean = _load(clean_collector, clean_collector.fetch())
    target = _target(family)
    timeout = _exec_timeout(target)
    _install(monkeypatch, family, {target: timeout})
    settings = _settings(tmp_path / "timeout")
    collector = _collector(family, settings)

    loaded = _load(collector, collector.fetch())

    rib = loaded.tables["rib"]
    assert rib.status == "complete"
    assert rib.row_count == clean.tables["rib"].row_count
    assert rib.row_count
    assert list((settings.sidestore_dir / "rib").rglob("*.parquet"))
    directions = manifest.bgp_direction_outcomes(loaded.tables)
    before = manifest.bgp_direction_outcomes(clean.tables)
    assert before[(session_uid, DIRECTION)].status == "complete"
    failed = directions[(session_uid, DIRECTION)]
    assert (failed.status, failed.detail) == ("failed", str(timeout))
    # every other direction reads what it reads in a clean fetch
    assert {key: o.status for key, o in directions.items() if key != (session_uid, DIRECTION)} == {
        key: o.status for key, o in before.items() if key != (session_uid, DIRECTION)
    }
    # the sections are whole; the failed direction is what makes the device partial
    authoritative = tuple(collector.AUTHORITATIVE_SECTIONS)
    assert section_verdict(loaded.sections, authoritative) == "ok"
    assert table_verdict(loaded.tables) == "partial"
    assert _completeness(clean_collector, clean) == "ok"
    assert _completeness(collector, loaded) == "partial"


# --- one shell session: the timeout fails the fetch -------------------------------------


@FAMILY
def test_a_timed_out_path_command_on_a_shell_session_fails_the_fetch(monkeypatch, family):
    target = _target(family)
    timeout = ssh.SshTimeout(f"{target!r} produced no further output within 30s")
    fake = _install(monkeypatch, family, {target: timeout})

    with pytest.raises(ssh.SshTimeout) as raised:
        _collector(family, channel="shell").fetch()

    assert raised.value is timeout
    assert fake.commands[-1] == target


@FAMILY
@pytest.mark.parametrize("channel", ["exec", "shell"])
def test_a_timed_out_bgp_summary_fails_the_fetch_on_either_channel(monkeypatch, family, channel):
    summary = _module(family).CMD_BGP_SESSIONS
    timeout = _exec_timeout(summary)
    fake = _install(monkeypatch, family, {summary: timeout})

    with pytest.raises(ssh.SshTimeout) as raised:
        _collector(family, channel=channel).fetch()

    assert raised.value is timeout
    assert fake.commands[-1] == summary


# --- a refused path command, on either channel ------------------------------------------


@FAMILY
@pytest.mark.parametrize("channel", ["exec", "shell"])
def test_a_refused_path_command_costs_only_its_direction_on_either_channel(monkeypatch, family, channel):
    clean = _clean_commands(monkeypatch, family)
    target = _target(family)
    refusal = ssh.CommandFailed(f"{target!r} exited 1")
    fake = _install(monkeypatch, family, {target: refusal})
    collector = _collector(family, channel=channel)

    raw = collector.fetch()

    assert raw[RAW_OUTCOMES_KEY][target] == {"status": "failed", "detail": str(refusal)}
    assert raw[target] == STAND_IN[family]
    assert fake.commands == clean
    directions = manifest.bgp_direction_outcomes(collector.table_outcomes(raw))
    outcome = directions[(_session_uid(family), DIRECTION)]
    assert (outcome.status, outcome.detail) == ("failed", str(refusal))


# --- a device that stops answering -----------------------------------------------------


def _all_path_commands(monkeypatch, family: str) -> list[str]:
    """Every path command a clean fetch of the base fixture sends, in order."""
    fake = _install(monkeypatch, family, {})
    raw = _collector(family).fetch()
    paths = set(_path_commands(family, raw))
    return [c for c in fake.commands if c in paths]


@FAMILY
def test_after_two_path_timeouts_in_a_row_no_further_path_command_is_sent(monkeypatch, family):
    paths = _all_path_commands(monkeypatch, family)
    assert len(paths) >= 3, "the fixture must have a path command after the two that time out"
    hung = {c: _exec_timeout(c) for c in paths}
    fake = _install(monkeypatch, family, hung)

    raw = _collector(family).fetch()

    sent = [c for c in fake.commands if c in hung]
    assert sent == paths[:2]
    outcomes = raw[RAW_OUTCOMES_KEY]
    for cmd in paths[:2]:
        assert outcomes[cmd] == {"status": "failed", "detail": str(hung[cmd])}
    for cmd in paths[2:]:
        assert outcomes[cmd] == {"status": "failed", "detail": "not sent: the 2 commands before it timed out"}
        assert raw[cmd] == STAND_IN[family]


@FAMILY
def test_an_answer_between_two_timeouts_restarts_the_count(monkeypatch, family):
    paths = _all_path_commands(monkeypatch, family)
    assert len(paths) >= 4
    hung = {paths[0]: _exec_timeout(paths[0]), paths[2]: _exec_timeout(paths[2])}
    fake = _install(monkeypatch, family, hung)

    raw = _collector(family).fetch()

    assert [c for c in fake.commands if c in set(paths)] == paths
    outcomes = raw[RAW_OUTCOMES_KEY]
    assert all(not str(outcomes[c].get("detail", "")).startswith("not sent") for c in paths)


@FAMILY
def test_a_refusal_between_two_timeouts_restarts_the_count(monkeypatch, family):
    """A refusal is an answer: the device is still responding."""
    paths = _all_path_commands(monkeypatch, family)
    assert len(paths) >= 4
    hung: dict[str, Exception] = {
        paths[0]: _exec_timeout(paths[0]),
        paths[1]: ssh.CommandFailed("% Invalid input detected at '^' marker."),
        paths[2]: _exec_timeout(paths[2]),
    }
    fake = _install(monkeypatch, family, hung)

    _collector(family).fetch()

    assert [c for c in fake.commands if c in set(paths)] == paths
