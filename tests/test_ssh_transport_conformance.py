"""SSH transport plumbing shared by every CLI collector (`cli_collector.py`)."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pytest
from tests.conftest import FakeSshSession

import test_iosxe as ix
import test_iosxr as ir
import test_nxos as nx
import test_vyos as vy
from hst.collectors import iosxe, iosxr, nxos
from hst.collectors.auth import SshPassword
from hst.collectors.base import RAW_OUTCOMES_KEY


@dataclass(frozen=True)
class Rig:
    id: str
    collector: Callable[[], Any]  # unpinned collector, config defaults
    pinned: Callable[[str], Any]  # collector configured with the given host_key pin
    run: Callable[[Any, str], str]  # collector, command -> transport call
    command: str  # the command the plumbing tests issue
    host: str
    user: str


TRANSPORT_RIGS = [
    Rig(
        "iosxe",
        ix._collector,
        lambda k: ix.IosxeCollector(
            ix.IosxeConfig(host=ix.HOST, auth=SshPassword(username=ix.USER, password="pw"), host_key=k),
            None,
        ),
        lambda c, cmd: c._run(cmd),
        "show version",
        ix.HOST,
        ix.USER,
    ),
    Rig(
        "iosxr",
        ir._collector,
        lambda k: ir.IosxrCollector(
            ir.IosxrConfig(host=ir.HOST, auth=SshPassword(username=ir.USER, password="pw"), host_key=k),
            None,
        ),
        lambda c, cmd: c._run(cmd),
        "show version",
        ir.HOST,
        ir.USER,
    ),
    Rig(
        "nxos",
        nx._collector,
        lambda k: nx.NxosCollector(
            nx.NxosConfig(host=nx.HOST, auth=SshPassword(username=nx.USER, password="pw"), host_key=k),
            None,
        ),
        lambda c, cmd: c._run(cmd),
        "show version | json",
        nx.HOST,
        nx.USER,
    ),
    Rig(
        "vyos",
        vy._collector,
        lambda k: vy.VyosCollector(
            vy.VyosConfig(host=vy.HOST, auth=SshPassword(username=vy.USER, password="pw"), host_key=k),
            None,
        ),
        lambda c, cmd: c._ssh(cmd),
        "ip -j link show",
        vy.HOST,
        vy.USER,
    ),
]

# `fetch()`'s one-transport, keyed-by-command loop is `CiscoCliCollector`'s; VyOS
# implements its own (see the module docstring).
CISCO_TRIO = [r for r in TRANSPORT_RIGS if r.id != "vyos"]
CISCO_RAW = {"iosxe": (ix.RAW, iosxe), "iosxr": (ir.RAW, iosxr), "nxos": (nx.RAW, nxos)}


def _outputs_of(raw):
    """The command outputs of a fetched payload, without the per-command
    outcomes the fetch records beside them under the reserved key."""
    return {k: v for k, v in raw.items() if k != RAW_OUTCOMES_KEY}


@pytest.mark.parametrize("rig", TRANSPORT_RIGS, ids=lambda r: r.id)
def test_run_passes_auth_and_pin_to_the_transport(rig, monkeypatch):
    fake = FakeSshSession(lambda cmd: "OUT", host_key="ssh-ed25519 OBSERVED").install(monkeypatch)
    collector = rig.collector()
    assert rig.run(collector, rig.command) == "OUT"
    assert fake.commands == [rig.command]
    conn = fake.connection
    assert conn["host"] == rig.host and conn["auth"].username == rig.user
    assert conn["known_host_key"] == "" and conn["port"] == 22 and conn["jump"] is None


@pytest.mark.parametrize("rig", TRANSPORT_RIGS, ids=lambda r: r.id)
def test_run_records_the_observed_host_keys(rig, monkeypatch):
    FakeSshSession(
        lambda cmd: "OUT", host_key="ssh-ed25519 OBSERVED", jump_host_key="ssh-ed25519 BASTION"
    ).install(monkeypatch)
    collector = rig.collector()
    rig.run(collector, rig.command)
    assert collector.observed_host_key == "ssh-ed25519 OBSERVED"
    assert collector.observed_jump_key == "ssh-ed25519 BASTION"


@pytest.mark.parametrize("rig", TRANSPORT_RIGS, ids=lambda r: r.id)
def test_configured_host_key_is_forwarded_as_the_pin(rig, monkeypatch):
    fake = FakeSshSession(lambda cmd: "OUT", host_key="ssh-ed25519 PINNED").install(monkeypatch)
    rig.run(rig.pinned("ssh-ed25519 PINNED"), rig.command)
    assert fake.connection["known_host_key"] == "ssh-ed25519 PINNED"


@pytest.mark.parametrize("rig", CISCO_TRIO, ids=lambda r: r.id)
def test_fetch_runs_every_command_and_keys_by_command(rig, monkeypatch):
    """The static command list runs first, in order."""
    raw, module = CISCO_RAW[rig.id]
    fake = FakeSshSession(raw).install(monkeypatch)
    out = rig.collector().fetch()
    assert fake.commands[: len(module.COMMANDS)] == list(module.COMMANDS)
    assert sorted(fake.commands) == sorted(raw)
    assert _outputs_of(out) == raw


@pytest.mark.parametrize("rig", CISCO_TRIO, ids=lambda r: r.id)
def test_fetch_opens_exactly_one_transport(rig, monkeypatch):
    raw, module = CISCO_RAW[rig.id]
    fake = FakeSshSession(raw).install(monkeypatch)
    rig.collector().fetch()
    assert len(fake.connections) == 1
    assert set(module.COMMANDS) <= set(fake.commands)
    assert len(fake.commands) == len(raw)


PROBE_CASES = [
    ("iosxe", ix._collector, lambda: ix.VERSION_TEXT, "Cisco IOS XE Software, Version 17.03.04a"),
    ("iosxr", ir._collector, lambda: ir.VERSION_TEXT, "Cisco IOS XR Software, Version 7.3.2"),
    ("nxos", nx._collector, lambda: json.dumps(nx.VERSION_PAYLOAD), "9.3(5)"),
]


@pytest.mark.parametrize(
    "collector, version_output, expected", [c[1:] for c in PROBE_CASES], ids=[c[0] for c in PROBE_CASES]
)
def test_collector_scope_and_probe(collector, version_output, expected, monkeypatch):
    c = collector()
    assert c.scope == f"{c.name}:{c.config.host}"
    assert c.config.host_key == ""

    FakeSshSession(lambda cmd: version_output()).install(monkeypatch)
    assert c.probe() == expected


EMPTY_PROBE_CASES = [
    ("iosxe", ix._collector, "\n\n"),
    ("iosxr", ir._collector, "\n\n"),
    ("nxos", nx._collector, json.dumps({})),
]


@pytest.mark.parametrize(
    "collector, empty_output", [c[1:] for c in EMPTY_PROBE_CASES], ids=[c[0] for c in EMPTY_PROBE_CASES]
)
def test_probe_handles_empty_version_output(collector, empty_output, monkeypatch):
    FakeSshSession(lambda cmd: empty_output).install(monkeypatch)
    assert collector().probe() == "connected (empty version output)"


# The fake stamps each recorded connection with the seam that served it.


def _with_transport(collector, transport: str):
    collector.config = collector.config.model_copy(update={"transport": transport})
    return collector


@pytest.mark.parametrize("rig", TRANSPORT_RIGS, ids=lambda r: r.id)
def test_the_default_transport_is_asyncssh(rig, monkeypatch):
    fake = FakeSshSession(lambda cmd: "OUT").install(monkeypatch)
    collector = rig.collector()
    assert collector.config.transport == "asyncssh"
    assert rig.run(collector, rig.command) == "OUT"
    assert fake.connection["seam"] == "asyncssh"


@pytest.mark.parametrize("rig", TRANSPORT_RIGS, ids=lambda r: r.id)
def test_the_paramiko_override_routes_to_the_sync_transport(rig, monkeypatch):
    fake = FakeSshSession(lambda cmd: "OUT").install(monkeypatch)
    collector = _with_transport(rig.collector(), "paramiko")
    assert rig.run(collector, rig.command) == "OUT"
    assert fake.connection["seam"] == "paramiko"


@pytest.mark.parametrize("rig", CISCO_TRIO, ids=lambda r: r.id)
def test_a_paramiko_fetch_matches_the_asyncssh_fetch(rig, monkeypatch):
    raw, _module = CISCO_RAW[rig.id]
    fake = FakeSshSession(raw).install(monkeypatch)
    out = _with_transport(rig.collector(), "paramiko").fetch()
    assert _outputs_of(out) == raw
    assert len(fake.connections) == 1
    assert fake.connection["seam"] == "paramiko"


def test_a_paramiko_vyos_fetch_matches_the_asyncssh_fetch(monkeypatch):
    fake_a = FakeSshSession(vy._fetch_outputs).install(monkeypatch)
    asyncssh_raw = vy._collector().fetch()
    fake_b = FakeSshSession(vy._fetch_outputs).install(monkeypatch)
    paramiko_raw = _with_transport(vy._collector(), "paramiko").fetch()
    assert paramiko_raw == asyncssh_raw
    assert fake_a.connection["seam"] == "asyncssh"
    assert fake_b.connection["seam"] == "paramiko"
