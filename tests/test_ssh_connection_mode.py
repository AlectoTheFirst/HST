"""Collection against devices that permit only one command per connection."""

import asyncio
from contextlib import asynccontextmanager, contextmanager

import pytest
from tests.test_assh_transport import PW, _server
from tests.test_cli_collector import AUTH, DemoCollector, DemoConfig

from hst.collectors import assh, ssh
from hst.collectors.auth import SshJumpHost
from hst.collectors.base import RAW_OUTCOMES_KEY


@pytest.mark.parametrize("transport", ["asyncssh", "paramiko"])
@pytest.mark.parametrize("entry", ["fetch", "afetch"])
@pytest.mark.parametrize("fresh", [False, True])
async def test_single_command_device_and_connection_cleanup(monkeypatch, transport, entry, fresh):
    events = []
    connections = []
    jump = SshJumpHost(host="bastion", auth=AUTH)

    class SingleCommandSession:
        host_key = "device-pin"
        jump_host_key = "bastion-pin"

        def __init__(self):
            self.used = False

        def run(self, command):
            if self.used:
                raise ssh.SshError("SSH connection closed")
            self.used = True
            events.append(command)
            return command

    @contextmanager
    def sync_session(host, auth, **kwargs):
        assert host == "device" and auth == AUTH
        connections.append(kwargs)
        events.append("open")
        try:
            yield SingleCommandSession()
        finally:
            events.append("close")

    @asynccontextmanager
    async def async_session(host, auth, **kwargs):
        with sync_session(host, auth, **kwargs) as session:

            class AsyncView:
                host_key = session.host_key
                jump_host_key = session.jump_host_key

                async def run(self, command):
                    return session.run(command)

            yield AsyncView()

    monkeypatch.setattr(ssh, "session", sync_session)
    monkeypatch.setattr(assh, "session", async_session)
    config = DemoConfig(
        host="device",
        auth=AUTH,
        jump_host=jump,
        transport=transport,
        fresh_connection_per_command=fresh,
        port=2222,
        timeout=11,
        connect_timeout=12,
        read_timeout=13,
    )
    collector = DemoCollector(config, None)

    async def collect():
        if entry == "fetch":
            return await asyncio.to_thread(collector.fetch)
        return await collector.afetch()

    if not fresh:
        with pytest.raises(ssh.SshError, match="SSH connection closed"):
            await collect()
        assert events == ["open", "show version", "close"]
        return

    raw = await collect()
    assert raw["show version"] == "show version"
    assert raw["show inventory"] == "show inventory"
    assert events == ["open", "show version", "close", "open", "show inventory", "close"]
    assert connections[0]["known_host_key"] == ""
    assert connections[1]["known_host_key"] == "device-pin"
    assert connections[1]["jump"].host_key == "bastion-pin"
    assert jump.host_key == ""
    assert collector.observed_host_key == "device-pin"
    assert collector.observed_jump_key == "bastion-pin"
    for connection in connections:
        assert connection["port"] == 2222
        assert connection["timeout"] == 11
        assert connection["connect_timeout"] == 12
        assert connection["read_timeout"] == 13


@pytest.mark.parametrize("transport", ["asyncssh", "paramiko"])
async def test_fresh_connections_over_real_ssh_keep_pins_and_optional_failures(transport):
    outputs = {"show version": ("version", "", 0), "show inventory": ("", "unsupported", 1)}
    async with _server(outputs) as (rec, port, pin):
        collector = DemoCollector(
            DemoConfig(
                host="127.0.0.1",
                port=port,
                auth=PW,
                host_key=pin,
                transport=transport,
                fresh_connection_per_command=True,
            ),
            None,
        )
        raw = await collector.afetch()
        assert rec.connections == 2
        assert raw["show version"] == "version"
        assert raw["show inventory"] == "STANDIN"
        assert raw[RAW_OUTCOMES_KEY]["show inventory"]["status"] == "failed"
        assert collector.observed_host_key == pin


async def test_reconnect_rejects_changed_device_key_before_authentication():
    async with (
        _server({"show version": ("version", "", 0)}) as (_, port, _),
        _server({"show inventory": ("inventory", "", 0)}) as (other, other_port, _),
    ):

        class RedirectedCollector(DemoCollector):
            async def _afetch_over(self, session):
                await session.run("show version")
                # Emulate an endpoint whose SSH key changes between commands.
                session._kwargs["port"] = other_port
                return await session.run("show inventory")

        collector = RedirectedCollector(
            DemoConfig(
                host="127.0.0.1",
                port=port,
                auth=PW,
                fresh_connection_per_command=True,
            ),
            None,
        )
        with pytest.raises(ssh.HostKeyMismatch):
            await collector.afetch()
        assert other.auth == []


def test_fresh_connection_mode_is_opt_in():
    assert DemoConfig(auth=AUTH).fresh_connection_per_command is False
