"""SshCliCollector scaffolding: the shared SshSourceConfig defaults, per-group
time budgets forwarded to the transport seam, transport routing between the
sync and async entries, the optional/required command split, observed-key
capture, and the Cisco subclass's scope string and per-fetch parse cache.

The SSH layer is faked at the same seam the transport tests use: the
`session` entry points on `ssh` and `assh`, via tests.conftest.FakeSshSession.
"""

from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from tests.conftest import FakeSshSession

from hst.collectors import ssh
from hst.collectors.auth import SshJumpHost, SshPassword
from hst.collectors.base import RAW_OUTCOMES_KEY
from hst.collectors.cli_collector import CiscoCliCollector, SshCliCollector, SshSourceConfig

AUTH = SshPassword(username="ro", password="pw")


class DemoConfig(SshSourceConfig):
    pass


class DemoCollector(SshCliCollector):
    name = "demo"
    ConfigModel = DemoConfig
    COMMANDS = ("show version", "show inventory")
    OPTIONAL_COMMANDS = {"show inventory": "STANDIN"}

    def normalize(self, raw):  # pragma: no cover - not under test
        raise NotImplementedError

    def probe(self):  # pragma: no cover - not under test
        raise NotImplementedError


def _collector(**overrides):
    fields = {"host": "r1", "auth": AUTH}
    fields.update(overrides)
    return DemoCollector(DemoConfig(**fields), None)


OUTPUTS = {"show version": "V", "show inventory": "I"}


def _outputs_of(raw):
    """The command outputs of a fetched payload, without the per-command
    outcomes the fetch records beside them under the reserved key."""
    return {k: v for k, v in raw.items() if k != RAW_OUTCOMES_KEY}


def _statuses_of(raw):
    return {k: v["status"] for k, v in raw[RAW_OUTCOMES_KEY].items()}


# --- config validation ------------------------------------------------------


def test_host_defaults_to_empty_meaning_device_group_source():
    """An empty host is legal at model time: the source is a device group and
    the fleet rows carry the hosts. Only prepare time may reject it."""
    assert DemoConfig(auth=AUTH).host == ""


def test_connection_field_defaults():
    cfg = DemoConfig(auth=AUTH)
    assert cfg.port == 22
    assert cfg.host_key == ""
    assert cfg.jump_host is None


def test_transport_defaults_to_asyncssh_and_rejects_unknown_values():
    assert DemoConfig(auth=AUTH).transport == "asyncssh"
    assert DemoConfig(auth=AUTH, transport="paramiko").transport == "paramiko"
    with pytest.raises(ValidationError):
        DemoConfig(auth=AUTH, transport="telnet")


def test_per_group_time_budget_defaults():
    cfg = DemoConfig(auth=AUTH)
    assert cfg.timeout == 120
    assert cfg.connect_timeout == 10
    assert cfg.read_timeout == ssh.DEFAULT_READ_TIMEOUT


def test_routing_scope_falls_back_to_site_code_and_accepts_the_l3dom_alias():
    cfg = DemoConfig(auth=AUTH, site_code="dc1")
    assert cfg.effective_routing_scope == "dc1"
    aliased = DemoConfig(auth=AUTH, site_code="dc1", l3dom="core")
    assert aliased.routing_scope == "core"
    assert aliased.effective_routing_scope == "core"


def test_transport_property_defaults_to_asyncssh_when_the_config_lacks_the_field():
    collector = DemoCollector(SimpleNamespace(host="r1", auth=AUTH), None)
    assert collector.transport == "asyncssh"


# --- session kwargs and transport routing -----------------------------------


def test_fetch_forwards_the_groups_budgets_and_pin_to_the_session(monkeypatch):
    fake = FakeSshSession(OUTPUTS).install(monkeypatch)
    jump = SshJumpHost(host="bastion", auth=AUTH)
    _collector(
        port=2222,
        host_key="ssh-ed25519 PINNED",
        jump_host=jump,
        timeout=7,
        connect_timeout=3,
        read_timeout=9,
    ).fetch()
    conn = fake.connection
    assert conn["host"] == "r1"
    assert conn["port"] == 2222
    assert conn["known_host_key"] == "ssh-ed25519 PINNED"
    assert conn["jump"] is jump
    assert conn["timeout"] == 7
    assert conn["connect_timeout"] == 3
    assert conn["read_timeout"] == 9


def test_fetch_with_asyncssh_uses_the_async_seam(monkeypatch):
    fake = FakeSshSession(OUTPUTS).install(monkeypatch)
    raw = _collector().fetch()
    assert fake.connection["seam"] == "asyncssh"
    assert _outputs_of(raw) == {"show version": "V", "show inventory": "I"}


def test_fetch_with_paramiko_uses_the_sync_seam(monkeypatch):
    fake = FakeSshSession(OUTPUTS).install(monkeypatch)
    raw = _collector(transport="paramiko").fetch()
    assert fake.connection["seam"] == "paramiko"
    assert _outputs_of(raw) == {"show version": "V", "show inventory": "I"}


async def test_afetch_with_asyncssh_runs_on_the_callers_loop(monkeypatch):
    fake = FakeSshSession(OUTPUTS).install(monkeypatch)
    raw = await _collector().afetch()
    assert fake.connection["seam"] == "asyncssh"
    assert _outputs_of(raw) == {"show version": "V", "show inventory": "I"}


async def test_afetch_bounces_a_paramiko_device_to_the_sync_seam(monkeypatch):
    fake = FakeSshSession(OUTPUTS).install(monkeypatch)
    raw = await _collector(transport="paramiko").afetch()
    assert fake.connection["seam"] == "paramiko"
    assert _outputs_of(raw) == {"show version": "V", "show inventory": "I"}


def test_one_fetch_opens_one_session_and_runs_the_commands_in_order(monkeypatch):
    fake = FakeSshSession(OUTPUTS).install(monkeypatch)
    _collector().fetch()
    assert len(fake.connections) == 1
    assert fake.commands == ["show version", "show inventory"]


# --- optional/required command split ----------------------------------------


def _outputs_refusing(refused: str, message: str = "refused"):
    def outputs(cmd: str) -> str:
        if cmd == refused:
            raise ssh.CommandFailed(message)
        return OUTPUTS[cmd]

    return outputs


def test_a_refused_optional_command_is_replaced_by_its_stand_in(monkeypatch, caplog):
    """The stand-in lands, and the payload says it is a stand-in: the refusal
    is recorded against that command and every other command reads ok."""
    FakeSshSession(_outputs_refusing("show inventory")).install(monkeypatch)
    raw = _collector().fetch()
    assert _outputs_of(raw) == {"show version": "V", "show inventory": "STANDIN"}
    assert _statuses_of(raw) == {"show version": "ok", "show inventory": "failed"}
    assert raw[RAW_OUTCOMES_KEY]["show inventory"]["detail"] == "refused"
    assert "show inventory" in caplog.text


def test_the_log_line_of_a_refused_optional_command_holds_no_credential(monkeypatch, caplog):
    message = "'show inventory' exited 1: tacacs-server key 7 S3cr3t-1"
    FakeSshSession(_outputs_refusing("show inventory", message)).install(monkeypatch)
    _collector().fetch()
    assert "show inventory" in caplog.text
    assert "S3cr3t-1" not in caplog.text


def test_a_permission_denied_optional_command_records_unauthorized(monkeypatch):
    FakeSshSession(
        _outputs_refusing("show inventory", "'show inventory' exited 1: Permission denied")
    ).install(monkeypatch)
    raw = _collector().fetch()
    assert _statuses_of(raw) == {"show version": "ok", "show inventory": "unauthorized"}


def test_a_command_the_platform_does_not_have_records_unsupported(monkeypatch):
    """A rejection banner is the box saying it has no such command."""
    FakeSshSession(
        _outputs_refusing("show inventory", "'show inventory' rejected by device: % Invalid input detected")
    ).install(monkeypatch)
    raw = _collector().fetch()
    assert _statuses_of(raw) == {"show version": "ok", "show inventory": "unsupported"}


def test_a_refused_required_command_aborts_the_fetch(monkeypatch):
    FakeSshSession(_outputs_refusing("show version")).install(monkeypatch)
    with pytest.raises(ssh.CommandFailed):
        _collector().fetch()


def test_the_paramiko_path_runs_the_same_command_loop(monkeypatch):
    """The optional-command substitution holds over the facade."""
    FakeSshSession(_outputs_refusing("show inventory")).install(monkeypatch)
    raw = _collector(transport="paramiko").fetch()
    assert _outputs_of(raw) == {"show version": "V", "show inventory": "STANDIN"}


# --- observed-key capture ---------------------------------------------------


def test_fetch_captures_the_observed_keys_for_pinning(monkeypatch):
    FakeSshSession(OUTPUTS, host_key="ssh-ed25519 HK", jump_host_key="ssh-ed25519 JK").install(monkeypatch)
    collector = _collector()
    assert collector.observed_host_key == ""
    assert collector.observed_jump_key == ""
    collector.fetch()
    assert collector.observed_host_key == "ssh-ed25519 HK"
    assert collector.observed_jump_key == "ssh-ed25519 JK"


def test_the_paramiko_path_captures_the_observed_keys_too(monkeypatch):
    FakeSshSession(OUTPUTS, host_key="ssh-ed25519 HK").install(monkeypatch)
    collector = _collector(transport="paramiko")
    collector.fetch()
    assert collector.observed_host_key == "ssh-ed25519 HK"


# --- the Cisco subclass: scope and parse cache ------------------------------


def _demo_cisco():
    calls = []

    class DemoCisco(CiscoCliCollector):
        name = "ciscoq"
        ConfigModel = DemoConfig

        @staticmethod
        def _parse(raw):
            calls.append(raw)
            return {"device": {"serial": "SER1"}}

        def probe(self):  # pragma: no cover - not under test
            raise NotImplementedError

    return DemoCisco, calls


def test_cisco_scope_is_name_colon_host():
    cls, _ = _demo_cisco()
    collector = cls(DemoConfig(host="c1", auth=AUTH), None)
    assert collector.scope == "ciscoq:c1"


def test_cisco_parse_cache_is_keyed_on_the_raw_dicts_identity():
    """The next fetch's dict reparses when its content is equal."""
    cls, calls = _demo_cisco()
    collector = cls(DemoConfig(host="c1", auth=AUTH), None)
    raw = {"show version": "V"}
    first = collector._inter(raw)
    assert collector._inter(raw) is first
    assert len(calls) == 1
    collector._inter({"show version": "V"})
    assert len(calls) == 2
