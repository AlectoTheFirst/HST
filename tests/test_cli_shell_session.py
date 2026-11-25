"""A login banner never reaches a parser.

A device prints its configured banners once per login, in front of the first
prompt. An exec channel has no prompt to read up to, so whatever the login
printed lands in front of the first command's output, and a TextFSM template
sends the first line it does not know to an Error state, which fails the whole
command, not the banner line.

An interactive shell reads each command's output up to the prompt.
"""

from __future__ import annotations

import asyncio

import pytest
from ntc_templates.parse import parse_output
from tests.conftest import FakeSshSession
from tests.test_cli_text_sanitize import SHOW_VRF, VRF_NAMES
from textfsm import TextFSMError

from hst.collectors import assh, iosxe, ssh
from hst.collectors.auth import SshPassword
from hst.collectors.base import RAW_OUTCOMES_KEY
from hst.collectors.cli_collector import SshCliCollector, SshSourceConfig
from hst.collectors.cli_parse import parse
from hst.collectors.ssh import ShellSession, shell_output_of, shell_prompt_of

AUTH = SshPassword(username="ro", password="pw")
PROMPT = "r1#"

# A banner of the shape that fails a parse, hand-written per CONTRIBUTING.md: a
# delimiter line, a box, and the empty line the device puts before the prompt.
# The delimiter is `C` on a device whose banners were configured with a literal
# `C` in place of Ctrl-C, and one `C` arrives per configured banner.
BANNER = (
    "CCCC\n"
    "**********************************************************\n"
    "*  Authorised access only. All activity is recorded.     *\n"
    "**********************************************************\n"
    "\n"
)
LOGIN = BANNER + PROMPT


class FakeChannel:
    """A paramiko `Channel` that answers from a script.

    `recv` hands back one queued chunk per call and raises `TimeoutError` when
    the queue is empty, which is what a real channel does when the device has
    gone quiet. A bare newline is answered with the prompt alone, as a device at
    an exec prompt answers it, and it is counted rather than added to `sent`.
    Every other `sendall` queues the echo, the answer and the prompt, in the
    order a device sends them.

    `prompt=""` is a device that never prompts.
    """

    def __init__(self, login: str, answers: dict[str, str], prompt: str = PROMPT) -> None:
        self._answers = answers
        self._prompt = prompt
        self._queue = [login]
        self.sent: list[str] = []
        self.newlines = 0
        self.timeouts = 0

    def settimeout(self, seconds: float) -> None:
        self.timeout = seconds

    def recv(self, size: int) -> bytes:
        if not self._queue:
            self.timeouts += 1
            raise TimeoutError
        return self._queue.pop(0).encode()

    def sendall(self, data: bytes) -> None:
        command = data.decode().strip()
        if not command:
            self.newlines += 1
            self._queue.append(f"\r\n{self._prompt}")
            return
        self.sent.append(command)
        answer = self._answers.get(command, "")
        self._queue.append(f"{command}\r\n{answer}{self._prompt}")


def _shell(
    login: str = LOGIN,
    answers: dict[str, str] | None = None,
    prompt: str = PROMPT,
    **kwargs,
) -> ShellSession:
    channel = FakeChannel(login, answers or {}, prompt)
    shell = ShellSession(channel, "k", "", read_timeout=5, **kwargs)
    shell.channel = channel
    return shell


# --- the fault the shell exists for -----------------------------------------


def test_a_banner_in_front_of_the_output_fails_the_whole_command():
    """The template itself, which is the fault the shell exists for."""
    with pytest.raises(TextFSMError) as caught:
        parse_output(platform="cisco_ios", command=iosxe.CMD_VRF, data=BANNER + SHOW_VRF)
    message = str(caught.value)
    # Rule 13 of `cisco_ios_show_vrf.textfsm` is the `Start` state's `^. -> Error`.
    assert "State Error raised" in message
    assert "Input Line: CCCC" in message


def test_the_preamble_trim_reads_that_same_text():
    """`cli_parse.parse` drops leading lines the `Start` state sends to Error."""
    assert [r["name"] for r in parse("iosxe", iosxe.CMD_VRF, BANNER + SHOW_VRF)] == VRF_NAMES


def test_the_shell_reads_the_banner_at_login_and_no_command_carries_it():
    shell = _shell(answers={iosxe.CMD_VRF: SHOW_VRF})
    output = shell.run(iosxe.CMD_VRF)
    assert "CCCC" not in output
    assert [r["name"] for r in parse("iosxe", iosxe.CMD_VRF, output)] == VRF_NAMES


# --- the prompt -------------------------------------------------------------


def test_the_prompt_is_the_last_line_of_the_login_burst():
    assert shell_prompt_of(LOGIN) == PROMPT
    assert shell_prompt_of(BANNER + "r1>") == "r1>"


def test_text_that_ends_in_no_prompt_has_none():
    assert shell_prompt_of(BANNER) == ""
    assert shell_prompt_of("") == ""
    assert shell_prompt_of("a line of prose with a # in it") == ""


def test_a_login_with_no_prompt_is_a_failure_and_names_what_came_back():
    with pytest.raises(ssh.SshError) as caught:
        _shell(login=BANNER, prompt="")
    assert "prompt did not settle" in str(caught.value)


def test_the_prompt_is_confirmed_by_a_bare_newline():
    """A device that pauses inside its banner ends the burst on a banner line,
    and a banner rule of `#` characters is prompt-shaped. Only the answer to a
    bare newline decides, and it has to answer the same twice."""
    boxed = "################################\n" + LOGIN
    shell = _shell(login=boxed, answers={iosxe.CMD_VRF: SHOW_VRF})
    assert shell.prompt == PROMPT
    assert shell.channel.newlines >= 2
    assert [r["name"] for r in parse("iosxe", iosxe.CMD_VRF, shell.run(iosxe.CMD_VRF))] == VRF_NAMES


def test_a_shell_the_device_closes_at_login_is_a_failure():
    class Closed(FakeChannel):
        def recv(self, size: int) -> bytes:
            return b""

    with pytest.raises(ssh.SshError, match="closed the shell"):
        ShellSession(Closed(LOGIN, {}), "k", "", read_timeout=5)


# --- one command's output ---------------------------------------------------


def test_the_echo_and_the_prompt_go_and_the_output_stays():
    text = f"show vrf\n{SHOW_VRF}{PROMPT}"
    assert shell_output_of(text, "show vrf", PROMPT) == SHOW_VRF


def test_a_first_line_that_is_not_the_echo_stays():
    text = f"{SHOW_VRF}{PROMPT}"
    assert shell_output_of(text, "show vrf", PROMPT) == SHOW_VRF


def test_output_that_repeats_the_command_keeps_every_line_but_the_echo():
    """Only the first line is a candidate, so a configuration line that reads
    back as the command itself survives."""
    command = "show running-config | include hostname"
    text = f"{command}\nhostname r1\n{command}\n{PROMPT}"
    assert shell_output_of(text, command, PROMPT) == f"hostname r1\n{command}\n"


def test_a_command_that_printed_nothing_comes_back_empty():
    assert shell_output_of(f"show vrf\n{PROMPT}", "show vrf", PROMPT) == ""


def test_a_device_rejection_fails_the_command():
    shell = _shell(answers={"show nonsense": "% Invalid input detected at '^' marker.\n"})
    with pytest.raises(ssh.CommandFailed, match="rejected by device"):
        shell.run("show nonsense")


# --- the setup commands -----------------------------------------------------


def test_the_setup_commands_run_first_and_their_output_is_not_returned():
    shell = _shell(answers={iosxe.CMD_VRF: SHOW_VRF}, setup=("terminal length 0",))
    shell.run(iosxe.CMD_VRF)
    assert shell.channel.sent == ["terminal length 0", iosxe.CMD_VRF]


# --- the async twin ---------------------------------------------------------


class FakeStream:
    def __init__(self, channel: FakeChannel) -> None:
        self._channel = channel

    async def read(self, size: int) -> str:
        return self._channel.recv(size).decode()


class FakeProcess:
    """An asyncssh process over the same script the paramiko fake answers from."""

    def __init__(self, channel: FakeChannel) -> None:
        self._channel = channel
        self.stdout = FakeStream(channel)
        self.closed = False

    class _Stdin:
        def __init__(self, channel: FakeChannel) -> None:
            self._channel = channel

        def write(self, data: str) -> None:
            self._channel.sendall(data.encode())

    @property
    def stdin(self) -> _Stdin:
        return self._Stdin(self._channel)

    def close(self) -> None:
        self.closed = True


class FakeConnection:
    def __init__(self, channel: FakeChannel) -> None:
        self._channel = channel
        self.term: dict = {}

    async def create_process(self, **kwargs) -> FakeProcess:
        self.term = kwargs
        return FakeProcess(self._channel)


async def _ashell(
    login: str = LOGIN,
    answers: dict[str, str] | None = None,
    prompt: str = PROMPT,
    **kwargs,
) -> assh.AsyncShellSession:
    channel = FakeChannel(login, answers or {}, prompt)
    conn = FakeConnection(channel)
    shell = await assh.AsyncShellSession.open(conn, "k", "", read_timeout=5, **kwargs)
    shell.channel = channel
    shell.conn = conn
    return shell


async def test_the_async_shell_reads_the_banner_at_login_too():
    shell = await _ashell(answers={iosxe.CMD_VRF: SHOW_VRF})
    assert shell.prompt == PROMPT
    output = await shell.run(iosxe.CMD_VRF)
    assert "CCCC" not in output
    assert [r["name"] for r in parse("iosxe", iosxe.CMD_VRF, output)] == VRF_NAMES


async def test_the_async_shell_asks_for_a_pty_wide_enough_not_to_wrap():
    shell = await _ashell()
    assert shell.conn.term["term_size"] == (ssh.SHELL_WIDTH, ssh.SHELL_HEIGHT)


async def test_the_async_shell_runs_the_setup_commands_first():
    shell = await _ashell(answers={iosxe.CMD_VRF: SHOW_VRF}, setup=("terminal length 0",))
    await shell.run(iosxe.CMD_VRF)
    assert shell.channel.sent == ["terminal length 0", iosxe.CMD_VRF]


async def test_the_async_shell_fails_a_rejected_command_the_same_way():
    shell = await _ashell(answers={"show nonsense": "% Invalid input detected at '^' marker.\n"})
    with pytest.raises(ssh.CommandFailed, match="rejected by device"):
        await shell.run("show nonsense")


async def test_the_async_shell_needs_a_prompt_too():
    with pytest.raises(ssh.SshError, match="prompt did not settle"):
        await _ashell(login=BANNER, prompt="")


async def test_a_device_that_never_opens_the_shell_is_a_timeout_not_a_hang():
    class NeverAnswers(FakeConnection):
        async def create_process(self, **kwargs):
            await asyncio.Event().wait()

    conn = NeverAnswers(FakeChannel(LOGIN, {}))
    with pytest.raises(ssh.SshTimeout, match="did not open a shell within"):
        await assh.AsyncShellSession.open(conn, "k", "", read_timeout=5, open_timeout=0.05)


async def test_a_refused_pty_is_a_named_transport_error():
    import asyncssh

    class RefusesPty(FakeConnection):
        async def create_process(self, **kwargs):
            raise asyncssh.ChannelOpenError(asyncssh.OPEN_REQUEST_PTY_FAILED, "PTY request failed")

    conn = RefusesPty(FakeChannel(LOGIN, {}))
    with pytest.raises(ssh.SshError, match=r"refused an interactive shell.*PTY request failed"):
        await assh.AsyncShellSession.open(conn, "k", "", read_timeout=5)


# --- the source's switch ----------------------------------------------------


class ShellConfig(SshSourceConfig):
    pass


class ShellCollector(SshCliCollector):
    name = "shell-demo"
    ConfigModel = ShellConfig
    COMMANDS = (iosxe.CMD_VRF,)
    SHELL_SETUP = ("terminal length 0",)

    def normalize(self, raw):  # pragma: no cover - not under test
        raise NotImplementedError

    def probe(self):  # pragma: no cover - not under test
        raise NotImplementedError


def _collector(**overrides):
    fields = {"host": "r1", "auth": AUTH}
    fields.update(overrides)
    return ShellCollector(ShellConfig(**fields), None)


def test_a_source_asks_for_an_exec_channel_by_default(monkeypatch):
    fake = FakeSshSession({iosxe.CMD_VRF: SHOW_VRF}).install(monkeypatch)
    _collector().fetch()
    assert fake.connection["channel"] == "exec"


@pytest.mark.parametrize("transport", ["asyncssh", "paramiko"])
def test_a_shell_source_carries_the_switch_and_the_setup_to_the_transport(monkeypatch, transport):
    fake = FakeSshSession({iosxe.CMD_VRF: SHOW_VRF}).install(monkeypatch)
    raw = _collector(channel="shell", transport=transport).fetch()
    assert fake.connection["channel"] == "shell"
    assert fake.connection["shell_setup"] == ("terminal length 0",)
    assert {k: v for k, v in raw.items() if k != RAW_OUTCOMES_KEY} == {iosxe.CMD_VRF: SHOW_VRF}


def test_the_cisco_families_kill_paging_in_a_shell():
    from hst.collectors.cli_collector import CiscoCliCollector

    assert "terminal length 0" in CiscoCliCollector.SHELL_SETUP


# --- the exec channel: the banner is read off the answers themselves ---------

# `banner motd ^CCCCC ... ^C`: the delimiter is ^C, and the text starts with the
# four C that followed it.
MOTD = (
    "CCCC\n"
    "**********************************************************\n"
    "*  Authorised access only. All activity is recorded.     *\n"
    "*  System Name: corp-edge  IP: 10.99.99.1 is monitored   *\n"
    "**********************************************************\n"
    "\n"
    "Load for five secs: 1%/0%; one minute: 1%; five minutes: 1%\n"
    "Time source is NTP, 08:02:57.000 UTC Thu Sep 24 2026\n"
    "\n"
    "Unauthorised use is prohibited.\n"
    "\n"
)


def test_the_banner_is_the_lines_every_answer_starts_with():
    from hst.collectors.cli_collector import exec_banner_of

    assert exec_banner_of([MOTD + SHOW_VRF, MOTD + "hostname r1\n", MOTD]) == MOTD
    assert exec_banner_of([MOTD + SHOW_VRF]) == ""
    assert exec_banner_of([SHOW_VRF, "hostname r1\n"]) == ""
    # a shared partial line is not a shared line
    assert exec_banner_of(["CCCCx\n", "CCCC\n"]) == ""


def test_an_answer_that_is_only_the_banner_is_empty():
    from hst.collectors.cli_collector import without_exec_banner

    assert without_exec_banner(MOTD + SHOW_VRF, MOTD) == SHOW_VRF
    assert without_exec_banner(MOTD, MOTD) == ""
    assert without_exec_banner(MOTD.rstrip("\n"), MOTD) == ""
    assert without_exec_banner(SHOW_VRF, MOTD) == SHOW_VRF
    assert without_exec_banner(SHOW_VRF, "") == SHOW_VRF


class TwoCommandCollector(ShellCollector):
    COMMANDS = (iosxe.CMD_VRF, "show hostname")
    STRIP_EXEC_BANNER = True


@pytest.mark.parametrize("transport", ["asyncssh", "paramiko"])
def test_an_exec_channel_loses_the_banner_on_every_command(monkeypatch, transport):
    answers = {iosxe.CMD_VRF: SHOW_VRF, "show hostname": "hostname r1\n"}
    FakeSshSession(lambda command: MOTD + answers[command]).install(monkeypatch)
    fields = {"host": "r1", "auth": AUTH, "transport": transport}
    raw = TwoCommandCollector(ShellConfig(**fields), None).fetch()
    assert raw[iosxe.CMD_VRF] == SHOW_VRF
    assert raw["show hostname"] == "hostname r1\n"


def test_a_refused_optional_command_does_not_hide_the_banner(monkeypatch):
    class WithOptional(TwoCommandCollector):
        OPTIONAL_COMMANDS = {"show hostname": ""}

    def answer(command: str) -> str:
        if command == "show hostname":
            raise ssh.CommandFailed("'show hostname' rejected by device: % Invalid input")
        return MOTD + SHOW_VRF

    FakeSshSession(answer).install(monkeypatch)
    raw = WithOptional(ShellConfig(host="r1", auth=AUTH), None).fetch()
    # one real answer is no basis for a comparison; the parse-side trim stands
    assert raw[iosxe.CMD_VRF] == MOTD + SHOW_VRF
    assert raw["show hostname"] == ""


def test_a_shell_answer_carries_no_banner_and_nothing_is_taken_off_it(monkeypatch):
    answers = {iosxe.CMD_VRF: SHOW_VRF, "show hostname": "hostname r1\n", "terminal length 0": ""}
    FakeSshSession(answers).install(monkeypatch)
    raw = TwoCommandCollector(ShellConfig(host="r1", auth=AUTH, channel="shell"), None).fetch()
    assert raw[iosxe.CMD_VRF] == SHOW_VRF


def test_every_iosxe_command_parses_behind_the_banner_as_it_does_without(monkeypatch):
    """The whole collector, every command answered behind the MOTD, against the
    same payload answered clean: one parse, one set of sections, one batch."""
    from tests.test_iosxe import RAW

    from hst.collectors import offline
    from hst.core.config import Settings

    collector = offline.build_collector("iosxe", Settings())
    FakeSshSession(lambda command: RAW.get(command, "")).install(monkeypatch)
    plain = collector.fetch()
    FakeSshSession(lambda command: MOTD + RAW.get(command, "")).install(monkeypatch)
    behind = collector.fetch()
    assert behind == plain
    clean = offline.parse_report(collector, plain, path="clean").as_dict()
    banner = offline.parse_report(collector, behind, path="banner").as_dict()
    assert banner["ok"], banner["error"]
    for key in ("sections", "labels", "side_tables", "outcomes"):
        assert banner[key] == clean[key], key


# --- the read loop ----------------------------------------------------------


class ScriptedChannel(FakeChannel):
    """A channel whose answer to a command arrives as a given list of chunks.

    A real read gets the output in whatever pieces the network hands over, and
    where the boundaries fall is what the prompt match has to survive.
    """

    def __init__(self, login: str, chunks: list[str], prompt: str = PROMPT) -> None:
        super().__init__(login, {}, prompt)
        self._chunks = list(chunks)

    def sendall(self, data: bytes) -> None:
        command = data.decode().strip()
        if not command:
            self.newlines += 1
            self._queue.append(f"\r\n{self._prompt}")
            return
        self.sent.append(command)
        self._queue.extend(self._chunks)


def _scripted(chunks: list[str]) -> ShellSession:
    channel = ScriptedChannel(LOGIN, chunks)
    shell = ShellSession(channel, "k", "", read_timeout=5)
    shell.channel = channel
    return shell


def test_a_chunk_that_ends_with_the_prompt_text_does_not_end_the_read():
    """The prompt match is anchored to a whole line."""
    shell = _scripted(["show run\r\nbanner motd r1#", "\r\nip forwarding\r\n" + PROMPT])
    output = shell.run("show run")
    assert "banner motd r1#" in output
    assert "ip forwarding" in output


def test_control_bytes_after_the_prompt_end_the_read():
    """The prompt is learned from sanitized text, so it has to be matched
    against sanitized text. A PTY is asked for, and a device that paints its
    prompt line puts an erase-to-end-of-line after it."""
    shell = _scripted([f"show vrf\r\n{SHOW_VRF}{PROMPT}\x1b[K"])
    assert [r["name"] for r in parse("iosxe", iosxe.CMD_VRF, shell.run("show vrf"))] == VRF_NAMES


def test_an_echo_that_is_not_the_first_line_is_cut():
    """The device echoes the command before it prints anything, so everything
    up to the echo is login noise."""
    shell = _scripted([f"\r\na trailing banner line\r\nshow vrf\r\n{SHOW_VRF}{PROMPT}"])
    output = shell.run("show vrf")
    assert "a trailing banner line" not in output
    assert [r["name"] for r in parse("iosxe", iosxe.CMD_VRF, output)] == VRF_NAMES


def test_a_login_that_ends_in_a_prompt_costs_no_idle_wait():
    """`_read_burst` returns on the first prompt-shaped line."""
    shell = _shell(answers={iosxe.CMD_VRF: SHOW_VRF})
    shell.run(iosxe.CMD_VRF)
    assert shell.channel.timeouts == 0


def test_a_refused_setup_command_does_not_cost_the_fetch():
    """A device that does not set its terminal answers every collected command."""
    shell = _shell(
        answers={
            "terminal width 511": "% Invalid input detected at '^' marker.\n",
            iosxe.CMD_VRF: SHOW_VRF,
        },
        setup=("terminal length 0", "terminal width 511"),
    )
    assert shell.channel.sent == ["terminal length 0", "terminal width 511"]
    assert [r["name"] for r in parse("iosxe", iosxe.CMD_VRF, shell.run(iosxe.CMD_VRF))] == VRF_NAMES


async def test_the_async_read_loop_holds_the_same_two_rules():
    channel = ScriptedChannel(LOGIN, ["show run\r\nbanner motd r1#", "\r\nip forwarding\r\n" + PROMPT])
    shell = await assh.AsyncShellSession.open(FakeConnection(channel), "k", "", read_timeout=5)
    output = await shell.run("show run")
    assert "banner motd r1#" in output
    assert "ip forwarding" in output
    assert channel.timeouts == 0
