"""Terminal control bytes never reach a parser.

A TextFSM template sends every line it does not know to an Error state, so one
line of control bytes fails the whole command rather than the one line. The
message quotes the line, and a log view drops the `ESC` bytes out of the
quotation, so the reader is left with an error that names no cause.

`ESC [ n C` is the one sequence a column-oriented parser cannot have deleted:
it moves the cursor n columns right, so a device that fills a column with it
rather than with spaces states the column that way.
"""

from __future__ import annotations

import asyncio

import pytest
from ntc_templates.parse import parse_output
from textfsm import TextFSMError

from hst.collectors import iosxe, offline
from hst.collectors.cli_parse import parse
from hst.collectors.ssh import sanitize_cli_text

ESC = "\x1b"

# An IOS-XE `show vrf`, hand-written per CONTRIBUTING.md but column for column
# what the release prints: the name at column 2, the RD at 35, the protocols at
# 57 and the member interfaces at 69. A continuation line one column to the left
# of 69 parses as a VRF of its own, so the column is the whole contract here.
SHOW_VRF = (
    "  Name                             Default RD            Protocols   Interfaces\n"
    "  Mgmt-intf                        <not set>             ipv4,ipv6   Gi0\n"
    "  blue                             65000:1               ipv4,ipv6   Lo1\n"
    "                                                                     Lo2\n"
    "                                                                     Te0/0/0\n"
    "  green                            65000:2               ipv4        Po1.200\n"
)
VRF_NAMES = ["Mgmt-intf", "blue", "green"]
BLUE_INTERFACES = ["Lo1", "Lo2", "Te0/0/0"]

# The same output as a terminal in the path leaves it. Each key names the shape.
CURSOR_ONLY_LINE = f"{ESC}[C{ESC}[C{ESC}[C{ESC}[C\n" + SHOW_VRF
COLUMNS_BY_CURSOR = SHOW_VRF.replace("  Name", f"{ESC}[2CName").replace(" " * 69, f"{ESC}[69C")
SHAPES = {
    "no control bytes at all": SHOW_VRF,
    "four cursor-forwards on a line of their own": CURSOR_ONLY_LINE,
    "columns filled by cursor-forward, not by spaces": COLUMNS_BY_CURSOR,
    "erase-to-end-of-line at each line end": "".join(f"{ln}{ESC}[K\n" for ln in SHOW_VRF.splitlines()),
    "colour codes around a field": SHOW_VRF.replace("Mgmt-intf", f"{ESC}[1;33mMgmt-intf{ESC}[0m"),
    "an OS command setting the window title": f"{ESC}]0;lab-rtr-01\x07" + SHOW_VRF,
    "CRLF line ends": SHOW_VRF.replace("\n", "\r\n"),
    "a bell and a backspace": SHOW_VRF.replace("Gi0", "Gi0\x07\x08"),
    "all of them together": (
        f"{ESC}[C{ESC}[C{ESC}[C{ESC}[C\r\n" + COLUMNS_BY_CURSOR.replace("\n", f"{ESC}[K\r\n")
    ),
}


# --- the fault the sanitize exists for ----------------------------------------------------


def test_a_line_of_cursor_forwards_fails_the_whole_command_unsanitized():
    """The template itself fails."""
    with pytest.raises(TextFSMError) as caught:
        parse_output(platform="cisco_ios", command=iosxe.CMD_VRF, data=CURSOR_ONLY_LINE)
    message = str(caught.value)
    # Rule 13 of `cisco_ios_show_vrf.textfsm` is the `Start` state's `^. -> Error`.
    assert "State Error raised" in message
    assert f"Input Line: {ESC}[C{ESC}[C{ESC}[C{ESC}[C" in message


def test_the_preamble_trim_reads_that_same_text_without_the_sanitize():
    assert [r["name"] for r in parse("iosxe", iosxe.CMD_VRF, CURSOR_ONLY_LINE)] == VRF_NAMES


def test_the_columns_are_what_breaks_when_a_sequence_is_only_deleted():
    # Deleting `ESC [ 69 C` moves the member interfaces to column 0, where the
    # template reads them as a VRF row with no RD.
    deleted = COLUMNS_BY_CURSOR.replace(f"{ESC}[69C", "").replace(f"{ESC}[2C", "")
    with pytest.raises(TextFSMError):
        parse("iosxe", iosxe.CMD_VRF, deleted)


# --- the sanitize ---------------------------------------------------------------------------


@pytest.mark.parametrize("shape", list(SHAPES), ids=list(SHAPES))
def test_every_shape_parses_to_the_same_vrfs_once_sanitized(shape):
    rows = parse("iosxe", iosxe.CMD_VRF, sanitize_cli_text(SHAPES[shape]))
    assert [r["name"] for r in rows] == VRF_NAMES
    assert rows[1]["interfaces"] == BLUE_INTERFACES


def test_cursor_forward_becomes_that_many_spaces():
    assert sanitize_cli_text(f"a{ESC}[3Cb") == "a   b"
    # No parameter means one column.
    assert sanitize_cli_text(f"a{ESC}[Cb") == "a b"


def test_a_line_left_holding_only_spaces_reads_as_empty():
    # A template skips an empty line and errors on a line of spaces, so the
    # right-strip is what makes an expanded control line harmless.
    assert sanitize_cli_text(f"{ESC}[4C\nx\n") == "\nx\n"
    assert sanitize_cli_text("x   \n") == "x\n"


def test_text_with_no_control_bytes_is_unchanged():
    for text in ("", "\n", SHOW_VRF, "  a\n\tb\n", '{"TABLE_vrf": {}}'):
        assert sanitize_cli_text(text) == text


def test_carriage_returns_become_newlines_and_a_bare_one_does_too():
    assert sanitize_cli_text("a\r\nb\r\n") == "a\nb\n"
    assert sanitize_cli_text("a\rb") == "a\nb"


def test_tabs_and_newlines_survive_and_the_other_controls_do_not():
    assert sanitize_cli_text("a\tb\n") == "a\tb\n"
    assert sanitize_cli_text("a\x00\x07\x08\x1f\x7fb\n") == "ab\n"


def test_an_os_command_sequence_goes_whether_or_not_it_is_terminated():
    assert sanitize_cli_text(f"{ESC}]0;title\x07x") == "x"
    assert sanitize_cli_text(f"{ESC}]0;title{ESC}\\x") == "x"


def test_a_cursor_forward_stops_at_the_terminal_width():
    """A terminal stops the cursor at its right margin."""
    from hst.collectors.ssh import SHELL_WIDTH

    assert sanitize_cli_text(f"a{ESC}[999999999Cb") == "a" + " " * SHELL_WIDTH + "b"
    assert sanitize_cli_text(f"a{ESC}[4Cb") == "a    b"


# --- both read paths -----------------------------------------------------------------------


def test_a_directory_capture_is_sanitized_on_the_way_in(tmp_path):
    directory = tmp_path / "iosxe"
    directory.mkdir()
    (directory / offline.raw_file_name(iosxe.CMD_VRF)).write_text(
        SHAPES["all of them together"], encoding="utf-8"
    )
    session = offline.DirectorySession(directory, required={iosxe.CMD_VRF})
    text = asyncio.run(session.run(iosxe.CMD_VRF))
    assert ESC not in text
    assert [r["name"] for r in parse("iosxe", iosxe.CMD_VRF, text)] == VRF_NAMES


def test_the_live_read_sanitizes_stdout_and_stderr():
    # `SshSession.run` without a transport: the channel is a stand-in that
    # answers with the bytes a console server in the path would add.
    import hst.collectors.ssh as sshmod

    class _File:
        def __init__(self, data: bytes) -> None:
            self._data = data

        def read(self) -> bytes:
            return self._data

    class _Channel:
        status_event = None

        def __init__(self) -> None:
            # What `recv` and `recv_stderr` hand out: the bytes the file objects serve.
            self._out = self.makefile("rb").read()
            self._err = self.makefile_stderr("rb").read()

        def settimeout(self, _t):
            pass

        def exec_command(self, _c):
            pass

        def makefile(self, _m):
            return _File(SHAPES["all of them together"].encode())

        def makefile_stderr(self, _m):
            return _File(f"{ESC}[1;31m\x07".encode())

        def recv(self, size: int) -> bytes:
            data, self._out = self._out[:size], self._out[size:]
            return data

        def recv_stderr_ready(self) -> bool:
            return bool(self._err)

        def recv_stderr(self, size: int) -> bytes:
            data, self._err = self._err[:size], self._err[size:]
            return data

        def recv_exit_status(self) -> int:
            return 0

        def close(self):
            pass

    class _Transport:
        def open_session(self, timeout=None):
            return _Channel()

    session = sshmod.SshSession(_Transport(), "", "", open_timeout=1, read_timeout=1)
    out = session.run(iosxe.CMD_VRF)
    assert ESC not in out
    assert [r["name"] for r in parse("iosxe", iosxe.CMD_VRF, out)] == VRF_NAMES
