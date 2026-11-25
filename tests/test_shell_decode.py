"""The paramiko shell decodes its stream as one text."""

from __future__ import annotations

import pytest
from tests.test_ssh_streaming import _raw_table
from tests.test_stream_sanitize import reference_shell_output_of

from hst.collectors import ssh
from hst.collectors.ssh import sanitize_cli_text


class _SplitShell:
    """A paramiko shell channel that hands out everything it sends in pieces
    of `size` bytes: the login, the prompt that answers a bare newline, and
    a command's echo, answer and prompt."""

    def __init__(self, prompt: str, answer: bytes, size: int) -> None:
        self._prompt = prompt.encode()
        self._answer = answer
        self._size = size
        self._queue: list[bytes] = []
        self._send(b"banner caf\xc3\xa9\r\n" + self._prompt)

    def _send(self, data: bytes) -> None:
        self._queue.extend(data[i : i + self._size] for i in range(0, len(data), self._size))

    def settimeout(self, seconds: float) -> None:
        self.timeout = seconds

    def recv(self, size: int) -> bytes:
        if not self._queue:
            raise TimeoutError
        return self._queue.pop(0)

    def sendall(self, data: bytes) -> None:
        command = data.strip()
        if not command:
            self._send(b"\r\n" + self._prompt)
        else:
            self._send(command + b"\r\n" + self._answer + self._prompt)


@pytest.mark.parametrize("size", [1, 2, 3, 5, 7])
def test_every_recv_boundary_inside_a_character_decodes_as_the_whole(size):
    raw = _raw_table(2_000)
    shell = ssh.ShellSession(_SplitShell("r1#", raw, size), "k", "", read_timeout=120)
    whole = f"show ip bgp\r\n{raw.decode(errors='replace')}r1#"
    expected = reference_shell_output_of(sanitize_cli_text(whole), "show ip bgp", "r1#")
    assert shell.run("show ip bgp") == expected
    assert "\U0001f600" in expected
    assert "\ufffd" in expected


def test_a_prompt_outside_ascii_split_across_recvs_is_learned_and_ends_every_read():
    """A prompt of two-byte characters delivered one byte per recv is
    learned whole and ends every read."""
    prompt = "k\u00f6ln-r\u00fc1#"
    shell = ssh.ShellSession(_SplitShell(prompt, b"line \xc3\xbc\r\n", 1), "k", "", read_timeout=5)
    assert shell.prompt == prompt
    assert shell.run("show ip bgp") == "line \u00fc\n"
    assert shell.run("show ip bgp") == "line \u00fc\n"
