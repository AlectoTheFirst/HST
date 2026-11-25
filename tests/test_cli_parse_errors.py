import pytest
from textfsm import TextFSMError

from hst.collectors.cli_parse import parse


def test_state_error_identifies_command_and_preserves_original_failure():
    with pytest.raises(TextFSMError) as caught:
        parse("iosxe", "show vrf", "CCCC;\n")

    message = str(caught.value)
    assert "iosxe (cisco_ios)" in message
    assert "command 'show vrf'" in message
    assert "Input Line: CCCC;" in message
    assert isinstance(caught.value.__cause__, TextFSMError)
