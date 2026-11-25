"""cli_parse.parse: hand-written CLI text through ntc-templates, offline.

The payloads below are composed by hand to match the templates' expected
layout; nothing here was captured from real infrastructure.
"""

import pytest
from ntc_templates.parse import ParsingException
from textfsm import TextFSMError

from hst.collectors.cli_parse import parse

IOSXE_IP_INT_BRIEF = """\
Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet1       10.0.0.1        YES NVRAM  up                    up
GigabitEthernet2       unassigned      YES NVRAM  administratively down down
"""

IOSXR_IPV4_INT_BRIEF = """\
Wed Aug  5 10:00:00.000 UTC

Interface                      IP-Address      Status          Protocol Vrf-Name
Loopback0                      192.0.2.1       Up              Up       default
GigabitEthernet0/0/0/0         unassigned      Shutdown        Down     default
"""


def test_iosxe_maps_to_the_cisco_ios_platform_and_yields_flat_string_records():
    records = parse("iosxe", "show ip interface brief", IOSXE_IP_INT_BRIEF)
    assert records == [
        {"interface": "GigabitEthernet1", "ip_address": "10.0.0.1", "status": "up", "proto": "up"},
        {
            "interface": "GigabitEthernet2",
            "ip_address": "unassigned",
            "status": "administratively down",
            "proto": "down",
        },
    ]


def test_iosxr_maps_to_the_cisco_xr_platform():
    records = parse("iosxr", "show ipv4 interface brief", IOSXR_IPV4_INT_BRIEF)
    assert [r["interface"] for r in records] == ["Loopback0", "GigabitEthernet0/0/0/0"]
    assert records[0]["vrf"] == "default"
    # every value is a string; the collectors own any typing beyond that
    assert all(isinstance(v, str) for r in records for v in r.values())


def test_a_command_with_no_template_raises():
    with pytest.raises(ParsingException, match="show frobnicate"):
        parse("iosxe", "show frobnicate widget", "any output at all")


def test_an_os_outside_the_platform_map_is_a_key_error():
    """Only iosxe and iosxr route through TextFSM; NX-OS parses `| json`
    output itself."""
    with pytest.raises(KeyError):
        parse("nxos", "show version", "whatever")


def test_output_that_matches_no_template_row_parses_to_an_empty_list():
    assert parse("iosxe", "show ip interface brief", "utter nonsense\nnothing tabular\n") == []


# --- the preamble trim -------------------------------------------------------
#
# An ntc-template that ends its `Start` state with `^. -> Error` fails the whole
# command on one line the template does not know. `parse` asks the template
# where its own output starts.
#
# `show vrf` has that Error rule. `show ip interface brief` has none, and
# ignores what it does not know, so it is the case that is not trimmed.

BANNER = (
    "CCCC\n"
    "**********************************************************\n"
    "*  Authorised access only. All activity is recorded.     *\n"
    "**********************************************************\n"
    "\n"
)

IOSXE_SHOW_VRF = """\
  Name                             Default RD            Protocols   Interfaces
  Mgmt-intf                        <not set>             ipv4,ipv6   Gi0
  blue                             65000:1               ipv4,ipv6   Lo1
                                                                     Lo2
  green                            65000:2               ipv4        Po1.200
"""


def test_a_banner_in_front_of_the_output_is_dropped_and_the_output_parses():
    records = parse("iosxe", "show vrf", BANNER + IOSXE_SHOW_VRF)
    assert [r["name"] for r in records] == ["Mgmt-intf", "blue", "green"]
    # The columns still decide the member interfaces, so the trim kept them.
    assert records[1]["interfaces"] == ["Lo1", "Lo2"]


def test_clean_output_is_not_touched():
    assert parse("iosxe", "show vrf", IOSXE_SHOW_VRF) == parse("iosxe", "show vrf", BANNER + IOSXE_SHOW_VRF)


def test_a_device_rejection_is_never_trimmed_away():
    """No line is accepted, so nothing is dropped and the template's own error
    stands."""
    with pytest.raises(TextFSMError) as caught:
        parse("iosxe", "show vrf", "% Invalid input detected at '^' marker.\n")
    assert "0 preamble line(s) dropped" in str(caught.value)
    assert "Invalid input detected" in str(caught.value)


def test_a_capture_holding_only_a_banner_raises():
    with pytest.raises(TextFSMError):
        parse("iosxe", "show vrf", BANNER)


def test_a_preamble_past_the_limit_is_not_a_preamble():
    from hst.collectors import cli_parse

    with pytest.raises(TextFSMError):
        parse(
            "iosxe",
            "show vrf",
            "junk\n" * (cli_parse._PREAMBLE_LIMIT + 1) + IOSXE_SHOW_VRF,
        )


def test_the_error_quotes_what_the_device_sent():
    """A TextFSM state error names a rule number and one input line, and nothing
    else."""
    with pytest.raises(TextFSMError) as caught:
        parse("iosxe", "show vrf", BANNER)
    assert "output starts 'CCCC | " in str(caught.value)


def test_a_command_with_no_template_is_unchanged_by_the_trim():
    from hst.collectors import cli_parse

    assert cli_parse._preamble("cisco_ios", "show nothing at all", ["x", "y"]) == 0


def test_a_template_with_no_error_rule_never_trims():
    """`show ip interface brief` ignores what it does not know. TextFSM drops
    such a line, so it is not a preamble and is not counted."""
    from hst.collectors import cli_parse

    lines = (BANNER + IOSXE_IP_INT_BRIEF).split("\n")
    assert cli_parse._preamble("cisco_ios", "show ip interface brief", lines) == 0


def test_an_iosxr_timestamp_header_is_left_where_it_is():
    from hst.collectors import cli_parse

    lines = IOSXR_IPV4_INT_BRIEF.split("\n")
    assert cli_parse._preamble("cisco_xr", "show ipv4 interface brief", lines) == 0


# --- the repository's own templates ------------------------------------------
#
# ntc-templates' `show ip access-lists` template names 13 ICMP message types and
# sends an ACE with any other to its Error rule, which fails the whole command.
# The repository carries a copy with the full IOS list and a numeric type.

IOSXE_ACL_ICMP = """\
Extended IP access list EDGE-IN
    10 deny icmp any any timestamp-request
    20 deny icmp any any information-request log
    30 permit icmp any host 192.0.2.1 42
    40 permit icmp any any 3 13 (5 matches)
    50 permit icmp any any echo-reply
    60 permit ip any any
"""


def test_every_ios_icmp_message_name_and_a_numeric_type_parse():
    records = parse("iosxe", "show ip access-lists", IOSXE_ACL_ICMP)
    aces = [r for r in records if r["action"]]
    assert [(r["line_num"], r["icmp_type"]) for r in aces] == [
        ("10", "timestamp-request"),
        ("20", "information-request"),
        ("30", "42"),
        ("40", "3 13"),
        ("50", "echo-reply"),
        ("60", ""),
    ]
    assert aces[1]["log"] == "log"
    assert aces[2]["dst_host"] == "192.0.2.1"
    assert aces[3]["matches"] == "5"


def test_the_short_command_form_reaches_the_repository_template():
    from hst.collectors import cli_parse

    assert cli_parse._template_dir("cisco_ios", "sh ip access-lists") == cli_parse._OVERRIDE_DIR
    assert parse("iosxe", "sh ip access-lists", IOSXE_ACL_ICMP) == parse(
        "iosxe", "show ip access-lists", IOSXE_ACL_ICMP
    )


def test_a_command_the_repository_does_not_carry_uses_the_installed_template():
    from ntc_templates.parse import _get_template_dir

    from hst.collectors import cli_parse

    assert cli_parse._template_dir("cisco_ios", "show vrf") == _get_template_dir()
    assert cli_parse._template_dir("cisco_xr", "show ip access-lists") == _get_template_dir()


def test_each_repository_template_names_the_notice_of_ntc_templates():
    from pathlib import Path

    from hst.collectors import cli_parse

    directory = Path(cli_parse._OVERRIDE_DIR)
    templates = sorted(path.name for path in directory.glob("*.textfsm"))
    index = (directory / "index").read_text()
    notice = (directory / "NOTICE").read_text()
    assert len(templates) == 3
    for name in templates:
        assert f"\n{name}, " in index
        assert f"  {name}\n" in notice
        first, second = (directory / name).read_text().splitlines()[:2]
        assert first.startswith("# Apache-2.0. ") and "NOTICE in this directory" in first
        assert second.startswith(f"# ntc-templates 9.3.0 {name}")
    assert "ntc-templates 9.3.0\n" in notice
    for name in ("LICENSE.ntc-templates", "LICENSE.Apache-2.0"):
        assert f"{name} is " in notice
        assert (directory / name).read_text().strip()
    assert "Network to Code, LLC" in (directory / "LICENSE.ntc-templates").read_text()
    assert "Apache License" in (directory / "LICENSE.Apache-2.0").read_text().splitlines()[0]


# --- tolerance for optional commands -------------------------------------------


def test_outside_tolerance_an_unreadable_answer_raises():
    with pytest.raises(TextFSMError):
        parse("iosxe", "show vrf", "A device answer no detector knows\n")


def test_within_tolerance_an_optional_command_yields_no_records_and_is_recorded():
    from hst.collectors import cli_parse

    with cli_parse.tolerating({"show version"}) as failures:
        assert parse("iosxe", "show vrf", "A device answer no detector knows\n") == []
    assert list(failures) == ["show vrf"]
    assert "A device answer no detector knows" in failures["show vrf"]


def test_within_tolerance_a_required_command_raises():
    from hst.collectors import cli_parse

    with cli_parse.tolerating({"show vrf"}) as failures, pytest.raises(TextFSMError):
        parse("iosxe", "show vrf", "A device answer no detector knows\n")
    assert failures == {}


def test_a_command_with_no_template_raises_within_tolerance_too():
    """No template is a fault in the collector, not in the device's answer."""
    from hst.collectors import cli_parse

    with cli_parse.tolerating(()), pytest.raises(ParsingException):
        parse("iosxe", "show frobnicate widget", "any output at all")
