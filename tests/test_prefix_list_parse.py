"""Prefix-list lines of the NX-OS and IOS-XE running-config: IOS-XE entries
without `seq`, and a warning for each `ip prefix-list` line that is not read."""

from hst.collectors import iosxe, nxos


def test_iosxe_entries_without_seq_are_numbered_5_10_15_per_list():
    lists = iosxe.parse_prefix_lists(
        "ip prefix-list PXL_CONN_PREFIXES permit 10.0.0.0/8 le 24\n"
        "ip prefix-list PXL_CONN_PREFIXES deny 0.0.0.0/0\n"
        "ip prefix-list OTHER permit 192.0.2.0/24\n"
        "ip prefix-list PXL_CONN_PREFIXES permit 172.16.0.0/12 ge 16 le 24\n"
    )
    assert [(e["seq"], e["action"], e["prefix"], e["ge"], e["le"]) for e in lists["PXL_CONN_PREFIXES"]] == [
        (5, "permit", "10.0.0.0/8", None, 24),
        (10, "deny", "0.0.0.0/0", None, None),
        (15, "permit", "172.16.0.0/12", 16, 24),
    ]
    assert [e["seq"] for e in lists["OTHER"]] == [5]


def test_iosxe_entries_with_seq_keep_it():
    lists = iosxe.parse_prefix_lists("ip prefix-list A seq 20 permit 10.0.0.0/8\n")
    assert [e["seq"] for e in lists["A"]] == [20]


def test_iosxe_an_unread_line_is_named_and_a_description_is_not(caplog):
    lists = iosxe.parse_prefix_lists(
        "ip prefix-list A description link nets\n"
        "ip prefix-list A seq 5 permit 10.0.0.0/8\n"
        "ip prefix-list B seq x permit 10.0.0.0/8\n"
    )
    assert list(lists) == ["A"]
    assert "ip prefix-list B seq x permit 10.0.0.0/8" in caplog.text
    assert "description" not in caplog.text


def test_nxos_an_unread_line_is_named_and_a_description_is_not(caplog):
    lists = nxos.parse_prefix_list_config(
        "ip prefix-list A description link nets\n"
        "ip prefix-list A seq 5 permit 10.0.0.0/8 le 24\n"
        "ip prefix-list B seq 5 permit 10.0.0.0/8 mask 255.0.0.0\n"
        "route-map RM permit 10\n"
    )
    assert list(lists) == ["A"]
    assert "ip prefix-list B seq 5 permit 10.0.0.0/8 mask 255.0.0.0" in caplog.text
    assert "description" not in caplog.text
    assert "route-map" not in caplog.text
