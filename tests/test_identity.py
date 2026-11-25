"""The device identity rule (core/identity.py):
a readable uid, minted one time from the short hostname and then kept."""

import hashlib

import pytest

from hst.core.identity import (
    DEFAULT_NAMES,
    MemoryResolver,
    identifier,
    mint,
    plain_uid,
    short_name,
    valid_uid,
)


def test_the_uid_is_the_short_hostname_in_lowercase():
    assert mint("DC1-Spine1.corp.example", "FDO24010101", None, set()) == "dev:dc1-spine1"
    assert short_name("Core_SW 1.corp") == "core_sw-1"
    assert short_name(None) == ""


def test_an_address_used_as_a_hostname_stays_whole():
    assert short_name("10.0.0.1") == "10.0.0.1"
    assert mint("10.0.0.1", "FDO24010101", None, set()) == "dev:10.0.0.1"


def test_a_collision_takes_the_last_4_characters_of_the_serial():
    assert mint("core1", "FOC1234ABCD", None, {"dev:core1"}) == "dev:core1-abcd"


def test_a_default_name_always_gets_a_suffix():
    assert {"switch", "router", "localhost", "unknown", "vyos"} <= DEFAULT_NAMES
    assert mint("Switch", "FOC1234ABCD", None, set()) == "dev:switch-abcd"
    assert mint("vyos", None, "vyos:vyos", set()).startswith("dev:vyos-")
    assert plain_uid("router") is None


def test_a_device_without_a_hostname_is_named_unknown():
    assert mint(None, "FOC1234ABCD", None, set()) == "dev:unknown-abcd"


def test_a_device_without_a_serial_takes_the_hash_of_its_ref():
    digest = hashlib.sha256(b"vyos:edge").hexdigest()
    assert mint("edge", None, "vyos:edge", set()) == "dev:edge"
    assert mint("edge", None, "vyos:edge", {"dev:edge"}) == f"dev:edge-{digest[:4]}"


def test_the_suffix_grows_by_one_character_until_the_uid_is_free():
    taken = {"dev:core1", "dev:core1-abcd", "dev:core1-3abcd"}
    assert mint("core1", "FOC123ABCD", None, taken) == "dev:core1-23abcd"
    digest = hashlib.sha256(b"vyos:edge").hexdigest()
    assert mint("edge", None, "vyos:edge", {"dev:edge", f"dev:edge-{digest[:4]}"}) == f"dev:edge-{digest[:5]}"


def test_a_counter_follows_when_the_serial_has_no_more_characters():
    assert mint("core1", "AB", None, {"dev:core1", "dev:core1-ab"}) == "dev:core1-ab-2"


def test_the_uid_stays_when_the_hostname_changes():
    registry = MemoryResolver()
    uid = registry.resolve_device("serial", "FOC1234ABCD", "core1")
    assert uid == "dev:core1"
    assert registry.resolve_device("serial", "FOC1234ABCD", "core9") == uid
    # a new device named like the old one gets a suffix, not the uid
    assert registry.resolve_device("serial", "FDO5555QRST", "core1") == "dev:core1-qrst"


def test_the_uid_stays_when_the_serial_changes_to_one_the_registry_holds():
    """A stack: the first serial resolves, the others are bound. When another
    member becomes the first one, its serial resolves to the same uid."""
    registry = MemoryResolver()
    uid = registry.resolve_device("serial", "FOC1111AAAA", "stack1")
    registry.bind_device(uid, "serial", "FOC2222BBBB")
    assert registry.resolve_device("serial", "FOC2222BBBB", "stack1") == uid


def test_an_identifier_keeps_its_uid_whatever_its_spelling():
    registry = MemoryResolver()
    uid = registry.resolve_device("serial", "FOC1234ABCD", "core1")
    assert registry.resolve_device("serial", " foc1234abcd ", None) == uid
    ref = registry.resolve_device("ref", "cp:Mgmt:GW-UID", "fw1")
    assert registry.resolve_device("ref", "cp:mgmt:gw-uid", None) == ref == "dev:fw1"
    assert identifier("ref", "cp:Mgmt:GW-UID") == "cp:mgmt:gw-uid"


def test_a_registry_read_from_rows_keeps_their_uids():
    registry = MemoryResolver([("dev:renamed", "serial", "foc1234abcd")], generation=3)
    assert registry.resolve_device("serial", "FOC1234ABCD", "core1") == "dev:renamed"
    assert registry.identity_generation() == 3
    with pytest.raises(LookupError):
        registry.bind_device("dev:nobody", "serial", "X")


def test_an_identifier_needs_a_known_kind_and_a_value():
    with pytest.raises(ValueError, match="unknown identifier kind"):
        identifier("mac", "aa:bb")
    with pytest.raises(ValueError, match="empty serial"):
        identifier("serial", " ")


def test_the_rename_takes_only_a_slugged_device_uid():
    assert valid_uid("dev:core1")
    assert valid_uid("dev:core1.lab")
    assert not valid_uid("core1")
    assert not valid_uid("dev:")
    assert not valid_uid("dev:Core1")
    assert not valid_uid("dev:a/b")
