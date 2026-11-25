"""Device- and controller-local uids are namespaced by the source that owns
them."""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from typing import Any

from tests import test_carry_forward_stream as stream
from tests import test_unchanged_carry as tuc
from tests import test_unifi as tu
from tests import test_vyos as tv

from hst.app import runs_exec
from hst.app.store import Source
from hst.collectors.nautobot import normalize_nautobot
from hst.collectors.unifi import UnifiCollector, UnifiConfig, normalize_unifi
from hst.collectors.vyos import normalize_vyos
from hst.core import Settings
from hst.core import manifest as manifests
from hst.core.identity import MemoryResolver
from hst.core.model import Batch

PREV, NEW = stream.PREV, stream.NEW
NOW = datetime(2026, 10, 1, tzinfo=UTC)

VYOS_LOCAL = {"FwRulebase", "FwRule", "Zone", "NatRule", "NetObject", "SvcObject", "PbrPolicy"}
UNIFI_LOCAL = {"FwRulebase", "FwRule", "Zone", "NetObject", "SvcObject", "VlanInstance"}


def _uids(batch: Batch, labels: set[str]) -> set[str]:
    return {n.uid for n in batch.nodes if n.label in labels}


# --- VyOS ------------------------------------------------------------------------------


def _vyos(source_name: str, resolver: MemoryResolver) -> Batch:
    return normalize_vyos(
        {"config": tv.CONFIG, "version_text": "Hardware S/N:     Unknown\n", "links": tv.LINKS},
        l3dom="home",
        source_name=source_name,
        resolver=resolver,
    )


def test_two_vyos_routers_with_one_hostname_share_no_policy_uid():
    registry = MemoryResolver()
    one, two = _vyos("vyos1", registry), _vyos("vyos2", registry)

    assert {n.label for n in one.nodes} >= VYOS_LOCAL
    assert _uids(one, VYOS_LOCAL) & _uids(two, VYOS_LOCAL) == set()
    assert one.scope != two.scope


def test_a_router_whose_hostname_is_its_device_uid_keeps_its_uids():
    """The namespace is the name part of the Device uid, which is the hostname
    for the first router that holds it: an existing graph keeps its uids, and
    only the second router moves under its suffixed name."""
    registry = MemoryResolver()
    one, two = _vyos("vyos1", registry), _vyos("vyos2", registry)
    nat = {n.uid for n in one.nodes if n.label == "NatRule"}
    assert "vyos:gw:nat:destination:10" in nat
    assert one.scope == "vyos:gw"
    assert {n.uid for n in two.nodes if n.label == "NatRule"} == {
        u.replace("vyos:gw:", "vyos:gw-0376:") for u in nat
    }


def test_wan_links_are_namespaced_by_the_device():
    config = copy.deepcopy(tv.CONFIG)
    config["interfaces"]["ethernet"]["eth0"]["address"] = ["dhcp"]
    registry = MemoryResolver()
    raw = {"config": config, "version_text": "Hardware S/N:     Unknown\n", "links": tv.LINKS}
    one = normalize_vyos(raw, l3dom="home", source_name="vyos1", resolver=registry)
    two = normalize_vyos(raw, l3dom="home", source_name="vyos2", resolver=registry)

    wan_one, wan_two = _uids(one, {"WanLink"}), _uids(two, {"WanLink"})
    assert wan_one and wan_two and wan_one & wan_two == set()


# --- UniFi -----------------------------------------------------------------------------


def _unifi_raw() -> dict[str, Any]:
    raw = copy.deepcopy(tu.RAW)
    raw["devices"] = [*raw["devices"], copy.deepcopy(tu.UDM)]
    raw["firewall_zones"] = copy.deepcopy(tu.ZONES)
    raw["firewall_rules"] = [
        {
            "_id": "rule-1",
            "ruleset": "LAN_IN",
            "rule_index": 2000,
            "name": "cameras to lan",
            "action": "drop",
            "enabled": True,
            "protocol": "all",
            "src_address": "192.168.30.0/24",
            "dst_address": "192.168.1.0/24",
            "src_firewallgroup_ids": [],
            "dst_firewallgroup_ids": [],
        }
    ]
    return raw


def _console(source_name: str) -> UnifiCollector:
    config = UnifiConfig(
        url=f"https://{source_name}",
        auth={"method": "user_password", "username": "ro", "password": "pw"},
        site_code=source_name,
        l3dom=source_name,
        source_name=source_name,
    )
    return UnifiCollector(config, Settings(_env_file=None))


def test_two_unifi_consoles_on_site_default_share_no_scope_and_no_policy_uid():
    """Each console is its own retirement partition."""
    a, b = _console("branch-a"), _console("branch-b")
    assert (a.scope, b.scope) == ("unifi:branch-a:default", "unifi:branch-b:default")

    one, two = a.normalize(_unifi_raw()), b.normalize(_unifi_raw())

    assert (one.scope, two.scope) == (a.scope, b.scope)
    assert {"FwRulebase", "FwRule", "Zone", "NetObject", "VlanInstance"} <= {n.label for n in one.nodes}
    assert _uids(one, UNIFI_LOCAL) & _uids(two, UNIFI_LOCAL) == set()
    assert {n.props.get("reported_location") for n in one.nodes if n.label == "Device"} == {"default"}


# --- carry across the scope rename -----------------------------------------------------


def _prepared_unifi(*consoles: UnifiCollector) -> list[runs_exec.PreparedSource]:
    return [
        runs_exec.PreparedSource(
            Source(i, c.config.source_name, "unifi", {}, b"", True, NOW, NOW),
            [runs_exec.PreparedDevice(None, c, None)],
        )
        for i, c in enumerate(consoles, 1)
    ]


def _entry(source: str, scope: str) -> manifests.DeviceEntry:
    return manifests.DeviceEntry(source=source, host="", outcome="collected", device_uids=[], scope=scope)


def test_a_console_that_fails_after_the_scope_rename_is_carried_under_its_old_scope():
    """The parent run holds the console under `unifi:default`, the scope the
    collector named it by before the rename. The console fails in the first
    run after it: the run names the old scope with the console's reason and
    holds everything the parent held."""
    console = _console("home")
    old = normalize_unifi(
        _unifi_raw(), site_code="home", l3dom="home", unifi_site="default", resolver=MemoryResolver()
    ).model_copy(update={"source": "home"})
    assert old.scope == "unifi:default"
    store = tuc._Store()
    tuc._load(store, old, PREV)
    scopes = runs_exec.CarryScopes()
    scopes.carry(runs_exec.PreparedDevice(None, console, None), "failed")

    runs_exec._name_renamed_scopes(
        _prepared_unifi(console), {("home", ""): _entry("home", "unifi:default")}, scopes
    )
    tuc._carry(store, scopes)

    assert scopes.reasons == {"unifi:home:default": "failed", "unifi:default": "failed"}
    assert tuc._run(store, NEW) == tuc._run(store, PREV)


def test_an_old_scope_two_consoles_shared_is_not_carried():
    a, b = _console("branch-a"), _console("branch-b")
    scopes = runs_exec.CarryScopes()
    scopes.carry(runs_exec.PreparedDevice(None, a, None), "failed")
    scopes.ran(runs_exec.PreparedDevice(None, b, None))
    previous = {
        ("branch-a", ""): _entry("branch-a", "unifi:default"),
        ("branch-b", ""): _entry("branch-b", "unifi:default"),
    }

    runs_exec._name_renamed_scopes(_prepared_unifi(a, b), previous, scopes)

    assert scopes.reasons == {"unifi:branch-a:default": "failed"}


# --- Nautobot --------------------------------------------------------------------------


def test_nautobot_locations_that_share_a_name_stay_apart():
    """`Floor 1` exists in two buildings. Each device reports its own
    location id, and each building keeps its own rack R01."""
    raw = {
        "locations": [
            {"id": "loc-a-f1", "name": "Floor 1", "parent": {"id": "bld-a", "name": "Building A"}},
            {"id": "loc-b-f1", "name": "Floor 1", "parent": {"id": "bld-b", "name": "Building B"}},
        ],
        "racks": [
            {"id": "r1", "name": "R01", "location": {"id": "loc-a-f1", "name": "Floor 1"}},
            {"id": "r2", "name": "R01", "location": {"id": "loc-b-f1", "name": "Floor 1"}},
        ],
        "devices": [
            {
                "id": "d1",
                "name": "sw-a",
                "serial": "SA1",
                "location": {"id": "loc-a-f1", "name": "Floor 1"},
                "rack": {"name": "R01", "location": {"id": "loc-a-f1", "name": "Floor 1"}},
                "interfaces": [],
            },
            {
                "id": "d2",
                "name": "sw-b",
                "serial": "SB1",
                "location": {"id": "loc-b-f1", "name": "Floor 1"},
                "rack": {"name": "R01", "location": {"id": "loc-b-f1", "name": "Floor 1"}},
                "interfaces": [],
            },
        ],
        "cables": [],
    }
    batch = normalize_nautobot(raw, host="nb.example")

    devices = {n.uid: n.props for n in batch.nodes if n.label == "Device"}
    assert devices["dev:sw-a"]["reported_location"] == "loc-a-f1"
    assert devices["dev:sw-b"]["reported_location"] == "loc-b-f1"
    in_rack = {r.start_uid: r.end_uid for r in batch.rels if r.rel_type == "IN_RACK"}
    assert len({n.uid for n in batch.nodes if n.label == "Rack"}) == 2
    assert in_rack["dev:sw-a"] != in_rack["dev:sw-b"]
