"""The batch digest change detection compares (collectors/base.py `graph_sha`).

A Cisco or VyOS payload differs on every fetch: uptimes, interface counters,
neighbor hold timers, LSA ages, BGP counters and route ages all move whether
or not anything the graph holds changed. What decides whether a device's
graph is written is the digest of the batch its payload normalizes to, so
two fetches of an unchanged device must digest the same and a change the
graph shows must not.

The payloads are the families' test fixtures and the synthetic payloads of
`tests/support/`, with the per-fetch values moved the way a device moves
them; nothing here is captured from real infrastructure.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from tests import test_iosxe, test_iosxr, test_nxos
from tests.support.synthetic_payloads import make_collector
from tests.support.synthetic_vyos import answers, new_raw
from tests.support.synthetic_vyos import make_collector as make_vyos_collector

from hst.collectors import iosxe, iosxr, nxos, vyos
from hst.collectors.base import Collector, SourceConfig, _key_matches, graph_sha, raw_sha
from hst.collectors.util import GraphBuilder
from hst.core import Settings
from hst.core.model import Batch, SectionOutcome

REPO = Path(__file__).resolve().parent.parent

# --- the digest itself ----------------------------------------------------------------------


class _Cfg(SourceConfig):
    host: str = ""


class _Stamped(Collector):
    """A collector whose objects carry a poll time, declared volatile."""

    name = "stamped"
    KIND = "orchestrator"
    ConfigModel = _Cfg
    VOLATILE_GRAPH_PROPS = {"Device": ("observed_at_ms",), "CONNECTED_TO": ("seen_ms",)}

    def fetch(self) -> Any:
        return {}

    def normalize(self, raw: Any) -> Batch:
        raise NotImplementedError

    def probe(self) -> str:
        return "ok"


def _batch(
    *,
    order: int = 1,
    hostname: str = "r1",
    observed: int = 1,
    seen: int = 1,
    port_observed: int = 1,
    members: tuple[str, ...] = ("a", "b"),
    source: str = "src",
    scope: str = "stamped:r1",
) -> Batch:
    """Two devices, a port, a list property and a keyed relationship, built
    in the order `order` names (1 or -1)."""
    b = GraphBuilder()
    steps: list[Callable[[], Any]] = [
        lambda: b.node("Device", "dev:r1", hostname=hostname, role="router", observed_at_ms=observed),
        lambda: b.node("Device", "dev:r2", hostname="r2", role="router", observed_at_ms=observed),
        lambda: b.node("Port", "port:r1:1", name="eth1", observed_at_ms=port_observed),
        lambda: b.node("VlanInstance", "vlan:r1:10", vid=10, name=",".join(members)),
        lambda: b.rel("ON", "Port", "port:r1:1", "Device", "dev:r1"),
        lambda: b.rel(
            "CONNECTED_TO", "Port", "port:r1:1", "Device", "dev:r2", key={"key": "k1"}, seen_ms=seen
        ),
        lambda: b.rel(
            "CONNECTED_TO", "Port", "port:r1:1", "Device", "dev:r2", key={"key": "k0"}, seen_ms=seen
        ),
    ]
    for step in steps[::order]:
        step()
    batch = b.batch(source, scope)
    (vlan,) = (n for n in batch.nodes if n.label == "VlanInstance")
    vlan.props["members"] = list(members)
    return batch


def _collector() -> _Stamped:
    return _Stamped(_Cfg(host="r1"), Settings(_env_file=None))


def _line(item: Any) -> str:
    return json.dumps(item, sort_keys=True, default=str, separators=(",", ":")) + "\n"


def test_the_digest_is_the_documented_canonical_text():
    batch = _batch()
    volatile = {"Device": {"observed_at_ms"}, "CONNECTED_TO": {"seen_ms"}}

    def props(name: str, values: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in values.items() if k not in volatile.get(name, set())}

    text = _line({"scope": batch.scope, "source": batch.source})
    for n in sorted(batch.nodes, key=lambda n: (n.label, n.uid)):
        text += _line([n.label, n.uid, props(n.label, n.props)])
    rels = sorted(
        batch.rels,
        key=lambda r: (r.rel_type, r.start_label, r.start_uid, r.end_label, r.end_uid, _line(r.key)),
    )
    for r in rels:
        text += _line(
            [
                r.rel_type,
                r.start_label,
                r.start_uid,
                r.end_label,
                r.end_uid,
                r.key,
                props(r.rel_type, r.props),
            ]
        )

    assert graph_sha(_collector(), batch) == hashlib.sha256(text.encode()).hexdigest()


def test_the_order_a_batch_was_built_in_is_not_part_of_the_digest():
    assert graph_sha(_collector(), _batch(order=1)) == graph_sha(_collector(), _batch(order=-1))


def test_a_declared_volatile_property_is_left_out_and_nothing_else_is():
    base = graph_sha(_collector(), _batch())

    assert graph_sha(_collector(), _batch(observed=2, seen=2)) == base
    # declared per label: the same name on a Port is graph content
    assert graph_sha(_collector(), _batch(port_observed=2)) != base
    assert graph_sha(_collector(), _batch(hostname="r1-new")) != base


def test_a_collector_without_the_declaration_digests_every_property():
    shaped = SimpleNamespace()

    assert graph_sha(shaped, _batch(observed=2)) != graph_sha(shaped, _batch())


def test_source_scope_and_list_order_are_part_of_the_digest_and_sections_are_not():
    base = graph_sha(_collector(), _batch())
    reported = _batch()
    reported.sections["config"] = SectionOutcome(status="malformed")
    reported.warnings.append("one warning")

    assert graph_sha(_collector(), _batch(source="other")) != base
    assert graph_sha(_collector(), _batch(scope="stamped:r2")) != base
    assert graph_sha(_collector(), _batch(members=("b", "a"))) != base
    assert graph_sha(_collector(), reported) == base


# --- a second fetch of an unchanged device ---------------------------------------------------


def _moved(text: str, *edits: tuple[str, str | Callable[[re.Match[str]], str]]) -> str:
    """`text` with each (pattern, replacement) applied. Every pattern has to
    match, so a fixture that changes cannot turn an edit into a no-op."""
    for pattern, replacement in edits:
        text, count = re.subn(pattern, replacement, text)
        assert count, pattern
    return text


def _lsa_ages(raw: dict[str, Any], commands: tuple[str, ...], n: int) -> dict[str, str]:
    return {
        cmd: _moved(raw[cmd], (r"LS age: (\d+)", lambda m: f"LS age: {int(m[1]) + 7 * n}"))
        for cmd in commands
        if "LS age:" in raw[cmd]
    }


def _iosxe_raw() -> dict[str, Any]:
    fhrp = test_iosxe.FHRP_RAW
    return {
        **test_iosxe.OSPF_RAW,
        iosxe.CMD_STANDBY: fhrp[iosxe.CMD_STANDBY],
        iosxe.CMD_VRRP: fhrp[iosxe.CMD_VRRP],
    }


def _iosxe_fetch(n: int, raw: dict[str, Any] | None = None) -> dict[str, Any]:
    """The IOS-XE fixture as the `n`th fetch of the same device returns it."""
    raw = raw or _iosxe_raw()
    m = iosxe
    db = (
        m.CMD_OSPF_DB_ROUTER,
        m.CMD_OSPF_DB_NETWORK,
        m.CMD_OSPF_DB_SUMMARY,
        m.CMD_OSPF_DB_ASBR_SUMMARY,
        m.CMD_OSPF_DB_EXTERNAL,
        m.CMD_OSPF_DB_NSSA_EXTERNAL,
    )
    return {
        **raw,
        m.CMD_VERSION: _moved(raw[m.CMD_VERSION], (r"4 hours, 5 minutes", f"4 hours, {5 + n} minutes")),
        m.CMD_INTERFACES: _moved(
            raw[m.CMD_INTERFACES],
            (r"Last input 00:00:01, output 00:00:02", f"Last input 00:00:0{n}, output 00:00:0{n + 1}"),
            (
                r"1000 packets input, 100000 bytes",
                f"{1000 + 37 * n} packets input, {100000 + 3811 * n} bytes",
            ),
            (
                r"1000 packets output, 100000 bytes",
                f"{1000 + 29 * n} packets output, {100000 + 2903 * n} bytes",
            ),
            (r"txload 1/255, rxload 1/255", f"txload {1 + n}/255, rxload {2 + n}/255"),
        ),
        m.CMD_LLDP: _moved(
            raw[m.CMD_LLDP], (r"Time remaining: 100 seconds", f"Time remaining: {100 - n} seconds")
        ),
        m.CMD_CDP: _moved(raw[m.CMD_CDP], (r"Holdtime : 150 sec", f"Holdtime : {150 - n} sec")),
        m.CMD_NAT_STATS: _moved(
            raw[m.CMD_NAT_STATS], (r"Hits: 100  Misses: 5", f"Hits: {100 + n}  Misses: {5 + n}")
        ),
        m.CMD_ARP: _moved(raw[m.CMD_ARP], (r"(10\.0\.0\.5 +)5 ", rf"\g<1>{5 + n} ")),
        m.CMD_OSPF: _moved(raw[m.CMD_OSPF], (r"Time elapsed: 2w3d", f"Time elapsed: 2w{3 + n}d")),
        m.CMD_OSPF_NBR: _moved(raw[m.CMD_OSPF_NBR], (r"00:00:33", f"00:00:{33 - n}")),
        **_lsa_ages(raw, db, n),
        m.CMD_BGP_SESSIONS: _moved(
            raw[m.CMD_BGP_SESSIONS],
            (r"120     118", f"{120 + n}     {118 + n}"),
            (r"01:02:03", f"01:0{2 + n}:03"),
        ),
    }


def _iosxr_fetch(n: int, raw: dict[str, Any] | None = None) -> dict[str, Any]:
    raw = raw or dict(test_iosxr.OSPF_RAW)
    m = iosxr
    db = (
        m.CMD_OSPF_DB_ROUTER,
        m.CMD_OSPF_DB_NETWORK,
        m.CMD_OSPF_DB_SUMMARY,
        m.CMD_OSPF_DB_ASBR_SUMMARY,
        m.CMD_OSPF_DB_EXTERNAL,
        m.CMD_OSPF_DB_NSSA_EXTERNAL,
    )
    return {
        **raw,
        m.CMD_VERSION: _moved(raw[m.CMD_VERSION], (r"4 hours, 5 minutes", f"4 hours, {5 + n} minutes")),
        m.CMD_INTERFACES: _moved(
            raw[m.CMD_INTERFACES],
            (r"txload 0/255, rxload 0/255", f"txload {n}/255, rxload {n + 1}/255"),
            (r"Last input never, output never", f"Last input 00:00:0{n}, output 00:00:0{n + 2}"),
        ),
        m.CMD_LLDP: _moved(
            raw[m.CMD_LLDP], (r"Time remaining: 100 seconds", f"Time remaining: {100 - n} seconds")
        ),
        m.CMD_CDP: _moved(raw[m.CMD_CDP], (r"Holdtime : 150 sec", f"Holdtime : {150 - n} sec")),
        m.CMD_ARP: _moved(raw[m.CMD_ARP], (r"00:05:00", f"00:0{5 + n}:00")),
        m.CMD_ROUTE: _moved(raw[m.CMD_ROUTE], (r"00:10:00", f"00:1{n}:00")),
        m.CMD_OSPF_NBR: _moved(
            raw[m.CMD_OSPF_NBR], (r"00:00:33", f"00:00:{33 - n}"), (r"up for 00:10:12", f"up for 00:1{n}:12")
        ),
        **_lsa_ages(raw, db, n),
        m.CMD_BGP_SESSIONS: _moved(
            raw[m.CMD_BGP_SESSIONS],
            (r"120     118", f"{120 + n}     {118 + n}"),
            (r"01:02:03", f"01:0{2 + n}:03"),
        ),
    }


def _json_rows(node: Any, name: str) -> Iterator[dict[str, Any]]:
    """Every row of the NX-OS table `ROW_<name>` anywhere under `node`."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == f"ROW_{name}":
                yield from value if isinstance(value, list) else [value]
            else:
                yield from _json_rows(value, name)
    elif isinstance(node, list):
        for item in node:
            yield from _json_rows(item, name)


def _json_moved(text: str, edit: Callable[[Any], None]) -> str:
    doc = json.loads(text)
    edit(doc)
    return json.dumps(doc)


def _nxos_fetch(n: int, raw: dict[str, Any] | None = None) -> dict[str, Any]:
    """The NX-OS fixture as the `n`th fetch returns it: the counters, ages and
    timers a real answer carries beside the fields the parser reads."""
    raw = raw or dict(test_nxos.RAW)
    m = nxos

    def version(doc: Any) -> None:
        doc.update(kern_uptm_days=17 + n, kern_uptm_hrs=4, kern_uptm_mins=5 + n, kern_uptm_secs=n)

    def interfaces(doc: Any) -> None:
        for row in _json_rows(doc, "interface"):
            row.update(eth_inpkts=1000 + 37 * n, eth_outbytes=90000 + 211 * n, eth_link_flapped=f"{n}d02h")

    def lldp(doc: Any) -> None:
        for row in _json_rows(doc, "nbor_detail"):
            row["ttl"] = 120 - n

    def neighbors(doc: Any) -> None:
        for row in _json_rows(doc, "nbr"):
            row.update(uptime=f"P{n}DT2H", lastnonhello=f"PT{n}S")

    def lsas(doc: Any) -> None:
        for row in _json_rows(doc, "lsdb"):
            row["age"] = str(int(row.get("age") or 0) + 7 * n)

    def sessions(doc: Any) -> None:
        for row in _json_rows(doc, "neighbor"):
            row.update(lastread=f"PT{20 + n}S", lastwrite=f"PT{8 + n}S")

    def macs(doc: Any) -> None:
        for row in _json_rows(doc, "mac_address"):
            row["disp_age"] = n

    db = (
        m.CMD_OSPF_DB_ROUTER,
        m.CMD_OSPF_DB_NETWORK,
        m.CMD_OSPF_DB_SUMMARY,
        m.CMD_OSPF_DB_EXTERNAL,
        m.CMD_OSPF_DB_NSSA,
        m.CMD_OSPF_DB_ASBR_SUMMARY,
    )
    return {
        **raw,
        m.CMD_VERSION: _json_moved(raw[m.CMD_VERSION], version),
        m.CMD_INTERFACE: _json_moved(raw[m.CMD_INTERFACE], interfaces),
        m.CMD_LLDP: _json_moved(raw[m.CMD_LLDP], lldp),
        m.CMD_OSPF_NBR: _json_moved(raw[m.CMD_OSPF_NBR], neighbors),
        **{cmd: _json_moved(raw[cmd], lsas) for cmd in db},
        m.CMD_BGP_SESSIONS: _json_moved(raw[m.CMD_BGP_SESSIONS], sessions),
        m.CMD_MAC: _json_moved(raw[m.CMD_MAC], macs),
    }


FETCHES: dict[str, Callable[..., dict[str, Any]]] = {
    "iosxe": _iosxe_fetch,
    "iosxr": _iosxr_fetch,
    "nxos": _nxos_fetch,
}

# One configuration change per family, in a text the graph is built from.
RECONFIGURED: dict[str, tuple[str, str, str]] = {
    "iosxe": (iosxe.CMD_INTERFACES, "Internet address is 10.0.9.1/24", "Internet address is 10.0.9.2/24"),
    "iosxr": (iosxr.CMD_INTERFACES, "Internet address is 10.0.9.1/24", "Internet address is 10.0.9.2/24"),
    "nxos": (nxos.CMD_INTERFACE, '"eth_ip_addr": "10.0.0.1"', '"eth_ip_addr": "10.0.0.2"'),
}


def _digest(family: str, raw: dict[str, Any]) -> str:
    collector = make_collector(family, None)
    return graph_sha(collector, collector.normalize(raw))


@pytest.mark.parametrize("family", sorted(FETCHES))
def test_two_fetches_of_an_unchanged_device_digest_the_same(family):
    """Every uptime, counter, timer and age of the second fetch moved, so its
    change hash differs and the payload is normalized; its batch does not."""
    first, second = FETCHES[family](1), FETCHES[family](2)
    collector = make_collector(family, None)

    assert raw_sha(collector, first) != raw_sha(collector, second)
    assert _digest(family, first) == _digest(family, second)


@pytest.mark.parametrize("family", sorted(FETCHES))
def test_a_configuration_change_the_graph_shows_changes_the_digest(family):
    command, old, new = RECONFIGURED[family]
    first = FETCHES[family](1)
    changed = {**first, command: _moved(first[command], (re.escape(old), new))}

    assert _digest(family, first) != _digest(family, changed)


@pytest.mark.parametrize("family", sorted(FETCHES))
def test_the_version_text_is_in_the_change_hash(family):
    """`show version` builds the Device node, so it stays in the change hash:
    a new uptime alone differs in `raw_sha`, and the batch digest shows that
    nothing the graph holds moved."""
    module = {"iosxe": iosxe, "iosxr": iosxr, "nxos": nxos}[family]
    first = FETCHES[family](1)
    second = {**first, module.CMD_VERSION: FETCHES[family](2)[module.CMD_VERSION]}
    collector = make_collector(family, None)

    assert module.CMD_VERSION not in collector.VOLATILE_RAW_KEYS
    assert raw_sha(collector, first) != raw_sha(collector, second)
    assert _digest(family, first) == _digest(family, second)


def _vyos_fetch(n: int) -> dict[str, Any]:
    """The synthetic VyOS device as the `n`th fetch returns it: every route's
    uptime, the system uptime and the BGP session counters moved."""
    raw = new_raw(answers("small/plain"))

    def routes(text: str) -> str:
        return _moved(text, (r'"uptime": "[^"]*"', f'"uptime": "{n}d0{n}h"'))

    summary = _moved(
        raw[vyos.BGP_SUMMARY_COMMAND],
        (r'"msgRcvd": \d+', f'"msgRcvd": {10000 + n}'),
        (r'"msgSent": \d+', f'"msgSent": {9000 + n}'),
        (r'"peerUptime": "[^"]*"', f'"peerUptime": "01w2d0{n}h"'),
        (r'"peerUptimeMsec": \d+', f'"peerUptimeMsec": {788400000 + 3600000 * n}'),
    )
    return {
        **raw,
        "version_text": _moved(raw["version_text"], (r"Uptime:( +)12 days", rf"Uptime:\g<1>{12 + n} days")),
        "routes": routes(raw["routes"]),
        "routes6": routes(raw["routes6"]) if '"uptime"' in raw["routes6"] else raw["routes6"],
        vyos.BGP_SUMMARY_COMMAND: summary,
    }


def _vyos_digest(raw: dict[str, Any], tmp_path: Path) -> str:
    from tests.support.synthetic_payloads import make_settings

    collector = make_vyos_collector(make_settings(tmp_path))
    return graph_sha(collector, collector.normalize(raw))


def test_two_vyos_fetches_of_an_unchanged_device_digest_the_same(tmp_path):
    """The routing tables are mirrored into the graph, and each route's uptime
    is not a property of the edge they become."""
    first, second = _vyos_fetch(1), _vyos_fetch(2)
    collector = make_vyos_collector(None)

    assert raw_sha(collector, first) != raw_sha(collector, second)
    assert _vyos_digest(first, tmp_path) == _vyos_digest(second, tmp_path)


def test_a_vyos_configuration_or_version_change_changes_the_digest(tmp_path):
    first = _vyos_fetch(1)
    renamed = {**first, "config": {**first["config"], "system": {"host-name": "edge-vyos-2"}}}
    upgraded = {**first, "version_text": first["version_text"].replace("1.5-rolling-202607150020", "1.5.1")}

    assert _vyos_digest(renamed, tmp_path) != _vyos_digest(first, tmp_path)
    assert _vyos_digest(upgraded, tmp_path) != _vyos_digest(first, tmp_path)


# --- what a key left out of the change hash feeds -------------------------------------------


def _volatile(collector: Collector, key: str) -> bool:
    return key in collector.VOLATILE_RAW_KEYS or _key_matches(collector.VOLATILE_RAW_KEY_PATTERN, key)


@pytest.mark.parametrize("family", sorted(FETCHES))
def test_every_volatile_key_is_an_observation_key(family):
    """What a volatile key feeds in the side tables reaches the side store
    through the observation hash, since the change hash does not see it."""
    cls = type(make_collector(family, None))

    assert set(cls.VOLATILE_RAW_KEYS) <= set(cls.OBSERVATION_RAW_KEYS)
    assert cls.VOLATILE_RAW_KEY_PATTERN is cls.OBSERVATION_RAW_KEY_PATTERN


@pytest.mark.parametrize("family", sorted(FETCHES))
def test_no_volatile_key_feeds_the_graph(family):
    """A payload whose volatile keys all answered nothing digests as the one
    that answered, so an equal change hash always means an equal graph."""
    raw = FETCHES[family](1)
    collector = make_collector(family, None)
    volatile = [key for key in raw if _volatile(collector, key)]
    emptied = {**raw, **dict.fromkeys(volatile, "")}

    assert len(volatile) >= 3
    assert raw_sha(collector, emptied) == raw_sha(collector, raw)
    assert _digest(family, emptied) == _digest(family, raw)


def test_vyos_declares_only_the_neighbor_table_volatile():
    """Its version text builds the Device node and its BGP summary feeds a
    side table it does not declare as an observation. The neighbor table
    feeds only the `arp` side table."""
    assert vyos.VyosCollector.VOLATILE_RAW_KEYS == ("neigh",)
    assert set(vyos.VyosCollector.VOLATILE_RAW_KEYS) <= set(vyos.VyosCollector.OBSERVATION_RAW_KEYS)
    assert vyos.VyosCollector.VOLATILE_RAW_KEY_PATTERN is None


# --- a controller's poll times --------------------------------------------------------------

# The VeloCloud properties that hold the poll time, or the time the poll cache
# last refreshed a module read (collectors/velocloud_poll.py): the ones its
# collector declares in `VOLATILE_GRAPH_PROPS`.
VELOCLOUD_POLL_TIMES: dict[str, tuple[str, ...]] = {
    "Device": ("configuration_observed_at_ms",),
    "WanLink": ("configuration_observed_at_ms",),
    "Tunnel": ("configuration_observed_at_ms",),
    "SdwanBusinessPolicy": ("observed_at_ms",),
}


def _velocloud_polls() -> tuple[Any, Any]:
    """Two polls of one unchanged estate a minute apart: a new poll time, the
    module reads refreshed, a BGP session's up/down time moved."""
    import copy

    from tests.enterprise.test_velocloud import _overlay_raw

    from hst.collectors.velocloud import normalize_velocloud

    first = _overlay_raw()
    second = copy.deepcopy(first)
    second["fetched_at_ms"] = first["fetched_at_ms"] + 60_000
    (enterprise,) = second["enterprises"]
    for detail in enterprise["edge_details"].values():
        detail["_freshness"]["modules"]["observed_at_ms"] += 60_000
    enterprise["bgp_sessions"][0]["upDownTime"] = "01:03:03"
    return normalize_velocloud(first), normalize_velocloud(second)


def _props(batch: Batch) -> dict[tuple[str, ...], dict[str, Any]]:
    nodes = {(n.label, n.uid): n.props for n in batch.nodes}
    rels = {
        (r.rel_type, r.start_uid, r.end_uid, json.dumps(r.key, sort_keys=True)): r.props for r in batch.rels
    }
    return {**nodes, **rels}


def test_the_poll_times_are_the_only_velocloud_properties_two_polls_differ_in():
    from hst.collectors.velocloud import VeloCloudCollector

    before, after = _velocloud_polls()
    first, second = _props(before), _props(after)
    moved = {
        (key[0], name)
        for key in first
        for name in {*first[key], *second[key]}
        if first[key].get(name) != second[key].get(name)
    }

    assert first.keys() == second.keys()
    assert moved == {(label, name) for label, names in VELOCLOUD_POLL_TIMES.items() for name in names}
    assert VeloCloudCollector.VOLATILE_GRAPH_PROPS == VELOCLOUD_POLL_TIMES
    assert graph_sha(VeloCloudCollector, before) == graph_sha(VeloCloudCollector, after)


# --- one process or another -----------------------------------------------------------------

_DIGESTS = """
import json, logging
logging.disable(logging.CRITICAL)
from tests import test_graph_digest as t
print(json.dumps(t.fixture_digests(), sort_keys=True))
"""


def fixture_digests() -> dict[str, str]:
    """The digest of each owned family's fixture, for the hash-seed test."""
    import tempfile

    out = {family: _digest(family, FETCHES[family](1)) for family in sorted(FETCHES)}
    with tempfile.TemporaryDirectory() as tmp:
        out["vyos"] = _vyos_digest(_vyos_fetch(1), Path(tmp))
    return out


def test_two_interpreters_with_different_hash_seeds_digest_alike():
    """The digest does not follow the string hash seed."""

    def run(seed: str) -> dict[str, str]:
        env = {**os.environ, "PYTHONHASHSEED": seed}
        done = subprocess.run(
            [sys.executable, "-c", _DIGESTS], cwd=REPO, env=env, capture_output=True, text=True, check=True
        )
        result: dict[str, str] = json.loads(done.stdout.strip().splitlines()[-1])
        return result

    assert run("1") == run("2") == fixture_digests()
