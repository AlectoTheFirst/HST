"""The Cisco route table, BGP session summaries and BGP path tables are
observations, not configuration (collectors/iosxe.py, iosxr.py, nxos.py
`VOLATILE_RAW_KEYS` and `BGP_OBSERVATION_KEY_RE`; collectors/base.py
`raw_sha`, `obs_sha`).

No graph object is built from the route table or the path tables, and the
summaries reach the graph only through the dynamic peers they list, which
`_strata_dynamic_bgp` keeps in the configuration hash. A fetch whose route or
path tables moved and whose configuration did not matches the configuration
hash, differs in the observation hash, and takes the observation-only path,
where the payload's sections judge the device (app/runs_exec.py).

tests/support/stream_golden.json, the base record, holds the digests of the
golden payloads under the declarations of the base record
(`synthetic_payloads.base_declarations`). `hash_as_base_record` gives a
family's collector class those declarations, the parser version included, and
the tests that hold the hashes to the base record (`base_digests`) use it.
The IOS-XE and IOS-XR `raw_sha` of parser2_golden.json, which `load_golden`
lays over the base record, are the digests under the same change-hash
declarations and the current parser version. The digests under the current
declarations are pinned here (`PINNED`); `show version`, and on IOS-XE `show
ip nat statistics`, are in the change hash under them, since the graph is
built from them (tests/test_graph_digest.py).

The payloads are synthetic (`tests/support/`) or the families' test fixtures,
nothing captured from real infrastructure.
"""

from __future__ import annotations

import functools
import importlib
import json
import re
from types import ModuleType
from typing import Any

import pytest
from tests import test_cisco_dynamic_bgp as dynamic
from tests.app.test_runs_exec_fleet import (
    PREV,
    _Cycle,
    _device,
    _recent,
    _Rt,
    _Rules,
    _Session,
    _source,
    _status,
)
from tests.support.synthetic_payloads import (
    CASES,
    COLLECTOR_HOST,
    FAMILIES,
    GOLDEN_PATH,
    base_declarations,
    base_spelling,
    case_payload,
    fixture_raw,
    iosxe_payload,
    iosxr_payload,
    load_golden,
    make_collector,
    make_settings,
    nxos_payload,
    split_case,
)

from hst.app import runs_exec
from hst.app.crypto import generate_key
from hst.collectors import REGISTRY, iosxe, iosxr, nxos, vyos
from hst.collectors.base import RAW_OUTCOMES_KEY, Collector, SourceConfig, graph_sha, obs_sha, raw_sha
from hst.collectors.cisco_common import MTU_COMMANDS

MODULES: dict[str, ModuleType] = {"iosxe": iosxe, "iosxr": iosxr, "nxos": nxos}
COLLECTORS: dict[str, type[Collector]] = {
    "iosxe": iosxe.IosxeCollector,
    "iosxr": iosxr.IosxrCollector,
    "nxos": nxos.NxosCollector,
}
BUILDERS = {"iosxe": iosxe_payload, "iosxr": iosxr_payload, "nxos": nxos_payload}


def hash_as_base_record(monkeypatch: pytest.MonkeyPatch, family: str) -> None:
    """Give `family`'s collector class the declarations `raw_sha` and
    `obs_sha` read that the base record was computed with
    (`synthetic_payloads.base_declarations`): its volatile and observation
    keys, no key pattern, and its parser version. A payload then hashes to
    the digests of the base record (`base_digests`)."""
    cls = COLLECTORS[family]
    for name, value in base_declarations(family).items():
        monkeypatch.setattr(cls, name, value)


@functools.cache
def _base_record() -> dict[str, Any]:
    cases: dict[str, Any] = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))["cases"]
    return cases


def base_digests(key: str) -> tuple[str, str]:
    """(raw_sha, obs_sha) of the golden case `key` in the base record,
    `stream_golden.json`, without the overlays `load_golden` lays over it."""
    case = _base_record()[key]
    return case["raw_sha"], case["obs_sha"]


# (raw_sha, obs_sha) of every golden case under the current declarations.
PINNED: dict[str, tuple[str, str]] = {
    "iosxe/fixture/plain": (
        "b780745e2c165682da0f0756feb36a5c0dbd1c543ed6269659223c211fe077df",
        "dc2ffa6a39a04e65401ee86fecd1c75c822665e44f44274704cf74e132894829",
    ),
    "iosxe/fixture/no_trailing_newline": (
        "dbec5974ecaa6102d88f919b8c3de8ae2a66d760772257b4d114bbed80980df3",
        "223661eca9242e0646da2541114d5f6dc4485db47e4576668ea94283c753d8e3",
    ),
    "iosxe/fixture/unicode": (
        "0b8b03a2ed70c22e9307053fc03fc3ac27835df96ed45731a81d1c8807f7b9ba",
        "6b7d6675681899f0225fce14c670e7746731771520e5aea752e13ef64f3be016",
    ),
    "iosxe/small/plain": (
        "4f34418d0294b296712f59305446962f697f060e9c709f269469293cd9e79ff6",
        "3ae0bf128ac311ffed72425639099ed033b2d717107941be803990426696e13a",
    ),
    "iosxe/small/no_trailing_newline": (
        "b01073245e4dc56e6694dd51b889e08add0b54436c789c1bd669aefb3a79ffb6",
        "2470ba6c641a3d324866d433147024ff036b08eff1c24f68e328039f31126d4c",
    ),
    "iosxe/small/unicode": (
        "ea8eb17d132dce990d3b3910106ce7ae34234078d71906a75d21c79445a46b48",
        "960e170c10985f6572a8de163b56f61e14f21dfec8574b6e0e4019f443704145",
    ),
    "iosxe/medium/plain": (
        "4f34418d0294b296712f59305446962f697f060e9c709f269469293cd9e79ff6",
        "0347e0f1068c2330024d20f822da3585dc96834894545965ab0098285729c53b",
    ),
    "iosxe/medium/no_trailing_newline": (
        "b01073245e4dc56e6694dd51b889e08add0b54436c789c1bd669aefb3a79ffb6",
        "0f4b3537ad6ee46fe3388398a6e71c688f0782b054efbca8aaf74a511b048e23",
    ),
    "iosxe/medium/unicode": (
        "ea8eb17d132dce990d3b3910106ce7ae34234078d71906a75d21c79445a46b48",
        "e700316a04dae267de1c6e14b6e7b5cd3c06f357fe3878d6f9f26434e9d8d221",
    ),
    "iosxr/fixture/plain": (
        "20cce0e36025fa2efc7937deaf2f725c1c933f7285d1f3df478ba6d5199279e6",
        "54b6f09aa8b21834c6564d64a0d096c60af9b2b7f6fd5d57e0946d297baf62fc",
    ),
    "iosxr/fixture/no_trailing_newline": (
        "60fcde69bdbc7f7000ba22df495318e238075c0ab07079ad8085f6fb5730957e",
        "df4bfbd45082812d107e891d9272a273e70d1b6781808c13dd7046adf1446f9f",
    ),
    "iosxr/fixture/unicode": (
        "4667f9e7941bad1c640ef498910d3738329403d37d04f69f5956e94eac33d2d8",
        "449f8750a9cc55cbc72ad5488ce0aa1400ffb8b7e8f98a127cdcd7122fa151d4",
    ),
    "iosxr/small/plain": (
        "394b0c81ea7e9618c20042efc788dfd019ec806d23349bea5a25eedf3004c803",
        "e61ded33560484351e70d8e2fc25d5eeb0d4eb311f16a40b5e90fd095d1320d5",
    ),
    "iosxr/small/no_trailing_newline": (
        "3013a62d875611e73fe9d9cc3a38b7a2d98615b123cec427bcdf23131eb497ae",
        "831d0c9b07555b54c2d9bf134a0f0efa9d008ed3d7ef0dbdd0b9d873be4b8e1b",
    ),
    "iosxr/small/unicode": (
        "2bae5b7816213d9dcf07889c34a6c47f1dd4f83d1c1438b80c692884fd750179",
        "ab8c2a5e77ceae619cd2e260af68382f57edb669c738c5c205f38b86a8eec877",
    ),
    "iosxr/medium/plain": (
        "394b0c81ea7e9618c20042efc788dfd019ec806d23349bea5a25eedf3004c803",
        "aa014aac0e982050402968583e171c6158d7f72c4dc594375770f46d217fb101",
    ),
    "iosxr/medium/no_trailing_newline": (
        "3013a62d875611e73fe9d9cc3a38b7a2d98615b123cec427bcdf23131eb497ae",
        "96c545b016beb05a4cab4c157f30292cf2021a05f2b0d14424234e2231ac0cc9",
    ),
    "iosxr/medium/unicode": (
        "2bae5b7816213d9dcf07889c34a6c47f1dd4f83d1c1438b80c692884fd750179",
        "dc1e855f3a9486858255aa535d648927d99edf0ec74838e730dadfaf30f1359c",
    ),
    "nxos/fixture/plain": (
        "b0a3a387965b87f0fbd971a3b91ce8ed664b63e88ce64f8bfd326945c4e2f7ba",
        "74cc05738fefbbea78b885fbcdf57e5f71b71ab4902046a74a67eb7ddee8aa7b",
    ),
    "nxos/fixture/no_trailing_newline": (
        "0aa9a217e9db2bae1c1bb8c30cbb92b239892078aec0d5c7873658873a6238ab",
        "867bc5c72bae2a76ead9fd06e98753d4f8845ee57be2f58ec41f913423ad559f",
    ),
    "nxos/fixture/unicode": (
        "1b73ed5963cbd494da19e6872ff811e9dcf7a82408a1b3ae068512a0a97408b5",
        "1d8dcce605197f9dbc757d752389f8dfcd8e129a089c868c4a7f1c3c27692078",
    ),
    "nxos/small/plain": (
        "42f6d66a1661eb8521a13ae76ac601e14c109fe009e51fc978eb3e0be3f6b273",
        "7b1ed330c573706d5913923a2e9a883861104d4e064bc5dd82153a1fcc95459a",
    ),
    "nxos/small/no_trailing_newline": (
        "3f0e01d82d68cbcd7210bc8cc479222838aa56901c7bbbbbc5aadd77611a3b46",
        "989a4d1908a5232040516796bc639816140ca0773f128b4cf069c2fdcdf33387",
    ),
    "nxos/small/unicode": (
        "734add15bfb2a233b5c9ad8873f0731bcb1c7d0ac8a05ed6ae26f4c4c2d4ed95",
        "02f22f490e9d17963d1ed81abcc381f413fe4d00047143ad7079ba7c4a01c55d",
    ),
    "nxos/medium/plain": (
        "42f6d66a1661eb8521a13ae76ac601e14c109fe009e51fc978eb3e0be3f6b273",
        "4012654fb8befe21f2efd3ba3415843f5c5298636a4d4f1633b1bf6bdd912ee7",
    ),
    "nxos/medium/no_trailing_newline": (
        "3f0e01d82d68cbcd7210bc8cc479222838aa56901c7bbbbbc5aadd77611a3b46",
        "1167318a97da58ace8462213416a5f07dc6f88ce163153083e96473742a93ba6",
    ),
    "nxos/medium/unicode": (
        "734add15bfb2a233b5c9ad8873f0731bcb1c7d0ac8a05ed6ae26f4c4c2d4ed95",
        "063e6e4c7eff9e9b5cb20412e0e879b9d757091f0676ecadb75fe09e7cf9223f",
    ),
    "iosxe/tenth/plain": (
        "0a05a6fd3172a5719d2e54090925fdbe8e23ea39e9a9ee643e07b2de4e7e247a",
        "ee07509127a37a91b5d32a194bd04372872e3a5ea0470c5d6793b941c65d274d",
    ),
}


# --- the digests ------------------------------------------------------------------------


@pytest.mark.parametrize("key", CASES)
def test_every_golden_case_hashes_to_its_pinned_and_its_golden_digests(key, tmp_path, monkeypatch):
    """Under the current declarations, a case hashes to its pinned digests.
    Under those of the base record (`hash_as_base_record`), the case in the
    spelling of the base record (`base_spelling`) hashes to the digests of the
    base record, and with the current parser version in place of the recorded
    one, to the golden digests `load_golden` returns."""
    family, _scale, _variant = split_case(key)
    cls = COLLECTORS[family]
    parser_version = cls.PARSER_VERSION
    collector = make_collector(family, make_settings(tmp_path))
    payload = case_payload(key)
    spelled = base_spelling(family, payload)
    golden = load_golden()["cases"][key]

    assert (raw_sha(collector, payload), obs_sha(collector, payload)) == PINNED[key]
    hash_as_base_record(monkeypatch, family)
    assert (raw_sha(collector, spelled), obs_sha(collector, spelled)) == base_digests(key)
    monkeypatch.setattr(cls, "PARSER_VERSION", parser_version)
    assert (raw_sha(collector, spelled), obs_sha(collector, spelled)) == (
        golden["raw_sha"],
        golden["obs_sha"],
    )


def test_the_pinned_digests_are_every_golden_case_and_differ_from_the_golden_ones():
    golden = load_golden()["cases"]

    assert sorted(PINNED) == sorted(CASES)
    for key, (sha, obs) in PINNED.items():
        record = base_digests(key)
        assert sha not in {golden[key]["raw_sha"], record[0]}, key
        assert obs not in {golden[key]["obs_sha"], record[1]}, key


@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("variant", ["plain", "no_trailing_newline", "unicode"])
def test_two_scales_that_differ_only_in_routes_and_paths_share_a_configuration_hash(family, variant):
    """The small and medium cases of one family and variant differ in the
    size of their route and path tables alone."""
    small, medium = PINNED[f"{family}/small/{variant}"], PINNED[f"{family}/medium/{variant}"]

    assert small[0] == medium[0]
    assert small[1] != medium[1]


# --- what the declarations leave out of the configuration hash ------------------------------


def _observation_keys(family: str, payload: dict[str, Any]) -> list[str]:
    """The route command and every key the family's pattern matches."""
    pattern = MODULES[family].BGP_OBSERVATION_KEY_RE
    return [key for key in payload if key == MODULES[family].CMD_ROUTE or pattern.fullmatch(key)]


def _graph(batch: Any) -> tuple[list[Any], list[Any], list[str]]:
    """Nodes and relationships with their properties, and warnings, in an
    order two batches compare in."""
    nodes = sorted((n.label, n.uid, json.dumps(n.props, sort_keys=True, default=str)) for n in batch.nodes)
    rels = sorted(json.dumps(r.model_dump(mode="json"), sort_keys=True) for r in batch.rels)
    return nodes, rels, list(batch.warnings)


@pytest.mark.parametrize("family", FAMILIES)
def test_the_route_and_path_texts_leave_the_graph_as_it_was(family):
    """Two fetches of one configuration whose route, summary and path texts
    differ: the same graph, the same configuration hash, and a different
    observation hash."""
    first = BUILDERS[family](routes=300, peers=2, paths=200, seed=0)
    other = BUILDERS[family](routes=300, peers=2, paths=200, seed=1)
    swapped = _observation_keys(family, first)
    second = {**first, **{key: other[key] for key in swapped}}
    assert any(first[key] != second[key] for key in swapped)
    collector = make_collector(family, None)

    before, after = collector.normalize(first), make_collector(family, None).normalize(second)

    assert _graph(before) == _graph(after)
    assert graph_sha(collector, before) == graph_sha(collector, after)
    assert {n: o for n, o in before.sections.items() if n != "rib"} == {
        n: o for n, o in after.sections.items() if n != "rib"
    }
    assert raw_sha(collector, first) == raw_sha(collector, second)
    assert obs_sha(collector, first) != obs_sha(collector, second)


@pytest.mark.parametrize("family", FAMILIES)
def test_configuration_and_route_outcome_changes_change_the_configuration_hash(family):
    module = MODULES[family]
    collector = make_collector(family, None)
    payload = BUILDERS[family](routes=50, peers=2, paths=20)
    sha, obs = raw_sha(collector, payload), obs_sha(collector, payload)

    reconfigured = {**payload, module.CMD_BGP: payload[module.CMD_BGP] + "\n"}
    refused = {
        **payload,
        RAW_OUTCOMES_KEY: {
            **payload[RAW_OUTCOMES_KEY],
            module.CMD_ROUTE: {"status": "failed", "detail": "% Invalid input"},
        },
    }
    path = (
        module.bgp_route_command("default", "192.0.2.77", "accepted")
        if family == "nxos"
        else module.bgp_route_command("192.0.2.77", "accepted")
    )
    one_more_path = {**payload, path: ""}

    assert raw_sha(collector, reconfigured) != sha
    assert raw_sha(collector, refused) != sha
    assert (raw_sha(collector, one_more_path), obs_sha(collector, one_more_path) != obs) == (sha, True)


# --- the pattern ----------------------------------------------------------------------------

VRFS = ("default", "WAN", "blue-1")
PEERS = ("192.0.2.1", "2001:db8::1")


def _derived(family: str) -> list[str]:
    """Every command the family's BGP capture derives, for each VRF, peer and
    direction."""
    module = MODULES[family]
    commands: list[str] = []
    for vrf in VRFS:
        if family != "nxos":
            commands.append(module.bgp_summary_command(vrf))
        for peer in PEERS:
            for direction in module.BGP_DIRECTION_KEYWORDS:
                commands.append(
                    module.bgp_route_command(vrf, peer, direction)
                    if family == "nxos"
                    else module.bgp_route_command(peer, direction, vrf)
                )
    return commands


@pytest.mark.parametrize("family", FAMILIES)
def test_the_pattern_matches_every_command_the_capture_derives(family):
    pattern = MODULES[family].BGP_OBSERVATION_KEY_RE
    commands = _derived(family)

    assert len(set(commands)) == len(commands)
    assert [command for command in commands if not pattern.fullmatch(command)] == []


@pytest.mark.parametrize("family", FAMILIES)
def test_the_pattern_matches_no_static_command(family):
    module = MODULES[family]
    cls = COLLECTORS[family]
    static = {
        *module.COMMANDS,
        *getattr(cls, "OPTIONAL_COMMANDS", {}),
        *MTU_COMMANDS[family].values(),
        module.CMD_BGP,
        RAW_OUTCOMES_KEY,
        "_strata_dynamic_bgp",
    }

    matched = {command for command in static if module.BGP_OBSERVATION_KEY_RE.fullmatch(command)}

    assert matched <= {module.CMD_BGP_SESSIONS}


@pytest.mark.parametrize("family", FAMILIES)
def test_the_pattern_matches_exactly_the_capture_of_the_family_fixture(family):
    module = MODULES[family]
    capture = set(importlib.import_module(f"tests.test_{family}")._bgp_capture_raw())
    raw = fixture_raw(family)

    matched = {key for key in raw if module.BGP_OBSERVATION_KEY_RE.fullmatch(key)}

    assert capture <= set(raw)
    assert matched | {module.CMD_BGP_SESSIONS} == capture


def test_no_cisco_route_table_is_mirrored_into_the_graph():
    """The route table can leave the configuration hash only while no graph
    object is built from it."""
    for cls in COLLECTORS.values():
        assert cls.GRAPH_MIRRORED_TABLES == (), cls.name
    assert "rib" in vyos.VyosCollector.GRAPH_MIRRORED_TABLES


def test_no_other_collector_declares_a_key_pattern():
    others = [
        cls
        for cls in REGISTRY.values()
        if cls.__module__.startswith("hst.collectors.") and cls.name not in COLLECTORS
    ]

    assert others
    for cls in others:
        assert (cls.VOLATILE_RAW_KEY_PATTERN, cls.OBSERVATION_RAW_KEY_PATTERN) == (None, None), cls.name


class _Cfg(SourceConfig):
    host: str = ""


class _Plain(Collector):
    name = "plain"
    KIND = "group"
    ConfigModel = _Cfg
    VOLATILE_RAW_KEYS = ("uptime",)
    OBSERVATION_RAW_KEYS = ("arp",)

    def fetch(self) -> Any:
        return {}

    def normalize(self, raw: Any) -> Any:
        raise NotImplementedError

    def probe(self) -> str:
        return "ok"


class _Patterned(_Plain):
    OBSERVATION_RAW_KEYS = ()
    VOLATILE_RAW_KEY_PATTERN = re.compile(r"show bgp neighbors \S+ routes")
    OBSERVATION_RAW_KEY_PATTERN = VOLATILE_RAW_KEY_PATTERN


class _Undeclared:
    """A collector-shaped object that declares no key pattern attributes at all."""

    VOLATILE_RAW_KEYS = ("uptime",)
    OBSERVATION_RAW_KEYS = ("arp",)
    PARSER_VERSION = "1"

    def __init__(self) -> None:
        self.config = _Cfg(host="r1")
        self.settings = None

    def normalization_inputs(self) -> dict[str, Any]:
        """What every Collector hashes: the device identity registry generation."""
        return {"identity_generation": 0}


RAW = {"uptime": "3 days", "arp": ["10.0.0.1"], "show bgp neighbors 192.0.2.1 routes": "a", "hostname": "r1"}


def test_a_collector_without_a_pattern_hashes_as_one_that_never_had_one():
    plain = _Plain(_Cfg(host="r1"), None)
    moved = {**RAW, "show bgp neighbors 192.0.2.1 routes": "b"}

    assert raw_sha(plain, RAW) == raw_sha(_Undeclared(), RAW)
    assert obs_sha(plain, RAW) == obs_sha(_Undeclared(), RAW)
    assert raw_sha(plain, moved) != raw_sha(plain, RAW)
    assert obs_sha(plain, moved) == obs_sha(plain, RAW)


def test_a_pattern_moves_the_keys_it_matches_from_one_hash_to_the_other():
    patterned = _Patterned(_Cfg(host="r1"), None)
    moved = {**RAW, "show bgp neighbors 192.0.2.1 routes": "b"}
    without = {k: v for k, v in RAW.items() if k != "show bgp neighbors 192.0.2.1 routes"}

    assert raw_sha(patterned, moved) == raw_sha(patterned, RAW) == raw_sha(patterned, without)
    assert obs_sha(patterned, moved) != obs_sha(patterned, RAW)
    # a pattern alone declares an observation half, empty or not
    assert obs_sha(patterned, without) != ""
    # a key that is not a str never matches
    assert raw_sha(patterned, {7: "x"}) != raw_sha(patterned, {})


# --- dynamic peers --------------------------------------------------------------------------

# The dynamic-neighbor network of test_cisco_dynamic_bgp.py, as a fixture of
# this module: a range whose members the per-VRF summary lists. A member that
# disappears from the summary is that module's
# `test_disappearing_peer_changes_fingerprint_and_graph`.
dynamic_network = dynamic.network


def _edit_summary(family: str, text: str, edit: Any) -> str:
    """The summary with `edit` applied to each neighbor: to its JSON row on
    NX-OS, and to its text line elsewhere."""
    if family == "nxos":
        payload = json.loads(text)
        for row in payload["TABLE_vrf"]["ROW_vrf"]["TABLE_neighbor"]["ROW_neighbor"]:
            edit(row)
        return json.dumps(payload)
    return "\n".join(
        edit(line) if line[:1].isdigit() or line[:1] == "*" else line for line in text.split("\n")
    )


def test_a_summary_whose_counters_moved_keeps_the_configuration_hash(dynamic_network):
    family, _mod, _base, outputs, summary, _routes, _fake = dynamic_network
    collector, first, _batch = dynamic.collect(dynamic_network, "sessions")

    def tick(row: Any) -> Any:
        if family == "nxos":
            row["lastflap"] = "PT7M"
            return row
        return row.replace(" 10 10 1 0 0 00:01:00 ", " 12 14 1 0 0 00:07:00 ")

    outputs[summary] = _edit_summary(family, outputs[summary], tick)
    second = collector.fetch()

    assert second[summary] != first[summary]
    assert second["_strata_dynamic_bgp"] == first["_strata_dynamic_bgp"]
    assert raw_sha(collector, second) == raw_sha(collector, first)
    assert obs_sha(collector, second) != obs_sha(collector, first)


def test_a_dynamic_peer_whose_state_moved_changes_the_configuration_hash(dynamic_network):
    family, _mod, _base, outputs, summary, _routes, _fake = dynamic_network
    collector, first, before = dynamic.collect(dynamic_network, "sessions")

    def establish(row: Any) -> Any:
        if family == "nxos":
            row["state"] = "Established"
            return row
        return row.replace(" 00:01:00 Idle", " 00:01:00 1")

    outputs[summary] = _edit_summary(family, outputs[summary], establish)
    second = collector.fetch()
    after = collector.normalize(second)

    assert raw_sha(collector, second) != raw_sha(collector, first)

    def states(batch: Any) -> set[str]:
        return {n.props["observed_state"] for n in batch.nodes if n.label == "BgpSession"}

    assert states(before) == {"Established", "Idle"}
    assert states(after) == {"Established"}


# --- the observation-only path --------------------------------------------------------------


class _Replaying(nxos.NxosCollector):
    """NX-OS answering every fetch with `answer`, on the thread lane."""

    answer: dict[str, Any] = {}

    def fetch(self) -> Any:
        return json.loads(json.dumps(self.answer))


def test_a_route_table_that_stops_parsing_fails_the_device_on_the_observation_path(tmp_path, monkeypatch):
    """The route text is volatile and its recorded outcome stays `ok`, so the
    configuration hash matches the run on record and the observation hash
    does not. The observation-only path judges the payload's sections and
    fails the device, as a full load of the same payload does."""
    pytest.importorskip("pyarrow")
    settings = make_settings(tmp_path, hst_secret_key=generate_key())
    good = nxos_payload(routes=50, peers=1, paths=20)
    config = make_collector("nxos", settings).config.model_copy(update={"transport": "paramiko"})
    collector = _Replaying(config, settings)
    collector.answer = {**good, nxos.CMD_ROUTE: '{"unexpected": 1}'}
    prior = {
        ("edge", COLLECTOR_HOST): _status(
            "edge", COLLECTOR_HOST, raw_sha(collector, good), _recent(), obs=obs_sha(collector, good)
        )
    }
    stub = _Cycle(PREV)
    monkeypatch.setattr(runs_exec, "cycle", stub)
    monkeypatch.setattr(runs_exec, "reasoner", _Rules())
    monkeypatch.setattr(runs_exec, "rt_reasoner", _Rt())
    monkeypatch.setattr(runs_exec.dbmod, "session", lambda s: _Session())
    unit = runs_exec.PreparedDevice(_device("edge", COLLECTOR_HOST), collector, None)
    outs: list[runs_exec.DeviceOutcome] = []

    runs_exec.execute_cycle(
        settings, [runs_exec.PreparedSource(_source("edge", "nxos"), [unit])], {"edge"}, None, prior, outs
    )

    (out,) = outs
    assert out.observations_only and not out.ok
    assert out.sections["rib"].status == "malformed"
    assert out.error == "sections not collected: rib=malformed"
    assert stub.scopes == {collector.scope: "failed"}
