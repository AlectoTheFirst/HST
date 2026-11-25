"""The VyOS fetch, parse, side rows and outcomes against the golden values."""

from __future__ import annotations

import functools
import gc
import ipaddress
import json
import weakref
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from tests.conftest import FakeSshSession
from tests.support.synthetic_payloads import (
    COLLECTOR_SOURCE,
    ROW_GROUP_ROWS,
    RUN_ID,
    SNAPSHOT_TS,
    make_settings,
    outcomes_json,
    parquet_layout,
    rows_digest,
)
from tests.support.synthetic_vyos import (
    CASES,
    POLICY_TABLES,
    SESSION_SETTING_PROPS,
    Refusal,
    answers,
    answers_sha,
    base_raw,
    base_shape,
    batch_digest,
    defaults_free,
    fetch,
    installation_free,
    is_beside_prefix_list_filter,
    is_device_pbr_enforces,
    is_ruleset_enforces,
    is_wanlink_on,
    link_local_free,
    load_golden,
    make_collector,
    new_raw,
    payload_json_sha,
    policy_table_command,
    session_settings_free,
    tree_family,
)
from tests.test_collector_execute import FakeSession

from hst.collectors import base as collectors_base
from hst.collectors import ssh, streams, vyos
from hst.collectors.base import RAW_OUTCOMES_KEY, load_payload
from hst.collectors.util import as_int
from hst.collectors.vyos import (
    BGP_DIRECTION_KEYWORDS,
    BGP_SUMMARY_COMMAND,
    READ_COMMANDS,
    _bgp_best,
    _bgp_communities,
)
from hst.core import manifest
from hst.core.l3domain import DEFAULT_VRF
from hst.core.model import SectionOutcome, TableOutcome

GOLDEN = load_golden()
OK = SectionOutcome(status="ok")


@functools.cache
def _answers(key: str) -> dict[str, str | Refusal]:
    """`synthetic_vyos.answers(key)`, built once per case for this module.
    Callers do not change it; a test that needs other answers copies it."""
    return answers(key)


@pytest.fixture(autouse=True, scope="module")
def _drop_answers():
    """The medium cases hold about 128 MB of text each."""
    yield
    _answers.cache_clear()


OP_WRAPPER = "/opt/vyatta/bin/vyatta-op-cmd-wrapper "


# --- the base implementations ------------------------------------------------------------

_BASE_ROUTE_TABLE_KEYS = {
    "received": "receivedRoutes",
    "accepted": "routes",
    "advertised": "advertisedRoutes",
}


def _base_command_outcome(text: Any, recorded: SectionOutcome | None, row_count: int | None) -> TableOutcome:
    if recorded is None:
        return TableOutcome(status="not-captured")
    if recorded.status == "unsupported":
        return TableOutcome(status="not-captured", detail=recorded.detail)
    if recorded.status != "ok":
        return TableOutcome(status="failed", detail=recorded.detail)
    body = str(text or "").strip()
    if not body:
        return TableOutcome(status="complete-empty", row_count=0)
    if body.startswith("%"):
        return TableOutcome(status="not-captured", detail=body.splitlines()[0].strip())
    try:
        payload = json.loads(body)
    except ValueError:
        return TableOutcome(status="failed", detail="the command answered with text that is not JSON")
    if not isinstance(payload, dict):
        return TableOutcome(status="failed", detail="the command answered with JSON that is not an object")
    warning = payload.get("warning")
    if isinstance(warning, str) and warning:
        return TableOutcome(status="not-captured", detail=warning)
    count = row_count or 0
    if not count:
        return TableOutcome(status="complete-empty", row_count=0)
    return TableOutcome(status="complete", row_count=count)


def _base_parse_bgp_paths(text: str, *, vrf: str, peer_ip: str, direction: str) -> list[dict[str, Any]]:
    if not str(text or "").strip():
        return []
    try:
        payload = json.loads(text)
    except ValueError:
        return []
    if not isinstance(payload, dict):
        return []
    table = payload.get(_BASE_ROUTE_TABLE_KEYS[direction])
    if not isinstance(table, dict):
        return []
    out: list[dict[str, Any]] = []
    for prefix, paths in table.items():
        if not isinstance(paths, list):
            continue
        for idx, path in enumerate(paths):
            if not isinstance(path, dict):
                continue
            nexthops = [h for h in (path.get("nexthops") or []) if isinstance(h, dict)]
            used = next((h.get("ip") for h in nexthops if h.get("used")), None)
            next_hop = used if used is not None else (nexthops[0].get("ip") if nexthops else None)
            out.append(
                {
                    "vrf": vrf,
                    "peer_ip": peer_ip,
                    "direction": direction,
                    "prefix": prefix,
                    "path_id": str(idx),
                    "next_hop": next_hop,
                    "as_path": (path.get("aspath") or {}).get("string") or None,
                    "local_pref": as_int(path.get("locPrf")),
                    "med": as_int(path.get("metric")),
                    "origin": path.get("origin"),
                    "communities": _bgp_communities(path.get("communityList")),
                    "best": _bgp_best(path, direction),
                }
            )
    return out


def _base_parse_bgp_summary(text: str) -> list[dict[str, Any]]:
    if not str(text or "").strip():
        return []
    try:
        payload = json.loads(text)
    except ValueError:
        return []
    if not isinstance(payload, dict):
        return []
    out: list[dict[str, Any]] = []
    for vrf_name, vrf_payload in payload.items():
        if not isinstance(vrf_payload, dict):
            continue
        fam = vrf_payload.get("ipv4Unicast")
        if not isinstance(fam, dict):
            continue
        peers = fam.get("peers")
        if not isinstance(peers, dict):
            continue
        for peer_ip, p in peers.items():
            if not isinstance(p, dict):
                continue
            out.append(
                {
                    "vrf": vrf_name,
                    "peer_ip": peer_ip,
                    "state": p.get("state"),
                    "established_since_ms": None,
                    "prefixes_received": p.get("pfxRcd"),
                    "prefixes_advertised": p.get("pfxSnt"),
                    "capabilities": None,
                }
            )
    return out


def _base_rib_entries(raw: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key, af in (("routes", 4), ("routes6", 6)):
        vrfs = raw.get(key)
        listings = list(vrfs.values()) if isinstance(vrfs, dict) else []
        tables = raw.get(f"{key}_tables")
        if isinstance(tables, dict):
            listings += list(tables.values())
        for by_prefix in listings:
            if not isinstance(by_prefix, dict):
                continue
            for prefix, routes in by_prefix.items():
                try:
                    net = ipaddress.ip_network(prefix)
                except ValueError:
                    continue
                if net.version != af:
                    continue
                for route in routes or []:
                    if not (route.get("installed") and route.get("selected")):
                        continue
                    if route.get("protocol") == "local":
                        continue
                    hops = [n for n in route.get("nexthops") or [] if n.get("fib")] or [
                        n for n in route.get("nexthops") or [] if n.get("active")
                    ]
                    for nh in hops:
                        gw, ifname = nh.get("ip"), nh.get("interfaceName")
                        rows.append(
                            {
                                "table": str(route.get("table") or "main"),
                                "cidr": str(net),
                                "af": net.version,
                                "next_hop": gw,
                                "interface": ifname,
                                "next_hop_vrf": nh.get("vrf"),
                                "protocol": str(route["protocol"]) if route.get("protocol") else None,
                                "metric": route.get("metric"),
                                "discard": "blackhole" if not gw and not ifname else None,
                            }
                        )
    return rows


# --- helpers -------------------------------------------------------------------------------


def _answer_outputs(built: dict[str, str | Refusal]) -> Callable[[str], str]:
    """`FakeSshSession` outputs that answer from `built`, refusing as the SSH
    layer does."""

    def outputs(command: str) -> str:
        answer = built.get(command.removeprefix(OP_WRAPPER))
        if answer is None:
            # a command the fixture device does not answer, such as the neighbor detail
            raise ssh.CommandFailed(f"{command!r} rejected by device: % Unknown command")
        if isinstance(answer, Refusal):
            raise ssh.CommandFailed(answer.message)
        return answer

    return outputs


def _rib_commands(payload: dict[str, Any]) -> dict[str, str]:
    """RIB raw key (and `<key>_tables/<n>`) -> the command that answered it."""
    out = {"routes": READ_COMMANDS["routes"], "routes6": READ_COMMANDS["routes6"]}
    for key, ip_word in (("routes", "ip"), ("routes6", "ipv6")):
        for number in payload.get(f"{key}_tables") or {}:
            out[f"{key}_tables/{number}"] = policy_table_command(ip_word, int(number))
    return out


def _rib_value(payload: dict[str, Any], name: str) -> Any:
    key, _, number = name.partition("/")
    return payload[key][number] if number else payload[key]


def _assert_only_device_pbr_enforces_added(batch: Any) -> None:
    """What `base_shape` takes out is one `(Device)-[:ENFORCES]->(PbrPolicy)` edge
    per PbrPolicy of the batch, from the batch's own Device, and nothing else."""
    devices = {n.uid for n in batch.nodes if n.label == "Device"}
    policies = sorted(n.uid for n in batch.nodes if n.label == "PbrPolicy")
    added = [r for r in batch.rels if is_device_pbr_enforces(r)]
    assert sorted(r.end_uid for r in added) == policies
    assert {r.start_uid for r in added} <= devices
    assert all(not r.key and not r.props for r in added)
    # and one `(WanLink)-[:ON]->(Interface)` edge per WanLink, to an
    # Interface of the batch
    links = sorted(n.uid for n in batch.nodes if n.label == "WanLink")
    on = [r for r in batch.rels if is_wanlink_on(r)]
    assert sorted(r.start_uid for r in on) == links
    interfaces = {n.uid for n in batch.nodes if n.label == "Interface"}
    assert {r.end_uid for r in on} <= interfaces
    assert all(not r.key and not r.props for r in on)
    # and every PbrPolicy and NatRule records the family its tree names as
    # `af`, the property `base_shape` takes off where it holds that family
    for n in batch.nodes:
        if tree_family(n) is not None:
            assert n.props.get("af") == tree_family(n), n.uid
    # and every VrfInstance records `rib_mirrored` as a boolean, the property
    # `base_shape` takes off; in a table it holds True, every forwarding static
    # is one the RIB confirmed, since each case's RIB installs every config
    # static, so the flag turns no installed static into a not installed one
    mirrored = {n.uid: n.props.get("rib_mirrored") for n in batch.nodes if n.label == "VrfInstance"}
    assert mirrored and all(isinstance(v, bool) for v in mirrored.values()), mirrored
    for r in batch.rels:
        if r.rel_type == "STATIC_ROUTE" and mirrored.get(r.start_uid) and not r.props.get("discard"):
            assert r.props.get("rib_confirmed") is True, (r.start_uid, r.end_uid, r.key)


def _assert_only_installation_evidence_added(batch: Any) -> None:
    """What `installation_free` takes out is the installation evidence of the
    VyOS firewall and nothing else: on every access FwRulebase and Zone,
    installed, complete, at one revision of this load that is also the
    configured one, and on every ruleset ENFORCES edge the same evidence
    with a scope of every context and interface in the chain's family."""
    nat = {n.uid for n in batch.nodes if n.label == "FwRulebase" and n.props.get("kind") == "nat"}
    holders = [n for n in batch.nodes if n.label in ("FwRulebase", "Zone") and n.uid not in nat]
    edges = [r for r in batch.rels if is_ruleset_enforces(r, batch) and r.end_uid not in nat]
    # a NAT rulebase is not an access layer and carries none of it
    assert not [n for n in batch.nodes if n.uid in nat and set(n.props) & {"installed", "installed_revision"}]
    revisions = {n.props.get("installed_revision") for n in holders} | {
        r.props.get("installed_revision") for r in edges
    }
    assert len(revisions) <= 1 and None not in revisions
    for node in holders:
        assert node.props["installed"] is True and node.props["coverage"] == "complete"
        assert node.props["configured_revision"] == node.props["installed_revision"]
    for rel in edges:
        assert rel.props["installed"] is True and rel.props["coverage"] == "complete"
        assert rel.props["context_uid"] == "*"
        assert rel.props["ingress_interface_uid"] == rel.props["egress_interface_uid"] == "*"
        assert rel.props["address_family"] in (4, 6)


def _assert_only_session_settings_added(batch: Any) -> None:
    """What `session_settings_free` takes out is the BgpSession settings
    and the process's unwritten neighbors, and
    nothing else: every session states route-reflector-client as true or
    false, no golden payload states a cluster id or attaches a filter-list or
    a prefix-list beside a route-map, so neither those properties nor the
    FILTERED_BY edge of the latter is present."""
    sessions = [n for n in batch.nodes if n.label == "BgpSession"]
    for node in sessions:
        assert node.props["route_reflector_client"] in (True, False), node.uid
        assert set(node.props) & SESSION_SETTING_PROPS == {"route_reflector_client"}, node.uid
    assert not [r for r in batch.rels if is_beside_prefix_list_filter(r)]
    for node in batch.nodes:
        if node.label == "RoutingProcess" and "session_gaps" in node.props:
            assert all("has no resolvable remote-as" in gap for gap in node.props["session_gaps"]), node.uid


def _artifacts(payload: dict[str, Any], data_dir: Path) -> dict[str, Any]:
    """Every golden artifact of one load of `payload`, computed as
    `synthetic_vyos` documents the fields of `vyos_golden.json`."""
    settings = make_settings(data_dir)
    assert settings.sidestore_row_group_rows == ROW_GROUP_ROWS
    collector = make_collector(settings)
    batch = collector.normalize(payload)
    _assert_only_device_pbr_enforces_added(batch)
    _assert_only_installation_evidence_added(batch)
    _assert_only_session_settings_added(batch)
    out: dict[str, Any] = {
        # the installation evidence of the rulesets, the default-valued
        # properties (`DEFAULT_PROPS`), the BgpSession settings and
        # the IPv6 link-local addresses of an interface are taken out as well
        "normalize": batch_digest(
            base_shape(link_local_free(session_settings_free(defaults_free(installation_free(batch)))))
        ),
        # the base record holds no `neigh` section
        "sections": outcomes_json({k: v for k, v in batch.sections.items() if k != "neigh"}),
    }
    del batch
    out["table_outcomes"] = outcomes_json(
        {k: v for k, v in collector.table_outcomes(payload).items() if k != "arp"}
    )
    side = collector.side_tables(payload)
    assert len(side.pop("arp")) == 0
    out["side_tables"] = {table: list(rows_digest(rows)) for table, rows in sorted(side.items())}
    del side
    source, host = collectors_base._identity(collector, None)
    written = collectors_base._write_side_tables(
        collector, payload, source, host, run_id=RUN_ID, collection_ts=SNAPSHOT_TS, on_write=None
    )
    out["tables"] = outcomes_json({k: v for k, v in written.items() if k != "arp"})
    parquet: dict[str, list[Any]] = {}
    layout: dict[str, dict[str, Any] | None] = {}
    for table in out["side_tables"]:
        path = data_dir / written[table].path if written[table].path else None
        parquet[table] = [0, None] if path is None else list(manifest.sidestore_row_facts(path))
        layout[table] = parquet_layout(path)
    out["parquet"] = parquet
    out["parquet_layout"] = layout
    collector.release_payload()
    return out


def test_the_base_shape_takes_out_the_device_pbr_edges_and_nothing_else(tmp_path: Path) -> None:
    """The fixture case holds policy routes, so the strip in `_artifacts` is not
    vacuous, and everything else of the batch passes through it unchanged."""
    batch = make_collector(make_settings(tmp_path)).normalize(new_raw(_answers(CASES[0])))
    added = [r for r in batch.rels if is_device_pbr_enforces(r)]
    assert added
    stripped = base_shape(batch)
    # the WireGuard Tunnel uids become those of the base record, and
    # nothing else of a node changes
    renamed = {n.uid: s.uid for n, s in zip(batch.nodes, stripped.nodes, strict=True) if n.uid != s.uid}
    assert renamed
    assert all(old.startswith("tun:wireguard:") and old.count("~") == 2 for old in renamed)
    # and a PbrPolicy and a NatRule lose the `af` of their tree, which the case
    # holds, and nothing else of a node changes
    assert [n for n in batch.nodes if n.label == "PbrPolicy" and n.props.get("af") == 4]
    assert [n for n in batch.nodes if n.label == "NatRule" and n.props.get("af") == 4]
    # and a VrfInstance loses its `rib_mirrored`, True for both tables of the case
    assert {n.uid: n.props.get("rib_mirrored") for n in batch.nodes if n.label == "VrfInstance"} == {
        "vrf:dev:qemu1234:default": True,
        "vrf:dev:qemu1234:table100": True,
    }
    assert [
        n.model_copy(
            update={
                "uid": renamed.get(n.uid, n.uid),
                "props": {
                    k: v
                    for k, v in n.props.items()
                    if not (k == "af" and tree_family(n) is not None)
                    and not (k == "rib_mirrored" and n.label == "VrfInstance")
                },
            }
        )
        for n in batch.nodes
    ] == stripped.nodes
    on = [r for r in batch.rels if is_wanlink_on(r)]
    assert on
    assert len(stripped.rels) == len(batch.rels) - len(added) - len(on)
    assert not [r for r in stripped.rels if is_device_pbr_enforces(r) or is_wanlink_on(r)]


ARTIFACT_FIELDS = (
    "normalize",
    "sections",
    "table_outcomes",
    "side_tables",
    "parquet",
    "parquet_layout",
    "tables",
)


# --- the golden cases ----------------------------------------------------------------------


@pytest.mark.parametrize("key", CASES)
def test_the_answers_and_the_base_payload_are_the_ones_the_golden_was_computed_from(key: str) -> None:
    golden = GOLDEN["cases"][key]
    built = answers(key)
    assert answers_sha(built) == golden["answers_sha"]
    assert payload_json_sha(base_raw(built)) == golden["base_payload_sha"]


@pytest.mark.parametrize("shape", ["text", "tree"])
@pytest.mark.parametrize("key", CASES)
def test_a_load_produces_what_the_base_produced_from_the_same_answers(
    key: str, shape: str, tmp_path: Path
) -> None:
    golden = GOLDEN["cases"][key]
    built = _answers(key)
    payload = new_raw(built) if shape == "text" else base_raw(built)
    got = _artifacts(payload, tmp_path)
    for field in ARTIFACT_FIELDS:
        assert got[field] == golden[field], f"{key} ({shape}): {field} differs from the golden value"
    collector = make_collector(make_settings(tmp_path / "hash"))
    if shape == "tree":
        # a tree payload hashes to the base record under the declarations of the base record
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(vyos.VyosCollector, "VOLATILE_RAW_KEYS", ("version_text", vyos.BGP_SUMMARY_COMMAND))
            patch.setattr(vyos.VyosCollector, "normalization_inputs", lambda self: None)
            patch.setattr(vyos.VyosCollector, "PARSER_VERSION", "1")
            # the base record declares only the MTU normalization version (the
            # firewall version marks the installation evidence)
            patch.setattr(
                vyos.VyosCollector, "NORMALIZATION_VERSIONS", {"mtu": vyos.MTU_NORMALIZATION_VERSION}
            )
            assert collectors_base.raw_sha(collector, payload) == golden["raw_sha"]
        assert collectors_base.raw_sha(collector, payload) != golden["raw_sha"]
        assert collectors_base.obs_sha(collector, payload) == golden["obs_sha"]
    else:
        again = new_raw(_answers(key))
        assert collectors_base.raw_sha(collector, payload) == collectors_base.raw_sha(collector, again)
        assert collectors_base.obs_sha(collector, payload) == collectors_base.obs_sha(collector, again)
        assert collectors_base.obs_sha(collector, payload) != golden["obs_sha"]


# --- the fetch -----------------------------------------------------------------------------


@pytest.mark.parametrize("key", CASES)
def test_a_fetch_seals_the_rib_as_text_and_records_what_the_base_recorded(
    key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    built = _answers(key)
    FakeSshSession(_answer_outputs(built)).install(monkeypatch)
    # the cases answer the BGP path commands in the spelling without the
    # family clause (`synthetic_vyos.old_route_spelling`)
    monkeypatch.setattr(vyos, "bgp_route_command", vyos.legacy_bgp_route_command)
    raw = make_collector(None).fetch()
    assert list(raw.items()) == list(new_raw(built).items())

    base = base_raw(built)
    base_outcomes, outcomes = base[RAW_OUTCOMES_KEY], raw[RAW_OUTCOMES_KEY]
    malformed = {name for name, entry in base_outcomes.items() if entry["status"] == "malformed"}
    for name, command in _rib_commands(raw).items():
        answer = built[command]
        value = _rib_value(raw, name)
        if isinstance(answer, Refusal):
            assert value == [] == _rib_value(base, name)
        else:
            assert value == answer, f"{name} is not the text the device printed"
    # Every command's outcome is the base fetch's, except for an answer that is not JSON.
    assert outcomes.pop("neigh")["status"] == "unsupported"
    assert raw.pop("neigh") == []
    del raw["neigh_error"]
    assert set(outcomes) == set(base_outcomes)
    for name, entry in base_outcomes.items():
        assert outcomes[name] == ({"status": "ok"} if name in malformed else entry), name
    rib_keys = {"routes", "routes6", "routes_tables", "routes6_tables"}
    notes = {f"{name}_error" for name in malformed}
    assert set(raw) == set(base) - notes
    for name, value in base.items():
        if name not in rib_keys and name not in notes and name != RAW_OUTCOMES_KEY:
            assert raw[name] == value, name


@pytest.mark.parametrize(
    ("key", "section", "command"),
    [
        ("fixture/malformed_rib", "routes6", READ_COMMANDS["routes6"]),
        ("small/malformed_rib", "routes6", READ_COMMANDS["routes6"]),
        ("fixture/malformed_table", "routes_table_100", policy_table_command("ip", 100)),
        (
            "small/malformed_table",
            f"routes_table_{POLICY_TABLES[0]}",
            policy_table_command("ip", POLICY_TABLES[0]),
        ),
    ],
)
def test_a_rib_answer_that_is_not_json_reads_malformed_once_loaded(
    key: str, section: str, command: str, tmp_path: Path
) -> None:
    built = _answers(key)
    raw = fetch(make_collector(None), built)
    assert raw[RAW_OUTCOMES_KEY][section] == {"status": "ok"}
    with pytest.raises(json.JSONDecodeError) as decoded:
        json.loads(str(built[command]))
    sections = make_collector(make_settings(tmp_path)).normalize(raw).sections
    assert sections[section] == SectionOutcome(status="malformed", detail=str(decoded.value))
    # the base record holds no `neigh` section, see `_artifacts`
    assert (
        outcomes_json({k: v for k, v in sections.items() if k != "neigh"}) == GOLDEN["cases"][key]["sections"]
    )


DEEP = "[" * 100_000 + "]" * 100_000


def _deep_sections(tmp_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    built = dict(_answers("fixture/plain"))
    built[READ_COMMANDS["routes"]] = DEEP
    base_sections = make_collector(make_settings(tmp_path)).normalize(base_raw(built)).sections
    new_sections = make_collector(make_settings(tmp_path)).normalize(new_raw(built)).sections
    # the base record holds no `neigh` section
    del new_sections["neigh"]
    return base_sections, new_sections


def test_a_deeply_nested_rib_answer_reads_as_the_base_fetch_recorded_it(tmp_path: Path) -> None:
    """Whether the decoder accepts this depth depends on the interpreter:
    CPython 3.12 raises RecursionError and 3.14 decodes it. Either way the
    load states what the base fetch recorded for the same text."""
    base_sections, new_sections = _deep_sections(tmp_path)
    assert new_sections == base_sections


def test_a_rib_answer_the_decoder_cannot_nest_reads_as_a_failed_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The base fetch's handler caught the decoder's `RecursionError` with the
    command failures, so the section read as a failed read; the load states
    the same outcome for the same text. The decoder is made to raise, so the
    case does not depend on the interpreter's nesting limit."""
    real = json.loads

    def loads(text: Any, *args: Any, **kwargs: Any) -> Any:
        if text == DEEP:
            raise RecursionError("maximum recursion depth exceeded while decoding a JSON array")
        return real(text, *args, **kwargs)

    monkeypatch.setattr(json, "loads", loads)
    base_sections, new_sections = _deep_sections(tmp_path)
    assert base_sections["routes"].status == "failed"
    assert "recursion" in (base_sections["routes"].detail or "")
    assert new_sections == base_sections


# --- one read per load, released when the load ends -----------------------------------------


def _load(collector: Any, payload: dict[str, Any]) -> Any:
    return load_payload(
        collector,
        FakeSession(),
        payload,
        collection_ts=SNAPSHOT_TS,
        run_id=RUN_ID,
        ts_ms=SNAPSHOT_TS,
        source_name=COLLECTOR_SOURCE,
    )


def _counting(monkeypatch: pytest.MonkeyPatch, name: str) -> list[Any]:
    """Replace `vyos.<name>` with a wrapper that records each call's first argument."""
    calls: list[Any] = []
    original = getattr(vyos, name)

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        calls.append(args[0] if args else None)
        return original(*args, **kwargs)

    monkeypatch.setattr(vyos, name, wrapper)
    return calls


def test_one_load_decodes_each_answer_once_and_the_writer_reads_each_path_table_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = new_raw(_answers("small/plain"))
    rib = _counting(monkeypatch, "_rib_rows")
    facts = _counting(monkeypatch, "_read_answer")
    rows = _counting(monkeypatch, "_bgp_path_rows")
    manifest_ = _load(make_collector(make_settings(tmp_path)), payload)
    assert manifest_.tables["rib"].status == "complete"

    rib_answers = 2 + 2 * len(POLICY_TABLES)
    assert len(rib) == rib_answers, "each RIB answer is decoded once per load"
    path_commands = [c for c in payload if isinstance(c, str) and " neighbors " in c]
    assert len(path_commands) == 6
    # the summary and every path table, once each: `table_outcomes` reads the
    # facts this decode stated and decodes nothing
    assert sorted(facts) == sorted([payload[BGP_SUMMARY_COMMAND], *(payload[c] for c in path_commands)])
    # the path rows are decoded again only as the writer reads them, once per table
    assert sorted(rows) == sorted(payload[c] for c in path_commands)


def test_the_read_is_released_when_a_load_returns_or_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Payload(dict[str, Any]):
        """A dict that can be weakly referenced."""

    collector = make_collector(make_settings(tmp_path))
    payload = Payload(new_raw(_answers("fixture/plain")))
    ref = weakref.ref(payload)
    manifest_ = _load(collector, payload)
    assert manifest_.tables["rib"].status == "complete"
    assert collector._payload_read is None
    del payload
    gc.collect()
    assert ref() is None, "the collector or the load kept the payload"

    def broken(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("normalize failed")

    monkeypatch.setattr(vyos, "_pbr", broken)
    failing = Payload(new_raw(_answers("fixture/plain")))
    with pytest.raises(RuntimeError, match="normalize failed"):
        _load(collector, failing)
    assert collector._payload_read is None


def test_normalize_side_tables_and_table_outcomes_share_one_read(tmp_path: Path) -> None:
    collector = make_collector(make_settings(tmp_path))
    payload = new_raw(_answers("small/plain"))
    collector.normalize(payload)
    read = collector._payload_read
    assert read is not None and read.raw is payload
    tables = collector.side_tables(payload)
    collector.table_outcomes(payload)
    assert collector._payload_read is read
    # the row views have their lengths before a row is built
    assert isinstance(tables["rib"], streams.MappedRows)
    assert isinstance(tables["bgp_session_routes"], streams.MappedRows)
    assert len(tables["bgp_session_routes"]) == 12_000
    other = new_raw(_answers("fixture/plain"))
    collector.side_tables(other)
    assert collector._payload_read is not read and collector._payload_read.raw is other
    collector.release_payload()
    assert collector._payload_read is None


# --- edges the synthetic answers do not reach ----------------------------------------------

_PATHS = {
    "10.20.0.0/24": [
        {
            "aspath": {"string": "65001 65002"},
            "origin": "IGP",
            "metric": "5",
            "locPrf": 150,
            "bestpath": True,
            "communityList": ["65000:1", "", None],
            "nexthops": [{"ip": "192.0.2.1"}, {"ip": "192.0.2.2", "used": True}],
        },
        "not a path",
        {"aspath": {}, "nexthops": [5, {"ip": "192.0.2.3"}]},
    ],
    "10.21.0.0/24": {"not": "a list"},
    "10.22.0.0/24": [{}],
}


def _edge_texts(direction: str) -> list[str]:
    table = json.dumps({_BASE_ROUTE_TABLE_KEYS[direction]: _PATHS})
    return [
        "",
        " \n\t\r",
        "\x0c",
        "\u2028",
        "% Inbound soft-reconfiguration is not configured for this neighbor\n",
        "  \r\n% first line\r\nsecond line\n",
        "%",
        "\x0b% banner\u2028more",
        table,
        "\n  " + table + "\r\n",
        "\xa0" + table,
        table + "\u2028",
        "\x0c" + table + "\n",
        "\ufeff" + table,
        table + " trailing",
        table[: len(table) // 2],
        '{"warning": "No such neighbor or address family"}',
        '{"warning": ""}',
        '{"warning": 3}',
        json.dumps({"warning": "partial table", **json.loads(table)}),
        "\xa0" + json.dumps({"warning": "behind a no-break space"}),
        "[]",
        "null",
        "42",
        '"text"',
        "{}",
        "not json at all",
    ]


@pytest.mark.parametrize("direction", list(BGP_DIRECTION_KEYWORDS))
def test_path_answers_read_as_the_base_read_them(direction: str) -> None:
    peer = "192.0.2.1"
    for text in _edge_texts(direction):
        expected_rows = _base_parse_bgp_paths(text, vrf=DEFAULT_VRF, peer_ip=peer, direction=direction)
        expected = _base_command_outcome(text, OK, len(expected_rows))
        facts, count = vyos._direction_read(
            text, vrf=DEFAULT_VRF, peer_ip=peer, direction=direction, legacy=True
        )
        assert count == len(expected_rows), repr(text)
        assert vyos._command_outcome(text, OK, count, facts=facts) == expected, repr(text)
        assert vyos._command_outcome(text, OK, count) == expected, repr(text)
        assert (
            vyos.parse_bgp_paths(text, vrf=DEFAULT_VRF, peer_ip=peer, direction=direction, legacy=True)
            == expected_rows
        )

        # the same through the observation read, the outcomes and the row view
        command = vyos.legacy_bgp_route_command(DEFAULT_VRF, peer, direction)
        raw = {
            "config": {"protocols": {"bgp": {"neighbor": {peer: {"remote-as": "65001"}}}}},
            BGP_SUMMARY_COMMAND: text,
            command: text,
            RAW_OUTCOMES_KEY: {BGP_SUMMARY_COMMAND: {"status": "ok"}, command: {"status": "ok"}},
        }
        observed = vyos.bgp_observed(raw)
        routes = vyos.bgp_side_rows(raw, "dev:x", observed=observed)["bgp_session_routes"]
        assert len(routes) == len(expected_rows)
        assert [r["prefix"] for r in routes] == [r["prefix"] for r in expected_rows]
        outcomes = vyos.bgp_table_outcomes(raw, "dev:x", capture="all", observed=observed)
        directions = manifest.bgp_direction_outcomes(outcomes)
        assert [o for (_session, d), o in directions.items() if d == direction] == [expected]
        # the summary is read the same way
        sessions = _base_parse_bgp_summary(text)
        assert observed["sessions"] == sessions
        summary = _base_command_outcome(text, OK, len(sessions))
        if summary.status in ("not-captured", "failed"):
            assert outcomes["bgp_sessions"] == summary
        else:
            assert "bgp_sessions" not in outcomes


def test_summary_answers_read_as_the_base_read_them() -> None:
    summary = json.dumps(
        {
            "default": {"ipv4Unicast": {"peers": {"192.0.2.1": {"state": "Established", "pfxRcd": 3}}}},
            "RED": {"ipv4Unicast": {"peers": {"192.0.2.9": "not a peer"}}},
            "BLUE": {"ipv6Unicast": {}},
            "GREEN": "not a vrf",
        }
    )
    for text in [
        "",
        summary,
        "\n" + summary + "\n",
        "\xa0" + summary,
        summary + "\u2028",
        "% bgpd is not running",
    ]:
        facts, sessions = vyos._summary_read(text)
        assert sessions == _base_parse_bgp_summary(text), repr(text)
        assert vyos.parse_bgp_summary(text) == sessions
        expected = _base_command_outcome(text, OK, len(sessions))
        assert vyos._command_outcome(text, OK, len(sessions), facts=facts) == expected, repr(text)


_RIB_KEYS = [
    "10.0.0.0/8",
    "0.0.0.0/0",
    "255.255.255.255/32",
    "1.2.3.4/32",
    "10.0.0.0/08",
    "10.1.0.0/8",
    "010.0.0.0/8",
    "10.0.0.0/33",
    "256.0.0.0/8",
    "10.0.0.0",
    "10.0.0.0/255.0.0.0",
    " 10.0.0.0/8",
    "10.0.0.0/8 ",
    "\u0661\u0660.0.0.0/8",
    "10.0.0.0/\u0668",
    "2001:db8::/32",
    "2001:DB8::/32",
    "2001:db8:0:0::/64",
    "::/0",
    "::ffff:10.0.0.0/104",
    "2001:db8::1/32",
    "fe80::/10",
    "not a prefix",
    "",
]


@pytest.mark.parametrize("prefix", _RIB_KEYS)
def test_rib_keys_read_as_ipaddress_reads_them(prefix: str) -> None:
    for af in (4, 6):
        try:
            net = ipaddress.ip_network(prefix)
        except ValueError:
            expected = None
        else:
            expected = str(net) if net.version == af else None
        assert vyos._rib_cidr(prefix, af) == expected, (prefix, af)


def _route(prefix: str, **fields: Any) -> dict[str, Any]:
    route: dict[str, Any] = {"prefix": prefix, "installed": True, "selected": True, "protocol": "bgp"}
    route.update(fields)
    return route


def test_rib_rows_are_the_base_rows_for_unusual_values() -> None:
    """Every value type a device's JSON can carry reaches the row as it was:
    the rows share repeated strings and integers, never a value of another
    type that compares equal (True, 1 and 1.0)."""
    hop = {"fib": True, "ip": "192.0.2.1", "interfaceName": "eth0"}
    default = {
        "10.0.0.0/24": [_route("10.0.0.0/24", table=254, metric=1, nexthops=[hop])],
        "10.0.1.0/24": [_route("10.0.1.0/24", table=254, metric=True, nexthops=[hop])],
        "10.0.2.0/24": [_route("10.0.2.0/24", table=254, metric=1.0, nexthops=[hop])],
        "10.0.3.0/24": [_route("10.0.3.0/24", table="254", metric="1", nexthops=[{**hop, "ip": 1}])],
        "10.0.4.0/24": [
            _route("10.0.4.0/24", protocol=7, table=0, nexthops=[{"active": True, "ip": "192.0.2.9"}])
        ],
        "10.0.5.0/24": [_route("10.0.5.0/24", nexthops=[{"fib": False, "active": False, "ip": "192.0.2.9"}])],
        "10.0.6.0/24": [_route("10.0.6.0/24", protocol=None, table=253, nexthops=[hop])],
        "10.0.7.0/24": [_route("10.0.7.0/24", protocol=7, table="default", nexthops=[hop])],
        "10.0.8.0/24": [
            _route("10.0.8.0/24", table=100, nexthops=[{"fib": True}, {"fib": True, "vrf": "RED"}])
        ],
        "10.0.9.0/24": [_route("10.0.9.0/24", installed=True, selected=False, nexthops=[hop])],
        "10.0.10.0/24": [_route("10.0.10.0/24", protocol="local", nexthops=[hop])],
        "10.0.11.0/24": [],
        "10.0.12.0/24": None,
        "10.0.13.5/24": [_route("10.0.13.5/24", nexthops=[hop])],
        "10.0.0.0/08": [_route("10.0.0.0/08", metric=[1], nexthops=[{**hop, "interfaceName": ["eth0"]}])],
        "2001:db8::/32": [_route("2001:db8::/32", nexthops=[hop])],
    }
    raw = {
        "routes": {
            "default": default,
            "RED": [],
            "BLUE": {"10.9.0.0/16": [_route("10.9.0.0/16", nexthops=[hop])]},
        },
        "routes6": {"default": {"2001:DB8:1::/48": [_route("2001:DB8:1::/48", table=254, nexthops=[hop])]}},
        "routes_tables": {
            "100": {"10.100.0.0/24": [_route("10.100.0.0/24", table=100, nexthops=[hop])]},
            "200": [],
        },
        "routes6_tables": {"100": {}},
    }
    expected = [row for row in _base_rib_entries(raw) if row["table"] not in ("default", "253")]
    for payload in (raw, {**raw, "routes": json.dumps(raw["routes"]), "routes6": json.dumps(raw["routes6"])}):
        read = vyos._read_rib(payload)
        got = [
            {
                "table": e.table,
                "cidr": e.cidr,
                "af": e.af,
                "next_hop": e.next_hop,
                "interface": e.interface,
                "next_hop_vrf": e.next_hop_vrf,
                "protocol": e.protocol,
                "metric": e.metric,
                "discard": e.discard,
            }
            for e in read.entries
        ]
        # JSON tells True from 1 and 1.0, which list equality does not
        assert json.dumps(got) == json.dumps(expected)
        counts: dict[str, int] = {}
        for row in expected:
            counts[row["table"]] = counts.get(row["table"], 0) + 1
        assert read.table_rows == counts
        assert list(read.table_rows) == list(counts)


def test_a_rib_answer_that_is_not_json_reads_as_no_rows_under_its_outcome_key() -> None:
    raw = {
        "routes": '{"default": {',
        "routes6": "{}",
        "routes_tables": {"100": "{}", "0200": "not json"},
        "routes6_tables": {"100": []},
        RAW_OUTCOMES_KEY: {"routes": {"status": "ok"}, "routes_table_200": {"status": "ok"}},
    }
    read = vyos._read_rib(raw)
    assert read.entries == []
    assert set(read.failures) == {"routes", "routes_table_200"}
    sections = vyos.section_outcomes(raw, read)
    assert sections["routes"].status == "malformed"
    # the table's own section names its config key; the outcome the fetch
    # keyed by the table number carries the verdict, as it did at the base
    assert sections["routes_table_0200"].status == "unknown"
    assert sections["routes_table_200"].status == "malformed"


def test_a_rib_answer_the_decoder_rejects_for_any_value_error_costs_only_its_section():
    """An integer past the interpreter's digit limit raises a plain ValueError."""
    huge = '{"10.0.0.0/8": [{"prefix": "10.0.0.0/8", "metric": ' + "1" * 5000 + "}]}"
    tree, outcome = vyos._rib_answer(huge)
    assert tree == []
    assert outcome is not None and outcome.status == "malformed"
    assert "digit" in (outcome.detail or "")

    tree, outcome = vyos._rib_answer("{not json")
    assert tree == []
    assert outcome == SectionOutcome(status="malformed", detail=_decode_error("{not json"))


def _decode_error(text: str) -> str:
    try:
        json.loads(text)
    except json.JSONDecodeError as exc:
        return str(exc)
    raise AssertionError("the text decoded")
