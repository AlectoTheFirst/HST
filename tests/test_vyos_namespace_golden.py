"""The golden overlay of the VyOS uid namespace change."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from tests.support.synthetic_payloads import make_settings
from tests.support.synthetic_vyos import (
    CASES,
    GOLDEN_PATH,
    LOCAL_UID_PREFIXES,
    NAMESPACE_GOLDEN_PATH,
    answers,
    base_shape,
    batch_digest,
    defaults_free,
    hostname_keyed,
    iface_uid_version_1,
    installation_free,
    link_local_free,
    load_golden,
    make_collector,
    new_raw,
    session_settings_free,
)

from hst.collectors.vyos import local_namespace
from hst.core.model import Batch, NodeRecord, RelRecord


def _overlay() -> dict[str, Any]:
    document: dict[str, Any] = json.loads(NAMESPACE_GOLDEN_PATH.read_text(encoding="utf-8"))
    return document


def _overlay_cases() -> dict[str, Any]:
    cases: dict[str, Any] = _overlay()["cases"]
    return cases


def _batch(hostname: str) -> Batch:
    device = NodeRecord(label="Device", uid="dev:serial1", props={"hostname": hostname})
    rulebase = NodeRecord(
        label="FwRulebase",
        uid="vyos:serial1:fw:LAN-WAN",
        props={"zones": ["vyos:serial1:zone:LAN", "vyos:serial1:zone:WAN"], "name": "vyos:serial1:fw:x"},
    )
    wan = NodeRecord(label="WanLink", uid="wan:serial1:eth0", props={"name": "eth0"})
    interface = NodeRecord(label="Interface", uid="dev:serial1/if/eth0", props={"name": "eth0"})
    other = NodeRecord(label="NetObject", uid="vyos:other:grp:net:RFC1918", props={})
    rels = [
        RelRecord.model_validate(
            {
                "type": "HAS_LINK",
                "start_label": "Device",
                "start_uid": device.uid,
                "end_label": "WanLink",
                "end_uid": wan.uid,
            }
        ),
        RelRecord.model_validate(
            {
                "type": "APPLIES_TO",
                "start_label": "FwRulebase",
                "start_uid": rulebase.uid,
                "end_label": "Interface",
                "end_uid": interface.uid,
                "key": {"zone": "vyos:serial1:zone:LAN"},
                "props": {"from": "wan:serial1:eth0", "note": "keeps vyos:serial1: inside"},
            }
        ),
    ]
    return Batch.model_construct(
        source="vyos",
        scope=f"vyos:{hostname}",
        nodes=[device, rulebase, wan, interface, other],
        rels=rels,
        sections={},
        warnings=[],
    )


def test_the_mapping_moves_only_the_namespaced_prefixes() -> None:
    batch = _batch("gw")
    keyed = hostname_keyed(batch)
    assert [n.uid for n in keyed.nodes] == [
        "dev:serial1",
        "vyos:gw:fw:LAN-WAN",
        "wan:gw:eth0",
        "dev:serial1/if/eth0",
        "vyos:other:grp:net:RFC1918",
    ]
    assert keyed.nodes[1].props == {"zones": ["vyos:gw:zone:LAN", "vyos:gw:zone:WAN"], "name": "vyos:gw:fw:x"}
    assert [(r.start_uid, r.end_uid) for r in keyed.rels] == [
        ("dev:serial1", "wan:gw:eth0"),
        ("vyos:gw:fw:LAN-WAN", "dev:serial1/if/eth0"),
    ]
    assert keyed.rels[1].key == {"zone": "vyos:gw:zone:LAN"}
    # only a leading prefix moves
    assert keyed.rels[1].props == {"from": "wan:gw:eth0", "note": "keeps vyos:serial1: inside"}
    assert (keyed.source, keyed.scope) == (batch.source, batch.scope)
    assert batch.nodes[1].uid == "vyos:serial1:fw:LAN-WAN"
    assert batch.rels[1].key == {"zone": "vyos:serial1:zone:LAN"}
    # a router whose namespace is its hostname is keyed as the base keyed it
    same = _batch("serial1")
    assert hostname_keyed(same) is same


def test_the_overlay_records_the_normalize_field() -> None:
    overlay = _overlay()
    assert overlay["fields"] == ["normalize"]
    assert _overlay_cases()
    assert set(_overlay_cases()) <= set(CASES)
    assert all(set(fields) == {"normalize"} for fields in _overlay_cases().values())


def test_without_the_overlay_the_golden_is_the_base_file() -> None:
    assert load_golden(namespace=False, iface_uid=False) == json.loads(
        GOLDEN_PATH.read_text(encoding="utf-8")
    )
    laid = load_golden(iface_uid=False)
    base = load_golden(namespace=False, iface_uid=False)
    for key in CASES:
        expected = {**base["cases"][key], **_overlay_cases().get(key, {})}
        assert laid["cases"][key] == expected, key


@pytest.mark.parametrize("key", CASES)
def test_an_overlay_digest_is_the_base_one_once_the_uids_are_keyed_by_the_hostname(
    key: str, tmp_path: Path
) -> None:
    """Every case keyed by the hostname gives the base digest. A case is in
    the overlay exactly when that keying moves a uid, and then the overlay
    digest is that of the load as it is."""
    # without the installation evidence of the rulesets, the
    # BgpSession settings, and the IPv6 link-local
    # addresses of an interface
    with iface_uid_version_1():
        batch = link_local_free(
            session_settings_free(
                defaults_free(
                    installation_free(
                        make_collector(make_settings(tmp_path)).normalize(new_raw(answers(key)))
                    )
                )
            )
        )
    keyed = hostname_keyed(batch)
    base = load_golden(namespace=False, iface_uid=False)["cases"][key]["normalize"]
    assert batch_digest(base_shape(keyed)) == base
    assert (keyed != batch) == (key in _overlay_cases())
    if key not in _overlay_cases():
        return
    assert batch_digest(base_shape(batch)) == _overlay_cases()[key]["normalize"]
    [device] = [n for n in batch.nodes if n.label == "Device"]
    namespace, host = local_namespace(device.uid), device.props["hostname"]
    assert namespace != host
    moved = [f"{prefix}:{namespace}:" for prefix in LOCAL_UID_PREFIXES]
    kept = [f"{prefix}:{host}:" for prefix in LOCAL_UID_PREFIXES]
    # the load writes these uids under the namespace only, and the keying
    # moves every one of them without folding two into one
    assert any(n.uid.startswith(tuple(moved)) for n in batch.nodes)
    assert not any(n.uid.startswith(tuple(kept)) for n in batch.nodes)
    assert not any(n.uid.startswith(tuple(moved)) for n in keyed.nodes)
    assert len({n.uid for n in keyed.nodes}) == len({n.uid for n in batch.nodes})
