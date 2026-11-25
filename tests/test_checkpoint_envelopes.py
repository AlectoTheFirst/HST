"""The Check Point API envelopes are side-store rows, not node
properties (analysis_model/checkpoint_envelopes.py)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from tests.test_checkpoint import _cfg
from tests.test_checkpoint_policy_facts import _estate

from hst.analysis_model import checkpoint_envelopes
from hst.analysis_model.read import MaterializedTable
from hst.collectors.checkpoint import ENVELOPE_TABLE, CpCollector, normalize_checkpoint
from hst.core import Settings

ENVELOPED = {"CpPolicyObject", "NetObject", "SvcObject", "CpPolicyPackage", "FwRulebase", "FwRule"}


def _normalized():
    rows: list[dict[str, str]] = []
    batch = normalize_checkpoint(_estate(), mgmt="manager", domain="domain", envelope_rows=rows)
    return batch, rows


def test_no_node_carries_its_envelope_and_each_carries_the_digest_of_its_row():
    batch, rows = _normalized()
    assert not any("checkpoint_envelope" in node.props for node in batch.nodes)
    digests = {
        node.uid: node.props["checkpoint_envelope_sha"]
        for node in batch.nodes
        if node.props.get("checkpoint_envelope_sha") is not None
    }
    by_uid = {row["uid"]: row for row in rows}
    assert len(by_uid) == len(rows)
    assert set(by_uid) == set(digests)
    labels = {row["label"] for row in rows}
    assert labels == ENVELOPED
    for uid, row in by_uid.items():
        assert row["envelope_sha"] == digests[uid] == hashlib.sha256(row["envelope"].encode()).hexdigest()
    rule = next(
        row for row in rows if row["label"] == "FwRule" and json.loads(row["envelope"])["uid"] == "r1"
    )
    assert json.loads(rule["envelope"])["install-on"] == ["gw-a"]


def test_the_collector_declares_the_table_and_hands_the_rows_of_the_payload_it_normalized():
    collector = CpCollector(_cfg(), Settings(_env_file=None))
    raw = _estate()
    assert ENVELOPE_TABLE in collector.SIDE_TABLES
    batch = collector.normalize(raw)
    rows = collector.side_tables(raw)[ENVELOPE_TABLE]
    digests = {
        n.uid: n.props["checkpoint_envelope_sha"] for n in batch.nodes if "checkpoint_envelope_sha" in n.props
    }
    assert {row["uid"]: row["envelope_sha"] for row in rows} == digests
    collector.release_payload()
    assert collector.side_tables(raw)[ENVELOPE_TABLE] == rows


# --- the read back ---------------------------------------------------------------------


def _nodes(rows: list[dict[str, str]], **extra_props) -> MaterializedTable:
    table_rows = tuple(
        {
            "id": row["uid"],
            "labels": [row["label"]],
            "props": {"uid": row["uid"], "checkpoint_envelope_sha": row["envelope_sha"], **extra_props},
        }
        for row in rows
    )
    return MaterializedTable("a" * 64, "nodes", table_rows, len(table_rows), True, "f" * 64)


def _snapshot(tmp_path: Path, monkeypatch, rows: list[dict[str, str]]):
    pytest.importorskip("pyarrow")
    pytest.importorskip("duckdb")
    from hst.core import sidestore

    base = tmp_path / "sidestore"
    path = sidestore.write_table(base, ENVELOPE_TABLE, "cp", "", "1700000000000-aaaaaaaa", rows, 7)
    assert path is not None
    # the files the pinned manifest selects for the table
    monkeypatch.setattr(
        "hst.core.ribsource.snapshot_evidence",
        lambda settings, cts, *, manifest=None, table="rib": SimpleNamespace(
            files=[path] if table == ENVELOPE_TABLE else []
        ),
    )
    return SimpleNamespace(cts=7, manifest=object(), settings=SimpleNamespace(sidestore_dir=base))


def test_a_load_puts_every_envelope_back_on_its_node(tmp_path, monkeypatch):
    _batch, rows = _normalized()
    snapshot = _snapshot(tmp_path, monkeypatch, rows)
    hydrated = checkpoint_envelopes.hydrate(_nodes(rows), snapshot)
    envelopes = {row["id"]: row["props"]["checkpoint_envelope"] for row in hydrated.rows}
    assert envelopes == {row["uid"]: row["envelope"] for row in rows}


def test_an_envelope_that_does_not_match_its_digest_puts_none_back(tmp_path, monkeypatch, caplog):
    """A layer or package without its envelope leaves the strict policy
    unqualified, which fails closed."""
    _batch, rows = _normalized()
    tampered = [dict(row) for row in rows]
    tampered[0]["envelope"] = tampered[0]["envelope"].replace("}", ',"x":1}', 1)
    snapshot = _snapshot(tmp_path, monkeypatch, tampered)
    with caplog.at_level("WARNING", logger="hst.analysis_model.checkpoint_envelopes"):
        hydrated = checkpoint_envelopes.hydrate(_nodes(rows), snapshot)
    assert not any("checkpoint_envelope" in row["props"] for row in hydrated.rows)
    assert any("not in the side store" in record.getMessage() for record in caplog.records)


def test_a_node_that_holds_its_envelope_is_left_as_it_is():
    """A run without the table, or a fixture, holds the envelope on the node
    and reads no side store."""
    nodes = _nodes([{"uid": "n", "label": "FwRule", "envelope_sha": "0" * 64}], checkpoint_envelope="{}")
    assert checkpoint_envelopes.hydrate(nodes, SimpleNamespace(manifest=None)) is nodes
