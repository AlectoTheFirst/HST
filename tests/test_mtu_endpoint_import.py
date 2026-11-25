"""Explicit subject import: no guessed endpoint, no implicit authority elevation."""

import json
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from hst.app.sources import validate_source
from hst.collectors.manual import ManualCollector, ManualConfig
from hst.collectors.mtu_import import parse_mtu_import, validate_import_subjects
from hst.core import cycle, db
from hst.core.config import Settings
from hst.core.mtu import MtuContext, MtuObservation
from hst.core.mtu_read import resolve_constraints


def document(**extra):
    row = {
        "subject_label": "Interface",
        "subject_uid": "dev:synthetic/if/eth0",
        "source": "operator:host-report",
        "evidence_ref": "synthetic hand-written evidence",
        "observed_at_ms": 100,
        "raw_value": 1500,
        "basis": "ip_packet",
        "metric": "ipv4_mtu_bytes",
        "direction": "tx",
        "bound_kind": "ceiling",
    }
    row.update(extra)
    return json.dumps({"version": 1, "observations": [row]})


class Session:
    def __init__(self, rows):
        self.rows, self.calls = rows, []

    def execute_read(self, work):
        return work(self)

    def run(self, query, **params):
        self.calls.append((query, params))
        return SimpleNamespace(data=lambda: self.rows)


def test_intent_default_never_overrides_actual():
    imported = parse_mtu_import(document())
    obs = imported.observations[0].observation("synthetic-import")
    assert obs.assertion_kind == "intent"
    assert obs.observed_at_ms == 100
    assert json.loads(obs.selector_json)["evidence_origin"] == "operator_import"
    result = resolve_constraints([obs], MtuContext(af=4))
    assert not result.constraints
    assert result.intent[0].value_bytes == 1500


def test_operator_observation_preserves_explicit_authority_and_receive_bound():
    obs = (
        parse_mtu_import(
            document(authority="operational", direction="rx", bound_kind="acceptance_lower_bound")
        )
        .observations[0]
        .observation("fixture")
    )
    assert obs.assertion_kind == "operational"
    assert obs.bound_kind == "acceptance_lower_bound"
    assert json.loads(obs.selector_json)["source_verified"] is False


@pytest.mark.parametrize(
    "change",
    [
        {"subject_uid": "a-hostname"},
        {"subject_uid": "dev:with space"},
        {"raw_value": True},
        {"raw_value": "inherit"},
        {"basis": "unknown"},
        {"observed_at_ms": None},
        {"basis": "ethernet_payload", "metric": "l2_max_frame_bytes"},
        {"evidence_ref": ""},
    ],
)
def test_ambiguous_or_unconvertible_import_rejected(change):
    with pytest.raises((ValidationError, ValueError)):
        parse_mtu_import(document(**change))


def test_bounds_and_duplicates():
    with pytest.raises(ValueError, match="1 MiB"):
        parse_mtu_import(" " * (1024 * 1024 + 1))
    doc = json.loads(document())
    doc["observations"] *= 513
    with pytest.raises(ValidationError):
        parse_mtu_import(json.dumps(doc))
    doc["observations"] = doc["observations"][:2]
    with pytest.raises(ValidationError, match="duplicate"):
        parse_mtu_import(json.dumps(doc))
    doc["observations"][1] = {**doc["observations"][1], "subject_label": "Endpoint"}
    with pytest.raises(ValidationError, match="ambiguous subject label"):
        parse_mtu_import(json.dumps(doc))


def test_subject_preflight_is_snapshot_pinned_and_refuses_missing_or_ambiguous():
    imported = parse_mtu_import(document())
    found = {"uid": "dev:synthetic/if/eth0", "label": "Interface"}
    session = Session([found])
    assert validate_import_subjects(session, imported, 42) == [found]
    assert session.calls[0][1]["snap"] == 42
    assert "n:Obj {uid: subject.uid, collection_ts: $snap}" in session.calls[0][0]
    for rows, snap in (([], 42), ([found, found], 42), ([found], None)):
        with pytest.raises(ValueError):
            validate_import_subjects(Session(rows), imported, snap)


def test_manual_probe_fetch_validates_and_normalizer_emits_only_metadata(monkeypatch):
    found = {"uid": "dev:synthetic/if/eth0", "label": "Interface"}
    fake = Session([found])

    @contextmanager
    def session(settings):
        yield fake

    monkeypatch.setattr(db, "session", session)
    monkeypatch.setattr(cycle, "current_ts", lambda session: 42)
    coll = ManualCollector(
        ManualConfig(devices="", source_name="synthetic-import", mtu_evidence=document()),
        Settings(_env_file=None),
    )
    assert "1 MTU subject(s) resolved" in coll.probe()
    raw = coll.fetch()
    batch = coll.normalize(raw)
    assert {n.label for n in batch.nodes} == {"MtuObservation"}
    assert {r.rel_type for r in batch.rels} == {"HAS_MTU"}
    assert batch.sections["mtu:import"].status == "ok"
    assert raw["mtu_subject_snapshot"] == 42
    obs = MtuObservation(uid=batch.nodes[0].uid, **batch.nodes[0].props)
    assert obs.observed_at_ms == 100
    batch.validate_registry()
    raw.pop("mtu_subjects")
    with pytest.raises(ValueError, match="preflight"):
        coll.normalize(raw)


def test_source_validation_exposes_import_field_and_checks_it_without_graph_reads():
    cfg, secrets = validate_source("manual", {"devices": "", "mtu_evidence": document()})
    assert cfg["mtu_evidence"] == document()
    assert secrets == {}
    with pytest.raises(ValidationError):
        validate_source("manual", {"devices": "", "mtu_evidence": document(raw_value="inherit")})
