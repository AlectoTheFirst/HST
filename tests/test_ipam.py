"""core/ipam.py: the IPAdmin register import and the run step that applies it."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from hst.app.crypto import SecretKeyError
from hst.core import ipam, rawstore
from hst.core.config import Settings

EXPORT = """# IPAdmin networklist Thu Oct  1 15:02:40 2026 (1790866960)
address,description,location,vlan
0.0.0.0/0,"All IPv4 addresses",,
10.0.0.0/8,"Corporate",,
10.1.0.0/16,,,
10.1.2.0/24,"Office LAN","FRA,Floor 2",120
10.1.3.0/24,,,
2001:db8::/32,"Doc v6",,<VLAN>
"""


def _settings() -> Settings:
    return Settings(hst_secret_key="ipam-test-key-that-is-long-enough-32b")


def test_parse_reads_the_columns_and_drops_a_vlan_that_is_not_a_number():
    entries = {str(e.network): e for e in ipam.parse(EXPORT)}
    assert len(entries) == 6
    lan = entries["10.1.2.0/24"]
    assert (lan.description, lan.location, lan.vlan) == ("Office LAN", "FRA,Floor 2", 120)
    assert entries["2001:db8::/32"].vlan is None


def test_parse_refuses_a_bad_address_and_a_repeated_one():
    with pytest.raises(ValueError, match="bad address"):
        ipam.parse("address,description,location,vlan\n10.1.2.1/24,,,\n")
    with pytest.raises(ValueError, match="twice"):
        ipam.parse("address,description,location,vlan\n10.0.0.0/8,,,\n10.0.0.0/8,,,\n")
    with pytest.raises(ValueError, match="no column"):
        ipam.parse("address,description\n10.0.0.0/8,x\n")


def test_match_is_exact_first_then_the_most_specific_informative_parent():
    found = ipam.match(
        ["10.1.2.0/24", "10.1.3.0/24", "10.1.2.128/25", "10.1.9.0/24", "192.168.0.0/24", "2001:db8:1::/48"],
        ipam.parse(EXPORT),
    )
    summary = {cidr: (str(e.network), kind) for cidr, (e, kind) in found.items()}
    assert summary == {
        # an exact entry stands even when it says nothing
        "10.1.3.0/24": ("10.1.3.0/24", "exact"),
        "10.1.2.0/24": ("10.1.2.0/24", "exact"),
        "10.1.2.128/25": ("10.1.2.0/24", "covering"),
        # 10.1.0.0/16 is empty, so the /8 answers
        "10.1.9.0/24": ("10.0.0.0/8", "covering"),
        "2001:db8:1::/48": ("2001:db8::/32", "covering"),
    }
    # 0.0.0.0/0 is never a covering match
    assert "192.168.0.0/24" not in found


def test_import_seals_the_export_and_a_run_takes_the_newest_one_before_its_time(tmp_path: Path):
    settings = _settings()
    raw, count = ipam.import_export(settings, tmp_path / "export.csv", EXPORT)
    assert count == 6
    assert raw.parent == settings.raw_dir / ipam.SOURCE
    # host-less, so never a parked device payload
    assert rawstore.parked(settings.raw_dir) == []
    fetch_ts = int(raw.name.split("-")[0])
    assert ipam.import_for(settings.raw_dir, fetch_ts) == raw
    assert ipam.import_for(settings.raw_dir, fetch_ts - 1) is None


class _Result:
    def __init__(self, rows: list[dict[str, Any]]):
        self._rows = rows

    def data(self) -> list[dict[str, Any]]:
        return self._rows

    def consume(self) -> None:
        return None


class _Session:
    def __init__(self, prefixes: list[dict[str, Any]]):
        self.prefixes = prefixes
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def run(self, query: str, **params: Any) -> _Result:
        self.calls.append((query, params))
        if query is ipam.FETCH_PREFIXES:
            return _Result(self.prefixes)
        if query is ipam.WRITE:
            return _Result([{"n": len(params["rows"])}])
        return _Result([])


def test_annotate_clears_the_run_then_writes_the_matches(tmp_path: Path):
    settings = _settings()
    raw, _ = ipam.import_export(settings, tmp_path / "export.csv", EXPORT)
    session = _Session(
        [
            {"uid": "pfx:vrf-a:10.1.2.0/24", "cidr": "10.1.2.0/24"},
            {"uid": "pfx:vrf-b:10.1.2.0/24", "cidr": "10.1.2.0/24"},
            {"uid": "pfx:vrf-a:10.1.9.0/24", "cidr": "10.1.9.0/24"},
            {"uid": "pfx:vrf-a:192.168.0.0/24", "cidr": "192.168.0.0/24"},
        ]
    )
    report = ipam.annotate(session, settings, collection_ts=42)
    assert report is not None
    assert (report["prefixes"], report["exact"], report["covering"], report["written"]) == (4, 2, 1, 3)
    queries = [q for q, _ in session.calls]
    assert queries == [ipam.FETCH_PREFIXES, ipam.CLEAR, ipam.WRITE]
    rows = {r["uid"]: r["props"] for r in session.calls[2][1]["rows"]}
    assert rows["pfx:vrf-b:10.1.2.0/24"] == {
        "ipam_cidr": "10.1.2.0/24",
        "ipam_match": "exact",
        "ipam_import": raw.name[: -len(rawstore.SUFFIX)],
        "ipam_description": "Office LAN",
        "ipam_location": "FRA,Floor 2",
        "ipam_vlan": 120,
    }
    assert rows["pfx:vrf-a:10.1.9.0/24"]["ipam_match"] == "covering"
    assert all(k in ipam.PROPS for props in rows.values() for k in props)


def test_annotate_does_nothing_without_an_import():
    session = _Session([])
    assert ipam.annotate(session, _settings(), collection_ts=42) is None
    assert session.calls == []


def test_parse_reads_a_byte_order_mark_and_a_header_in_any_case():
    text = "﻿Address, Description ,Location,VLAN\n10.1.2.0/24,Office,FRA,120\n"
    [entry] = ipam.parse(text)
    assert (str(entry.network), entry.description, entry.vlan) == ("10.1.2.0/24", "Office", 120)


def test_parse_skips_rows_with_no_value():
    text = "address,description,location,vlan\n10.1.2.0/24,a,b,1\n,,,\n , , , \n"
    assert [str(e.network) for e in ipam.parse(text)] == ["10.1.2.0/24"]


def test_parse_keeps_a_quoted_line_that_starts_with_a_hash():
    text = 'address,description,location,vlan\n10.1.2.0/24,"first\n#second",FRA,1\n10.1.3.0/24,next,FRA,2\n'
    entries = ipam.parse(text)
    assert [str(e.network) for e in entries] == ["10.1.2.0/24", "10.1.3.0/24"]
    assert entries[0].description == "first\n#second"


def test_parse_skips_a_comment_row_after_the_header():
    text = "address,description,location,vlan\n# a comment row\n10.1.2.0/24,a,b,1\n"
    assert [str(e.network) for e in ipam.parse(text)] == ["10.1.2.0/24"]


def test_parse_errors_name_the_physical_line():
    text = (
        "# exported\n# by IPAdmin\naddress,description,location,vlan\n"
        "10.1.2.0/24,a,b,1\nnot-an-address,a,b,1\n"
    )
    with pytest.raises(ValueError, match="line 5: bad address 'not-an-address'"):
        ipam.parse(text)


def _other_key(settings):
    return settings.model_copy(update={"hst_secret_key": "another-ipam-test-key-of-32-bytes-or-more!!"})


def test_annotate_clears_the_run_when_the_import_cannot_be_read(tmp_path: Path):
    settings = _settings()
    ipam.import_export(settings, tmp_path / "export.csv", EXPORT)
    session = _Session([])
    with pytest.raises(SecretKeyError):
        ipam.annotate(session, _other_key(settings), collection_ts=42)
    assert [(q, p.get("cts")) for q, p in session.calls] == [(ipam.CLEAR, 42)]


def test_annotate_clears_the_run_when_the_import_does_not_parse(tmp_path: Path, monkeypatch):
    settings = _settings()
    ipam.import_export(settings, tmp_path / "export.csv", EXPORT)

    def refuse(text: str):
        raise ValueError("line 2: bad address")

    monkeypatch.setattr(ipam, "parse", refuse)
    session = _Session([])
    with pytest.raises(ValueError):
        ipam.annotate(session, settings, collection_ts=42)
    assert [q for q, _ in session.calls] == [ipam.CLEAR]


def test_annotate_clears_the_run_again_when_a_write_fails(tmp_path: Path):
    settings = _settings()
    ipam.import_export(settings, tmp_path / "export.csv", EXPORT)

    class _Failing(_Session):
        def run(self, query: str, **params: Any) -> _Result:
            if query is ipam.WRITE:
                self.calls.append((query, params))
                raise RuntimeError("write failed")
            return super().run(query, **params)

    session = _Failing([{"uid": "pfx:vrf-a:10.1.2.0/24", "cidr": "10.1.2.0/24"}])
    with pytest.raises(RuntimeError):
        ipam.annotate(session, settings, collection_ts=42)
    assert [q for q, _ in session.calls] == [ipam.FETCH_PREFIXES, ipam.CLEAR, ipam.WRITE, ipam.CLEAR]


def _finalize(session: Any, settings: Any) -> list[str]:
    from hst.core import finalize
    from hst.core.model import RunManifest

    class _RouteTargets:
        def execute(self, session: Any, settings: Any, collection_ts: int | None = None) -> RunManifest:
            return RunManifest(run_id="rt-i", source="reasoner", scope="rt-imports")

        def execute_rt_domains(
            self, session: Any, settings: Any, collection_ts: int | None = None
        ) -> RunManifest:
            return RunManifest(run_id="rt-d", source="reasoner", scope="rt-domains")

        def execute_link_speed(
            self, session: Any, settings: Any, collection_ts: int | None = None
        ) -> RunManifest:
            return RunManifest(run_id="ls", source="reasoner", scope="link-speed")

    class _Rules:
        def run(self, session: Any, collection_ts: int | None = None) -> list[dict]:
            return []

    class _Cycle:
        def apply_site_assignments(self, session: Any, assigned: Any, cts: int | None = None) -> int:
            return 0

    return finalize.finalize_derivations(
        session, settings, 42, {}, rules=_Rules(), route_targets=_RouteTargets(), cycle=_Cycle()
    )


def test_finalize_records_the_ipam_line(tmp_path: Path):
    settings = _settings()
    ipam.import_export(settings, tmp_path / "export.csv", EXPORT)
    session = _Session([{"uid": "pfx:vrf-a:10.1.2.0/24", "cidr": "10.1.2.0/24"}])
    details = _finalize(session, settings)
    assert any(line.startswith("ipam: 1 of 1 prefix(es) annotated") for line in details), details


def test_finalize_keeps_the_run_when_the_register_cannot_be_read(tmp_path: Path):
    settings = _settings()
    ipam.import_export(settings, tmp_path / "export.csv", EXPORT)
    session = _Session([])
    details = _finalize(session, _other_key(settings))
    assert any(line.startswith("ipam: not applied (") for line in details), details
    assert [q for q, _ in session.calls] == [ipam.CLEAR]
