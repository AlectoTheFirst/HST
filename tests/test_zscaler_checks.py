"""The zscaler check: sites that only ZIA names, and Zscaler scopes that two
sources write. Reads are scripted through a fake session."""

from __future__ import annotations

from typing import Any

from hst import reasoner


class _Tx:
    def __init__(self, sites: list[dict[str, Any]], shared: list[dict[str, Any]]) -> None:
        self.rows = {reasoner.FETCH_ZIA_ONLY_SITES: sites, reasoner.FETCH_SHARED_ZSCALER_SCOPES: shared}

    def run(self, query: str, **params: Any) -> Any:
        rows = self.rows[query]

        class _Result:
            def data(self) -> list[dict[str, Any]]:
                return rows

        return _Result()


class _Session:
    def __init__(self, sites: list[dict[str, Any]], shared: list[dict[str, Any]] | None = None) -> None:
        self.tx = _Tx(sites, shared or [])

    def execute_read(self, fn: Any) -> Any:
        return fn(self.tx)


def test_a_site_only_zia_names_is_a_warning():
    report = reasoner.check_zscaler(
        _Session([{"site": "vie01", "locations": ["Wien", "Wien-Guest"]}]), collection_ts=1
    )
    assert report["warnings"] == [
        "ZIA site vie01: only ZIA locations name it (Wien, Wien-Guest); "
        "no device or port is located in it in this run"
    ]


def test_two_sources_on_one_scope_is_a_warning():
    report = reasoner.check_zscaler(_Session([], [{"scope": "zia:acme", "loads": 2}]), collection_ts=1)
    assert report["warnings"] == [
        "2 sources write scope zia:acme in this run; objects with the same Zscaler id share one node"
    ]


def test_more_than_twenty_sites_end_with_one_count_line():
    sites = [{"site": f"s{i:02d}", "locations": [f"L{i}"]} for i in range(23)]
    report = reasoner.check_zscaler(_Session(sites), collection_ts=1)
    assert len(report["warnings"]) == 21
    assert report["warnings"][-1] == "3 more ZIA site(s) that only ZIA locations name"


def test_nothing_to_report_adds_no_warning():
    assert reasoner.check_zscaler(_Session([]), collection_ts=1)["warnings"] == []


def test_finalize_appends_the_zscaler_lines_after_the_site_assignments():
    from hst.core import finalize
    from hst.core.config import Settings
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

    class _Cycle:
        def apply_site_assignments(self, session: Any, assigned: Any, cts: int | None = None) -> int:
            return 0

    class _Rules:
        def __init__(self, warnings: list[str]) -> None:
            self.warnings = warnings

        def run(self, session: Any, collection_ts: int | None = None) -> list[dict]:
            return []

        def check_zscaler(self, session: Any, *, collection_ts: int) -> dict[str, Any]:
            return {"sites": [], "shared_scopes": [], "warnings": self.warnings}

    settings = Settings(_env_file=None, hst_secret_key="finalize-zscaler-wiring-test-key-32-bytes!!")
    findings = finalize.RunFindings()
    details = finalize.finalize_derivations(
        object(),
        settings,
        4242,
        {},
        rules=_Rules(["w1"]),
        route_targets=_RouteTargets(),
        cycle=_Cycle(),
        findings=findings,
    )
    assert details[-2:] == ["zscaler: 1 warning(s)", "warning: w1"]
    assert findings.warnings == ["w1"]
    quiet = finalize.finalize_derivations(
        object(), settings, 4242, {}, rules=_Rules([]), route_targets=_RouteTargets(), cycle=_Cycle()
    )
    assert not [line for line in quiet if line.startswith("zscaler")]
