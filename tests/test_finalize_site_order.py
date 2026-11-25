from __future__ import annotations

from typing import Any

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


def test_site_assignments_are_applied_before_the_vlan_stretch_check_reads_them() -> None:
    calls: list[str] = []

    class _Cycle:
        def apply_site_assignments(self, session: Any, assigned: Any, cts: int | None = None) -> int:
            calls.append("apply")
            return 0

        def carry_site_assignments(
            self, session: Any, assigned: Any, cts: int | None = None, parent: int | None = None
        ) -> int:
            calls.append("carry")
            return 0

    class _Rules:
        def run(self, session: Any, collection_ts: int | None = None) -> list[dict]:
            return []

        def check_vlan_stretch(
            self, session: Any, *, collection_ts: int, sidestore_dir: Any
        ) -> dict[str, Any]:
            calls.append("vlan-stretch")
            return {"observations": [], "warnings": [], "unbound_ports": [], "uncarried": 0}

        def check_edge_devices(self, session: Any, *, collection_ts: int) -> dict[str, Any]:
            calls.append("edge-devices")
            return {"proposed": [], "warnings": []}

    settings = Settings(_env_file=None, hst_secret_key="finalize-site-order-test-key-32-bytes!!!!")
    finalize.finalize_derivations(
        object(),
        settings,
        4242,
        {"dev:a": "hq"},
        rules=_Rules(),
        route_targets=_RouteTargets(),
        cycle=_Cycle(),
    )
    assert calls == ["apply", "carry", "vlan-stretch", "edge-devices"]
