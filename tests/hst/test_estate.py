from collections import Counter

import pytest

from hst.map import estate as estatemod
from hst.map.estate import Spec


def _run(estate: estatemod.Estate, run: int) -> tuple[list, list]:
    nodes, rels = [], []
    for n, r in estatemod.run_objects(estate, run):
        nodes += n
        rels += r
    return nodes, rels


@pytest.fixture(scope="module")
def estate() -> estatemod.Estate:
    return estatemod.build(Spec(devices=800, seed=3, change_rate=0.25, transient_share=0.05))


def test_the_estate_is_the_same_for_the_same_seed(estate: estatemod.Estate) -> None:
    again = estatemod.build(estate.spec)
    assert [d.uid for d in again.devices] == [d.uid for d in estate.devices]
    assert _run(again, 2) == _run(estate, 2)


def test_every_relationship_joins_two_objects_of_the_same_run_and_every_uid_is_unique(
    estate: estatemod.Estate,
) -> None:
    for run in (0, 1):
        nodes, rels = _run(estate, run)
        uids = Counter(row["uid"] for _label, row in nodes)
        assert max(uids.values()) == 1
        missing = {(kind, a, b) for kind, a, b, _p in rels if a not in uids or b not in uids}
        assert missing == set()


def test_the_device_count_and_the_orphan_share_match_the_spec(estate: estatemod.Estate) -> None:
    ratios = estatemod.ratios(estate)
    assert abs(ratios["devices"] - 800) <= 8
    assert ratios["orphan_devices"] == round(800 * estate.spec.orphan_share)
    tiers = Counter(d.tier for d in estate.devices)
    assert tiers["firewall"] == 2 * ratios["sites"]


def test_the_change_rate_between_two_runs_matches_the_spec(estate: estatemod.Estate) -> None:
    changed = sum(estatemod.changed(estate.spec, d.index, 1) for d in estate.devices)
    assert abs(changed / len(estate.devices) - 0.25) < 0.05
    assert not any(estatemod.changed(estate.spec, d.index, 0) for d in estate.devices)
    device = next(d for d in estate.devices if estatemod.changed(estate.spec, d.index, 1))
    assert estatemod.device_objects(estate, device, 1) != estatemod.device_objects(estate, device, 0)


def test_a_transient_device_and_its_cables_leave_and_return(estate: estatemod.Estate) -> None:
    transient = next(d for d in estate.devices if d.transient)
    present = {run: estatemod.present(estate, transient, run) for run in range(3)}
    assert present[0] != present[1] and present[0] == present[2]
    absent_run = 0 if not present[0] else 1
    nodes, rels = _run(estate, absent_run)
    assert transient.uid not in {row["uid"] for _label, row in nodes}
    assert not any(transient.uid in a or transient.uid in b for _k, a, b, _p in rels)


def test_the_coverage_shares_apply_per_interface(estate: estatemod.Estate) -> None:
    nodes, rels = _run(estate, 0)
    interfaces = [row["uid"] for label, row in nodes if label == "Interface" and "/if/eth" in row["uid"]]
    realized = {a for kind, a, _b, _p in rels if kind == "REALIZED_BY"}
    in_vrf = {a for kind, a, _b, _p in rels if kind == "IN_VRF" and "/if/" in a}
    assert abs(len(realized) / len(interfaces) - estate.spec.port_edge_share) < 0.05
    assert abs(len(in_vrf) / len(interfaces) - estate.spec.context_edge_share) < 0.05


def test_the_benchmark_refuses_the_configured_twin(tmp_path) -> None:
    from hst import bench
    from hst.core.config import Settings

    with pytest.raises(RuntimeError, match="configured twin"):
        bench.run_map_bench(settings=Settings(_env_file=None, hst_data_dir=tmp_path), devices=10, runs=1)
    assert not any(tmp_path.iterdir())
