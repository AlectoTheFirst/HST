from pathlib import Path
from typing import Any

from hst.map import markers, store
from hst.map.project import Projection


def test_a_failed_projection_publishes_the_run_without_tiers(tmp_path: Path) -> None:
    class Broken:
        def run(self, query: str, **params: Any) -> Any:
            raise RuntimeError("graph unavailable")

    markers_dir, sidestore = tmp_path / "manifests", tmp_path / "sidestore"
    projection = Projection(sidestore, markers_dir, 7, None, "full")
    projection.prepare(Broken())
    marker = projection.publish()
    assert projection.failed is not None and "graph unavailable" in projection.failed
    assert marker["tiers_ready"] is False
    assert markers.read(markers_dir, 7)["tiers_ready"] is False


def test_a_new_projection_discards_the_stages_of_runs_that_never_published(tmp_path: Path) -> None:
    sidestore = tmp_path / "sidestore"
    for key in (5, 6):
        store.staged_path(sidestore, key, "render_t1").parent.mkdir(parents=True)
    Projection(sidestore, tmp_path / "manifests", 7, None, "full")
    assert not store.staging_dir(sidestore, 5).exists()
    assert not store.staging_dir(sidestore, 6).exists()
