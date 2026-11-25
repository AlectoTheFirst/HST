from types import SimpleNamespace

import pytest

from hst.analysis_model.cache import ArtifactCache, MemoryCacheIndex
from hst.app.crypto import dek, generate_key, rewrap_dek
from hst.assessment.result_artifacts import ResultArtifactStore


@pytest.mark.asyncio
async def test_kek_rotation_preserves_cache_and_saved_result_artifacts(tmp_path):
    old_kek = generate_key()
    new_kek = generate_key()
    old_settings = SimpleNamespace(
        hst_data_dir=tmp_path,
        hst_secret_key=old_kek,
        hst_secret_key_file="",
    )
    data_key = dek(old_settings)
    index = MemoryCacheIndex()
    cache_key = "1" * 64
    cache = ArtifactCache(tmp_path / "analysis-cache", data_key, index)
    await cache.publish(cache_key, b"compiled-model")

    results = ResultArtifactStore(tmp_path, data_key)
    reference = results.publish(
        b'{"members":[]}', estate="estate", manifest_sha256="2" * 64, request_id="3" * 64
    )

    rewrap_dek(old_settings, new_kek)
    new_settings = SimpleNamespace(
        hst_data_dir=tmp_path,
        hst_secret_key=new_kek,
        hst_secret_key_file="",
    )
    rotated_data_key = dek(new_settings)

    assert rotated_data_key == data_key
    rotated_cache = ArtifactCache(tmp_path / "analysis-cache", rotated_data_key, index)
    assert await rotated_cache.load(cache_key) == b"compiled-model"
    assert ResultArtifactStore(tmp_path, rotated_data_key).load(reference) == b'{"members":[]}'
