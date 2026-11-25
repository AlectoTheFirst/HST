import asyncio
import hashlib
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from hst.analysis_model.cache import ArtifactCache, CacheCorruptionError, MemoryCacheIndex


def run(value):
    return asyncio.run(value)


def test_encrypted_atomic_publication_rotation_corruption_and_materialization(tmp_path: Path):
    old_key, new_key = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    index = MemoryCacheIndex()
    cache = ArtifactCache(tmp_path / "cache", old_key, index, max_bytes=10_000)
    key = hashlib.sha256(b"binding").hexdigest()
    record = run(cache.publish(key, b"exact-model"))
    stored = (tmp_path / "cache" / record.path).read_bytes()
    assert b"exact-model" not in stored
    assert run(cache.load(key)) == b"exact-model"
    destination = tmp_path / "saved" / "model"
    assert run(cache.materialize(key, destination)) == hashlib.sha256(b"exact-model").hexdigest()
    assert destination.read_bytes() == b"exact-model"
    with pytest.raises(CacheCorruptionError):
        run(ArtifactCache(tmp_path / "cache", new_key, index).load(key))
    (tmp_path / "cache" / record.path).write_bytes(stored[:-1] + bytes([stored[-1] ^ 1]))
    with pytest.raises(CacheCorruptionError):
        run(cache.load(key))
    assert not list((tmp_path / "cache").glob("*.tmp"))


def test_leases_and_pins_prevent_eviction(tmp_path: Path):
    async def scenario():
        index = MemoryCacheIndex()
        cache = ArtifactCache(tmp_path, Fernet.generate_key().decode(), index, max_bytes=1000)
        key = hashlib.sha256(b"one").hexdigest()
        await cache.publish(key, b"payload")
        cache.max_bytes = 1
        async with cache.lease(key) as value:
            assert value == b"payload"
            assert await cache.evict() == 0
        assert await cache.evict() == 1
        assert await cache.load(key) is None

    run(scenario())


def test_same_key_cannot_publish_different_artifact(tmp_path: Path):
    async def scenario():
        cache = ArtifactCache(tmp_path, Fernet.generate_key().decode(), MemoryCacheIndex())
        key = "0" * 64
        await cache.publish(key, b"first")
        with pytest.raises(Exception, match="cannot identify two artifacts"):
            await cache.publish(key, b"second")

    run(scenario())


def test_shared_blob_survives_one_key_eviction_and_pinned_bytes_count_toward_quota(
    tmp_path: Path,
):
    async def scenario():
        index = MemoryCacheIndex()
        cache = ArtifactCache(tmp_path, Fernet.generate_key().decode(), index, max_bytes=10_000)
        first, second = hashlib.sha256(b"first").hexdigest(), hashlib.sha256(b"second").hexdigest()
        one = await cache.publish(first, b"shared")
        await cache.publish(second, b"shared")
        index.records[first] = replace(index.records[first], pinned=True)
        cache.max_bytes = one.encrypted_bytes - 1
        assert await cache.evict() == 1
        assert await cache.load(first) == b"shared"

    run(scenario())
