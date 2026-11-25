"""Job-owned bridge from synchronous native compilation to durable artifacts.

The cache is an optimization. A model that cannot be read from it is compiled
again, and a model that cannot be stored in it is used from memory. Neither
failure fails the analysis. Errors of the compiler are not caught.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import Any

from hst.analysis_model.cache import ArtifactCache, PgCacheIndex
from hst.analysis_model.codec import ModelBinding, ModelCodecError, decode_model, encode_model
from hst.analysis_model.compile import AnalysisModel, compiled_fingerprint, with_estate_exits
from hst.analysis_model.model import ModelInput
from hst.symbolic import SymbolicManager
from hst.symbolic.artifacts import ArtifactLimits
from hst.symbolic.backend import backend_identity

log = logging.getLogger(__name__)

LIMITS = ArtifactLimits(max_bytes=64 * 1024 * 1024, max_nodes=1_000_000, max_roots=200_000)


class CompiledModelCache:
    def __init__(self, cache: ArtifactCache, *, engine: Any = None, semantic_version: str):
        self.cache, self.engine, self.semantic_version = cache, engine, semantic_version
        self.runner = asyncio.Runner()
        self.hits = self.misses = 0
        self.read_failures = self.store_failures = 0
        self.closed = False
        self.backend = backend_identity().identifier

    @classmethod
    def from_settings(cls, settings: Any, *, semantic_version: str) -> CompiledModelCache:
        from sqlalchemy.ext.asyncio import create_async_engine

        from hst.app import crypto
        from hst.app.store.pg import pg_ssl_engine_kwargs

        engine = create_async_engine(
            settings.postgres_dsn,
            pool_size=1,
            max_overflow=0,
            **pg_ssl_engine_kwargs(settings.postgres_ca_file),
        )
        cache = ArtifactCache(
            settings.hst_data_dir / "analysis-cache",
            crypto.dek(settings),
            PgCacheIndex(engine),
            max_bytes=settings.analysis_cache_mb * 1024 * 1024,
            max_artifact_bytes=LIMITS.max_bytes,
        )
        return cls(cache, engine=engine, semantic_version=semantic_version)

    def compile(
        self,
        source: ModelInput,
        manager: SymbolicManager,
        known_fields: frozenset[str],
        *,
        estate: str,
        compiler: Callable[[ModelInput, SymbolicManager, frozenset[str]], AnalysisModel],
    ) -> AnalysisModel:
        if self.closed:
            raise RuntimeError("compiled model cache is closed")
        binding = ModelBinding(
            estate=estate,
            manifest_digest=source.manifest_digest,
            semantic_version=self.semantic_version,
            header_schema=manager.capabilities.schema_version,
            ordering_version=manager.capabilities.ordering_version,
            backend_version=manager.capabilities.backend_version,
            model_fingerprint=compiled_fingerprint(source, manager, known_fields),
            known_fields=tuple(sorted(known_fields)),
            build_identity=self.backend,
        )
        cached = self._load(binding, manager)
        if cached is not None:
            self.hits += 1
            return with_estate_exits(cached, source)
        self.misses += 1
        model = compiler(source, manager, known_fields)
        self._store(binding, model)
        return model

    def _load(self, binding: ModelBinding, manager: SymbolicManager) -> AnalysisModel | None:
        """The cached model, or None when it is absent or cannot be used."""
        try:
            artifact = self.runner.run(self.cache.load(binding.key))
            if artifact is None:
                return None
            model = decode_model(artifact, manager, binding, limits=LIMITS)
            if model.fingerprint != binding.model_fingerprint:
                raise ModelCodecError("cached model does not match the normalized network")
            return model
        except Exception as exc:  # any cache failure falls back to a compile
            self.read_failures += 1
            log.warning(
                "Compiled analysis model %s of estate %s not read from the analysis cache; "
                "compiling it instead: %s: %s",
                binding.key[:16],
                binding.estate,
                type(exc).__name__,
                exc,
            )
            return None

    def _store(self, binding: ModelBinding, model: AnalysisModel) -> None:
        """Publish the model. After a failure the analysis uses the in-memory model."""
        try:
            artifact = encode_model(model, binding, limits=LIMITS)
            self.runner.run(self.cache.publish(binding.key, artifact))
        except Exception as exc:  # the in-memory model stays valid
            self.store_failures += 1
            log.warning(
                "Compiled analysis model %s of estate %s not stored in the analysis cache; "
                "the analysis continues with the in-memory model: %s: %s",
                binding.key[:16],
                binding.estate,
                type(exc).__name__,
                exc,
            )

    def close(self) -> None:
        if self.closed:
            return
        try:
            if self.engine is not None:
                self.runner.run(self.engine.dispose())
        finally:
            self.runner.close()
            self.closed = True
