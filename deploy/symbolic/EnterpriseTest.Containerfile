# tools/run_enterprise_remote.py builds one target per check on the BuildKit builder.
# No target writes an image.
FROM python:3.14-slim@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4 AS symbolic-build
WORKDIR /build
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential make patch \
    && rm -rf /var/lib/apt/lists/*
COPY tools/build_symbolic_wheels.py tools/build_symbolic_wheels.py
COPY third_party/symbolic/ third_party/symbolic/
RUN python tools/build_symbolic_wheels.py --work-dir /tmp/hst-symbolic-build --out-dir /wheelhouse

FROM python:3.14-slim@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4 AS test-base
WORKDIR /work
ARG HST_CONTEXT_ID
COPY --from=ghcr.io/astral-sh/uv:0.13.10@sha256:a3ea1357342c1a4bf9a0c53a3deb1b55379aefa037338d8113d5771efa01774f /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY --from=symbolic-build /wheelhouse/ /wheelhouse/
COPY --from=symbolic-build /wheelhouse/symbolic-artifacts.json /usr/share/hst/symbolic-build.json
RUN uv sync --frozen --no-install-project \
      --extra dev --extra mcp --extra app --extra sidestore --extra agent --extra symbolic \
    && wheel=$(find /wheelhouse -maxdepth 1 -name 'dd-0.6.0-*.whl' -print -quit) \
    && test -n "$wheel" \
    && uv pip install --python .venv/bin/python --no-deps --no-index "$wheel"
COPY src/ src/
COPY tests/enterprise/ tests/enterprise/
COPY tests/test_checkpoint.py tests/test_checkpoint.py
COPY tests/test_labels.py tests/test_schema_contract.py \
  tests/test_schema_fixtures.py tests/test_queries_catalog.py tests/
COPY tests/test_apic.py tests/test_cisco_common.py tests/test_iosxe.py \
  tests/test_iosxr.py tests/test_manual.py tests/test_nautobot.py tests/test_nxos.py \
  tests/test_unifi.py tests/test_vyos.py tests/
COPY tests/conftest.py tests/conftest.py
COPY tests/test_manifest.py tests/test_manifest_device_provenance.py \
  tests/test_collector_execute.py tests/
COPY tests/test_simul_rib.py tests/test_simul_propagate.py tests/test_impact_evaluate.py \
  tests/test_impact_soundness_bounds.py tests/test_impact_soundness_walks.py tests/
COPY fixtures/enterprise/ fixtures/enterprise/
COPY tools/build_symbolic_wheels.py tools/check_symbolic_licenses.py tools/run_limited.py \
  tools/enterprise_private_acceptance.py tools/run_enterprise_remote.py tools/
COPY third_party/symbolic/ third_party/symbolic/
COPY deploy/Containerfile deploy/Containerfile
COPY deploy/helm/hst/ deploy/helm/hst/
COPY third_party/symbolic/2026-09-12-enterprise-symbolic-sources.json third_party/symbolic/2026-09-12-enterprise-symbolic-sources.json
COPY web/src/settings/schema.fixtures.json web/src/settings/schema.fixtures.json
# tools/run_enterprise_remote.py packs the context from an allow-list and writes
# .hst-remote-context-id and .hst-remote-context.sha256 into it.
RUN test -n "$HST_CONTEXT_ID"
COPY . /work/
RUN test "$(cat .hst-remote-context-id)" = "$HST_CONTEXT_ID" \
    && sha256sum -c .hst-remote-context.sha256
RUN find /work/src /work/tests -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
ENV HST_SYMBOLIC_REQUIRE=1 \
    PYTHONPATH=/work/src:/work \
    PYTHONPYCACHEPREFIX=/tmp/hst-pycache \
    PYTHONUNBUFFERED=1

FROM symbolic-build AS enterprise-determinism
RUN cp -a /tmp/hst-symbolic-build/cache /tmp/hst-symbolic-source-cache \
    && rm -rf /tmp/hst-symbolic-build \
    && python tools/build_symbolic_wheels.py \
      --work-dir /tmp/hst-symbolic-build \
      --source-cache /tmp/hst-symbolic-source-cache \
      --out-dir /wheelhouse-second \
    && python -c 'import json,pathlib; a=json.loads(pathlib.Path("/wheelhouse/symbolic-artifacts.json").read_text()); b=json.loads(pathlib.Path("/wheelhouse-second/symbolic-artifacts.json").read_text()); assert a["wheel_sha256"] == b["wheel_sha256"], (a["wheel_sha256"], b["wheel_sha256"]); assert a["extension_sha256"] == b["extension_sha256"], (a["extension_sha256"], b["extension_sha256"]); print(a["wheel_sha256"], a["extension_sha256"])'

FROM test-base AS enterprise-smoke
RUN .venv/bin/python -c 'from hst.symbolic.backend import backend_identity; i=backend_identity(); assert i.verified and i.status == "ready", i' \
    && .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 180 -- \
    .venv/bin/pytest tests/enterprise/test_backend_install.py \
      tests/enterprise/test_contracts.py tests/enterprise/test_sdwan_bounds.py \
      -m 'not db and not pg and not perf'

FROM test-base AS enterprise-lint
RUN .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 300 -- \
      .venv/bin/ruff check src tests/enterprise \
    && .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 300 -- \
      .venv/bin/ruff format --check src tests/enterprise

FROM test-base AS enterprise-model-lint
RUN .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 300 -- \
      .venv/bin/ruff check --output-format concise \
        src/hst/analysis_model/counterfactual.py src/hst/analysis_model/gates.py \
        src/hst/analysis_model/network.py \
        src/hst/analysis_model/network_session.py src/hst/analysis_model/session_walk.py \
        src/hst/analysis_model/sessions.py src/hst/policy/nat.py \
        src/hst/impact/symbolic_walk.py tests/enterprise/test_gate_parity.py \
        tests/enterprise/test_compiled_sessions.py tests/enterprise/test_session_walk.py \
        tests/enterprise/test_network_compile.py tests/enterprise/test_counterfactual_model.py \
    && .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 300 -- \
      .venv/bin/ruff format --check \
        src/hst/analysis_model/counterfactual.py src/hst/analysis_model/gates.py \
        src/hst/analysis_model/network.py \
        src/hst/analysis_model/network_session.py src/hst/analysis_model/session_walk.py \
        src/hst/analysis_model/sessions.py src/hst/policy/nat.py \
        src/hst/impact/symbolic_walk.py tests/enterprise/test_gate_parity.py \
        tests/enterprise/test_compiled_sessions.py tests/enterprise/test_session_walk.py \
        tests/enterprise/test_network_compile.py tests/enterprise/test_counterfactual_model.py

FROM node:26-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5 AS enterprise-web-base
WORKDIR /work/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
COPY src/hst/core/labels.py /work/src/hst/core/labels.py
ENV NODE_OPTIONS=--max-old-space-size=768

FROM enterprise-web-base AS enterprise-web
RUN ulimit -v 3145728 \
    && timeout 300 npm run lint \
    && timeout 300 npm run typecheck \
    && timeout 300 npm test -- --maxWorkers=1 --no-file-parallelism \
      src/changesim/ServiceImpactPane.test.tsx src/changesim/SymbolicBuckets.test.tsx \
      src/changesim/PagedServiceBucket.test.tsx src/assessments/AnalysisDetail.test.tsx \
      src/flowdesk/strata/layers.test.ts src/settings/SchemaForm.test.tsx \
      src/settings/SchemaForm.sections.test.tsx src/settings/SchemaForm.collection.test.tsx

FROM test-base AS enterprise-typecheck
RUN .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 600 -- .venv/bin/mypy

FROM test-base AS enterprise-tests
RUN set -eu; \
    for path in $(find tests/enterprise -type f -name 'test_*.py' | sort); do \
      case "$path" in *scale*|*benchmark*) echo "excluded: $path"; continue;; esac; \
      set +e; \
      .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 120 -- \
        .venv/bin/pytest "$path" -m 'not db and not pg and not perf'; status=$?; \
      set -e; \
      test "$status" -eq 0 || test "$status" -eq 5 || exit "$status"; \
    done

FROM test-base AS enterprise-model-tests
RUN set -eu; \
    for path in \
      tests/enterprise/test_session_walk.py \
      tests/enterprise/test_compiled_sessions.py \
      tests/enterprise/test_gate_parity.py \
      tests/enterprise/test_network_compile.py \
      tests/enterprise/test_counterfactual_model.py; do \
      .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 120 -- \
        .venv/bin/pytest -vv -s "$path" -m 'not db and not pg and not perf'; \
    done

FROM test-base AS enterprise-root-tests
RUN set -eu; \
    for path in tests/enterprise/test_direct_analysis.py \
      tests/enterprise/test_result_artifacts.py \
      tests/enterprise/test_result_page.py \
      tests/enterprise/test_result_evidence.py \
      tests/enterprise/test_result_provenance.py \
      tests/enterprise/test_result_packages.py \
      tests/enterprise/test_compiled_model_cache.py \
      tests/enterprise/test_incremental_model_compile.py \
      tests/enterprise/test_incremental.py \
      tests/enterprise/test_artifact_key_rotation.py \
      tests/enterprise/test_result_quota.py \
      tests/enterprise/test_request_headers.py \
      tests/enterprise/test_symbolic_repair.py \
      tests/enterprise/test_symbolic_cost.py \
      tests/enterprise/test_assessment_symbolic_bridge.py \
      tests/enterprise/test_symbolic_result_projection.py; do \
      .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 120 -- \
        .venv/bin/pytest -vv "$path" -m 'not db and not pg and not perf'; \
    done

FROM test-base AS enterprise-latest-tests
RUN set -eu; \
    for path in tests/enterprise/test_native_changes.py \
      tests/enterprise/test_native_verification.py \
      tests/enterprise/test_private_acceptance.py \
      tests/enterprise/test_upgrade.py \
      tests/enterprise/test_deployment_profile.py \
      tests/enterprise/test_result_quota.py \
      tests/enterprise/test_network_compile.py; do \
      .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 120 -- \
        .venv/bin/pytest -vv "$path" -m 'not db and not pg and not perf'; \
    done

FROM test-base AS enterprise-native-changes
RUN .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 120 -- \
    .venv/bin/pytest -vv tests/enterprise/test_native_changes.py -m 'not db and not pg and not perf'

FROM test-base AS enterprise-private-acceptance
RUN .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 120 -- \
    .venv/bin/pytest -vv tests/enterprise/test_private_acceptance.py -m 'not db and not pg and not perf'

FROM test-base AS enterprise-upgrade
RUN .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 120 -- \
    .venv/bin/pytest -vv tests/enterprise/test_upgrade.py -m 'not db and not pg and not perf'

FROM test-base AS enterprise-deployment-tests
RUN set -eu; \
    for path in tests/enterprise/test_deployment_profile.py \
      tests/enterprise/test_result_quota.py tests/enterprise/test_network_compile.py; do \
      .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 120 -- \
        .venv/bin/pytest -vv "$path" -m 'not db and not pg and not perf'; \
    done

FROM test-base AS enterprise-native-mtu
RUN set -eu; \
    for path in tests/enterprise/test_native_mtu.py tests/enterprise/test_native_sdwan.py \
      tests/enterprise/test_missing_firewall_policy.py tests/enterprise/test_network_compile.py; do \
      .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 120 -- \
        .venv/bin/pytest -vv "$path" -m 'not db and not pg and not perf'; \
    done

FROM test-base AS enterprise-checkpoint-graph
RUN set -eu; \
    for path in tests/enterprise/test_checkpoint_graph_integration.py \
      tests/enterprise/test_checkpoint_normalize.py \
      tests/enterprise/test_checkpoint_pipeline.py \
      tests/enterprise/test_native_changes.py \
      tests/enterprise/test_native_verification.py; do \
      .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 120 -- \
        .venv/bin/pytest -vv "$path" -m 'not db and not pg and not perf'; \
    done
RUN .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 300 -- \
      .venv/bin/ruff check --output-format concise \
        src/hst/analysis_model/checkpoint_graph.py src/hst/analysis_model/network.py \
        src/hst/collectors/checkpoint.py src/hst/core/labels.py \
        tests/enterprise/test_checkpoint_graph_integration.py \
    && .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 300 -- \
      .venv/bin/mypy src/hst/analysis_model/checkpoint_graph.py \
        src/hst/analysis_model/network.py src/hst/collectors/checkpoint.py \
        src/hst/core/labels.py

FROM test-base AS enterprise-checkpoint-graph-checks
RUN .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 300 -- \
      .venv/bin/ruff check --output-format concise \
        src/hst/analysis_model/checkpoint_graph.py src/hst/analysis_model/network.py \
        src/hst/collectors/checkpoint.py src/hst/core/labels.py \
        tests/enterprise/test_checkpoint_graph_integration.py
RUN .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 300 -- \
      .venv/bin/mypy src/hst/analysis_model/checkpoint_graph.py \
        src/hst/analysis_model/network.py src/hst/collectors/checkpoint.py \
        src/hst/core/labels.py

FROM test-base AS enterprise-checkpoint-graph-mypy
RUN .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 300 -- \
      .venv/bin/mypy src/hst/analysis_model/checkpoint_graph.py \
        src/hst/analysis_model/network.py src/hst/collectors/checkpoint.py \
        src/hst/core/labels.py

FROM test-base AS enterprise-checkpoint-regressions
RUN set -eu; \
    for path in tests/enterprise/test_checkpoint_normalize.py \
      tests/enterprise/test_checkpoint_pipeline.py \
      tests/enterprise/test_native_changes.py \
      tests/enterprise/test_native_verification.py; do \
      .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 120 -- \
        .venv/bin/pytest -vv "$path" -m 'not db and not pg and not perf'; \
    done

FROM test-base AS enterprise-helm
# The release notes of helm v3.16.4 hold the SHA-256 of helm-v3.16.4-linux-amd64.tar.gz.
RUN set -eu; \
    arch=$(uname -m); test "$arch" = x86_64; \
    .venv/bin/python -c 'import urllib.request; urllib.request.urlretrieve("https://get.helm.sh/helm-v3.16.4-linux-amd64.tar.gz", "/tmp/helm.tgz")'; \
    echo "fc307327959aa38ed8f9f7e66d45492bb022a66c3e5da6063958254b9767d179  /tmp/helm.tgz" | sha256sum -c -; \
    tar -xzf /tmp/helm.tgz -C /tmp; helm=/tmp/linux-amd64/helm; \
    fake='--set secrets.secretKey=lint --set secrets.neo4jPassword=lint --set secrets.postgresPassword=lint --set ingress.acceptInsecureHttp=true --set app.forwardedAllowIps='; \
    $helm template standard deploy/helm/hst $fake > /tmp/standard.yaml; \
    $helm template enterprise deploy/helm/hst $fake --set analysis.profile=enterprise > /tmp/enterprise.yaml; \
    grep -A1 'name: ANALYSIS_MEMORY_MB' /tmp/enterprise.yaml | grep -q 'value: "2048"'; \
    $helm template enterprise deploy/helm/hst $fake --set analysis.profile=enterprise \
      --show-only templates/deployment.yaml > /tmp/enterprise-app.yaml; \
    grep -A4 '^          resources:' /tmp/enterprise-app.yaml | grep -q 'memory: 6Gi'; \
    if $helm template invalid deploy/helm/hst $fake --set analysis.profile=invalid >/dev/null 2>&1; then \
      echo "the chart rendered the analysis profile invalid"; exit 1; fi; \
    if $helm template invalid deploy/helm/hst $fake --set analysis.profiles.enterprise.workers=2 >/dev/null 2>&1; then \
      echo "the chart rendered 2 analysis workers"; exit 1; fi; \
    .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 120 -- \
      .venv/bin/pytest -vv tests/enterprise/test_deployment_profile.py

FROM test-base AS enterprise-schema-collectors
RUN set -eu; \
    for path in tests/enterprise/test_velocloud_pagination.py tests/enterprise/test_velocloud.py \
      tests/test_labels.py tests/test_schema_contract.py tests/test_schema_fixtures.py \
      tests/test_queries_catalog.py; do \
      .venv/bin/python tools/run_limited.py --memory-mib 3072 --timeout 120 -- \
        .venv/bin/pytest -vv "$path" -m 'not db and not pg and not perf'; \
    done

FROM test-base AS enterprise-latest-format-diff
RUN .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 300 -- \
    .venv/bin/ruff format --diff src/hst tests/enterprise \
      tools/run_enterprise_remote.py tools/run_limited.py \
      tools/build_symbolic_wheels.py tools/check_symbolic_licenses.py \
      tools/enterprise_private_acceptance.py

FROM test-base AS enterprise-clock-evidence-focused
COPY tests/app/ tests/app/
RUN set -eu; \
    .venv/bin/python -c 'import inspect; from hst.analysis_model.evidence import EvidenceWindow; assert "clock_source" in inspect.signature(EvidenceWindow).parameters, (inspect.getfile(EvidenceWindow), EvidenceWindow.__annotations__, inspect.signature(EvidenceWindow))'; \
    for path in tests/enterprise/test_evidence_windows.py \
      tests/enterprise/test_temporal_network.py tests/enterprise/test_clock_provenance.py \
      tests/app/test_sources_glue.py; do \
      .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 180 -- \
        .venv/bin/pytest -vv "$path" -m 'not db and not pg and not perf'; \
    done; \
    .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 300 -- \
      .venv/bin/ruff check --output-format concise src/hst/collectors/base.py \
        src/hst/core/manifest.py src/hst/app/runs_exec.py \
        src/hst/analysis_model/temporal.py tests/enterprise/test_clock_provenance.py; \
    .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 300 -- \
      .venv/bin/mypy src/hst/collectors/base.py src/hst/core/manifest.py \
        src/hst/app/runs_exec.py src/hst/analysis_model/temporal.py

FROM test-base AS enterprise-schema-fixture-diff
RUN .venv/bin/python -c 'import json; from pathlib import Path; from hst.collectors.apic import ApicConfig; from hst.collectors.checkpoint import CpConfig; from hst.collectors.nxos import NxosConfig; Path("/tmp/schema.fixtures.json").write_text(json.dumps({"apic": ApicConfig.model_json_schema(), "nxos": NxosConfig.model_json_schema(), "checkpoint": CpConfig.model_json_schema()}, indent=2) + "\n")' \
    && diff -u web/src/settings/schema.fixtures.json /tmp/schema.fixtures.json

FROM test-base AS enterprise-latest-checks
RUN .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 300 -- \
      .venv/bin/ruff check --output-format concise \
        src/hst/analysis_model/upgrade.py src/hst/analysis_model/mtu_gate.py \
        src/hst/analysis_model/network.py src/hst/assessment/native_verification.py \
        tools/enterprise_private_acceptance.py tests/enterprise/test_native_changes.py \
        tests/enterprise/test_native_verification.py tests/enterprise/test_private_acceptance.py \
        tests/enterprise/test_upgrade.py tests/enterprise/test_deployment_profile.py \
        tests/enterprise/test_result_quota.py tests/enterprise/test_network_compile.py \
    && .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 300 -- \
      .venv/bin/mypy src/hst/analysis_model/upgrade.py \
        src/hst/analysis_model/mtu_gate.py src/hst/analysis_model/network.py \
        src/hst/assessment/native_verification.py tools/enterprise_private_acceptance.py

FROM test-base AS enterprise-latest-mypy
RUN .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 300 -- \
      .venv/bin/mypy src/hst/analysis_model/upgrade.py \
        src/hst/analysis_model/mtu_gate.py src/hst/analysis_model/network.py \
        src/hst/assessment/native_verification.py tools/enterprise_private_acceptance.py

FROM test-base AS enterprise-full-mypy
RUN .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 600 -- .venv/bin/mypy

FROM test-base AS enterprise-full-ruff
RUN .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 600 -- \
    .venv/bin/ruff check --output-format concise src/hst tests/enterprise \
      tools/run_enterprise_remote.py tools/run_limited.py \
      tools/build_symbolic_wheels.py tools/check_symbolic_licenses.py \
      tools/enterprise_private_acceptance.py

FROM test-base AS enterprise-full-ruff-diff
RUN .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 600 -- \
    .venv/bin/ruff check --diff src/hst tests/enterprise \
      tools/run_enterprise_remote.py tools/run_limited.py \
      tools/build_symbolic_wheels.py tools/check_symbolic_licenses.py \
      tools/enterprise_private_acceptance.py

FROM test-base AS enterprise-incremental
RUN set -eu; \
    for path in tests/enterprise/test_incremental.py \
      tests/enterprise/test_incremental_model_compile.py \
      tests/enterprise/test_compiled_model_cache.py \
      tests/enterprise/test_assessment_symbolic_bridge.py; do \
      .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 180 -- \
        .venv/bin/pytest -vv "$path" -m 'not db and not pg and not perf'; \
    done; \
    .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 300 -- \
      .venv/bin/ruff check --output-format concise \
        src/hst/analysis_model/incremental.py src/hst/analysis_model/compile.py \
        src/hst/assessment/symbolic_evaluation.py tests/enterprise/test_incremental.py; \
    .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 300 -- \
      .venv/bin/mypy src/hst/analysis_model/incremental.py \
        src/hst/analysis_model/compile.py src/hst/assessment/symbolic_evaluation.py

FROM test-base AS enterprise-routing-incremental
RUN set -eu; \
    for path in tests/enterprise/test_routing_incremental.py \
      tests/enterprise/test_routing_dependencies.py \
      tests/enterprise/test_routing_convergence.py \
      tests/test_simul_rib.py tests/test_simul_propagate.py \
      tests/test_impact_evaluate.py tests/test_impact_soundness_bounds.py \
      tests/test_impact_soundness_walks.py tests/enterprise/test_network_compile.py; do \
      .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 180 -- \
        .venv/bin/pytest -vv "$path" -m 'not db and not pg and not perf'; \
    done; \
    .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 300 -- \
      .venv/bin/ruff check --output-format concise src/hst/simul/dependencies.py \
        src/hst/simul/rib.py src/hst/impact/evaluate.py \
        tests/enterprise/test_routing_incremental.py; \
    .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 300 -- \
      .venv/bin/mypy src/hst/simul/dependencies.py src/hst/simul/rib.py \
        src/hst/impact/evaluate.py

FROM test-base AS enterprise-root-format-diff
RUN .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 300 -- \
    .venv/bin/ruff format --diff \
      src/hst/assessment/direct.py src/hst/assessment/jobs.py \
      src/hst/analysis_model/model_cache.py src/hst/assessment/native_verification.py \
      src/hst/analysis_model/preflight.py src/hst/assessment/request_document.py \
      src/hst/assessment/result_artifacts.py src/hst/assessment/result_page.py \
      src/hst/assessment/service.py src/hst/assessment/symbolic_cost.py \
      src/hst/assessment/symbolic_evaluation.py src/hst/assessment/symbolic_repair.py \
      src/hst/assessment/symbolic_results.py src/hst/app/routes/health.py \
      src/hst/app/routes/impact.py src/hst/core/config.py \
      src/hst/mcp_server.py src/hst/app/agent/tools.py \
      tests/enterprise/test_direct_analysis.py tests/enterprise/test_native_verification.py \
      tests/enterprise/test_result_artifacts.py tests/enterprise/test_result_page.py \
      tests/enterprise/test_result_evidence.py tests/enterprise/test_result_quota.py \
      tests/enterprise/test_result_packages.py tests/enterprise/test_compiled_model_cache.py \
      tests/enterprise/test_incremental_model_compile.py tests/enterprise/test_request_headers.py \
      tests/enterprise/test_symbolic_repair.py tests/enterprise/test_symbolic_cost.py \
      tests/enterprise/test_assessment_symbolic_bridge.py \
      tests/enterprise/test_symbolic_result_projection.py

FROM test-base AS enterprise-populations
RUN .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 120 -- \
    .venv/bin/pytest -vv tests/enterprise/test_populations.py \
      tests/enterprise/test_population_request.py tests/enterprise/test_temporal_network.py \
      tests/enterprise/test_policy_catalogs.py -m 'not db and not pg and not perf'

FROM test-base AS enterprise-routing-extra
RUN set -eu; \
    for path in tests/enterprise/test_checkpoint_gateway_integration.py \
      tests/enterprise/test_vsx.py tests/test_labels.py; do \
      .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 120 -- \
        .venv/bin/pytest -vv "$path" -m 'not db and not pg and not perf'; \
    done

FROM test-base AS enterprise-checkpoint-session
RUN .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 120 -- \
    .venv/bin/pytest -vvv --tb=long tests/test_checkpoint.py

FROM test-base AS enterprise-cache
RUN .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 120 -- \
      .venv/bin/pytest -vv tests/enterprise/test_cache.py -m 'not db and not pg and not perf' \
    && .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 300 -- \
      .venv/bin/mypy src/hst/analysis_model/cache.py src/hst/app/store/pg.py \
    && .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 300 -- \
      .venv/bin/ruff check src/hst/analysis_model/cache.py tests/enterprise/test_cache.py \
    && .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 300 -- \
      .venv/bin/ruff format --check src/hst/analysis_model/cache.py tests/enterprise/test_cache.py

FROM test-base AS enterprise-root-lint
RUN .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 300 -- \
      .venv/bin/ruff check src/hst/assessment/direct.py \
        src/hst/assessment/request_document.py src/hst/assessment/jobs.py \
        src/hst/assessment/service.py src/hst/assessment/symbolic_cost.py \
        src/hst/assessment/symbolic_evaluation.py src/hst/assessment/symbolic_results.py \
        src/hst/app/routes/impact.py src/hst/mcp_server.py src/hst/app/agent/tools.py \
        tests/enterprise/test_direct_analysis.py tests/enterprise/test_symbolic_cost.py \
        tests/enterprise/test_assessment_symbolic_bridge.py \
    && .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 300 -- \
      .venv/bin/ruff format --check src/hst/assessment/direct.py \
        src/hst/assessment/request_document.py src/hst/assessment/jobs.py \
        src/hst/assessment/service.py src/hst/assessment/symbolic_cost.py \
        src/hst/assessment/symbolic_evaluation.py src/hst/assessment/symbolic_results.py \
        src/hst/app/routes/impact.py src/hst/mcp_server.py src/hst/app/agent/tools.py \
        tests/enterprise/test_direct_analysis.py tests/enterprise/test_symbolic_cost.py \
        tests/enterprise/test_assessment_symbolic_bridge.py

FROM postgres:16.15@sha256:f9a7b9ebf6f56201f949db745e47bc423c0f0f8294bafe991cc10bf74b029657 AS enterprise-postgres
COPY --from=test-base /usr/local/ /usr/local/
COPY --from=test-base /work/ /work/
WORKDIR /work
COPY tests/app/ tests/app/
COPY tests/conftest.py tests/conftest.py
ENV HST_SYMBOLIC_REQUIRE=1 \
    PYTHONPATH=/work/src:/work \
    PYTHONUNBUFFERED=1 \
    HST_TEST_PG_DSN=postgresql+asyncpg://postgres@127.0.0.1:5544/hst_test
RUN set -eu; \
    install -d -o postgres -g postgres /tmp/hst-pg; \
    su postgres -c '/usr/lib/postgresql/16/bin/initdb --auth=trust -D /tmp/hst-pg/data'; \
    su postgres -c "/usr/lib/postgresql/16/bin/pg_ctl -D /tmp/hst-pg/data -o '-h 127.0.0.1 -p 5544' -w start"; \
    trap "su postgres -c '/usr/lib/postgresql/16/bin/pg_ctl -D /tmp/hst-pg/data -m immediate stop'" EXIT; \
    su postgres -c '/usr/lib/postgresql/16/bin/createdb -h 127.0.0.1 -p 5544 hst_test'; \
    for path in tests/app/test_store_pg.py tests/app/test_store_contract.py \
      tests/app/test_migrations.py tests/app/test_assessment_store_pg.py \
      tests/app/test_scheduler.py tests/enterprise/test_cache_pg.py; do \
      .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 180 -- \
        .venv/bin/pytest -vv "$path" -m pg; \
    done

FROM postgres:16.15@sha256:f9a7b9ebf6f56201f949db745e47bc423c0f0f8294bafe991cc10bf74b029657 AS enterprise-postgres-api
COPY --from=test-base /usr/local/ /usr/local/
COPY --from=test-base /work/ /work/
WORKDIR /work
COPY tests/app/ tests/app/
COPY tests/conftest.py tests/conftest.py
COPY tests/test_impact_evaluate.py tests/test_impact_evaluate.py
COPY tests/test_path_nat.py tests/test_path_trace.py tests/
ENV HST_SYMBOLIC_REQUIRE=1 \
    PYTHONPATH=/work/src:/work \
    PYTHONUNBUFFERED=1 \
    HST_TEST_PG_DSN=postgresql+asyncpg://postgres@127.0.0.1:5544/hst_test
RUN set -eu; \
    install -d -o postgres -g postgres /tmp/hst-pg; \
    su postgres -c '/usr/lib/postgresql/16/bin/initdb --auth=trust -D /tmp/hst-pg/data'; \
    su postgres -c "/usr/lib/postgresql/16/bin/pg_ctl -D /tmp/hst-pg/data -o '-h 127.0.0.1 -p 5544' -w start"; \
    trap "su postgres -c '/usr/lib/postgresql/16/bin/pg_ctl -D /tmp/hst-pg/data -m immediate stop'" EXIT; \
    su postgres -c '/usr/lib/postgresql/16/bin/createdb -h 127.0.0.1 -p 5544 hst_test'; \
    for path in tests/app/test_jobs_api.py tests/app/test_assessment_jobs.py \
      tests/app/test_assessments_api.py tests/app/test_impact_api.py \
      tests/app/test_changesim_export_api.py tests/app/test_mtu_api.py; do \
      .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 180 -- \
        .venv/bin/pytest -vv \
          -W 'ignore:pathlib.PurePath.as_uri:DeprecationWarning' \
          "$path" -m 'not db and not pg and not perf'; \
    done

FROM enterprise-postgres-api AS enterprise-clock-evidence
RUN set -eu; \
    install -d -o postgres -g postgres /tmp/hst-pg-clock-evidence; \
    su postgres -c '/usr/lib/postgresql/16/bin/initdb --auth=trust -D /tmp/hst-pg-clock-evidence/data'; \
    su postgres -c "/usr/lib/postgresql/16/bin/pg_ctl -D /tmp/hst-pg-clock-evidence/data -o '-h 127.0.0.1 -p 5544' -w start"; \
    trap "su postgres -c '/usr/lib/postgresql/16/bin/pg_ctl -D /tmp/hst-pg-clock-evidence/data -m immediate stop'" EXIT; \
    su postgres -c '/usr/lib/postgresql/16/bin/createdb -h 127.0.0.1 -p 5544 hst_test'; \
    for path in tests/enterprise/test_evidence_windows.py tests/enterprise/test_temporal_network.py; do \
      .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 180 -- \
        .venv/bin/pytest -vv "$path" -m 'not db and not pg and not perf'; \
    done; \
    .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 180 -- \
      .venv/bin/pytest -vv tests/enterprise/test_clock_provenance.py \
        -m 'not db and not pg and not perf'; \
    for path in tests/test_manifest.py tests/test_manifest_device_provenance.py; do \
      .venv/bin/python tools/run_limited.py --memory-mib 3072 --timeout 180 -- \
        .venv/bin/pytest -vv "$path" -m 'not db and not pg and not perf'; \
    done; \
    for path in tests/test_collector_execute.py \
      tests/app/test_runs_exec_fleet.py tests/app/test_runs_exec_rt.py \
      tests/app/test_sources_api.py tests/app/test_sources_glue.py; do \
      su postgres -c '/usr/lib/postgresql/16/bin/dropdb --if-exists -h 127.0.0.1 -p 5544 hst_test'; \
      su postgres -c '/usr/lib/postgresql/16/bin/createdb -h 127.0.0.1 -p 5544 hst_test'; \
      .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 180 -- \
        .venv/bin/pytest -vv -W 'ignore:pathlib.PurePath.as_uri:DeprecationWarning' \
          "$path" -m 'not db and not pg and not perf'; \
    done; \
    .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 300 -- \
      .venv/bin/ruff check --output-format concise src/hst/collectors/base.py \
        src/hst/core/manifest.py src/hst/app/runs_exec.py \
        src/hst/analysis_model/temporal.py; \
    .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 300 -- \
      .venv/bin/mypy src/hst/collectors/base.py src/hst/core/manifest.py \
        src/hst/app/runs_exec.py src/hst/analysis_model/temporal.py

FROM test-base AS enterprise-shared-tests
COPY tests/app/ tests/app/
COPY tests/conftest.py tests/conftest.py
COPY tests/test_assessment_package.py tests/test_changesim_export.py tests/test_impact_evaluate.py tests/
COPY tests/test_path_determinism.py tests/test_path_multihop.py tests/test_path_nat.py tests/
COPY tests/test_path_trace.py tests/test_path_trace.py
COPY tests/test_path_policy.py tests/test_path_reply.py tests/test_mtu_contract.py tests/
COPY tests/test_mtu_path.py tests/test_mtu_regression.py tests/
COPY tests/test_mtu_snapshot.py tests/test_mtu_assessment.py tests/test_grapharchive.py tests/
COPY tests/test_mtu_budget.py tests/test_mtu_budget.py
RUN set -eu; \
    for path in tests/test_assessment_package.py tests/test_changesim_export.py \
      tests/test_impact_evaluate.py tests/test_path_determinism.py \
      tests/test_path_multihop.py tests/test_path_nat.py tests/test_path_policy.py \
      tests/test_path_reply.py tests/test_mtu_contract.py tests/test_mtu_path.py \
      tests/test_mtu_regression.py; do \
      .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 120 -- \
        .venv/bin/pytest -vv "$path" -m 'not db and not pg and not perf'; \
    done

FROM test-base AS enterprise-priority-tests
RUN set -eu; \
    for path in \
      tests/enterprise/test_routing_convergence.py \
      tests/enterprise/test_routing_dependencies.py \
      tests/enterprise/test_network_compile.py \
      tests/enterprise/test_session_walk.py \
      tests/enterprise/test_compiled_sessions.py \
      tests/enterprise/test_gate_parity.py \
      tests/enterprise/test_populations.py \
      tests/enterprise/test_assessment_symbolic_bridge.py \
      tests/enterprise/test_symbolic_result_projection.py; do \
      .venv/bin/python tools/run_limited.py --memory-mib 1024 --timeout 120 -- \
        .venv/bin/pytest -vv "$path" -m 'not db and not pg and not perf'; \
    done

FROM test-base AS enterprise-artifacts
RUN .venv/bin/python tools/build_symbolic_wheels.py --check-lock --out-dir /tmp/lock-check \
    && .venv/bin/python tools/check_symbolic_licenses.py

FROM test-base AS enterprise-format
RUN .venv/bin/ruff format src tests/enterprise \
    && .venv/bin/ruff check --fix src tests/enterprise \
    && .venv/bin/ruff format src tests/enterprise

FROM scratch AS enterprise-format-export
COPY --from=enterprise-format /work/src/ /formatted/src/
COPY --from=enterprise-format /work/tests/enterprise/ /formatted/tests/enterprise/
