# CONTRIBUTING.md and .github/workflows/ci.yml call these targets.
#
# Each target runs through `uv run --frozen`, which installs from the committed uv.lock
# and resolves nothing.

UV      ?= uv
RUN     := $(UV) run --frozen
EXTRAS  := --extra dev --extra mcp --extra app --extra sidestore --extra agent
ENTERPRISE_EXTRAS := $(EXTRAS) --extra symbolic
ENTERPRISE_RUN := $(UV) run --frozen --no-sync

.PHONY: help install py-install web-install symbolic-install lock-check lint format typecheck test test-pg test-db estate-acceptance \
        web-check coverage audit e2e check check-db no-run-data helm-check \
        enterprise-check enterprise-check-db enterprise-build-check \
        test-stack test-stack-down \
        k8s-image k8s-secret k8s-install k8s-verify k8s-uninstall

help:
	@grep -E '^[a-z0-9-]+:.*?## ' $(MAKEFILE_LIST) | sed 's/:.*## /\t/'

install: py-install web-install  ## Both toolchains: the venv and the SPA's node_modules

# The CI jobs call py-install and web-install separately.
py-install:  ## Sync the venv from the lock (all extras CI installs)
	$(UV) sync --frozen $(EXTRAS)

# WHEEL must name the artifact produced by tools/build_symbolic_wheels.py. The
# checker rejects a wheel whose filename/hash is not qualified for this target.
symbolic-install:  ## Install the locked symbolic closure and a verified native wheel (WHEEL=...)
	@test -n "$(WHEEL)" || { echo "WHEEL is required"; exit 1; }
	$(UV) sync --frozen $(ENTERPRISE_EXTRAS)
	$(RUN) python tools/check_symbolic_licenses.py --wheel "$(WHEEL)" --require-qualified-wheel
	$(UV) pip install --python .venv/bin/python --no-deps --no-index --force-reinstall "$(WHEEL)"
	HST_SYMBOLIC_REQUIRE=1 $(ENTERPRISE_RUN) python -c 'from hst.symbolic.manager import backend_available; assert backend_available()'

web-install:  ## npm ci in web/
	cd web && npm ci

lock-check:  ## Fail if uv.lock has drifted from pyproject.toml
	$(UV) lock --check

no-run-data:  ## Fail if collected data, dumps or sealed secrets are tracked
	$(RUN) python tools/check_no_run_data.py

CHART   := deploy/helm/hst
# helm lint and helm template render only with the 3 secrets and a peer in
# networkPolicy.ingressFrom. The values are placeholders.
# The bundled Neo4j and Postgres without tls.serverSecret render only with the 2
# acceptInsecure values.
HELM_PLAIN_DB := --set neo4j.acceptInsecure=true --set postgres.acceptInsecure=true
HELM_NO_PEERS := --set secrets.secretKey=lint --set secrets.neo4jPassword=lint --set secrets.postgresPassword=lint \
  $(HELM_PLAIN_DB)
HELM_FAKE := $(HELM_NO_PEERS) \
  --set-json 'networkPolicy.ingressFrom=[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"ingress"}}}]'

# The default values (ingress on, TLS off) render only with ingress.acceptInsecureHttp=true.
HELM_INSECURE_OK := --set ingress.acceptInsecureHttp=true

# The TLS listeners of the bundled Neo4j and Postgres.
HELM_DB_TLS := --set neo4j.tls.enabled=true --set neo4j.tls.caSecret=db-tls --set neo4j.tls.serverSecret=db-tls \
  --set postgres.tls.enabled=true --set postgres.tls.caSecret=db-tls --set postgres.tls.serverSecret=db-tls

# The values of the backup CronJob, without backup.s3.endpoint.
HELM_BACKUP := --set backup.enabled=true --set backup.s3.bucket=b \
  --set backup.s3.secretName=hst-backup-s3 --set backup.recoverySecretName=hst-backup-recovery

helm-check:  ## Lint the chart and prove it renders, with bundled and external backends
	helm lint $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK)
	helm template lint-bundled $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK) > /dev/null
	@# pg:5432 and neo4j:7687 are non-loopback hosts, so this case sets both acceptInsecure values.
	helm template lint-external $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK) \
	  --set postgres.enabled=false --set postgres.externalDsn=postgresql+asyncpg://u:p@pg:5432/d --set postgres.acceptInsecure=true \
	  --set neo4j.enabled=false --set neo4j.externalUri=bolt://neo4j:7687 --set neo4j.acceptInsecure=true > /dev/null
	@# The backup CronJob renders only with backup.enabled=true.
	helm template lint-backup $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK) $(HELM_BACKUP) \
	  --set backup.s3.endpoint=https://s3.example > /dev/null
	@# values.schema.json refuses a backup.s3.endpoint with the scheme http.
	@! helm template lint-backup-http $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK) $(HELM_BACKUP) \
	  --set backup.s3.endpoint=http://s3.example >/dev/null 2>&1 \
	  || (echo "chart rendered the backup with an http:// S3 endpoint"; exit 1)
	@# The default render has the NetworkPolicy of the app pod.
	@helm template lint-bundled $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK) \
	  --show-only templates/networkpolicy.yaml | grep -q 'name: lint-bundled-hst-app$$' \
	  || (echo "the default render has no NetworkPolicy for the app pod"; exit 1)
	@# The default egress rules exclude the cloud metadata range, and egress.enabled=false removes them.
	@helm template lint-bundled $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK) \
	  --show-only templates/networkpolicy.yaml | grep -q -- '- 169.254.0.0/16$$' \
	  || (echo "the default egress rules do not exclude 169.254.0.0/16"; exit 1)
	@! helm template lint-no-egress $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK) --set networkPolicy.egress.enabled=false \
	  --show-only templates/networkpolicy.yaml | grep -q 'ipBlock' \
	  || (echo "networkPolicy.egress.enabled=false rendered an egress ipBlock"; exit 1)
	@# app.forwardedAllowIps without a peer in networkPolicy.ingressFrom must fail.
	@! helm template lint-no-peers $(CHART) $(HELM_NO_PEERS) $(HELM_INSECURE_OK) >/dev/null 2>&1 \
	  || (echo "chart rendered app.forwardedAllowIps without networkPolicy.ingressFrom"; exit 1)
	@# Without a peer the chart renders with an empty app.forwardedAllowIps.
	helm template lint-no-proxy $(CHART) $(HELM_NO_PEERS) $(HELM_INSECURE_OK) --set app.forwardedAllowIps= > /dev/null
	@# An install with TLS at the ingress and auth.cookieSecure=true renders.
	helm template lint-tls $(CHART) $(HELM_FAKE) \
	  --set ingress.tls.enabled=true --set ingress.tls.secretName=hst-tls \
	  --set auth.cookieSecure=true > /dev/null
	@# postgres.enabled=false without postgres.externalDsn must fail.
	@! helm template lint-missing $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK) --set postgres.enabled=false >/dev/null 2>&1 \
	  || (echo "chart rendered with postgres disabled and no externalDsn"; exit 1)
	@# An ingress without TLS and without ingress.acceptInsecureHttp must fail.
	@! helm template lint-insecure $(CHART) $(HELM_FAKE) >/dev/null 2>&1 \
	  || (echo "chart rendered ingress without TLS and without acceptInsecureHttp"; exit 1)
	@# A non-loopback external Neo4j without TLS and without neo4j.acceptInsecure must fail.
	@! helm template lint-neo4j-insecure $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK) --set neo4j.acceptInsecure=false \
	  --set neo4j.enabled=false --set neo4j.externalUri=bolt://neo4j.example:7687 >/dev/null 2>&1 \
	  || (echo "chart rendered a non-loopback external neo4j without TLS or acceptInsecure"; exit 1)
	@# A non-loopback external Postgres without TLS and without postgres.acceptInsecure must fail.
	@! helm template lint-postgres-insecure $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK) --set postgres.acceptInsecure=false \
	  --set postgres.enabled=false --set postgres.externalDsn=postgresql+asyncpg://u:p@pg.example:5432/d >/dev/null 2>&1 \
	  || (echo "chart rendered a non-loopback external postgres without TLS or acceptInsecure"; exit 1)
	@# The bundled Neo4j or Postgres without tls.serverSecret and without acceptInsecure must fail.
	@helm template lint-neo4j-plain $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK) --set neo4j.acceptInsecure=false 2>&1 \
	  | grep -q 'neo4j.enabled=true with an empty neo4j.tls.serverSecret' \
	  || (echo "chart rendered the bundled neo4j without TLS or acceptInsecure"; exit 1)
	@helm template lint-postgres-plain $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK) --set postgres.acceptInsecure=false 2>&1 \
	  | grep -q 'postgres.enabled=true with an empty postgres.tls.serverSecret' \
	  || (echo "chart rendered the bundled postgres without TLS or acceptInsecure"; exit 1)
	@# The bundled Neo4j and Postgres with their TLS listeners render without acceptInsecure.
	helm template lint-db-tls $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK) $(HELM_DB_TLS) \
	  --set neo4j.acceptInsecure=false --set postgres.acceptInsecure=false > /dev/null
	@# tls.enabled=true without tls.caSecret must fail.
	@! helm template lint-neo4j-tls-missing-ca $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK) --set neo4j.tls.enabled=true >/dev/null 2>&1 \
	  || (echo "chart rendered neo4j.tls.enabled=true without a caSecret"; exit 1)
	@! helm template lint-postgres-tls-missing-ca $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK) --set postgres.tls.enabled=true >/dev/null 2>&1 \
	  || (echo "chart rendered postgres.tls.enabled=true without a caSecret"; exit 1)
	@# The non-loopback external endpoints render with TLS and a CA secret.
	helm template lint-neo4j-tls $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK) \
	  --set neo4j.enabled=false --set neo4j.externalUri=bolt://neo4j.example:7687 \
	  --set neo4j.tls.enabled=true --set neo4j.tls.caSecret=neo4j-ca > /dev/null
	helm template lint-postgres-tls $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK) \
	  --set postgres.enabled=false --set postgres.externalDsn=postgresql+asyncpg://u:p@pg.example:5432/d \
	  --set postgres.tls.enabled=true --set postgres.tls.caSecret=postgres-ca > /dev/null
	@# They also render without TLS and with acceptInsecure=true.
	helm template lint-neo4j-accept $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK) \
	  --set neo4j.enabled=false --set neo4j.externalUri=bolt://neo4j.example:7687 \
	  --set neo4j.acceptInsecure=true > /dev/null
	helm template lint-postgres-accept $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK) \
	  --set postgres.enabled=false --set postgres.externalDsn=postgresql+asyncpg://u:p@pg.example:5432/d \
	  --set postgres.acceptInsecure=true > /dev/null
	@# The worker Deployment renders with worker.enabled=true on ReadWriteOnce and on ReadWriteMany.
	helm template lint-worker-rwo $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK) --set worker.enabled=true > /dev/null
	helm template lint-worker-rwx $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK) --set worker.enabled=true \
	  --set app.persistence.accessMode=ReadWriteMany > /dev/null
	@# On ReadWriteOnce the worker has a required affinity to the app pod's node.
	@# With the worker on, the app pods queue the triggered runs.
	@# On ReadWriteMany the worker has no required affinity.
	@helm template lint-worker-rwo $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK) --set worker.enabled=true \
	  | grep -q 'requiredDuringSchedulingIgnoredDuringExecution' \
	  || (echo "worker on ReadWriteOnce rendered without required co-location with the app pod"; exit 1)
	@helm template lint-worker-rwo $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK) --set worker.enabled=true \
	  | grep -A1 'name: RUN_EXECUTION' | grep -q '"queue"' \
	  || (echo "worker enabled but the app pods do not queue triggered runs"; exit 1)
	@! helm template lint-worker-rwx $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK) --set worker.enabled=true \
	  --set app.persistence.accessMode=ReadWriteMany | grep -q 'requiredDuringSchedulingIgnoredDuringExecution' \
	  || (echo "worker on ReadWriteMany rendered with a required placement"; exit 1)
	@# With worker.tolerations empty the worker takes app.tolerations.
	@helm template lint-worker-taint $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK) --set worker.enabled=true \
	  --set 'app.tolerations[0].key=dedicated' --set 'app.tolerations[0].operator=Exists' \
	  --show-only templates/deployment-worker.yaml | grep -q 'key: dedicated' \
	  || (echo "the worker does not take app.tolerations"; exit 1)
	@# The default values render no worker.
	@! helm template lint-bundled $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK) \
	  | grep -q 'app.kubernetes.io/component: worker' \
	  || (echo "the default render contains a worker"; exit 1)
	@# The worker with an emptyDir or a ReadWriteOncePod data volume must fail.
	@! helm template lint-worker-emptydir $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK) --set worker.enabled=true \
	  --set app.persistence.enabled=false >/dev/null 2>&1 \
	  || (echo "chart rendered the worker with an emptyDir data volume"; exit 1)
	@! helm template lint-worker-rwop $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK) --set worker.enabled=true \
	  --set app.persistence.accessMode=ReadWriteOncePod >/dev/null 2>&1 \
	  || (echo "chart rendered the worker on a ReadWriteOncePod data volume"; exit 1)
	@# The enterprise analysis profile raises the app's memory limit for its analysis
	@# worker, and keeps a higher limit an operator set on app.resources.
	@helm template lint-enterprise $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK) --set analysis.profile=enterprise \
	  --show-only templates/deployment.yaml | grep -A4 '^          resources:' | grep -q 'memory: 6Gi' \
	  || (echo "the enterprise profile does not raise the app memory limit to 6Gi"; exit 1)
	@helm template lint-enterprise $(CHART) $(HELM_FAKE) $(HELM_INSECURE_OK) --set analysis.profile=enterprise \
	  --set app.resources.limits.memory=8Gi \
	  --show-only templates/deployment.yaml | grep -A4 '^          resources:' | grep -q 'memory: 8Gi' \
	  || (echo "the enterprise profile lowered a higher app memory limit"; exit 1)
	@# appVersion is the image tag when image.tag is empty, so it must equal hst.__version__.
	@# The check uses awk, because helm-check runs without a synced venv.
	@app=$$(awk -F'"' '/^appVersion:/ {print $$2}' $(CHART)/Chart.yaml); \
	 pkg=$$(awk -F'"' '/^__version__/ {print $$2}' src/hst/__init__.py); \
	 [ -n "$$app" ] && [ "$$app" = "$$pkg" ] \
	   || (echo "Chart.yaml appVersion '$$app' != hst.__version__ '$$pkg'"; exit 1)
	@echo "chart ok"

lint:  ## ruff check + ruff format --check
	$(RUN) ruff check src tests tools
	$(RUN) ruff format --check src tests tools

format:  ## Apply ruff formatting (not a gate; convenience)
	$(RUN) ruff check src tests tools --fix
	$(RUN) ruff format src tests tools

typecheck:  ## mypy over src
	$(RUN) mypy

test:  ## Unit tests (no database needed)
	$(RUN) pytest -n auto

test-pg:  ## Store tests. Needs HST_TEST_PG_DSN pointing at a DISPOSABLE Postgres.
	$(RUN) pytest -m pg

# The db suite deletes data. tests/test_integration_db.py refuses the URI that
# core/config.py resolves as the live twin.
test-db:  ## Lifecycle tests. Needs NEO4J_TEST_URI / NEO4J_TEST_PASSWORD, scratch DB only.
	$(RUN) pytest -m db

# tests/perf/test_estate_acceptance.py runs only with HST_ESTATE_ACCEPTANCE=1 and reads
# these 4 variables.
estate-acceptance:  ## Full target-estate benchmark. Destructive scratch Neo4j only.
	@for v in NEO4J_TEST_URI NEO4J_TEST_PASSWORD HST_ESTATE_DEVICES HST_ESTATE_RESULT; do \
	  printenv "$$v" >/dev/null || { echo "$$v is required"; exit 1; }; \
	done
	HST_ESTATE_ACCEPTANCE=1 $(RUN) pytest -q tests/perf/test_estate_acceptance.py

web-check:  ## SPA: lint, typecheck+build, tests
	cd web && npm run lint && npm run build && npm test

coverage:  ## Unit-test coverage, reported not gated
	$(RUN) pytest -n auto --cov --cov-report=term-missing --cov-report=xml

# pip-audit reads the exported lock. Against a synced environment it looks the project
# up on PyPI, and --strict fails on that lookup. --disable-pip and --no-deps skip the
# resolver. npm audit covers the production dependencies only (--omit=dev).
audit:  ## Dependency advisories, both ecosystems
	@tmp=$$(mktemp -d) && trap 'rm -rf "$$tmp"' EXIT; \
	  $(UV) export --frozen --no-emit-project --no-hashes $(EXTRAS) -o "$$tmp/requirements-audit.txt" && \
	  $(UV) tool run --from pip-audit==2.10.1 pip-audit --strict --disable-pip --no-deps -r "$$tmp/requirements-audit.txt"
	cd web && npm audit --omit=dev --audit-level=high

# e2e loads 3 fixture runs into the Neo4j of NEO4J_URI. The guard admits a NEO4J_URI in
# the environment of the run whose endpoint differs from the endpoint that
# core/config.py resolves without it, from .env or from its default. E2E_SCRATCH=1
# skips the guard.
define E2E_GUARD
import os, sys
from hst.core.config import Settings
from hst.core.db import same_endpoint
if os.environ.get("E2E_SCRATCH") == "1":
    sys.exit(0)
uri = os.environ.pop("NEO4J_URI", "")
twin = Settings().neo4j_uri
advice = "Set NEO4J_URI to a scratch database, or set E2E_SCRATCH=1 to load into the twin."
if not uri:
    sys.exit(f"e2e loads 3 fixture runs into Neo4j, and NEO4J_URI is not set for this run. The twin is {twin}. {advice}")
if same_endpoint(uri, twin):
    sys.exit(f"e2e loads 3 fixture runs into Neo4j, and NEO4J_URI ({uri}) is the twin ({twin}). {advice}")
endef
export E2E_GUARD

# validate-demo exits non-zero without the derived edges. Each `hst load-fixture`
# derives them into the run that it builds.
e2e:  ## Load the fixtures, derive edges, validate the scenarios. Scratch Neo4j only.
	@$(RUN) python -c "$$E2E_GUARD"
	$(RUN) hst init-db
	$(RUN) hst load-fixture fixtures/mini-dc.yaml
	$(RUN) hst load-fixture fixtures/mini-enterprise.yaml
	$(RUN) hst load-fixture fixtures/equinix-site.yaml
	$(RUN) hst validate-demo

check: no-run-data lock-check lint typecheck helm-check test web-check  ## Everything that needs no database

enterprise-check:  ## Enterprise tests without DB/PG/perf; native backend is mandatory
	HST_SYMBOLIC_REQUIRE=1 $(ENTERPRISE_RUN) pytest tests/enterprise -m 'not db and not pg and not perf'
	$(RUN) python tools/build_symbolic_wheels.py --check-lock --out-dir /tmp/hst-symbolic-lock-check
	$(RUN) python tools/check_symbolic_licenses.py

enterprise-check-db:  ## Enterprise DB/PG tests against explicitly configured scratch databases
	@HST_SYMBOLIC_REQUIRE=1 $(ENTERPRISE_RUN) pytest tests/enterprise -m 'db or pg'; \
	  code=$$?; [ $$code -eq 0 ] || { [ $$code -eq 5 ] && echo "no enterprise DB/PG tests at this revision"; }

enterprise-build-check:  ## Validate locks/licenses and the supplied qualified native wheel
	@test -n "$(WHEEL)" || { echo "WHEEL is required"; exit 1; }
	$(RUN) python tools/build_symbolic_wheels.py --check-lock --out-dir /tmp/hst-symbolic-lock-check
	$(RUN) python tools/check_symbolic_licenses.py --wheel "$(WHEEL)" --require-qualified-wheel
	HST_SYMBOLIC_REQUIRE=1 $(ENTERPRISE_RUN) pytest tests/enterprise/test_backend_install.py


# --- Local disposable test databases ---------------------------------------------------
# The images, the credentials and the host ports are those of the CI service containers
# (ci.yml). The host ports 7699, 7477 and 5544 differ from the ports of the compose stack.
test-stack:  ## Start disposable Postgres+Neo4j matching the CI service containers (ci.yml). Scratch data only.
	podman run -d --rm --name hst-test-pg -e POSTGRES_USER=hst -e POSTGRES_PASSWORD=citest \
	  -e POSTGRES_DB=hst_test -p 127.0.0.1:5544:5432 postgres:16.15@sha256:f9a7b9ebf6f56201f949db745e47bc423c0f0f8294bafe991cc10bf74b029657
	podman run -d --rm --name hst-test-neo4j -e NEO4J_AUTH=neo4j/citest-password \
	  -p 127.0.0.1:7699:7687 -p 127.0.0.1:7477:7474 neo4j:5.26.33-community@sha256:51d0314ef86074f519003da8dd4daaa9fff72b8479672b742d7cab7f3064e3ed

test-stack-down:  ## Stop and remove both disposable databases (their data goes with them).
	podman rm -f hst-test-pg hst-test-neo4j

check-db: ## The three database suites against the test-stack, with CI's env values.
	HST_TEST_PG_DSN=postgresql+asyncpg://hst:citest@localhost:5544/hst_test $(MAKE) test-pg
	NEO4J_TEST_URI=bolt://localhost:7699 NEO4J_TEST_PASSWORD=citest-password $(MAKE) test-db
	NEO4J_URI=bolt://localhost:7699 NEO4J_PASSWORD=citest-password $(MAKE) e2e


# --- Kubernetes ------------------------------------------------------------------------
# With REGISTRY unset, k8s-image builds the image and side-loads it into the kind node.
# With REGISTRY set, k8s-image builds the image and pushes it to that registry.
#
#   make k8s-image k8s-install INGRESS_NS=ingress-nginx INGRESS_INSECURE_HTTP=true DB_INSECURE=true   # kind
#   make k8s-image k8s-install REGISTRY=harbor.example/hst \
#        INGRESS_CLASS=traefik INGRESS_HOST=hst.example \
#        INGRESS_NS=traefik INGRESS_TLS_SECRET=hst-tls                               # any other cluster
K8S_NS       ?= hst
RELEASE      ?= hst
# The name that `kind create cluster` gives a cluster.
KIND_CLUSTER ?= kind
REGISTRY     ?=
IMAGE_NAME   ?= hst

# A new commit or a changed working tree gives a new tag. A new tag rolls the pods under
# `image.pullPolicy: IfNotPresent`.
GIT_SHA      := $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo nogit)
GIT_DIRTY    := $(shell git status --porcelain --untracked-files=no 2>/dev/null | head -c 1)
GIT_DIFF     := $(shell git diff HEAD 2>/dev/null | git hash-object --stdin | cut -c1-8)
IMAGE_TAG    ?= $(GIT_SHA)$(if $(GIT_DIRTY),-dirty.$(GIT_DIFF))

# With REGISTRY unset the repository is localhost/$(IMAGE_NAME).
IMAGE_REPO   := $(if $(REGISTRY),$(REGISTRY)/$(IMAGE_NAME),localhost/$(IMAGE_NAME))
IMAGE        := $(IMAGE_REPO):$(IMAGE_TAG)

# PLATFORM is the architecture of the cluster nodes. An empty value omits the flag.
# The nodes of a kind cluster have the architecture of the host.
HOST_ARCH := $(shell uname -m | sed -e 's/^x86_64$$/amd64/' -e 's/^aarch64$$/arm64/')
PLATFORM ?= $(if $(REGISTRY),linux/amd64,linux/$(HOST_ARCH))

# With INGRESS_CLASS unset the default IngressClass of the cluster applies. With
# INGRESS_HOST unset the host is hst.localtest.me.
INGRESS_CLASS ?=
INGRESS_HOST  ?=
# k8s-install requires INGRESS_NS, the namespace of the ingress controller. It sets
# networkPolicy.ingressFrom to the pods of that namespace.
INGRESS_NS    ?=
# k8s-install requires one of the two. INGRESS_TLS_SECRET is the name of the
# kubernetes.io/tls Secret of the ingress. It sets ingress.tls.enabled=true and
# auth.cookieSecure=true. INGRESS_INSECURE_HTTP=true installs the ingress on plain HTTP.
INGRESS_TLS_SECRET    ?=
INGRESS_INSECURE_HTTP ?=
# DB_INSECURE=true installs the bundled Neo4j and Postgres without TLS. It sets
# neo4j.acceptInsecure and postgres.acceptInsecure.
DB_INSECURE           ?=
SECRET_NAME   ?= hst-secrets
# The timeout of `helm upgrade --wait`.
HELM_TIMEOUT  ?= 3m
HELM_EXTRA    ?=

k8s-image:  ## Build the image; push to REGISTRY, or side-load into kind when it is unset
	podman build $(if $(PLATFORM),--platform $(PLATFORM)) -f deploy/Containerfile \
	  -t $(IMAGE) --build-arg VCS_REF="$$(git rev-parse --short HEAD)" .
	@set -e; \
	if [ -n "$(REGISTRY)" ]; then \
	  echo "pushing $(IMAGE)"; podman push $(IMAGE); \
	else \
	  echo "REGISTRY is not set, side-loading $(IMAGE) into kind cluster $(KIND_CLUSTER)"; \
	  dir=$$(mktemp -d); trap 'rm -rf "$$dir"' EXIT INT TERM; \
	  podman save -o "$$dir/image.tar" $(IMAGE); \
	  kind load image-archive "$$dir/image.tar" --name $(KIND_CLUSTER) \
	    || { echo "kind load failed, and the nodes do not have $(IMAGE)"; exit 1; }; \
	fi
	@echo "image $(IMAGE)"

k8s-secret:  ## Create the Secret the install needs. Never overwrites an existing one.
	@kubectl get ns $(K8S_NS) >/dev/null 2>&1 || kubectl create ns $(K8S_NS)
	@if kubectl -n $(K8S_NS) get secret $(SECRET_NAME) >/dev/null 2>&1; then \
	  echo "$(SECRET_NAME) exists and stays unchanged."; \
	  echo "Rotating secret-key makes every stored credential and raw snapshot unreadable."; \
	else \
	  secret_key="$$($(RUN) hst secret-key)" || secret_key=""; \
	  neo4j_password="$$($(RUN) python -c 'import secrets;print(secrets.token_urlsafe(24))')" || neo4j_password=""; \
	  postgres_password="$$($(RUN) python -c 'import secrets;print(secrets.token_urlsafe(24))')" || postgres_password=""; \
	  [ -n "$$secret_key" ] \
	    || { echo "'hst secret-key' returned no key. $(SECRET_NAME) is not created."; exit 1; }; \
	  [ -n "$$neo4j_password" ] && [ -n "$$postgres_password" ] \
	    || { echo "The password generator returned no value. $(SECRET_NAME) is not created."; exit 1; }; \
	  printf 'secret-key=%s\nneo4j-password=%s\npostgres-password=%s\n' \
	    "$$secret_key" "$$neo4j_password" "$$postgres_password" \
	    | kubectl -n $(K8S_NS) create secret generic $(SECRET_NAME) --from-env-file=/dev/stdin; \
	fi

k8s-install:  ## Install/upgrade the release. Run k8s-secret first.
	$(if $(INGRESS_TLS_SECRET)$(filter true,$(INGRESS_INSECURE_HTTP)),,$(error k8s-install needs INGRESS_TLS_SECRET=<TLS secret name> or INGRESS_INSECURE_HTTP=true))
	$(if $(INGRESS_NS),,$(error k8s-install needs INGRESS_NS=<namespace of the ingress controller>))
	@kubectl -n $(K8S_NS) get secret $(SECRET_NAME) >/dev/null 2>&1 \
	  || { echo "secret $(SECRET_NAME) is missing from namespace $(K8S_NS). Run 'make k8s-secret'."; exit 1; }
	helm upgrade --install $(RELEASE) $(CHART) -n $(K8S_NS) --create-namespace \
	  --set secrets.existingSecret=$(SECRET_NAME) \
	  --set image.repository=$(IMAGE_REPO) --set image.tag=$(IMAGE_TAG) \
	  $(if $(INGRESS_CLASS),--set ingress.className=$(INGRESS_CLASS)) \
	  $(if $(INGRESS_HOST),--set ingress.host=$(INGRESS_HOST)) \
	  --set-json 'networkPolicy.ingressFrom=[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"$(INGRESS_NS)"}}}]' \
	  $(if $(INGRESS_TLS_SECRET),--set ingress.tls.enabled=true --set ingress.tls.secretName=$(INGRESS_TLS_SECRET) --set auth.cookieSecure=true) \
	  $(if $(filter true,$(INGRESS_INSECURE_HTTP)),--set ingress.acceptInsecureHttp=true) \
	  $(if $(filter true,$(DB_INSECURE)),--set neo4j.acceptInsecure=true --set postgres.acceptInsecure=true) \
	  $(HELM_EXTRA) \
	  --wait --timeout $(HELM_TIMEOUT)

k8s-verify:  ## Prove the deployed release actually serves
	$(RUN) python tools/verify_k8s.py

k8s-uninstall:  ## Remove the release. PVCs holding the twin and the changes log survive.
	helm uninstall $(RELEASE) -n $(K8S_NS)
