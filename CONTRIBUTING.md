# Contributing

## Licensing of contributions

The software is proprietary under [LICENSE](LICENSE). The licence permits a
modification only to prepare a contribution. Pull requests are accepted at the
maintainer's discretion, and only from contributors who agree to the
[Contributor Licence Agreement](CLA.md). To agree, the person who opens the pull
request and every commit author write the sentence from its "How to agree"
section in the pull request description or in a comment on it. A pull request
without it is not merged. The `cla` status on the pull request shows who still
has to write it. The status fails for a commit whose author is not a GitHub
account and for a pull request with more than 250 commits. The repository owner
and the automated accounts that the maintainer configures, such as Dependabot,
are exempt.

## Setup

```
uv sync --frozen --extra dev --extra mcp --extra app --extra sidestore --extra agent
cd web && npm ci
```

`make install` runs both commands.

`--frozen` installs the resolution in `uv.lock` and fails if the lock does not match.
CI and `deploy/Containerfile` install from the same lock. After a dependency change in
`pyproject.toml`, run `uv lock` and commit the result. `make lock-check` is a CI gate.

The lockfile needs uv 0.12 or later. CI pins 0.13.10 in `ci.yml`.
`uv self update` updates a standalone install. Change the CI pin, the uv stage in
`deploy/Containerfile` and the lock in the same commit.

The suite needs all the extras above. With `dev` alone, test collection aborts.
`sidestore` enables the tests that import duckdb or pyarrow. `agent` makes the
provider SDKs importable.

For a database connection, copy `.env.example` to `.env` and set `NEO4J_PASSWORD`.

## Checks

`make check` runs the checks of `.github/workflows/ci.yml` that need no database
and no native symbolic wheel. It needs helm and Node on the host.

```
make check          # the CI checks that need no database and no native symbolic wheel
make help           # the description of each target, generated from the Makefile
```

2 suites need a database. The end-to-end fixture load needs a scratch Neo4j.

```
HST_TEST_PG_DSN=... make test-pg                        # disposable Postgres
NEO4J_TEST_URI=... NEO4J_TEST_PASSWORD=... make test-db    # scratch Neo4j only
NEO4J_URI=... NEO4J_PASSWORD=... make e2e                  # scratch Neo4j only
```

`make test-stack` starts a disposable Postgres and Neo4j with the CI images and
credentials. It calls podman. `make check-db` runs the 2 suites and the fixture
load against them. `make test-stack-down` removes both.

The tests with the marker `pg` skip when `HST_TEST_PG_DSN` is unset. The tests
with the marker `db` skip when `NEO4J_TEST_URI` is unset. With `CI` set, a run
that selects a marker fails when the variable of the marker is unset.

`make e2e` needs the derived edges. `validate-demo` exits non-zero without them. Each
`hst load-fixture` derives into the run that it builds. `hst reason` without a
subcommand exits with an error.

`fixtures/path-a.yaml` is the fixture of the trace acceptance test in
`tests/test_integration_db.py`. It holds the Check Point and NetScaler part of a
path from VyOS through Check Point to NetScaler. The test loads the VyOS part
from a collector normalizer run. The fixture also holds a ZPA layer for the
brokered-access test.

The db and e2e targets are destructive. They run `DETACH DELETE` and reload. The
fixture in `tests/test_integration_db.py` refuses to run against the URI that
`core/config.py` resolves as the live twin. Point the targets at a scratch database.

## Running the app on the host

The deployable forms are the compose stack in `compose.yaml` and the Helm chart
in `deploy/helm/hst`. To run the app on the host, start the pieces directly. The
server needs a Postgres that matches `POSTGRES_DSN` in `.env` and an operator key
in `HST_SECRET_KEY`:

```
podman run -d --name hst-pg -v hst-pg:/var/lib/postgresql/data \
  -e POSTGRES_USER=hst -e POSTGRES_PASSWORD=change-me -e POSTGRES_DB=hst \
  -p 127.0.0.1:5433:5432 postgres:16
uv run hst serve                    # http://127.0.0.1:8787; setup screen on first run
```

The SPA's dev loop, with hot reload against that server:

```
cd web && npm run dev                  # http://127.0.0.1:5173, proxies /api to :8787
```

`npm run build` writes the built SPA to `web/dist`, and `hst serve` serves it from
there. `npm test` runs the component suite with vitest and a fetch mock. It needs
no backend.

## Changing the schema

The schema is versioned and defined in 2 places that must agree:

1. `src/hst/core/labels.py` is the machine-readable registry. The loader rejects
   any label or relationship type that is not in it.
2. `README.md` "Architecture" summarizes the model. It must not contradict the
   registry.

Checklist for a schema change:

- Add the label or relationship to `labels.py`. Set its layer, and set `gate=True` if
  the object can permit, deny or rewrite traffic.
- Bump `SCHEMA_VERSION` in `labels.py`. A breaking change is a major bump.
- Extend one of the fixtures so the new element appears in a loaded graph. Add or
  extend a scenario in `src/hst/demo.py` when the element enables a new kind of
  question.
- For a new `:Gate`, add its evaluation to `src/hst/path/gates/`, or confirm that
  it reports `indeterminate`. A gate the engine cannot evaluate must never render
  as a pass.
- Run the checks.

The loader reserves the property `uid` and every property that starts with `_`. The
normalizer renames a vendor field with such a name.

## Writing a collector

Each management plane has one collector under `src/hst/collectors/`. A collector
is 1 module or a group of modules, as for Check Point. A collector fetches raw
objects without transformation, then normalizes them into `NodeRecord` and
`RelRecord` batches. Rules:

- Use read-only credentials, and the read-only login mode where the management plane
  has one, such as Check Point's `"read-only": true`.
- Release each session that the collector opens.
- Every `Device` uid comes from the device identity registry: call `self.identity.resolve_device`
  with the chassis serial, or with `<source>:<ref>` when the device reports no serial, and with
  the hostname. Do not build a `dev:` uid by hand.
- Never write the derived edges `L3_ADJACENT`, `INTERCONNECTED_BY` and resolved
  `SAME_AS`. The reasoner writes them.
- Set a stable `scope` per partition, for example `apic:fab1`. Retirement depends on it.
- For an SSH collector, open one `ssh.session()` per fetch and run every command over it.
  `ssh.run()` is for the single command of `probe()`.
- Interface names go through `core.normalize.canonical_ifname` and `iface_slug`. Never
  key a dictionary on a raw vendor interface name.
- The 3 templates in `src/hst/collectors/templates/` are changed copies of
  ntc-templates files under Apache-2.0. `NOTICE` in that directory lists them.
- Nothing that this tool produced from real infrastructure goes in the repository:
  raw snapshots, the changes log, the parquet side store, database dumps, collector
  captures, anything sealed with `HST_SECRET_KEY`. This applies to raw, redacted and
  scrubbed data of any size.

  Collector tests use hand-written payloads, for example `tests/test_nxos.py`.
  `tests/test_apic.py::test_first_contact_capture_replays_clean` reads a real capture and
  skips in CI. Keep this skip.

  `make no-run-data` enforces this rule. It also finds files added with
  `git add -f` and files under a relocated `HST_DATA_DIR`. It runs first in
  `make check`. In CI, the job `secrets` runs it.

## Extending assessment workflows

`src/hst/simul/intents.py` records 4 capabilities for each intent kind. A kind is
stored, has engines that simulate it, is generated and is reversible. Set each
capability by itself. The impact evaluator does not support a new stored kind
until its evaluation is added. Save, export and reevaluation must keep the order
of the edits, the target UIDs and the snapshot preconditions.

Add a typed gap code where the gap is produced, in `impact/gaps.py` or at an
unknown terminal step. Leave an explanation without a code unclassified. A
collector recipe must reuse a read operation that the collector has, and must
state the address family, the prerequisites and the full collection scope. Add
tests for a missing section, a missing side table, a failed publication and a
lost permission. A successful fetch alone must not close a reasoning gap.

For new search semantics or failure semantics, add small exhaustive fixtures.
The fixtures must separate these cases:

- unknown and failure
- edits that interact and edits that are not monotone
- 1-minimal sets and inclusion-minimal sets
- bounded findings and proven minima

Run the real evaluator and isolated overlays in the tests. A new failure target
needs route acceptance tests and gate acceptance tests before it is listed as
supported. Change an existing test only when its required behavior changes. Run
`make check`.

## Dependency advisories

`make audit` runs `pip-audit` and `npm audit`. The workflow `audit` runs it each day
and for a pull request that changes a lock file.

The open advisory is in brace-expansion. The dev dependency
`eslint-plugin-jsx-a11y` depends on `minimatch@^3.1.2`, which depends on it. An
override of `brace-expansion` to 5.x or of `minimatch` to 10.x breaks eslint.
Remove this paragraph when jsx-a11y depends on minimatch 4 or later.

## Keeping versions current

No dependency stays more than 1 major version behind the latest release, with 2
exceptions. eslint and @eslint/js stay at 9, because
`eslint-plugin-jsx-a11y@6.10.2` has the peer range `eslint ^3..^9`, and `npm ci`
refuses eslint 10 without `legacy-peer-deps`. typescript stays at 6, because
`typescript-eslint@8.73.0` has the peer range `typescript <6.1.0`.

Re-check with `npm view eslint-plugin-jsx-a11y peerDependencies.eslint` and
`npm view typescript-eslint peerDependencies.typescript`.

Write manifest versions with `npm install <pkg>@latest` and `uv add <pkg>`.
`npm outdated` shows old versions.

Before a version floor is lowered or an override is added, run the tool that
depends on the package.

## Language

Text in this repository follows the sections "Current information only" and
"No AI slop" in [CLAUDE.md](CLAUDE.md).
