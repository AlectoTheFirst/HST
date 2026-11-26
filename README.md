# HST

HST is a digital twin mapper for enterprise networks. The twin is stored as a
graph in Neo4j.

The project is pre-1.0. The software is proprietary, and the licence permits
internal, non-production use. [Status](#status) and [Licence](#licence) have the
details.

HST collects from these sources:

- Cisco ACI through the APIC controller and through Nexus Dashboard Orchestrator
- Cisco NX-OS, IOS-XE and IOS-XR
- VyOS
- VeloCloud SD-WAN
- UniFi Network
- Check Point through the management API and through SSH on the gateways
- NetScaler
- Zscaler ZIA and ZPA
- Equinix Fabric
- Nautobot
- manual device lists for devices without a management platform

The APIC collector reads contracts, service graphs, policy-based redirects and
endpoints. HST has no collector for AWS, Azure, FortiGate, TippingPoint or
vSphere.

Use cases:

- Path tracing takes a source, a destination and a port. The trace returns the
  devices and the policy decisions on the path, including policy-based redirects,
  NAT, load balancer hops, SD-WAN steering and Zscaler.
- Impact analysis finds which applications, sites and services a failed
  device, link, contract or rule affects.
- Policy analysis evaluates a flow against ACI contracts, firewall rulebases and
  ZPA policies. An assessment can require that a flow is isolated, and the result
  states if the isolation holds.
- For operations, HST shows the state of each collected source in one UI.
- For documentation under the Digital Operational Resilience Act (DORA), HST has
  a register of third-party providers and reconstructs the graph as of a past
  date with `hst rebuild --as-of`.

## Architecture

Each collector reads one management plane with the credentials of its source and
stores the raw response in the raw snapshot store. The store is encrypted, and a
written file is not modified. A normalizer converts the raw data into typed
entities. The loader writes the entities to Neo4j under the timestamp of the run
with idempotent merges. Each collection is a separate run, and a published run is
a snapshot. An object that a source does not report is absent from that run, and
`GET /api/diff` reports what appeared and disappeared between 2 runs. The
reasoner runs after the load and creates derived edges such as L2/L3 stitching
and gateway resolution. The path engine traces a flow hop by hop and evaluates
each policy gate on the path. A gate that the engine cannot evaluate is reported
as indeterminate.

Postgres stores user accounts, source configuration, encrypted credentials,
assessment revisions with their analysis jobs and results, the Business
Application catalog, HST AI conversations with their tool steps, AI event
records and personal access tokens.

Routing tables, MAC tables, ARP tables, the OSPF link-state database, the observed
BGP sessions and paths, and Check Point policy envelopes are stored in the side
store. The side store holds parquet files that DuckDB reads. The side store is
not encrypted.

## Analysis engines

The setting `ANALYSIS_ENGINE` selects the engine of the assessments and of the
policy analysis. The default `legacy-v1` is the interval engine. `symbolic-v2`
uses the native symbolic backend that the image holds.

`symbolic-v2` models a network as a symbolic transition system. A routing fixed
point gives the forwarding choices. Packet sets, ordered policies, NAT, session
state, routing and evidence form one model. An analysis answers each request
with success, failure or unknown. The model accepts Check Point policy of
release R81.20.

## Requirements

- HST needs podman or docker with compose support.
- The stack needs at least 10 GB of free RAM. `compose.yaml` caps Neo4j at 3g,
  the app at 4g and Postgres at 1g. The host and the container runtime need more
  memory. `compose.worker.yaml` adds a collection worker capped at 4g. On 1
  installation, a load held about 1.1 GB for an IOS-XE device with a full
  routing table and about 3.6 GB for an NX-OS device with a full routing table.
- The disk holds the twin and the raw snapshots. A keep count bounds the twin,
  and a scheduled job prunes it. The raw snapshots grow without bound while
  `EVIDENCE_RETENTION_DAYS` is unset. With the setting, the raw-store prune
  deletes a raw snapshot that is older than the period and that no retained run
  needs.

## Quick start

```
cp .env.example .env
podman compose up -d --build
```

Set `HST_SECRET_KEY`, `HST_PG_PASSWORD` and `NEO4J_PASSWORD` in `.env` before the
first start. `HST_SECRET_KEY` is the operator key, and
`openssl rand -hex 32` generates one. Keep a copy of the key in a secret store.
[Security](#security) describes the keys. The same commands work with docker
compose.

Open http://localhost:8787. The first visit shows a setup form for the
administrator account. The gear in the top bar opens the settings. Add a
group on the Groups page or an orchestrator on the Orchestrators page. A group is
a source with a list of hosts that share credentials. An orchestrator is a
management platform that reports its own devices. Start a run on the Runs page,
and trace a flow in the Trace view.

The application port 8787 and the Neo4j ports are bound to the loopback
interface. Postgres publishes no port.

### Commands and settings in the compose stack

In the compose stack, the `hst` commands run in the `app` container:

```
podman compose exec app hst --help
```

The `app` container gets a setting only if `compose.yaml` names it. For any other
setting of `src/hst/core/config.py`, add an `environment` entry to a file
`compose.override.yaml` next to `compose.yaml`. A setting that names a file also
needs a mount of that file. Compose loads `compose.override.yaml` only when the
command names no file with `-f`. With `compose.worker.yaml`, name
`compose.override.yaml` as the third `-f` file and give the `worker` service the
same entries. `hst serve` on the host reads `.env`, and the Helm chart takes
these settings through `app.extraEnv`.

### Demo estate

The image holds a synthetic estate in `/usr/share/hst/demo-enterprise`. It needs
no network hardware. This `compose.override.yaml` turns the demo load on:

```
services:
  app:
    environment:
      HST_DEMO_FIXTURES: /usr/share/hst/demo-enterprise
```

On the Runs page, an admin then has the card "Demo estate" with the button "Load
demo estate". The load publishes 3 runs, creates the demo sites and imports 5
Business Applications.
[fixtures/demo-enterprise/README.md](fixtures/demo-enterprise/README.md)
describes the estate.

### Kubernetes

```
make k8s-secret k8s-image k8s-install k8s-verify INGRESS_NS=ingress-nginx INGRESS_INSECURE_HTTP=true
```

The command installs on the kind cluster with the name `kind`, with the ingress
on plain HTTP. `KIND_CLUSTER` sets another cluster name. The targets call podman,
kind, kubectl, helm and uv. The cluster needs an ingress controller, and
`INGRESS_NS` is its namespace. Without `REGISTRY`, the image has the
architecture of the host. On any other cluster, set `REGISTRY`, and set
`INGRESS_TLS_SECRET` to the name of the TLS Secret of the ingress.
[deploy/helm/hst/README.md](deploy/helm/hst/README.md) describes the registry,
the ingress and the chart values.

## Backups

```
mkdir -p backups
podman compose --profile backup run --rm backup
podman compose stop neo4j
podman compose --profile backup run --rm backup-neo4j
podman compose start neo4j
```

The `backup` service writes a Postgres dump to `backups/`. The `backup-neo4j`
service writes a Neo4j dump to `backups/`. The `backup-neo4j` service needs a
stopped Neo4j. The 2 dumps are not encrypted. The volume `hst-data` holds the raw
snapshots, the side store and the wrapped data key. No backup service copies the
volume `hst-data`. A restore needs the operator key `HST_SECRET_KEY`. With docker
compose, remove `:U` from the 2 `backups` bind mounts in `compose.yaml`.
[deploy/helm/hst/README.md](deploy/helm/hst/README.md) describes the backup of a
Kubernetes install.

## Place data

The site address field looks places up in a table that ships empty.
[GeoNames](https://download.geonames.org/export/zip/) publishes postal code files
under CC BY 4.0. To fill the table, download `allCountries.zip` or the zip file
of 1 country and load it:

```
hst geo-places load allCountries.zip
```

With `GEO_PLACES_FILE` set to the path of the file, the app loads the file at
start-up, once per file. In the compose stack, mount the file into the `app`
container and use the path in the container. The app makes no external request
for the file or for a lookup.

## Interfaces

- The web UI has flow tracing with per-gate verdicts, a graph explorer with canned
  queries and read-only Cypher, Business Applications, change simulation, HST AI
  and settings pages. The settings pages are Runs, Groups, Devices, Sites,
  Orchestrators, Users, AI agent, Authentication, Lifecycle and Access tokens.
- The CLI command `hst` manages sources, runs, traces, point-in-time
  rebuilds, key rotation and users. `hst --help` prints the full list.
- The MCP server gives the tool catalogue to LLM clients over the Model Context
  Protocol. The tools cover runs and snapshot diffs, inventory, routing, policy,
  NAT and load-balancer lookups, path traces and MTU audits, change impact and
  simulation, Business Applications, saved assessments, evidence gaps, the graph
  schema, the named query catalog and read-only Cypher.
  - `uv run hst mcp` runs the server on stdio.
  - `/api/mcp` serves the same tools over HTTP after an admin enables it. A
    client authenticates with a personal access token and gets the permissions
    of the token's user.
  - `hst mcp --remote URL` connects a stdio client to `/api/mcp`.
  - The repository `.mcp.json` connects Claude Code to `/api/mcp`. It reads
    `HST_MCP_URL`, the `https://<host>/api/mcp` of the instance, and
    `HST_MCP_TOKEN`, a personal access token of that instance, from the
    environment that Claude Code starts in.
- The REST API under `/api` uses session cookie authentication and 3 roles:
  viewer, operator and admin. The read-only GraphQL endpoint `/api/graphql` takes
  the session cookie or a personal access token.

## Saved assessments

Open "Analysis" in the web UI and then the section "Assessments". Choose the
question: "Check a service", "Troubleshoot a service", "Explain what changed",
"Find a safe repair", "Test service resilience" or "Verify a deployment". Choose a
service by name or discover it from a URL, IP, location or application. Browse
groups when the name is unfamiliar. Select a recorded snapshot, choose the
relevant scope, then review and start. Protected services and failure targets
are selected by name. A permitted change to a shared policy needs the recorded
owner of the policy.

The optional "Prepare with AI" uses the configured provider to
suggest a workflow, ask for missing clues and find recorded objects. A known
traffic form covers services absent from the catalog. The user selects the matches
and reviews the same guided form before the run.

A result lists the unknowns, the excluded candidates, the snapshots and the
search bounds. A saved proposal revision keeps its verified evidence. A portable
package restores the snapshots of an assessment into an empty Neo4j target for a
replay. The analysis engine evaluates connectivity and constraints. AI drafting
does not collect evidence, and an assessment does not deploy a repair proposal.

## HST AI

HST AI is optional and needs a model provider, which an admin configures in
the AI settings. The supported providers are Anthropic, Amazon Bedrock and
OpenRouter.

HST AI answers questions about the recorded network. It opens from the top
bar on every page and inside change simulation. Each answer uses the tool
catalogue that the MCP server exposes, within the permissions of the user. A
tool call reads the recorded run of the question unless the call names another
retained run, and the answer lists each other run that it read. The context is the device, flow, finding, application
or run that is selected on the page. The server checks each of these objects
against the run before the model receives it.

Conversations are stored per user and continue after a reload. An answer cites
the tool steps it used, and the statements that no tool step supports are
counted under the answer. Simulation results appear as cards, and a user with
`changes.write` can save one as an analysis session. A finding or an analysis
result opens a conversation with that object as its context.

A Business Application can be drafted from a description. The generator
resolves the named objects against one run, writes each unresolved object as a
placeholder, and returns the YAML with its validation result. The user saves
each draft.

HST AI cannot collect evidence or deploy changes. Each tool call is stored as an
AI event record. Stored conversations, step results and event records have
retention limits in the lifecycle settings.

## Security

The operator key `HST_SECRET_KEY` wraps a data key. The data key encrypts
credentials and raw snapshots. `hst rotate-secret-key` replaces the operator key
without re-encryption of the data. HST has no external vault integration.

Authentication uses local accounts with argon2id password hashing, or single
sign-on through SAML 2.0 or OIDC. Single sign-on needs `HST_PUBLIC_URL`, the
origin that users reach. Local login can be turned off only while an enabled
single sign-on provider can sign a user in. While local login is off, the last
such provider cannot be disabled or deleted.

Personal access tokens authenticate MCP clients on `/api/mcp` and clients of the
read-only GraphQL endpoint `/api/graphql`. A token has the scope `read` or
`read-write` and the permissions of its user. Only its hash is stored.

In a portable assessment package, the graph archives, the side-store tables and
the result artifacts are sealed under a package key. The package key is derived
from the data key and opens only that package. The raw snapshots in the package
are encrypted under the data key. The assessment document and the manifests in
the package are not encrypted.
`hst assessments export --portable --package-key-file PATH` writes the package
key, and `hst assessments replay FILE --into URI --package-key-file PATH` reads
it.

The application serves plain HTTP by default. Put a TLS terminator in front of
it, or set `TLS_CERT_FILE` and `TLS_KEY_FILE` so that `hst serve` terminates TLS
itself. Behind a TLS terminator, set `HST_FORWARDED_ALLOW_IPS` to the address of
the terminator.

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Development

```
make install     # uv sync --frozen and npm ci in web/
make check       # the CI checks that need no database and no native symbolic wheel
make test-stack  # disposable Postgres and Neo4j containers
make check-db    # database test suites against the test stack
make e2e         # fixture load, derived edges, scenario checks on a scratch Neo4j
```

`make check` needs helm and Node on the host. `make test-stack` and
`make k8s-image` call podman. CI also runs the database suites, the tests that
need the native symbolic wheel, an image build and a secret scan.

`make e2e` loads 3 fixtures into a scratch Neo4j instance, derives the edges and
validates 20 scenarios. This needs no network hardware.

The backend uses Python 3.13 or later, FastAPI and pydantic v2. CI runs the
tests on Python 3.14. The frontend in `web/` uses React 19 and TypeScript.
[CONTRIBUTING.md](CONTRIBUTING.md) has the setup and the checklists for schema
changes and new collectors. The docs in [docs/](docs/) describe the storage, the
graph schema, the collectors and the code flow.

## Status

The project is pre-1.0. The schema is versioned. There are no compatibility
guarantees before the first tagged release.

The path engine has these limits:

- When 2 or more routers of an MPLS transport path, members of a load balancer
  pool or zones of an interface are equal candidates, the trace follows the
  candidate with the lowest uid.
- On the far PE of an L3VPN, the trace evaluates the ingress ACL, the NAT role
  and the zone pair on the CE-facing interface.

The design target of the collection engine is 5,000 to 10,000 devices:

- A source is either a group with a fleet of hosts or an orchestrator that
  discovers its own devices and reports where each sits. `hst devices import`
  and `PUT /api/sources/{name}/devices` set the hosts of a group.
- With `RUN_EXECUTION=queue`, a run is a job on a Postgres-backed queue in
  `src/hst/worker/`. The default `inline` starts a run in the API process. The
  scheduler of the worker queues one fetch job per device at the collection
  interval of the device, with per-device failure backoff.
- SSH uses the asyncssh transport in `src/hst/collectors/assh.py` by default,
  with paramiko as a second transport.
- The `COLLECT_*` settings in `src/hst/core/config.py` bound concurrency, load,
  queue depth and backoff. `COLLECT_FETCH_BUFFER` with `COLLECT_SPILL_MB` bounds the
  fetch-to-load memory of a cycle, `COLLECT_MAX_ANSWER_MB` bounds one SSH answer
  and one HTTP response, and `SIDESTORE_ROW_GROUP_ROWS` bounds the row-group size
  of each parquet write.
  [Commands and settings in the compose stack](#commands-and-settings-in-the-compose-stack)
  states how a setting gets into a container.

No test has run against a fleet of that size. The 2 opt-in benchmarks are
`hst bench fleet` and `hst bench estate`. `hst bench fleet` measures one
collection cycle over a fake fleet of 1,000 devices by default.
`hst bench estate` measures the write, the digest, the lookup and the checkpoint
of a synthetic estate. Its defaults are 100 devices and 1,000 routing table rows
for each device, which is less than a full Internet routing table. No test
covers a full Internet routing table, the BGP paths of each peer or the cost of
a simulation at that size.

## Licence

The software is proprietary, and all rights are reserved. The licence permits
reading the source and running the software for internal, non-production use, at
the risk of the user. The licence forbids the use of the software for a competing
product and for the training or evaluation of a machine learning model.
Production use needs a written grant from the copyright holder. Requests go to
strata-sec@xmx.starkweb.io. No support is owed. [LICENSE](LICENSE) states what is
permitted. Contributions come under [CLA.md](CLA.md).
