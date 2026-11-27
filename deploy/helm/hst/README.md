# hst Helm chart

The chart installs HST on Kubernetes with the same three services as the supported
single-host compose stack in `compose.yaml`.

## What it deploys

| Resource | Purpose |
|---|---|
| `Deployment` | the API and the built SPA |
| `Deployment` worker | `hst worker`: the scheduler, the job executor and every collection run, when `worker.enabled`. See "Collection worker" |
| `StatefulSet` postgres | identity, source config, run history. `postgres.enabled=false` for an external Postgres |
| `StatefulSet` neo4j | the twin. `neo4j.enabled=false` for an external Neo4j |
| `Job` migrate | Alembic, once per release, gating the app rollout |
| `Job` initdb | `hst init-db`: Neo4j constraints and the fulltext index |
| `NetworkPolicy` | the pods of the release reach bolt and Postgres. The peers in `networkPolicy.ingressFrom` reach port 8787 of the app pod. No peer reaches the worker, backup, migrate and initdb pods |
| `Ingress` | every host in `ingress.host` + `extraHosts`; the SPA and `/api` share an origin |
| `PodDisruptionBudget` | app pods, when `podDisruptionBudget.enabled` |

## Install

The chart creates no secrets. Create them out of band:

```
kubectl create ns hst
kubectl -n hst create secret generic hst-secrets \
  --from-literal=secret-key="$(hst secret-key)" \
  --from-literal=neo4j-password='...' \
  --from-literal=postgres-password='...'
kubectl -n hst create secret tls hst-tls --cert=tls.crt --key=tls.key

helm upgrade --install hst deploy/helm/hst -n hst \
  --set secrets.existingSecret=hst-secrets \
  --set ingress.host=hst.example.com \
  --set ingress.tls.enabled=true --set ingress.tls.secretName=hst-tls \
  --set auth.cookieSecure=true \
  --set-json 'networkPolicy.ingressFrom=[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"ingress-nginx"}}}]' \
  --wait
```

The chart refuses to render an ingress without TLS. `ingress.acceptInsecureHttp=true`
installs the ingress on plain HTTP.

`networkPolicy.ingressFrom` takes the namespace or the pods of the ingress controller.
The chart refuses to render `app.forwardedAllowIps` without a peer. See "Access to the
app pod".

A deployment with no accounts serves a setup screen and no login form. Enter an
administrator username and password there. The screen is gone once any account exists.

The CLI does the same, and is idempotent:

```
kubectl -n hst exec -it deploy/hst -- hst user create-admin
```

Prefer `secrets.existingSecret` over the inline `secrets.secretKey`.

`HST_SECRET_KEY` cannot be regenerated. It wraps the data key that seals every stored
source credential and every raw snapshot. The app pods read it from a mounted file
(`HST_SECRET_KEY_FILE`). The chart does not generate one. Keep it in a secret store. To
rotate it, run `hst rotate-secret-key` inside an app pod, then update the Secret.

### Rotating the database passwords

A change of `neo4j-password` or `postgres-password` in the Secret does not rotate the
databases. A bare `helm upgrade` then locks the app out. The Neo4j image applies
`NEO4J_AUTH` only when `/data` is empty. Postgres applies `POSTGRES_PASSWORD` only at
initdb.

Rotate the server side first, then the Secret, in this order:

```
# 1. Postgres: change the role password on the running server
kubectl -n hst exec statefulset/<release>-postgres -- \
  psql -U hst -d hst -c "ALTER USER hst WITH PASSWORD '<new>';"

# 2. Neo4j: change the neo4j user's password on the running server
kubectl -n hst exec statefulset/<release>-neo4j -- \
  cypher-shell -u neo4j -p '<old>' \
  "ALTER CURRENT USER SET PASSWORD FROM '<old>' TO '<new>';"

# 3. Update the Secret to match, then upgrade so the app picks up the new values
kubectl -n hst create secret generic hst-secrets \
  --from-literal=secret-key="$(...)" \
  --from-literal=neo4j-password='<new>' \
  --from-literal=postgres-password='<new>' \
  --dry-run=client -o yaml | kubectl apply -f -
helm upgrade <release> deploy/helm/hst ...
```

If the Secret changed before the servers, set the Secret back to the old values, run
steps 1 and 2, then re-apply the new Secret.

### External Postgres

With `postgres.enabled=false` the pods read `POSTGRES_DSN` from the key `postgres-dsn` of
the Secret. With `secrets.existingSecret`, that Secret holds the key `postgres-dsn`.

```
kubectl -n hst create secret generic hst-secrets \
  --from-literal=secret-key="$(hst secret-key)" \
  --from-literal=neo4j-password='...' \
  --from-literal=postgres-password='...' \
  --from-literal=postgres-dsn='postgresql+asyncpg://user:pass@host:5432/db'

helm upgrade --install hst deploy/helm/hst -n hst \
  --set secrets.existingSecret=hst-secrets \
  --set postgres.enabled=false \
  --set postgres.tls.enabled=true --set postgres.tls.caSecret=postgres-ca \
  ...
```

The chart refuses `postgres.externalDsn` together with `secrets.existingSecret`. It
refuses `postgres.tls.enabled=false` with that Secret unless
`postgres.acceptInsecure=true`.

With an empty `secrets.existingSecret` the chart-rendered Secret holds
`postgres.externalDsn` under the key `postgres-dsn`.

## Differences from compose

### Migrations

The app applies Alembic on start-up when `HST_RUN_MIGRATIONS` is true. The chart sets it
false, runs `hst migrate` in a Job, and holds the app pods behind an init container running
`hst migrate --check`. After a failed migration the app pods do not start.

### Database access

`networkPolicy.enabled`, on by default, controls access to the databases. Bolt is
unencrypted unless `neo4j.tls.serverSecret` is set. The CNI must enforce NetworkPolicy.
Verify that ingress is blocked:

```
kubectl -n hst run np-probe --rm -i --restart=Never --image=busybox:1.36 -- \
  sh -c 'nc -z -w3 hst-neo4j 7687 && echo REACHABLE || echo blocked'
```

The neo4j and postgres policies also have an Egress rule restricted to DNS (port 53).
Verify it from inside one of the pods:

```
kubectl -n hst exec statefulset/hst-postgres -- \
  sh -c 'nc -z -w3 1.1.1.1 443 && echo REACHABLE || echo blocked'
```

`blocked` confirms enforcement. `REACHABLE` means that the CNI does not enforce Egress.

### Access to the app pod

With a peer in `networkPolicy.ingressFrom` the chart renders a NetworkPolicy for the app
pod. The policy admits those peers to port 8787. The peers are standard NetworkPolicy
`from` entries:

```
networkPolicy:
  ingressFrom:
    - namespaceSelector:
        matchLabels: {kubernetes.io/metadata.name: ingress-nginx}
```

The app accepts `X-Forwarded-For` and `X-Forwarded-Proto` from every address in
`app.forwardedAllowIps`. The default list is the private and loopback ranges, so the
policy is the bound of that trust. The chart refuses to render with
`app.forwardedAllowIps` set and without `networkPolicy.enabled=true` and a peer.
`app.forwardedAllowIps=""` renders without a peer. The app then trusts no proxy, and every
pod in the cluster reaches port 8787.

A NetworkPolicy does not block traffic from the node of a pod, so the kubelet probes need
no peer. An ingress controller on the host network is no pod peer. It needs an `ipBlock`
with the node addresses.

Verify that another pod is blocked:

```
kubectl -n hst run np-probe --rm -i --restart=Never --image=busybox:1.36 -- \
  sh -c 'nc -z -w3 hst 8787 && echo REACHABLE || echo blocked'
```

### Probes

`/api/readyz` reports Postgres only and takes a pod out of the Service. `/api/livez`
checks no backend and restarts the pod.

`/api/analysis/readyz` is an authenticated operator preflight. With
`ANALYSIS_ENGINE=symbolic-v2`, it verifies the installed native backend against the image's
build stamp, including Python ABI, platform, source, wheel, and extension hashes. It returns
503 when analysis is disabled or that verification fails. Keep the pod readiness probe on
`/api/readyz`.

## 404 from the ingress

An Ingress matches on the `Host` header. With only `ingress.host` set,
`http://localhost:<port>` returns a 404 from the ingress controller while every pod is
healthy. `ingress.extraHosts` defaults to `[localhost]`.

An IP literal cannot be an Ingress host, and `http://127.0.0.1:<port>` never matches.
Use `localhost`, a name, or bypass the ingress:

```
kubectl -n hst port-forward svc/hst 8787:8787
```

On kind, the node publishes the ingress controller's ports on the host. Check which:

```
podman inspect <cluster>-control-plane --format '{{json .HostConfig.PortBindings}}'
```

## Values

| Value | Default | Notes |
|---|---|---|
| `secrets.existingSecret` | `""` | Preferred. Needs keys `secret-key`, `neo4j-password`, `postgres-password`. Needs the key `postgres-dsn` with `postgres.enabled=false` |
| `image.buildRevision` | `""` | Leave empty. The image stamps its own git SHA; setting this overrides it |
| `app.replicaCount` | `1` | Safe above 1. Migrations run in a Job. A per-source Postgres advisory lock claims the collection of a source. A second advisory lock serializes each cycle and refresh across pods |
| `app.resources` | requests `100m`/`256Mi`, limits `2`/`4Gi` | Without the worker, every collection run executes in the app pod under this limit. A load holds about 1.1 GB for an IOS-XE full-table device and about 3.6 GB for an NX-OS one. `analysis.profile=enterprise` raises the memory limit to `6Gi` for its analysis worker, unless `app.resources.limits.memory` is higher |
| `auth.cookieSecure` | `false` | Set true only with TLS. A browser sends no Secure cookie over HTTP. True without TLS breaks login |
| `app.publicUrl` | `""` | The origin that users reach (`HST_PUBLIC_URL`), for example `https://hst.example.net`, with no path. SAML and OIDC sign-in need it. Empty with `ingress.enabled=true` gives `https://<ingress.host>` when `ingress.tls.enabled` is true and `http://<ingress.host>` otherwise |
| `app.forwardedAllowIps` | private and loopback ranges | `HST_FORWARDED_ALLOW_IPS` of the app pod, set only with `ingress.enabled=true`. It lists the proxies whose `X-Forwarded-For` and `X-Forwarded-Proto` the app accepts. A value requires `networkPolicy.enabled=true` and a peer in `networkPolicy.ingressFrom`. The ingress must replace the `X-Forwarded-For` of a client. `""` trusts no proxy. An entry in `app.extraEnv` replaces the value, and the chart does not check that entry |
| `networkPolicy.ingressFrom` | `[]` | The NetworkPolicy `from` peers that reach port 8787 of the app pod: the pods of the ingress controller. Empty renders no policy for the app pod. See "Access to the app pod" |
| `networkPolicy.dnsTo` | `[]` | The `to` peers of the DNS egress rule of the databases. Empty allows port 53 to any host |
| `neo4j.tls.serverSecret` / `postgres.tls.serverSecret` | `""` | Opt-in TLS listener of the bundled database: a `kubernetes.io/tls` Secret whose certificate names `<fullname>-neo4j` / `<fullname>-postgres`. Requires `tls.enabled=true` and `tls.caSecret` for the same database |
| `app.persistence.enabled` | `true` | Raw snapshots. The PVC has `resource-policy: keep` and survives `helm uninstall` |
| `neo4j.heap` / `pagecache` | `1G` | Sized against the container limit. When unset, the JVM sizes them from the RAM of the node |
| `postgres.externalDsn` | `""` | Required when `postgres.enabled=false` and `secrets.existingSecret` is empty |
| `neo4j.externalUri` | `""` | Required when `neo4j.enabled=false` |
| `image.digest` | `""` | `sha256:<digest>`. Wins over `image.tag`. See "Pinning by digest" |
| `imagePullSecrets` | `[]` | Required for a private registry. See "Private registries" |
| `demo.fixtures` | `""` | A demo instance only: `/usr/share/hst/demo-enterprise`, the folder the image holds the synthetic demo estate in. Set, an admin can load the estate from the Runs page as a `demo` run (fixtures/demo-enterprise/README.md). A value requires `analysis.profile=enterprise`; the render fails otherwise. Leave it empty on any other instance |
| `analysis.profiles.<name>.clockQuality` / `clockAssumption` | `unknown` / `""` | The collector host's clock declaration (`COLLECTOR_CLOCK_QUALITY`, `COLLECTOR_CLOCK_ASSUMPTION`), set in both pods. `trusted` requires the assumption that states the basis for the trust; the render fails otherwise |
| `analysis.profiles.<name>.evidenceMaxAgeSeconds` / `evidenceMaxSkewSeconds` / `evidenceConsistency` / `evidenceStableWindowAssumption` | `3600` / `300` / `bounded-window` / `""` | The symbolic analysis's evidence policy (`ANALYSIS_EVIDENCE_*`). `stable-window-assumption` requires its assumption |
| `app.extraEnv` / `app.envFrom` | `[]` | Anything `core/config.py` reads that the chart does not model |
| `ANALYSIS_CACHE_MB` through `app.extraEnv` | `10240` | Physical encrypted compiled-artifact quota on the data volume, with shared blobs counted once. Size the PVC above this quota plus retained raw snapshots; it is not an in-memory allocation |
| `ANALYSIS_MEMORY_MB` through `app.extraEnv` | `1024` | Address-space limit for each isolated analysis worker. Leave container memory headroom for the API process, queues, and native-library overhead; a 1 GiB worker needs a container limit above 1 GiB |
| `migrations.waitAttempts` | `200` | Maximum polls of the init container. After the last poll, the pod fails and does not stay in `Init:0/1` |
| `migrations.resources` | requests `50m`/`128Mi`, limits `1`/`512Mi` | The `migrate` container and the init containers `wait-for-postgres` and `wait-for-migrations` |
| `initDb.resources` | requests `50m`/`128Mi`, limits `1`/`512Mi` | The `initdb` container and the init container `wait-for-neo4j` |
| `podDisruptionBudget.enabled` | `false` | App pods only. `minAvailable: 1` against `replicaCount: 1` blocks every node drain |
| `backup.enabled` | `false` | Adds the immutable S3 recovery-set CronJob. See "Backups" |
| `backup.s3.endpoint` | `""` | An `https://` URL. The schema refuses any other scheme |
| `backup.s3.secretName` | `""` | Needs keys `accessKey`, `secretKey` |
| `backup.recoverySecretName` | `""` | Secret with `encryption-key`. The key encrypts the operator key, the configuration and the Postgres dump of each set |
| `backup.resources` | requests `50m`/`64Mi`, limits `500m`/`256Mi` | The `dump` and `upload` containers |
| `backup.recoveryResources` | requests `100m`/`256Mi`, limits `1`/`1Gi` | The `prepare` and `finalize` containers |
| `podSecurityContext` | uid/gid `10001` | The uid, the gid and the fsGroup of the application. The app Deployment, the worker Deployment and the backup CronJob read it |
| `worker.enabled` | `false` | Collection in its own Deployment. See "Collection worker" |
| `worker.resources` | requests `250m`/`1Gi`, limits `2`/`4Gi` | The worker's own limit; a run that exceeds it ends the worker, not the API |

`values.schema.json` validates all of this at install time, and rejects keys it does not
know.

Neo4j runs one replica, and the count is not configurable.

## Collection worker

By default the app pods run the scheduler, the job executor and every collection run
beside the API, under the app container's memory limit. `worker.enabled=true` moves them
to a second Deployment, `<release>-worker`, running `hst worker` (the scheduler and
the executor, no HTTP server) under `worker.resources`. The app pods then get
`SCHEDULER_ENABLED=false` and `RUN_EXECUTION=queue`: they serve requests, and a run an
operator triggers becomes a `collect.run` job the worker executes. A worker killed for
memory ends the run it was executing; the API keeps serving.

The worker has no Service and no probes: it listens on nothing, and the kubelet restarts
the container when the process exits. It waits for the migration Job as the app pods do,
mounts the same Secret and data volume, and receives `app.extraEnv` followed by
`worker.extraEnv`, and `app.envFrom` followed by `worker.envFrom`. On SIGTERM it cancels
the runs it is executing. A cancelled run waits for its builder thread, which stops before
its next device's load, between the stages of the load in flight or before the next row
group of the side table it writes, and whose SSH collectors stop before their next
command, the devices of a fetch window in flight included; a command already sent ends at
its answer or its read timeout. One still running after 60 s is logged at ERROR and
waited for. `worker.terminationGracePeriodSeconds` (90)
covers those 60 s; the kill at its end ends a thread that has not stopped, and the run
row then reads `orphaned by crash` once a worker starts again.

Both pods mount the data volume, so its access mode decides placement:

- `ReadWriteOnce` (the default) attaches the volume to one node. The worker is required
  onto the app pod's node, as the backup CronJob is, and the app pod prefers the
  worker's node. The worker's resource requests must fit on that node beside the app
  pod, and the worker must tolerate that node's taints, or the worker stays Pending;
  `worker.tolerations` left empty takes `app.tolerations`. If the app pod is
  rescheduled to another node while the worker runs, the new app pod waits on the
  volume until the worker pod stops.
- `ReadWriteMany` places the worker like any other pod.
- `ReadWriteOncePod` and `app.persistence.enabled=false` cannot be shared between pods,
  and the chart refuses to render either with the worker enabled.

`worker.affinity` replaces the default placement. The worker package imports no FastAPI
module, and the worker process opens no port.

## Deploying

The targets work against any cluster. Which path the image takes is decided by
`REGISTRY`.

Local kind side-loads the image into the node, with `image.pullPolicy: IfNotPresent`:

```
make k8s-secret     # once: generates the app key and the DB passwords
make k8s-image      # podman build, save, kind load
make k8s-install INGRESS_NS=ingress-nginx INGRESS_INSECURE_HTTP=true
make k8s-verify     # checks that the deployment serves
```

Any other cluster: build for the architecture of the cluster, push to a registry it
can pull from, and name the ingress it runs and the TLS Secret of the ingress:

```
make k8s-secret
make k8s-image   REGISTRY=harbor.example/hst
make k8s-install REGISTRY=harbor.example/hst \
                 INGRESS_CLASS=traefik INGRESS_HOST=hst.example \
                 INGRESS_NS=traefik INGRESS_TLS_SECRET=hst-tls
make k8s-verify
```

`make k8s-install` requires `INGRESS_NS`, the namespace of the ingress controller. It sets
`networkPolicy.ingressFrom` to the pods of that namespace.

`make k8s-install` requires `INGRESS_TLS_SECRET` or `INGRESS_INSECURE_HTTP=true`.
`INGRESS_TLS_SECRET` sets `ingress.tls.enabled`, `ingress.tls.secretName` and
`auth.cookieSecure`. `INGRESS_INSECURE_HTTP=true` sets `ingress.acceptInsecureHttp`.

`PLATFORM` must match the architecture of the cluster nodes. With `REGISTRY` set it
defaults to `linux/amd64`. Without `REGISTRY` it defaults to the architecture of the host.
`KIND_CLUSTER` is the name of the kind cluster that `make k8s-image` loads the image
into. It defaults to `kind`.

Other variables: `K8S_NS`, `RELEASE`, `SECRET_NAME`, `IMAGE_NAME`, `IMAGE_TAG`,
`HELM_TIMEOUT` (3m), and `HELM_EXTRA` for any `--set` the targets do not cover:

```
make k8s-install INGRESS_NS=traefik INGRESS_TLS_SECRET=hst-tls \
  HELM_EXTRA='--set app.replicaCount=2 --set podDisruptionBudget.enabled=true'
```

`make k8s-secret` never overwrites an existing Secret. It creates no Secret when a
generated value is empty.
`make k8s-install` refuses to run when the Secret is absent.

### A rebuild rolls

`IMAGE_TAG` is `git rev-parse --short=12 HEAD`, plus a hash of the uncommitted diff when
the working tree is dirty. A changed tree gives a changed tag and a rollout under
`image.pullPolicy: IfNotPresent`. `make k8s-image` prints the tag it built.

### Private registries

A registry that requires credentials, such as Harbor, needs a pull Secret. The
chart applies `imagePullSecrets` to every pod it creates:

```
kubectl -n hst create secret docker-registry harbor-pull \
  --docker-server=harbor.example \
  --docker-username='robot$hst+deploy' \
  --docker-password='<robot token>'

make k8s-install REGISTRY=harbor.example/hst INGRESS_NS=traefik INGRESS_TLS_SECRET=hst-tls \
  HELM_EXTRA='--set imagePullSecrets[0].name=harbor-pull'
```

Use a project-scoped robot account with push and pull on that project alone.

### Pinning by digest

`image.digest` overrides `image.tag`. Set it on a production install:

```
make k8s-install REGISTRY=harbor.example/hst INGRESS_NS=traefik INGRESS_TLS_SECRET=hst-tls \
  HELM_EXTRA='--set image.digest=sha256:<digest>'
```

The `release` workflow prints the digest of every image it pushes to the run summary.

### Registry provenance

`.github/workflows/release.yml` is run by hand (`workflow_dispatch`) and pushes
`ghcr.io/<owner>/<repository>:<git-sha>` for `linux/amd64`. The job authenticates with
the workflow's own `GITHUB_TOKEN`; it needs no registry secret.

- The image is scanned with Trivy before it is pushed to the registry.
- The digest is signed with cosign, and the SPDX SBOM is attached as an attestation.
  The image gets its tag after the scan, the signature and the attestation.
- A candidate image and a stable image from `main` have the same certificate identity.
  The identity proves that `release.yml` on `main` built the digest.
- The `stable` channel is accepted on `main` only. It runs the `ci` workflow against the
  commit and verifies the certificate identity of the digest. It then signs the digest a
  second time with the annotation `channel=stable` and tags it `stable-<git-sha>`, and
  with the release version when the commit carries a matching `v*` tag.
- The signature of a stable image verifies with this command:

  ```
  cosign verify \
    --certificate-identity https://github.com/AlectoTheFirst/HST/.github/workflows/release.yml@refs/heads/main \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    -a channel=stable \
    ghcr.io/alectothefirst/hst@sha256:<digest>
  ```

  Without `-a channel=stable`, the command also accepts a candidate image from `main`.
- A package on ghcr.io is private after its first push. Make it public, or give the
  cluster a pull secret (`imagePullSecrets`).

## Backups

Off by default (`backup.enabled: false`). Enabling it adds one ordered CronJob.
It selects the committed graph pointer under the collection lock, stages the
manifest's exact graph archive and evidence, dumps Postgres, then uploads every
file under a new immutable `sets/<job-uid>/` prefix.

```
kubectl -n hst create secret generic hst-backup-s3 \
  --from-literal=accessKey='...' --from-literal=secretKey='...'
kubectl -n hst create secret generic hst-backup-recovery \
  --from-literal=encryption-key="$(openssl rand -base64 32 | tr '+/' '-_')"

helm upgrade hst deploy/helm/hst -n hst --reuse-values \
  --set backup.enabled=true \
  --set backup.s3.endpoint=https://s3.example.com \
  --set backup.s3.bucket=hst-backups \
  --set backup.s3.secretName=hst-backup-s3 \
  --set backup.recoverySecretName=hst-backup-recovery
```

The recovery record is uploaded last, after object-store HEAD checks confirm the
digest metadata and length of every exact object. The configuration, the operator
key and the Postgres dump are encrypted with the separate recovery key. Preserve that
key outside the cluster. `hst recovery check <set>` verifies the restored
inventory and evidence. The `prepare` container receives `app.extraEnv` and
`app.envFrom`.

The data PVC grows with the raw-snapshot trail. No raw payload is deleted while
`EVIDENCE_RETENTION_DAYS` (through `app.extraEnv`) is unset; once it is set, the raw-store
prune removes the payloads past that period that no retained run needs. The graph is
bounded by the keep count in the Lifecycle settings and pruned by the scheduled maintenance job.

The backup CronJob does not cover Neo4j. Recovery rebuilds the graph from the recovery set:

0. Pick one recovery set (`recovery-set/<job-uid>.json`): it names every exact object
   that belong together.
1. Decrypt its operator-key and configuration envelopes with the separately held
   recovery encryption key.
2. Restore only the listed data objects to their `restore_path` on a fresh
   `app.persistence` PVC.
3. `hst recovery materialize <set> <objects> <target>`, with `HST_BACKUP_ENCRYPTION_KEY`
   set, decrypts that set's `postgres.dump.enc` to `<target>/.recovery/postgres.dump`.
   Restore Postgres from that file (`pg_restore`).
4. `hst init-db` against a fresh Neo4j, then `hst rebuild --snapshot <key> --into
   <target>`. A manifest that carries a graph archive restores it, so graph answers keep
   the recorded interpretation; without one, and with `--as-of <time>`, the raw
   snapshots replay through today's normalize and load code.

The rebuild reconstructs the graph as it stood at the replay target. The multi-cycle
history in `:CycleRun` and `:CyclePointer` lives only in Neo4j. An install that must keep
that history through total loss needs an offline dump in a maintenance window. The
image of the dump pod is the tag of `neo4j.image` in `values.yaml`:

```
kubectl -n hst scale statefulset hst-neo4j --replicas=0
kubectl -n hst run neo4j-dump --rm -i --restart=Never \
  --image=docker.io/library/neo4j:5.26.33-community --overrides='{"spec":{"containers":[{"name":"neo4j-dump","image":"docker.io/library/neo4j:5.26.33-community","command":["neo4j-admin","database","dump","neo4j","--to-path=/dumps"],"volumeMounts":[{"name":"data","mountPath":"/data"},{"name":"dumps","mountPath":"/dumps"}]}],"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"data-hst-neo4j-0"}},{"name":"dumps","emptyDir":{}}]}}' \
  -- true
kubectl -n hst scale statefulset hst-neo4j --replicas=1
```

Copy the dump out of the pod (`kubectl cp`) before it is removed, or mount a volume that
outlives it. The chart does not automate the dump.

## Uninstall

```
helm uninstall hst -n hst
```

PVCs survive: they hold the twin, the identity store, and the raw snapshots, which are
not rebuildable from the collectors. Delete them by hand to remove that data.
