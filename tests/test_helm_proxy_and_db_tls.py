"""Chart renders for the proxy trust behind the ingress (GS-06), the NetworkPolicy of
each pod, the pod hardening and the opt-in TLS listeners of the bundled databases
(GS-07). Skips where `helm` is not installed."""

from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

CHART = Path(__file__).resolve().parents[1] / "deploy/helm/hst"
NO_PEERS = [
    "--set", "secrets.secretKey=lint",
    "--set", "secrets.neo4jPassword=lint",
    "--set", "secrets.postgresPassword=lint",
    "--set", "ingress.acceptInsecureHttp=true",
    "--set", "neo4j.acceptInsecure=true",
    "--set", "postgres.acceptInsecure=true",
]  # fmt: skip
PEER = {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "ingress-nginx"}}}
FAKE = [*NO_PEERS, "--set-json", f"networkPolicy.ingressFrom={json.dumps([PEER])}"]
DB_TLS = [
    "--set", "neo4j.tls.enabled=true", "--set", "neo4j.tls.caSecret=db-tls",
    "--set", "neo4j.tls.serverSecret=db-tls",
    "--set", "postgres.tls.enabled=true", "--set", "postgres.tls.caSecret=db-tls",
    "--set", "postgres.tls.serverSecret=db-tls",
]  # fmt: skip

HELM = shutil.which("helm")
pytestmark = pytest.mark.skipif(HELM is None, reason="helm is not installed")


def _render(*args: str, base: list[str] = FAKE) -> subprocess.CompletedProcess[str]:
    assert HELM is not None
    return subprocess.run(
        [HELM, "template", "r", str(CHART), *base, *args], capture_output=True, text=True, check=False
    )


def _docs(*args: str, base: list[str] = FAKE) -> list[dict]:
    out = _render(*args, base=base)
    assert out.returncode == 0, out.stderr
    return [d for d in yaml.safe_load_all(out.stdout) if d]


def _find(docs: list[dict], kind: str, name: str) -> dict:
    return next(d for d in docs if d["kind"] == kind and d["metadata"]["name"] == name)


def _env(container: dict) -> list[dict]:
    return container.get("env", [])


def _fwd(docs: list[dict]) -> list[str]:
    app = _find(docs, "Deployment", "r-hst")["spec"]["template"]["spec"]["containers"][0]
    return [e["value"] for e in _env(app) if e["name"] == "HST_FORWARDED_ALLOW_IPS"]


def test_the_app_behind_the_ingress_trusts_the_default_by_default():
    default = yaml.safe_load((CHART / "values.yaml").read_text())["app"]["forwardedAllowIps"]
    docs = _docs()
    assert _fwd(docs) == [default]
    # only the process that serves HTTP reads it
    worker_docs = _docs("--set", "worker.enabled=true")
    worker = _find(worker_docs, "Deployment", "r-hst-worker")["spec"]["template"]["spec"]["containers"][0]
    assert all(e["name"] != "HST_FORWARDED_ALLOW_IPS" for e in _env(worker))


def test_no_ingress_or_an_empty_value_trusts_no_proxy():
    assert _fwd(_docs("--set", "ingress.enabled=false")) == []
    assert _fwd(_docs("--set", "app.forwardedAllowIps=")) == []


def test_an_existing_extra_env_setting_stays_the_only_one():
    docs = _docs(
        "--set", "app.extraEnv[0].name=HST_FORWARDED_ALLOW_IPS",
        "--set", "app.extraEnv[0].value=10.244.0.0/16",
    )  # fmt: skip
    assert _fwd(docs) == ["10.244.0.0/16"]


def test_the_app_policy_admits_the_named_peers_to_port_8787():
    policy = _find(_docs(), "NetworkPolicy", "r-hst-app")["spec"]
    assert policy["podSelector"]["matchLabels"]["app.kubernetes.io/component"] == "app"
    assert policy["policyTypes"] == ["Ingress", "Egress"]
    assert policy["ingress"] == [{"from": [PEER], "ports": [{"port": 8787, "protocol": "TCP"}]}]


@pytest.mark.parametrize(
    ("base", "args"),
    [(NO_PEERS, []), (FAKE, ["--set", "networkPolicy.enabled=false"])],
)
def test_the_proxy_trust_without_the_app_policy_fails_the_render(base, args):
    out = _render(*args, base=base)
    assert out.returncode != 0
    assert "app.forwardedAllowIps needs networkPolicy.enabled=true and a peer" in out.stderr


def test_no_peer_and_no_proxy_trust_renders_an_app_policy_without_ingress():
    docs = _docs("--set", "app.forwardedAllowIps=", base=NO_PEERS)
    assert _fwd(docs) == []
    policy = _find(docs, "NetworkPolicy", "r-hst-app")["spec"]
    assert policy["policyTypes"] == ["Egress"]
    assert "ingress" not in policy


def test_no_peer_and_no_egress_renders_no_app_policy():
    no_egress = ["--set", "networkPolicy.egress.enabled=false"]
    docs = _docs("--set", "app.forwardedAllowIps=", *no_egress, base=NO_PEERS)
    assert [d["metadata"]["name"] for d in docs if d["kind"] == "NetworkPolicy"] == [
        "r-hst-neo4j",
        "r-hst-postgres",
        "r-hst-initdb",
        "r-hst-migrate",
    ]


def _pod_labels(docs: list[dict]) -> dict[str, dict]:
    pods = {}
    for doc in docs:
        spec = doc.get("spec", {})
        template = spec.get("jobTemplate", {}).get("spec", {}).get("template") or spec.get("template")
        if template:
            labels = template["metadata"]["labels"]
            pods[labels["app.kubernetes.io/component"]] = labels
    return pods


WORKER_AND_BACKUP = [
    "--set", "worker.enabled=true",
    "--set", "backup.enabled=true", "--set", "backup.s3.bucket=b",
    "--set", "backup.s3.endpoint=https://s3.example", "--set", "backup.s3.secretName=s",
    "--set", "backup.recoverySecretName=r",
]  # fmt: skip


@pytest.mark.parametrize(
    ("args", "types"),
    [([], ["Ingress", "Egress"]), (["--set", "networkPolicy.egress.enabled=false"], ["Ingress"])],
)
def test_the_worker_the_backup_and_the_jobs_admit_no_ingress(args, types):
    docs = _docs(*WORKER_AND_BACKUP, *args)
    pods = _pod_labels(docs)
    assert set(pods) == {"app", "worker", "backup", "migrate", "initdb", "neo4j", "postgres"}
    for component in ("worker", "backup", "migrate", "initdb"):
        policy = _find(docs, "NetworkPolicy", f"r-hst-{component}")["spec"]
        assert policy["policyTypes"] == types
        assert "ingress" not in policy
        assert ("egress" in policy) == ("Egress" in types)
        selector = policy["podSelector"]["matchLabels"]
        assert [name for name, labels in pods.items() if selector.items() <= labels.items()] == [component]


DNS = {"ports": [{"port": 53, "protocol": "UDP"}, {"port": 53, "protocol": "TCP"}]}


def _to_pod(component: str, port: int) -> dict:
    labels = {"app.kubernetes.io/name": "hst", "app.kubernetes.io/instance": "r"}
    return {
        "to": [{"podSelector": {"matchLabels": {**labels, "app.kubernetes.io/component": component}}}],
        "ports": [{"port": port, "protocol": "TCP"}],
    }


NEO4J = _to_pod("neo4j", 7687)
POSTGRES = _to_pod("postgres", 5432)
OTHER = {
    "to": [
        {"ipBlock": {"cidr": "0.0.0.0/0", "except": ["169.254.0.0/16"]}},
        {"ipBlock": {"cidr": "::/0", "except": ["fe80::/10", "fd00:ec2::254/128"]}},
    ]
}
EXTERNAL = [
    "--set", "neo4j.enabled=false", "--set", "neo4j.externalUri=bolt://neo4j.example:7687",
    "--set", "postgres.enabled=false", "--set", "postgres.externalDsn=postgresql+asyncpg://u:p@pg.example:5432/d",
]  # fmt: skip


def _egress(docs: list[dict]) -> dict[str, list[dict]]:
    return {
        d["metadata"]["name"].removeprefix("r-hst-"): d["spec"].get("egress")
        for d in docs
        if d["kind"] == "NetworkPolicy"
    }


def test_each_pod_reaches_dns_and_the_bundled_databases_that_it_opens():
    egress = _egress(_docs(*WORKER_AND_BACKUP))
    assert egress["app"] == [DNS, NEO4J, POSTGRES, OTHER]
    assert egress["worker"] == [DNS, NEO4J, POSTGRES, OTHER]
    assert egress["backup"] == [DNS, NEO4J, POSTGRES, OTHER]
    assert egress["migrate"] == [DNS, POSTGRES]
    assert egress["initdb"] == [DNS, NEO4J]


def test_the_jobs_reach_other_addresses_with_external_databases():
    egress = _egress(_docs(*EXTERNAL, "--set", "worker.enabled=true"))
    assert egress["app"] == [DNS, OTHER]
    assert egress["worker"] == [DNS, OTHER]
    assert egress["migrate"] == [DNS, OTHER]
    assert egress["initdb"] == [DNS, OTHER]


def test_the_except_list_splits_by_address_family():
    docs = _docs("--set-json", 'networkPolicy.egress.except=["169.254.0.0/16","10.244.0.0/16","fe80::/10"]')
    blocks = [peer["ipBlock"] for peer in _egress(docs)["app"][-1]["to"]]
    assert blocks == [
        {"cidr": "0.0.0.0/0", "except": ["169.254.0.0/16", "10.244.0.0/16"]},
        {"cidr": "::/0", "except": ["fe80::/10"]},
    ]
    empty = _docs("--set-json", "networkPolicy.egress.except=[]")
    blocks = [peer["ipBlock"] for peer in _egress(empty)["app"][-1]["to"]]
    assert blocks == [{"cidr": "0.0.0.0/0"}, {"cidr": "::/0"}]


def test_each_default_except_entry_lies_inside_its_cidr():
    for block in OTHER["to"]:
        cidr = ipaddress.ip_network(block["ipBlock"]["cidr"])
        for entry in block["ipBlock"]["except"]:
            assert ipaddress.ip_network(entry).subnet_of(cidr)
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    assert values["networkPolicy"]["egress"]["except"] == ["169.254.0.0/16", "fe80::/10", "fd00:ec2::254/128"]


def test_the_dns_rule_goes_to_the_dns_peers():
    peer = {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}
    egress = _egress(_docs("--set-json", f"networkPolicy.dnsTo={json.dumps([peer])}"))
    assert egress["app"][0] == {**DNS, "to": [peer]}
    assert egress["migrate"][0] == {**DNS, "to": [peer]}


def test_the_schema_refuses_an_except_entry_that_is_not_a_cidr():
    out = _render("--set-json", 'networkPolicy.egress.except=["169.254.169.254"]')
    assert out.returncode != 0


def test_no_network_policy_renders_without_network_policy_enabled():
    docs = _docs("--set", "networkPolicy.enabled=false", "--set", "app.forwardedAllowIps=")
    assert [d for d in docs if d["kind"] == "NetworkPolicy"] == []


def test_a_pod_that_the_chart_does_not_render_has_no_policy():
    docs = _docs("--set", "migrations.enabled=false", "--set", "initDb.enabled=false")
    assert [d["metadata"]["name"] for d in docs if d["kind"] == "NetworkPolicy"] == [
        "r-hst-neo4j",
        "r-hst-postgres",
        "r-hst-app",
    ]


def test_a_setting_in_extra_env_renders_without_a_peer():
    docs = _docs(
        "--set", "app.extraEnv[0].name=HST_FORWARDED_ALLOW_IPS",
        "--set", "app.extraEnv[0].value=10.244.0.0/16",
        base=NO_PEERS,
    )  # fmt: skip
    assert _fwd(docs) == ["10.244.0.0/16"]


def test_postgres_has_a_read_only_root_and_a_mount_for_each_path_it_writes():
    postgres = _find(_docs(), "StatefulSet", "r-hst-postgres")["spec"]["template"]["spec"]
    container = postgres["containers"][0]
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert {m["name"]: m["mountPath"] for m in container["volumeMounts"]} == {
        "data": "/var/lib/postgresql/data",
        "run": "/var/run/postgresql",
        "tmp": "/tmp",
    }
    assert postgres["volumes"] == [{"name": "run", "emptyDir": {}}, {"name": "tmp", "emptyDir": {}}]
    pgdata = next(e["value"] for e in _env(container) if e["name"] == "PGDATA")
    assert pgdata.startswith("/var/lib/postgresql/data/")


def test_the_job_containers_have_resources():
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    docs = _docs()
    initdb = next(d for d in docs if d["kind"] == "Job" and "initdb" in d["metadata"]["name"])
    migrate = next(d for d in docs if d["kind"] == "Job" and "migrate" in d["metadata"]["name"])
    app = _find(docs, "Deployment", "r-hst")["spec"]["template"]["spec"]
    for container in (
        *initdb["spec"]["template"]["spec"]["initContainers"],
        *initdb["spec"]["template"]["spec"]["containers"],
    ):
        assert container["resources"] == values["initDb"]["resources"], container["name"]
    assert [c["name"] for c in initdb["spec"]["template"]["spec"]["initContainers"]] == ["wait-for-neo4j"]
    for container in (
        *migrate["spec"]["template"]["spec"]["initContainers"],
        *migrate["spec"]["template"]["spec"]["containers"],
        *app["initContainers"],
    ):
        assert container["resources"] == values["migrations"]["resources"], container["name"]


def test_the_bundled_databases_are_unchanged_without_the_switch():
    docs = _docs()
    neo4j = _find(docs, "StatefulSet", "r-hst-neo4j")["spec"]["template"]["spec"]
    postgres = _find(docs, "StatefulSet", "r-hst-postgres")["spec"]["template"]["spec"]
    assert "volumes" not in neo4j
    assert all("secret" not in v for v in postgres["volumes"])
    assert "args" not in postgres["containers"][0]
    assert not any(e["name"].startswith("NEO4J_dbms_ssl") for e in _env(neo4j["containers"][0]))
    initdb = next(d for d in docs if d["kind"] == "Job" and "initdb" in d["metadata"]["name"])
    wait = initdb["spec"]["template"]["spec"]["initContainers"][0]
    assert {e["name"]: e.get("value") for e in _env(wait)}["NEO4J_WAIT_URI"] == "bolt://r-hst-neo4j:7687"


def test_the_switch_gives_both_databases_a_tls_listener():
    docs = _docs(*DB_TLS)
    neo4j = _find(docs, "StatefulSet", "r-hst-neo4j")["spec"]["template"]["spec"]
    env = {e["name"]: e.get("value") for e in _env(neo4j["containers"][0])}
    assert env["NEO4J_server_bolt_tls__level"] == "REQUIRED"
    assert env["NEO4J_dbms_ssl_policy_bolt_base__directory"] == "/ssl/bolt"
    assert neo4j["volumes"][0]["secret"]["secretName"] == "db-tls"
    assert "bolt+ssc://localhost:7687" in neo4j["containers"][0]["readinessProbe"]["exec"]["command"][2]

    postgres = _find(docs, "StatefulSet", "r-hst-postgres")["spec"]["template"]["spec"]
    assert "ssl=on" in postgres["containers"][0]["args"]
    assert next(v for v in postgres["volumes"] if v["name"] == "server-tls")["secret"] == {
        "secretName": "db-tls",
        "defaultMode": 0o440,
        "items": [{"key": "tls.crt", "path": "tls.crt"}, {"key": "tls.key", "path": "tls.key"}],
    }

    app = _find(docs, "Deployment", "r-hst")["spec"]["template"]["spec"]["containers"][0]
    app_env = {e["name"]: e.get("value") for e in _env(app)}
    assert app_env["NEO4J_URI"] == "bolt://r-hst-neo4j:7687"
    assert app_env["NEO4J_TLS_CA_FILE"] == "/etc/hst/tls/neo4j/ca.crt"
    assert app_env["POSTGRES_CA_FILE"] == "/etc/hst/tls/postgres/ca.crt"

    # the backup's prepare step opens both databases with the same settings
    backup_docs = _docs(
        *DB_TLS,
        "--set", "backup.enabled=true", "--set", "backup.s3.bucket=b",
        "--set", "backup.s3.endpoint=https://s3.example", "--set", "backup.s3.secretName=s",
        "--set", "backup.recoverySecretName=r",
    )  # fmt: skip
    cron = _find(backup_docs, "CronJob", "r-hst-backup")["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    prepare = cron["initContainers"][0]
    assert {"neo4j-ca", "postgres-ca"} <= {m["name"] for m in prepare["volumeMounts"]}
    assert {"neo4j-ca", "postgres-ca"} <= {v["name"] for v in cron["volumes"]}


NEO4J_PLAIN = "neo4j.enabled=true with an empty neo4j.tls.serverSecret"
POSTGRES_PLAIN = "postgres.enabled=true with an empty postgres.tls.serverSecret"


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--set", "neo4j.acceptInsecure=false"], NEO4J_PLAIN),
        (["--set", "postgres.acceptInsecure=false"], POSTGRES_PLAIN),
        (
            [
                "--set", "neo4j.acceptInsecure=false",
                "--set", "neo4j.tls.enabled=true", "--set", "neo4j.tls.caSecret=c",
            ],
            NEO4J_PLAIN,
        ),
    ],
)  # fmt: skip
def test_a_bundled_database_without_its_tls_listener_fails_the_render(args, message):
    out = _render(*args)
    assert out.returncode != 0
    assert message in out.stderr


def test_the_bundled_databases_with_their_tls_listeners_need_no_accept_insecure():
    _docs(*DB_TLS, "--set", "neo4j.acceptInsecure=false", "--set", "postgres.acceptInsecure=false")


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--set", "neo4j.tls.serverSecret=x"], "neo4j.tls.enabled=false"),
        (["--set", "postgres.tls.serverSecret=x"], "postgres.tls.enabled=false"),
        (
            [
                "--set", "neo4j.enabled=false", "--set", "neo4j.externalUri=bolt://n.example:7687",
                "--set", "neo4j.tls.enabled=true", "--set", "neo4j.tls.caSecret=c",
                "--set", "neo4j.tls.serverSecret=x",
            ],
            "no bundled Neo4j",
        ),
        (
            [
                "--set", "postgres.enabled=false",
                "--set", "postgres.externalDsn=postgresql+asyncpg://u:p@pg.example:5432/d",
                "--set", "postgres.tls.enabled=true", "--set", "postgres.tls.caSecret=c",
                "--set", "postgres.tls.serverSecret=x",
            ],
            "no bundled Postgres",
        ),
    ],
)  # fmt: skip
def test_a_server_secret_without_the_client_side_fails_the_render(args, message):
    out = _render(*args)
    assert out.returncode != 0
    assert message in out.stderr
