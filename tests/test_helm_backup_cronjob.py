"""Chart renders of the backup CronJob. Skips where `helm` is not installed."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

CHART = Path(__file__).resolve().parents[1] / "deploy/helm/hst"
SECRETS = [
    "--set", "secrets.secretKey=lint",
    "--set", "secrets.neo4jPassword=lint",
    "--set", "secrets.postgresPassword=lint",
]  # fmt: skip
BACKUP = [
    "--set", "ingress.acceptInsecureHttp=true",
    "--set", "networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.ns=ingress",
    "--set", "backup.enabled=true",
    "--set", "backup.s3.bucket=b",
    "--set", "backup.s3.secretName=s3",
    "--set", "backup.recoverySecretName=recovery",
]  # fmt: skip
HTTPS = ["--set", "backup.s3.endpoint=https://s3.example"]

HELM = shutil.which("helm")
pytestmark = pytest.mark.skipif(HELM is None, reason="helm is not installed")


def _render(*args: str) -> subprocess.CompletedProcess[str]:
    assert HELM is not None
    return subprocess.run(
        [HELM, "template", "r", str(CHART), *BACKUP, *args], capture_output=True, text=True, check=False
    )


def _pod(*args: str) -> dict:
    out = _render(*args)
    assert out.returncode == 0, out.stderr
    docs = [d for d in yaml.safe_load_all(out.stdout) if d]
    cron = next(d for d in docs if d["kind"] == "CronJob" and d["metadata"]["name"] == "r-hst-backup")
    return cron["spec"]["jobTemplate"]["spec"]["template"]["spec"]


def _container(pod: dict, name: str) -> dict:
    return next(c for c in pod["initContainers"] + pod["containers"] if c["name"] == name)


def _env(container: dict) -> dict:
    return {e["name"]: e.get("value", e.get("valueFrom")) for e in container.get("env", [])}


@pytest.mark.parametrize(
    ("secrets", "secret_name"),
    [(SECRETS, "r-hst"), (["--set", "secrets.existingSecret=operator"], "operator")],
)
def test_prepare_reads_the_operator_key_from_a_read_only_mount(secrets, secret_name):
    pod = _pod(*secrets, *HTTPS)
    prepare = _container(pod, "prepare")
    assert _env(prepare)["HST_SECRET_KEY_FILE"] == "/etc/hst/secret-key"
    assert {"name": "secret-key", "mountPath": "/etc/hst", "readOnly": True} in prepare["volumeMounts"]
    volume = next(v for v in pod["volumes"] if v["name"] == "secret-key")
    assert volume["secret"] == {
        "secretName": secret_name,
        "items": [{"key": "secret-key", "path": "secret-key"}],
    }


def test_prepare_and_finalize_get_the_recovery_key_from_the_recovery_secret():
    pod = _pod(*SECRETS, *HTTPS)
    reference = {"secretKeyRef": {"name": "recovery", "key": "encryption-key"}}
    assert _env(_container(pod, "prepare"))["HST_BACKUP_ENCRYPTION_KEY"] == reference
    assert _env(_container(pod, "finalize"))["HST_BACKUP_ENCRYPTION_KEY"] == reference
    assert "HST_BACKUP_ENCRYPTION_KEY" not in _env(_container(pod, "dump"))
    assert "HST_BACKUP_ENCRYPTION_KEY" not in _env(_container(pod, "upload"))


def test_prepare_gets_the_extra_environment_of_the_app():
    pod = _pod(
        *SECRETS, *HTTPS,
        "--set", "app.extraEnv[0].name=ESTATE_NAME", "--set", "app.extraEnv[0].value=lab",
        "--set", "app.envFrom[0].secretRef.name=extra",
    )  # fmt: skip
    prepare = _container(pod, "prepare")
    assert _env(prepare)["ESTATE_NAME"] == "lab"
    assert prepare["envFrom"] == [{"secretRef": {"name": "extra"}}]


def test_the_pod_gets_the_pull_secrets_and_each_container_has_resources():
    values = yaml.safe_load((CHART / "values.yaml").read_text())["backup"]
    pod = _pod(*SECRETS, *HTTPS, "--set", "imagePullSecrets[0].name=harbor-pull")
    assert pod["imagePullSecrets"] == [{"name": "harbor-pull"}]
    assert _container(pod, "prepare")["resources"] == values["recoveryResources"]
    assert _container(pod, "finalize")["resources"] == values["recoveryResources"]
    assert _container(pod, "dump")["resources"] == values["resources"]
    assert _container(pod, "upload")["resources"] == values["resources"]


def test_the_pod_has_the_service_account_of_the_chart_and_no_token():
    pod = _pod(*SECRETS, *HTTPS)
    assert pod["serviceAccountName"] == "r-hst"
    assert pod["automountServiceAccountToken"] is False
    for name in ("prepare", "dump", "finalize", "upload"):
        context = _container(pod, name)["securityContext"]
        assert context["runAsNonRoot"] is True, name
        assert context["allowPrivilegeEscalation"] is False, name


def test_each_container_has_a_read_only_root_filesystem():
    pod = _pod(*SECRETS, *HTTPS)
    for name in ("prepare", "dump", "finalize", "upload"):
        assert _container(pod, name)["securityContext"]["readOnlyRootFilesystem"] is True, name
    assert {"name": "tmp", "emptyDir": {}} in pod["volumes"]
    for name in ("prepare", "finalize", "upload"):
        assert {"name": "tmp", "mountPath": "/tmp"} in _container(pod, name)["volumeMounts"], name
    assert _env(_container(pod, "upload"))["HOME"] == "/work"


def _run_script(container: dict, work: Path, tool: str, status: int) -> int:
    sh = shutil.which("sh")
    assert sh
    stand_ins = work / "bin"
    stand_ins.mkdir(exist_ok=True)
    stand_in = stand_ins / tool
    stand_in.write_text(f"#!/bin/sh\nprintf dump\nexit {status}\n")
    stand_in.chmod(0o755)
    script = container["args"][0].replace("/work", str(work))
    env = {"PATH": f"{stand_ins}:{os.environ['PATH']}"}
    return subprocess.run([sh, "-c", script], env=env, capture_output=True, check=False).returncode


def test_a_failed_step_leaves_no_plain_dump(tmp_path):
    pod = _pod(*SECRETS, *HTTPS)
    (tmp_path / "set-id").write_text("abc")
    dump = tmp_path / "sets" / "abc" / "postgres.dump"
    dump.parent.mkdir(parents=True)
    assert _run_script(_container(pod, "dump"), tmp_path, "pg_dump", 1) == 1
    assert not dump.exists()
    assert _run_script(_container(pod, "dump"), tmp_path, "pg_dump", 0) == 0
    assert dump.read_text() == "dump"
    assert _run_script(_container(pod, "finalize"), tmp_path, "hst", 1) == 1
    assert not dump.exists()


@pytest.mark.parametrize("endpoint", ["http://minio:9000", "s3.example"])
def test_the_schema_refuses_an_endpoint_that_is_not_https(endpoint):
    out = _render(*SECRETS, "--set", f"backup.s3.endpoint={endpoint}")
    assert out.returncode != 0
    assert "/backup/s3/endpoint" in out.stderr
