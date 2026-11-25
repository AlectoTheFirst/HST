#!/usr/bin/env python3
"""Run bounded enterprise checks on the existing Kubernetes BuildKit daemon."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# The kubectl context of the cluster that hosts the BuildKit builder.
CONTEXT = os.environ.get("HST_KUBE_CONTEXT", "")
NAMESPACE = "buildkit"
BUILDER_SELECTOR = "app=buildkitd"
BUILDER_CONTAINER = "buildkitd"
REMOTE_ROOT = "/tmp/hst-enterprise-remote"  # noqa: S108 -- path is inside the remote builder pod
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_CONTEXT_BYTES = 24 * 1024 * 1024
ALLOWED_SUFFIXES = {
    ".css",
    ".html",
    ".js",
    ".json",
    ".lock",
    ".md",
    ".patch",
    ".py",
    ".svg",
    ".toml",
    ".tpl",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}
ALLOWED_NAMES = {"Containerfile", "EnterpriseTest.Containerfile", "LICENSE"}
DENIED_PARTS = {".git", "output"}
SENSITIVE_SUFFIXES = {".cer", ".crt", ".key", ".kubeconfig", ".p12", ".pem", ".pfx"}
INCLUDED = (
    "pyproject.toml",
    "uv.lock",
    "README.md",
    "LICENSE",
    "src",
    "tests/enterprise",
    "tests/test_checkpoint.py",
    "tests/test_labels.py",
    "tests/test_schema_contract.py",
    "tests/test_schema_fixtures.py",
    "tests/test_queries_catalog.py",
    "tests/conftest.py",
    "tests/test_manifest.py",
    "tests/test_manifest_device_provenance.py",
    "tests/test_collector_execute.py",
    "tests/test_simul_rib.py",
    "tests/test_simul_propagate.py",
    "tests/test_impact_evaluate.py",
    "tests/test_impact_soundness_bounds.py",
    "tests/test_impact_sessions.py",
    "tests/test_impact_soundness_walks.py",
    "tests/test_path_nat.py",
    "tests/test_path_trace.py",
    "tests/test_apic.py",
    "tests/test_cisco_common.py",
    "tests/test_iosxe.py",
    "tests/test_iosxr.py",
    "tests/test_manual.py",
    "tests/test_nautobot.py",
    "tests/test_nxos.py",
    "tests/test_unifi.py",
    "tests/test_vyos.py",
    "fixtures/enterprise",
    "third_party/symbolic",
    "tools/build_symbolic_wheels.py",
    "tools/check_symbolic_licenses.py",
    "tools/run_enterprise_remote.py",
    "tools/run_limited.py",
    "tools/enterprise_private_acceptance.py",
    "deploy/Containerfile",
    "deploy/helm/hst",
    "deploy/symbolic/EnterpriseTest.Containerfile",
    "third_party/symbolic/2026-09-12-enterprise-symbolic-sources.json",
    "web/src",
    "web/eslint.config.js",
    "web/index.html",
    "web/package.json",
    "web/package-lock.json",
    "web/tsconfig.json",
    "web/tsconfig.app.json",
    "web/tsconfig.node.json",
    "web/vite.config.ts",
)
POSTGRES_INCLUDED = ("tests/app", "tests/conftest.py")
SHARED_INCLUDED = (
    *POSTGRES_INCLUDED,
    "tests/test_assessment_package.py",
    "tests/test_changesim_export.py",
    "tests/test_impact_evaluate.py",
    "tests/test_path_determinism.py",
    "tests/test_path_multihop.py",
    "tests/test_path_nat.py",
    "tests/test_path_policy.py",
    "tests/test_path_reply.py",
    "tests/test_mtu_contract.py",
    "tests/test_mtu_path.py",
    "tests/test_mtu_regression.py",
    "tests/test_path_trace.py",
    "tests/test_mtu_snapshot.py",
    "tests/test_mtu_assessment.py",
    "tests/test_grapharchive.py",
    "tests/test_mtu_budget.py",
)


def run(
    command: list[str], *, input_data: bytes | None = None, timeout: int = 1200
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(command, input=input_data, check=True, timeout=timeout)  # noqa: S603


def ready_builder() -> str:
    result = subprocess.run(  # noqa: S603 -- kubectl is a trusted operator executable
        [  # noqa: S607
            "kubectl",
            "--context",
            CONTEXT,
            "-n",
            NAMESPACE,
            "get",
            "pods",
            "-l",
            BUILDER_SELECTOR,
            "-o",
            "json",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    pods = json.loads(result.stdout)["items"]
    for pod in pods:
        ready = any(
            c.get("type") == "Ready" and c.get("status") == "True"
            for c in pod["status"].get("conditions", [])
        )
        containers = {container["name"] for container in pod["spec"].get("containers", [])}
        if pod["status"].get("phase") == "Running" and ready and containers == {BUILDER_CONTAINER}:
            return str(pod["metadata"]["name"])
    raise RuntimeError("no Ready, Running BuildKit pod found")


def context_tar(included: tuple[str, ...] = INCLUDED) -> tuple[bytes, str]:
    output = io.BytesIO()
    digest = hashlib.sha256()
    manifest_lines: list[str] = []
    total = 0
    with tarfile.open(fileobj=output, mode="w") as archive:
        for relative in included:
            path = ROOT / relative
            if not path.exists():
                raise FileNotFoundError(path)
            if path.is_symlink():
                raise RuntimeError(f"refusing symlink in remote context: {relative}")
            candidates = [path] if path.is_file() else sorted(path.rglob("*"))
            paths: list[Path] = []
            for candidate in candidates:
                if candidate.is_symlink():
                    raise RuntimeError(f"refusing symlink in remote context: {candidate.relative_to(ROOT)}")
                mode = candidate.lstat().st_mode
                if stat.S_ISDIR(mode):
                    continue
                if not stat.S_ISREG(mode):
                    raise RuntimeError(f"refusing non-regular file: {candidate.relative_to(ROOT)}")
                paths.append(candidate)
            for item in paths:
                relative_item = item.relative_to(ROOT)
                lower_parts = tuple(part.lower() for part in relative_item.parts)
                if any(
                    part in DENIED_PARTS or part == "__pycache__" or part.startswith(".env")
                    for part in lower_parts
                ):
                    continue
                if item.suffix.lower() in SENSITIVE_SUFFIXES:
                    continue
                if item.name not in ALLOWED_NAMES and item.suffix.lower() not in ALLOWED_SUFFIXES:
                    continue
                size = item.stat(follow_symlinks=False).st_size
                if size > MAX_FILE_BYTES:
                    raise RuntimeError(f"remote context file exceeds {MAX_FILE_BYTES} bytes: {relative_item}")
                total += size
                if total > MAX_CONTEXT_BYTES:
                    raise RuntimeError(f"remote context exceeds {MAX_CONTEXT_BYTES} bytes")
                arcname = relative_item.as_posix()
                data = item.read_bytes()
                digest.update(arcname.encode())
                digest.update(b"\0")
                digest.update(data)
                manifest_lines.append(f"{hashlib.sha256(data).hexdigest()}  {arcname}\n")
                info = tarfile.TarInfo(arcname)
                info.size = len(data)
                item_stat = item.stat(follow_symlinks=False)
                info.mode = item_stat.st_mode & 0o777
                # each entry keeps the source mtime for the BuildKit COPY layer reuse
                info.mtime = int(item_stat.st_mtime)
                archive.addfile(info, io.BytesIO(data))
        context_id = digest.hexdigest()[:16]
        for generated_name, generated_data in (
            (".hst-remote-context.sha256", "".join(manifest_lines).encode()),
            (".hst-remote-context-id", f"{context_id}\n".encode()),
        ):
            info = tarfile.TarInfo(generated_name)
            info.size = len(generated_data)
            info.mode = 0o644
            info.mtime = int(time.time())
            archive.addfile(info, io.BytesIO(generated_data))
    return output.getvalue(), context_id


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smoke", action="store_true", help="run only the bounded synthetic smoke target")
    parser.add_argument(
        "--model", action="store_true", help="run only stable gate/session/network adapter tests"
    )
    parser.add_argument("--model-check", action="store_true", help="run bounded model mypy and Ruff checks")
    parser.add_argument("--model-ruff", action="store_true", help="run bounded read-only model Ruff checks")
    parser.add_argument("--root", action="store_true", help="run only assessment bridge tests")
    parser.add_argument("--priority", action="store_true", help="run routing, session and bridge tests")
    parser.add_argument(
        "--web", action="store_true", help="run bounded web lint, typecheck, and focused tests"
    )
    parser.add_argument(
        "--routing-extra", action="store_true", help="run Check Point gateway integration tests"
    )
    parser.add_argument(
        "--checkpoint-session", action="store_true", help="run the Check Point renewal regression"
    )
    parser.add_argument("--populations", action="store_true", help="run the population tests")
    parser.add_argument(
        "--postgres", action="store_true", help="run the store tests in a disposable loopback Postgres"
    )
    parser.add_argument("--cache", action="store_true", help="run bounded non-Postgres cache checks")
    parser.add_argument(
        "--root-lint", action="store_true", help="run read-only Ruff checks for root integration files"
    )
    parser.add_argument(
        "--determinism", action="store_true", help="rebuild the native wheel at two remapped paths"
    )
    parser.add_argument(
        "--artifacts", action="store_true", help="verify the native artifact lock and licenses"
    )
    parser.add_argument("--shared", action="store_true", help="run bounded shared regressions")
    parser.add_argument("--latest", action="store_true", help="run latest focused enterprise gates")
    parser.add_argument("--native-changes", action="store_true", help="run native change integration tests")
    parser.add_argument(
        "--private-acceptance", action="store_true", help="run private acceptance harness tests"
    )
    parser.add_argument("--upgrade", action="store_true", help="run upgrade report tests")
    parser.add_argument("--deployment", action="store_true", help="run deployment, quota, and network gates")
    parser.add_argument("--latest-checks", action="store_true", help="run latest focused Ruff and mypy")
    parser.add_argument("--native-mtu", action="store_true", help="run native MTU adapter tests")
    parser.add_argument("--latest-mypy", action="store_true", help="run latest focused mypy")
    parser.add_argument("--full-mypy", action="store_true", help="run full project mypy")
    parser.add_argument("--full-ruff", action="store_true", help="run full Ruff rules checks")
    parser.add_argument("--full-ruff-diff", action="store_true", help="show full Ruff rules diff")
    parser.add_argument("--incremental", action="store_true", help="run focused incremental compiler gates")
    parser.add_argument(
        "--routing-incremental", action="store_true", help="run focused routing incrementality gates"
    )
    parser.add_argument("--root-format-diff", action="store_true", help="show root source format diff")
    parser.add_argument("--enterprise", action="store_true", help="run all non-scale enterprise tests")
    parser.add_argument("--checkpoint-graph", action="store_true", help="run Check Point graph integration")
    parser.add_argument(
        "--checkpoint-graph-checks", action="store_true", help="check Check Point graph integration"
    )
    parser.add_argument(
        "--checkpoint-graph-mypy", action="store_true", help="type-check Check Point graph integration"
    )
    parser.add_argument(
        "--checkpoint-regressions", action="store_true", help="run Check Point adapter regressions"
    )
    parser.add_argument("--helm", action="store_true", help="verify and render Helm profiles")
    parser.add_argument(
        "--schema-collectors", action="store_true", help="run schema and collector regressions"
    )
    parser.add_argument(
        "--schema-fixture-diff", action="store_true", help="show generated schema fixture diff"
    )
    parser.add_argument(
        "--clock-evidence", action="store_true", help="run clock-quality and manifest regressions"
    )
    parser.add_argument(
        "--clock-evidence-focused", action="store_true", help="run focused clock-quality tests and checks"
    )
    parser.add_argument("--latest-format-diff", action="store_true", help="show latest source format diff")
    args = parser.parse_args()
    if not CONTEXT:
        parser.error("set HST_KUBE_CONTEXT to the kubectl context of the cluster with the BuildKit builder")
    modes = (
        args.smoke,
        args.model,
        args.model_check,
        args.model_ruff,
        args.root,
        args.priority,
        args.web,
        args.routing_extra,
        args.checkpoint_session,
        args.populations,
        args.postgres,
        args.cache,
        args.root_lint,
        args.determinism,
        args.artifacts,
        args.shared,
        args.latest,
        args.native_changes,
        args.private_acceptance,
        args.upgrade,
        args.deployment,
        args.latest_checks,
        args.native_mtu,
        args.latest_mypy,
        args.full_mypy,
        args.full_ruff,
        args.full_ruff_diff,
        args.incremental,
        args.routing_incremental,
        args.root_format_diff,
        args.enterprise,
        args.checkpoint_graph,
        args.checkpoint_graph_checks,
        args.checkpoint_graph_mypy,
        args.checkpoint_regressions,
        args.helm,
        args.schema_collectors,
        args.schema_fixture_diff,
        args.clock_evidence,
        args.clock_evidence_focused,
        args.latest_format_diff,
    )
    if sum(modes) > 1:
        parser.error("focused modes are mutually exclusive")
    pod = ready_builder()
    extra = (
        POSTGRES_INCLUDED
        if args.postgres
        else SHARED_INCLUDED
        if args.shared or args.clock_evidence or args.clock_evidence_focused
        else ()
    )
    included = INCLUDED + extra
    archive, context_id = context_tar(included)
    remote = f"{REMOTE_ROOT}/{context_id}"
    kubectl = ["kubectl", "--context", CONTEXT, "-n", NAMESPACE, "exec"]
    run([*kubectl, pod, "--", "mkdir", "-p", remote], timeout=30)
    run([*kubectl, "-i", pod, "--", "tar", "-xf", "-", "-C", remote], input_data=archive, timeout=120)
    targets: tuple[str, ...]
    if args.smoke:
        targets = ("enterprise-smoke",)
    elif args.model:
        targets = ("enterprise-model-tests", "enterprise-typecheck", "enterprise-model-lint")
    elif args.model_check:
        targets = ("enterprise-typecheck", "enterprise-model-lint")
    elif args.model_ruff:
        targets = ("enterprise-model-lint",)
    elif args.root:
        targets = ("enterprise-root-tests",)
    elif args.priority:
        targets = ("enterprise-priority-tests",)
    elif args.web:
        targets = ("enterprise-web",)
    elif args.routing_extra:
        targets = ("enterprise-routing-extra",)
    elif args.checkpoint_session:
        targets = ("enterprise-checkpoint-session",)
    elif args.populations:
        targets = ("enterprise-populations",)
    elif args.postgres:
        targets = ("enterprise-postgres",)
    elif args.cache:
        targets = ("enterprise-cache",)
    elif args.root_lint:
        targets = ("enterprise-root-lint",)
    elif args.determinism:
        targets = ("enterprise-determinism",)
    elif args.artifacts:
        targets = ("enterprise-artifacts",)
    elif args.shared:
        targets = ("enterprise-postgres-api", "enterprise-shared-tests")
    elif args.latest:
        targets = ("enterprise-latest-tests", "enterprise-latest-checks")
    elif args.native_changes:
        targets = ("enterprise-native-changes",)
    elif args.private_acceptance:
        targets = ("enterprise-private-acceptance",)
    elif args.upgrade:
        targets = ("enterprise-upgrade",)
    elif args.deployment:
        targets = ("enterprise-deployment-tests",)
    elif args.latest_checks:
        targets = ("enterprise-latest-checks",)
    elif args.native_mtu:
        targets = ("enterprise-native-mtu",)
    elif args.latest_mypy:
        targets = ("enterprise-latest-mypy",)
    elif args.full_mypy:
        targets = ("enterprise-full-mypy",)
    elif args.full_ruff:
        targets = ("enterprise-full-ruff",)
    elif args.full_ruff_diff:
        targets = ("enterprise-full-ruff-diff",)
    elif args.incremental:
        targets = ("enterprise-incremental",)
    elif args.routing_incremental:
        targets = ("enterprise-routing-incremental",)
    elif args.root_format_diff:
        targets = ("enterprise-root-format-diff",)
    elif args.enterprise:
        targets = ("enterprise-tests",)
    elif args.checkpoint_graph:
        targets = ("enterprise-checkpoint-graph",)
    elif args.checkpoint_graph_checks:
        targets = ("enterprise-checkpoint-graph-checks",)
    elif args.checkpoint_graph_mypy:
        targets = ("enterprise-checkpoint-graph-mypy",)
    elif args.checkpoint_regressions:
        targets = ("enterprise-checkpoint-regressions",)
    elif args.helm:
        targets = ("enterprise-helm",)
    elif args.schema_collectors:
        targets = ("enterprise-schema-collectors",)
    elif args.schema_fixture_diff:
        targets = ("enterprise-schema-fixture-diff",)
    elif args.clock_evidence:
        targets = ("enterprise-clock-evidence",)
    elif args.clock_evidence_focused:
        targets = ("enterprise-clock-evidence-focused",)
    elif args.latest_format_diff:
        targets = ("enterprise-latest-format-diff",)
    else:
        targets = (
            "enterprise-smoke",
            "enterprise-lint",
            "enterprise-typecheck",
            "enterprise-tests",
            "enterprise-artifacts",
        )
    print(f"remote builder: {NAMESPACE}/{pod}; context: {context_id}", flush=True)
    base_command = [
        *kubectl,
        pod,
        "--",
        "buildctl",
        "--addr",
        "unix:///run/user/1000/buildkit/buildkitd.sock",
        "build",
        "--frontend",
        "dockerfile.v0",
        "--local",
        f"context={remote}",
        "--local",
        f"dockerfile={remote}",
        "--opt",
        "filename=deploy/symbolic/EnterpriseTest.Containerfile",
        "--opt",
        "platform=linux/amd64",
        "--opt",
        f"build-arg:HST_CONTEXT_ID={context_id}",
    ]
    for target in targets:
        print(f"remote target: {target}", flush=True)
        command = [*base_command, "--opt", f"target={target}"]
        run(command, timeout=1200)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.TimeoutExpired as exc:
        print(f"remote validation exceeded its {exc.timeout}s client deadline", file=sys.stderr)
        raise SystemExit(124) from exc
    except (subprocess.CalledProcessError, RuntimeError, FileNotFoundError) as exc:
        print(f"remote validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
