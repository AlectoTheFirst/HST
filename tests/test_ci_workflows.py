"""The GitHub workflows and the Dependabot configuration.

The paths job of ci counts a docs file that a test reads as code.

Every job runs on a GitHub-hosted runner. test-integration gets its Postgres
and Neo4j as job-level service containers, so no two runs share a database.
release pushes to the repository's own ghcr.io package with the workflow token.

cla reports the commit status `cla` for a pull request. It runs with this
repository's token for a pull request from a fork, so it executes nothing from
the pull request and takes no contributor text through an expression.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import textwrap
from fnmatch import fnmatch
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
CI_SERVICES = ROOT / ".github" / "ci-services" / "compose.yaml"

# `"docs" / "examples"` and `"docs/examples/business-application.yaml"`
_READS = re.compile(r'"docs"\s*/\s*"([^"]+)"|"(docs/[^"\s]+\.(?:md|ya?ml|json))"')


def _code_docs_patterns() -> list[str]:
    ci = (WORKFLOWS / "ci.yml").read_text()
    for line in ci.splitlines():
        stripped = line.strip()
        if stripped.startswith("docs/") and stripped.endswith(")"):
            return stripped[:-1].split("|")
    raise AssertionError("ci.yml has no case line for the docs files that tests read")


def _docs_read_by_tests() -> set[str]:
    found: set[str] = set()
    for path in (ROOT / "tests").rglob("*.py"):
        if path.name == Path(__file__).name:
            continue
        for match in _READS.finditer(path.read_text()):
            name = f"docs/{match.group(1)}" if match.group(1) else match.group(2)
            # a docs path a test only names as fixture data is not a file it reads
            if not (ROOT / name).exists():
                continue
            if (ROOT / name).is_dir():
                name = f"{name}/x"
            found.add(name)
    return found


def test_every_docs_file_a_test_reads_counts_as_code():
    patterns = _code_docs_patterns()
    read = _docs_read_by_tests()
    assert "docs/examples/x" in read
    missing = sorted(name for name in read if not any(fnmatch(name, p) for p in patterns))
    assert missing == []


def test_every_code_docs_pattern_names_something_in_the_tree():
    for pattern in _code_docs_patterns():
        assert list(ROOT.glob(pattern)), pattern


def test_the_code_docs_line_comes_before_the_docs_pattern_and_names_no_plan_md():
    ci = (WORKFLOWS / "ci.yml").read_text()
    code_line = ci.index("docs/examples/*)")
    docs_line = ci.index("|docs/*)")
    assert code_line < docs_line
    assert "PLAN.md" not in ci


# `"web" / "src" / "api" / "inventory.ts"` and `"web/src/settings/schema.fixtures.json"`
_WEB_READS = re.compile(r'"web"((?:\s*/\s*"[^"]+")+)|"(web/[^"\s]+)"')


def _code_web_patterns() -> list[str]:
    ci = (WORKFLOWS / "ci.yml").read_text()
    for line in ci.splitlines():
        stripped = line.strip()
        if stripped.startswith("web/src/") and stripped.endswith(")"):
            return stripped[:-1].split("|")
    raise AssertionError("ci.yml has no case line for the web files that Python tests read")


def _web_files_read_by_python() -> set[str]:
    """The files under web/ that a test names, or that a module of src/hst names."""
    found: set[str] = set()
    for top in ("tests", "src"):
        for path in (ROOT / top).rglob("*.py"):
            if path.name == Path(__file__).name:
                continue
            for match in _WEB_READS.finditer(path.read_text()):
                name = (
                    "web/" + "/".join(re.findall(r'"([^"]+)"', match.group(1)))
                    if match.group(1)
                    else match.group(2)
                )
                if (ROOT / name).is_file():
                    found.add(name)
    return found


def test_every_web_file_a_python_test_reads_counts_as_code():
    patterns = _code_web_patterns()
    read = _web_files_read_by_python()
    assert "web/src/api/inventory.ts" in read
    assert sorted(read) == sorted(patterns)
    paths = _step("ci.yml", "paths", "Determine changed path groups")["run"]
    line = "|".join(patterns) + ")\n"
    # the line stands before `web/*)`, and a file of the line also selects test-web
    assert paths.index(line) < paths.index("web/*)\n")
    assert paths[paths.index(line) + len(line) :].lstrip().startswith("code=true; web=true ;;")


def test_a_pull_request_that_changes_a_web_file_a_python_test_reads_runs_the_python_jobs(tmp_path):
    paths = _step("ci.yml", "paths", "Determine changed path groups")["run"]
    loop = paths[paths.index("code=false; web=false;") : paths.index('echo "code=$code"')]
    head, _, tail = loop.partition("done <<<")
    assert tail.strip() == '"$(git diff --name-only "$base"...HEAD)"'
    script = head + 'done <<< "$CHANGED"\necho "$code $web $image"\n'

    def groups(*changed: str) -> str:
        result = _run(script, {"CHANGED": "\n".join(changed)})
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()

    assert groups("web/src/App.tsx") == "false true false"
    for name in _code_web_patterns():
        assert groups(name) == "true true false", name
    assert groups("README.md") == "false false false"
    assert groups("docs/examples/business-application.yaml") == "true false false"
    assert groups("src/hst/cli.py") == "true false false"
    assert groups("pyproject.toml") == "true false true"
    assert groups("third_party/symbolic/build-lock.json") == "true false true"
    assert groups("fixtures/demo-enterprise/estate-v1.yaml") == "true false true"
    assert groups("web/package-lock.json") == "false true true"


def test_every_job_runs_on_a_github_hosted_runner():
    # release.yml's validate job calls ci.yml and has no runs-on of its own
    jobs = {"audit.yml": 1, "ci.yml": 8, "cla.yml": 1, "release.yml": 2}
    assert set(jobs) == {path.name for path in WORKFLOWS.iterdir()}
    for name, count in jobs.items():
        workflow = (WORKFLOWS / name).read_text()
        assert re.findall(r"runs-on:\s*(.+)", workflow) == ["ubuntu-latest"] * count, name
        assert "self-hosted" not in workflow
    assert not (ROOT / ".github" / "actionlint.yaml").exists()


def test_the_unit_suites_use_every_cpu_of_the_runner():
    assert "PYTEST_XDIST_AUTO_NUM_WORKERS" not in (WORKFLOWS / "ci.yml").read_text()


def _job(workflow: str, name: str) -> str:
    text = (WORKFLOWS / workflow).read_text()
    start = text.index(f"\n  {name}:\n")
    following = re.search(r"\n  [a-z][a-z-]*:\n", text[start + 1 :])
    return text[start : start + 1 + following.start()] if following else text[start:]


def _jobs(workflow: str) -> dict:
    return yaml.safe_load((WORKFLOWS / workflow).read_text())["jobs"]


def _step(workflow: str, job: str, name: str) -> dict:
    """The step with this name, or the step that uses this action."""
    for step in _jobs(workflow)[job]["steps"]:
        if step.get("name") == name or step.get("uses", "").startswith(f"{name}@"):
            return step
    raise AssertionError(f"{workflow} {job} has no step {name}")


def _step_names(workflow: str, job: str) -> list[str]:
    return [step.get("name") or step["uses"].split("@")[0] for step in _jobs(workflow)[job]["steps"]]


def _run(script: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """One `run:` script in the shell of a GitHub-hosted runner."""
    bash = shutil.which("bash")
    assert bash
    return subprocess.run(
        [bash, "-eo", "pipefail", "-c", script],
        cwd=ROOT,
        env={"PATH": os.environ["PATH"], **env},
        capture_output=True,
        text=True,
        check=False,
    )


def test_test_integration_runs_against_its_own_service_containers():
    job = _job("ci.yml", "test-integration")
    assert re.findall(r"runs-on:\s*(\S+)", job) == ["ubuntu-latest"]
    services = job[job.index("\n    services:\n") : job.index("\n    env:\n")]
    assert re.findall(r"image: (.+)", services) == [
        "${{ needs.paths.outputs.postgres_image }}",
        "${{ needs.paths.outputs.neo4j_image }}",
    ]
    assert 'ports: ["5544:5432"]' in services
    assert '"7699:7687"' in services
    assert services.count("--health-cmd") == 2
    assert ".svc" not in job
    assert "HST_TEST_PG_DSN: postgresql+asyncpg://hst:citest@localhost:5544/hst_test" in job
    assert "NEO4J_TEST_URI: bolt://localhost:7699" in job
    assert "NEO4J_URI: bolt://localhost:7699" in job
    # the containers are this job's alone: nothing to wait for, nothing left to drop
    first_step = job.index("    steps:\n") + len("    steps:\n")
    assert job[first_step:].lstrip().startswith("- uses: actions/checkout@")
    assert "Wait for older runs" not in job
    assert "actions: read" not in job
    assert "DROP DATABASE" not in job
    for database in ("hst_smoke", "hst_worker_smoke"):
        assert f'"CREATE DATABASE {database}"' in job
        assert f"@localhost:5544/{database}\n" in job


def test_every_service_image_has_a_digest(tmp_path):
    images = {
        name: service["image"]
        for name, service in yaml.safe_load(CI_SERVICES.read_text())["services"].items()
    }
    assert set(images) == {"postgres", "neo4j"}
    for image in images.values():
        assert re.fullmatch(r"[\w./-]+:[\w.-]+@sha256:[0-9a-f]{64}", image), image
    # every service container of every workflow takes its image from the paths job
    for path in sorted(WORKFLOWS.glob("*.yml")):
        for job in yaml.safe_load(path.read_text())["jobs"].values():
            for name, service in job.get("services", {}).items():
                assert service["image"] == f"${{{{ needs.paths.outputs.{name}_image }}}}", path.name
                assert "paths" in job["needs"]
    outputs = _jobs("ci.yml")["paths"]["outputs"]
    for name in images:
        assert outputs[f"{name}_image"] == f"${{{{ steps.services.outputs.{name} }}}}"
    step = _step("ci.yml", "paths", "Service images")
    assert step["id"] == "services"
    written = tmp_path / "output"
    result = _run(step["run"], {"GITHUB_OUTPUT": str(written)})
    assert result.returncode == 0, result.stdout + result.stderr
    assert written.read_text().splitlines() == [f"{name}={images[name]}" for name in ("postgres", "neo4j")]


def test_dependabot_reads_every_containerfile_and_compose_file():
    updates = {
        entry["package-ecosystem"]: entry
        for entry in yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text())["updates"]
    }
    assert set(updates) == {"uv", "npm", "docker", "docker-compose", "github-actions"}
    assert set(updates["uv"]["groups"]) == {"python-minor"}
    assert set(updates["npm"]["groups"]) == {"npm-minor"}
    containerfiles = {
        f"/{path.parent.relative_to(ROOT).as_posix()}"
        for path in (ROOT / "deploy").rglob("*")
        if path.is_file() and "containerfile" in path.name.lower()
    }
    assert containerfiles == {"/deploy", "/deploy/symbolic"}
    assert set(updates["docker"]["directories"]) == containerfiles
    # the file name pattern of the docker-compose ecosystem of Dependabot
    compose = re.compile(r"(docker-)?compose(-[\w]+)?(\.[\w-]+)?\.ya?ml", re.I)
    assert set(updates["docker-compose"]["directories"]) == {"/", "/.github/ci-services"}
    for directory in updates["docker-compose"]["directories"]:
        names = [path.name for path in (ROOT / directory.lstrip("/")).iterdir()]
        assert any(compose.fullmatch(name) for name in names), directory


def test_each_long_running_compose_service_has_the_pids_limit_of_podman():
    stack = yaml.safe_load((ROOT / "compose.yaml").read_text())["services"]
    worker = yaml.safe_load((ROOT / "compose.worker.yaml").read_text())["services"]["worker"]
    running = {name: service for name, service in stack.items() if service["restart"] == "unless-stopped"}
    assert set(running) == {"app", "neo4j", "pg"}
    assert worker["restart"] == "unless-stopped"
    for name, service in {**running, "worker": worker}.items():
        assert service["pids_limit"] == 2048, name


def test_the_makefile_defaults_of_the_local_cluster_and_the_estate_benchmark():
    makefile = (ROOT / "Makefile").read_text()
    # `kind create cluster` gives a cluster the name `kind`
    assert "\nKIND_CLUSTER ?= kind\n" in makefile
    assert "\nPLATFORM ?= $(if $(REGISTRY),linux/amd64,linux/$(HOST_ARCH))\n" in makefile
    recipe = makefile[makefile.index("\nestate-acceptance:") :]
    recipe = recipe[: recipe.index("\n\n")]
    assert "\tHST_ESTATE_ACCEPTANCE=1 $(RUN) pytest -q tests/perf/test_estate_acceptance.py" in recipe
    test = (ROOT / "tests" / "perf" / "test_estate_acceptance.py").read_text()
    for name in re.findall(r"for v in ([A-Z0-9_ ]+); do", recipe)[0].split():
        assert f'os.environ["{name}"]' in test, name


def test_the_local_test_stack_matches_the_ci_service_containers():
    makefile = (ROOT / "Makefile").read_text()
    job = _job("ci.yml", "test-integration")
    assert "-e POSTGRES_USER=hst -e POSTGRES_PASSWORD=citest" in makefile
    assert "-e NEO4J_AUTH=neo4j/citest-password" in makefile
    for line in re.findall(r"^\t(\S+=\S+(?: \S+=\S+)*) \$\(MAKE\) (?:test-pg|test-db|e2e)$", makefile, re.M):
        for assignment in line.split():
            key, _, value = assignment.partition("=")
            assert f"{key}: {value}\n" in job, assignment


def test_test_integration_approves_the_scratch_neo4j_for_the_mtu_graph_tests():
    job = _job("ci.yml", "test-integration")
    step = job[job.index("- name: Integration tests (lifecycle against the scratch Neo4j)") :]
    step = step[: step.index("run: make test-db")]
    assert 'HST_MTU_TEST_NEO4J_APPROVED: "1"' in step


def test_every_output_of_the_paths_job_is_read():
    ci = (WORKFLOWS / "ci.yml").read_text()
    for name in _jobs("ci.yml")["paths"]["outputs"]:
        assert f"needs.paths.outputs.{name} " in ci, name


def test_the_required_check_covers_the_image_build(monkeypatch):
    jobs = _jobs("ci.yml")
    image = jobs["image"]
    assert image["needs"] == ["paths"]
    assert image["if"] == "needs.paths.outputs.image == 'true'"
    build = _step("ci.yml", "image", "Build without a push")
    assert build["uses"].startswith("docker/build-push-action@")
    assert build["with"]["file"] == "deploy/Containerfile"
    assert build["with"]["push"] is False
    assert "permissions" not in image
    paths = _step("ci.yml", "paths", "Determine changed path groups")["run"]
    selected = (
        "deploy/Containerfile|.dockerignore|uv.lock|web/package-lock.json|.github/workflows/*) image=true ;;"
    )
    assert selected in paths
    assert paths.count("for g in code web labels webinfra image;") == 3
    # every file of the build context that deploy/Containerfile reads selects the job,
    # except src/ and web/, the readme and the licence
    recipe = (ROOT / "deploy" / "Containerfile").read_text()
    sources: set[str] = set()
    for line in recipe.splitlines():
        if line.startswith("COPY ") and "--from=" not in line:
            sources.update(line.split()[1:-1])
        sources.update(re.findall(r"--mount=type=bind,source=([^,\s]+)", line))
    sources -= {"src", "web/", "web/package*.json", "README.md", "LICENSE"}
    assert {"pyproject.toml", "uv.lock", "tools/smoke_image.py", "fixtures/demo-enterprise"} <= sources
    patterns = [p for line in re.findall(r"^\s*(\S+)\) image=true ;;$", paths, re.M) for p in line.split("|")]
    for source in sorted(sources):
        name = f"{source}x" if source.endswith("/") else source
        name = f"{name}/x" if (ROOT / source).is_dir() and not source.endswith("/") else name
        assert any(fnmatch(name, p) for p in patterns), source

    assert jobs["python"]["needs"] == [
        "paths",
        "python-checks",
        "test-python",
        "test-integration",
        "test-web",
        "image",
        "secrets",
    ]
    assert jobs["python"]["if"] == "always()"
    script = jobs["python"]["steps"][0]["run"]
    script = script[script.index("<<'PYTHON'\n") + len("<<'PYTHON'\n") : script.rindex("PYTHON")]

    def check(image_group: str, image_result: str) -> None:
        groups = {
            "code": "false",
            "web": "false",
            "labels": "false",
            "webinfra": "false",
            "image": image_group,
        }
        needs = {name: {"result": "skipped", "outputs": {}} for name in jobs["python"]["needs"]}
        needs["paths"] = {"result": "success", "outputs": groups}
        needs["secrets"]["result"] = "success"
        needs["image"]["result"] = image_result
        monkeypatch.setenv("NEEDS", json.dumps(needs))
        # the text is this repository's own workflow file, not input
        exec(script, {})  # noqa: S102

    check("false", "skipped")
    check("true", "success")
    for result in ("skipped", "failure", "cancelled"):
        with pytest.raises(AssertionError):
            check("true", result)
    with pytest.raises(AssertionError):
        check("false", "failure")


def test_the_secrets_job_runs_a_pinned_gitleaks_binary():
    job = _jobs("ci.yml")["secrets"]
    # the job needs no secret and no permission, so it runs for a pull request from a fork
    assert "permissions" not in job
    assert "secrets." not in _job("ci.yml", "secrets")
    assert "gitleaks-action" not in (WORKFLOWS / "ci.yml").read_text()
    step = _step("ci.yml", "secrets", "Scan commits for secrets")
    assert step["env"] == {"GITLEAKS_VERSION": "8.30.1", "BASE": "${{ github.event.pull_request.base.sha }}"}
    assert "GITLEAKS_VERSION" in (ROOT / ".gitleaks.toml").read_text()
    script = step["run"]
    assert len(set(re.findall(r"\bsum=([0-9a-f]{64}) ;;", script))) == 2
    assert "gitleaks_${GITLEAKS_VERSION}_linux_${arch}.tar.gz" in script
    assert script.index("sha256sum -c -") < script.index("tar -xzf")
    assert script.count('gitleaks" git --config .gitleaks.toml --redact --no-banner') == 2
    assert '--log-opts="$BASE..HEAD"' in script
    assert "${{" not in script


def test_the_audit_runs_on_a_schedule_outside_the_required_check():
    workflow = yaml.safe_load((WORKFLOWS / "audit.yml").read_text())
    # PyYAML reads the key `on` as True
    assert set(workflow[True]) == {"schedule", "workflow_dispatch", "pull_request"}
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["audit"]
    assert job["steps"][-1] == {"name": "Audit", "run": "make audit"}
    uv = next(step for step in job["steps"] if step.get("uses", "").startswith("astral-sh/setup-uv@"))
    assert uv["with"]["cache-suffix"] == "audit"
    assert "cache-suffix" not in (WORKFLOWS / "ci.yml").read_text()
    assert "continue-on-error" not in (WORKFLOWS / "audit.yml").read_text()
    ci = (WORKFLOWS / "ci.yml").read_text()
    for step in job["steps"]:
        if "uses" in step:
            assert f"uses: {step['uses']}\n" in ci
    assert "audit" not in _jobs("ci.yml")["python"]["needs"]
    makefile = (ROOT / "Makefile").read_text()
    assert "audit:  ##" in makefile
    assert re.search(r"tool run --from pip-audit==\d+\.\d+\.\d+ pip-audit ", makefile)


def test_the_workflows_and_the_containerfiles_pin_one_uv_version():
    versions: set[str] = set()
    for path in sorted(WORKFLOWS.glob("*.yml")):
        for job in yaml.safe_load(path.read_text())["jobs"].values():
            for step in job.get("steps", []):
                if step.get("uses", "").startswith("astral-sh/setup-uv@"):
                    versions.add(step["with"]["version"])
    assert versions
    for name in ("deploy/Containerfile", "deploy/symbolic/EnterpriseTest.Containerfile"):
        found = re.findall(r"ghcr\.io/astral-sh/uv:([\d.]+)@sha256:", (ROOT / name).read_text())
        assert found, name
        versions.update(found)
    assert len(versions) == 1, versions


def test_release_pushes_to_the_repository_package_with_the_workflow_token():
    release = (WORKFLOWS / "release.yml").read_text()
    assert "vars." not in release
    assert set(re.findall(r"secrets\.(\w+)", release)) == {"GITHUB_TOKEN"}
    for name in ("image", "promote"):
        job = _job("release.yml", name)
        assert "\n    if: vars." not in job
        assert "      packages: write\n" in job
        assert 'echo "IMAGE=ghcr.io/${GITHUB_REPOSITORY,,}" >> "$GITHUB_ENV"' in job
        assert 'docker login ghcr.io --username "$GITHUB_ACTOR" --password-stdin' in job
        assert "driver: remote" not in job
    image = _job("release.yml", "image")
    assert "      id-token: write\n" in image
    assert "platforms: linux/amd64\n" in image
    by_digest = "${{ env.IMAGE }}@${{ steps.build.outputs.digest }}"
    assert f"image: {by_digest}\n" in image
    assert 'cosign sign --yes "$IMAGE@$DIGEST"' in image
    assert 'cosign attest --yes --type spdxjson --predicate sbom.spdx.json "$IMAGE@$DIGEST"' in image


def test_release_tags_the_image_after_the_scan_the_signature_and_the_attestation():
    build = _step("release.yml", "image", "Build and push by digest")
    assert build["id"] == "build"
    assert build["with"]["outputs"] == (
        "type=image,name=${{ env.IMAGE }},push-by-digest=true,name-canonical=true,push=true"
    )
    assert "tags" not in build["with"]
    assert "push" not in build["with"]
    names = _step_names("release.yml", "image")
    order = ["Trivy scan", "Build and push by digest", "Sign the image", "Attest the SBOM", "Tag the image"]
    assert [name for name in names if name in order] == order
    assert "continue-on-error" not in (WORKFLOWS / "release.yml").read_text()
    # the step "Tag the image" is the one step of the job that writes a tag
    for step in _jobs("release.yml")["image"]["steps"]:
        tags = "--tag" in step.get("run", "")
        assert tags == (step.get("name") == "Tag the image"), step
    assert '--tag "$IMAGE:$SHA" "$IMAGE@$DIGEST"' in _step("release.yml", "image", "Tag the image")["run"]


def test_release_scans_the_archive_of_the_image_before_the_push():
    archive = "${{ runner.temp }}/hst-image.tar"
    scan_build = _step("release.yml", "image", "Build for the scan")
    push_build = _step("release.yml", "image", "Build and push by digest")
    assert scan_build["with"]["outputs"] == f"type=docker,dest={archive}"
    assert "push" not in scan_build["with"]
    for key in ("context", "file", "platforms", "build-args"):
        assert scan_build["with"][key] == push_build["with"][key], key
    trivy = _step("release.yml", "image", "Trivy scan")
    assert trivy["with"]["input"] == archive
    assert "image-ref" not in trivy["with"]
    assert trivy["with"]["exit-code"] == "1"
    names = _step_names("release.yml", "image")
    order = ["Build for the scan", "Trivy scan", "Build and push by digest"]
    assert [name for name in names if name in order] == order
    steps = _jobs("release.yml")["image"]["steps"]
    writers = [step.get("name") for step in steps if "push=true" in str(step.get("with"))]
    assert writers == ["Build and push by digest"]


def test_promote_verifies_the_signature_of_main_before_it_tags():
    job = _jobs("release.yml")["promote"]
    assert job["needs"] == ["image", "validate"]
    assert job["env"]["DIGEST"] == "${{ needs.image.outputs.digest }}"
    names = _step_names("release.yml", "promote")
    order = [
        "sigstore/cosign-installer",
        "Verify that release.yml on main signed the candidate",
        "Refuse a version tag that exists",
        "Sign the promoted image",
        "Tag the candidate as stable",
    ]
    assert names[-5:] == order
    verify = _step("release.yml", "promote", order[1])
    assert "if" not in verify
    identity = "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/.github/workflows/release.yml@refs/heads/main"
    assert f'--certificate-identity "{identity}" \\\n' in verify["run"]
    assert "--certificate-oidc-issuer https://token.actions.githubusercontent.com \\\n" in verify["run"]
    assert verify["run"].rstrip().endswith('"$IMAGE@$DIGEST"')
    assert "identity-regexp" not in verify["run"]
    for step in job["steps"]:
        assert ("imagetools create" in step.get("run", "")) == (step.get("name") == order[4]), step


def test_promote_signs_the_image_with_the_stable_annotation_before_it_tags():
    job = _jobs("release.yml")["promote"]
    assert job["permissions"] == {"id-token": "write", "packages": "write"}
    sign = _step("release.yml", "promote", "Sign the promoted image")
    assert sign["run"] == 'cosign sign --yes -a channel=stable "$IMAGE@$DIGEST"'
    assert "if" not in sign
    # the image job signs a candidate without the annotation
    assert "channel=stable" not in _job("release.yml", "image")
    assert "channel=stable" not in (WORKFLOWS / "ci.yml").read_text()


def test_release_reads_the_version_from_the_full_history_and_labels_the_image(tmp_path):
    checkout = _jobs("release.yml")["image"]["steps"][0]
    assert checkout["uses"].startswith("actions/checkout@")
    assert checkout["with"]["fetch-depth"] == 0
    assert checkout["with"]["fetch-tags"] is True
    step = _step("release.yml", "image", "Release version")
    assert step["id"] == "version"
    written = tmp_path / "output"
    result = _run(step["run"], {"GITHUB_OUTPUT": str(written)})
    assert result.returncode == 0, result.stdout + result.stderr
    package = re.search(r'^__version__ = "([^"]+)"$', (ROOT / "src/hst/__init__.py").read_text(), re.M)
    assert package
    assert written.read_text().splitlines()[0] == f"package={package.group(1)}"
    for name in ("Build for the scan", "Build and push by digest"):
        args = _step("release.yml", "image", name)["with"]["build-args"].splitlines()
        assert args[0] == "VERSION=${{ steps.version.outputs.package }}", name
    recipe = (ROOT / "deploy" / "Containerfile").read_text()
    assert 'org.opencontainers.image.version="${VERSION}"' in recipe


def test_promote_refuses_a_version_tag_that_exists(tmp_path):
    step = _step("release.yml", "promote", "Refuse a version tag that exists")
    assert step["if"] == "env.VERSION != ''"
    docker = tmp_path / "docker"
    docker.write_text('#!/bin/sh\nprintf \'%s\\n\' "$FAKE_OUTPUT"\nexit "$FAKE_STATUS"\n')
    docker.chmod(0o755)

    def run(status: int, output: str) -> int:
        env = {
            "PATH": f"{tmp_path}:{os.environ['PATH']}",
            "IMAGE": "ghcr.io/owner/hst",
            "VERSION": "1.2.3",
            "FAKE_STATUS": str(status),
            "FAKE_OUTPUT": output,
        }
        return _run(step["run"], env).returncode

    assert run(0, "sha256:" + "a" * 64) == 1
    assert run(1, "ERROR: ghcr.io/owner/hst:1.2.3: not found") == 0
    assert run(1, "ERROR: unexpected status from HEAD request: 403 Forbidden") == 1
    assert run(1, "ERROR: no resolve hosts: not found") == 1


# `uses:` as a key of its own. A bare search also finds the permission `statuses:`.
_USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)", re.M)


def test_every_action_is_pinned_by_commit_sha():
    for path in sorted(WORKFLOWS.glob("*.yml")):
        for ref in _USES.findall(path.read_text()):
            if ref.startswith("./"):
                continue
            assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", ref), f"{path.name}: {ref}"


def _cla_script() -> dict:
    """The names the script in cla.yml defines, without a run of its main()."""
    workflow = (WORKFLOWS / "cla.yml").read_text()
    start = workflow.index("python3 - <<'PYTHON'\n") + len("python3 - <<'PYTHON'\n")
    namespace: dict = {"__name__": "cla_script"}
    # the text is this repository's own workflow file, not input
    exec(textwrap.dedent(workflow[start : workflow.rindex("PYTHON")]), namespace)  # noqa: S102
    return namespace


def _pull(opener: str, body: str = "", commits: int = 1) -> dict:
    return {"user": {"login": opener}, "body": body, "commits": commits}


def _commit(login: str | None, sha: str = "0123456789abcdef") -> dict:
    return {"sha": sha, "author": {"login": login} if login else None}


def _comment(login: str, body: str) -> dict:
    return {"user": {"login": login}, "body": body}


def test_the_cla_workflow_executes_nothing_from_the_pull_request():
    workflow = (WORKFLOWS / "cla.yml").read_text()
    assert _USES.findall(workflow) == []
    assert "checkout" not in workflow.replace("no checkout", "")
    assert "\npermissions: {}\n" in workflow
    job = _job("cla.yml", "status")
    permissions = job[job.index("    permissions:\n") : job.index("    env:\n")]
    assert permissions.split("\n")[1:-1] == ["      pull-requests: read", "      statuses: write"]
    # a number and the token: no description, comment, title, branch or author name
    number = "github.event.pull_request.number || github.event.issue.number"
    assert set(re.findall(r"\$\{\{\s*(.+?)\s*\}\}", workflow)) == {number, "github.token"}
    assert "secrets." not in workflow


def test_the_cla_sentence_is_the_one_in_cla_md():
    script = _cla_script()
    cla = (ROOT / "CLA.md").read_text()
    assert script["normal"](script["SENTENCE"]) in script["normal"](cla)
    assert "version 1.0" in script["SENTENCE"]
    assert "\nVersion 1.0\n" in cla


def test_the_cla_status_names_who_has_not_agreed():
    script = _cla_script()
    missing, sentence = script["missing_signers"], script["SENTENCE"]
    quoted = (
        "> I have read CLA.md version 1.0 and I agree to it for this and all my past and\n"
        "> future contributions to this repository."
    )
    owner = "TheOwner"

    def check(pull, commits, comments=()):
        return missing(pull, commits, list(comments), owner)

    # nobody wrote it
    assert check(_pull("ann"), [_commit("ann")]) == (["ann"], [])
    # in the description, or in a comment, copied with the quote marks and the line break
    assert check(_pull("ann", f"Fixes a bug.\n\n{sentence}"), [_commit("ann")]) == ([], [])
    assert check(_pull("ann"), [_commit("ann")], [_comment("ANN", quoted)]) == ([], [])
    # each author writes it from their own account; a changed sentence does not count
    two = [_commit("ann"), _commit("bob")]
    assert check(_pull("ann", sentence), two) == (["bob"], [])
    assert check(_pull("ann", sentence), two, [_comment("ann", sentence)]) == (["bob"], [])
    assert check(_pull("ann", sentence), two, [_comment("bob", sentence)]) == ([], [])
    assert check(_pull("ann", sentence.replace("past and ", "")), [_commit("ann")]) == (["ann"], [])
    # the person who opened it agrees even when every commit names another account
    assert check(_pull("ann"), [_commit("dependabot[bot]"), _commit(owner)]) == (["ann"], [])
    # the configured accounts and the owner open pull requests without it
    assert check(_pull("dependabot[bot]"), [_commit("dependabot[bot]")]) == ([], [])
    assert check(_pull("theowner"), [_commit("ann"), _commit(None)]) == ([], [])
    # a commit that names no account is reported, not passed
    assert check(_pull("ann", sentence), [_commit("ann"), _commit(None, "f" * 40)]) == ([], ["f" * 10])


_AGREED = ("success", "The CLA.md sentence is there for every commit author")
_BOB_MISSING = ("failure", "The CLA.md sentence is missing from: bob")


def test_the_cla_status_fails_above_250_commits():
    script = _cla_script()
    verdict, outcome, sentence = script["verdict"], script["outcome"], script["SENTENCE"]
    owner = "TheOwner"
    commits = [_commit("ann")]
    assert verdict(_pull("ann", sentence, 250), commits, [], owner) == _AGREED
    too_many = verdict(_pull("ann", sentence, 251), commits, [], owner)
    assert too_many == ("failure", "More than 250 commits")
    assert outcome(1, {1: too_many}) == (*too_many, True)
    assert verdict(_pull("theowner", "", 251), commits, [], owner) == _AGREED
    assert verdict(_pull("bob", "", 1), [_commit("bob")], [], owner) == _BOB_MISSING


def test_the_cla_status_covers_every_open_pull_request_with_the_head_commit():
    outcome = _cla_script()["outcome"]
    other = f"Pull request 2 has the same head commit. {_BOB_MISSING[1]}"
    assert outcome(1, {1: _AGREED}) == (*_AGREED, False)
    assert outcome(1, {1: _BOB_MISSING}) == (*_BOB_MISSING, False)
    assert outcome(1, {1: _AGREED, 2: _AGREED}) == (*_AGREED, False)
    assert outcome(1, {1: _AGREED, 2: _BOB_MISSING}) == ("failure", other, True)
    assert outcome(2, {1: _AGREED, 2: _BOB_MISSING}) == (*_BOB_MISSING, True)
    # the pull request of the event is closed
    assert outcome(3, {2: _BOB_MISSING}) == ("failure", other, False)


def test_the_cla_run_reports_one_status_for_two_pull_requests_with_one_head_commit(monkeypatch):
    script = _cla_script()
    head = "a" * 40

    def pull(number: int, opener: str, body: str, sha: str) -> dict:
        return {**_pull(opener, body), "number": number, "head": {"sha": sha}, "base": {"ref": "main"}}

    pulls = {
        1: pull(1, "ann", script["SENTENCE"], head),
        2: pull(2, "bob", "", head),
        3: pull(3, "bob", "", "b" * 40),
    }
    open_pulls = {1, 2, 3}
    posted: list[tuple[str, dict]] = []

    def api(path: str, data: dict | None = None):
        if data is not None:
            posted.append((path, data))
            return {}
        if match := re.fullmatch(r"pulls/(\d+)", path):
            return pulls[int(match[1])]
        if path == "pulls?per_page=100&page=1&state=open":
            return [pulls[number] for number in sorted(open_pulls)]
        if re.fullmatch(r"pulls/\d+/commits\?per_page=100&page=1", path):
            return [_commit("ann")]
        if re.fullmatch(r"issues/\d+/comments\?per_page=100&page=1", path):
            return []
        raise AssertionError(path)

    script["api"] = api
    monkeypatch.setenv("GITHUB_REPOSITORY_OWNER", "TheOwner")
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.example")
    monkeypatch.setenv("GITHUB_REPOSITORY", "TheOwner/hst")

    def status(state: str, description: str) -> tuple[str, dict]:
        target = "https://github.example/TheOwner/hst/blob/main/CLA.md"
        return f"statuses/{head}", {
            "state": state,
            "context": "cla",
            "description": description,
            "target_url": target,
        }

    # a run for the signed pull request 1 reports pull request 2, which holds no sentence
    monkeypatch.setenv("PR", "1")
    assert script["main"]() == 1
    missing = "The CLA.md sentence is missing from: ann, bob"
    assert posted == [status("failure", f"Pull request 2 has the same head commit. {missing}")]
    # pull request 2 is closed, and its `closed` event reports for pull request 1
    posted.clear()
    open_pulls.discard(2)
    monkeypatch.setenv("PR", "2")
    assert script["main"]() == 0
    assert posted == [status(*_AGREED)]
    workflow = yaml.safe_load((WORKFLOWS / "cla.yml").read_text())
    assert "closed" in workflow[True]["pull_request_target"]["types"]
