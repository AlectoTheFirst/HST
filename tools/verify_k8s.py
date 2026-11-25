#!/usr/bin/env python3
"""Check that the pods of a deployed release are ready and that the release serves.

Run with `make k8s-verify`. Read-only: it creates nothing and changes nothing.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Iterator

NS = os.environ.get("K8S_NS", "hst")
RELEASE = os.environ.get("RELEASE", "hst")
# Without HST_URL the script opens a port-forward to the Service.
BASE = os.environ.get("HST_URL", "")
HOST = os.environ.get("HST_HOST", "")
# The chart name. service_name() builds the Service name from it, RELEASE and FULLNAME_OVERRIDE.
CHART_NAME = "hst"
FULLNAME_OVERRIDE = os.environ.get("FULLNAME_OVERRIDE", "")

KUBECTL = shutil.which("kubectl")
_BASE = ""  # resolved in main(): HST_URL, or the port-forward opened there
_failures: list[str] = []


def service_name() -> str:
    """The Service name, by the same rule the chart's `hst.fullname` helper uses."""
    if FULLNAME_OVERRIDE:
        return FULLNAME_OVERRIDE[:63].rstrip("-")
    name = RELEASE if CHART_NAME in RELEASE else f"{RELEASE}-{CHART_NAME}"
    return name[:63].rstrip("-")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@contextlib.contextmanager
def _service_url() -> Iterator[str]:
    """A URL for the release, port-forwarding the Service when none was given."""
    if BASE:
        if not BASE.startswith(("http://", "https://")):
            raise SystemExit("HST_URL must start with http:// or https://")
        yield BASE
        return
    if KUBECTL is None:
        raise SystemExit("kubectl is not on PATH")
    port = _free_port()
    proc = subprocess.Popen(  # noqa: S603 - kubectl from PATH, arguments from this file and K8S_NS
        [KUBECTL, "-n", NS, "port-forward", f"svc/{service_name()}", f"{port}:8787"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            with contextlib.suppress(OSError), socket.create_connection(("127.0.0.1", port), 0.5):
                break
            time.sleep(0.3)
        yield f"http://127.0.0.1:{port}"
    finally:
        proc.terminate()
        with contextlib.suppress(Exception):
            proc.wait(timeout=5)


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if ok else 'FAIL'}  {name}{f': {detail}' if detail else ''}")
    if not ok:
        _failures.append(name)


def kubectl(*args: str) -> str:
    if KUBECTL is None:
        raise SystemExit("kubectl is not on PATH")
    return subprocess.run(  # noqa: S603 - kubectl from PATH, arguments from this file and K8S_NS
        [KUBECTL, "-n", NS, *args], capture_output=True, text=True, check=False
    ).stdout.strip()


def check_job(component: str, name: str, gc_ok: bool, gc_detail: str) -> None:
    """Check that the release's newest Job for `component` succeeded.

    The newest Job is the newest by creationTimestamp."""
    selector = f"app.kubernetes.io/component={component}"
    names = kubectl("get", "jobs", "-l", selector, "-o", "jsonpath={.items[*].metadata.name}")
    if not names:
        check(name, gc_ok, gc_detail)
        return
    succeeded = kubectl(
        "get",
        "jobs",
        "-l",
        selector,
        "--sort-by=.metadata.creationTimestamp",
        "-o",
        "jsonpath={.items[-1:].status.succeeded}",
    )
    check(name, succeeded == "1", f"succeeded={succeeded or '0'}")


def get(path: str) -> tuple[int, str]:
    headers = {"Host": HOST} if HOST else {}
    req = urllib.request.Request(f"{_BASE}{path}", headers=headers)  # noqa: S310 - _BASE is http or https
    try:
        with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310 - _BASE is http or https
            return r.status, r.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()
    except OSError as exc:
        return 0, str(exc)


def main() -> int:
    global _BASE
    with _service_url() as url:
        _BASE = url
        via = f"{url}" + (f" (Host: {HOST})" if HOST else " (port-forward to the Service)")
        print(f"verifying release {RELEASE!r} in namespace {NS!r} via {via}\n")
        return _checks()


def _checks() -> int:

    print("workloads")
    component_ready: dict[str, bool] = {}
    for component in ("app", "postgres", "neo4j"):
        ready = kubectl(
            "get",
            "pods",
            "-l",
            f"app.kubernetes.io/component={component}",
            "-o",
            "jsonpath={.items[*].status.containerStatuses[*].ready}",
        )
        component_ready[component] = ready != "" and "false" not in ready
        check(f"{component} container ready", component_ready[component], ready or "no pods")

    # A Ready app pod means the migration succeeded.
    check_job(
        "migrate",
        "migration job succeeded",
        gc_ok=component_ready["app"],
        gc_detail="no migrate Job (TTL-expired); app pods are ready behind its init gate"
        if component_ready["app"]
        else "no migrate Job found and app pods are not ready",
    )
    # Without the init-db Job, a Ready neo4j is the health signal.
    check_job(
        "initdb",
        "neo4j init-db job succeeded",
        gc_ok=component_ready["neo4j"],
        gc_detail="no initdb Job (TTL-expired); neo4j is ready and serving"
        if component_ready["neo4j"]
        else "no initdb Job found and neo4j is not ready",
    )

    print("\nserving")
    status, body = get("/api/livez")
    check("livez", status == 200, f"{status} {body[:60]}")
    status, body = get("/api/readyz")
    check("readyz", status == 200, f"{status} {body[:60]}")

    status, html = get("/")
    check("SPA index served", status == 200 and 'id="root"' in html, str(status))
    asset = ""
    if 'id="root"' in html:
        marker = "/assets/"
        idx = html.find(marker)
        if idx != -1:
            end = html.find('"', idx)
            asset = html[idx:end]
    if asset:
        status, _ = get(asset)
        check("hashed SPA asset served", status == 200, f"{status} {asset}")
    else:
        check("hashed SPA asset served", False, "no /assets/ reference in index.html")

    status, body = get("/api/health")
    check("health requires auth", status == 401, str(status))

    print("\nidentity")
    # The image bakes the git SHA in; the chart must not override it with its own version.
    revision = kubectl(
        "get",
        "deploy",
        "-o",
        "jsonpath={.items[0].spec.template.spec.containers[0].image}",
    )
    check("app image resolved", ":" in revision, revision)

    print()
    ingress_host = kubectl("get", "ingress", "-o", "jsonpath={.items[0].spec.rules[0].host}")
    if ingress_host:
        print(f"open:  http://{ingress_host}/   (host resolves to the ingress controller)")
    print(f"       or: kubectl -n {NS} port-forward svc/{service_name()} 8787:8787")
    print()
    if _failures:
        print(f"{len(_failures)} check(s) failed: {', '.join(_failures)}", file=sys.stderr)
        print(f"\nkubectl -n {NS} get pods,jobs   and   kubectl -n {NS} logs <pod>", file=sys.stderr)
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
