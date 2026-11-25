#!/usr/bin/env python3
"""Create the sites and import the business applications of the demo estate through the HTTP API.

    HST_PASSWORD=... python3 tools/seed_demo.py --base https://<instance host> --user <admin user>

Run it after the three fixture loads (fixtures/demo-enterprise/README.md): each application is
resolved at the current run after its import. It reads fixtures/demo-enterprise/sites.yaml
and fixtures/demo-enterprise/apps/*.yaml from the repository, or from --dir. A site that exists is
left as it is. An application import that changes nothing writes no new revision. It needs only
the Python standard library and PyYAML.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DIR = ROOT / "fixtures" / "demo-enterprise"


class Api:
    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )

    def call(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(self.base + path, data=data, method=method)  # noqa: S310
        request.add_header("content-type", "application/json")
        request.add_header("X-HST-CSRF", "1")
        try:
            with self.opener.open(request, timeout=60) as response:
                text = response.read().decode()
                return response.status, json.loads(text) if text else None
        except urllib.error.HTTPError as exc:
            text = exc.read().decode()
            try:
                return exc.code, json.loads(text)
            except ValueError:
                return exc.code, text


def seed_sites(api: Api, sites_file: Path) -> None:
    status, existing = api.call("GET", "/api/sites")
    if status != 200:
        sys.exit(f"cannot list the sites: {status} {existing}")
    have = {site["code"] for site in existing.get("sites", [])}
    for site in yaml.safe_load(sites_file.read_text())["sites"]:
        if site["code"] in have:
            print(f"site {site['code']}: exists")
            continue
        body = {
            "code": site["code"],
            "name": site["name"],
            "location": site["location"],
            "params": {"lat": site["lat"], "lon": site["lon"]},
        }
        status, answer = api.call("POST", "/api/sites", body)
        if status != 201:
            sys.exit(f"site {site['code']}: {status} {answer}")
        print(f"site {site['code']}: created")


def import_applications(api: Api, apps_dir: Path) -> None:
    """Import each application, then resolve its revision at the current run: an import with no
    validation snapshot resolves nothing by itself."""
    status, snapshots = api.call("GET", "/api/snapshots")
    current = snapshots.get("current") if status == 200 else None
    if current is None:
        sys.exit("no current run: load the fixtures first")
    for path in sorted(apps_dir.glob("*.yaml")):
        text = path.read_text()
        status, preview = api.call("POST", "/api/business-applications/import/preview", {"yaml": text})
        if status != 200:
            sys.exit(f"{path.name}: preview {status} {preview}")
        body = {
            "yaml": text,
            "mode": "merge",
            "base_revision": preview["base_revision"],
            "base_digest": preview["base_digest"],
            "preview_digest": preview["preview_digest"],
        }
        status, saved = api.call("POST", "/api/business-applications/import/commit", body)
        if status not in (200, 201):
            sys.exit(f"{path.name}: commit {status} {saved}")
        app_id, revision = saved["id"], saved["revision"]
        status, resolved = api.call(
            "POST",
            f"/api/business-applications/{app_id}/resolve",
            {"snapshot": str(current), "revision": revision},
        )
        state = "resolved" if status == 200 else f"not resolved: {status} {resolved}"
        print(f"application {app_id}: revision {revision}, {state} at run {current}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--base", required=True, help="the URL of the demo instance")
    parser.add_argument("--user", required=True, help="an account with sites.write and applications write")
    parser.add_argument("--dir", type=Path, default=DEFAULT_DIR, help="the demo-enterprise fixture folder")
    args = parser.parse_args()
    password = os.environ.get("HST_PASSWORD")
    if not password:
        sys.exit("set HST_PASSWORD to the account's password")
    api = Api(args.base)
    status, answer = api.call("POST", "/api/login", {"username": args.user, "password": password})
    if status != 200:
        sys.exit(f"login failed: {status} {answer}")
    seed_sites(api, args.dir / "sites.yaml")
    import_applications(api, args.dir / "apps")


if __name__ == "__main__":
    main()
