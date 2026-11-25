#!/usr/bin/env python3
"""Validate and execute an explicitly configured private acceptance manifest."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MAX_CAPTURE_BYTES = 16 * 1024 * 1024
REQUIRED_SCOPES = frozenset(
    {
        "largest-policy",
        "standalone-firewall",
        "vsx-multiple-vs",
        "repeated-vs-address-space",
        "cisco-acl",
        "velocloud-dia",
        "velocloud-hub",
        "asymmetric-session",
        "observation-gap",
        "known-policy-regression",
        "routing-change",
    }
)
CLASSIFICATIONS = frozenset(
    {"pass", "implementation-defect", "unsupported-semantics", "evidence-gap", "capacity"}
)


@dataclass(frozen=True, slots=True)
class PilotCase:
    name: str
    scopes: tuple[str, ...]
    source: str
    expected: tuple[str, ...]


def load_manifest(path: Path) -> tuple[dict[str, Any], tuple[PilotCase, ...]]:
    raw = json.loads(path.read_text())
    if not isinstance(raw, dict) or raw.get("schema") != "strata-private-acceptance-v1":
        raise ValueError("unsupported private acceptance manifest schema")
    if raw.get("authorization") != "read-only":
        raise ValueError("manifest authorization must be read-only")
    cases = []
    for item in raw.get("cases", ()):
        if not isinstance(item, dict):
            raise ValueError("each private case must be an object")
        case = PilotCase(
            str(item.get("name") or ""),
            tuple(str(value) for value in item.get("scopes", ())),
            str(item.get("source") or ""),
            tuple(str(value) for value in item.get("expected", ())),
        )
        if not case.name or not case.scopes or not case.source or not case.expected:
            raise ValueError("private cases require name, scopes, source and expected outcomes")
        unknown = set(case.scopes) - REQUIRED_SCOPES
        if unknown:
            raise ValueError(f"{case.name}: unknown qualification scopes {sorted(unknown)}")
        cases.append(case)
    return raw, tuple(cases)


def qualification_scope(cases: tuple[PilotCase, ...]) -> dict[str, tuple[str, ...]]:
    covered = {scope for case in cases for scope in case.scopes}
    return {
        "configured": tuple(sorted(covered)),
        "pending": tuple(sorted(REQUIRED_SCOPES - covered)),
    }


def _outside_repository(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    if resolved == ROOT or ROOT in resolved.parents:
        raise ValueError("private captures and reports must remain outside the Git workspace")
    return resolved


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _read_result(source: str, token_env: str | None) -> dict[str, Any]:
    if source.startswith("https://"):
        headers = {"Accept": "application/json"}
        if token_env:
            token = os.environ.get(token_env)
            if not token:
                raise ValueError(f"required authorization environment variable {token_env} is unset")
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(source, headers=headers, method="GET")  # noqa: S310
        opener = urllib.request.build_opener(_NoRedirect)
        with opener.open(request, timeout=60) as response:
            payload = response.read(MAX_CAPTURE_BYTES + 1)
            if len(payload) > MAX_CAPTURE_BYTES:
                raise ValueError("private result exceeds the capture size limit")
            return json.loads(payload)
    path = _outside_repository(Path(source))
    if path.stat().st_size > MAX_CAPTURE_BYTES:
        raise ValueError("private result exceeds the capture size limit")
    return json.loads(path.read_text())


def execute(manifest: dict[str, Any], cases: tuple[PilotCase, ...]) -> dict[str, Any]:
    results = []
    token_env = manifest.get("authorization_env")
    for case in cases:
        try:
            observed = _read_result(case.source, str(token_env) if token_env else None)
            outcome = str(observed.get("outcome") or "")
            classification = str(observed.get("classification") or "")
            if classification not in CLASSIFICATIONS:
                classification = "pass" if outcome in case.expected else "implementation-defect"
            matched = outcome in case.expected and classification == "pass"
            results.append(
                {
                    "name": case.name,
                    "scopes": case.scopes,
                    "expected": case.expected,
                    "outcome": outcome,
                    "classification": classification,
                    "matched": matched,
                    "release": observed.get("release"),
                    "workload": observed.get("workload"),
                    "report_ref": observed.get("report_ref"),
                }
            )
        except Exception as exc:
            results.append(
                {
                    "name": case.name,
                    "scopes": case.scopes,
                    "expected": case.expected,
                    "classification": "evidence-gap",
                    "matched": False,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
    scope = qualification_scope(cases)
    passed = not scope["pending"] and all(item["matched"] for item in results)
    return {
        "schema": "hst-private-acceptance-report-v1",
        "created_at": datetime.now(UTC).isoformat(),
        "qualified": passed,
        "scope": scope,
        "cases": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    manifest, cases = load_manifest(_outside_repository(args.config))
    scope = qualification_scope(cases)
    if not args.execute:
        print(json.dumps({"valid": True, "case_count": len(cases), "scope": scope}, sort_keys=True))
        return 0
    if args.output is None:
        parser.error("--execute requires --output outside the repository")
    output = _outside_repository(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    report = execute(manifest, cases)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"qualified": report["qualified"], "report": str(output)}, sort_keys=True))
    return 0 if report["qualified"] else 1


if __name__ == "__main__":
    sys.exit(main())
