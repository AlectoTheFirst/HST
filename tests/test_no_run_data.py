"""The guard that keeps collected data out of the repo."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

CHECKER = Path(__file__).resolve().parent.parent / "tools" / "check_no_run_data.py"
# Ruff's bandit rules reject a partial executable path.
GIT = shutil.which("git")
pytestmark = pytest.mark.skipif(GIT is None, reason="git is not on PATH")


def _repo(tmp_path: Path, files: dict[str, bytes | str]) -> Path:
    for rel, body in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body.encode() if isinstance(body, str) else body)
    subprocess.run([GIT, "init", "-q", "."], cwd=tmp_path, check=True)
    # -f adds files that .gitignore excludes.
    subprocess.run([GIT, "add", "-A", "-f"], cwd=tmp_path, check=True)
    return tmp_path


def _run(repo: Path) -> subprocess.CompletedProcess:
    (repo / "tools").mkdir(exist_ok=True)
    (repo / "tools" / "check_no_run_data.py").write_bytes(CHECKER.read_bytes())
    subprocess.run([GIT, "add", "-A", "-f"], cwd=repo, check=True)
    return subprocess.run(
        [sys.executable, "tools/check_no_run_data.py"], cwd=repo, capture_output=True, text=True
    )


CLEAN = {
    "src/app.py": "print('hello')\n",
    "README.md": "# project\n",
    "fixtures/mini-dc.yaml": "device: leaf1\nserial: FDO1234ABCD\naddress: 10.0.0.1/24\n",
    "docs/04-query-cookbook.md": "MATCH (n) WHERE n.ip = '192.168.1.1' RETURN n\n",
}


def test_a_clean_repo_passes(tmp_path):
    result = _run(_repo(tmp_path, CLEAN))
    assert result.returncode == 0, result.stderr
    assert "no run data is tracked" in result.stdout


def test_fixtures_and_docs_are_not_false_positives(tmp_path):
    result = _run(_repo(tmp_path, CLEAN))
    assert result.returncode == 0
    assert "fixtures" not in result.stderr and "cookbook" not in result.stderr


@pytest.mark.parametrize(
    ("rel", "body", "expected"),
    [
        ("data/raw/apic/snap.json", '{"imdata": []}', "under data/"),
        ("raw/handoff/x.json", "{}", "under raw/"),
        ("backups/hst-pg.dump", "PGDMP\x00", "backups/"),
        ("var/snapshots/nxos.json", "{}", "snapshots/"),
        ("tests/captures/apic.json", "{}", "captures/"),
        ("src/changes.jsonl", '{"op":"add"}\n', ".jsonl"),
        ("out/rib.parquet", "PAR1", ".parquet"),
        ("cap/session.pcap", "\xd4\xc3\xb2\xa1", ".pcap"),
    ],
)
def test_run_data_paths_are_rejected(tmp_path, rel, body, expected):
    result = _run(_repo(tmp_path, {**CLEAN, rel: body}))
    assert result.returncode == 1, f"{rel} was not caught"
    assert rel in result.stderr
    assert expected in result.stderr


def test_a_fernet_token_anywhere_is_rejected(tmp_path):
    """A Fernet token marks data sealed with HST_SECRET_KEY."""
    # A literal token sample would trip the checker on this file.
    sealed = "creds: " + "gAAAAA" + "Bm1234567890abcdefghijklmnopqrstuv" + "\n"
    result = _run(_repo(tmp_path, {**CLEAN, "src/settings.yaml": sealed}))
    assert result.returncode == 1
    assert "Fernet token" in result.stderr


def test_a_private_key_is_rejected(tmp_path):
    key = "-----" + "BEGIN OPENSSH PRIVATE KEY" + "-----\nb3BlbnNzaC1rZXktdjEA\n"
    result = _run(_repo(tmp_path, {**CLEAN, "deploy/id_ed25519": key}))
    assert result.returncode == 1
    assert "private key" in result.stderr


def test_a_postgres_dump_is_rejected_by_its_magic_number(tmp_path):
    result = _run(_repo(tmp_path, {**CLEAN, "notes/attachment.bin": b"PGDMP\x00\x01\x02"}))
    assert result.returncode == 1
    assert "PostgreSQL dump" in result.stderr


def test_the_failure_message_says_history_is_the_problem(tmp_path):
    result = _run(_repo(tmp_path, {**CLEAN, "data/raw/x.json": "{}"}))
    assert "history" in result.stderr and "disclosed" in result.stderr
