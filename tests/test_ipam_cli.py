"""`hst ipam import`: a file with a byte order mark and a capitalized
header seals; a bad address exits 1 and names its line."""

from __future__ import annotations

from typer.testing import CliRunner

from hst import cli
from hst.app.crypto import generate_key
from hst.core import ipam
from hst.core.config import Settings

runner = CliRunner()


def _settings(monkeypatch, tmp_path):
    settings = Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())
    monkeypatch.setattr(cli, "Settings", lambda: settings)
    return settings


def test_ipam_import_seals_a_file_with_a_byte_order_mark_and_a_capitalized_header(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path)
    export = tmp_path / "export.csv"
    export.write_text(
        "﻿Address,Description,Location,VLAN\n10.1.2.0/24,a,FRA,1\n10.1.3.0/24,b,FRA,2\n", "utf-8"
    )
    result = runner.invoke(cli.app, ["ipam", "import", str(export)])
    assert result.exit_code == 0, result.output
    assert "imported 2 subnets as" in result.output
    assert len(list((settings.raw_dir / ipam.SOURCE).iterdir())) == 1


def test_ipam_import_refuses_a_bad_address_with_its_line(monkeypatch, tmp_path):
    _settings(monkeypatch, tmp_path)
    export = tmp_path / "export.csv"
    export.write_text("address,description,location,vlan\n10.1.2.0/24,a,FRA,1\nnope,b,FRA,2\n", "utf-8")
    result = runner.invoke(cli.app, ["ipam", "import", str(export)])
    assert result.exit_code == 1
    assert "line 3" in result.output
