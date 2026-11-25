"""JSON Schema text for Business Application definitions and import patches.

The schema files under ``docs/examples`` are generated from the pydantic models.
``python -m hst.applications.schema --write`` rewrites them after a model
change. Without ``--write`` the command reports the files that differ from the
models and exits with status 1. The default directory is ``docs/examples`` of a
source checkout. ``--output-dir`` names another directory, for example when the
package is installed from a wheel.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import get_args

from pydantic import BaseModel

from hst.applications.models import BusinessApplicationDefinition, BusinessApplicationPatch

JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
SCHEMA_ID_BASE = "https://strata.invalid/schemas"
EXAMPLES_DIR = Path(__file__).resolve().parents[3] / "docs" / "examples"
APPLICATION_SCHEMA_FILE = "business-application.schema.json"
PATCH_SCHEMA_FILE = "business-application-patch.schema.json"


def application_json_schema() -> str:
    """Return the committed text of the complete definition schema."""
    return _schema_text(BusinessApplicationDefinition, "business-application")


def patch_json_schema() -> str:
    """Return the committed text of the keyed-merge import patch schema."""
    return _schema_text(BusinessApplicationPatch, "business-application-patch")


def schema_files() -> dict[str, str]:
    """Map each schema file name under ``docs/examples`` to its generated text."""
    return {
        APPLICATION_SCHEMA_FILE: application_json_schema(),
        PATCH_SCHEMA_FILE: patch_json_schema(),
    }


def _schema_text(model: type[BaseModel], name: str) -> str:
    version = max(get_args(model.model_fields["schema_version"].annotation))
    schema = {
        "$schema": JSON_SCHEMA_DIALECT,
        "$id": f"{SCHEMA_ID_BASE}/{name}/v{version}.schema.json",
        **model.model_json_schema(),
    }
    return json.dumps(schema, indent=2) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m hst.applications.schema",
        description="Generate the Business Application JSON Schema files from the models.",
    )
    parser.add_argument("--write", action="store_true", help="write the schema files")
    parser.add_argument(
        "--output-dir",
        type=Path,
        help=f"directory that holds the schema files (default: {EXAMPLES_DIR})",
    )
    args = parser.parse_args(argv)
    directory: Path = args.output_dir or EXAMPLES_DIR
    stale = []
    for name, text in schema_files().items():
        path = directory / name
        if args.write:
            path.write_text(text, encoding="utf-8")
        elif not path.is_file() or path.read_text(encoding="utf-8") != text:
            stale.append(name)
    for name in stale:
        print(f"{directory / name} differs from the models; run with --write", file=sys.stderr)
    return 1 if stale else 0


if __name__ == "__main__":
    raise SystemExit(main())
