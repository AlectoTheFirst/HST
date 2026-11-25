from __future__ import annotations

from pathlib import Path

import yaml

from .model import Batch


def load_fixture(path: Path | str) -> Batch:
    with Path(path).open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    batch = Batch.model_validate(data)
    batch.validate_registry()
    return batch
