"""Print every `| json` command in the newest raw payload whose answer is not JSON."""

import json

from hst.app.crypto import dek
from hst.collectors.base import RAW_OUTCOMES_KEY
from hst.core import Settings, rawstore

settings = Settings()
files = sorted(settings.raw_dir.glob("*/*/*.json.gz.enc"), key=lambda p: p.stat().st_mtime)
if not files:
    raise SystemExit(f"no raw files under {settings.raw_dir}")
path = files[-1]
print("payload:", path, f"{path.stat().st_size / 1e6:.1f} MB")
raw = rawstore.read(path, dek(settings))
outcomes = raw.get(RAW_OUTCOMES_KEY) or {}
print("commands:", len(raw) - 1)
bad = 0
for cmd, text in raw.items():
    if cmd == RAW_OUTCOMES_KEY or not str(cmd).endswith("| json"):
        continue
    try:
        json.loads(text)
    except (TypeError, ValueError):
        bad += 1
        status = (outcomes.get(cmd) or {}).get("status", "-")
        print(f"\nNOT JSON  {cmd!r}  outcome={status}  length={len(str(text))}")
        print(repr(str(text)[:300]))
print(f"\n{bad} command(s) answered with text that is not JSON")
