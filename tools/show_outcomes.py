"""Print every command outcome that is not `ok` in the newest raw payload, with the
device's own words. `podman compose exec -T app python - < tools/show_outcomes.py`."""

from hst.app.crypto import dek
from hst.collectors.base import RAW_OUTCOMES_KEY
from hst.core import Settings, rawstore

settings = Settings()
files = sorted(settings.raw_dir.glob("*/*/*.json.gz.enc"), key=lambda p: p.stat().st_mtime)
if not files:
    raise SystemExit(f"no raw files under {settings.raw_dir}")
path = files[-1]
print("payload:", path)
raw = rawstore.read(path, dek(settings))
outcomes = raw.get(RAW_OUTCOMES_KEY) or {}
print("commands:", len(outcomes))
for cmd, entry in outcomes.items():
    status = (entry or {}).get("status", "-")
    if status == "ok":
        continue
    print(f"\n{status.upper():12} {cmd!r}")
    print("   ", (entry or {}).get("detail", ""))
    text = str(raw.get(cmd) or "")
    if text.strip():
        print("    stored text:", repr(text[:200]))
