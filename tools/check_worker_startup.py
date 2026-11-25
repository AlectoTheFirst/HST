"""Start the installed `hst worker` against CI service containers, wait for both
loops, and check that SIGTERM stops it with exit status 0."""

import os
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

START_S = 90
STOP_S = 30


def _running(log: str) -> bool:
    executor = any("executor " in line and "started (concurrency" in line for line in log.splitlines())
    return executor and "scheduler: this process is the leader" in log


def main() -> None:
    executable = shutil.which("hst")
    if executable is None:
        raise RuntimeError("installed hst CLI missing")
    with tempfile.TemporaryDirectory() as scratch:
        data = Path(scratch) / "data"
        log_path = Path(scratch) / "worker.log"
        env = {**os.environ, "HST_DATA_DIR": str(data), "PYTHONUNBUFFERED": "1"}
        # The log is read through its own handle: the child's descriptor keeps its
        # own offset while this process polls the file.
        with log_path.open("w") as log:
            process = subprocess.Popen(  # noqa: S603 -- fixed CLI and arguments in the CI environment
                [executable, "worker"],
                stdout=log,
                stderr=subprocess.STDOUT,
                env=env,
            )
        try:
            deadline = time.monotonic() + START_S
            while not _running(log_path.read_text()):
                if process.poll() is not None:
                    raise RuntimeError(f"worker exited with status {process.returncode} before its loops ran")
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"worker did not start both loops within {START_S} seconds")
                time.sleep(1)
            process.send_signal(signal.SIGTERM)
            try:
                status = process.wait(timeout=STOP_S)
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(f"worker did not exit within {STOP_S} seconds of SIGTERM") from exc
            if status != 0:
                raise RuntimeError(f"worker exited with status {status} after SIGTERM")
            print("worker startup, both loops and SIGTERM shutdown passed")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            print(log_path.read_text())


if __name__ == "__main__":
    main()
