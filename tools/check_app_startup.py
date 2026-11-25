"""Start the installed CLI against CI service containers and check readiness."""

import json
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def main() -> None:
    executable = shutil.which("hst")
    if executable is None:
        raise RuntimeError("installed hst CLI missing")
    with tempfile.TemporaryFile(mode="w+") as log:
        process = subprocess.Popen(  # noqa: S603 -- fixed CLI and arguments in the CI environment
            [executable, "serve", "--host", "127.0.0.1", "--port", "8787"],
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(f"server exited with status {process.returncode}")
                try:
                    for path in ("livez", "readyz"):
                        url = f"http://127.0.0.1:8787/api/{path}"
                        with urllib.request.urlopen(url, timeout=3) as response:
                            if json.load(response) != {"status": "ok"}:
                                raise RuntimeError(f"unexpected response from {path}")
                    print("CLI startup, liveness and database readiness passed")
                    return
                except (urllib.error.URLError, TimeoutError):
                    time.sleep(1)
            raise RuntimeError("server did not become ready within 90 seconds")
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            log.seek(0)
            print(log.read())


if __name__ == "__main__":
    main()
