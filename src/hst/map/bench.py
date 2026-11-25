"""The measurements of the HST map benchmark, run with `python -m hst.map.bench`."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m hst.map.bench", description=__doc__)
    parser.add_argument("--devices", type=int, default=10_000)
    parser.add_argument("--runs", type=int, default=12)
    parser.add_argument("--change-rate", type=float, default=0.05)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--data-dir", type=Path, required=True, help="an empty directory for the side store")
    parser.add_argument("--neo4j-uri", required=True, help="a scratch Neo4j: the benchmark clears it first")
    parser.add_argument("--neo4j-user", default="neo4j")
    parser.add_argument(
        "--neo4j-password-env", default="NEO4J_BENCH_PASSWORD", help="the variable with its password"
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    from hst import bench
    from hst.core.config import Settings

    settings = Settings(
        hst_data_dir=args.data_dir,
        neo4j_uri=args.neo4j_uri,
        neo4j_user=args.neo4j_user,
        neo4j_password=os.environ[args.neo4j_password_env],
    )
    result = bench.run_map_bench(
        settings=settings,
        devices=args.devices,
        runs=args.runs,
        change_rate=args.change_rate,
        seed=args.seed,
        output=args.output,
    )
    print(json.dumps({k: v for k, v in result.items() if k != "per_run"}, indent=2))


if __name__ == "__main__":
    main()
