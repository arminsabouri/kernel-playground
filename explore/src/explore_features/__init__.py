"""MVP CLI / helpers for basic Parquet feature-matrix stats."""

from __future__ import annotations

import argparse
from pathlib import Path

import polars as pl

# Prefer the scan output in the repo root (parent of explore/).
# __file__ = explore/src/explore_features/__init__.py → parents[3] = repo root
_REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CANDIDATES = [
    _REPO_ROOT / "features_20k.parquet",
    Path("/tmp/features_mainnet200.parquet"),
]


def parquet_ready(path: Path) -> bool:
    if not path.exists() or path.stat().st_size == 0:
        return False
    try:
        pl.scan_parquet(path).collect_schema()
        return True
    except Exception as e:
        print(f"skip {path}: not readable yet ({type(e).__name__})")
        return False


def resolve_parquet(explicit: Path | None) -> Path:
    if explicit is not None:
        if not parquet_ready(explicit):
            raise SystemExit(f"cannot read {explicit}")
        return explicit
    for path in DEFAULT_CANDIDATES:
        if parquet_ready(path):
            return path
    raise SystemExit(
        "no readable parquet yet — wait for the scan to finish, "
        "or pass --parquet PATH"
    )


def family(name: str) -> str:
    for prefix in (
        "fp_",
        "h_",
        "prevout_type__",
        "output_type__",
        "change_heuristic__",
        "change_",
        "reveals_",
    ):
        if name.startswith(prefix):
            return prefix.rstrip("_")
    return "other"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--parquet",
        type=Path,
        default=None,
        help="Parquet feature matrix (default: ../features_20k.parquet if ready)",
    )
    parser.add_argument("--top", type=int, default=20, help="Top/bottom feature rows")
    args = parser.parse_args()

    path = resolve_parquet(args.parquet)
    lf = pl.scan_parquet(path)
    schema = lf.collect_schema()

    print(f"file: {path.resolve()}")
    print(f"size: {path.stat().st_size / 1e6:.1f} MB")
    print(f"cols: {len(schema)}")
    print()

    overview = lf.select(
        pl.len().alias("n_txs"),
        pl.col("block_height").min().alias("height_min"),
        pl.col("block_height").max().alias("height_max"),
        (
            pl.col("block_height").max() - pl.col("block_height").min() + 1
        ).alias("n_heights_span"),
        pl.col("block_height").n_unique().alias("n_heights_seen"),
        pl.col("is_coinbase").mean().alias("coinbase_rate"),
        pl.col("version").mean().alias("version_mean"),
    ).collect()
    print("== overview ==")
    print(overview)
    print()

    n = overview["n_txs"][0]
    versions = (
        lf.group_by("version")
        .agg(pl.len().alias("count"))
        .with_columns((pl.col("count") / n).alias("rate"))
        .sort("version")
        .collect()
    )
    print("== tx version ==")
    print(versions)
    print()

    per_block = (
        lf.group_by("block_height")
        .agg(pl.len().alias("n_txs"))
        .select(
            pl.col("n_txs").mean().alias("mean"),
            pl.col("n_txs").median().alias("median"),
            pl.col("n_txs").min().alias("min"),
            pl.col("n_txs").max().alias("max"),
            pl.col("n_txs").quantile(0.05).alias("p05"),
            pl.col("n_txs").quantile(0.95).alias("p95"),
        )
        .collect()
    )
    print("== txs per block ==")
    print(per_block)
    print()

    bool_cols = [
        name
        for name, dtype in schema.items()
        if dtype == pl.Boolean and name != "is_coinbase"
    ]
    prevalence = (
        lf.select([pl.col(c).mean().alias(c) for c in bool_cols])
        .collect()
        .transpose(include_header=True, header_name="feature", column_names=["rate"])
        .sort("rate", descending=True)
    )
    print(f"== feature prevalence ({len(bool_cols)} bool cols) ==")
    print(f"-- top {args.top} --")
    print(prevalence.head(args.top))
    print(f"-- bottom {args.top} --")
    print(prevalence.tail(args.top))
    print()

    by_family = (
        prevalence.with_columns(
            pl.col("feature").map_elements(family, return_dtype=pl.String).alias("family")
        )
        .group_by("family")
        .agg(
            pl.len().alias("n_features"),
            pl.col("rate").mean().alias("mean_rate"),
            pl.col("rate").max().alias("max_rate"),
            pl.col("rate").min().alias("min_rate"),
        )
        .sort("mean_rate", descending=True)
    )
    print("== by family ==")
    print(by_family)


if __name__ == "__main__":
    main()
