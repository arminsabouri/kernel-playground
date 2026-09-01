# kernel-playground

Scans a Bitcoin Core data directory via libbitcoinkernel and emits per-tx wallet
fingerprints as a normalized feature matrix.

```bash
# one pass: block walk, per-tx analysis and normalization all in memory
cargo run -- scan ~/.bitcoin --chain mainnet --depth 1000 \
  --format parquet -o features.parquet --schema-out schema.json

# omit --depth to walk to genesis
```

`--format` also accepts `ndjson` and `csv` (both stream to stdout, or to
`--output`), plus `raw-ndjson` — the unnormalized internal analysis records,
kept for replay and debugging.

`normalize` is a compatibility shim for raw NDJSON captured before the two
commands were fused; it takes the same `--format` / `--output` / `--schema-out`
flags:

```bash
cargo run -- scan ~/.bitcoin --chain mainnet --format raw-ndjson > raw.ndjson
cargo run -- normalize raw.ndjson --format parquet -o features.parquet
```

Prefer the single `scan` invocation: it avoids the multi-hundred-megabyte
intermediate file and a full JSON serialize/parse round trip per transaction.

`cargo run -- schema` prints the feature column schema on its own.
