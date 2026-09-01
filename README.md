# kernel-playground

Scans a Bitcoin Core data directory via libbitcoinkernel and writes per-tx wallet
fingerprints as a normalized Parquet feature matrix.

```bash
# block walk, per-tx analysis and normalization in a single pass
cargo run -- scan ~/.bitcoin --chain mainnet --depth 1000 \
  -o features.parquet --schema-out schema.json

# omit --depth to walk to genesis
```

Output is streamed one row group at a time, so memory stays flat over a full-chain
walk rather than growing with the number of transactions. `--batch-size` (default
1,000,000 rows) sets the row group size and thus the memory ceiling; a crash
mid-walk leaves the row groups written so far readable.

`cargo run -- schema` prints the feature column schema on its own.

Adding another output format means implementing the `RowSink` trait; the block
walk feeds it through a trait object and needs no changes.
