# kernel-playground

Scans a Bitcoin Core data directory via libbitcoinkernel and emits per-tx wallet fingerprints as NDJSON, then optionally normalizes them into a binary feature matrix.

```bash
cargo run -- scan ~/.bitcoin --chain mainnet --depth 1000 > raw.ndjson   # omit --depth to walk to genesis
cargo run -- normalize raw.ndjson --format parquet -o features.parquet
```
