mod analysis;

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use analysis::normalize::NormalizedTx;
use analysis::{
    analyze_tx, bitcoin_tx_from_bytes, normalize_tx, prevouts_from_kernel_coins, schema,
    schema_ref, BlockTxContext,
};
use bitcoinkernel::{
    prelude::*, BlockTreeEntry, ChainType, ChainstateManager, ChainstateManagerBuilder, Context,
    ContextBuilder,
};
use clap::{Parser, Subcommand, ValueEnum};
use polars::prelude::*;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliChainType {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

impl From<CliChainType> for ChainType {
    fn from(value: CliChainType) -> Self {
        match value {
            CliChainType::Mainnet => ChainType::Mainnet,
            CliChainType::Testnet => ChainType::Testnet,
            CliChainType::Signet => ChainType::Signet,
            CliChainType::Regtest => ChainType::Regtest,
        }
    }
}

/// Rows buffered per Parquet row group. At ~123 boolean columns this is on the
/// order of 120MB of staging memory, near the usual Parquet row-group target.
const DEFAULT_BATCH_SIZE: usize = 1_000_000;

/// Bitcoin tx fingerprint scanner and feature normalizer.
#[derive(Debug, Parser)]
#[command(name = "kernel-playground", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Walk blocks from tip, analyze each tx, and write a normalized Parquet feature matrix.
    Scan(ScanArgs),
    /// Print the normalized feature column schema as JSON.
    Schema,
}

#[derive(Debug, Parser)]
struct ScanArgs {
    /// Path to a Bitcoin Core data directory readable by libbitcoinkernel.
    data_dir: String,
    /// How many blocks to walk back from the tip (inclusive of tip).
    /// Omit to scan all the way to genesis.
    #[arg(long)]
    depth: Option<u32>,
    /// Network the data directory belongs to.
    #[arg(long, value_enum, default_value_t = CliChainType::Regtest)]
    chain: CliChainType,
    /// Optional override for the blocks directory (defaults to `<data_dir>/blocks`).
    #[arg(long)]
    blocks_dir: Option<String>,
    /// Destination Parquet file for the feature matrix.
    #[arg(short, long)]
    output: PathBuf,
    /// Optional path to write the column schema JSON.
    #[arg(long)]
    schema_out: Option<PathBuf>,
    /// Rows per Parquet row group. Caps how much is held in memory at once.
    #[arg(long, default_value_t = DEFAULT_BATCH_SIZE)]
    batch_size: usize,
}

fn main() -> ExitCode {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn run() -> Result<(), String> {
    match Cli::parse().command {
        Command::Scan(args) => run_scan(args),
        Command::Schema => {
            let schema = schema();
            println!(
                "{}",
                serde_json::to_string_pretty(&schema)
                    .map_err(|e| format!("serialize schema: {e}"))?
            );
            Ok(())
        }
    }
}

fn create_context(chain: ChainType) -> Result<Arc<Context>, String> {
    ContextBuilder::new()
        .chain_type(chain)
        .build()
        .map(Arc::new)
        .map_err(|e| format!("failed to build kernel context: {e}"))
}

fn run_scan(args: ScanArgs) -> Result<(), String> {
    if matches!(args.depth, Some(0)) {
        return Err("depth must be >= 1 (omit --depth to scan to genesis)".into());
    }

    if args.batch_size == 0 {
        return Err("--batch-size must be >= 1".into());
    }
    if let Some(path) = &args.schema_out {
        write_schema(path)?;
    }

    // Open the sink before spending minutes importing blocks, so a bad output
    // path fails immediately rather than after the walk.
    let columns = &schema_ref().columns;
    let mut sink: Box<dyn RowSink> =
        Box::new(ParquetSink::new(&args.output, columns, args.batch_size)?);

    let context = create_context(args.chain.into())?;
    let blocks_dir = args
        .blocks_dir
        .unwrap_or_else(|| format!("{}/blocks", args.data_dir));

    let chainman = ChainstateManagerBuilder::new(&context, &args.data_dir, &blocks_dir)
        .map_err(|e| format!("chainstate manager builder: {e}"))?
        .build()
        .map_err(|e| format!("chainstate manager build: {e}"))?;

    chainman
        .import_blocks()
        .map_err(|e| format!("import_blocks: {e}"))?;

    let tip = chainman
        .best_entry()
        .ok_or_else(|| "no best block entry (empty chain?)".to_string())?;
    let tip_height = tip.height();

    let start_height = match args.depth {
        Some(depth) => tip_height.saturating_sub(depth.saturating_sub(1) as i32),
        None => 0,
    };
    eprintln!(
        "scanning {} block(s) from height {} to tip {} ({})",
        tip_height.saturating_sub(start_height) + 1,
        start_height,
        tip_height,
        tip.block_hash()
    );

    let mut entry = tip;
    loop {
        let height = entry.height();
        if height < start_height {
            break;
        }

        analyze_block(&chainman, &entry, sink.as_mut())?;

        if height == 0 {
            break;
        }
        entry = match entry.prev() {
            Some(prev) => prev,
            None => break,
        };
    }

    let rows = sink.finish()?;
    eprintln!("wrote {} ({rows} rows)", args.output.display());
    Ok(())
}

/// Destination for normalized feature rows.
///
/// One implementation per output format; `scan` holds it boxed so adding a
/// format is a new impl rather than a change to the block walk.
trait RowSink {
    /// Accept one row. `columns` is the feature schema `norm.x` is aligned with.
    fn push(&mut self, norm: &NormalizedTx, columns: &[String]) -> Result<(), String>;

    /// Flush anything buffered and close the output, returning rows written.
    fn finish(self: Box<Self>) -> Result<u64, String>;
}

fn write_schema(path: &Path) -> Result<(), String> {
    let mut f = File::create(path).map_err(|e| format!("schema_out: {e}"))?;
    writeln!(
        f,
        "{}",
        serde_json::to_string_pretty(schema_ref()).map_err(|e| format!("schema json: {e}"))?
    )
    .map_err(|e| format!("schema write: {e}"))
}

/// Column-major staging buffer for one Parquet row group.
struct ParquetRows {
    txid: Vec<String>,
    block_height: Vec<i32>,
    tx_index: Vec<u32>,
    is_coinbase: Vec<bool>,
    version: Vec<i32>,
    bool_names: Vec<String>,
    bool_cols: Vec<Vec<bool>>,
}

impl ParquetRows {
    fn new(columns: &[String]) -> Self {
        let bool_names: Vec<String> = columns
            .iter()
            .filter(|name| *name != "version")
            .cloned()
            .collect();
        let bool_cols = vec![Vec::new(); bool_names.len()];
        Self {
            txid: Vec::new(),
            block_height: Vec::new(),
            tx_index: Vec::new(),
            is_coinbase: Vec::new(),
            version: Vec::new(),
            bool_names,
            bool_cols,
        }
    }

    fn len(&self) -> usize {
        self.txid.len()
    }

    /// Polars schema of the frames produced by [`ParquetRows::take_frame`].
    ///
    /// Declared up front so every row group in the file shares one schema.
    fn polars_schema(&self) -> Schema {
        let mut fields: Vec<(PlSmallStr, DataType)> = vec![
            ("txid".into(), DataType::String),
            ("block_height".into(), DataType::Int32),
            ("tx_index".into(), DataType::UInt32),
            ("is_coinbase".into(), DataType::Boolean),
            ("version".into(), DataType::Int32),
        ];
        fields.extend(
            self.bool_names
                .iter()
                .map(|name| (name.as_str().into(), DataType::Boolean)),
        );
        Schema::from_iter(fields)
    }

    fn push(&mut self, norm: &NormalizedTx, columns: &[String]) -> Result<(), String> {
        if norm.x.len() != columns.len() {
            return Err(format!(
                "feature width {} != schema {}",
                norm.x.len(),
                columns.len()
            ));
        }
        self.txid.push(norm.txid.clone());
        self.block_height.push(norm.block_height);
        self.tx_index.push(norm.tx_index as u32);
        self.is_coinbase.push(norm.is_coinbase);

        let mut bool_i = 0;
        for (name, value) in columns.iter().zip(norm.x.iter()) {
            if name == "version" {
                self.version.push(*value as i32);
            } else {
                self.bool_cols[bool_i].push(*value != 0.0);
                bool_i += 1;
            }
        }
        Ok(())
    }

    /// Drain the buffered rows into a frame, leaving the buffer empty and reusable.
    ///
    /// Column order must match [`ParquetRows::polars_schema`].
    fn take_frame(&mut self) -> Result<DataFrame, String> {
        let mut cols: Vec<Column> = vec![
            Series::new("txid".into(), std::mem::take(&mut self.txid)).into(),
            Series::new("block_height".into(), std::mem::take(&mut self.block_height)).into(),
            Series::new("tx_index".into(), std::mem::take(&mut self.tx_index)).into(),
            Series::new("is_coinbase".into(), std::mem::take(&mut self.is_coinbase)).into(),
            Series::new("version".into(), std::mem::take(&mut self.version)).into(),
        ];
        for (name, values) in self.bool_names.iter().zip(self.bool_cols.iter_mut()) {
            cols.push(Series::new(name.as_str().into(), std::mem::take(values)).into());
        }
        DataFrame::new(cols).map_err(|e| format!("dataframe: {e}"))
    }
}

/// Streams feature rows to Parquet one row group at a time.
///
/// Only `batch_size` rows are held in memory, so a full-chain walk costs a
/// bounded amount of RAM regardless of how many transactions it visits.
struct ParquetSink {
    writer: BatchedWriter<BufWriter<File>>,
    rows: ParquetRows,
    batch_size: usize,
    written: u64,
}

impl ParquetSink {
    fn new(path: &Path, columns: &[String], batch_size: usize) -> Result<Self, String> {
        let rows = ParquetRows::new(columns);
        let schema = rows.polars_schema();
        let file = File::create(path).map_err(|e| format!("create {}: {e}", path.display()))?;
        let writer = ParquetWriter::new(BufWriter::new(file))
            .batched(&schema)
            .map_err(|e| format!("parquet writer: {e}"))?;
        Ok(Self {
            writer,
            rows,
            batch_size,
            written: 0,
        })
    }

    /// Write the buffered rows as one row group.
    fn flush(&mut self) -> Result<(), String> {
        let n = self.rows.len();
        if n == 0 {
            return Ok(());
        }
        let frame = self.rows.take_frame()?;
        self.writer
            .write_batch(&frame)
            .map_err(|e| format!("parquet row group: {e}"))?;
        self.written += n as u64;
        Ok(())
    }

}

impl RowSink for ParquetSink {
    fn push(&mut self, norm: &NormalizedTx, columns: &[String]) -> Result<(), String> {
        self.rows.push(norm, columns)?;
        if self.rows.len() >= self.batch_size {
            self.flush()?;
        }
        Ok(())
    }

    /// Flush the tail and write the file footer.
    ///
    /// With no rows at all this still emits a valid empty file carrying the schema.
    fn finish(mut self: Box<Self>) -> Result<u64, String> {
        self.flush()?;
        self.writer
            .finish()
            .map_err(|e| format!("parquet footer: {e}"))?;
        Ok(self.written)
    }
}

fn analyze_block(
    chainman: &ChainstateManager,
    entry: &BlockTreeEntry<'_>,
    sink: &mut dyn RowSink,
) -> Result<(), String> {
    let height = entry.height();
    let block_hash = entry.block_hash().to_string();
    let block = chainman
        .read_block_data(entry)
        .map_err(|e| format!("read_block_data at {height}: {e}"))?;

    let spent = if height == 0 {
        None
    } else {
        Some(
            chainman
                .read_spent_outputs(entry)
                .map_err(|e| format!("read_spent_outputs at {height}: {e}"))?,
        )
    };

    let mut txs = Vec::with_capacity(block.transaction_count());
    for (tx_index, kernel_tx) in block.transactions().enumerate() {
        let bytes = kernel_tx
            .consensus_encode()
            .map_err(|e| format!("tx encode {block_hash}:{tx_index}: {e}"))?;
        let tx = bitcoin_tx_from_bytes(&bytes)?;
        txs.push(tx);
    }

    let block_ctxs = build_cpfp_context(&txs);

    for (tx_index, tx) in txs.iter().enumerate() {
        let prevouts = if tx.is_coinbase() {
            Vec::new()
        } else {
            let spent = spent
                .as_ref()
                .ok_or_else(|| format!("missing spent outputs for non-genesis block {height}"))?;
            let spent_index = tx_index
                .checked_sub(1)
                .ok_or_else(|| format!("non-coinbase tx at index 0 in block {height}"))?;
            let tx_spent = spent
                .transaction_spent_outputs(spent_index)
                .map_err(|e| format!("tx spent outputs {block_hash}:{tx_index}: {e}"))?;

            let coin_pairs: Vec<(i64, Vec<u8>)> = tx_spent
                .coins()
                .map(|coin| {
                    let out = coin.output();
                    (out.value(), out.script_pubkey().to_bytes())
                })
                .collect();

            if coin_pairs.len() != tx.input.len() {
                return Err(format!(
                    "prevout count mismatch at {block_hash}:{tx_index}: {} coins vs {} inputs",
                    coin_pairs.len(),
                    tx.input.len()
                ));
            }
            prevouts_from_kernel_coins(coin_pairs)?
        };

        match analyze_tx(
            tx,
            &prevouts,
            height,
            &block_hash,
            tx_index,
            &block_ctxs[tx_index],
        ) {
            Ok(analysis) => {
                let norm = normalize_tx(&analysis);
                sink.push(&norm, &schema_ref().columns)?;
            }
            Err(err) => {
                eprintln!("warn: skipping tx {block_hash}:{tx_index}: {err}");
            }
        }
    }

    Ok(())
}

fn build_cpfp_context(txs: &[bitcoin::Transaction]) -> Vec<BlockTxContext> {
    let txid_to_index: HashMap<bitcoin::Txid, usize> = txs
        .iter()
        .enumerate()
        .map(|(i, tx)| (tx.compute_txid(), i))
        .collect();

    let mut parents_with_child: HashSet<usize> = HashSet::new();
    let mut children_with_parent: HashSet<usize> = HashSet::new();

    for (child_idx, tx) in txs.iter().enumerate() {
        if tx.is_coinbase() {
            continue;
        }
        for input in &tx.input {
            if let Some(&parent_idx) = txid_to_index.get(&input.previous_output.txid) {
                if parent_idx < child_idx {
                    parents_with_child.insert(parent_idx);
                    children_with_parent.insert(child_idx);
                }
            }
        }
    }

    (0..txs.len())
        .map(|i| BlockTxContext {
            spends_same_block_parent: children_with_parent.contains(&i),
            has_same_block_child: parents_with_child.contains(&i),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic normalized row; `x` must be schema-wide.
    fn row(i: usize, columns: &[String]) -> NormalizedTx {
        let x = columns
            .iter()
            .enumerate()
            .map(|(j, name)| {
                if name == "version" {
                    2.0
                } else if (i + j).is_multiple_of(3) {
                    1.0
                } else {
                    0.0
                }
            })
            .collect();
        NormalizedTx {
            txid: format!("tx{i}"),
            block_height: i as i32,
            tx_index: i,
            is_coinbase: i == 0,
            x,
        }
    }

    fn write_rows(path: &Path, n: usize, batch_size: usize) -> DataFrame {
        let columns = &schema_ref().columns;
        // Exercise it through the trait object, the way `scan` drives it.
        let mut sink: Box<dyn RowSink> =
            Box::new(ParquetSink::new(path, columns, batch_size).unwrap());
        for i in 0..n {
            sink.push(&row(i, columns), columns).unwrap();
        }
        assert_eq!(sink.finish().unwrap(), n as u64);

        ParquetReader::new(File::open(path).unwrap()).finish().unwrap()
    }

    /// Row-group size must not change the data that comes back out.
    #[test]
    fn batching_does_not_change_contents() {
        let dir = std::env::temp_dir().join("kp_parquet_stream_test");
        std::fs::create_dir_all(&dir).unwrap();

        let streamed = write_rows(&dir.join("many.parquet"), 250, 7);
        let single = write_rows(&dir.join("one.parquet"), 250, 10_000);

        assert_eq!(streamed.shape(), single.shape());
        assert_eq!(streamed.shape().0, 250);
        assert!(streamed.equals(&single), "row groups changed the contents");

        // Metadata columns survived the round trip in order.
        let txids = streamed.column("txid").unwrap().str().unwrap();
        assert_eq!(txids.get(0), Some("tx0"));
        assert_eq!(txids.get(249), Some("tx249"));
    }

    /// A partial trailing batch must still be flushed by `finish`.
    #[test]
    fn trailing_partial_batch_is_written() {
        let dir = std::env::temp_dir().join("kp_parquet_stream_test");
        std::fs::create_dir_all(&dir).unwrap();
        // 10 rows at batch 4 => 2 full groups + a 2-row tail.
        let df = write_rows(&dir.join("tail.parquet"), 10, 4);
        assert_eq!(df.shape().0, 10);
    }

    /// Zero rows must still produce a readable file carrying the schema.
    #[test]
    fn empty_input_writes_valid_file() {
        let dir = std::env::temp_dir().join("kp_parquet_stream_test");
        std::fs::create_dir_all(&dir).unwrap();
        let df = write_rows(&dir.join("empty.parquet"), 0, 16);
        assert_eq!(df.shape().0, 0);
        assert_eq!(df.width(), schema_ref().columns.len() + 4);
    }
}
