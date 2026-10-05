mod analysis;

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use analysis::normalize::{INT_COLUMNS, NormalizedTx};
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
use rayon::prelude::*;

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

/// How often the scan prints a progress line. A full-chain walk runs for hours,
/// so silence is indistinguishable from a hang.
const PROGRESS_INTERVAL: Duration = Duration::from_secs(5);

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
    #[arg(long, conflicts_with_all = ["start_height", "end_height"])]
    depth: Option<u32>,
    /// Lowest block height to scan (inclusive). Defaults to genesis.
    #[arg(long)]
    start_height: Option<u32>,
    /// Highest block height to scan (inclusive). Defaults to the tip.
    ///
    /// With `--start-height`, this makes a run restartable: a walk that died at
    /// height N resumes with `--end-height N`.
    #[arg(long)]
    end_height: Option<u32>,
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

    let end_height = match args.end_height {
        Some(end) => {
            let end = end as i32;
            if end > tip_height {
                return Err(format!(
                    "--end-height {end} is above the tip at {tip_height}"
                ));
            }
            end
        }
        None => tip_height,
    };
    let start_height = match (args.start_height, args.depth) {
        (Some(start), _) => start as i32,
        (None, Some(depth)) => {
            let chain_len = tip_height as i64 + 1;
            if depth as i64 > chain_len {
                return Err(format!(
                    "--depth {depth} is longer than the chain ({chain_len} blocks)"
                ));
            }
            tip_height - (depth as i32 - 1)
        }
        (None, None) => 0,
    };
    if start_height > end_height {
        return Err(format!(
            "--start-height {start_height} is above --end-height {end_height}"
        ));
    }

    // Walk down from the tip to the requested range. `prev()` only follows the
    // block index, so skipping ahead of the range costs no block reads.
    let mut entry = tip;
    while entry.height() > end_height {
        entry = entry
            .prev()
            .ok_or_else(|| format!("chain ended before reaching height {end_height}"))?;
    }

    eprintln!(
        "scanning {} block(s) from height {} to {} ({})",
        end_height.saturating_sub(start_height) + 1,
        start_height,
        end_height,
        entry.block_hash()
    );

    let total_blocks = (end_height.saturating_sub(start_height) + 1) as u64;
    let mut progress = Progress::new(total_blocks);

    loop {
        let height = entry.height();
        if height < start_height {
            break;
        }

        let outcome = analyze_block(&chainman, &entry, sink.as_mut())?;
        progress.record(height, &outcome);

        if height == 0 {
            break;
        }
        entry = match entry.prev() {
            Some(prev) => prev,
            None => break,
        };
    }

    let rows = sink.finish()?;
    progress.finish();
    eprintln!("wrote {} ({rows} rows)", args.output.display());
    Ok(())
}

/// Periodic scan progress on stderr, plus a skipped-tx tally.
///
/// Skipped transactions are counted rather than printed one by one: a bad run
/// could otherwise emit millions of lines, and the analysis now runs on rayon
/// threads where those prints would interleave.
struct Progress {
    total_blocks: u64,
    blocks: u64,
    rows: u64,
    skipped: u64,
    first_error: Option<String>,
    started: Instant,
    last_print: Instant,
}

impl Progress {
    fn new(total_blocks: u64) -> Self {
        let now = Instant::now();
        Self {
            total_blocks,
            blocks: 0,
            rows: 0,
            skipped: 0,
            first_error: None,
            started: now,
            last_print: now,
        }
    }

    fn record(&mut self, height: i32, outcome: &BlockOutcome) {
        self.blocks += 1;
        self.rows += outcome.rows;
        self.skipped += outcome.skipped;
        if self.first_error.is_none() {
            self.first_error.clone_from(&outcome.first_error);
        }

        if self.last_print.elapsed() >= PROGRESS_INTERVAL {
            self.print(height);
            self.last_print = Instant::now();
        }
    }

    fn print(&self, height: i32) {
        let elapsed = self.started.elapsed().as_secs_f64();
        let bps = if elapsed > 0.0 {
            self.blocks as f64 / elapsed
        } else {
            0.0
        };
        // Blocks remaining at the current rate; the walk runs tip-to-genesis, so
        // `height` alone does not say how much is left.
        let eta = if bps > 0.0 {
            format_duration(((self.total_blocks - self.blocks) as f64 / bps) as u64)
        } else {
            "?".to_string()
        };
        eprintln!(
            "  height {height}: {}/{} blocks, {} rows, {:.1} blocks/s, eta {eta}",
            self.blocks, self.total_blocks, self.rows, bps
        );
    }

    fn finish(&self) {
        let elapsed = self.started.elapsed().as_secs_f64();
        eprintln!(
            "scanned {} block(s), {} tx in {} ({:.1} blocks/s)",
            self.blocks,
            self.rows,
            format_duration(elapsed as u64),
            if elapsed > 0.0 {
                self.blocks as f64 / elapsed
            } else {
                0.0
            }
        );
        if self.skipped > 0 {
            eprintln!(
                "warn: skipped {} tx that failed analysis; first was {}",
                self.skipped,
                self.first_error.as_deref().unwrap_or("unknown")
            );
        }
    }
}

fn format_duration(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}h{m:02}m")
    } else if m > 0 {
        format!("{m}m{s:02}s")
    } else {
        format!("{s}s")
    }
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
    block_height: Vec<i32>,
    int_names: Vec<String>,
    int_cols: Vec<Vec<i32>>,
    bool_names: Vec<String>,
    bool_cols: Vec<Vec<bool>>,
}

impl ParquetRows {
    fn new(columns: &[String]) -> Self {
        let (int_names, bool_names): (Vec<String>, Vec<String>) = columns
            .iter()
            .cloned()
            .partition(|name| INT_COLUMNS.contains(&name.as_str()));
        let int_cols = vec![Vec::new(); int_names.len()];
        let bool_cols = vec![Vec::new(); bool_names.len()];
        Self {
            block_height: Vec::new(),
            int_names,
            int_cols,
            bool_names,
            bool_cols,
        }
    }

    fn len(&self) -> usize {
        self.block_height.len()
    }

    /// Polars schema of the frames produced by [`ParquetRows::take_frame`].
    ///
    /// Declared up front so every row group in the file shares one schema.
    fn polars_schema(&self) -> Schema {
        let mut fields: Vec<(PlSmallStr, DataType)> =
            vec![("block_height".into(), DataType::Int32)];
        fields.extend(
            self.int_names
                .iter()
                .map(|name| (name.as_str().into(), DataType::Int32)),
        );
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
        self.block_height.push(norm.block_height);

        let (mut int_i, mut bool_i) = (0, 0);
        for (name, value) in columns.iter().zip(norm.x.iter()) {
            if INT_COLUMNS.contains(&name.as_str()) {
                self.int_cols[int_i].push(*value as i32);
                int_i += 1;
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
            Series::new("block_height".into(), std::mem::take(&mut self.block_height)).into(),
        ];
        for (name, values) in self.int_names.iter().zip(self.int_cols.iter_mut()) {
            cols.push(Series::new(name.as_str().into(), std::mem::take(values)).into());
        }
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
) -> Result<BlockOutcome, String> {
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

    // Kernel handles are FFI-bound and not `Send`, so prevouts are pulled out
    // here, on this thread, before any parallel work starts.
    let mut prevouts: Vec<Vec<bitcoin::TxOut>> = Vec::with_capacity(txs.len());
    for (tx_index, tx) in txs.iter().enumerate() {
        if tx.is_coinbase() {
            prevouts.push(Vec::new());
            continue;
        }
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
        prevouts.push(prevouts_from_kernel_coins(coin_pairs)?);
    }

    let block_ctxs = build_cpfp_context(&txs);

    // Analysis is pure over owned data, so it fans out across the block's txs.
    // `collect` keeps rows in block order. Coinbase txs are built by pool
    // software rather than a wallet, so they are not part of the output.
    let rows: Vec<Result<NormalizedTx, String>> = txs
        .par_iter()
        .zip(prevouts.par_iter())
        .zip(block_ctxs.par_iter())
        .enumerate()
        .filter(|(_, ((tx, _), _))| !tx.is_coinbase())
        .map(|(tx_index, ((tx, prevouts), block_ctx))| {
            match analyze_tx(tx, prevouts, height, &block_hash, block_ctx) {
                Ok(analysis) => Ok(normalize_tx(&analysis)),
                // Reported back to the caller rather than printed here: this
                // closure runs on rayon threads, where prints interleave.
                Err(err) => Err(format!("tx {block_hash}:{tx_index}: {err}")),
            }
        })
        .collect();

    let mut outcome = BlockOutcome::default();
    for row in &rows {
        match row {
            Ok(norm) => {
                sink.push(norm, &schema_ref().columns)?;
                outcome.rows += 1;
            }
            Err(err) => {
                outcome.skipped += 1;
                if outcome.first_error.is_none() {
                    outcome.first_error = Some(err.clone());
                }
            }
        }
    }

    Ok(outcome)
}

/// What one block contributed to the scan.
#[derive(Debug, Default)]
struct BlockOutcome {
    rows: u64,
    skipped: u64,
    /// One sample error, so a run can show *why* txs are being skipped without
    /// emitting a line per failure.
    first_error: Option<String>,
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
            if let Some(&parent_idx) = txid_to_index.get(&input.previous_output.txid)
                && parent_idx < child_idx
            {
                parents_with_child.insert(parent_idx);
                children_with_parent.insert(child_idx);
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
            block_height: i as i32,
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
        let heights = streamed.column("block_height").unwrap().i32().unwrap();
        assert_eq!(heights.get(0), Some(0));
        assert_eq!(heights.get(249), Some(249));
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
        assert_eq!(df.width(), schema_ref().columns.len() + 1);
    }
}
