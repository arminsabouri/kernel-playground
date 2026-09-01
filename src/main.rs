mod analysis;

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use analysis::{
    analyze_tx, bitcoin_tx_from_bytes, normalize_tx, prevouts_from_kernel_coins, schema,
    schema_ref, BlockTxContext, TxAnalysis,
};
use analysis::normalize::{FeatureSchema, NormalizedTx};
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

/// Normalized feature-matrix output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum NormalizeFormat {
    /// One JSON object per line: metadata + `x` feature vector.
    Ndjson,
    /// CSV with a header row matching the feature schema (metadata columns first).
    Csv,
    /// Polars dataframe as Parquet (bool columns + integer version). Requires `--output`.
    Parquet,
}

/// What `scan` writes. Normalization happens in-process for every variant but
/// `raw-ndjson`, which dumps the internal analysis records for later replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ScanFormat {
    /// Raw per-tx analysis JSON, one object per line (legacy `scan | normalize` input).
    RawNdjson,
    /// Normalized NDJSON: metadata + `x` feature vector.
    Ndjson,
    /// Normalized CSV with a header row matching the feature schema.
    Csv,
    /// Normalized Parquet feature matrix. Requires `--output`.
    Parquet,
}

impl ScanFormat {
    /// The normalized format this maps to, or `None` for the raw passthrough.
    fn as_normalize(self) -> Option<NormalizeFormat> {
        match self {
            ScanFormat::RawNdjson => None,
            ScanFormat::Ndjson => Some(NormalizeFormat::Ndjson),
            ScanFormat::Csv => Some(NormalizeFormat::Csv),
            ScanFormat::Parquet => Some(NormalizeFormat::Parquet),
        }
    }
}

/// Bitcoin tx fingerprint scanner and feature normalizer.
#[derive(Debug, Parser)]
#[command(name = "kernel-playground", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Walk blocks from tip, analyze each tx, and emit a normalized feature matrix.
    Scan(ScanArgs),
    /// Compatibility shim: normalize an existing raw NDJSON file from `scan --format raw-ndjson`.
    ///
    /// Prefer `scan --format parquet -o ...`, which skips the intermediate file.
    Normalize(NormalizeArgs),
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
    /// Output format. Everything but `raw-ndjson` normalizes in-process.
    #[arg(long, value_enum, default_value_t = ScanFormat::RawNdjson)]
    format: ScanFormat,
    /// Output path (defaults to stdout). Required for `--format parquet`.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Optional path to write the column schema JSON.
    #[arg(long)]
    schema_out: Option<PathBuf>,
}

#[derive(Debug, Parser)]
struct NormalizeArgs {
    /// Raw NDJSON from `scan --format raw-ndjson` (`-` for stdin).
    input: PathBuf,
    /// Output format.
    #[arg(long, value_enum, default_value_t = NormalizeFormat::Ndjson)]
    format: NormalizeFormat,
    /// Output path (defaults to stdout). Required for `--format parquet`.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Optional path to write the column schema JSON.
    #[arg(long)]
    schema_out: Option<PathBuf>,
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
        Command::Normalize(args) => run_normalize(args),
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

    // Fail on bad output flags before spending minutes importing blocks.
    let mut sink = match args.format.as_normalize() {
        Some(format) => Sink::Normalized(Box::new(RowSink::new(
            format,
            args.output.as_deref(),
            args.schema_out.as_deref(),
        )?)),
        None => {
            if let Some(path) = &args.schema_out {
                write_schema(path)?;
            }
            Sink::Raw(open_output(args.output.as_deref())?)
        }
    };

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

        analyze_block(&chainman, &entry, &mut sink)?;

        if height == 0 {
            break;
        }
        entry = match entry.prev() {
            Some(prev) => prev,
            None => break,
        };
    }

    sink.finish()
}

fn run_normalize(args: NormalizeArgs) -> Result<(), String> {
    let mut sink = RowSink::new(
        args.format,
        args.output.as_deref(),
        args.schema_out.as_deref(),
    )?;

    let reader = open_input(&args.input)?;
    for (lineno, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("read line {}: {e}", lineno + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        let raw: TxAnalysis =
            serde_json::from_str(&line).map_err(|e| format!("parse line {}: {e}", lineno + 1))?;
        sink.push(&raw)?;
    }

    sink.finish()
}

/// Where `scan` sends each analyzed tx.
enum Sink {
    /// Legacy passthrough: serialize the internal analysis record verbatim.
    Raw(Box<dyn Write>),
    /// Normalize in-process and accumulate / stream feature rows.
    /// Boxed: the accumulator is much larger than the raw writer.
    Normalized(Box<RowSink>),
}

impl Sink {
    fn push(&mut self, raw: &TxAnalysis) -> Result<(), String> {
        match self {
            Sink::Raw(out) => {
                let line = serde_json::to_string(raw)
                    .map_err(|e| format!("serialize analysis: {e}"))?;
                writeln!(out, "{line}").map_err(|e| format!("write: {e}"))
            }
            Sink::Normalized(sink) => sink.push(raw),
        }
    }

    fn finish(self) -> Result<(), String> {
        match self {
            Sink::Raw(mut out) => out.flush().map_err(|e| format!("flush: {e}")),
            Sink::Normalized(sink) => sink.finish(),
        }
    }
}

/// Normalizes [`TxAnalysis`] records and emits them in the requested format.
///
/// NDJSON and CSV stream row by row; Parquet accumulates columns in memory
/// until [`RowSink::finish`].
struct RowSink {
    format: NormalizeFormat,
    schema: &'static FeatureSchema,
    /// Text sink for NDJSON / CSV.
    out: Option<Box<dyn Write>>,
    wrote_csv_header: bool,
    /// Column accumulator for Parquet, with its destination path.
    parquet: Option<(ParquetRows, PathBuf)>,
}

impl RowSink {
    fn new(
        format: NormalizeFormat,
        output: Option<&Path>,
        schema_out: Option<&Path>,
    ) -> Result<Self, String> {
        let sch = schema_ref();
        if let Some(path) = schema_out {
            write_schema(path)?;
        }

        let (out, parquet) = match format {
            NormalizeFormat::Parquet => {
                let path = output
                    .ok_or_else(|| "--format parquet requires --output".to_string())?
                    .to_path_buf();
                (None, Some((ParquetRows::new(&sch.columns), path)))
            }
            NormalizeFormat::Ndjson | NormalizeFormat::Csv => (Some(open_output(output)?), None),
        };

        Ok(Self {
            format,
            schema: sch,
            out,
            wrote_csv_header: false,
            parquet,
        })
    }

    fn push(&mut self, raw: &TxAnalysis) -> Result<(), String> {
        let norm = normalize_tx(raw);
        match self.format {
            NormalizeFormat::Ndjson => {
                let out = self.out.as_mut().expect("ndjson sink has a writer");
                let line =
                    serde_json::to_string(&norm).map_err(|e| format!("serialize: {e}"))?;
                writeln!(out, "{line}").map_err(|e| format!("write: {e}"))
            }
            NormalizeFormat::Csv => {
                let out = self.out.as_mut().expect("csv sink has a writer");
                if !self.wrote_csv_header {
                    let mut header = vec![
                        "txid".to_string(),
                        "block_height".to_string(),
                        "tx_index".to_string(),
                        "is_coinbase".to_string(),
                    ];
                    header.extend(self.schema.columns.iter().cloned());
                    writeln!(out, "{}", header.join(",")).map_err(|e| format!("write: {e}"))?;
                    self.wrote_csv_header = true;
                }
                let mut row = vec![
                    escape_csv(&norm.txid),
                    norm.block_height.to_string(),
                    norm.tx_index.to_string(),
                    if norm.is_coinbase { "1" } else { "0" }.to_string(),
                ];
                row.extend(norm.x.iter().map(|v| format!("{v}")));
                writeln!(out, "{}", row.join(",")).map_err(|e| format!("write: {e}"))
            }
            NormalizeFormat::Parquet => {
                let (rows, _) = self.parquet.as_mut().expect("parquet sink has an accumulator");
                rows.push(&norm, &self.schema.columns)
            }
        }
    }

    fn finish(self) -> Result<(), String> {
        if let Some((rows, path)) = self.parquet {
            rows.write(&path)
                .map_err(|e| format!("write parquet {}: {e}", path.display()))?;
            eprintln!("wrote {}", path.display());
        }
        if let Some(mut out) = self.out {
            out.flush().map_err(|e| format!("flush: {e}"))?;
        }
        Ok(())
    }
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

fn open_input(path: &Path) -> Result<Box<dyn BufRead>, String> {
    if path.as_os_str() == "-" {
        Ok(Box::new(BufReader::new(std::io::stdin())))
    } else {
        let f = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
        Ok(Box::new(BufReader::new(f)))
    }
}

fn open_output(path: Option<&Path>) -> Result<Box<dyn Write>, String> {
    match path {
        Some(path) if path.as_os_str() != "-" => {
            let f = File::create(path).map_err(|e| format!("create {}: {e}", path.display()))?;
            Ok(Box::new(BufWriter::new(f)))
        }
        _ => Ok(Box::new(BufWriter::new(std::io::stdout()))),
    }
}

fn escape_csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

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

    fn write(self, path: &Path) -> Result<(), String> {
        let mut cols: Vec<Column> = vec![
            Series::new("txid".into(), self.txid).into(),
            Series::new("block_height".into(), self.block_height).into(),
            Series::new("tx_index".into(), self.tx_index).into(),
            Series::new("is_coinbase".into(), self.is_coinbase).into(),
            Series::new("version".into(), self.version).into(),
        ];
        for (name, values) in self.bool_names.into_iter().zip(self.bool_cols) {
            cols.push(Series::new(name.as_str().into(), values).into());
        }
        let mut df = DataFrame::new(cols).map_err(|e| format!("dataframe: {e}"))?;
        let mut file = File::create(path).map_err(|e| e.to_string())?;
        ParquetWriter::new(&mut file)
            .finish(&mut df)
            .map_err(|e| format!("parquet: {e}"))?;
        Ok(())
    }
}

fn analyze_block(
    chainman: &ChainstateManager,
    entry: &BlockTreeEntry<'_>,
    sink: &mut Sink,
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
            Ok(analysis) => sink.push(&analysis)?,
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
