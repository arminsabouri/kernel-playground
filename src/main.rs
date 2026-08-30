mod analysis;

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use analysis::{
    analyze_tx, bitcoin_tx_from_bytes, normalize_tx, prevouts_from_kernel_coins, schema,
    BlockTxContext, TxAnalysis,
};
use bitcoinkernel::{
    prelude::*, BlockTreeEntry, ChainType, ChainstateManager, ChainstateManagerBuilder, Context,
    ContextBuilder,
};
use clap::{Parser, Subcommand, ValueEnum};

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

#[derive(Debug, Clone, Copy, ValueEnum)]
enum NormalizeFormat {
    /// One JSON object per line: metadata + `x` feature vector.
    Ndjson,
    /// CSV with a header row matching the feature schema (metadata columns first).
    Csv,
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
    /// Walk blocks from tip and emit raw per-tx analysis as NDJSON.
    Scan(ScanArgs),
    /// Read raw analysis NDJSON and emit a normalized numeric feature matrix.
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
}

#[derive(Debug, Parser)]
struct NormalizeArgs {
    /// Raw NDJSON from `scan` (`-` for stdin).
    input: PathBuf,
    /// Output format.
    #[arg(long, value_enum, default_value_t = NormalizeFormat::Ndjson)]
    format: NormalizeFormat,
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

        analyze_block(&chainman, &entry)?;

        if height == 0 {
            break;
        }
        entry = match entry.prev() {
            Some(prev) => prev,
            None => break,
        };
    }

    Ok(())
}

fn run_normalize(args: NormalizeArgs) -> Result<(), String> {
    let sch = schema();
    if let Some(path) = &args.schema_out {
        let mut f = File::create(path).map_err(|e| format!("schema_out: {e}"))?;
        writeln!(
            f,
            "{}",
            serde_json::to_string_pretty(&sch).map_err(|e| format!("schema json: {e}"))?
        )
        .map_err(|e| format!("schema write: {e}"))?;
    }

    let reader = open_input(&args.input)?;
    let mut wrote_csv_header = false;

    for (lineno, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("read line {}: {e}", lineno + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        let raw: TxAnalysis = serde_json::from_str(&line)
            .map_err(|e| format!("parse line {}: {e}", lineno + 1))?;
        let norm = normalize_tx(&raw);

        match args.format {
            NormalizeFormat::Ndjson => {
                println!(
                    "{}",
                    serde_json::to_string(&norm).map_err(|e| format!("serialize: {e}"))?
                );
            }
            NormalizeFormat::Csv => {
                if !wrote_csv_header {
                    let mut header = vec![
                        "txid".to_string(),
                        "block_height".to_string(),
                        "tx_index".to_string(),
                        "is_coinbase".to_string(),
                    ];
                    header.extend(sch.columns.iter().cloned());
                    println!("{}", header.join(","));
                    wrote_csv_header = true;
                }
                let mut row = vec![
                    escape_csv(&norm.txid),
                    norm.block_height.to_string(),
                    norm.tx_index.to_string(),
                    if norm.is_coinbase { "1" } else { "0" }.to_string(),
                ];
                row.extend(norm.x.iter().map(|v| format!("{v}")));
                println!("{}", row.join(","));
            }
        }
    }

    Ok(())
}

fn open_input(path: &Path) -> Result<Box<dyn BufRead>, String> {
    if path.as_os_str() == "-" {
        Ok(Box::new(BufReader::new(std::io::stdin())))
    } else {
        let f = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
        Ok(Box::new(BufReader::new(f)))
    }
}

fn escape_csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn analyze_block(chainman: &ChainstateManager, entry: &BlockTreeEntry<'_>) -> Result<(), String> {
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
                println!(
                    "{}",
                    serde_json::to_string(&analysis)
                        .map_err(|e| format!("serialize analysis: {e}"))?
                );
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
