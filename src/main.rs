mod analysis;

use std::collections::{HashMap, HashSet};
use std::process::ExitCode;
use std::sync::Arc;

use analysis::{analyze_tx, bitcoin_tx_from_bytes, prevouts_from_kernel_coins, BlockTxContext};
use bitcoinkernel::{
    prelude::*, BlockTreeEntry, ChainType, ChainstateManager, ChainstateManagerBuilder, Context,
    ContextBuilder,
};
use clap::{Parser, ValueEnum};

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

/// Walk blocks from tip backwards and dump per-tx fingerprint / heuristic features as NDJSON.
#[derive(Debug, Parser)]
#[command(name = "kernel-playground", version, about)]
struct Args {
    /// Path to a Bitcoin Core data directory readable by libbitcoinkernel.
    data_dir: String,

    /// How many blocks to walk back from the tip (inclusive of tip).
    blocks: u32,

    /// Network the data directory belongs to.
    #[arg(long, value_enum, default_value_t = CliChainType::Regtest)]
    chain: CliChainType,

    /// Optional override for the blocks directory (defaults to `<data_dir>/blocks`).
    #[arg(long)]
    blocks_dir: Option<String>,
}

fn create_context(chain: ChainType) -> Result<Arc<Context>, String> {
    ContextBuilder::new()
        .chain_type(chain)
        .build()
        .map(Arc::new)
        .map_err(|e| format!("failed to build kernel context: {e}"))
}

fn main() -> ExitCode {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn run() -> Result<(), String> {
    let args = Args::parse();
    if args.blocks == 0 {
        return Err("--blocks / blocks argument must be >= 1".into());
    }

    let context = create_context(args.chain.into())?;
    let blocks_dir = args
        .blocks_dir
        .unwrap_or_else(|| format!("{}/blocks", args.data_dir));

    let chainman = ChainstateManagerBuilder::new(&context, &args.data_dir, &blocks_dir)
        .map_err(|e| format!("chainstate manager builder: {e}"))?
        .build()
        .map_err(|e| format!("chainstate manager build: {e}"))?;

    // Load block index / undo data for an on-disk datadir.
    chainman
        .import_blocks()
        .map_err(|e| format!("import_blocks: {e}"))?;

    let tip = chainman
        .best_entry()
        .ok_or_else(|| "no best block entry (empty chain?)".to_string())?;
    let tip_height = tip.height();

    let start_height = tip_height.saturating_sub(args.blocks.saturating_sub(1) as i32);
    eprintln!(
        "scanning {} block(s) from height {} to tip {} ({})",
        args.blocks,
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

    // Materialize txs so we can build a same-block spend graph for CPFP.
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
            // Spent-output index is 0-based excluding coinbase.
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

/// Detect same-block parent/child spends (the confirmed form of a CPFP package).
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
