//! Transaction fingerprint and heuristic analysis.
//!
//! Designed to be reusable: given a rust-bitcoin [`Transaction`] and its prevouts
//! (and optionally same-block context for CPFP), produce a flat feature record
//! suitable for later distribution / normalization work.

mod change;
mod fingerprints;
mod heuristics;
pub mod normalize;
mod rawtx;
pub mod types;

use bitcoin::{Amount, Transaction, TxOut};
use serde::{Deserialize, Serialize};

pub use change::ChangeAnalysis;
pub use fingerprints::FingerprintFeatures;
pub use heuristics::HeuristicFeatures;
pub use normalize::{normalize_tx, schema, schema_ref};
pub use rawtx::RawTxFeatures;

/// Everything we currently extract about a single confirmed transaction.
///
/// Fields are kept close to their source heuristics so they can later be
/// normalized / one-hot encoded independently.
#[derive(Debug, Serialize, Deserialize)]
pub struct TxAnalysis {
    pub txid: String,
    pub block_height: i32,
    pub block_hash: String,
    pub tx_index: usize,
    pub is_coinbase: bool,
    pub fingerprints: FingerprintFeatures,
    pub rawtx: RawTxFeatures,
    pub heuristics: HeuristicFeatures,
    pub change: ChangeAnalysis,
}

/// Same-block spend graph info needed for CPFP detection.
#[derive(Debug, Clone, Default)]
pub struct BlockTxContext {
    /// True if this tx spends an output created earlier in the same block.
    pub spends_same_block_parent: bool,
    /// True if a later tx in the same block spends one of this tx's outputs.
    pub has_same_block_child: bool,
}

/// Analyze a single transaction.
///
/// `prevouts` must align with `tx.input` (empty / ignored for coinbase).
pub fn analyze_tx(
    tx: &Transaction,
    prevouts: &[TxOut],
    block_height: i32,
    block_hash: &str,
    tx_index: usize,
    block_ctx: &BlockTxContext,
) -> Result<TxAnalysis, String> {
    let fingerprints = fingerprints::extract(tx, prevouts);
    let rawtx = rawtx::extract(tx)?;
    let heuristics =
        heuristics::extract(tx, prevouts, &fingerprints, &rawtx, block_ctx, block_height);
    let change = change::analyze(tx, prevouts, &fingerprints);

    Ok(TxAnalysis {
        txid: tx.compute_txid().to_string(),
        block_height,
        block_hash: block_hash.to_string(),
        tx_index,
        is_coinbase: tx.is_coinbase(),
        fingerprints,
        rawtx,
        heuristics,
        change,
    })
}

/// Convert kernel spent-output coins into rust-bitcoin [`TxOut`]s.
pub fn prevouts_from_kernel_coins<'a, I>(coins: I) -> Result<Vec<TxOut>, String>
where
    I: IntoIterator<Item = (i64, Vec<u8>)>,
{
    coins
        .into_iter()
        .map(|(value_sat, script_bytes)| {
            Ok(TxOut {
                value: Amount::from_sat(
                    value_sat
                        .try_into()
                        .map_err(|_| format!("negative or overflowing coin value: {value_sat}"))?,
                ),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(script_bytes),
            })
        })
        .collect()
}

/// Deserialize a kernel-encoded transaction into rust-bitcoin.
pub fn bitcoin_tx_from_bytes(bytes: &[u8]) -> Result<Transaction, String> {
    bitcoin::consensus::deserialize(bytes).map_err(|e| format!("tx deserialize: {e}"))
}
