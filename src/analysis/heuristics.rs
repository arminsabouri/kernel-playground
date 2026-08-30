//! Extra heuristics not fully covered by the fingerprint / rawtx crates.

use std::collections::HashMap;

use bitcoin::{Amount, Transaction, TxOut};
use serde::{Deserialize, Serialize};

use super::fingerprints::FingerprintFeatures;
use super::rawtx::{MultisigInfo, RawTxFeatures};
use super::types::{CpfpRole, LocktimeShape, PubkeyAlgo, RawInputType, SequenceShape, SighashType};
use super::BlockTxContext;

#[derive(Debug, Serialize, Deserialize)]
pub struct HeuristicFeatures {
    /// Dumb equal-amount check: ≥2 non-OP_RETURN outputs share the exact same value.
    pub equal_amount_outputs: bool,
    /// Likely coinjoin: equal-amount outputs *or* ≥⅓ of all outputs share a value (count > 2).
    pub likely_coinjoin: bool,
    /// Many inputs (≥3) into 1 or 2 non-OP_RETURN outputs, or ≥10 inputs and ≤2 outputs.
    pub likely_consolidation: bool,
    pub cpfp: CpfpRole,
    /// Distinct sighash types seen across all input signatures.
    pub sighashes: Vec<SighashType>,
    /// Per-input nSequence shape.
    pub sequence_shapes: Vec<SequenceShape>,
    /// nLockTime shape vs confirming block height.
    pub locktime_shape: LocktimeShape,
    /// Any input or output reveals an uncompressed ECDSA pubkey.
    pub has_uncompressed_pubkey: bool,
    /// Distinct multisig configurations observed on inputs.
    pub multisig_configs: Vec<MultisigInfo>,
    pub has_multisig: bool,
    /// Gibson UIH1: some payment-like output is smaller than every input.
    pub uih1: bool,
    /// Gibson UIH2: some input is larger than every output (unnecessary-looking input).
    pub uih2: bool,
}

pub fn extract(
    tx: &Transaction,
    prevouts: &[TxOut],
    fingerprints: &FingerprintFeatures,
    rawtx: &RawTxFeatures,
    block_ctx: &BlockTxContext,
    block_height: i32,
) -> HeuristicFeatures {
    let payment_outputs: Vec<&bitcoin::TxOut> = tx
        .output
        .iter()
        .filter(|o| !o.script_pubkey.is_op_return())
        .collect();

    let equal_amount_outputs = has_equal_amount_outputs(&payment_outputs);
    let likely_coinjoin = equal_amount_outputs || potentially_coinjoin(tx);
    let likely_consolidation = (tx.input.len() >= 3 && payment_outputs.len() <= 2)
        || (tx.input.len() >= 10 && tx.output.len() <= 2);

    let cpfp = match (
        block_ctx.has_same_block_child,
        block_ctx.spends_same_block_parent,
    ) {
        (true, true) => CpfpRole::Both,
        (true, false) => CpfpRole::Parent,
        (false, true) => CpfpRole::Child,
        (false, false) => CpfpRole::None,
    };

    let mut sighashes: Vec<SighashType> = rawtx
        .inputs
        .iter()
        .flat_map(|i| i.signatures.iter().map(|s| s.sighash))
        .collect();
    sighashes.sort_by_key(|s| *s as u8);
    sighashes.dedup();

    let sequence_shapes: Vec<SequenceShape> = tx
        .input
        .iter()
        .map(|i| SequenceShape::from_nsequence(i.sequence.0))
        .collect();

    let nlocktime = tx.lock_time.to_consensus_u32();
    let locktime_shape = LocktimeShape::from_locktime(nlocktime, block_height);

    let has_uncompressed_pubkey = fingerprints
        .inputs
        .iter()
        .any(|i| i.has_uncompressed_pubkey)
        || rawtx.inputs.iter().any(|i| {
            i.pubkeys
                .iter()
                .any(|p| !p.compressed && p.pubkey_type == PubkeyAlgo::Ecdsa)
        })
        || rawtx.outputs.iter().any(|o| {
            o.pubkeys
                .iter()
                .any(|p| !p.compressed && p.pubkey_type == PubkeyAlgo::Ecdsa)
        });

    let mut multisig_configs: Vec<MultisigInfo> =
        rawtx.inputs.iter().filter_map(|i| i.multisig).collect();
    multisig_configs.sort_by_key(|m| (m.m, m.n, m.unknown_n));
    multisig_configs.dedup();

    let has_multisig = !multisig_configs.is_empty()
        || rawtx
            .inputs
            .iter()
            .any(|i| matches!(i.input_type, RawInputType::P2ms | RawInputType::P2msLaxDer));

    let (uih1, uih2) = uih_flags(prevouts, &payment_outputs);

    HeuristicFeatures {
        equal_amount_outputs,
        likely_coinjoin,
        likely_consolidation,
        cpfp,
        sighashes,
        sequence_shapes,
        locktime_shape,
        has_uncompressed_pubkey,
        multisig_configs,
        has_multisig,
        uih1,
        uih2,
    }
}

fn has_equal_amount_outputs(outputs: &[&bitcoin::TxOut]) -> bool {
    if outputs.len() < 2 {
        return false;
    }
    let mut amounts: Vec<Amount> = outputs.iter().map(|o| o.value).collect();
    amounts.sort();
    amounts.windows(2).any(|w| w[0] == w[1])
}

/// rawtx-rs equal-output coinjoin heuristic: ≥2 ins/outs, ≥⅓ of outputs share a
/// value, and that shared value appears more than twice.
fn potentially_coinjoin(tx: &Transaction) -> bool {
    if tx.input.len() < 2 || tx.output.len() < 2 {
        return false;
    }
    let mut counts: HashMap<Amount, usize> = HashMap::new();
    for output in &tx.output {
        *counts.entry(output.value).or_insert(0) += 1;
    }
    let max_count = counts.values().copied().max().unwrap_or(0);
    max_count >= tx.output.len() / 3 && max_count > 2
}

/// Gibson UIH1 / UIH2 (see eprint 2022/589).
///
/// UIH1: there exists an output smaller than every input → that output looks like change.
/// UIH2: there exists an input larger than every output → the tx looks like it has an
/// unnecessary input relative to a simple payment.
fn uih_flags(prevouts: &[TxOut], payment_outputs: &[&bitcoin::TxOut]) -> (bool, bool) {
    if prevouts.is_empty() || payment_outputs.is_empty() {
        return (false, false);
    }

    let min_input = prevouts.iter().map(|p| p.value).min().unwrap();
    let max_input = prevouts.iter().map(|p| p.value).max().unwrap();
    let min_output = payment_outputs.iter().map(|o| o.value).min().unwrap();
    let max_output = payment_outputs.iter().map(|o| o.value).max().unwrap();

    let uih1 = min_output < min_input;
    let uih2 = max_input > max_output;
    (uih1, uih2)
}
