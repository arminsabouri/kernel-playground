//! Extra heuristics not fully covered by the fingerprint / rawtx crates.

use bitcoin::{Transaction, TxOut};
use serde::{Deserialize, Serialize};

use super::fingerprints::FingerprintFeatures;
use super::rawtx::{MultisigInfo, RawTxFeatures};
use super::types::{CpfpRole, LocktimeShape, PubkeyAlgo, SequenceShape, SighashType};
use super::BlockTxContext;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct HeuristicFeatures {
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
    /// Gibson UIH1: some payment-like output is smaller than every input.
    pub uih1: bool,
    /// Gibson UIH2: some input is larger than every output (unnecessary-looking input).
    pub uih2: bool,
    /// Fee is a whole number of sat/vB: `fee % vsize == 0` with a non-zero fee.
    pub fee_rate_round: bool,
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

    let (uih1, uih2) = uih_flags(prevouts, &payment_outputs);
    let fee_rate_round = fee_rate_round(tx, prevouts);

    HeuristicFeatures {
        cpfp,
        sighashes,
        sequence_shapes,
        locktime_shape,
        has_uncompressed_pubkey,
        multisig_configs,
        uih1,
        uih2,
        fee_rate_round,
    }
}

fn fee_rate_round(tx: &Transaction, prevouts: &[TxOut]) -> bool {
    if prevouts.is_empty() {
        return false;
    }
    let input_sum: u64 = prevouts.iter().map(|p| p.value.to_sat()).sum();
    let output_sum: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
    let vsize = tx.vsize() as u64;
    match input_sum.checked_sub(output_sum) {
        Some(fee) => fee > 0 && vsize > 0 && fee % vsize == 0,
        None => false,
    }
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
