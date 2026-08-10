//! Extra heuristics not fully covered by the fingerprint / rawtx crates.

use bitcoin::{Amount, Transaction, TxOut};
use serde::Serialize;

use super::fingerprints::FingerprintFeatures;
use super::rawtx::{MultisigInfo, RawTxFeatures};
use super::types::{CpfpRole, PubkeyAlgo, RawInputType, RawOutputType, SighashType};
use super::BlockTxContext;

#[derive(Debug, Serialize)]
pub struct HeuristicFeatures {
    /// Dumb equal-amount check: ≥2 non-OP_RETURN outputs share the exact same value.
    pub equal_amount_outputs: bool,
    /// Likely coinjoin: equal-amount outputs *or* rawtx-rs potentially_coinjoin.
    pub likely_coinjoin: bool,
    /// Many inputs (≥3) into 1 or 2 non-OP_RETURN outputs.
    pub likely_consolidation: bool,
    pub cpfp: CpfpRole,
    pub is_cpfp_package: bool,
    /// Distinct sighash types seen across all input signatures.
    pub sighashes: Vec<SighashType>,
    /// Raw nSequence values for every input.
    pub nsequences: Vec<u32>,
    /// Non-zero nLockTime (anti-fee-sniping style locktime usage).
    pub nlocktime_anti_fee_sniping: bool,
    /// nLockTime encoded as a block height rather than a unix timestamp.
    pub nlocktime_is_height: bool,
    pub nlocktime: u32,
    /// Any input or fingerprint indicates an uncompressed pubkey.
    pub has_uncompressed_pubkey: bool,
    /// Distinct multisig configurations observed on inputs.
    pub multisig_configs: Vec<MultisigInfo>,
    pub has_multisig: bool,
    /// Prevout script types via rawtx-rs.
    pub prevout_types: Vec<RawOutputType>,
    /// Spend types from rawtx-rs.
    pub input_types: Vec<RawInputType>,
    /// Gibson UIH1: some payment-like output is smaller than every input.
    pub uih1: bool,
    /// Gibson UIH2: some input is larger than every output (unnecessary-looking input).
    pub uih2: bool,
    pub has_op_return: bool,
    pub reveals_inscription: bool,
    pub carries_raw_data: bool,
}

pub fn extract(
    tx: &Transaction,
    prevouts: &[TxOut],
    fingerprints: &FingerprintFeatures,
    rawtx: &RawTxFeatures,
    block_ctx: &BlockTxContext,
) -> HeuristicFeatures {
    let payment_outputs: Vec<&bitcoin::TxOut> = tx
        .output
        .iter()
        .filter(|o| !o.script_pubkey.is_op_return())
        .collect();

    let equal_amount_outputs = has_equal_amount_outputs(&payment_outputs);
    let likely_coinjoin = equal_amount_outputs || rawtx.structure.potentially_coinjoin;
    let likely_consolidation = tx.input.len() >= 3 && payment_outputs.len() <= 2
        || rawtx.structure.potentially_consolidation;

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

    let nsequences: Vec<u32> = tx.input.iter().map(|i| i.sequence.0).collect();
    let nlocktime = tx.lock_time.to_consensus_u32();
    let nlocktime_anti_fee_sniping = nlocktime != 0;
    let nlocktime_is_height = nlocktime > 0 && nlocktime < 500_000_000;

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

    let mut multisig_configs: Vec<MultisigInfo> = rawtx
        .inputs
        .iter()
        .filter_map(|i| i.multisig)
        .collect();
    multisig_configs.sort_by_key(|m| (m.m, m.n, m.unknown_n));
    multisig_configs.dedup();

    let prevout_types: Vec<RawOutputType> =
        fingerprints.inputs.iter().map(|i| i.input_type).collect();
    let input_types: Vec<RawInputType> = rawtx.inputs.iter().map(|i| i.input_type).collect();

    let (uih1, uih2) = uih_flags(prevouts, &payment_outputs);

    HeuristicFeatures {
        equal_amount_outputs,
        likely_coinjoin,
        likely_consolidation,
        cpfp,
        is_cpfp_package: cpfp != CpfpRole::None,
        sighashes,
        nsequences,
        nlocktime_anti_fee_sniping,
        nlocktime_is_height,
        nlocktime,
        has_uncompressed_pubkey,
        multisig_configs,
        has_multisig: rawtx.script_types.is_spending_multisig,
        prevout_types,
        input_types,
        uih1,
        uih2,
        has_op_return: rawtx.structure.has_opreturn_output,
        reveals_inscription: rawtx.reveals_inscription,
        carries_raw_data: rawtx.carries_raw_data,
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
