//! Wallet fingerprints from `tx-indexer-fingerprints`.
//!
//! <https://github.com/payjoin/tx-indexer/tree/master/src/crates/fingerprints>

use bitcoin::{Transaction, TxOut};
use serde::Serialize;
use tx_indexer_fingerprints::{input, input_with_prevout, transaction};

use super::types::{InputSorting, OutputStructure, RawOutputType};

#[derive(Debug, Serialize)]
pub struct FingerprintFeatures {
    pub transaction: TransactionFingerprints,
    pub inputs: Vec<InputFingerprints>,
    pub outputs: Vec<OutputFingerprints>,
}

#[derive(Debug, Serialize)]
pub struct TransactionFingerprints {
    pub signals_rbf: bool,
    /// Non-zero nLockTime (library's anti-fee-sniping heuristic).
    pub anti_fee_snipe: bool,
    pub address_reuse: bool,
    pub mixed_input_types: bool,
    pub input_order: Vec<InputSorting>,
    pub nlocktime_optin_without_use: bool,
    pub bip68_with_absolute_locktime: bool,
    pub outputs_bip69_sorted: bool,
    pub output_structure: OutputStructure,
    pub round_fee: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct InputFingerprints {
    pub index: usize,
    pub signals_rbf: bool,
    pub low_r_grinding: bool,
    /// Prevout script type via rawtx-rs.
    pub input_type: RawOutputType,
    pub has_uncompressed_pubkey: bool,
    pub taproot_keyspend_non_default_sighash: bool,
}

#[derive(Debug, Serialize)]
pub struct OutputFingerprints {
    pub index: usize,
    pub output_type: RawOutputType,
}

pub fn extract(tx: &Transaction, prevouts: &[TxOut]) -> FingerprintFeatures {
    let locktime = tx.lock_time.to_consensus_u32();

    let transaction = TransactionFingerprints {
        signals_rbf: transaction::tx_signals_rbf(&tx.input),
        anti_fee_snipe: transaction::anti_fee_snipe(locktime),
        address_reuse: transaction::address_reuse(&tx.output, prevouts),
        mixed_input_types: transaction::mixed_input_types(prevouts),
        input_order: transaction::input_order(&tx.input, prevouts)
            .into_iter()
            .map(InputSorting::from)
            .collect(),
        nlocktime_optin_without_use: transaction::nlocktime_optin_without_use(&tx.input, locktime),
        bip68_with_absolute_locktime: transaction::bip68_with_absolute_locktime(
            &tx.input, locktime,
        ),
        outputs_bip69_sorted: transaction::is_bip69_sorted(&tx.output),
        output_structure: transaction::output_structure(&tx.output).into(),
        round_fee: transaction::round_fee(prevouts, &tx.output),
    };

    let inputs = tx
        .input
        .iter()
        .enumerate()
        .map(|(index, txin)| {
            let prevout = prevouts.get(index);
            InputFingerprints {
                index,
                signals_rbf: input::signals_rbf(txin),
                low_r_grinding: input::low_r_grinding(txin),
                input_type: prevout
                    .map(RawOutputType::from_txout)
                    .unwrap_or(RawOutputType::Unknown),
                has_uncompressed_pubkey: prevout
                    .map(|p| input_with_prevout::has_uncompressed_pubkey(txin, p))
                    .unwrap_or(false),
                taproot_keyspend_non_default_sighash: prevout
                    .map(|p| input_with_prevout::taproot_keyspend_non_default_sighash(txin, p))
                    .unwrap_or(false),
            }
        })
        .collect();

    let outputs = tx
        .output
        .iter()
        .enumerate()
        .map(|(index, txout)| OutputFingerprints {
            index,
            output_type: RawOutputType::from_txout(txout),
        })
        .collect();

    FingerprintFeatures {
        transaction,
        inputs,
        outputs,
    }
}
