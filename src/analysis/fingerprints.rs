//! Wallet fingerprints from `tx-indexer-fingerprints`, plus taproot-specific vectors.
//!
//! <https://github.com/payjoin/tx-indexer/tree/master/src/crates/fingerprints>

use bitcoin::{Transaction, TxIn, TxOut};
use rawtx_rs::input::{InputTypeDetection, TAPROOT_ANNEX_INDICATOR};
use serde::Serialize;
use tx_indexer_fingerprints::{input, input_with_prevout, transaction};

use super::types::{
    InputSorting, OutputStructure, RawOutputType, SchnorrSighashForm, TaprootSpendPath,
};

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
    /// Any taproot input carries a BIP341 annex.
    pub has_taproot_annex: bool,
    /// Any Schnorr sig uses the 64-byte DEFAULT encoding.
    pub has_schnorr_default: bool,
    /// Any Schnorr sig uses a 65-byte explicit SIGHASH_ALL.
    pub has_schnorr_explicit_all: bool,
    /// Any Schnorr sig uses a 65-byte explicit non-ALL sighash.
    pub has_schnorr_explicit_other: bool,
    /// Creates at least one P2A (ephemeral anchor) output.
    pub has_p2a_output: bool,
}

#[derive(Debug, Serialize)]
pub struct InputFingerprints {
    pub index: usize,
    pub signals_rbf: bool,
    pub low_r_grinding: bool,
    /// Prevout script type via rawtx-rs.
    pub input_type: RawOutputType,
    pub has_uncompressed_pubkey: bool,
    pub taproot_spend_path: TaprootSpendPath,
    /// BIP341 annex present on this taproot input.
    pub has_taproot_annex: bool,
    /// Schnorr sighash wire encodings on this input (key- or script-path).
    pub schnorr_sighash_forms: Vec<SchnorrSighashForm>,
    /// Any Schnorr sig on this input is not the compact DEFAULT form.
    pub taproot_non_default_sighash: bool,
}

#[derive(Debug, Serialize)]
pub struct OutputFingerprints {
    pub index: usize,
    pub output_type: RawOutputType,
}

pub fn extract(tx: &Transaction, prevouts: &[TxOut]) -> FingerprintFeatures {
    let locktime = tx.lock_time.to_consensus_u32();

    let inputs: Vec<InputFingerprints> = tx
        .input
        .iter()
        .enumerate()
        .map(|(index, txin)| {
            let prevout = prevouts.get(index);
            let taproot = taproot_input_info(txin);
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
                taproot_spend_path: taproot.path,
                has_taproot_annex: taproot.has_annex,
                schnorr_sighash_forms: taproot.schnorr_forms.clone(),
                taproot_non_default_sighash: taproot
                    .schnorr_forms
                    .iter()
                    .any(|f| *f != SchnorrSighashForm::Default),
            }
        })
        .collect();

    let outputs: Vec<OutputFingerprints> = tx
        .output
        .iter()
        .enumerate()
        .map(|(index, txout)| OutputFingerprints {
            index,
            output_type: RawOutputType::from_txout(txout),
        })
        .collect();

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
        has_taproot_annex: inputs.iter().any(|i| i.has_taproot_annex),
        has_schnorr_default: inputs.iter().any(|i| {
            i.schnorr_sighash_forms
                .iter()
                .any(|f| *f == SchnorrSighashForm::Default)
        }),
        has_schnorr_explicit_all: inputs.iter().any(|i| {
            i.schnorr_sighash_forms
                .iter()
                .any(|f| *f == SchnorrSighashForm::ExplicitAll)
        }),
        has_schnorr_explicit_other: inputs.iter().any(|i| {
            i.schnorr_sighash_forms
                .iter()
                .any(|f| *f == SchnorrSighashForm::ExplicitOther)
        }),
        has_p2a_output: outputs.iter().any(|o| o.output_type == RawOutputType::P2a),
    };

    FingerprintFeatures {
        transaction,
        inputs,
        outputs,
    }
}

struct TaprootInputInfo {
    path: TaprootSpendPath,
    has_annex: bool,
    schnorr_forms: Vec<SchnorrSighashForm>,
}

fn taproot_input_info(txin: &TxIn) -> TaprootInputInfo {
    let has_annex = witness_has_annex(txin);
    let path = if txin.is_p2trkp() {
        TaprootSpendPath::Key
    } else if txin.is_p2trsp() {
        TaprootSpendPath::Script
    } else {
        TaprootSpendPath::None
    };

    let schnorr_forms = match path {
        TaprootSpendPath::Key => {
            // witness: [ <sig> (<annex>) ]
            txin.witness
                .nth(0)
                .and_then(|sig| SchnorrSighashForm::from_sig_bytes(sig))
                .into_iter()
                .collect()
        }
        TaprootSpendPath::Script => {
            // witness: [ <stack...>, <script>, <control>, (<annex>) ]
            let items = txin.witness.to_vec();
            let skip_tail = if has_annex { 3 } else { 2 };
            if items.len() < skip_tail {
                Vec::new()
            } else {
                items[..items.len() - skip_tail]
                    .iter()
                    .filter_map(|bytes| SchnorrSighashForm::from_sig_bytes(bytes))
                    .collect()
            }
        }
        TaprootSpendPath::None => Vec::new(),
    };

    TaprootInputInfo {
        path,
        has_annex: has_annex && path != TaprootSpendPath::None,
        schnorr_forms,
    }
}

fn witness_has_annex(txin: &TxIn) -> bool {
    txin.witness.len() >= 2
        && txin
            .witness
            .last()
            .is_some_and(|item| !item.is_empty() && item[0] == TAPROOT_ANNEX_INDICATOR)
}
