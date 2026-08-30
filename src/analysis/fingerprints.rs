//! Wallet fingerprints from `tx-indexer-fingerprints`, plus taproot-specific vectors.
//!
//! <https://github.com/payjoin/tx-indexer/tree/master/src/crates/fingerprints>

use bitcoin::{Transaction, TxIn, TxOut};
use rawtx_rs::input::{InputTypeDetection, TAPROOT_ANNEX_INDICATOR};
use serde::{Deserialize, Serialize};
use tx_indexer_fingerprints::{input, input_with_prevout, transaction};

use super::types::{
    InputSorting, OutputStructure, RawOutputType, SchnorrSighashForm, TaprootSpendPath,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct FingerprintFeatures {
    pub transaction: TransactionFingerprints,
    pub inputs: Vec<InputFingerprints>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionFingerprints {
    pub address_reuse: bool,
    pub mixed_input_types: bool,
    pub input_order: Vec<InputSorting>,
    pub nlocktime_optin_without_use: bool,
    pub bip68_with_absolute_locktime: bool,
    pub outputs_bip69_sorted: bool,
    pub output_structure: OutputStructure,
    pub round_fee: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InputFingerprints {
    pub low_r_grinding: bool,
    /// Prevout script type via rawtx-rs.
    pub input_type: RawOutputType,
    pub has_uncompressed_pubkey: bool,
    /// BIP341 annex present on this taproot input.
    pub has_taproot_annex: bool,
    /// Schnorr sighash wire encodings on this input (key- or script-path).
    pub schnorr_sighash_forms: Vec<SchnorrSighashForm>,
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
                low_r_grinding: input::low_r_grinding(txin),
                input_type: prevout
                    .map(RawOutputType::from_txout)
                    .unwrap_or(RawOutputType::Unknown),
                has_uncompressed_pubkey: prevout
                    .map(|p| input_with_prevout::has_uncompressed_pubkey(txin, p))
                    .unwrap_or(false),
                has_taproot_annex: taproot.has_annex,
                schnorr_sighash_forms: taproot.schnorr_forms,
            }
        })
        .collect();

    let transaction = TransactionFingerprints {
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

    FingerprintFeatures {
        transaction,
        inputs,
    }
}

struct TaprootInputInfo {
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
