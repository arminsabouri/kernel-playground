//! Transaction characteristics from `rawtx-rs`.
//!
//! <https://github.com/0xB10C/rawtx-rs>

use bitcoin::Transaction;
use rawtx_rs::input::InputInscriptionDetection;
use rawtx_rs::script::SignatureType;
use rawtx_rs::tx::{TransactionSigops, TxInfo};
use serde::Serialize;

use super::types::{DerEncoding, PubkeyAlgo, RawInputType, RawOutputType, SigAlgo, SighashType};

#[derive(Debug, Serialize)]
pub struct RawTxFeatures {
    pub version: i32,
    pub vsize: u64,
    pub weight: u64,
    pub locktime: u32,
    pub sigops: Option<usize>,
    pub payments: u32,
    pub script_types: ScriptTypeFlags,
    pub structure: StructureFlags,
    pub inputs: Vec<InputCharacteristics>,
    pub outputs: Vec<OutputCharacteristics>,
    /// True if any input reveals an ordinals inscription envelope.
    pub reveals_inscription: bool,
    /// True if the tx carries arbitrary data via OP_RETURN and/or an inscription.
    pub carries_raw_data: bool,
}

#[derive(Debug, Serialize)]
pub struct ScriptTypeFlags {
    pub is_spending_segwit: bool,
    pub is_spending_taproot: bool,
    pub is_spending_nested_segwit: bool,
    pub is_spending_native_segwit: bool,
    pub is_only_spending_segwit: bool,
    pub is_only_spending_legacy: bool,
    pub is_only_spending_taproot: bool,
    pub is_spending_segwit_and_legacy: bool,
    pub is_only_spending_nested_segwit: bool,
    pub is_only_spending_native_segwit: bool,
    pub is_spending_multisig: bool,
}

#[derive(Debug, Serialize)]
pub struct StructureFlags {
    pub is_signaling_explicit_rbf: bool,
    pub is_bip69_compliant: bool,
    pub has_opreturn_output: bool,
    /// Creates at least one P2A (ephemeral anchor) output.
    pub has_p2a_output: bool,
    /// rawtx-rs equal-output coinjoin heuristic (≥⅓ of outputs share a value, count > 2).
    pub potentially_coinjoin: bool,
    /// rawtx-rs consolidation heuristic (≥10 inputs, ≤2 outputs).
    pub potentially_consolidation: bool,
    pub output_value_sum_sat: u64,
}

#[derive(Debug, Serialize)]
pub struct InputCharacteristics {
    pub index: usize,
    pub input_type: RawInputType,
    pub sequence: u32,
    pub multisig: Option<MultisigInfo>,
    pub signatures: Vec<SignatureCharacteristics>,
    pub pubkeys: Vec<PubkeyCharacteristics>,
    pub spending: InputSpendFlags,
    pub reveals_inscription: bool,
}

#[derive(Debug, Serialize)]
pub struct InputSpendFlags {
    pub is_spending_segwit: bool,
    pub is_spending_taproot: bool,
    pub is_spending_nested_segwit: bool,
    pub is_spending_native_segwit: bool,
    pub is_spending_legacy: bool,
    pub is_spending_multisig: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MultisigInfo {
    pub m: u8,
    pub n: u8,
    pub unknown_n: bool,
}

#[derive(Debug, Serialize)]
pub struct SignatureCharacteristics {
    pub signature_type: SigAlgo,
    pub der_encoding: DerEncoding,
    pub sighash: SighashType,
    /// Original sighash flag byte (useful when [`SighashType::Unknown`]).
    pub sighash_flag: u8,
    pub length: usize,
    pub low_r: bool,
    pub low_s: bool,
}

#[derive(Debug, Serialize)]
pub struct PubkeyCharacteristics {
    pub pubkey_type: PubkeyAlgo,
    pub compressed: bool,
}

#[derive(Debug, Serialize)]
pub struct OutputCharacteristics {
    pub index: usize,
    pub output_type: RawOutputType,
    pub value_sat: u64,
    pub is_opreturn: bool,
    pub pubkeys: Vec<PubkeyCharacteristics>,
}

pub fn extract(tx: &Transaction) -> Result<RawTxFeatures, String> {
    let info = TxInfo::new(tx).map_err(|e| format!("rawtx-rs failed to parse tx: {e}"))?;

    let inscription_flags: Vec<bool> = tx
        .input
        .iter()
        .map(|i| i.reveals_inscription().unwrap_or(false))
        .collect();
    let reveals_inscription = inscription_flags.iter().any(|&v| v);
    let has_opreturn = info.has_opreturn_output();
    let has_p2a_output = info
        .output_infos
        .iter()
        .any(|o| matches!(o.out_type, rawtx_rs::output::OutputType::P2a));

    let inputs = info
        .input_infos
        .iter()
        .enumerate()
        .map(|(index, i)| InputCharacteristics {
            index,
            input_type: i.in_type.into(),
            sequence: i.sequence.0,
            multisig: i.multisig_info.as_ref().map(|m| MultisigInfo {
                m: m.m_of_n.0,
                n: m.m_of_n.1,
                unknown_n: m.unknown_n,
            }),
            signatures: i
                .signature_info
                .iter()
                .map(|s| {
                    // rawtx-rs reports 64-byte Schnorr sigs as sighash 0x01 (ALL).
                    // BIP341 treats that encoding as SIGHASH_DEFAULT (0x00).
                    let (sighash, sighash_flag) = match &s.signature {
                        SignatureType::Schnorr(_) if s.length == 64 => {
                            (SighashType::Default, 0x00)
                        }
                        SignatureType::Schnorr(_) => {
                            (SighashType::from_flag(s.sig_hash), s.sig_hash)
                        }
                        SignatureType::Ecdsa(_) => {
                            (SighashType::from_flag(s.sig_hash), s.sig_hash)
                        }
                    };
                    SignatureCharacteristics {
                        signature_type: match s.signature {
                            SignatureType::Ecdsa(_) => SigAlgo::Ecdsa,
                            SignatureType::Schnorr(_) => SigAlgo::Schnorr,
                        },
                        der_encoding: DerEncoding::from(&s.der_encoded),
                        sighash,
                        sighash_flag,
                        length: s.length,
                        low_r: s.low_r(),
                        low_s: s.low_s(),
                    }
                })
                .collect(),
            pubkeys: i.pubkey_stats.iter().map(pubkey_info).collect(),
            spending: InputSpendFlags {
                is_spending_segwit: i.is_spending_segwit(),
                is_spending_taproot: i.is_spending_taproot(),
                is_spending_nested_segwit: i.is_spending_nested_segwit(),
                is_spending_native_segwit: i.is_spending_native_segwit(),
                is_spending_legacy: i.is_spending_legacy(),
                is_spending_multisig: i.is_spending_multisig(),
            },
            reveals_inscription: inscription_flags.get(index).copied().unwrap_or(false),
        })
        .collect();

    let outputs = info
        .output_infos
        .iter()
        .enumerate()
        .map(|(index, o)| OutputCharacteristics {
            index,
            output_type: o.out_type.into(),
            value_sat: o.value.to_sat(),
            is_opreturn: o.is_opreturn(),
            pubkeys: o.pubkey_stats.iter().map(pubkey_info).collect(),
        })
        .collect();

    Ok(RawTxFeatures {
        version: info.version,
        vsize: info.vsize,
        weight: info.weight,
        locktime: info.locktime.to_consensus_u32(),
        sigops: tx.sigops().ok(),
        payments: info.payments(),
        script_types: ScriptTypeFlags {
            is_spending_segwit: info.is_spending_segwit(),
            is_spending_taproot: info.is_spending_taproot(),
            is_spending_nested_segwit: info.is_spending_nested_segwit(),
            is_spending_native_segwit: info.is_spending_native_segwit(),
            is_only_spending_segwit: info.is_only_spending_segwit(),
            is_only_spending_legacy: info.is_only_spending_legacy(),
            is_only_spending_taproot: info.is_only_spending_taproot(),
            is_spending_segwit_and_legacy: info.is_spending_segwit_and_legacy(),
            is_only_spending_nested_segwit: info.is_only_spending_nested_segwit(),
            is_only_spending_native_segwit: info.is_only_spending_native_segwit(),
            is_spending_multisig: info.is_spending_multisig(),
        },
        structure: StructureFlags {
            is_signaling_explicit_rbf: info.is_signaling_explicit_rbf_replicability(),
            is_bip69_compliant: info.is_bip69_compliant(),
            has_opreturn_output: has_opreturn,
            has_p2a_output,
            potentially_coinjoin: info.potentially_coinjoin(),
            potentially_consolidation: info.potentially_consolidation(),
            output_value_sum_sat: info.output_value_sum().to_sat(),
        },
        inputs,
        outputs,
        reveals_inscription,
        carries_raw_data: has_opreturn || reveals_inscription,
    })
}

fn pubkey_info(p: &rawtx_rs::script::PubKeyInfo) -> PubkeyCharacteristics {
    PubkeyCharacteristics {
        pubkey_type: match p.pubkey_type {
            rawtx_rs::script::PubkeyType::ECDSA => PubkeyAlgo::Ecdsa,
            rawtx_rs::script::PubkeyType::Schnorr => PubkeyAlgo::Schnorr,
        },
        compressed: p.compressed,
    }
}
