//! Transaction characteristics from `rawtx-rs`.

use bitcoin::Transaction;
use rawtx_rs::input::InputInscriptionDetection;
use rawtx_rs::script::SignatureType;
use rawtx_rs::tx::TxInfo;
use serde::{Deserialize, Serialize};

use super::types::{DerEncoding, PubkeyAlgo, RawInputType, RawOutputType, SigAlgo, SighashType};

#[derive(Debug, Serialize, Deserialize)]
pub struct RawTxFeatures {
    pub version: i32,
    pub inputs: Vec<InputCharacteristics>,
    pub outputs: Vec<OutputCharacteristics>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InputCharacteristics {
    pub input_type: RawInputType,
    pub multisig: Option<MultisigInfo>,
    pub signatures: Vec<SignatureCharacteristics>,
    pub pubkeys: Vec<PubkeyCharacteristics>,
    pub reveals_inscription: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigInfo {
    pub m: u8,
    pub n: u8,
    pub unknown_n: bool,
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct PubkeyCharacteristics {
    pub pubkey_type: PubkeyAlgo,
    pub compressed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OutputCharacteristics {
    pub output_type: RawOutputType,
    pub pubkeys: Vec<PubkeyCharacteristics>,
}

pub fn extract(tx: &Transaction) -> Result<RawTxFeatures, String> {
    let info = TxInfo::new(tx).map_err(|e| format!("rawtx-rs failed to parse tx: {e}"))?;

    let inscription_flags: Vec<bool> = tx
        .input
        .iter()
        .map(|i| i.reveals_inscription().unwrap_or(false))
        .collect();

    let inputs = info
        .input_infos
        .iter()
        .enumerate()
        .map(|(index, i)| InputCharacteristics {
            input_type: i.in_type.into(),
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
                        SignatureType::Schnorr(_) if s.length == 64 => (SighashType::Default, 0x00),
                        SignatureType::Schnorr(_) => {
                            (SighashType::from_flag(s.sig_hash), s.sig_hash)
                        }
                        SignatureType::Ecdsa(_) => (SighashType::from_flag(s.sig_hash), s.sig_hash),
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
            reveals_inscription: inscription_flags.get(index).copied().unwrap_or(false),
        })
        .collect();

    let outputs = info
        .output_infos
        .iter()
        .map(|o| OutputCharacteristics {
            output_type: o.out_type.into(),
            pubkeys: o.pubkey_stats.iter().map(pubkey_info).collect(),
        })
        .collect();

    Ok(RawTxFeatures {
        version: info.version,
        inputs,
        outputs,
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
