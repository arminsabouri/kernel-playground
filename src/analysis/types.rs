//! Categorical feature types for later integer / one-hot normalization.
//!
//! Every enum here:
//! - has a stable `#[repr(u8)]` discriminant (wire / storage code)
//! - serializes/deserializes as that integer in JSON
//! - implements [`Display`] for human-readable labels
//! - exposes [`Categorical::all`] for dense one-hot / multi-hot columns

use std::fmt;

use serde_repr::{Deserialize_repr, Serialize_repr};

/// Enums that can be expanded into a fixed one-hot / multi-hot block.
pub trait Categorical: Copy + Eq + 'static {
    fn all() -> &'static [Self];

    fn dense_id(self) -> usize {
        Self::all()
            .iter()
            .position(|&x| x == self)
            .expect("categorical variant missing from all()")
    }

    fn cardinality() -> usize {
        Self::all().len()
    }

    fn label(self) -> String
    where
        Self: fmt::Display,
    {
        self.to_string()
    }
}

/// Input ordering fingerprints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum InputSorting {
    Single = 0,
    Ascending = 1,
    Descending = 2,
    Bip69 = 3,
    Historical = 4,
    Unknown = 5,
}

impl Categorical for InputSorting {
    fn all() -> &'static [Self] {
        &[
            Self::Single,
            Self::Ascending,
            Self::Descending,
            Self::Bip69,
            Self::Historical,
            Self::Unknown,
        ]
    }
}

impl From<tx_indexer_fingerprints::types::InputSortingType> for InputSorting {
    fn from(t: tx_indexer_fingerprints::types::InputSortingType) -> Self {
        match t {
            tx_indexer_fingerprints::types::InputSortingType::Single => Self::Single,
            tx_indexer_fingerprints::types::InputSortingType::Ascending => Self::Ascending,
            tx_indexer_fingerprints::types::InputSortingType::Descending => Self::Descending,
            tx_indexer_fingerprints::types::InputSortingType::Bip69 => Self::Bip69,
            tx_indexer_fingerprints::types::InputSortingType::Historical => Self::Historical,
            tx_indexer_fingerprints::types::InputSortingType::Unknown => Self::Unknown,
        }
    }
}

impl fmt::Display for InputSorting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Single => "single",
            Self::Ascending => "ascending",
            Self::Descending => "descending",
            Self::Bip69 => "bip69",
            Self::Historical => "historical",
            Self::Unknown => "unknown",
        })
    }
}

/// Coarse output-count structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum OutputStructure {
    Single = 0,
    Double = 1,
    Multi = 2,
    Unknown = 3,
}

impl From<tx_indexer_fingerprints::types::OutputStructureType> for OutputStructure {
    fn from(t: tx_indexer_fingerprints::types::OutputStructureType) -> Self {
        match t {
            tx_indexer_fingerprints::types::OutputStructureType::Single => Self::Single,
            tx_indexer_fingerprints::types::OutputStructureType::Double => Self::Double,
            tx_indexer_fingerprints::types::OutputStructureType::Multi => Self::Multi,
            tx_indexer_fingerprints::types::OutputStructureType::Unknown => Self::Unknown,
        }
    }
}

impl fmt::Display for OutputStructure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Single => "single",
            Self::Double => "double",
            Self::Multi => "multi",
            Self::Unknown => "unknown",
        })
    }
}

/// Input spend type from rawtx-rs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum RawInputType {
    P2pk = 0,
    P2pkLaxDer = 1,
    P2pkh = 2,
    P2pkhLaxDer = 3,
    P2shP2wpkh = 4,
    P2wpkh = 5,
    P2ms = 6,
    P2msLaxDer = 7,
    P2sh = 8,
    P2shP2wsh = 9,
    P2wsh = 10,
    P2trkp = 11,
    P2trsp = 12,
    P2a = 13,
    Coinbase = 14,
    CoinbaseWitness = 15,
    Unknown = 16,
}

impl From<rawtx_rs::input::InputType> for RawInputType {
    fn from(t: rawtx_rs::input::InputType) -> Self {
        match t {
            rawtx_rs::input::InputType::P2pk => Self::P2pk,
            rawtx_rs::input::InputType::P2pkLaxDer => Self::P2pkLaxDer,
            rawtx_rs::input::InputType::P2pkh => Self::P2pkh,
            rawtx_rs::input::InputType::P2pkhLaxDer => Self::P2pkhLaxDer,
            rawtx_rs::input::InputType::P2shP2wpkh => Self::P2shP2wpkh,
            rawtx_rs::input::InputType::P2wpkh => Self::P2wpkh,
            rawtx_rs::input::InputType::P2ms => Self::P2ms,
            rawtx_rs::input::InputType::P2msLaxDer => Self::P2msLaxDer,
            rawtx_rs::input::InputType::P2sh => Self::P2sh,
            rawtx_rs::input::InputType::P2shP2wsh => Self::P2shP2wsh,
            rawtx_rs::input::InputType::P2wsh => Self::P2wsh,
            rawtx_rs::input::InputType::P2trkp => Self::P2trkp,
            rawtx_rs::input::InputType::P2trsp => Self::P2trsp,
            rawtx_rs::input::InputType::P2a => Self::P2a,
            rawtx_rs::input::InputType::Coinbase => Self::Coinbase,
            rawtx_rs::input::InputType::CoinbaseWitness => Self::CoinbaseWitness,
            rawtx_rs::input::InputType::Unknown => Self::Unknown,
        }
    }
}

impl fmt::Display for RawInputType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::P2pk => "p2pk",
            Self::P2pkLaxDer => "p2pk_lax_der",
            Self::P2pkh => "p2pkh",
            Self::P2pkhLaxDer => "p2pkh_lax_der",
            Self::P2shP2wpkh => "p2sh_p2wpkh",
            Self::P2wpkh => "p2wpkh",
            Self::P2ms => "p2ms",
            Self::P2msLaxDer => "p2ms_lax_der",
            Self::P2sh => "p2sh",
            Self::P2shP2wsh => "p2sh_p2wsh",
            Self::P2wsh => "p2wsh",
            Self::P2trkp => "p2tr_keypath",
            Self::P2trsp => "p2tr_scriptpath",
            Self::P2a => "p2a",
            Self::Coinbase => "coinbase",
            Self::CoinbaseWitness => "coinbase_witness",
            Self::Unknown => "unknown",
        })
    }
}

/// Output type from rawtx-rs, with OP_RETURN flavors flattened for a single int column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum RawOutputType {
    P2pk = 0,
    P2pkh = 1,
    P2wpkhV0 = 2,
    P2ms = 3,
    P2sh = 4,
    P2wshV0 = 5,
    P2tr = 6,
    P2a = 7,
    Unknown = 8,
    OpReturn = 20,
    OpReturnWitnessCommitment = 21,
    OpReturnOmni = 22,
    OpReturnStacksBlockCommit = 23,
    OpReturnLen1Byte = 24,
    OpReturnLen20Byte = 25,
    OpReturnLen80Byte = 26,
    OpReturnBip47PaymentCode = 27,
    OpReturnRskBlock = 28,
    OpReturnCoreDao = 29,
    OpReturnExSat = 30,
    OpReturnHathorNetwork = 31,
    OpReturnRunestone = 32,
}

impl From<rawtx_rs::output::OutputType> for RawOutputType {
    fn from(t: rawtx_rs::output::OutputType) -> Self {
        use rawtx_rs::output::{OpReturnFlavor, OutputType};
        match t {
            OutputType::P2pk => Self::P2pk,
            OutputType::P2pkh => Self::P2pkh,
            OutputType::P2wpkhV0 => Self::P2wpkhV0,
            OutputType::P2ms => Self::P2ms,
            OutputType::P2sh => Self::P2sh,
            OutputType::P2wshV0 => Self::P2wshV0,
            OutputType::P2tr => Self::P2tr,
            OutputType::P2a => Self::P2a,
            OutputType::Unknown => Self::Unknown,
            OutputType::OpReturn(flavor) => match flavor {
                OpReturnFlavor::Unspecified => Self::OpReturn,
                OpReturnFlavor::WitnessCommitment => Self::OpReturnWitnessCommitment,
                OpReturnFlavor::Omni => Self::OpReturnOmni,
                OpReturnFlavor::StacksBlockCommit => Self::OpReturnStacksBlockCommit,
                OpReturnFlavor::Len1Byte => Self::OpReturnLen1Byte,
                OpReturnFlavor::Len20Byte => Self::OpReturnLen20Byte,
                OpReturnFlavor::Len80Byte => Self::OpReturnLen80Byte,
                OpReturnFlavor::Bip47PaymentCode => Self::OpReturnBip47PaymentCode,
                OpReturnFlavor::RSKBlock => Self::OpReturnRskBlock,
                OpReturnFlavor::CoreDao => Self::OpReturnCoreDao,
                OpReturnFlavor::ExSat => Self::OpReturnExSat,
                OpReturnFlavor::HathorNetwork => Self::OpReturnHathorNetwork,
                OpReturnFlavor::Runestone => Self::OpReturnRunestone,
            },
        }
    }
}

impl RawOutputType {
    /// Classify a transaction output via rawtx-rs.
    pub fn from_txout(txout: &bitcoin::TxOut) -> Self {
        use rawtx_rs::output::OutputTypeDetection;
        txout.get_type().into()
    }
}

impl fmt::Display for RawOutputType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::P2pk => "p2pk",
            Self::P2pkh => "p2pkh",
            Self::P2wpkhV0 => "p2wpkh_v0",
            Self::P2ms => "p2ms",
            Self::P2sh => "p2sh",
            Self::P2wshV0 => "p2wsh_v0",
            Self::P2tr => "p2tr",
            Self::P2a => "p2a",
            Self::Unknown => "unknown",
            Self::OpReturn => "op_return",
            Self::OpReturnWitnessCommitment => "op_return_witness_commitment",
            Self::OpReturnOmni => "op_return_omni",
            Self::OpReturnStacksBlockCommit => "op_return_stacks_block_commit",
            Self::OpReturnLen1Byte => "op_return_len_1",
            Self::OpReturnLen20Byte => "op_return_len_20",
            Self::OpReturnLen80Byte => "op_return_len_80",
            Self::OpReturnBip47PaymentCode => "op_return_bip47",
            Self::OpReturnRskBlock => "op_return_rsk",
            Self::OpReturnCoreDao => "op_return_coredao",
            Self::OpReturnExSat => "op_return_exsat",
            Self::OpReturnHathorNetwork => "op_return_hathor",
            Self::OpReturnRunestone => "op_return_runestone",
        })
    }
}

/// Sighash type. Discriminants match the on-wire flag byte where possible;
/// [`Self::Unknown`] covers anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum SighashType {
    Default = 0x00,
    All = 0x01,
    None = 0x02,
    Single = 0x03,
    AllAnyoneCanPay = 0x81,
    NoneAnyoneCanPay = 0x82,
    SingleAnyoneCanPay = 0x83,
    Unknown = 0xff,
}

impl SighashType {
    pub fn from_flag(flag: u8) -> Self {
        match flag {
            0x00 => Self::Default,
            0x01 => Self::All,
            0x02 => Self::None,
            0x03 => Self::Single,
            0x81 => Self::AllAnyoneCanPay,
            0x82 => Self::NoneAnyoneCanPay,
            0x83 => Self::SingleAnyoneCanPay,
            _ => Self::Unknown,
        }
    }
}

impl fmt::Display for SighashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Default => "DEFAULT",
            Self::All => "ALL",
            Self::None => "NONE",
            Self::Single => "SINGLE",
            Self::AllAnyoneCanPay => "ALL|ANYONECANPAY",
            Self::NoneAnyoneCanPay => "NONE|ANYONECANPAY",
            Self::SingleAnyoneCanPay => "SINGLE|ANYONECANPAY",
            Self::Unknown => "UNKNOWN",
        })
    }
}

/// How a Schnorr signature encodes its sighash (BIP341).
///
/// rawtx-rs maps 64-byte sigs to flag `0x01`; we recover the wire encoding here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum SchnorrSighashForm {
    /// 64-byte signature → implicit SIGHASH_DEFAULT.
    Default = 0,
    /// 65-byte signature with explicit SIGHASH_ALL (`0x01`).
    ExplicitAll = 1,
    /// 65-byte signature with some other explicit sighash flag.
    ExplicitOther = 2,
}

impl SchnorrSighashForm {
    pub fn from_sig_bytes(sig: &[u8]) -> Option<Self> {
        match sig.len() {
            64 => Some(Self::Default),
            65 => match sig[64] {
                0x01 => Some(Self::ExplicitAll),
                _ => Some(Self::ExplicitOther),
            },
            _ => None,
        }
    }
}

impl fmt::Display for SchnorrSighashForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Default => "default",
            Self::ExplicitAll => "explicit_all",
            Self::ExplicitOther => "explicit_other",
        })
    }
}

/// Taproot spend path for an input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum TaprootSpendPath {
    None = 0,
    Key = 1,
    Script = 2,
}

impl fmt::Display for TaprootSpendPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "none",
            Self::Key => "key",
            Self::Script => "script",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum SigAlgo {
    Ecdsa = 0,
    Schnorr = 1,
}

impl fmt::Display for SigAlgo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Ecdsa => "ecdsa",
            Self::Schnorr => "schnorr",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum PubkeyAlgo {
    Ecdsa = 0,
    Schnorr = 1,
}

impl From<rawtx_rs::script::PubkeyType> for PubkeyAlgo {
    fn from(t: rawtx_rs::script::PubkeyType) -> Self {
        match t {
            rawtx_rs::script::PubkeyType::ECDSA => Self::Ecdsa,
            rawtx_rs::script::PubkeyType::Schnorr => Self::Schnorr,
        }
    }
}

impl fmt::Display for PubkeyAlgo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Ecdsa => "ecdsa",
            Self::Schnorr => "schnorr",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum DerEncoding {
    NotApplicable = 0,
    Valid = 1,
    SigTooShort = 2,
    SigTooLong = 3,
    NoCompoundMarker = 4,
    InvalidCompoundLengthDescriptor = 5,
    NoSValueLengthDescriptor = 6,
    DescribedLengthMismatch = 7,
    RElementNotAnInteger = 8,
    RLengthIsZero = 9,
    NegativeRValue = 10,
    NullByteAtRValueStart = 11,
    SElementNotAnInteger = 12,
    SLengthIsZero = 13,
    NegativeSValue = 14,
    NullByteAtSValueStart = 15,
}

impl From<&rawtx_rs::script::DEREncoding> for DerEncoding {
    fn from(d: &rawtx_rs::script::DEREncoding) -> Self {
        use rawtx_rs::script::DEREncoding as D;
        match d {
            D::NotApplicable => Self::NotApplicable,
            D::Valid => Self::Valid,
            D::SigTooShort => Self::SigTooShort,
            D::SigTooLong => Self::SigTooLong,
            D::NoCompoundMarker => Self::NoCompoundMarker,
            D::InvalidCompoundLengthDescriptor => Self::InvalidCompoundLengthDescriptor,
            D::NoSValueLengthDescriptor => Self::NoSValueLengthDescriptor,
            D::DescribedLengthMismatch => Self::DescribedLengthMismatch,
            D::RElementNotAnInteger => Self::RElementNotAnInteger,
            D::RLengthIsZero => Self::RLengthIsZero,
            D::NegativeRValue => Self::NegativeRValue,
            D::NullByteAtRValueStart => Self::NullByteAtRValueStart,
            D::SElementNotAnInteger => Self::SElementNotAnInteger,
            D::SLengthIsZero => Self::SLengthIsZero,
            D::NegativeSValue => Self::NegativeSValue,
            D::NullByteAtSValueStart => Self::NullByteAtSValueStart,
        }
    }
}

impl fmt::Display for DerEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotApplicable => "not_applicable",
            Self::Valid => "valid",
            Self::SigTooShort => "sig_too_short",
            Self::SigTooLong => "sig_too_long",
            Self::NoCompoundMarker => "no_compound_marker",
            Self::InvalidCompoundLengthDescriptor => "invalid_compound_length",
            Self::NoSValueLengthDescriptor => "no_s_length",
            Self::DescribedLengthMismatch => "described_length_mismatch",
            Self::RElementNotAnInteger => "r_not_integer",
            Self::RLengthIsZero => "r_length_zero",
            Self::NegativeRValue => "negative_r",
            Self::NullByteAtRValueStart => "null_byte_r",
            Self::SElementNotAnInteger => "s_not_integer",
            Self::SLengthIsZero => "s_length_zero",
            Self::NegativeSValue => "negative_s",
            Self::NullByteAtSValueStart => "null_byte_s",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum CpfpRole {
    None = 0,
    Parent = 1,
    Child = 2,
    Both = 3,
}

impl fmt::Display for CpfpRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "none",
            Self::Parent => "parent",
            Self::Child => "child",
            Self::Both => "both",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum ChangeHeuristic {
    AddressReuse = 0,
    OptimalChange = 1,
    ScriptTypeMatch = 2,
}

impl fmt::Display for ChangeHeuristic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AddressReuse => "address_reuse",
            Self::OptimalChange => "optimal_change",
            Self::ScriptTypeMatch => "script_type_match",
        })
    }
}

/// BIP68 / BIP125 shape of an input's nSequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum SequenceShape {
    /// `0xffffffff` — final; does not opt into nLockTime or RBF.
    Final = 0,
    /// `0xfffffffe` — enables nLockTime, does not signal BIP125 RBF.
    LocktimeNoRbf = 1,
    /// `0xfffffffd` — typical explicit BIP125 RBF (Core).
    Rbf = 2,
    /// Bit 31 clear, type flag clear — BIP68 relative locktime in blocks.
    RelativeBlocks = 3,
    /// Bit 31 clear, type flag set — BIP68 relative locktime in 512s units.
    RelativeTime = 4,
    /// Any other nSequence (unusual RBF-capable values, etc.).
    Other = 5,
}

impl SequenceShape {
    const DISABLE_FLAG: u32 = 1 << 31;
    const TYPE_FLAG: u32 = 1 << 22;

    pub fn from_nsequence(n: u32) -> Self {
        match n {
            0xffff_ffff => Self::Final,
            0xffff_fffe => Self::LocktimeNoRbf,
            0xffff_fffd => Self::Rbf,
            n if n & Self::DISABLE_FLAG != 0 => Self::Other,
            n if n & Self::TYPE_FLAG != 0 => Self::RelativeTime,
            _ => Self::RelativeBlocks,
        }
    }
}

impl fmt::Display for SequenceShape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Final => "final",
            Self::LocktimeNoRbf => "locktime_no_rbf",
            Self::Rbf => "rbf",
            Self::RelativeBlocks => "relative_blocks",
            Self::RelativeTime => "relative_time",
            Self::Other => "other",
        })
    }
}

/// nLockTime shape relative to the confirming block.
///
/// Height-delta bins follow common anti-fee-sniping practice (Core/Electrum often
/// use tip or tip−1; deltas ≥100 are weak/odd for that heuristic).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum LocktimeShape {
    /// nLockTime = 0.
    None = 0,
    /// Height-based, locktime == confirming height.
    HeightExact = 1,
    /// Height-based, confirming_height − locktime == 1.
    HeightDelta1 = 2,
    /// Height-based, delta in 2..=9.
    HeightDelta2To9 = 3,
    /// Height-based, delta in 10..=99.
    HeightDelta10To99 = 4,
    /// Height-based, delta ≥ 100 (weak anti-fee-snipe / stale).
    HeightDelta100Plus = 5,
    /// Height-based, but locktime > confirming height (should not confirm).
    HeightFuture = 6,
    /// Unix-timestamp locktime (≥ 500_000_000).
    Timestamp = 7,
}

impl LocktimeShape {
    const HEIGHT_THRESHOLD: u32 = 500_000_000;

    pub fn from_locktime(locktime: u32, block_height: i32) -> Self {
        if locktime == 0 {
            return Self::None;
        }
        if locktime >= Self::HEIGHT_THRESHOLD {
            return Self::Timestamp;
        }

        let height = block_height.max(0) as u32;
        if locktime > height {
            return Self::HeightFuture;
        }

        match height - locktime {
            0 => Self::HeightExact,
            1 => Self::HeightDelta1,
            2..=9 => Self::HeightDelta2To9,
            10..=99 => Self::HeightDelta10To99,
            _ => Self::HeightDelta100Plus,
        }
    }
}

impl fmt::Display for LocktimeShape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "none",
            Self::HeightExact => "height_exact",
            Self::HeightDelta1 => "height_delta_1",
            Self::HeightDelta2To9 => "height_delta_2_9",
            Self::HeightDelta10To99 => "height_delta_10_99",
            Self::HeightDelta100Plus => "height_delta_100_plus",
            Self::HeightFuture => "height_future",
            Self::Timestamp => "timestamp",
        })
    }
}

impl Categorical for OutputStructure {
    fn all() -> &'static [Self] {
        &[Self::Single, Self::Double, Self::Multi, Self::Unknown]
    }
}

impl Categorical for RawInputType {
    fn all() -> &'static [Self] {
        &[
            Self::P2pk,
            Self::P2pkLaxDer,
            Self::P2pkh,
            Self::P2pkhLaxDer,
            Self::P2shP2wpkh,
            Self::P2wpkh,
            Self::P2ms,
            Self::P2msLaxDer,
            Self::P2sh,
            Self::P2shP2wsh,
            Self::P2wsh,
            Self::P2trkp,
            Self::P2trsp,
            Self::P2a,
            Self::Coinbase,
            Self::CoinbaseWitness,
            Self::Unknown,
        ]
    }
}

impl Categorical for RawOutputType {
    fn all() -> &'static [Self] {
        &[
            Self::P2pk,
            Self::P2pkh,
            Self::P2wpkhV0,
            Self::P2ms,
            Self::P2sh,
            Self::P2wshV0,
            Self::P2tr,
            Self::P2a,
            Self::Unknown,
            Self::OpReturn,
            Self::OpReturnWitnessCommitment,
            Self::OpReturnOmni,
            Self::OpReturnStacksBlockCommit,
            Self::OpReturnLen1Byte,
            Self::OpReturnLen20Byte,
            Self::OpReturnLen80Byte,
            Self::OpReturnBip47PaymentCode,
            Self::OpReturnRskBlock,
            Self::OpReturnCoreDao,
            Self::OpReturnExSat,
            Self::OpReturnHathorNetwork,
            Self::OpReturnRunestone,
        ]
    }
}

impl Categorical for SighashType {
    fn all() -> &'static [Self] {
        &[
            Self::Default,
            Self::All,
            Self::None,
            Self::Single,
            Self::AllAnyoneCanPay,
            Self::NoneAnyoneCanPay,
            Self::SingleAnyoneCanPay,
            Self::Unknown,
        ]
    }
}

impl Categorical for SchnorrSighashForm {
    fn all() -> &'static [Self] {
        &[Self::Default, Self::ExplicitAll, Self::ExplicitOther]
    }
}

impl Categorical for TaprootSpendPath {
    fn all() -> &'static [Self] {
        &[Self::None, Self::Key, Self::Script]
    }
}

impl Categorical for CpfpRole {
    fn all() -> &'static [Self] {
        &[Self::None, Self::Parent, Self::Child, Self::Both]
    }
}

impl Categorical for ChangeHeuristic {
    fn all() -> &'static [Self] {
        &[
            Self::AddressReuse,
            Self::OptimalChange,
            Self::ScriptTypeMatch,
        ]
    }
}

impl Categorical for SequenceShape {
    fn all() -> &'static [Self] {
        &[
            Self::Final,
            Self::LocktimeNoRbf,
            Self::Rbf,
            Self::RelativeBlocks,
            Self::RelativeTime,
            Self::Other,
        ]
    }
}

impl Categorical for LocktimeShape {
    fn all() -> &'static [Self] {
        &[
            Self::None,
            Self::HeightExact,
            Self::HeightDelta1,
            Self::HeightDelta2To9,
            Self::HeightDelta10To99,
            Self::HeightDelta100Plus,
            Self::HeightFuture,
            Self::Timestamp,
        ]
    }
}
