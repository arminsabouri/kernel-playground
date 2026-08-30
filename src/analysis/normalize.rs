//! Normalize raw [`TxAnalysis`] NDJSON into a fixed numeric feature matrix.
//!
//! Encoding chosen for fingerprint **distribution / co-occurrence** work:
//! - bools → `0.0` / `1.0`
//! - single categoricals → one-hot over [`Categorical::all`]
//! - set-valued categoricals → multi-hot over the same vocabulary
//! - version kept as a raw float (no z-score yet)
//!
//! Identifiers (`txid`, block hash) stay as metadata beside the vector.
//! Aggregates that are linear functions of another block (e.g. "any RBF" vs
//! sequence-shape multi-hot) are omitted.

use serde::{Deserialize, Serialize};

use super::TxAnalysis;
use super::types::Categorical;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedTx {
    pub txid: String,
    pub block_height: i32,
    pub tx_index: usize,
    pub is_coinbase: bool,
    /// Feature values aligned with [`schema`].
    pub x: Vec<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureSchema {
    pub columns: Vec<String>,
}

struct FeatureBuilder {
    columns: Vec<String>,
    values: Vec<f64>,
    recording_schema: bool,
}

impl FeatureBuilder {
    fn new_schema() -> Self {
        Self {
            columns: Vec::new(),
            values: Vec::new(),
            recording_schema: true,
        }
    }

    fn new_row(ncols: usize) -> Self {
        Self {
            columns: Vec::new(),
            values: Vec::with_capacity(ncols),
            recording_schema: false,
        }
    }

    fn push_bool(&mut self, name: &str, v: bool) {
        if self.recording_schema {
            self.columns.push(name.to_string());
        } else {
            self.values.push(if v { 1.0 } else { 0.0 });
        }
    }

    fn push_f64(&mut self, name: &str, v: f64) {
        if self.recording_schema {
            self.columns.push(name.to_string());
        } else {
            self.values.push(v);
        }
    }

    fn push_one_hot<T: Categorical + std::fmt::Display>(&mut self, prefix: &str, value: T) {
        debug_assert_eq!(T::cardinality(), T::all().len());
        for variant in T::all() {
            let name = format!("{prefix}__{}", variant.label());
            self.push_bool(&name, variant.dense_id() == value.dense_id());
        }
    }

    fn push_multi_hot<T: Categorical + std::fmt::Display>(&mut self, prefix: &str, values: &[T]) {
        for variant in T::all() {
            let name = format!("{prefix}__{}", variant.label());
            self.push_bool(&name, values.iter().any(|v| v == variant));
        }
    }

    fn push_optional_bool_one_hot(&mut self, prefix: &str, value: Option<bool>) {
        self.push_bool(&format!("{prefix}__none"), value.is_none());
        self.push_bool(&format!("{prefix}__false"), value == Some(false));
        self.push_bool(&format!("{prefix}__true"), value == Some(true));
    }
}

/// Stable column names for the normalized feature vector.
pub fn schema() -> FeatureSchema {
    let mut b = FeatureBuilder::new_schema();
    encode_into(&dummy_analysis(), &mut b);
    FeatureSchema { columns: b.columns }
}

/// Encode one raw analysis record into a normalized row.
pub fn normalize_tx(tx: &TxAnalysis) -> NormalizedTx {
    let sch = schema();
    let mut b = FeatureBuilder::new_row(sch.columns.len());
    encode_into(tx, &mut b);
    debug_assert_eq!(
        b.values.len(),
        sch.columns.len(),
        "feature vector width drifted from schema"
    );
    NormalizedTx {
        txid: tx.txid.clone(),
        block_height: tx.block_height,
        tx_index: tx.tx_index,
        is_coinbase: tx.is_coinbase,
        x: b.values,
    }
}

fn encode_into(tx: &TxAnalysis, b: &mut FeatureBuilder) {
    let fp = &tx.fingerprints.transaction;
    let h = &tx.heuristics;
    let raw = &tx.rawtx;
    let change = &tx.change;

    b.push_f64("version", raw.version as f64);

    b.push_bool("fp_address_reuse", fp.address_reuse);
    b.push_bool("fp_mixed_input_types", fp.mixed_input_types);
    b.push_bool(
        "fp_nlocktime_optin_without_use",
        fp.nlocktime_optin_without_use,
    );
    b.push_bool(
        "fp_bip68_with_absolute_locktime",
        fp.bip68_with_absolute_locktime,
    );
    b.push_bool("fp_outputs_bip69_sorted", fp.outputs_bip69_sorted);
    b.push_optional_bool_one_hot("fp_round_fee", fp.round_fee);
    b.push_multi_hot("fp_input_order", &fp.input_order);
    b.push_one_hot("fp_output_structure", fp.output_structure);

    b.push_bool(
        "fp_any_low_r_grinding",
        tx.fingerprints.inputs.iter().any(|i| i.low_r_grinding),
    );
    b.push_bool(
        "fp_any_taproot_annex",
        tx.fingerprints.inputs.iter().any(|i| i.has_taproot_annex),
    );
    let schnorr_forms = unique_by(
        tx.fingerprints
            .inputs
            .iter()
            .flat_map(|i| i.schnorr_sighash_forms.iter().copied()),
        |x| x as u8,
    );
    b.push_multi_hot("fp_schnorr_sighash_form", &schnorr_forms);

    b.push_bool("h_equal_amount_outputs", h.equal_amount_outputs);
    b.push_bool("h_likely_coinjoin", h.likely_coinjoin);
    b.push_bool("h_likely_consolidation", h.likely_consolidation);
    b.push_one_hot("h_cpfp", h.cpfp);
    b.push_multi_hot("h_sighash", &h.sighashes);
    let sequence_shapes = unique_by(h.sequence_shapes.iter().copied(), |x| x as u8);
    b.push_multi_hot("h_sequence_shape", &sequence_shapes);
    b.push_one_hot("h_locktime_shape", h.locktime_shape);
    b.push_bool("h_has_uncompressed_pubkey", h.has_uncompressed_pubkey);
    b.push_bool("h_has_multisig", h.has_multisig);
    b.push_bool("h_uih1", h.uih1);
    b.push_bool("h_uih2", h.uih2);

    let prevout_types = unique_by(
        tx.fingerprints.inputs.iter().map(|i| i.input_type),
        |x| x as u8,
    );
    let input_types = unique_by(raw.inputs.iter().map(|i| i.input_type), |x| x as u8);
    let output_types = unique_by(raw.outputs.iter().map(|o| o.output_type), |x| x as u8);
    b.push_multi_hot("prevout_type", &prevout_types);
    b.push_multi_hot("input_type", &input_types);
    b.push_multi_hot("output_type", &output_types);

    b.push_bool(
        "reveals_inscription",
        raw.inputs.iter().any(|i| i.reveals_inscription),
    );

    b.push_bool("change_no_change_apparent", change.no_change_apparent);
    let change_heuristics = unique_by(
        change
            .candidates
            .iter()
            .flat_map(|c| c.heuristics.iter().copied()),
        |x| x as u8,
    );
    b.push_multi_hot("change_heuristic", &change_heuristics);
}

fn unique_by<T: Copy + Eq>(items: impl IntoIterator<Item = T>, key: impl Fn(T) -> u8) -> Vec<T> {
    let mut v: Vec<T> = items.into_iter().collect();
    v.sort_by_key(|x| key(*x));
    v.dedup();
    v
}

/// Minimal placeholder used only while recording schema column names.
fn dummy_analysis() -> TxAnalysis {
    serde_json::from_str(
        r#"{
          "txid":"0",
          "block_height":0,
          "block_hash":"0",
          "tx_index":0,
          "is_coinbase":false,
          "fingerprints":{
            "transaction":{
              "address_reuse":false,"mixed_input_types":false,"input_order":[],
              "nlocktime_optin_without_use":false,"bip68_with_absolute_locktime":false,
              "outputs_bip69_sorted":false,"output_structure":0,"round_fee":null
            },
            "inputs":[]
          },
          "rawtx":{
            "version":2,
            "inputs":[],"outputs":[]
          },
          "heuristics":{
            "equal_amount_outputs":false,"likely_coinjoin":false,"likely_consolidation":false,
            "cpfp":0,"sighashes":[],"sequence_shapes":[],"locktime_shape":0,
            "has_uncompressed_pubkey":false,"multisig_configs":[],"has_multisig":false,
            "uih1":false,"uih2":false
          },
          "change":{
            "candidates":[],"no_change_apparent":true
          }
        }"#,
    )
    .expect("dummy TxAnalysis JSON")
}
