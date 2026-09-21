//! Normalize raw [`TxAnalysis`] NDJSON into a fixed numeric feature matrix.
//!
//! Encoding chosen for fingerprint **distribution / co-occurrence** work:
//! - bools → `0.0` / `1.0`
//! - single categoricals → one-hot over [`Categorical::all`]
//! - set-valued categoricals → multi-hot over the same vocabulary
//! - version kept as a raw float (no z-score yet)
//!
//! Only `block_height` and `is_coinbase` ride along as metadata. Per-tx
//! identifiers (txid, position in block) carry no wallet-fingerprint signal and
//! nothing downstream joins on them, so they are not stored.
//! Aggregates that are linear functions of another block (e.g. "any RBF" vs
//! sequence-shape multi-hot) are omitted.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use super::TxAnalysis;
use super::types::Categorical;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedTx {
    pub block_height: i32,
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
        self.push_bool_lazy(|| name.to_string(), v);
    }

    /// Like [`FeatureBuilder::push_bool`], but the column name is only built
    /// when the schema is being recorded.
    ///
    /// Row encoding discards the name, so a `format!` per feature per row would
    /// be ~120 throwaway allocations for every transaction scanned.
    fn push_bool_lazy(&mut self, name: impl FnOnce() -> String, v: bool) {
        if self.recording_schema {
            self.columns.push(name());
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
            self.push_bool_lazy(
                || format!("{prefix}__{}", variant.label()),
                variant.dense_id() == value.dense_id(),
            );
        }
    }

    fn push_multi_hot<T: Categorical + std::fmt::Display>(&mut self, prefix: &str, values: &[T]) {
        for variant in T::all() {
            self.push_bool_lazy(
                || format!("{prefix}__{}", variant.label()),
                values.iter().any(|v| v == variant),
            );
        }
    }

    fn push_optional_bool_one_hot(&mut self, prefix: &str, value: Option<bool>) {
        self.push_bool_lazy(|| format!("{prefix}__none"), value.is_none());
        self.push_bool_lazy(|| format!("{prefix}__false"), value == Some(false));
        self.push_bool_lazy(|| format!("{prefix}__true"), value == Some(true));
    }
}

/// Stable column names for the normalized feature vector.
pub fn schema() -> FeatureSchema {
    schema_ref().clone()
}

/// Borrowed view of the process-wide schema.
///
/// Building the schema allocates a column name per feature, so hot paths that
/// normalize millions of rows must not call [`schema`] per row.
pub fn schema_ref() -> &'static FeatureSchema {
    static SCHEMA: OnceLock<FeatureSchema> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        let mut b = FeatureBuilder::new_schema();
        encode_into(&dummy_analysis(), &mut b);
        FeatureSchema { columns: b.columns }
    })
}

/// Encode one raw analysis record into a normalized row.
pub fn normalize_tx(tx: &TxAnalysis) -> NormalizedTx {
    let sch = schema_ref();
    let mut b = FeatureBuilder::new_row(sch.columns.len());
    encode_into(tx, &mut b);
    debug_assert_eq!(
        b.values.len(),
        sch.columns.len(),
        "feature vector width drifted from schema"
    );
    NormalizedTx {
        block_height: tx.block_height,
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
///
/// Every field is `Default`, so adding or renaming one is a compile-time
/// concern rather than something that breaks the schema probe at runtime.
fn dummy_analysis() -> TxAnalysis {
    TxAnalysis::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Checked-in column list. Regenerate with:
    /// `cargo run -- schema | jq -r '.columns[]' > src/analysis/schema_columns.txt`
    const GOLDEN: &str = include_str!("schema_columns.txt");

    /// The feature vector's column order is a wire format: every Parquet file
    /// ever written is only interpretable against it. Reordering or renaming a
    /// column silently invalidates historical output, so it has to be a
    /// deliberate, reviewed change to the golden file.
    #[test]
    fn schema_matches_golden() {
        let golden: Vec<&str> = GOLDEN.lines().filter(|l| !l.is_empty()).collect();
        let actual = &schema_ref().columns;

        // Compare position by position so a diff points at the drift, not just
        // at a length mismatch.
        for (i, (want, got)) in golden.iter().zip(actual.iter()).enumerate() {
            assert_eq!(got, want, "column {i} drifted from the golden schema");
        }
        assert_eq!(
            actual.len(),
            golden.len(),
            "feature count changed; review and regenerate schema_columns.txt"
        );
    }

    /// Duplicate names would make a column ambiguous downstream (and Parquet
    /// would happily write both).
    #[test]
    fn schema_columns_are_unique() {
        let cols = &schema_ref().columns;
        let unique: HashSet<&String> = cols.iter().collect();
        assert_eq!(unique.len(), cols.len(), "duplicate feature column name");
    }

    /// A row must line up with the schema it claims to be encoded against.
    #[test]
    fn row_width_matches_schema() {
        let norm = normalize_tx(&TxAnalysis::default());
        assert_eq!(norm.x.len(), schema_ref().columns.len());
    }
}
