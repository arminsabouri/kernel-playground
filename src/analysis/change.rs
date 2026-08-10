//! Change-output assignment heuristics.
//!
//! Several weak signals are combined. When none fire, `no_change_apparent` is set —
//! useful later for distribution stats of "payment-only" shaped transactions.

use bitcoin::{Transaction, TxOut};
use serde::Serialize;

use super::fingerprints::FingerprintFeatures;
use super::types::{ChangeHeuristic, RawOutputType};

#[derive(Debug, Serialize)]
pub struct ChangeCandidate {
    pub vout: usize,
    pub value_sat: u64,
    pub heuristics: Vec<ChangeHeuristic>,
}

#[derive(Debug, Serialize)]
pub struct ChangeAnalysis {
    /// Best-effort change vouts. Empty when nothing looks like change.
    pub candidates: Vec<ChangeCandidate>,
    /// True when we could not assign change with any of the heuristics below.
    pub no_change_apparent: bool,
    pub address_reuse: bool,
    pub uih1_optimal_change: bool,
}

pub fn analyze(
    tx: &Transaction,
    prevouts: &[TxOut],
    fingerprints: &FingerprintFeatures,
) -> ChangeAnalysis {
    if tx.is_coinbase() {
        return ChangeAnalysis {
            candidates: Vec::new(),
            no_change_apparent: true,
            address_reuse: false,
            uih1_optimal_change: false,
        };
    }

    let payment: Vec<(usize, &TxOut)> = tx
        .output
        .iter()
        .enumerate()
        .filter(|(_, o)| !o.script_pubkey.is_op_return())
        .collect();

    // Single payment output → typically no change (or all value is change to self; we can't tell).
    if payment.len() <= 1 {
        return ChangeAnalysis {
            candidates: Vec::new(),
            no_change_apparent: true,
            address_reuse: fingerprints.transaction.address_reuse,
            uih1_optimal_change: false,
        };
    }

    let mut scores: Vec<(usize, Vec<ChangeHeuristic>)> =
        payment.iter().map(|(i, _)| (*i, Vec::new())).collect();

    let address_reuse = fingerprints.transaction.address_reuse;
    if address_reuse {
        let input_scripts: std::collections::HashSet<Vec<u8>> = prevouts
            .iter()
            .map(|p| p.script_pubkey.as_bytes().to_vec())
            .collect();
        for (vout, out) in &payment {
            if input_scripts.contains(out.script_pubkey.as_bytes()) {
                push_heuristic(&mut scores, *vout, ChangeHeuristic::AddressReuse);
            }
        }
    }

    let uih1_optimal_change = if let Some(min_in) = prevouts.iter().map(|p| p.value).min() {
        if let Some((vout, out)) = payment.iter().min_by_key(|(_, o)| o.value) {
            if out.value < min_in {
                push_heuristic(&mut scores, *vout, ChangeHeuristic::OptimalChange);
                true
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };

    // Homogeneous input script type → matching unique output may be change.
    let input_types: Vec<RawOutputType> = fingerprints.inputs.iter().map(|i| i.input_type).collect();
    if !input_types.is_empty() && input_types.iter().all(|t| *t == input_types[0]) {
        let itype = input_types[0];
        let matching: Vec<usize> = payment
            .iter()
            .filter(|(_, o)| RawOutputType::from_txout(o) == itype)
            .map(|(i, _)| *i)
            .collect();
        if matching.len() == 1 {
            push_heuristic(&mut scores, matching[0], ChangeHeuristic::ScriptTypeMatch);
        }
    }

    let mut candidates: Vec<ChangeCandidate> = scores
        .into_iter()
        .filter(|(_, hs)| !hs.is_empty())
        .map(|(vout, heuristics)| ChangeCandidate {
            vout,
            value_sat: tx.output[vout].value.to_sat(),
            heuristics,
        })
        .collect();
    candidates.sort_by_key(|c| c.vout);

    let no_change_apparent = candidates.is_empty();

    ChangeAnalysis {
        candidates,
        no_change_apparent,
        address_reuse,
        uih1_optimal_change,
    }
}

fn push_heuristic(
    scores: &mut [(usize, Vec<ChangeHeuristic>)],
    vout: usize,
    heuristic: ChangeHeuristic,
) {
    if let Some((_, hs)) = scores.iter_mut().find(|(i, _)| *i == vout) {
        if !hs.contains(&heuristic) {
            hs.push(heuristic);
        }
    }
}
