# Features

Every column written to the Parquet feature matrix, one row per transaction.
The column order is pinned by `src/analysis/schema_columns.txt` (checked by the
`schema_matches_golden` test); `cargo run -- schema` prints the same list.

## Encoding

Encoding happens in `src/analysis/normalize.rs`:

| Source shape              | Encoding                                                    |
| ------------------------- | ----------------------------------------------------------- |
| bool                      | one `Boolean` column                                        |
| single categorical        | one-hot: one column per variant, `<prefix>__<label>`        |
| set-valued categorical    | multi-hot: one column per variant, set if any input/output/signature has it |
| `Option<bool>`            | three columns: `__none`, `__false`, `__true`                |
| `version`                 | raw integer (`Int32`)                                       |

Per-input values (prevout type, Schnorr sighash form, sequence shape, …) are
collapsed to the set of distinct values seen in the transaction before
multi-hot encoding, so a column means "at least one input has this".

## Metadata

| Column         | Type    | Description                     |
| -------------- | ------- | ------------------------------- |
| `block_height` | Int32   | Height of the confirming block  |
| `is_coinbase`  | Boolean | Transaction is the coinbase     |

Per-tx identifiers (txid, position in block) are not stored.

## Raw transaction

| Column    | Type  | Description                        |
| --------- | ----- | ---------------------------------- |
| `version` | Int32 | Transaction `nVersion` (rawtx-rs)  |

## `fp_*` — wallet fingerprints

Source: `src/analysis/fingerprints.rs`. Transaction-level values come from
[`tx-indexer-fingerprints`](https://github.com/payjoin/tx-indexer/tree/master/src/crates/fingerprints)
(`transaction::*`, `input::*`); the taproot columns are computed locally.

| Column(s) | Encoding | Description |
| --------- | -------- | ----------- |
| `fp_address_reuse` | bool | |
| `fp_mixed_input_types` | bool | |
| `fp_nlocktime_optin_without_use` | bool | |
| `fp_bip68_with_absolute_locktime` | bool | |
| `fp_outputs_bip69_sorted` | bool | |
| `fp_round_fee__{none,false,true}` | `Option<bool>` | |
| `fp_input_order__{single,ascending,descending,bip69,historical,unknown}` | multi-hot | |
| `fp_output_structure__{single,double,multi,unknown}` | one-hot | |
| `fp_any_low_r_grinding` | bool | |
| `fp_any_taproot_annex` | bool | Any taproot (key- or script-path) input whose witness carries a BIP341 annex (last item starts with `0x50`) |
| `fp_schnorr_sighash_form__{default,explicit_all,explicit_other}` | multi-hot | Wire encoding of Schnorr signatures on taproot inputs: `default` = 64-byte sig (implicit `SIGHASH_DEFAULT`), `explicit_all` = 65-byte sig with trailing `0x01`, `explicit_other` = 65-byte sig with any other trailing flag. Key path reads witness item 0; script path reads every stack item before the script and control block. |

## `h_*` — heuristics

Source: `src/analysis/heuristics.rs`. "Payment outputs" below means all
outputs except OP_RETURN.

| Column(s) | Encoding | Description |
| --------- | -------- | ----------- |
| `h_equal_amount_outputs` | bool | ≥2 payment outputs share the exact same value |
| `h_likely_coinjoin` | bool | `h_equal_amount_outputs`, or the rawtx-rs equal-output check: ≥2 inputs and ≥2 outputs, the most common output value appears in ≥⅓ of outputs and more than twice |
| `h_likely_consolidation` | bool | (≥3 inputs and ≤2 payment outputs) or (≥10 inputs and ≤2 outputs) |
| `h_cpfp__{none,parent,child,both}` | one-hot | Same-block spend relation: `parent` = a later tx in the block spends one of its outputs; `child` = it spends an output created earlier in the block; `both` = both |
| `h_sighash__{DEFAULT,ALL,NONE,SINGLE,ALL\|ANYONECANPAY,NONE\|ANYONECANPAY,SINGLE\|ANYONECANPAY,UNKNOWN}` | multi-hot | Sighash flag of every input signature (rawtx-rs). 64-byte Schnorr sigs are mapped to `DEFAULT`; any flag outside the listed values is `UNKNOWN` |
| `h_sequence_shape__{final,locktime_no_rbf,rbf,relative_blocks,relative_time,other}` | multi-hot | Per-input `nSequence`: `final` = `0xffffffff`; `locktime_no_rbf` = `0xfffffffe`; `rbf` = `0xfffffffd`; otherwise bit 31 set → `other`; bit 22 set → `relative_time` (BIP68, 512 s units); else `relative_blocks` (BIP68) |
| `h_locktime_shape__{none,height_exact,height_delta_1,height_delta_2_9,height_delta_10_99,height_delta_100_plus,height_future,timestamp}` | one-hot | `nLockTime` relative to the confirming height *h*: `none` = 0; `timestamp` = ≥ 500,000,000; `height_future` = locktime > *h*; otherwise binned by *h* − locktime: 0, 1, 2–9, 10–99, ≥100 |
| `h_has_uncompressed_pubkey` | bool | Any input or output reveals an uncompressed ECDSA pubkey (tx-indexer `input_with_prevout::has_uncompressed_pubkey`, or rawtx-rs pubkey stats) |
| `h_has_multisig` | bool | Any input has rawtx-rs multisig info, or an input type of `p2ms` / `p2ms_lax_der` |
| `h_uih1` | bool | Gibson UIH1 (eprint 2022/589): smallest payment output < smallest input |
| `h_uih2` | bool | Gibson UIH2: largest input > largest payment output |

## Script types

Multi-hot over the rawtx-rs type of each input/output, deduplicated per
transaction.

| Column prefix | Source | Variants |
| ------------- | ------ | -------- |
| `prevout_type__*` | Output type of each spent prevout | see output type variants below |
| `input_type__*` | rawtx-rs `InputType` of each input | `p2pk`, `p2pk_lax_der`, `p2pkh`, `p2pkh_lax_der`, `p2sh_p2wpkh`, `p2wpkh`, `p2ms`, `p2ms_lax_der`, `p2sh`, `p2sh_p2wsh`, `p2wsh`, `p2tr_keypath`, `p2tr_scriptpath`, `p2a`, `coinbase`, `coinbase_witness`, `unknown` |
| `output_type__*` | rawtx-rs `OutputType` of each output | see below |

Output type variants (shared by `prevout_type__*` and `output_type__*`), with
OP_RETURN flavors flattened into their own variants:
`p2pk`, `p2pkh`, `p2wpkh_v0`, `p2ms`, `p2sh`, `p2wsh_v0`, `p2tr`, `p2a`,
`unknown`, `op_return`, `op_return_witness_commitment`, `op_return_omni`,
`op_return_stacks_block_commit`, `op_return_len_1`, `op_return_len_20`,
`op_return_len_80`, `op_return_bip47`, `op_return_rsk`, `op_return_coredao`,
`op_return_exsat`, `op_return_hathor`, `op_return_runestone`.

## Inscriptions

| Column | Encoding | Description |
| ------ | -------- | ----------- |
| `reveals_inscription` | bool | |

## Signatures

Per-signature values from rawtx-rs, over every signature on every input.

| Column(s) | Encoding | Description |
| --------- | -------- | ----------- |
| `sig_any_high_s` | bool | Any ECDSA signature whose S is above half the curve order. Schnorr signatures are not checked |
| `der_encoding__{not_applicable,valid,sig_too_short,sig_too_long,no_compound_marker,invalid_compound_length,no_s_length,described_length_mismatch,r_not_integer,r_length_zero,negative_r,null_byte_r,s_not_integer,s_length_zero,negative_s,null_byte_s}` | multi-hot | rawtx-rs strict-DER check of each signature. Schnorr signatures report `not_applicable` |

## Fee

| Column | Encoding | Description |
| ------ | -------- | ----------- |
| `fee_rate_round` | bool | Fee is a whole number of sat/vB: fee > 0 and fee % vsize == 0, with vsize = ceil(weight / 4). Always 0 for coinbase |

## `change_*` — change detection

Source: `src/analysis/change.rs`. Coinbase transactions and transactions with
≤1 payment output get no candidates.

| Column(s) | Encoding | Description |
| --------- | -------- | ----------- |
| `change_no_change_apparent` | bool | No payment output was flagged by any of the change heuristics below |
| `change_heuristic__address_reuse` | multi-hot | `fp_address_reuse` is set and a payment output's script matches a prevout script |
| `change_heuristic__optimal_change` | multi-hot | The smallest payment output is smaller than the smallest input |
| `change_heuristic__script_type_match` | multi-hot | All prevouts share one script type and exactly one payment output has that type |
| `change_position__{first,middle,last}` | multi-hot | Position of each change candidate among the payment outputs: `first` = index 0, `last` = final index, `middle` = anything between |

## Collected but not in the matrix

`TxAnalysis` also records these, which are not encoded into Parquet columns:
`block_hash`, per-signature details (signature algorithm, DER encoding,
sighash flag byte, length, low-R, low-S), per-pubkey details, multisig m-of-n
configurations (`multisig_configs`), and change candidate vouts/values.
