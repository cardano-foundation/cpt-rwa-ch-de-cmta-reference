use aiken/builtin.{head_list, tail_list}
use aiken/collection/dict
use aiken/collection/list
use aiken/collection/pairs
use cardano/address.{Credential, Script}
use cardano/assets.{PolicyId, Value, quantity_of, tokens}
use cardano/transaction.{InlineDatum, Input, Output, Transaction}

/// Consent from a credential that may legitimately be EITHER a key or a
/// script — an admin, a power user, an operator. A key signature and a
/// script's withdraw-0 are equally valid evidence for those.
///
/// Do NOT use this where the credential must be a script that independently
/// re-decides something (i.e. where the point is that specific script's
/// LOGIC runs). A bare signature satisfies this function, so such a check
/// would be satisfiable without the script ever executing. Use
/// `must_run_script_withdrawal` instead — see its doc comment.
pub fn must_be_signed_by_credential(
  transaction: Transaction,
  credential_hash: ByteArray,
) {
  or {
    list.has(transaction.extra_signatories, credential_hash),
    pairs.has_key(transaction.withdrawals, Script(credential_hash)),
  }
}

/// Strictly "this SCRIPT ran and succeeded in this transaction" — the
/// withdraw-0 half of `must_be_signed_by_credential`, with the
/// signature-equivalence deliberately removed.
///
/// A script named as a withdrawal key must be executed and must succeed for
/// the transaction to validate at all (Plutus phase-2 validation is
/// all-or-nothing across every script purpose in a transaction), so presence
/// of the key here really does prove that script's own logic approved this
/// transaction. That is a strictly stronger claim than
/// `must_be_signed_by_credential` makes, and it is the claim required
/// wherever one validator delegates a decision to another.
pub fn must_run_script_withdrawal(
  transaction: Transaction,
  script_hash: ByteArray,
) -> Bool {
  pairs.has_key(transaction.withdrawals, Script(script_hash))
}

pub fn safe_list_at(self: List<a>, index: Int) -> a {
  expect index >= 0
  do_list_at(self, index)
}

fn do_list_at(elems: List<a>, at: Int) -> a {
  if at >= 2 {
    do_list_at(tail_list(tail_list(elems)), at - 2)
  } else {
    head_list(
      if at == 1 {
        tail_list(elems)
      } else {
        elems
      },
    )
  }
}

/// Returns the quantity of all tokens with the policyId
pub fn quantity_of_policy_id(value: Value, policyId: PolicyId) {
  dict.foldl(tokens(value, policyId), 0, fn(_k, v, result) { v + result })
}

/// Rebuild a Constr field list, replacing the element at `index` with
/// `new_value`. Every other field is carried through as opaque `Data` (no unwrap/rewrap).
pub fn replace_data_field(
  fields: List<Data>,
  index: Int,
  new_value: Data,
) -> List<Data> {
  if index == 0 {
    [new_value, ..tail_list(fields)]
  } else {
    [
      head_list(fields),
      ..replace_data_field(tail_list(fields), index - 1, new_value)
    ]
  }
}

/// Bool <-> Plutus Data codec. The 0/1 constructor convention lives here in one
/// place: False = Constr 0 [], True = Constr 1 [].
pub fn data_to_bool(value: Data) -> Bool {
  builtin.unconstr_index(value) == 1
}

pub fn bool_to_data(value: Bool) -> Data {
  if value {
    builtin.constr_data(1, [])
  } else {
    builtin.constr_data(0, [])
  }
}

pub fn get_config_as_data_list(
  config_ref_input: Input,
  config_nft_policy_id: ByteArray,
  config_nft_asset_name: ByteArray,
) {
  expect
    quantity_of(
      config_ref_input.output.value,
      config_nft_policy_id,
      config_nft_asset_name,
    ) > 0
  expect InlineDatum(output_datum) = config_ref_input.output.datum
  builtin.unconstr_fields(output_datum)
}

pub fn expect_inline_datum(output: Output) -> Data {
  expect InlineDatum(d) = output.datum
  d
}

pub fn derive_issuance_policy_id_from_registry_node(
  ref_inputs: List<Input>,
  registry_policy_id: ByteArray,
  credential: Credential,
  // The index of the registry node field which is taken into account for checking the correctnes of the registry node
  // and extracting the hashed params which are used to derive the issuance policy id
  registry_node_field_index: Int,
  // Index into `ref_inputs` naming the registry node for THIS token.
  registry_node_ref_input_index: Int,
) -> PolicyId {
  // The node is addressed BY INDEX rather than located by search. Searching on
  // the registry policy alone returns the FIRST matching reference input, but
  // every CIP-113 programmable token's node carries that same policy — so a
  // transaction touching a second programmable token resolves whichever node
  // sorts first and then traps on the identity assertion below. Reference
  // inputs are ledger-sorted by output reference, so off-chain cannot reorder
  // its way out of it; the caller must say which node is theirs.
  //
  // A caller-supplied index grants no privilege: `has_any_nft_strict` still
  // requires a genuine single-NFT registry-node UTxO, and the identity
  // assertion still requires that node to name THIS script at the field index.
  // CIP-113 derives the issuance policy id from the minting-logic hash and the
  // linked list keys nodes by that policy id, so at most one node can ever
  // satisfy both. A wrong index only ever traps.
  let registry_ref_input = safe_list_at(
    ref_inputs,
    registry_node_ref_input_index,
  )
  derive_issuance_policy_id_from_registry_node_output(
    registry_ref_input.output,
    registry_policy_id,
    credential,
    registry_node_field_index,
  )
}

/// Same derivation, against a registry node given directly as an `Output`.
///
/// Steady-state callers reach the node through `reference_inputs` (use the
/// wrapper above). At CIP-113 registration time, though, the node does not
/// exist as a spendable UTxO yet — it is an OUTPUT of the very transaction
/// creating it — so a caller that must resolve the issuance policy during a
/// registry insert has to read it from `self.outputs` instead.
///
/// That is not a weaker source. `has_any_nft_strict` still requires a genuine
/// registry NFT, and a registry NFT can only enter an output by being minted
/// (`registry_mint` runs and enforces CIP-113's cryptographic `key` ↔
/// `minting_logic_script` binding) or by being carried forward from an
/// existing node (`registry_spend` runs and enforces its own rules). Combined
/// with the identity assertion below, a node output claiming to belong to
/// `credential` cannot lie about which policy id it keys.
pub fn derive_issuance_policy_id_from_registry_node_output(
  node_output: Output,
  registry_policy_id: ByteArray,
  credential: Credential,
  // The index of the registry node field which is taken into account for checking the correctnes of the registry node
  // and extracting the hashed params which are used to derive the issuance policy id
  registry_node_field_index: Int,
) -> PolicyId {
  expect Script(hashed_params) = credential
  expect assets.has_any_nft_strict(node_output.value, registry_policy_id)
  let registry_raw: Data = expect_inline_datum(node_output)
  let registry_fields: List<Data> = builtin.unconstr_fields(registry_raw)
  // The indexed registry field holds the script `Credential` of the logic
  // running this withdraw-0 (e.g. CIP-113's `minting_logic_script` /
  // `transfer_logic_script` / `third_party_transfer_logic_script`). Decode it as
  // a `Credential` and pull out the script hash to compare with the redeemer.
  expect Some(reg_credential_data) = list.at(
    registry_fields,
    registry_node_field_index,
  )
  expect reg_credential: Credential = reg_credential_data
  expect Script(reg_hashed_params) = reg_credential
  // Checking if the hashed params in the registry match the hashed params provided in the redeemer
  // Which if it's the case the key of the node_registry is the issuance_policy_id
  expect reg_hashed_params == hashed_params
  builtin.un_b_data(builtin.head_list(registry_fields))
}
