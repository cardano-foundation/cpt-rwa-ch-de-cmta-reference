use aiken/builtin
use aiken/collection/dict
use aiken/collection/list
use aiken/interval.{Interval, IntervalBound, NegativeInfinity, PositiveInfinity}
use aiken/primitive/bytearray
use aiken_design_patterns/linked_list.{
  Element, Node, Root, get_element_info, run_element_with,
}
use cardano/address.{Address, Credential, Inline, Script, VerificationKey}
use cardano/assets.{from_asset, from_lovelace, merge, quantity_of}
use cardano/certificate.{Certificate, RegisterCredential}
use cardano/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, Transaction,
}
use constants
use denylist/absence.{verify_denylist_absence}
use kyc/verify.{verify_kyc_proof}
use types/global_state.{GlobalStateDatum}
use types/kyc_proof.{Attestation, AttestationProof}
use types/minting_logic_script.{
  MintingLogicDestinationAction, MintingLogicScriptWithdrawRedeemer,
}
use types/power_users.{PowerUser}
use utils.{must_be_signed_by_credential}

validator minting_logic_validator(
  security_asset_name: ByteArray,
  global_state_policy_id: ByteArray,
  registry_policy_id: ByteArray,
  power_users_linked_list_policy_id: ByteArray,
) {
  withdraw(
    redeemer: MintingLogicScriptWithdrawRedeemer,
    credential: Credential,
    self: Transaction,
  ) {
    let issuance_policy_id = utils.derive_issuance_policy_id_from_registry_node(
      self.reference_inputs,
      registry_policy_id,
      credential,
      constants.minting_logic_script_registry_node_index,
    )

    let minted_amount = quantity_of(
      self.mint,
      issuance_policy_id,
      security_asset_name,
    )

    // GS is always spent during a mint under the Track 4 design (GS minted at
    // initCompliance; register spends-and-updates it via the MintSecurity
    // branch, which enforces the supply cap). This validator only needs to
    // assert the GS NFT is actually on the referenced input — NFT presence on
    // an input implies the GS spend validator is running; by the non-Mint-
    // branches-reject-mint invariant in global_state.ak, only the MintSecurity
    // branch permits a security-token mint — and it decrements `mintable_amount`.
    let gs_input = utils.safe_list_at(
      self.inputs,
      redeemer.global_state_input_index,
    )
    expect
      quantity_of(
        gs_input.output.value,
        global_state_policy_id,
        constants.global_state_asset_name,
      ) == 1

    let power_user_ref_input = utils.safe_list_at(
      self.reference_inputs,
      redeemer.power_user_node_ref_input_index,
    )

    let (power_user_node_key, power_user_data) = get_element_info(
      power_user_ref_input.output,
      fn(_lovelace, node_key, data, _link) {
        expect Some(key) = node_key
        expect power_user_data: PowerUser = data
        (key, power_user_data)
      },
    )
      |> run_element_with(
          power_users_linked_list_policy_id,
          constants.linked_list_root_key,
          constants.linked_list_node_key_prefix,
          constants.linked_list_node_key_prefix_length,
        )

    // Destination verification (mirrors transfer_logic_script's per-output
    // gate): CMTAT v3.2.0 refuses to mint to a frozen address (core) and to
    // a non-allowlisted receiver (Allowlist variant). When minting, every
    // unique destination stake credential among outputs carrying the
    // security token needs a denylist-absence covering proof, plus — when
    // GS.requires_receiver_kyc — a KYC check that passes if EITHER a valid
    // KYC proof is presented OR the receiver is the power user authorising
    // this mint (`power_user_node_key`, already resolved above; it holds
    // `can_mint` and signed the tx). This lets a minter mint to their own
    // (list-authenticated) credential without a separate KYC attestation.
    // Burns have no destinations — the holder side is vetted by the CIP-113
    // spend path.
    let destinations_ok = if minted_amount > 0 {
      expect InlineDatum(gs_datum_raw) = gs_input.output.datum
      expect gs_datum: GlobalStateDatum = gs_datum_raw
      let outputs_user_stake_cred_hash = list.unique(
        list.foldr(
          self.outputs,
          [],
          fn(output, result) {
            if quantity_of(
              output.value,
              issuance_policy_id,
              security_asset_name,
            ) > 0 {
              expect Some(Inline(stake_cred)) = output.address.stake_credential
              let credential_hash = when stake_cred is {
                VerificationKey(hash) -> hash
                Script(hash) -> hash
              }
              list.push(result, credential_hash)
            } else {
              result
            }
          },
        ),
      )
      list.indexed_foldr(
        outputs_user_stake_cred_hash,
        True,
        fn(index, dest_pkh, acc) {
          expect acc
          let action = utils.safe_list_at(redeemer.destination_actions, index)
          let kyc_ok = if gs_datum.requires_receiver_kyc {
            or {
              // The receiver is the power user authorising this mint.
              dest_pkh == power_user_node_key,
              // …or a valid KYC proof is presented for the receiver.
              verify_kyc_proof(
                action.destination_proof,
                dest_pkh,
                gs_datum,
                issuance_policy_id,
                gs_datum.network_id,
                self,
              ),
            }
          } else {
            True
          }
          let denylist_ok = verify_denylist_absence(
            dest_pkh,
            action.destination_denylist_covering_ref_input_index,
            self.reference_inputs,
            gs_datum.denylist_linked_list_policy_id,
          )
          and {
            kyc_ok,
            denylist_ok,
          }
        },
      )
    } else {
      True
    }

    and {
      //Redeemer contains the amount just for easy reference for eventual other contracts
      (minted_amount == redeemer.minted_amount)?,
      //A power user must have signed the transaction
      must_be_signed_by_credential(self, power_user_node_key)?,
      //If minted_amount > 0, power user must be minter
      //If minted_amount < 0, power user must be burner
      if minted_amount > 0 {
        power_user_data.can_mint
      } else {
        power_user_data.can_burn
      }?,
      //Mint destinations must be vetted (denylist absence + optional KYC)
      destinations_ok?,
    }
  }

  // Whitelist RegisterCredential only. Rejecting UnregisterCredential prevents
  // a ~2 ADA griefing DoS: a rubber-stamp publish would allow anyone to
  // de-register this script's stake credential, which would brick every
  // withdraw-zero mint/burn until re-registered. Also rejects delegation and
  // DRep/committee cert types — this credential exists solely for withdraw-0.
  // Tradeoff: the stake credential becomes permanent (2 ADA locked forever).
  publish(_r: Data, c: Certificate, _s: Transaction) {
    when c is {
      RegisterCredential { .. } -> True
      _ -> False
    }
  }

  else(_) {
    fail
  }
}

// ============================================================================
// Tests — withdraw handler (validator-level)
// ============================================================================
//
// Fixtures follow the aiken-design-patterns linked-list conventions verified
// against the vendored library: an element UTxO carries exactly ADA + one
// list NFT, an inline `Element` datum, and no reference script. The root's
// NFT asset name equals the root key (empty), a node's equals
// "Node" ++ key. The denylist-absence fixtures exercise the real
// covering-node proof through `verify_denylist_absence`.

const test_security_asset_name: ByteArray = "SEC"

const test_gs_policy_id: ByteArray =
  #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

const test_pu_policy_id: ByteArray =
  #"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

const test_registry_policy_id: ByteArray =
  #"cccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

const test_denylist_policy_id: ByteArray =
  #"dddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

// Registry node `key` == the issuance policy id the mint must use.
const test_issuance_policy_id: ByteArray =
  #"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

const test_minting_logic_hash: ByteArray =
  #"f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1"

const test_transfer_logic_hash: ByteArray =
  #"f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2"

const test_third_party_logic_hash: ByteArray =
  #"f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3"

const test_pu_credential_hash: ByteArray =
  #"01010101010101010101010101010101010101010101010101010101"

const test_dest_stake_hash: ByteArray =
  #"02020202020202020202020202020202020202020202020202020202"

// A second, distinct destination — must sort strictly above the first so the
// empty-denylist root covers both, and so the two are aggregated as separate
// unique destinations (exercising destination_actions index 1).
const test_dest_stake_hash_2: ByteArray =
  #"04040404040404040404040404040404040404040404040404040404"

const test_dest_payment_hash: ByteArray =
  #"03030303030303030303030303030303030303030303030303030303"

// Faithful mirror of the CIP-113 registry node layout (field order is
// load-bearing: minting=2, transfer=3, third-party=4).
type TestRegistryNode {
  key: ByteArray,
  next: ByteArray,
  minting_logic_script: Credential,
  transfer_logic_script: Credential,
  third_party_transfer_logic_script: Credential,
  global_state_cs: ByteArray,
}

fn test_out_ref(ix: Int) -> OutputReference {
  OutputReference {
    transaction_id: #"0000000000000000000000000000000000000000000000000000000000000000",
    output_index: ix,
  }
}

// GS input — NFT presence gates the cap path; the datum now also feeds the
// destination checks (denylist policy id, receiver-KYC toggle, network id).
fn make_gs_input(requires_receiver_kyc: Bool) -> Input {
  let gs_datum = GlobalStateDatum {
    transfers_paused: False,
    deactivated: False,
    mintable_amount: 1_000_000,
    admin_credential_hash: #"",
    power_user_linked_list_policy_id: test_pu_policy_id,
    denylist_linked_list_policy_id: test_denylist_policy_id,
    security_info: builtin.constr_data(0, []),
    trusted_entity_vkeys: [],
    member_root_hash: #"",
    requires_sender_kyc: False,
    requires_receiver_kyc,
    network_id: 1,
  }
  Input {
    output_reference: test_out_ref(0),
    output: Output {
      address: Address {
        payment_credential: Script(test_gs_policy_id),
        stake_credential: None,
      },
      value: merge(
        from_lovelace(2_000_000),
        from_asset(test_gs_policy_id, constants.global_state_asset_name, 1),
      ),
      datum: InlineDatum(gs_datum),
      reference_script: None,
    },
  }
}

// Power-user linked-list node: asset name = "Node" ++ credential_hash, datum
// wraps a PowerUser as Node data.
fn make_pu_node_ref_input(can_mint: Bool, can_burn: Bool) -> Input {
  let pu = PowerUser {
    credential_hash: test_pu_credential_hash,
    is_admin: False,
    can_mint,
    can_burn,
    can_pause: False,
    can_force_transfer: False,
  }
  let element: Element<Data, PowerUser> = Element {
    data: Node { data: pu },
    link: None,
  }
  let node_asset_name = bytearray.concat(
    constants.linked_list_node_key_prefix,
    test_pu_credential_hash,
  )
  Input {
    output_reference: test_out_ref(1),
    output: Output {
      address: Address {
        payment_credential: Script(test_pu_policy_id),
        stake_credential: None,
      },
      value: merge(
        from_lovelace(2_000_000),
        from_asset(test_pu_policy_id, node_asset_name, 1),
      ),
      datum: InlineDatum(element),
      reference_script: None,
    },
  }
}

// CIP-113 registry node ref input: exactly one registry NFT so
// `has_any_nft_strict` locates it; field 2 must equal the withdraw credential.
fn make_registry_ref_input() -> Input {
  let node = TestRegistryNode {
    key: test_issuance_policy_id,
    next: #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    minting_logic_script: Script(test_minting_logic_hash),
    transfer_logic_script: Script(test_transfer_logic_hash),
    third_party_transfer_logic_script: Script(test_third_party_logic_hash),
    global_state_cs: test_gs_policy_id,
  }
  Input {
    output_reference: test_out_ref(2),
    output: Output {
      address: Address {
        payment_credential: Script(test_registry_policy_id),
        stake_credential: None,
      },
      value: merge(
        from_lovelace(2_000_000),
        from_asset(test_registry_policy_id, "Node", 1),
      ),
      datum: InlineDatum(node),
      reference_script: None,
    },
  }
}

// Denylist ROOT element with an empty list (`link: None`) — the root covers
// every possible key, so it is a valid absence proof for any target.
fn make_denylist_root_ref_input() -> Input {
  let root_info: Data = builtin.constr_data(0, [])
  let element: Element<Data, Data> = Element {
    data: Root { data: root_info },
    link: None,
  }
  Input {
    output_reference: test_out_ref(3),
    output: Output {
      address: Address {
        payment_credential: Script(test_denylist_policy_id),
        stake_credential: None,
      },
      value: merge(
        from_lovelace(2_000_000),
        from_asset(test_denylist_policy_id, constants.linked_list_root_key, 1),
      ),
      datum: InlineDatum(element),
      reference_script: None,
    },
  }
}

// Denylist NODE keyed exactly at `pkh` — the target IS denylisted, so this
// node cannot witness its absence (covers_from_below: key < target is
// false when key == target). Models the "destination is sanctioned" case.
fn make_denylist_node_ref_input(pkh: ByteArray) -> Input {
  let node_info: Data = builtin.constr_data(0, [])
  let element: Element<Data, Data> = Element {
    data: Node { data: node_info },
    link: None,
  }
  let node_asset_name = bytearray.concat(
    constants.linked_list_node_key_prefix,
    pkh,
  )
  Input {
    output_reference: test_out_ref(3),
    output: Output {
      address: Address {
        payment_credential: Script(test_denylist_policy_id),
        stake_credential: None,
      },
      value: merge(
        from_lovelace(2_000_000),
        from_asset(test_denylist_policy_id, node_asset_name, 1),
      ),
      datum: InlineDatum(element),
      reference_script: None,
    },
  }
}

// Mint destination: a base address whose stake credential is the identity
// the destination checks must vet.
fn make_dest_output(amount: Int) -> Output {
  make_dest_output_for(amount, test_dest_stake_hash)
}

// Same, but parameterised on the destination stake credential — used to build
// a mint with two distinct destinations.
fn make_dest_output_for(amount: Int, stake_hash: ByteArray) -> Output {
  Output {
    address: Address {
      payment_credential: VerificationKey(test_dest_payment_hash),
      stake_credential: Some(Inline(VerificationKey(stake_hash))),
    },
    value: merge(
      from_lovelace(2_000_000),
      from_asset(test_issuance_policy_id, test_security_asset_name, amount),
    ),
    datum: NoDatum,
    reference_script: None,
  }
}

// Reference-input order: 0 = power-user node, 1 = registry node,
// 2 = denylist covering node (the index the destination actions cite).
fn make_withdraw_tx(
  minted_amount: Int,
  can_mint: Bool,
  can_burn: Bool,
  requires_receiver_kyc: Bool,
  denylist_ref: Input,
  outputs: List<Output>,
  signatories: List<ByteArray>,
) -> Transaction {
  Transaction {
    inputs: [make_gs_input(requires_receiver_kyc)],
    reference_inputs: [
      make_pu_node_ref_input(can_mint, can_burn),
      make_registry_ref_input(),
      denylist_ref,
    ],
    outputs,
    fee: 0,
    mint: from_asset(
      test_issuance_policy_id,
      test_security_asset_name,
      minted_amount,
    ),
    certificates: [],
    withdrawals: [],
    validity_range: Interval {
      lower_bound: IntervalBound {
        bound_type: NegativeInfinity,
        is_inclusive: True,
      },
      upper_bound: IntervalBound {
        bound_type: PositiveInfinity,
        is_inclusive: False,
      },
    },
    extra_signatories: signatories,
    redeemers: [],
    datums: dict.empty,
    id: #"0000000000000000000000000000000000000000000000000000000000000000",
    votes: [],
    proposal_procedures: [],
    current_treasury_amount: None,
    treasury_donation: None,
  }
}

// Structurally invalid KYC proof — only reachable when receiver KYC is
// required, where it must make the destination check fail.
fn dummy_proof() {
  Attestation {
    kyc_proof: AttestationProof {
      payload: #"",
      signature: #"",
      issuer_vkey: #"",
    },
  }
}

fn clean_dest_action() -> MintingLogicDestinationAction {
  MintingLogicDestinationAction {
    destination_proof: dummy_proof(),
    destination_denylist_covering_ref_input_index: 2,
  }
}

fn run_withdraw(redeemer: MintingLogicScriptWithdrawRedeemer, tx: Transaction) {
  minting_logic_validator.withdraw(
    test_security_asset_name,
    test_gs_policy_id,
    test_registry_policy_id,
    test_pu_policy_id,
    redeemer,
    Script(test_minting_logic_hash),
    tx,
  )
}

// ── destination verification ─────────────────────────────────────────────────

test mint_succeeds_with_clean_destination_no_receiver_kyc() {
  let amount = 1_000
  let redeemer = MintingLogicScriptWithdrawRedeemer {
    global_state_input_index: 0,
    power_user_node_ref_input_index: 0,
    minted_amount: amount,
    destination_actions: [clean_dest_action()],
  }
  run_withdraw(
    redeemer,
    make_withdraw_tx(
      amount,
      True,
      False,
      False,
      make_denylist_root_ref_input(),
      [make_dest_output(amount)],
      [test_pu_credential_hash],
    ),
  )
}

test mint_fails_when_destination_denylisted() {
  // The provided covering node is keyed exactly at the destination — i.e.
  // the destination IS in the denylist, so no absence proof exists for it.
  let amount = 1_000
  let redeemer = MintingLogicScriptWithdrawRedeemer {
    global_state_input_index: 0,
    power_user_node_ref_input_index: 0,
    minted_amount: amount,
    destination_actions: [clean_dest_action()],
  }
  !run_withdraw(
    redeemer,
    make_withdraw_tx(
      amount,
      True,
      False,
      False,
      make_denylist_node_ref_input(test_dest_stake_hash),
      [make_dest_output(amount)],
      [test_pu_credential_hash],
    ),
  )
}

test mint_succeeds_with_two_clean_destinations() {
  // Two distinct destinations in one mint. Both are absent from the (empty)
  // denylist, so both need a covering proof at ref index 2. This exercises
  // destination_actions index 0 AND index 1 — a short action list or an
  // index-mapping regression would trap on the second destination.
  let amount = 1_000
  let redeemer = MintingLogicScriptWithdrawRedeemer {
    global_state_input_index: 0,
    power_user_node_ref_input_index: 0,
    minted_amount: amount,
    destination_actions: [clean_dest_action(), clean_dest_action()],
  }
  run_withdraw(
    redeemer,
    make_withdraw_tx(
      amount,
      True,
      False,
      False,
      make_denylist_root_ref_input(),
      [
        make_dest_output_for(amount, test_dest_stake_hash),
        make_dest_output_for(amount, test_dest_stake_hash_2),
      ],
      [test_pu_credential_hash],
    ),
  )
}

test mint_fails_when_receiver_kyc_required_but_proof_invalid() {
  let amount = 1_000
  let redeemer = MintingLogicScriptWithdrawRedeemer {
    global_state_input_index: 0,
    power_user_node_ref_input_index: 0,
    minted_amount: amount,
    destination_actions: [clean_dest_action()],
  }
  !run_withdraw(
    redeemer,
    make_withdraw_tx(
      amount,
      True,
      False,
      True,
      make_denylist_root_ref_input(),
      [make_dest_output(amount)],
      [test_pu_credential_hash],
    ),
  )
}

test mint_to_authorizing_power_user_bypasses_receiver_kyc() {
  // requires_receiver_kyc = true and only an invalid (dummy) KYC proof is
  // supplied — but the sole destination IS the power user authorizing this
  // mint (dest stake credential == test_pu_credential_hash). The receiver
  // check must pass via the power-user exemption, not via KYC.
  let amount = 1_000
  let redeemer = MintingLogicScriptWithdrawRedeemer {
    global_state_input_index: 0,
    power_user_node_ref_input_index: 0,
    minted_amount: amount,
    destination_actions: [clean_dest_action()],
  }
  run_withdraw(
    redeemer,
    make_withdraw_tx(
      amount,
      True,
      False,
      True,
      make_denylist_root_ref_input(),
      [make_dest_output_for(amount, test_pu_credential_hash)],
      [test_pu_credential_hash],
    ),
  )
}

test mint_fails_when_destination_action_missing() fail {
  // A destination exists but no matching action was supplied — indexing the
  // empty action list must trap.
  let amount = 1_000
  let redeemer = MintingLogicScriptWithdrawRedeemer {
    global_state_input_index: 0,
    power_user_node_ref_input_index: 0,
    minted_amount: amount,
    destination_actions: [],
  }
  run_withdraw(
    redeemer,
    make_withdraw_tx(
      amount,
      True,
      False,
      False,
      make_denylist_root_ref_input(),
      [make_dest_output(amount)],
      [test_pu_credential_hash],
    ),
  )
}

test burn_succeeds_without_destination_checks() {
  let amount = -1_000
  let redeemer = MintingLogicScriptWithdrawRedeemer {
    global_state_input_index: 0,
    power_user_node_ref_input_index: 0,
    minted_amount: amount,
    destination_actions: [],
  }
  run_withdraw(
    redeemer,
    make_withdraw_tx(
      amount,
      False,
      True,
      False,
      make_denylist_root_ref_input(),
      [],
      [test_pu_credential_hash],
    ),
  )
}

// ── pre-existing behavior pins ───────────────────────────────────────────────

test withdraw_fails_when_not_signed_by_power_user() {
  let amount = 1_000
  let redeemer = MintingLogicScriptWithdrawRedeemer {
    global_state_input_index: 0,
    power_user_node_ref_input_index: 0,
    minted_amount: amount,
    destination_actions: [clean_dest_action()],
  }
  !run_withdraw(
    redeemer,
    make_withdraw_tx(
      amount,
      True,
      False,
      False,
      make_denylist_root_ref_input(),
      [make_dest_output(amount)],
      [],
    ),
  )
}

test withdraw_fails_when_minting_without_mint_permission() {
  let amount = 1_000
  let redeemer = MintingLogicScriptWithdrawRedeemer {
    global_state_input_index: 0,
    power_user_node_ref_input_index: 0,
    minted_amount: amount,
    destination_actions: [clean_dest_action()],
  }
  !run_withdraw(
    redeemer,
    make_withdraw_tx(
      amount,
      False,
      True,
      False,
      make_denylist_root_ref_input(),
      [make_dest_output(amount)],
      [test_pu_credential_hash],
    ),
  )
}
