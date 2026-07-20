use types/kyc_proof.{KycProof}

/// One entry per unique destination (unique stake-credential among outputs
/// carrying the security token) when minting. Mirrors the transfer-logic
/// destination action: a KYC proof (checked only when
/// `GlobalStateDatum.requires_receiver_kyc`) and a denylist-absence
/// covering-node reference-input index (always checked). CMTAT v3.2.0
/// refuses to mint to a frozen address (core) or to a non-allowlisted one
/// (Allowlist variant); this is the eUTxO equivalent.
pub type MintingLogicDestinationAction {
  destination_proof: KycProof,
  destination_denylist_covering_ref_input_index: Int,
}

/// Withdraw redeemer for the minting_logic_script.
///
/// Under the Track 4 refactor, GS is minted at `initCompliance` (not at
/// register), so GS always exists by the time any security-token mint
/// runs. The earlier `GlobalStateRef` sum type (`GlobalStateInput` for
/// steady-state vs `GlobalStateOutputIndex` for genesis) is gone — every
/// mint now spends the GS UTxO via its input.
pub type MintingLogicScriptWithdrawRedeemer {
  /// Index into `self.inputs` — the GS UTxO being spent in this tx. Its
  /// spend validator runs under `MintSecurity`, which enforces the cap.
  global_state_input_index: Int,
  power_user_node_ref_input_index: Int,
  /// Amount minted (signed: positive for mint, negative for burn).
  minted_amount: Int,
  /// One action per unique destination stake credential among outputs
  /// carrying the security token. Only consulted when `minted_amount > 0`
  /// (burns have no destinations); ordered to match the aggregated
  /// unique-destinations order.
  destination_actions: List<MintingLogicDestinationAction>,
}
