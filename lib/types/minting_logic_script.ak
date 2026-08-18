/// Withdraw redeemer for minting_logic_script.ak — the permanent,
/// CIP-113-registered PROXY.
///
/// The proxy makes exactly one decision: "is the minting authority that
/// GlobalState currently names running in this transaction?" It therefore
/// needs exactly one thing from the caller — where to find GlobalState. Every
/// other decision, and so every other redeemer field, belongs to the
/// authority (see types/minting_authority.ak).
///
/// The two constructors exist only because a UTxO cannot be both spent and
/// referenced: a mint or burn must SPEND GlobalState (so its `MintSecurity`
/// branch runs and enforces the supply cap), while a structural registration
/// merely REFERENCES it. The proxy does not care which of those is happening
/// — it just needs to read the datum — so it accepts either and leaves the
/// "was the right one used for this operation?" judgement to the authority.
pub type MintingLogicScriptWithdrawRedeemer {
  /// Index into `self.inputs`.
  GlobalStateSpent { global_state_input_index: Int }
  /// Index into `self.reference_inputs`.
  GlobalStateReferenced { global_state_ref_input_index: Int }
}
