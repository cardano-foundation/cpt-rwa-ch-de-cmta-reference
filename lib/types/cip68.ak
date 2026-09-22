/// The datum a CIP-68 reference token carries.
///
/// CIP-68 defines it as `#6.121([metadata, version, extra_plutus_data])` — a
/// `Constr` with tag 0 and exactly three fields. Decoding a datum as this type
/// is what "correctly shaped" means for `cip68.output_is_well_formed`: the
/// constructor, the field count and the first two field TYPES are all checked.
///
/// The contents are deliberately not inspected. `metadata` is issuer-defined,
/// `extra` is reserved by the standard for future use, and this deployment
/// makes no claim about either — the register lives on chain in GlobalState,
/// not in the token's metadata.
pub type Cip68Datum {
  /// Issuer-defined metadata map. CBOR map; contents not interpreted here.
  metadata: Pairs<Data, Data>,
  /// CIP-68 datum version. Not pinned to a value: a future version must be
  /// able to ship without a redeploy of this module.
  version: Int,
  /// Reserved by CIP-68 for future extension.
  extra: Data,
}
