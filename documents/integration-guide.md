# Practical integration guide

This guide is for a transaction builder integrating the validators in this repository with a
deployed CIP-113 programmable-token base layer. The [README](../README.md) explains the protocol
and lists the exact script parameter order. The base layer supplies token custody, registry
transactions and owner authorisation; its transaction builder and redeemers depend on the deployed
base-layer version. The examples below describe **this repository's** witnesses and data. They are
Aiken-shaped sketches, not a ready-to-submit SDK or CLI implementation.

## Before building transactions

1. Build and apply every validator's parameters in [README: Parameter order](../README.md#parameter-order).
   Record the applied script hashes, the issuance policy ID, the selected `security_asset_name`,
   the CIP-113 registry policy ID and the deployed base-layer commit. Keep list **policy IDs**
   distinct from list **spend validator hashes**.
2. Select three spendable one-shot inputs: one for GlobalState, one for the power-users root and
   one for the denylist root. The list mint validators' `init_input_out_ref` values and the
   GlobalState mint validator's `tx0`/`index0` must match the inputs actually spent at genesis.
3. Choose the admin credential, initial minting authority script hash, cap, network ID and KYC
   settings. The initial datum must have `transfers_paused = False`, `deactivated = False`,
   `upgrades_locked = False`, a non-negative `mintable_amount`, a 28-byte admin hash, a 28-byte
   authority hash, a network ID from 0 to 255 and an empty or 32-byte `member_root_hash`.
   Trusted-entity vkeys are 32 bytes, sorted and unique. See
   [`GlobalStateDatum`](../lib/types/global_state.ak) and the genesis checks in
   [`global_state.ak`](../validators/global_state.ak).
4. Publish large applied scripts as reference scripts and keep their reference UTxOs available to
   the builder. Register every withdraw-0 script's stake credential before a transaction invokes
   it; see [README: Deployment](../README.md#deployment-reference-scripts).

All `*_index` fields below are **zero-based positions in the final transaction**, after coin
selection and output ordering. Recompute them after a builder inserts change outputs, collateral,
reference inputs or other witnesses. In particular, an index into `inputs` is not an index into
`reference_inputs`; GlobalState must never appear in both lists in one transaction.

## Bootstrap a token

### 1. Mint GlobalState and both list roots together

Spend the three reserved inputs in **one transaction**. Mint exactly one GlobalState NFT under
`global_state.global_state_mint_validator` and initialise both linked lists with the `Init` mint
redeemer from their respective [`MintRedeemer` types](../lib/types/power_users.ak) and
[`denylist` type](../lib/types/denylist.ak). Each `Init { root_output_index }` points to its own
root output. The GlobalState mint validator checks that both root policies mint in this same
transaction; a later transaction for either root is rejected.

Output the GlobalState NFT with an inline `GlobalStateDatum` at
`global_state.global_state_spend_validator`. Output each root at its corresponding list spend
validator address. The three mint validators cannot verify those destination addresses at
genesis, so compare the applied hashes and output addresses **before signing**. Also assert that
the two list policy IDs are distinct and equal the compiled list mint hashes. The datum's
`minting_script_credential_hash` must identify the intended current minting authority, not the
permanent proxy.

### 2. Register the four withdrawal credentials

Register the applied stake credentials for `minting_logic_validator` (proxy),
`minting_authority_validator`, `transfer_logic_validator` and
`third_party_transfer_logic_validator`. The first two **must** be registered before the CIP-113
registry insert, because registration runs both withdraw-0 scripts. The latter two must be
registered before transfers or seizures. Each validator's `publish` handler accepts
`RegisterCredential` and refuses deregistration.

### 3. Create an operator and register the CIP-113 node

Add a power-user node with `can_mint = True` if the registration will also issue initial supply.
The admin grants the role through the power-users list. Keep a reference to the new node for mint
transactions. A structural-only registration does not need a minter role.

Insert this token's CIP-113 registry node with `key` derived from the permanent **proxy** hash,
the applied transfer and third-party logic **script** credentials, the deployment's GlobalState
policy ID, and the disabled unfracking credential. The admin signs. The proxy's withdraw redeemer
is `GlobalStateReferenced { global_state_ref_input_index }` for the usual structural-only shape;
the authority's is:

```aiken
RegisterStructural {
  registry_node_output_index,
  global_state_location: GlobalStateReferenced { global_state_ref_input_index },
}
```

`registry_node_output_index` must identify **this token's new node**, not the covering node that
the CIP-113 insert also outputs. Do not mint anything under this issuance policy in a
`RegisterStructural` transaction. [`RegisterMint`](../lib/types/minting_authority.ak) is the
alternative if initial supply is issued during the insert: spend GlobalState, use its
`MintSecurity` spend redeemer, invoke the proxy with `GlobalStateSpent`, and supply the minter node,
`minted_amount` and destination actions as for a normal mint below. Only this registration shape
may also create a single CIP-68 reference NFT. The registry's base-layer redeemers and covering
node proof are version-specific; construct them using the deployed CIP-113 implementation.

## Build a normal transfer

The CIP-113 base layer spends the programmable-base token UTxOs and invokes the registered
`transfer_logic_validator` as a zero-value withdrawal. Include GlobalState as a reference input
for an ordinary transfer, plus a genuine denylist covering-node reference input for every unique
sender and receiver. A covering node's key must be below the holder's hash and its `next` link
above it; the root covers the initial empty list. The node must still sit at the denylist spend
validator address. One node can cover several holders.

For one sender and one destination, the repository's withdrawal redeemer has this shape:

```aiken
TransferLogicScriptWithdrawRedeemer {
  global_state_location: GlobalStateReferenced { global_state_ref_input_index },
  actions_for_each_input: [TransferLogicScriptAction {
    source_proof,
    source_denylist_covering_ref_input_index,
  }],
  destination_actions: [TransferLogicScriptDestinationAction {
    destination_proof,
    destination_denylist_covering_ref_input_index,
  }],
}
```

For example, with `reference_inputs = [GlobalState, denylist_root]`, set
`global_state_ref_input_index = 0` and both covering indices to `1` if the empty denylist root
covers both parties. With one token-bearing sender input and one token-bearing receiver output,
the two action lists each have one entry. Recalculate these positions after finalising the
transaction; the example does not apply once another reference input is inserted ahead of them.

For multiple parties, build one source action per unique **full stake credential** among token
inputs, and one destination action per unique full stake credential among token outputs. Preserve
the first-occurrence order in the transaction input and output lists; the validator matches
actions positionally. Both sides always need denylist absence. The corresponding KYC proof is
checked only when `requires_sender_kyc` or `requires_receiver_kyc` is true. The transaction fails
while paused or deactivated. See the actual schemas in
[`types/transfer_logic_script.ak`](../lib/types/transfer_logic_script.ak).

### Construct an attestation proof

For a `KycProof` of type `Attestation`, an issuer whose 32-byte Ed25519 vkey is in GlobalState's
`trusted_entity_vkeys` signs exactly this 67-byte payload:

```text
credential_hash(28) | tier(1) | valid_until_ms(8, big-endian) |
issuance_policy_id(28) | network_id(1) | credential_type(1)
```

Use credential type `0x00` for a verification-key stake credential or `0x01` for a script stake
credential, and a nonzero tier. The transaction validity range must have a finite upper bound no
later than `valid_until_ms`. Put the payload, raw 64-byte Ed25519 signature and issuer vkey in
`AttestationProof { payload, signature, issuer_vkey }`. The deterministic
[`scripts/kyc-test-vectors.mjs`](../scripts/kyc-test-vectors.mjs) shows a Node `crypto.sign(null,
payload, key)` construction with test data. Its fixed seed is a fixture, **not** an issuer key.

The alternative `Membership` proof uses an MPF leaf with key
`credential_type(1) | credential_hash(28)` and value
`valid_until_ms(8) | issuance_policy_id(28) | network_id(1)`. Use
[`membership_leaf_key` and `membership_leaf_value`](../lib/kyc/verify.ak) as the encoding reference
and publish its tree root through `UpdateMemberRootHash`. Revoking a tree leaf does not invalidate
an independently issued attestation before that attestation expires.

### Construct a CIP-30 wallet attestation

`Cip30Attestation` lets an **already trusted issuer** sign the same 67-byte
claim with a CIP-30 wallet. The issuer's 32-byte public key must still be in
GlobalState's `trusted_entity_vkeys`. A holder signing their own claim does not
grant KYC status. The public transaction builder never needs the issuer's
private key.

Build the payload exactly as for `Attestation` above, then ask the issuer's
wallet to sign it. CIP-30 addresses and payloads are hex-encoded bytes, while
the result consists of hex-encoded CBOR `COSE_Sign1` and `COSE_Key` objects:

```js
const api = await window.cardano[walletName].enable();
const addressHex = (await api.getChangeAddress()); // issuer's payment-key address
const bytes = h => Uint8Array.from(h.match(/../g), x => parseInt(x, 16));
const hex = b => [...b].map(x => x.toString(16).padStart(2, "0")).join("");
function buildKycPayload({ credentialHash, tier, validUntilMs,
                           issuancePolicyId, kycNetworkId, credentialType }) {
  const expiry = new Uint8Array(8);
  let value = BigInt(validUntilMs);
  for (let i = 7; i >= 0; i--) {
    expiry[i] = Number(value & 255n);
    value >>= 8n;
  }
  if (value !== 0n || tier < 1 || tier > 255 ||
      kycNetworkId < 0 || kycNetworkId > 3 ||
      ![0, 1].includes(credentialType) ||
      credentialHash.length !== 56 || issuancePolicyId.length !== 56) {
    throw new Error("invalid KYC claim fields");
  }
  return hex(new Uint8Array([
    ...bytes(credentialHash), tier, ...expiry, ...bytes(issuancePolicyId),
    kycNetworkId, credentialType,
  ]));
}
const payloadHex = buildKycPayload({
  credentialHash, tier, validUntilMs, issuancePolicyId,
  kycNetworkId, credentialType,
}); // 67 bytes, layout above
const { signature, key } = await api.signData(addressHex, payloadHex);
// Hex-decode both strings before placing them in the Plutus redeemer:
const proof = {
  cose_sign1: bytes(signature),
  cose_key: bytes(key),
};
```

Use an issuer **base, enterprise, or pointer address with a payment key**, or a
**reward address with a stake key**. The verifier hashes the COSE public key
and checks the corresponding payment or stake credential in the signed address
header. It accepts base address types 0 and 2, enterprise type 6, pointer type
4, and reward type 14. Use `getRewardAddresses()` and select one of those for
stake-key signing; `getChangeAddress()` normally selects a payment key. The
address must belong to the issuer wallet and match the key enrolled in the
trusted list.

Put the decoded bytes in the Aiken redeemer as:

```aiken
Cip30Attestation {
  cip30_proof: Cip30AttestationProof { cose_sign1, cose_key },
}
```

At the Plutus Data boundary, this is `Constr(2, [Constr(0, [B(cose_sign1),
B(cose_key)])])`: constructor 2 was appended after the existing `Attestation`
and `Membership` constructors. Encode this Data with the transaction builder's
normal Plutus Data serializer, and use it wherever a `KycProof` is required.
[`scripts/cip30-test-vectors.mjs`](../scripts/cip30-test-vectors.mjs) reproducibly
generates genuine Ed25519 COSE signatures with a fixed **test-only** seed; its
`sender_valid` and `receiver_valid` entries are the on-chain test fixtures.

The address's Cardano network nibble uses `0` for testnets and `1` for
mainnet. This is distinct from the signed KYC payload's configured network
value: KYC `0` preview, `1` preprod and `3` yaci map to address nibble `0`,
while KYC `2` mainnet maps to nibble `1`. The signed payload must still equal
the configured KYC value, so a preview claim cannot be reused on preprod.
The wallet's `getNetworkId()` alone does not distinguish those testnets.

The on-chain decoder accepts a bounded CIP-30 profile: definite CBOR with
shortest-form lengths, at most six entries per map, a COSE_Sign1 of at most
1024 bytes, a COSE_Key and protected map of at most 256 bytes each, an address
of at most 64 bytes, and an optional `kid` of at most 128 bytes. It accepts
the standard COSE_Sign1 tag 18 or an untagged array, map entries in any order,
optional `kid` (either absent from both objects or equal in both), optional unprotected
`"hashed": false`, and optional unprotected `"version": 1`. Other headers,
indefinite forms, detached payloads, and non-minimal pointer coordinates are
rejected. Check the wallet's returned COSE against this profile before
submitting a transaction; rejection cannot grant KYC status.

## Mint, burn and forced transfer

For a later mint, spend the GlobalState UTxO and continue it at the same script address, with its
NFT and non-ADA value preserved. Set its spend redeemer to
`GlobalStateSpendRedeemer { global_state_output_index, action: MintSecurity {
issuance_policy_redeemer_index } }`; the inner index points into the transaction's **redeemers**
at `Mint(issuance_policy_id)`. The validator writes the new `mintable_amount` by subtracting the
actual minted security quantity. Include the `can_mint` power-user node as a reference input,
signed by that operator; the CIP-113 registry node is referenced, not spent. Invoke the proxy and
authority as zero-value withdrawals:

```aiken
// Proxy withdraw redeemer
GlobalStateSpent { global_state_input_index }

// Minting authority withdraw redeemer
MintBurn {
  global_state_input_index,
  power_user_node_ref_input_index,
  minted_amount,
  destination_actions: [MintingLogicDestinationAction {
    destination_proof,
    destination_denylist_covering_ref_input_index,
  }],
}
```

`minted_amount` must equal the actual signed quantity under `security_asset_name`. Supply
increases require one action per unique token destination, with denylist absence and receiver KYC
when enabled. The authenticated, signing `can_mint` operator may mint to their own stake credential
without a separate KYC proof; their destination still needs denylist absence. Only the security
asset name can be minted in a steady-state `MintBurn` transaction;
the CIP-68 reference NFT is a registration-time artefact.

A burn uses the same GlobalState, proxy and authority shape with a **negative** `minted_amount`,
an operator with `can_burn`, and no mint destination actions. Burning returns cap headroom. It
also spends a programmable-base token UTxO, so satisfy the CIP-113 base layer's required movement
path. During a pause or when the holder cannot pass the ordinary sender gates, route the burn
through `ThirdPartyAct` with a `can_force_transfer` operator as well; `can_burn` alone does not
make that base-layer path buildable. Use `GlobalStateSpent` in any accompanying transfer or
third-party withdrawal redeemer, since GlobalState is spent in this transaction.

A forced transfer invokes `third_party_transfer_logic_validator` with
`ThirdPartyTransferLogicScriptWithdrawRedeemer { global_state_location,
power_user_node_ref_input_index, destination_actions }`. The `can_force_transfer` operator signs;
destinations supply denylist absence and enabled receiver KYC. Source KYC and denylist status are
deliberately overridden, and pause does not block seizure. Against a sanctioned or expired
holder, drain whole UTxOs: the base layer returns a partial UTxO residual to its source, which
then fails this deployment's destination checks. See
[`types/third_party_transfer_logic_script.ak`](../lib/types/third_party_transfer_logic_script.ak).

## Upgrades and operator checks

The admin can change `minting_script_credential_hash` with GlobalState's `RotateMintingScript`.
The permanent proxy will delegate **all** mint, burn and registration decisions to the new
authority. Register its stake credential first. Before switching, verify that the replacement
preserves supply-cap enforcement, GlobalState spending for supply changes, allowed asset names,
registration structure and deactivation rules described at the top of
[`minting_authority.ak`](../validators/minting_authority.ak). Test an unsigned mint and each
power-user role without its authorised signature; each should reject.

To change transfer or third-party logic, update this token's CIP-113 registry node with
`UpgradeRegistryNode { registry_node_input_index, registry_node_output_index,
global_state_location }` on the minting authority withdrawal. The admin signs. The authority
pins the node to this issuance policy, retains this deployment's GlobalState and disabled
unfracking setting, and checks `upgrades_locked == False`. Register replacement logic stake
credentials before their first use. This transaction cannot change the token supply.

`LockUpgrades` irreversibly closes both the authority-rotation and registry-upgrade paths for
**later** transactions. A registry upgrade bundled into the same transaction can still read the
unlocked input state and succeed; inspect all redeemers in the locking transaction. Admin-only
GlobalState actions similarly expose their pre-state to a bundled registry operation. Record the
active script hashes, operator credentials, base-layer version and lock transaction as deployment
artifacts. For final retirement, follow the ordered
[decommissioning runbook](security/security-fixes.md#the-decommissioning-runbook-in-order).
