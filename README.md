# Regulated security tokens on Cardano — German (eWpG) and Swiss (CMTA) profiles

Aiken (Plutus V3) contracts that provide the **on-chain enforcement primitives** a regulated
security token needs: KYC-gated transfers, a sanctions denylist, global pause, forced transfer
(seizure), a supply cap, role-split operators, and an irreversible decommission switch.

The contracts build on CIP-113 (programmable tokens) by Michele Nuzzi, Matteo Coppola,
Giovanni Gargiulo and Philip Di Sarro:
<https://github.com/HarmonicLabs/CIPs/tree/master/CIP-meta-assets%20(ERC20-like%20assets)>

---

## A note on terminology

This repository previously described itself as implementing a "BaFin standard". It does not —
**there is no BaFin token standard.** Getting this right matters, so to be precise:

| Term | What it actually is |
|---|---|
| **BaFin** | *Bundesanstalt für Finanzdienstleistungsaufsicht*, the German Federal Financial Supervisory Authority. It **supervises and licenses** crypto securities registrars and publishes the § 20 eWpG list of notified crypto securities. It does **not** publish a smart contract standard. |
| **eWpG** | *Gesetz über elektronische Wertpapiere*, the German Electronic Securities Act (in force since 10 June 2021). The **law**, together with the **eWpRV** register ordinance. Instruments issued under it are *Kryptowertpapiere* recorded in a *Kryptowertpapierregister*. |
| **ERC-7551** | "Crypto Security Token Smart Contract Interface (eWpG)" — the nearest thing to a **German technical standard**, now also a CMTAT module. EVM-specific in its signatures. |
| **CMTA** | *Capital Markets and Technology Association*, a Swiss association. The **organisation**, not the standard. |
| **CMTAT** | The *CMTA Token* — CMTA's blockchain-agnostic, open-source security token framework. This is the **Swiss standard** referred to below. |
| **Swiss law** | The DLT Act (in force 1 February 2021) introduced **ledger-based securities** (*Registerwertrechte*) in Art. 973d ff. of the Swiss Code of Obligations. |

Accordingly, this repository does not claim to be "BaFin compliant" or "CMTA certified". It aims
to implement the **on-chain half** of what each regime requires. See
[Compliance status](#compliance-status) and the [disclaimer](#disclaimer).

---

## The two profiles

Both profiles are served by **one shared contract set**, not two separate codebases — the
enforcement primitives the two regimes demand overlap almost entirely. What differs is the
metadata schema and which behaviours are mandatory.

### German profile — eWpG / eWpRV

Targets the obligations of the German Electronic Securities Act. The register itself is kept by a
BaFin-authorised registrar (*registerführende Stelle*); these contracts are intended to serve as
the technical register layer under that registrar's control. Requirements addressed on-chain:

* **Tamper-evident, chronological record of state changes** — every transfer, mint, freeze, role
  change and metadata update is a ledger transaction, ordered and immutable once settled.
* **Enforcement of disposal restrictions** — transfers are validated against on-chain KYC status
  and denylist entries before they can settle; unauthorised transfers cannot be constructed.
* **Per-holder and global freezing** — denylist entries block send *and* receive; the pause flag
  halts standard transfers globally.
* **Role-based access control** — registrar/issuer/compliance functions are split across
  separately assignable power-user roles (see [Actors](#actors)).
* **Holder identification** — holders are recorded on-chain by credential hash in a linked list,
  which a registrar maps 1:1 to identities verified off-chain.
* **Forced transfer / seizure** — an authorised role can move tokens to a verified, non-denylisted
  address for regulatory enforcement or corporate actions.
* **Securities metadata** — a `SecurityInfo` schema covering ISIN, terms of issue, issuer details,
  nominal amount, volume of issuance, register and custodian references
  ([`lib/types/security/bafin.ak`](lib/types/security/bafin.ak)).

Two things this layer deliberately does **not** do, because they are not smart contract problems:

* **§ 20 eWpG publication** — publishing the entry in the *Bundesanzeiger* and notifying BaFin are
  **off-chain duties of the issuer and registrar**. On-chain metadata does not discharge them.
* **KYC/AML itself** — identity verification is performed off-chain by the registrar; the contracts
  only record and enforce the resulting verified/denylisted status.

### Swiss profile — CMTA / CMTAT

Targets the CMTA Framework (*Blockchain-agnostic functional specification of the CMTAT token*),
which defines 42 numbered functionalities `ABS-01…42`, of which **only `ABS-01…14` are mandatory**.
CMTAT v3.2.0 (Solidity) is used as a semantic reference, not as the gold standard — it is itself
unaudited at v3.2.0 (last fully audited release is v3.0.0).

The mandatory base and enforcement modules are implemented: supply and balance views (ledger-native
on Cardano), transfer, mint, burn, pause/unpause and status, deactivate and status, and
full-address freeze/unfreeze and status. Optional modules (snapshots,
distributions, debt terms, delegated approval) are not implemented; EVM-specific machinery
(allowance mechanic, gasless relaying, cross-chain, interface conformance) is not applicable on
eUTxO.

A third-party equivalency assessment of this codebase is maintained at
[CMTA/CMTAT-Cardano](https://github.com/CMTA/CMTAT-Cardano).

---

## Compliance status

The mandatory enforcement core is implemented and covered by the test suite: KYC-gated transfers
(sender and receiver, each independently toggleable), a sanctions denylist, global pause, forced
transfer, a supply cap, mint and burn, role-split operators, and an irreversible decommission
switch.

Optional CMTA modules — snapshots, distributions, debt terms, delegated approval — are **not**
implemented. EVM-specific machinery (the allowance mechanic, gasless relaying, cross-chain
messaging, interface conformance) does not apply on eUTxO.

One item is a deliberate deployment responsibility rather than a contract feature: `security_info`
is carried in the GlobalState datum as opaque `Data` and is not parsed by any validator.
[`lib/types/security/bafin.ak`](lib/types/security/bafin.ak) defines the intended shape, but
populating it correctly — and keeping it consistent with the register — is an off-chain duty of the
issuer and registrar.

### Review and audit

* **Penetration testing** — two engagements have been carried out; the reports are in
  [`documents/pentesting/`](documents/pentesting/).
* **Formal security audit** — an official third-party audit is **planned and not yet completed**.
  Until it has been, treat this code as unaudited.
* **Third-party equivalency assessment** — an independent CMTAT mapping of this codebase is
  maintained at [CMTA/CMTAT-Cardano](https://github.com/CMTA/CMTAT-Cardano).

---

## Actors

* **Admin** — the `admin_credential_hash` held in the GlobalState datum. Controls the power-user
  list itself (add, remove, modify), the security metadata, and the irreversible deactivation
  switch. Rotatable, so the master key can be replaced without redeploying.
* **Power user** — a node in the power-users linked list, carrying independently grantable flags:
  * `is_admin` — add and remove denylist entries. Deliberately split from the master admin key, so a
    compliance function can be delegated without handing over control of the protocol.
  * `can_mint` — mint new tokens, up to the remaining supply cap
  * `can_burn` — burn tokens, restoring headroom under the cap
  * `can_pause` — pause and unpause all standard transfers
  * `can_force_transfer` — seize tokens, moving them to a vetted address
* **Trusted entity** — an off-chain KYC attestor whose Ed25519 verification key is listed in the
  GlobalState datum. It signs the KYC proofs that transfers present. Not an on-chain role: it never
  submits transactions, it only signs attestations.
* **Holder** — any wallet or script holding the token. Must be absent from the denylist and, when
  the corresponding flag is set, must present a valid KYC proof (or prove membership of the
  allowlist tree).

## How it works

* An issuer initialises the protocol, then grants power-user flags to the operators who need them.
* Power users and denylist entries are each stored on-chain as a linked list; **presence in the
  denylist is the sanction** — there is no flag to toggle, and absence is proven with a covering-node
  proof.
* A transfer must clear the pause gate, then per sender and per receiver: denylist absence, plus a
  valid KYC proof whenever `requires_sender_kyc` / `requires_receiver_kyc` is set. The two are
  toggled independently.
* Forced transfers move tokens to a vetted destination. They intentionally remain available while
  transfers are paused, so enforcement is not blocked by a pause.
* Minting is capped; burning returns headroom to the cap.
* Deactivation is one-way and requires a paused protocol first — it is a decommissioning switch, not
  a stronger pause.

## Building the scripts

Requires Aiken **v1.1.22**, pinned in [`aiken.toml`](aiken.toml) and matched by CI.

```sh
aiken fmt --check   # formatting
aiken check -D      # type-check and run the test suite
aiken build         # compile; regenerates plutus.json
```

`aiken build` writes the blueprint to `plutus.json`. Every validator takes compile-time parameters,
so the blueprint contains **unapplied** scripts — apply parameters with `aiken blueprint apply` (or
the equivalent in your off-chain library) before deriving any hash or address.

Parameters have to be applied in dependency order, because each layer's policy ID is an input to
the next:

1. Choose the genesis UTxO (`tx0`, `index0`) and apply it to `global_state_mint_validator` →
   **GlobalState policy ID**
2. That, plus one genesis UTxO per list, applied to `power_users.mint` and `denylist.mint` →
   **power-users** and **denylist policy IDs**
3. Those, plus `security_asset_name` and the CIP-113 registry policy ID, applied to
   `minting_logic_validator` → its hash yields the **issuance policy ID**, which *is* the security
   token's policy ID
4. The issuance policy ID applied to `global_state_spend_validator`
5. `transfer_logic_validator` and `third_party_transfer_logic_validator` from the same set

## Initialising a token

Genesis is a short sequence of transactions. They can be submitted one at a time or built as a
deterministic chain and signed in a single batch.

1. **Create GlobalState** — spend the genesis UTxO and mint the GlobalState NFT into a new UTxO
   carrying the initial datum: admin credential, supply cap, the two linked-list policy IDs, KYC
   flags, trusted entity keys, and the target network ID.
2. **Register in the CIP-113 registry** — insert a registry node keyed by the issuance policy ID,
   recording the minting, transfer and third-party transfer logic scripts plus the GlobalState
   policy. Nothing validates until this node exists.
3. **Initialise the linked lists** — mint the root node of the power-users list and of the denylist
   (one transaction each).
4. **Register the logic scripts' stake credentials** — the three logic validators are invoked as
   zero-value withdrawals, so their stake credentials must be registered before any transfer, mint
   or burn can reference them.
5. **Assign power users** — insert one node per operator, with the role flags that operator should
   hold.
6. **Mint the initial supply** — spends GlobalState to decrement the cap and mints under the
   issuance policy to holders that pass the denylist and KYC gates.

From there the protocol is live: mint and burn, pause and unpause, force transfers, verify or
denylist holders, and add or modify power users.

## Security token uniqueness

Uniqueness derives from the genesis UTxO. `tx0`/`index0` are applied to `global_state_mint_validator`,
which makes the GlobalState policy ID unique to that deployment; every other validator takes that
policy ID (directly or transitively) as a parameter. Together with `security_asset_name`, this means
each deployment compiles to different validator hashes — and therefore to a different security token
policy ID — even for identical source code.

## How to retrieve information

For wallets and dApps reading protocol state:

1. Go to the CIP-113 registry and find the linked-list node with `key ==` this token's policy ID
2. Read its GlobalState field to identify the NFT holding the GlobalState datum
3. Find that UTxO and read the GlobalState datum for: pause and deactivation flags, remaining
   mintable amount, security info, the KYC requirement flags, the trusted entity keys, and the
   power-users and denylist linked-list policy IDs
4. To check whether a holder is sanctioned, look for a UTxO holding an NFT with `policy_id ==` the
   denylist policy ID and `datum.key ==` the holder's credential hash. **Presence means denylisted**
   — there is no flag to read, and absence is proven on-chain with a covering-node proof
5. For operator roles, read the power-users list the same way; each node's datum carries that
   operator's role flags

---

## Disclaimer

Obtain your own legal and security review before any production issuance.

## Authors

Matteo Coppola, as part of the Finest team.
