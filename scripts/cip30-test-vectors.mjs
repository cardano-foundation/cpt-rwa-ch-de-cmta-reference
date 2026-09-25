#!/usr/bin/env node
// Deterministic, genuine CIP-30/CIP-8 COSE vectors. This fixed test seed is
// public and must never be used as an issuer's production signing key.
// Run: node scripts/cip30-test-vectors.mjs
import { createPrivateKey, createPublicKey, sign } from "node:crypto";

const seed = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const key = createPrivateKey({
  key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
  format: "der",
  type: "pkcs8",
});
const vkey = createPublicKey(key).export({ format: "der", type: "spki" }).subarray(-32);
// BLAKE2b-224(vkey), independently reproducible with Python:
// hashlib.blake2b(bytes.fromhex(vkey_hex), digest_size=28).hexdigest()
const issuerPkh = Buffer.from("27e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b43", "hex");

function head(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  if (n < 65536) return Buffer.from([(major << 5) | 25, n >> 8, n & 255]);
  throw new RangeError(`CBOR item too large: ${n}`);
}
function enc(x) {
  if (Buffer.isBuffer(x)) return Buffer.concat([head(2, x.length), x]);
  if (typeof x === "string") {
    const b = Buffer.from(x);
    return Buffer.concat([head(3, b.length), b]);
  }
  if (typeof x === "number") return head(x >= 0 ? 0 : 1, x >= 0 ? x : -x - 1);
  if (typeof x === "boolean") return Buffer.from([x ? 0xf5 : 0xf4]);
  if (Array.isArray(x)) return Buffer.concat([head(4, x.length), ...x.map(enc)]);
  if (x instanceof Map) {
    return Buffer.concat([head(5, x.size), ...[...x].flatMap(([k, v]) => [enc(k), enc(v)])]);
  }
  throw new TypeError(`unsupported CBOR value: ${typeof x}`);
}
function payload(holder, policy = "bb".repeat(28), network = 1, tier = 1, ttl = 100_000_000, kind = 0) {
  const expiry = Buffer.alloc(8);
  expiry.writeBigUInt64BE(BigInt(ttl));
  return Buffer.concat([Buffer.from(holder, "hex"), Buffer.from([tier]), expiry,
    Buffer.from(policy, "hex"), Buffer.from([network, kind])]);
}
function make({ holder, policy, address, network = 1, tier = 1, ttl = 100_000_000,
  kind = 0, algorithm = -8, keyAlgorithm = -8, keyCurve = 6,
  reordered = false, kid = false, tag = false }) {
  const claim = payload(holder, policy, network, tier, ttl, kind);
  const addressBytes = Buffer.from(address, "hex");
  const protectedMap = new Map(reordered
    ? [["address", addressBytes], [1, algorithm]]
    : [[1, algorithm], ["address", addressBytes]]);
  if (kid) protectedMap.set(4, addressBytes);
  const protectedBytes = enc(protectedMap);
  const unprotected = new Map([["hashed", false]]);
  const toSign = enc(["Signature1", protectedBytes, Buffer.alloc(0), claim]);
  const signature = sign(null, toSign, key);
  const sign1 = enc([protectedBytes, unprotected, claim, signature]);
  const coseKey = enc(new Map([[1, 1], [3, keyAlgorithm], [-1, keyCurve], [-2, vkey], ...(kid ? [[2, addressBytes]] : [])]));
  return {
    cose_sign1: Buffer.concat([tag ? Buffer.from([0xd2]) : Buffer.alloc(0), sign1]).toString("hex"),
    cose_key: coseKey.toString("hex"),
    payload: claim.toString("hex"),
    protected: protectedBytes.toString("hex"),
    signature: signature.toString("hex"),
  };
}
const pkh = issuerPkh.toString("hex");
const address = {
  enterprise: `60${pkh}`,
  base: `00${pkh}${"cc".repeat(28)}`,
  base_script_stake: `20${pkh}${"cc".repeat(28)}`,
  pointer: `40${pkh}010203`,
  reward: `e0${pkh}`,
  wrong_key: `60${"dd".repeat(28)}`,
  wrong_network: `61${pkh}`,
};
const cases = {
  unit_valid: make({ holder: "aa".repeat(28), address: address.enterprise }),
  sender_valid: make({ holder: "0a".repeat(28), policy: "ee".repeat(28), address: address.enterprise }),
  receiver_valid: make({ holder: "0b".repeat(28), policy: "ee".repeat(28), address: address.enterprise }),
  base_valid: make({ holder: "aa".repeat(28), address: address.base }),
  base_script_stake_valid: make({ holder: "aa".repeat(28), address: address.base_script_stake }),
  pointer_valid: make({ holder: "aa".repeat(28), address: address.pointer }),
  reward_valid: make({ holder: "aa".repeat(28), address: address.reward }),
  reordered_valid: make({ holder: "aa".repeat(28), address: address.enterprise, reordered: true }),
  kid_valid: make({ holder: "aa".repeat(28), address: address.enterprise, kid: true }),
  tagged_valid: make({ holder: "aa".repeat(28), address: address.enterprise, tag: true }),
  wrong_address_key: make({ holder: "aa".repeat(28), address: address.wrong_key }),
  wrong_address_network: make({ holder: "aa".repeat(28), address: address.wrong_network }),
  wrong_algorithm: make({ holder: "aa".repeat(28), address: address.enterprise, algorithm: -7 }),
  wrong_key_algorithm: make({ holder: "aa".repeat(28), address: address.enterprise, keyAlgorithm: -7 }),
  wrong_key_curve: make({ holder: "aa".repeat(28), address: address.enterprise, keyCurve: 7 }),
  invalid_tier: make({ holder: "aa".repeat(28), address: address.enterprise, tier: 0 }),
  expired: make({ holder: "aa".repeat(28), address: address.enterprise, ttl: 49_999_999 }),
  wrong_holder: make({ holder: "dd".repeat(28), address: address.enterprise }),
  wrong_policy: make({ holder: "aa".repeat(28), address: address.enterprise, policy: "ff".repeat(28) }),
  wrong_kyc_network: make({ holder: "aa".repeat(28), address: address.enterprise, network: 2 }),
  wrong_credential_type: make({ holder: "aa".repeat(28), address: address.enterprise, kind: 1 }),
};
function plutusConstr(index, fields) {
  // Plutus Data constructor indices 0..6 use CBOR tags 121..127.
  return Buffer.concat([Buffer.from([0xd8, 121 + index]), head(4, fields.length), ...fields]);
}
function proofBytes(sign1Hex, coseKeyHex, claimHex, rawSignatureHex) {
  const raw = plutusConstr(0, [plutusConstr(0, [
    enc(Buffer.from(claimHex, "hex")), enc(Buffer.from(rawSignatureHex, "hex")), enc(vkey),
  ])]);
  const cip30 = plutusConstr(2, [plutusConstr(0, [
    enc(Buffer.from(sign1Hex, "hex")), enc(Buffer.from(coseKeyHex, "hex")),
  ])]);
  return { raw_attestation: raw.length, cip30_attestation: cip30.length,
    delta: cip30.length - raw.length };
}
const comparable = cases.sender_valid;
const rawSignature = sign(null, Buffer.from(comparable.payload, "hex"), key).toString("hex");
console.log(JSON.stringify({
  issuer_vkey: vkey.toString("hex"), issuer_pkh: pkh, cases,
  serialized_proof_bytes: proofBytes(comparable.cose_sign1, comparable.cose_key,
    comparable.payload, rawSignature),
}, null, 2));
