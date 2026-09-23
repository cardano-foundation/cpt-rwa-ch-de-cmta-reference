use aiken/builtin
use aiken/collection/list
use aiken/collection/pairs
use aiken/crypto
use aiken/fuzz
use aiken/primitive/bytearray

// This is a bounded CIP-30 profile, not a general-purpose CBOR decoder.
// Only definite, shortest-form encodings and the documented header labels are
// accepted. Map order is unrestricted; duplicate labels are always rejected.
// Scalar and the generic map reader below are retained as a test oracle for
// the cheaper streaming readers; they do not contribute to validator code.
type Scalar {
  Integer(Int)
  Bytes(ByteArray)
  Text(ByteArray)
  Boolean(Bool)
}

type Head {
  major: Int,
  value: Int,
  next: Int,
}

type Signed {
  protected: ByteArray,
  unprotected_kid: Option<ByteArray>,
  payload: ByteArray,
  signature: ByteArray,
}

type Fields {
  value: ByteArray,
  kid: Option<ByteArray>,
}

// The enclosing input is at most 1024 bytes. Two-byte lengths suffice, and
// rejecting wider forms also rejects non-minimal encodings of small values.
fn head(input: ByteArray, offset: Int) -> Option<Head> {
  let size = bytearray.length(input)
  if offset < 0 || offset >= size {
    None
  } else {
    let first = builtin.index_bytearray(input, offset)
    let major = first / 32
    let additional = first % 32
    if additional < 24 {
      Some(Head { major, value: additional, next: offset + 1 })
    } else if additional == 24 && offset + 1 < size {
      let value = builtin.index_bytearray(input, offset + 1)
      if value >= 24 {
        Some(Head { major, value, next: offset + 2 })
      } else {
        None
      }
    } else if additional == 25 && offset + 2 < size {
      let value = builtin.index_bytearray(input, offset + 1) * 256 + builtin.index_bytearray(
        input,
        offset + 2,
      )
      if value >= 256 {
        Some(Head { major, value, next: offset + 3 })
      } else {
        None
      }
    } else {
      None
    }
  }
}

fn scalar(input: ByteArray, offset: Int) -> Option<Pair<Scalar, Int>> {
  when head(input, offset) is {
    Some(Head { major: 0, value, next }) -> Some(Pair(Integer(value), next))
    Some(Head { major: 1, value, next }) ->
      Some(Pair(Integer(-1 - value), next))
    Some(Head { major: 7, value: 20, next }) -> Some(Pair(Boolean(False), next))
    Some(Head { major: 7, value: 21, next }) -> Some(Pair(Boolean(True), next))
    Some(Head { major, value, next }) ->
      if ( major == 2 || major == 3 ) && next + value <= bytearray.length(input) {
        let bytes = builtin.slice_bytearray(next, value, input)
        Some(
          Pair(
            if major == 2 {
              Bytes(bytes)
            } else {
              Text(bytes)
            },
            next + value,
          ),
        )
      } else {
        None
      }
    None -> None
  }
}

fn bytes(input: ByteArray, offset: Int) -> Option<Pair<ByteArray, Int>> {
  when head(input, offset) is {
    Some(Head { major: 2, value, next }) ->
      if next + value <= bytearray.length(input) {
        Some(Pair(builtin.slice_bytearray(next, value, input), next + value))
      } else {
        None
      }
    _ -> None
  }
}

fn entries(
  input: ByteArray,
  offset: Int,
  remaining: Int,
  found: Pairs<Scalar, Scalar>,
) -> Option<Pair<Pairs<Scalar, Scalar>, Int>> {
  if remaining == 0 {
    Some(Pair(found, offset))
  } else {
    when scalar(input, offset) is {
      Some(Pair(key, next)) ->
        if pairs.has_key(found, key) {
          None
        } else {
          when scalar(input, next) is {
            Some(Pair(value, end)) ->
              entries(input, end, remaining - 1, [Pair(key, value), ..found])
            None -> None
          }
        }
      None -> None
    }
  }
}

fn map(
  input: ByteArray,
  offset: Int,
) -> Option<Pair<Pairs<Scalar, Scalar>, Int>> {
  when head(input, offset) is {
    Some(Head { major: 5, value, next }) ->
      if value <= 6 {
        entries(input, next, value, [])
      } else {
        None
      }
    _ -> None
  }
}

fn complete_map(input: ByteArray) -> Option<Pairs<Scalar, Scalar>> {
  when map(input, 0) is {
    Some(Pair(fields, end)) ->
      if end == bytearray.length(input) {
        Some(fields)
      } else {
        None
      }
    None -> None
  }
}

// Each accepted label and fixed value has one shortest CBOR encoding. Match
// those bytes directly and retain only the variable fields; this avoids
// constructing a generic map and repeatedly traversing it. Explicit presence
// flags reject duplicates even when their values agree.
fn prefix(input: ByteArray, offset: Int, expected: ByteArray) -> Bool {
  builtin.slice_bytearray(offset, bytearray.length(expected), input) == expected
}

fn map_start(input: ByteArray, offset: Int, maximum: Int) -> Option<Int> {
  if offset < 0 || offset >= bytearray.length(input) {
    None
  } else {
    let header = builtin.index_bytearray(input, offset)
    if header >= 0xa0 && header <= 0xa0 + maximum {
      Some(header - 0xa0)
    } else {
      None
    }
  }
}

fn read_kid(input: ByteArray, offset: Int) -> Option<Pair<ByteArray, Int>> {
  when bytes(input, offset) is {
    Some(Pair(value, end)) ->
      if bytearray.length(value) <= 128 {
        Some(Pair(value, end))
      } else {
        None
      }
    None -> None
  }
}

fn protected_entries(
  input: ByteArray,
  offset: Int,
  remaining: Int,
  algorithm: Bool,
  address: Option<ByteArray>,
  kid: Option<ByteArray>,
) -> Option<Fields> {
  if remaining == 0 {
    when address is {
      Some(value) ->
        if algorithm && offset == bytearray.length(input) {
          Some(Fields { value, kid })
        } else {
          None
        }
      None -> None
    }
  } else if offset >= bytearray.length(input) {
    None
  } else {
    when builtin.index_bytearray(input, offset) is {
      0x1 ->
        if !algorithm && prefix(input, offset, #"0127") {
          protected_entries(
            input,
            offset + 2,
            remaining - 1,
            True,
            address,
            kid,
          )
        } else {
          None
        }
      0x67 ->
        if address == None && prefix(input, offset, #"6761646472657373") {
          when bytes(input, offset + 8) is {
            Some(Pair(value, end)) ->
              protected_entries(
                input,
                end,
                remaining - 1,
                algorithm,
                Some(value),
                kid,
              )
            None -> None
          }
        } else {
          None
        }
      0x4 ->
        if kid == None {
          when read_kid(input, offset + 1) is {
            Some(Pair(value, end)) ->
              protected_entries(
                input,
                end,
                remaining - 1,
                algorithm,
                address,
                Some(value),
              )
            None -> None
          }
        } else {
          None
        }
      _ -> None
    }
  }
}

fn read_protected(input: ByteArray) -> Option<Fields> {
  // Algorithm -8 and the issuer address are required. An optional kid must
  // appear at most once. The recursive reader also consumes the whole map.
  when map_start(input, 0, 3) is {
    Some(count) -> protected_entries(input, 1, count, False, None, None)
    None -> None
  }
}

fn unprotected_entries(
  input: ByteArray,
  offset: Int,
  remaining: Int,
  hashed: Bool,
  version: Bool,
  kid: Option<ByteArray>,
) -> Option<Pair<Option<ByteArray>, Int>> {
  if remaining == 0 {
    Some(Pair(kid, offset))
  } else if offset >= bytearray.length(input) {
    None
  } else {
    when builtin.index_bytearray(input, offset) is {
      0x66 ->
        if !hashed && prefix(input, offset, #"66686173686564f4") {
          unprotected_entries(
            input,
            offset + 8,
            remaining - 1,
            True,
            version,
            kid,
          )
        } else {
          None
        }
      0x67 ->
        if !version && prefix(input, offset, #"6776657273696f6e01") {
          unprotected_entries(
            input,
            offset + 9,
            remaining - 1,
            hashed,
            True,
            kid,
          )
        } else {
          None
        }
      0x4 ->
        if kid == None {
          when read_kid(input, offset + 1) is {
            Some(Pair(value, end)) ->
              unprotected_entries(
                input,
                end,
                remaining - 1,
                hashed,
                version,
                Some(value),
              )
            None -> None
          }
        } else {
          None
        }
      _ -> None
    }
  }
}

fn read_unprotected(
  input: ByteArray,
  offset: Int,
) -> Option<Pair<Option<ByteArray>, Int>> {
  // Only kid, hashed=false, and version=1 are permitted here. Algorithm and
  // address must stay in the signed protected map, never this unsigned map.
  when map_start(input, offset, 3) is {
    Some(count) ->
      unprotected_entries(input, offset + 1, count, False, False, None)
    None -> None
  }
}

fn key_entries(
  input: ByteArray,
  offset: Int,
  remaining: Int,
  kty: Bool,
  algorithm: Bool,
  curve: Bool,
  key: Option<ByteArray>,
  kid: Option<ByteArray>,
) -> Option<Fields> {
  if remaining == 0 {
    when key is {
      Some(value) ->
        if kty && algorithm && curve && offset == bytearray.length(input) {
          Some(Fields { value, kid })
        } else {
          None
        }
      None -> None
    }
  } else if offset >= bytearray.length(input) {
    None
  } else {
    when builtin.index_bytearray(input, offset) is {
      0x1 ->
        if !kty && prefix(input, offset, #"0101") {
          key_entries(
            input,
            offset + 2,
            remaining - 1,
            True,
            algorithm,
            curve,
            key,
            kid,
          )
        } else {
          None
        }
      0x3 ->
        if !algorithm && prefix(input, offset, #"0327") {
          key_entries(
            input,
            offset + 2,
            remaining - 1,
            kty,
            True,
            curve,
            key,
            kid,
          )
        } else {
          None
        }
      0x20 ->
        if !curve && prefix(input, offset, #"2006") {
          key_entries(
            input,
            offset + 2,
            remaining - 1,
            kty,
            algorithm,
            True,
            key,
            kid,
          )
        } else {
          None
        }
      0x21 ->
        if key == None {
          when bytes(input, offset + 1) is {
            Some(Pair(value, end)) ->
              if bytearray.length(value) == 32 {
                key_entries(
                  input,
                  end,
                  remaining - 1,
                  kty,
                  algorithm,
                  curve,
                  Some(value),
                  kid,
                )
              } else {
                None
              }
            None -> None
          }
        } else {
          None
        }
      0x2 ->
        if kid == None {
          when read_kid(input, offset + 1) is {
            Some(Pair(value, end)) ->
              key_entries(
                input,
                end,
                remaining - 1,
                kty,
                algorithm,
                curve,
                key,
                Some(value),
              )
            None -> None
          }
        } else {
          None
        }
      _ -> None
    }
  }
}

fn read_key(input: ByteArray) -> Option<Fields> {
  // Require OKP / EdDSA / Ed25519 and a 32-byte x coordinate. Unknown or
  // duplicate labels fail, even when a repeated value is identical.
  when map_start(input, 0, 5) is {
    Some(count) -> key_entries(input, 1, count, False, False, False, None, None)
    None -> None
  }
}

fn matching_kids(
  protected: Option<ByteArray>,
  unprotected: Option<ByteArray>,
  key: Option<ByteArray>,
) -> Bool {
  // A kid may live in one Sign1 header map, but never both. Its absence is
  // distinct from an empty byte string, and must match COSE_Key exactly.
  when protected is {
    Some(_) -> unprotected == None && protected == key
    None -> unprotected == key
  }
}

fn signed(input: ByteArray) -> Option<Signed> {
  let size = builtin.length_of_bytearray(input)
  if size == 0 || size > 1024 {
    None
  } else {
    // COSE_Sign1 may be bare or wrapped in its standard tag 18.
    let start = if builtin.index_bytearray(input, 0) == 0xd2 {
      1
    } else {
      0
    }
    // A definite four-item array has exactly this shortest CBOR header.
    if !prefix(input, start, #"84") {
      None
    } else {
      when bytes(input, start + 1) is {
        Some(Pair(protected, after_protected)) ->
          if builtin.length_of_bytearray(protected) > 256 {
            None
          } else {
            when read_unprotected(input, after_protected) is {
              Some(Pair(unprotected_kid, after_unprotected)) -> {
                let payload_start = after_unprotected + 2
                let signature_header = payload_start + 67
                // The signed KYC claim is always 67 bytes and Ed25519
                // signatures are 64 bytes. Fixed shortest-form headers plus
                // exact total length rule out truncation and trailing data.
                if signature_header + 2 + 64 == size && prefix(
                  input,
                  after_unprotected,
                  #"5843",
                ) && prefix(input, signature_header, #"5840") {
                  Some(
                    Signed {
                      protected,
                      unprotected_kid,
                      payload: builtin.slice_bytearray(payload_start, 67, input),
                      signature: builtin.slice_bytearray(
                        signature_header + 2,
                        64,
                        input,
                      ),
                    },
                  )
                } else {
                  None
                }
              }
              None -> None
            }
          }
        None -> None
      }
    }
  }
}

fn optional_kid(value: Option<Scalar>) -> Bool {
  when value is {
    None -> True
    Some(Bytes(kid)) -> bytearray.length(kid) <= 128
    _ -> False
  }
}

fn protected_ok(fields: Pairs<Scalar, Scalar>) -> Bool {
  and {
    pairs.get_first(fields, Integer(1)) == Some(Integer(-8)),
    list.all(
      fields,
      fn(entry) {
        when entry is {
          Pair(Integer(1), _) -> True
          Pair(Integer(4), _) -> True
          Pair(Text("address"), Bytes(_)) -> True
          _ -> False
        }
      },
    ),
    optional_kid(pairs.get_first(fields, Integer(4))),
  }
}

fn unprotected_ok(fields: Pairs<Scalar, Scalar>) -> Bool {
  list.all(
    fields,
    fn(entry) {
      when entry is {
        Pair(Text("hashed"), Boolean(False)) -> True
        Pair(Text("version"), Integer(1)) -> True
        Pair(Integer(4), Bytes(kid)) -> bytearray.length(kid) <= 128
        _ -> False
      }
    },
  )
}

fn key_ok(fields: Pairs<Scalar, Scalar>) -> Bool {
  and {
    pairs.get_first(fields, Integer(1)) == Some(Integer(1)),
    pairs.get_first(fields, Integer(3)) == Some(Integer(-8)),
    pairs.get_first(fields, Integer(-1)) == Some(Integer(6)),
    optional_kid(pairs.get_first(fields, Integer(2))),
    list.all(
      fields,
      fn(entry) {
        when entry is {
          Pair(Integer(1), _) -> True
          Pair(Integer(2), _) -> True
          Pair(Integer(3), _) -> True
          Pair(Integer(-1), _) -> True
          Pair(Integer(-2), Bytes(key)) -> bytearray.length(key) == 32
          _ -> False
        }
      },
    ),
  }
}

fn kids_match(
  protected: Pairs<Scalar, Scalar>,
  unprotected: Pairs<Scalar, Scalar>,
  key: Pairs<Scalar, Scalar>,
) -> Bool {
  let protected_kid = pairs.get_first(protected, Integer(4))
  let unprotected_kid = pairs.get_first(unprotected, Integer(4))
  let key_kid = pairs.get_first(key, Integer(2))
  when Pair(protected_kid, unprotected_kid) is {
    Pair(Some(_), Some(_)) -> False
    _ -> {
      let signing_kid = when protected_kid is {
        Some(value) -> Some(value)
        None -> unprotected_kid
      }
      when Pair(signing_kid, key_kid) is {
        Pair(Some(a), Some(b)) -> a == b
        Pair(None, None) -> True
        _ -> False
      }
    }
  }
}

// Three minimally encoded, terminated base-128 integers; no trailing bytes.
// The complete address is capped at 64 bytes, bounding recursion even when an
// adversary supplies unterminated or extremely large pointer coordinates.
fn pointer(input: ByteArray, offset: Int, remaining: Int, first: Bool) -> Bool {
  let size = bytearray.length(input)
  if remaining == 0 {
    offset == size
  } else if offset >= size {
    False
  } else {
    let value = builtin.index_bytearray(input, offset)
    if first && value == 128 {
      False
    } else if value >= 128 {
      pointer(input, offset + 1, remaining, False)
    } else {
      pointer(input, offset + 1, remaining - 1, True)
    }
  }
}

fn address_ok(address: ByteArray, key: ByteArray, network_id: Int) -> Bool {
  let size = bytearray.length(address)
  // The signed KYC network is more specific than Cardano's address nibble:
  // preview, preprod, and Yaci all use testnet nibble 0.
  let network = when network_id is {
    0 -> 0
    1 -> 0
    2 -> 1
    3 -> 0
    _ -> -1
  }
  if size < 29 || size > 64 || network < 0 {
    False
  } else {
    let header = builtin.index_bytearray(address, 0)
    let kind = header / 16
    // Supported address types put this key hash in the first credential slot.
    // This excludes script payment keys and base addresses whose stake key
    // alone matches the signer; reward type 14 instead uses a stake key.
    and {
      header % 16 == network,
      builtin.slice_bytearray(1, 28, address) == crypto.blake2b_224(key),
      when kind is {
        0 -> size == 57
        2 -> size == 57
        4 -> pointer(address, 29, 3, True)
        6 -> size == 29
        14 -> size == 29
        _ -> False
      },
    }
  }
}

fn encode_bytes(value: ByteArray) -> ByteArray {
  // Protected-map bytes stay verbatim in Sig_structure. Only their byte-string
  // length prefix is rebuilt; accepted lengths fit in at most two bytes.
  let size = builtin.length_of_bytearray(value)
  let prefix = if size < 24 {
    builtin.cons_bytearray(64 + size, #"")
  } else if size < 256 {
    builtin.cons_bytearray(0x58, builtin.cons_bytearray(size, #""))
  } else {
    #"590100"
  }
  builtin.append_bytearray(prefix, value)
}

fn signature_structure(protected: ByteArray, payload: ByteArray) -> ByteArray {
  // signed() already proved payload is 67 bytes. COSE signs the original
  // protected-map bytes, followed by empty external AAD and that exact claim.
  builtin.append_bytearray(
    #"846a5369676e617475726531",
    builtin.append_bytearray(
      encode_bytes(protected),
      builtin.append_bytearray(#"405843", payload),
    ),
  )
}

/// Authenticate a wallet's raw CIP-30 return values and return its payload.
/// The caller must additionally check holder, policy, KYC network, tier and TTL.
/// Limits: Sign1 1024 bytes, key/protected map 256, kid 128, address 64.
/// Unknown fields, indefinite/non-minimal CBOR and detached payloads fail closed.
pub fn verify(
  cose_sign1: ByteArray,
  cose_key: ByteArray,
  trusted_keys: Pairs<ByteArray, Data>,
  network_id: Int,
) -> Option<ByteArray> {
  // Cheap structural and issuer checks precede the expensive Ed25519 builtin.
  // The caller checks the signed claim's holder, policy, tier, and expiry.
  if bytearray.length(cose_key) > 256 {
    None
  } else {
    when signed(cose_sign1) is {
      Some(message) ->
        when Pair(read_protected(message.protected), read_key(cose_key)) is {
          Pair(Some(protected), Some(key_fields)) -> {
            let address = protected.value
            let key = key_fields.value
            if and {
              matching_kids(
                protected.kid,
                message.unprotected_kid,
                key_fields.kid,
              ),
              pairs.has_key(trusted_keys, key),
              address_ok(address, key, network_id),
            } {
              if crypto.verify_ed25519_signature(
                key,
                signature_structure(message.protected, message.payload),
                message.signature,
              ) {
                Some(message.payload)
              } else {
                None
              }
            } else {
              None
            }
          }
          _ -> None
        }
      None -> None
    }
  }
}

test decoder_rejects_truncation_nonminimal_and_indefinite() {
  and {
    head(#"", 0) == None,
    head(#"58", 0) == None,
    head(#"5901", 0) == None,
    head(#"5817", 0) == None,
    head(#"5900ff", 0) == None,
    head(#"5f", 0) == None,
    bytes(#"430102", 0) == None,
    complete_map(#"a1010100") == None,
    complete_map(#"a201010102") == None,
    complete_map(#"bf01ff") == None,
  }
}

test decoder_preserves_major_types_and_rejects_nested_values() {
  and {
    scalar(#"6161", 0) == Some(Pair(Text("a"), 2)),
    scalar(#"4161", 0) == Some(Pair(Bytes("a"), 2)),
    scalar(#"f4", 0) == Some(Pair(Boolean(False), 1)),
    scalar(#"26", 0) == Some(Pair(Integer(-7), 1)),
    complete_map(#"a10180") == None,
    complete_map(#"a101a0") == None,
  }
}

test pointer_requires_three_complete_minimal_integers() {
  and {
    pointer(#"000000", 0, 3, True),
    pointer(#"8100017f", 0, 3, True),
    !pointer(#"80000000", 0, 3, True),
    !pointer(#"0000", 0, 3, True),
    !pointer(#"000080", 0, 3, True),
    !pointer(#"00000000", 0, 3, True),
  }
}

// Genuine deterministic signatures from scripts/cip30-test-vectors.mjs.
const test_key =
  #"03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"

fn trusted() -> Pairs<ByteArray, Data> {
  [Pair(test_key, builtin.constr_data(0, []))]
}

test genuine_unit_valid() {
  verify(
    #"84582aa201276761646472657373581d6027e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b43a166686173686564f45843aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01005840b98e5f45c6b54500cf64d816928f8bd81ec095d85c12e642c4204325df16f06943e6d8a1ae82796f4dd91fe71caa31e7e2cf5356b7a96d7ba1a1bd10482b2b06",
    #"a401010327200621582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
    trusted(),
    1,
  ) == Some(
    #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0100",
  )
}

test genuine_base_valid() {
  verify(
    #"845846a20127676164647265737358390027e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b43cccccccccccccccccccccccccccccccccccccccccccccccccccccccca166686173686564f45843aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01005840db8b1b209af2ba040b5079305a0727ca58eb2f9b717ac3eea664d5bc316ab01c493cb4cf3a44fcfbaf2fa73557942b0bda48b51406247e9b2655644261a6b30a",
    #"a401010327200621582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
    trusted(),
    1,
  ) == Some(
    #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0100",
  )
}

test genuine_base_script_stake_valid() {
  verify(
    #"845846a20127676164647265737358392027e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b43cccccccccccccccccccccccccccccccccccccccccccccccccccccccca166686173686564f45843aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0100584060426af856c5d88075db034f7a8b7b763886f1fb65cf487ff8d051705a8e7fae84ae1ca53e65e20477340676fa8f9ab17b39f7674537762ad1158f46553e7b0a",
    #"a401010327200621582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
    trusted(),
    1,
  ) == Some(
    #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0100",
  )
}

test genuine_pointer_valid() {
  verify(
    #"84582da20127676164647265737358204027e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b43010203a166686173686564f45843aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01005840acac35351f64d37f1a89a7a030091bd523b0896274898676c28c974e0de8cca07140eb521a0b08d8e59157c278a629e0d55f0930ecdae6eda9d1b1208e78520d",
    #"a401010327200621582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
    trusted(),
    1,
  ) == Some(
    #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0100",
  )
}

test genuine_reward_valid() {
  verify(
    #"84582aa201276761646472657373581de027e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b43a166686173686564f45843aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0100584093571932dcd3fd62d5c27e11becf5801ead506cc791d0de0f1de8540d1915c8792784dd0db5678e0000d6b82a15f9f8d3f37f1a81c827d41c8ce42f2b9bca10c",
    #"a401010327200621582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
    trusted(),
    1,
  ) == Some(
    #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0100",
  )
}

test genuine_reordered_valid() {
  verify(
    #"84582aa26761646472657373581d6027e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b430127a166686173686564f45843aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01005840f6c48c2503f92fa278a5b75a72c8395184e5693e4a7ea1f8bf019c576acf66aa9da016f3e4df0cebced48c5b5b57deb4f4778770add401e9728a6ecc1e150505",
    #"a401010327200621582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
    trusted(),
    1,
  ) == Some(
    #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0100",
  )
}

test genuine_kid_valid() {
  verify(
    #"84584aa301276761646472657373581d6027e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b4304581d6027e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b43a166686173686564f45843aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01005840af5b0e22ea7e5aabdcbcd38339c48e96e20ddf76686f695909b58d4c842e58f8559d8550a0a9ac35efbd1446b955be1dc0a336d511ec0fef4d15ff30dba8e007",
    #"a501010327200621582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b802581d6027e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b43",
    trusted(),
    1,
  ) == Some(
    #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0100",
  )
}

test genuine_tagged_valid() {
  verify(
    #"d284582aa201276761646472657373581d6027e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b43a166686173686564f45843aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01005840b98e5f45c6b54500cf64d816928f8bd81ec095d85c12e642c4204325df16f06943e6d8a1ae82796f4dd91fe71caa31e7e2cf5356b7a96d7ba1a1bd10482b2b06",
    #"a401010327200621582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
    trusted(),
    1,
  ) == Some(
    #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0100",
  )
}

test genuine_wrong_address_key() {
  verify(
    #"84582aa201276761646472657373581d60dddddddddddddddddddddddddddddddddddddddddddddddddddddddda166686173686564f45843aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb010058409d01defb2502822e1c40f29ad97d24d66fa825532e6bb7b47893b414141565d793c18a5113235a8373fbe32a46e8b0b7baa03493e6b98f0066664092aa72690d",
    #"a401010327200621582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
    trusted(),
    1,
  ) == None
}

test genuine_wrong_address_network() {
  verify(
    #"84582aa201276761646472657373581d6127e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b43a166686173686564f45843aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01005840505c944da3800be28975aebcfd846e3d5ccdf88fb282945811ca784682cde7765b36d13b9f7992947912b6d1a911c9da325c9d84a84c5ce4c422f273abcb900c",
    #"a401010327200621582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
    trusted(),
    1,
  ) == None
}

test genuine_wrong_algorithm() {
  verify(
    #"84582aa201266761646472657373581d6027e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b43a166686173686564f45843aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01005840046a17266739c5d0ddfe16845af5206fd303ca0652728dfb0cbfcb563c5620b549ca7e84d6a665882a7a40f01b436165c76fa0376d0a9e018db84b94f1079b04",
    #"a401010327200621582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
    trusted(),
    1,
  ) == None
}

test genuine_wrong_key_algorithm() {
  verify(
    #"84582aa201276761646472657373581d6027e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b43a166686173686564f45843aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01005840b98e5f45c6b54500cf64d816928f8bd81ec095d85c12e642c4204325df16f06943e6d8a1ae82796f4dd91fe71caa31e7e2cf5356b7a96d7ba1a1bd10482b2b06",
    #"a401010326200621582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
    trusted(),
    1,
  ) == None
}

test genuine_wrong_key_curve() {
  verify(
    #"84582aa201276761646472657373581d6027e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b43a166686173686564f45843aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01005840b98e5f45c6b54500cf64d816928f8bd81ec095d85c12e642c4204325df16f06943e6d8a1ae82796f4dd91fe71caa31e7e2cf5356b7a96d7ba1a1bd10482b2b06",
    #"a401010327200721582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
    trusted(),
    1,
  ) == None
}

const valid_sign1 =
  #"84582aa201276761646472657373581d6027e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b43a166686173686564f45843aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01005840b98e5f45c6b54500cf64d816928f8bd81ec095d85c12e642c4204325df16f06943e6d8a1ae82796f4dd91fe71caa31e7e2cf5356b7a96d7ba1a1bd10482b2b06"

const valid_key =
  #"a401010327200621582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"

const valid_payload =
  #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0100"

test signature_structure_is_exact_cbor_with_unchunked_payload() {
  signature_structure(#"a0", valid_payload) == bytearray.concat(
    #"846a5369676e61747572653141a0405843",
    valid_payload,
  )
}

test reject_untrusted_issuer_and_unknown_network() {
  and {
    verify(valid_sign1, valid_key, [], 1) == None,
    verify(valid_sign1, valid_key, trusted(), 4) == None,
    verify(valid_sign1, valid_key, trusted(), -1) == None,
    verify(valid_sign1, valid_key, trusted(), 2) == None,
  }
}

test payload_and_header_mutations_fail_signature_verification() {
  // All changes preserve the structural encoding and accepted header schema.
  let changed_payload = bytearray.concat(
    builtin.slice_bytearray(0, 60, valid_sign1),
    bytearray.concat(#"ab", builtin.slice_bytearray(61, 1024, valid_sign1)),
  )
  // The network header changes from testnet to mainnet, with the verifier
  // likewise switched; the remaining failure must be the signature.
  let changed_address = bytearray.concat(
    builtin.slice_bytearray(0, 16, valid_sign1),
    bytearray.concat(#"61", builtin.slice_bytearray(17, 1024, valid_sign1)),
  )
  and {
    verify(changed_payload, valid_key, trusted(), 1) == None,
    verify(changed_address, valid_key, trusted(), 2) == None,
  }
}

test reject_trailing_bytes_truncation_and_wrong_cose_tag() {
  and {
    verify(bytearray.concat(valid_sign1, #"00"), valid_key, trusted(), 1) == None,
    verify(
      builtin.slice_bytearray(0, bytearray.length(valid_sign1) - 1, valid_sign1),
      valid_key,
      trusted(),
      1,
    ) == None,
    verify(bytearray.concat(#"d1", valid_sign1), valid_key, trusted(), 1) == None,
    verify(valid_sign1, bytearray.concat(valid_key, #"00"), trusted(), 1) == None,
    verify(#"", valid_key, trusted(), 1) == None,
  }
}

fn replace_test_byte(input: ByteArray, offset: Int, value: Int) -> ByteArray {
  builtin.append_bytearray(
    builtin.slice_bytearray(0, offset, input),
    builtin.cons_bytearray(
      value,
      builtin.slice_bytearray(offset + 1, bytearray.length(input), input),
    ),
  )
}

test fixed_sign1_headers_require_complete_shortest_envelope() {
  let size = bytearray.length(valid_sign1)
  expect Some(Pair(_, after_protected)) = bytes(valid_sign1, 1)
  expect Some(Pair(_, payload_header)) = read_unprotected(
    valid_sign1,
    after_protected,
  )
  let signature_header = payload_header + 2 + 67
  and {
    // The optional tag must be followed by the canonical four-item array.
    signed(#"d2") == None,
    signed(
      builtin.append_bytearray(
        #"9804",
        builtin.slice_bytearray(1, size, valid_sign1),
      ),
    ) == None,
    // Wrong byte-string type or declared length must fail at either field.
    signed(replace_test_byte(valid_sign1, payload_header, 0x78)) == None,
    signed(replace_test_byte(valid_sign1, payload_header + 1, 0x42)) == None,
    signed(replace_test_byte(valid_sign1, signature_header, 0x78)) == None,
    signed(replace_test_byte(valid_sign1, signature_header + 1, 0x3f)) == None,
    // A valid prefix cannot compensate for a missing header or body byte.
    signed(builtin.slice_bytearray(0, payload_header + 1, valid_sign1)) == None,
    signed(builtin.slice_bytearray(0, signature_header + 1, valid_sign1)) == None,
    signed(builtin.slice_bytearray(0, size - 1, valid_sign1)) == None,
    signed(builtin.append_bytearray(valid_sign1, #"00")) == None,
  }
}

test reject_wrong_and_duplicate_key_parameters() {
  // A map declaring an extra duplicate x remains invalid even with a valid key.
  let duplicate = bytearray.concat(
    #"a5",
    bytearray.concat(
      builtin.slice_bytearray(1, 256, valid_key),
      bytearray.concat(#"215820", test_key),
    ),
  )
  and {
    verify(valid_sign1, duplicate, trusted(), 1) == None,
    verify(valid_sign1, #"a4010203272006215820", trusted(), 1) == None,
    key_ok(
      [
        Pair(Integer(1), Integer(2)),
        Pair(Integer(3), Integer(-8)),
        Pair(Integer(-1), Integer(6)),
        Pair(Integer(-2), Bytes(test_key)),
      ],
    ) == False,
  }
}

test optional_kids_must_be_bytes_and_match_when_both_present() {
  and {
    kids_match([], [], []),
    !kids_match([Pair(Integer(4), Bytes(#"01"))], [], []),
    !kids_match([], [], [Pair(Integer(2), Bytes(#"01"))]),
    kids_match(
      [],
      [Pair(Integer(4), Bytes(#"01"))],
      [Pair(Integer(2), Bytes(#"01"))],
    ),
    !kids_match(
      [Pair(Integer(4), Bytes(#"01"))],
      [],
      [Pair(Integer(2), Bytes(#"02"))],
    ),
    !kids_match(
      [Pair(Integer(4), Bytes(#"01"))],
      [Pair(Integer(4), Bytes(#"01"))],
      [],
    ),
    !optional_kid(Some(Text("kid"))),
  }
}

test headers_reject_unprotected_overrides_unknowns_and_hashed_payloads() {
  and {
    unprotected_ok([]),
    unprotected_ok(
      [Pair(Text("hashed"), Boolean(False)), Pair(Text("version"), Integer(1))],
    ),
    !unprotected_ok([Pair(Text("hashed"), Boolean(True))]),
    !unprotected_ok([Pair(Integer(1), Integer(-8))]),
    !unprotected_ok([Pair(Text("address"), Bytes(#""))]),
    !unprotected_ok([Pair(Text("version"), Integer(2))]),
    !unprotected_ok([Pair(Text("other"), Boolean(False))]),
    !protected_ok([Pair(Integer(1), Integer(-8)), Pair(Integer(2), Integer(1))]),
  }
}

test address_forms_reject_script_credentials_bad_lengths_and_wrong_key_roles() {
  let hash = crypto.blake2b_224(test_key)
  let wrong = #"dddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
  and {
    !address_ok(bytearray.concat(#"70", hash), test_key, 1),
    !address_ok(bytearray.concat(#"f0", hash), test_key, 1),
    !address_ok(
      bytearray.concat(#"10", bytearray.concat(wrong, hash)),
      test_key,
      1,
    ),
    !address_ok(
      bytearray.concat(#"00", bytearray.concat(wrong, hash)),
      test_key,
      1,
    ),
    !address_ok(bytearray.concat(#"00", hash), test_key, 1),
    !address_ok(
      bytearray.concat(#"60", bytearray.concat(hash, #"00")),
      test_key,
      1,
    ),
    !address_ok(
      bytearray.concat(#"40", bytearray.concat(hash, #"0000")),
      test_key,
      1,
    ),
    !address_ok(bytearray.concat(#"80", hash), test_key, 1),
    !address_ok(bytearray.concat(#"90", hash), test_key, 1),
  }
}

test all_explicit_kyc_network_mappings() {
  let hash = crypto.blake2b_224(test_key)
  and {
    address_ok(bytearray.concat(#"60", hash), test_key, 0),
    address_ok(bytearray.concat(#"60", hash), test_key, 1),
    address_ok(bytearray.concat(#"60", hash), test_key, 3),
    address_ok(bytearray.concat(#"61", hash), test_key, 2),
    !address_ok(bytearray.concat(#"61", hash), test_key, 1),
    !address_ok(bytearray.concat(#"62", hash), test_key, 2),
  }
}

fn with_unprotected(original: ByteArray, unprotected: ByteArray) -> ByteArray {
  expect Some(message) = signed(original)
  bytearray.concat(
    #"84",
    bytearray.concat(
      encode_bytes(message.protected),
      bytearray.concat(
        unprotected,
        bytearray.concat(
          encode_bytes(message.payload),
          encode_bytes(message.signature),
        ),
      ),
    ),
  )
}

test absent_hashed_and_optional_version_are_accepted() {
  and {
    verify(with_unprotected(valid_sign1, #"a0"), valid_key, trusted(), 1) == Some(
      valid_payload,
    ),
    verify(
      with_unprotected(valid_sign1, #"a16776657273696f6e01"),
      valid_key,
      trusted(),
      1,
    ) == Some(valid_payload),
    verify(
      with_unprotected(valid_sign1, #"a166686173686564f5"),
      valid_key,
      trusted(),
      1,
    ) == None,
  }
}

test one_sided_kids_are_rejected() {
  let key_only = bytearray.concat(
    #"a5",
    bytearray.concat(builtin.slice_bytearray(1, 256, valid_key), #"024101"),
  )
  and {
    verify(valid_sign1, key_only, trusted(), 1) == None,
    verify(with_unprotected(valid_sign1, #"a1044101"), valid_key, trusted(), 1) == None,
    verify(with_unprotected(valid_sign1, #"a1044102"), key_only, trusted(), 1) == None,
  }
}

test protected_only_kid_and_duplicate_kid_rejected() {
  let kid_sign1 = #"84584aa301276761646472657373581d6027e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b4304581d6027e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b43a166686173686564f45843aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01005840af5b0e22ea7e5aabdcbcd38339c48e96e20ddf76686f695909b58d4c842e58f8559d8550a0a9ac35efbd1446b955be1dc0a336d511ec0fef4d15ff30dba8e007"
  and {
    verify(kid_sign1, valid_key, trusted(), 1) == None,
    verify(with_unprotected(kid_sign1, #"a1044101"), valid_key, trusted(), 1) == None,
  }
}

// The original generic decoder and profile predicates above remain a test
// oracle. They are not reachable from verify and do not enter its script.
fn oracle_kid(fields: Pairs<Scalar, Scalar>, label: Int) -> Option<ByteArray> {
  when pairs.get_first(fields, Integer(label)) is {
    Some(Bytes(value)) -> Some(value)
    _ -> None
  }
}

fn oracle_protected(input: ByteArray) -> Option<Fields> {
  when complete_map(input) is {
    Some(fields) ->
      if protected_ok(fields) {
        when pairs.get_first(fields, Text("address")) is {
          Some(Bytes(value)) ->
            Some(Fields { value, kid: oracle_kid(fields, 4) })
          _ -> None
        }
      } else {
        None
      }
    None -> None
  }
}

fn oracle_key(input: ByteArray) -> Option<Fields> {
  when complete_map(input) is {
    Some(fields) ->
      if key_ok(fields) {
        when pairs.get_first(fields, Integer(-2)) is {
          Some(Bytes(value)) ->
            Some(Fields { value, kid: oracle_kid(fields, 2) })
          _ -> None
        }
      } else {
        None
      }
    None -> None
  }
}

fn oracle_unprotected(
  input: ByteArray,
  offset: Int,
) -> Option<Pair<Option<ByteArray>, Int>> {
  when map(input, offset) is {
    Some(Pair(fields, end)) ->
      if unprotected_ok(fields) {
        Some(Pair(oracle_kid(fields, 4), end))
      } else {
        None
      }
    None -> None
  }
}

fn encoded_map(fields: List<ByteArray>) -> ByteArray {
  builtin.cons_bytearray(
    0xa0 + list.length(fields),
    list.foldr(fields, #"", bytearray.concat),
  )
}

fn insert_everywhere(value: a, items: List<a>) -> List<List<a>> {
  when items is {
    [] -> [[value]]
    [first, ..rest] ->
      [
        [value, ..items],
        ..list.map(insert_everywhere(value, rest), fn(tail) { [first, ..tail] })
      ]
  }
}

fn permutations(items: List<a>) -> List<List<a>> {
  when items is {
    [] -> [[]]
    [first, ..rest] ->
      list.flat_map(
        permutations(rest),
        fn(tail) { insert_everywhere(first, tail) },
      )
  }
}

fn subsets(items: List<a>) -> List<List<a>> {
  when items is {
    [] -> [[]]
    [first, ..rest] -> {
      let without = subsets(rest)
      list.concat(without, list.map(without, fn(tail) { [first, ..tail] }))
    }
  }
}

fn protected_test_fields() -> List<ByteArray> {
  [#"0127", #"67616464726573734100"]
}

fn key_test_fields() -> List<ByteArray> {
  [#"0101", #"0327", #"2006", bytearray.concat(#"215820", test_key)]
}

test streaming_protected_accepts_all_orders_and_optional_kid() {
  list.all(
    [[], [#"0440"], [#"04420102"]],
    fn(optional) {
      list.all(
        permutations(list.concat(protected_test_fields(), optional)),
        fn(fields) {
          let input = encoded_map(fields)
          let expected = oracle_protected(input)
          expected != None && read_protected(input) == expected
        },
      )
    },
  )
}

test streaming_key_accepts_all_orders_and_optional_kid() {
  list.all(
    [[], [#"0240"], [#"02420102"]],
    fn(optional) {
      list.all(
        permutations(list.concat(key_test_fields(), optional)),
        fn(fields) {
          let input = encoded_map(fields)
          let expected = oracle_key(input)
          expected != None && read_key(input) == expected
        },
      )
    },
  )
}

test streaming_unprotected_accepts_all_subsets_orders_and_offsets() {
  list.all(
    subsets([#"66686173686564f4", #"6776657273696f6e01", #"0440"]),
    fn(fields) {
      list.all(
        permutations(fields),
        fn(ordered) {
          let input = encoded_map(ordered)
          let embedded = bytearray.concat(
            #"ff00",
            bytearray.concat(input, #"ff"),
          )
          let expected = oracle_unprotected(input, 0)
          and {
            expected != None,
            read_unprotected(input, 0) == expected,
            read_unprotected(embedded, 2) == oracle_unprotected(embedded, 2),
          }
        },
      )
    },
  )
}

test streaming_readers_reject_every_duplicate_and_missing_required_field() {
  let protected = protected_test_fields()
  let key = key_test_fields()
  let unprotected = [#"66686173686564f4", #"6776657273696f6e01", #"0440"]
  and {
    read_protected(encoded_map([#"0440", #"0440", ..protected])) == None,
    read_key(encoded_map([#"0240", #"0240", ..key])) == None,
    list.all(
      protected,
      fn(field) {
        let input = encoded_map([field, ..protected])
        oracle_protected(input) == None && read_protected(input) == None
      },
    ),
    list.all(
      protected,
      fn(field) {
        let input = encoded_map(list.delete(protected, field))
        oracle_protected(input) == None && read_protected(input) == None
      },
    ),
    list.all(
      key,
      fn(field) {
        let input = encoded_map([field, ..key])
        oracle_key(input) == None && read_key(input) == None
      },
    ),
    list.all(
      key,
      fn(field) {
        let input = encoded_map(list.delete(key, field))
        oracle_key(input) == None && read_key(input) == None
      },
    ),
    list.all(
      unprotected,
      fn(field) {
        let input = encoded_map([field, field])
        oracle_unprotected(input, 0) == None && read_unprotected(input, 0) == None
      },
    ),
  }
}

test streaming_kid_limits_preserve_absence_and_empty_bytes() {
  list.all(
    [0, 1, 23, 24, 127, 128, 129],
    fn(size) {
      let value = builtin.replicate_byte(size, 0)
      let protected = encoded_map(
        [
          bytearray.concat(#"04", encode_bytes(value)),
          ..protected_test_fields()
        ],
      )
      let key = encoded_map(
        [bytearray.concat(#"02", encode_bytes(value)), ..key_test_fields()],
      )
      let unprotected = encoded_map(
        [bytearray.concat(#"04", encode_bytes(value))],
      )
      and {
        read_protected(protected) == oracle_protected(protected),
        read_key(key) == oracle_key(key),
        read_unprotected(unprotected, 0) == oracle_unprotected(unprotected, 0),
        read_protected(protected) != None == ( size <= 128 ),
        read_key(key) != None == ( size <= 128 ),
        read_unprotected(unprotected, 0) != None == ( size <= 128 ),
      }
    },
  )
}

fn kid_fields(kid: Option<ByteArray>, label: Int) -> Pairs<Scalar, Scalar> {
  when kid is {
    None -> []
    Some(value) -> [Pair(Integer(label), Bytes(value))]
  }
}

test streaming_kid_matching_agrees_for_every_presence_and_value_combination() {
  let variants = [None, Some(#""), Some(#"00"), Some(#"01")]
  list.all(
    variants,
    fn(protected) {
      list.all(
        variants,
        fn(unprotected) {
          list.all(
            variants,
            fn(key) {
              matching_kids(protected, unprotected, key) == kids_match(
                kid_fields(protected, 4),
                kid_fields(unprotected, 4),
                kid_fields(key, 2),
              )
            },
          )
        },
      )
    },
  )
}

test streaming_readers_match_oracle_on_truncations_and_trailing_bytes() {
  let protected = encoded_map([#"0440", ..protected_test_fields()])
  let key = encoded_map([#"0240", ..key_test_fields()])
  let unprotected = encoded_map(
    [#"66686173686564f4", #"6776657273696f6e01", #"0440"],
  )
  and {
    list.all(
      list.range(0, bytearray.length(protected) - 1),
      fn(size) {
        let input = builtin.slice_bytearray(0, size, protected)
        oracle_protected(input) == None && read_protected(input) == None
      },
    ),
    list.all(
      list.range(0, bytearray.length(key) - 1),
      fn(size) {
        let input = builtin.slice_bytearray(0, size, key)
        oracle_key(input) == None && read_key(input) == None
      },
    ),
    list.all(
      list.range(0, bytearray.length(unprotected) - 1),
      fn(size) {
        let input = builtin.slice_bytearray(0, size, unprotected)
        oracle_unprotected(input, 0) == None && read_unprotected(input, 0) == None
      },
    ),
    read_protected(bytearray.concat(protected, #"00")) == None,
    read_key(bytearray.concat(key, #"00")) == None,
    read_unprotected(bytearray.concat(unprotected, #"00"), 0) == Some(
      Pair(Some(#""), bytearray.length(unprotected)),
    ),
    read_unprotected(unprotected, -1) == None,
    read_unprotected(unprotected, bytearray.length(unprotected)) == None,
  }
}

test streaming_readers_match_oracle_on_wrong_types_and_nonminimal_cbor() {
  let malformed_fields = [
    #"011827", #"0126", #"0101", #"016127", #"018127", #"01a0", #"181827",
    #"180127", #"0301", #"0326", #"032818", #"2007", #"380006", #"0441",
    #"044101", #"04616b", #"04f4", #"045800", #"04590000", #"0240", #"02616b",
    #"024101", #"2140", #"21581f", #"215821", #"2180", #"66686173686564f5",
    #"66686173686564f814", #"6668617368656400", #"6776657273696f6e00",
    #"6776657273696f6e1801", #"6776657273696f6e20", #"676164647265737360",
    #"676164647265737380", #"67616464726573735800", #"58186164647265737340",
    #"476164647265737340", #"656f7468657201",
  ]
  and {
    list.all(
      malformed_fields,
      fn(field) {
        let protected = encoded_map([field, ..protected_test_fields()])
        let key = encoded_map([field, ..key_test_fields()])
        let unprotected = encoded_map([field])
        and {
          read_protected(protected) == oracle_protected(protected),
          read_key(key) == oracle_key(key),
          read_unprotected(unprotected, 0) == oracle_unprotected(unprotected, 0),
        }
      },
    ),
    list.all(
      [#"b800", #"b90000", #"bf", #"80", #"a7", #"a0ff"],
      fn(input) {
        and {
          read_protected(input) == oracle_protected(input),
          read_key(input) == oracle_key(input),
          read_unprotected(input, 0) == oracle_unprotected(input, 0),
        }
      },
    ),
  }
}

test streaming_readers_match_oracle_on_byte_mutations(
  mutation via fuzz.tuple3(
    fuzz.int_between(0, 2),
    fuzz.int_between(0, 255),
    fuzz.byte(),
  ),
) {
  let (profile, position, value) = mutation
  let original = when profile is {
    0 -> encoded_map([#"0440", ..protected_test_fields()])
    1 -> encoded_map([#"0240", ..key_test_fields()])
    _ -> encoded_map([#"66686173686564f4", #"6776657273696f6e01", #"0440"])
  }
  let offset = position % ( bytearray.length(original) + 1 )
  let input = bytearray.concat(
    bytearray.take(original, offset),
    builtin.cons_bytearray(value, bytearray.drop(original, offset + 1)),
  )
  when profile is {
    0 -> read_protected(input) == oracle_protected(input)
    1 -> read_key(input) == oracle_key(input)
    _ -> read_unprotected(input, 0) == oracle_unprotected(input, 0)
  }
}

test direct_byte_reader_preserves_lengths_types_and_offsets() {
  let samples = list.concat(
    list.map(
      [0, 1, 23, 24, 255, 256],
      fn(size) { encode_bytes(builtin.replicate_byte(size, 0)) },
    ),
    [
      #"", #"00", #"20", #"60", #"80", #"a0", #"f4", #"41", #"58", #"5901",
      #"5817", #"5900ff", #"5a00000100", #"5f40ff", #"430102",
    ],
  )
  list.all(
    samples,
    fn(input) {
      list.all(
        [-1, 0, 1, bytearray.length(input)],
        fn(offset) {
          let expected = when scalar(input, offset) is {
            Some(Pair(Bytes(value), end)) -> Some(Pair(value, end))
            _ -> None
          }
          bytes(input, offset) == expected
        },
      )
    },
  )
}
