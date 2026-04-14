import {
  hashOf,
  hashOutputLength,
  hkdfOf,
  hmacOf,
  type HashName,
} from "../util/kdf.js";
import { concat, lvU64, utf8 } from "../util/bytes.js";

/**
 * RFC 9383 §4 transcript construction.
 *
 *   TT = len(Context)    || Context
 *     || len(idProver)   || idProver
 *     || len(idVerifier) || idVerifier
 *     || len(M)          || M
 *     || len(N)          || N
 *     || len(shareP)     || shareP
 *     || len(shareV)     || shareV
 *     || len(Z)          || Z
 *     || len(V)          || V
 *     || len(w0)         || w0
 *
 * All length prefixes are 8-byte little-endian per RFC 9383.
 */
export function transcript(p: {
  context: Uint8Array;
  idProver: Uint8Array;
  idVerifier: Uint8Array;
  M: Uint8Array;
  N: Uint8Array;
  shareP: Uint8Array;
  shareV: Uint8Array;
  Z: Uint8Array;
  V: Uint8Array;
  w0: Uint8Array;
}): Uint8Array {
  return concat(
    lvU64(p.context),
    lvU64(p.idProver),
    lvU64(p.idVerifier),
    lvU64(p.M),
    lvU64(p.N),
    lvU64(p.shareP),
    lvU64(p.shareV),
    lvU64(p.Z),
    lvU64(p.V),
    lvU64(p.w0),
  );
}

/**
 * RFC 9383 §4 key schedule.
 *
 *   K_main                  = Hash(TT)
 *   K_confirmP || K_confirmV = KDF(nil, K_main, "ConfirmationKeys")
 *   K_shared                 = KDF(nil, K_main, "SharedKey")
 *
 * KDF is HKDF-Extract-then-Expand [RFC 5869] with the specified hash.
 */
export function keySchedule(
  hash: HashName,
  TT: Uint8Array,
): {
  K_main: Uint8Array;
  K_confirmP: Uint8Array;
  K_confirmV: Uint8Array;
  K_shared: Uint8Array;
} {
  const hLen = hashOutputLength(hash);
  const K_main = hashOf(hash, TT);
  const salt = new Uint8Array(0);
  const confirmKeys = hkdfOf(
    hash,
    K_main,
    salt,
    utf8("ConfirmationKeys"),
    2 * hLen,
  );
  const K_confirmP = confirmKeys.slice(0, hLen);
  const K_confirmV = confirmKeys.slice(hLen);
  const K_shared = hkdfOf(hash, K_main, salt, utf8("SharedKey"), hLen);
  return { K_main, K_confirmP, K_confirmV, K_shared };
}

/**
 * RFC 9383 key confirmation:
 *   confirmP = MAC(K_confirmP, shareV)
 *   confirmV = MAC(K_confirmV, shareP)
 */
export function computeConfirmations(
  hash: HashName,
  K_confirmP: Uint8Array,
  K_confirmV: Uint8Array,
  shareP: Uint8Array,
  shareV: Uint8Array,
): { confirmP: Uint8Array; confirmV: Uint8Array } {
  return {
    confirmP: hmacOf(hash, K_confirmP, shareV),
    confirmV: hmacOf(hash, K_confirmV, shareP),
  };
}
