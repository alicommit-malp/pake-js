import { RistrettoPoint, ed25519 } from "@noble/curves/ed25519";
import { sha512 } from "@noble/hashes/sha2";
import {
  concat,
  ctEqual,
  leb128,
  lvCat,
  oCat,
  zeroBytes,
} from "../util/bytes.js";
import { randomBytes } from "../util/random.js";

// CPace over Ristretto255 with SHA-512, per draft-irtf-cfrg-cpace-20 §7.3.
// All protocol constants, length encodings, and transcript formulas below are
// copied from the draft text literally. Do not modify without spec review.

const DSI = new TextEncoder().encode("CPaceRistretto255");
const DSI_ISK = new TextEncoder().encode("CPaceRistretto255_ISK");
const HASH_BLOCK_BYTES = 128; // SHA-512 block size (s_in_bytes in the draft)
const FIELD_BYTES = 32; // Ristretto255 encoding length
const HASH_TO_CURVE_BYTES = 2 * FIELD_BYTES; // 64 bytes fed to RistrettoPoint.hashToCurve
const SCALAR_BYTES = 32;
const ORDER: bigint = ed25519.CURVE.n;

type RPoint = InstanceType<typeof RistrettoPoint>;

/**
 * draft-irtf-cfrg-cpace-20 §4.2 generator_string:
 *
 *   def generator_string(DSI, PRS, CI, sid, s_in_bytes):
 *       len_zpad = max(0, s_in_bytes - 1
 *                        - len(prepend_len(PRS))
 *                        - len(prepend_len(DSI)))
 *       return lv_cat(DSI, PRS, zero_bytes(len_zpad), CI, sid)
 */
function generatorString(
  PRS: Uint8Array,
  CI: Uint8Array,
  sid: Uint8Array,
): Uint8Array {
  const prependLenDsi = leb128(DSI.length).length + DSI.length;
  const prependLenPrs = leb128(PRS.length).length + PRS.length;
  const lenZpad = Math.max(
    0,
    HASH_BLOCK_BYTES - 1 - prependLenPrs - prependLenDsi,
  );
  return lvCat(DSI, PRS, zeroBytes(lenZpad), CI, sid);
}

/**
 * draft-irtf-cfrg-cpace-20 §4.3 calculate_generator: hash generator_string to
 * `2 * field_size_bytes` = 64 uniform bytes and feed to Ristretto255's one-way
 * map (RFC 9496 §4).
 */
function calculateGenerator(
  PRS: Uint8Array,
  CI: Uint8Array,
  sid: Uint8Array,
): RPoint {
  const genStr = generatorString(PRS, CI, sid);
  const h = sha512(genStr);
  // sha512 outputs 64 bytes, which is exactly HASH_TO_CURVE_BYTES.
  if (h.length !== HASH_TO_CURVE_BYTES) {
    throw new Error(
      "cpace/ristretto255: unexpected SHA-512 output length (impossible)",
    );
  }
  return RistrettoPoint.hashToCurve(h);
}

/**
 * draft-irtf-cfrg-cpace-20 §4.1 sample_scalar for Ristretto255: uniformly at
 * random in [1, L-1] where L is the ed25519 subgroup order. We oversample by
 * 16 bytes for k=64 bits of statistical distance.
 */
function sampleScalar(): bigint {
  for (let tries = 0; tries < 64; tries++) {
    const bytes = randomBytes(SCALAR_BYTES + 16);
    let x = 0n;
    for (let i = bytes.length - 1; i >= 0; i--) {
      x = (x << 8n) | BigInt(bytes[i] as number);
    }
    const s = x % ORDER;
    if (s !== 0n) return s;
  }
  throw new Error("cpace/ristretto255: failed to sample non-zero scalar");
}

function scalarToLeBytes(s: bigint): Uint8Array {
  if (s < 0n || s >= ORDER) {
    throw new RangeError("cpace/ristretto255: scalar out of range [0, L)");
  }
  const out = new Uint8Array(SCALAR_BYTES);
  let x = s;
  for (let i = 0; i < SCALAR_BYTES; i++) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function leBytesToScalar(b: Uint8Array): bigint {
  if (b.length !== SCALAR_BYTES) {
    throw new Error("cpace/ristretto255: scalar must be 32 bytes");
  }
  let x = 0n;
  for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i] as number);
  return x;
}

function encodePoint(p: RPoint): Uint8Array {
  return p.toRawBytes();
}

function decodePointOrNull(b: Uint8Array): RPoint | null {
  try {
    return RistrettoPoint.fromHex(b);
  } catch {
    return null;
  }
}

// draft-irtf-cfrg-cpace-20 §4.4 scalar_mult_vfy: returns encode(y * decode(X))
// and signals abort if the result is the identity encoding.
function scalarMultVfy(scalar: bigint, peerEncoded: Uint8Array): Uint8Array {
  const P = decodePointOrNull(peerEncoded);
  if (P === null) {
    throw new Error(
      "cpace/ristretto255: peer share failed Ristretto255 decoding",
    );
  }
  const K = P.multiply(scalar);
  if (K.equals(RistrettoPoint.ZERO)) {
    throw new Error("cpace/ristretto255: K is the neutral element (abort)");
  }
  return encodePoint(K);
}

/**
 * Output of `init()`. The caller MUST keep `ephemeralSecret` private on the
 * local side — it is the scalar used to form this party's public share. Send
 * `share` (and any associated data) to the peer.
 */
export interface CPaceInit {
  ephemeralSecret: Uint8Array;
  share: Uint8Array;
}

export interface CPaceInputs {
  /** PRS — Password-Related String. Derive from a password via an MHF first. */
  PRS: Uint8Array;
  /** sid — Session ID, agreed by both parties out-of-band. */
  sid: Uint8Array;
  /** CI — Channel Identifier (optional, empty means no binding). */
  CI?: Uint8Array;
}

/**
 * Begin a CPace exchange. Produces the local ephemeral secret and the public
 * share to send to the peer.
 */
export function init(inputs: CPaceInputs): CPaceInit {
  return __initWithScalar(inputs, sampleScalar());
}

/**
 * @internal — deterministic CPace init for vector tests. Not part of the
 * public API. Do not use with a caller-supplied scalar in production code.
 */
export function __initWithScalar(
  inputs: CPaceInputs,
  scalar: bigint,
): CPaceInit {
  const { PRS, sid } = inputs;
  const CI = inputs.CI ?? new Uint8Array(0);
  if (scalar === 0n || scalar >= ORDER) {
    throw new Error("cpace/ristretto255: invalid scalar");
  }
  const g = calculateGenerator(PRS, CI, sid);
  const Y = g.multiply(scalar);
  if (Y.equals(RistrettoPoint.ZERO)) {
    throw new Error("cpace/ristretto255: generated identity share (abort)");
  }
  return { ephemeralSecret: scalarToLeBytes(scalar), share: encodePoint(Y) };
}

/**
 * @internal — exposes calculate_generator for B.3.1 test vectors.
 * Returns the encoded 32-byte Ristretto255 point.
 */
export function __calculateGeneratorEncoded(
  PRS: Uint8Array,
  CI: Uint8Array,
  sid: Uint8Array,
): Uint8Array {
  return encodePoint(calculateGenerator(PRS, CI, sid));
}

/**
 * @internal — exposes generator_string for B.3.1 test vectors.
 * Returns the pre-hash octet string.
 */
export function __generatorString(
  PRS: Uint8Array,
  CI: Uint8Array,
  sid: Uint8Array,
): Uint8Array {
  return generatorString(PRS, CI, sid);
}

/**
 * @internal — exposes scalar_mult_vfy for B.3.10/B.3.11 test vectors.
 * Throws on decode failure or identity result (matching draft semantics of
 * "return G.I and abort").
 */
export function __scalarMultVfy(
  scalarLE: Uint8Array,
  peerEncoded: Uint8Array,
): Uint8Array {
  return scalarMultVfy(leBytesToScalar(scalarLE), peerEncoded);
}

export interface InitiatorResponderParams {
  /** Own ephemeral secret returned from `init()`. */
  ephemeralSecret: Uint8Array;
  /** Own public share returned from `init()`. */
  ownShare: Uint8Array;
  /** Peer's public share. */
  peerShare: Uint8Array;
  /** Own associated data sent alongside `ownShare`. Empty by default. */
  ownAD?: Uint8Array;
  /** Peer's associated data. Empty by default. */
  peerAD?: Uint8Array;
  /** Session ID (must match the value passed to `init`). */
  sid: Uint8Array;
  /**
   * Role in the initiator-responder transcript. The initiator's (share, AD)
   * goes first. Symmetric mode is available via `deriveIskSymmetric`.
   */
  role: "initiator" | "responder";
}

/**
 * draft-irtf-cfrg-cpace-20 §4.5 initiator-responder ISK:
 *
 *   ISK = H.hash( lv_cat(G.DSI || b"_ISK", sid, K)
 *                 || lv_cat(Ya, ADa) || lv_cat(Yb, ADb) )
 */
export function deriveIskInitiatorResponder(
  p: InitiatorResponderParams,
): Uint8Array {
  const ownAD = p.ownAD ?? new Uint8Array(0);
  const peerAD = p.peerAD ?? new Uint8Array(0);
  const scalar = leBytesToScalar(p.ephemeralSecret);
  const K = scalarMultVfy(scalar, p.peerShare);

  let firstShare: Uint8Array;
  let firstAD: Uint8Array;
  let secondShare: Uint8Array;
  let secondAD: Uint8Array;
  if (p.role === "initiator") {
    firstShare = p.ownShare;
    firstAD = ownAD;
    secondShare = p.peerShare;
    secondAD = peerAD;
  } else {
    firstShare = p.peerShare;
    firstAD = peerAD;
    secondShare = p.ownShare;
    secondAD = ownAD;
  }

  const prefix = lvCat(DSI_ISK, p.sid, K);
  const transcript = concat(
    lvCat(firstShare, firstAD),
    lvCat(secondShare, secondAD),
  );
  return sha512(concat(prefix, transcript));
}

export interface SymmetricParams {
  ephemeralSecret: Uint8Array;
  ownShare: Uint8Array;
  peerShare: Uint8Array;
  ownAD?: Uint8Array;
  peerAD?: Uint8Array;
  sid: Uint8Array;
}

/**
 * draft-irtf-cfrg-cpace-20 §4.5 symmetric ISK:
 *
 *   ISK = H.hash( lv_cat(G.DSI || b"_ISK", sid, K)
 *                 || o_cat(lv_cat(Ya, ADa), lv_cat(Yb, ADb)) )
 *
 * `o_cat` concatenates its two arguments in lexicographic order of the first
 * differing byte, yielding an order-independent transcript.
 */
export function deriveIskSymmetric(p: SymmetricParams): Uint8Array {
  const ownAD = p.ownAD ?? new Uint8Array(0);
  const peerAD = p.peerAD ?? new Uint8Array(0);
  const scalar = leBytesToScalar(p.ephemeralSecret);
  const K = scalarMultVfy(scalar, p.peerShare);

  const mine = lvCat(p.ownShare, ownAD);
  const theirs = lvCat(p.peerShare, peerAD);
  const prefix = lvCat(DSI_ISK, p.sid, K);
  return sha512(concat(prefix, oCat(mine, theirs)));
}

/** Constant-time comparison of two ISKs (e.g. for test assertions). */
export function iskEqual(a: Uint8Array, b: Uint8Array): boolean {
  return ctEqual(a, b);
}

export const SUITE_NAME = "CPACE-RISTR255-SHA512";
