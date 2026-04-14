import { p256 } from "@noble/curves/p256";
import { randomBytes } from "../util/random.js";
import { ctEqual } from "../util/bytes.js";
import { computeConfirmations, keySchedule, transcript } from "./core.js";

// RFC 9383 §4 ciphersuite: SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256.
// M and N are the fixed group elements registered in RFC 9383 for the P-256
// ciphersuite; they are compressed SEC1 encodings. These bytes are part of the
// on-wire protocol — DO NOT MODIFY WITHOUT SPEC REVIEW.
const M_COMPRESSED_HEX =
  "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f";
const N_COMPRESSED_HEX =
  "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49";

const Point = p256.ProjectivePoint;
type P256Point = InstanceType<typeof p256.ProjectivePoint>;

const M: P256Point = Point.fromHex(M_COMPRESSED_HEX);
const N: P256Point = Point.fromHex(N_COMPRESSED_HEX);
const ORDER: bigint = p256.CURVE.n;
const SCALAR_BYTES = 32;

// RFC 9383 transcript encoding for P-256 uses uncompressed SEC1 (0x04 || x || y),
// matching the "Serialize" function of §4.
function encodePoint(p: P256Point): Uint8Array {
  return p.toRawBytes(false);
}

function decodePoint(b: Uint8Array): P256Point {
  const p = Point.fromHex(b);
  // fromHex validates the point is on-curve and not identity.
  return p;
}

function beBytesToScalar(b: Uint8Array): bigint {
  let x = 0n;
  for (let i = 0; i < b.length; i++) x = (x << 8n) | BigInt(b[i] as number);
  return x;
}

function scalarToBeBytes(s: bigint): Uint8Array {
  if (s < 0n || s >= ORDER) {
    throw new RangeError("spake2plus/p256: scalar out of range [0, n)");
  }
  const out = new Uint8Array(SCALAR_BYTES);
  let x = s;
  for (let i = SCALAR_BYTES - 1; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function reduceMod(b: Uint8Array): Uint8Array {
  return scalarToBeBytes(beBytesToScalar(b) % ORDER);
}

// RFC 9383 §4: draw ephemeral scalars uniformly from [1, n-1]. We oversample
// by 16 bytes (k=64 bits of statistical distance) to match RFC guidance.
function sampleScalar(): bigint {
  for (let tries = 0; tries < 64; tries++) {
    const bytes = randomBytes(SCALAR_BYTES + 16);
    const s = beBytesToScalar(bytes) % ORDER;
    if (s !== 0n) return s;
  }
  throw new Error("spake2plus/p256: failed to sample non-zero scalar");
}

/**
 * Derive (w0, w1) from a memory-hard function output per RFC 9383 §4.
 *
 * The caller is expected to run a password-hashing KDF (scrypt, Argon2id, or
 * PBKDF2 with a strong iteration count) over
 *   len(pw) || pw || len(idProver) || idProver || len(idVerifier) || idVerifier
 * and pass the resulting bytes here. pake-js intentionally does not bundle an
 * MHF so that applications can choose one appropriate for their platform.
 *
 * `mhfOutput.length` must be >= 80 (2 * (32 + 8)) to provide the k=64-bit
 * safety margin required by the RFC for uniform reduction modulo the group
 * order.
 */
export function deriveScalars(mhfOutput: Uint8Array): {
  w0: Uint8Array;
  w1: Uint8Array;
} {
  if (mhfOutput.length < 80 || mhfOutput.length % 2 !== 0) {
    throw new Error(
      "spake2plus/p256: MHF output must be an even length >= 80 bytes",
    );
  }
  const half = mhfOutput.length >>> 1;
  return {
    w0: reduceMod(mhfOutput.subarray(0, half)),
    w1: reduceMod(mhfOutput.subarray(half)),
  };
}

/** Server-side registration: compute L = w1 * G. Store (w0, L). */
export function registerVerifier(w1: Uint8Array): Uint8Array {
  const s = beBytesToScalar(w1);
  if (s === 0n || s >= ORDER) {
    throw new Error("spake2plus/p256: invalid w1");
  }
  return encodePoint(Point.BASE.multiply(s));
}

export interface ClientStart {
  x: Uint8Array;
  shareP: Uint8Array;
}

/** Client begins the exchange. shareP is sent to the server. */
export function clientStart(w0: Uint8Array): ClientStart {
  return __clientStartWithScalar(w0, sampleScalar());
}

/**
 * @internal — deterministic client start for vector tests. Not part of the
 * public API. Do not use with a caller-supplied scalar in production code;
 * protocol security requires a freshly sampled, secret scalar each session.
 */
export function __clientStartWithScalar(
  w0: Uint8Array,
  xs: bigint,
): ClientStart {
  const w0s = beBytesToScalar(w0);
  if (w0s === 0n || w0s >= ORDER) {
    throw new Error("spake2plus/p256: invalid w0");
  }
  if (xs === 0n || xs >= ORDER) {
    throw new Error("spake2plus/p256: invalid x");
  }
  const X = Point.BASE.multiply(xs).add(M.multiply(w0s));
  return { x: scalarToBeBytes(xs), shareP: encodePoint(X) };
}

export interface ServerRespond {
  y: Uint8Array;
  shareV: Uint8Array;
  Z: Uint8Array;
  V: Uint8Array;
}

/** Server processes the client's shareP and returns shareV + internal (Z,V). */
export function serverRespond(params: {
  w0: Uint8Array;
  L: Uint8Array;
  shareP: Uint8Array;
}): ServerRespond {
  return __serverRespondWithScalar(params, sampleScalar());
}

/**
 * @internal — deterministic server respond for vector tests. Not part of the
 * public API.
 */
export function __serverRespondWithScalar(
  params: { w0: Uint8Array; L: Uint8Array; shareP: Uint8Array },
  ys: bigint,
): ServerRespond {
  const w0s = beBytesToScalar(params.w0);
  if (w0s === 0n || w0s >= ORDER) {
    throw new Error("spake2plus/p256: invalid w0");
  }
  if (ys === 0n || ys >= ORDER) {
    throw new Error("spake2plus/p256: invalid y");
  }
  const L = decodePoint(params.L);
  const X = decodePoint(params.shareP);
  const Y = Point.BASE.multiply(ys).add(N.multiply(w0s));
  // Z = y * (X - w0*M);  V = y * L  (cofactor h = 1 for P-256)
  const XminusW0M = X.add(M.multiply(w0s).negate());
  const Z = XminusW0M.multiply(ys);
  const V = L.multiply(ys);
  assertNonIdentity(Z);
  assertNonIdentity(V);
  return {
    y: scalarToBeBytes(ys),
    shareV: encodePoint(Y),
    Z: encodePoint(Z),
    V: encodePoint(V),
  };
}

export interface ClientFinish {
  Z: Uint8Array;
  V: Uint8Array;
}

/** Client processes the server's shareV and computes (Z, V). */
export function clientFinish(params: {
  w0: Uint8Array;
  w1: Uint8Array;
  x: Uint8Array;
  shareV: Uint8Array;
}): ClientFinish {
  const w0s = beBytesToScalar(params.w0);
  const w1s = beBytesToScalar(params.w1);
  const xs = beBytesToScalar(params.x);
  if (w0s === 0n || w1s === 0n || xs === 0n) {
    throw new Error("spake2plus/p256: zero scalar");
  }
  const Y = decodePoint(params.shareV);
  const YminusW0N = Y.add(N.multiply(w0s).negate());
  const Z = YminusW0N.multiply(xs);
  const V = YminusW0N.multiply(w1s);
  assertNonIdentity(Z);
  assertNonIdentity(V);
  return { Z: encodePoint(Z), V: encodePoint(V) };
}

export interface FinalKeys {
  K_main: Uint8Array;
  K_confirmP: Uint8Array;
  K_confirmV: Uint8Array;
  K_shared: Uint8Array;
  confirmP: Uint8Array;
  confirmV: Uint8Array;
}

/**
 * Build the transcript, run the RFC 9383 key schedule, and compute the pair of
 * key-confirmation MACs. Callers send `confirmP`/`confirmV` to the peer and
 * compare the received value with `verifyConfirmation` (constant-time).
 */
export function deriveKeys(params: {
  context: Uint8Array;
  idProver: Uint8Array;
  idVerifier: Uint8Array;
  w0: Uint8Array;
  shareP: Uint8Array;
  shareV: Uint8Array;
  Z: Uint8Array;
  V: Uint8Array;
}): FinalKeys {
  const TT = transcript({
    context: params.context,
    idProver: params.idProver,
    idVerifier: params.idVerifier,
    M: encodePoint(M),
    N: encodePoint(N),
    shareP: params.shareP,
    shareV: params.shareV,
    Z: params.Z,
    V: params.V,
    w0: params.w0,
  });
  const ks = keySchedule("sha256", TT);
  const conf = computeConfirmations(
    "sha256",
    ks.K_confirmP,
    ks.K_confirmV,
    params.shareP,
    params.shareV,
  );
  return { ...ks, ...conf };
}

/** Constant-time MAC comparison. Use for incoming confirmP/confirmV. */
export function verifyConfirmation(
  expected: Uint8Array,
  received: Uint8Array,
): boolean {
  return ctEqual(expected, received);
}

function assertNonIdentity(p: P256Point): void {
  if (p.equals(Point.ZERO)) {
    throw new Error("spake2plus/p256: degenerate point (identity)");
  }
}

export const SUITE_NAME = "SPAKE2PLUS-P256-SHA256-HKDF-SHA256-HMAC-SHA256";
export const M_BYTES = encodePoint(M);
export const N_BYTES = encodePoint(N);
