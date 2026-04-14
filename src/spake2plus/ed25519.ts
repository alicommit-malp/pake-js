import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes } from "../util/random.js";
import { ctEqual } from "../util/bytes.js";
import { computeConfirmations, keySchedule, transcript } from "./core.js";

// RFC 9383 ciphersuite: SPAKE2+-edwards25519-SHA256-HKDF-SHA256-HMAC-SHA256.
//
// NOTE ON M AND N:
// The M/N constants below are the edwards25519 generators registered by RFC 9383.
// They are encoded as 32-byte compressed Edwards points (RFC 8032 §5.1.2).
//
// SPEC-VERIFY: these bytes MUST be cross-checked against the canonical RFC 9383
// text before any production deployment. The authoritative correctness gate is
// the RFC 9383 Appendix test vectors — if they fail, the constants or the
// implementation are wrong. See THREAT_MODEL.md §"Constants verification".
const M_HEX =
  "d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf";
const N_HEX =
  "d3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab";

const Point = ed25519.ExtendedPoint;
type EdPoint = InstanceType<typeof ed25519.ExtendedPoint>;

const M: EdPoint = Point.fromHex(M_HEX);
const N: EdPoint = Point.fromHex(N_HEX);
const ORDER: bigint = ed25519.CURVE.n;
const COFACTOR = 8n;
const SCALAR_BYTES = 32;

function encodePoint(p: EdPoint): Uint8Array {
  return p.toRawBytes();
}

function decodePoint(b: Uint8Array): EdPoint {
  return Point.fromHex(b);
}

// edwards25519 scalars are little-endian 32-byte values.
function leBytesToScalar(b: Uint8Array): bigint {
  let x = 0n;
  for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i] as number);
  return x;
}

function scalarToLeBytes(s: bigint): Uint8Array {
  if (s < 0n || s >= ORDER) {
    throw new RangeError("spake2plus/ed25519: scalar out of range [0, n)");
  }
  const out = new Uint8Array(SCALAR_BYTES);
  let x = s;
  for (let i = 0; i < SCALAR_BYTES; i++) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function reduceMod(b: Uint8Array): Uint8Array {
  let x = 0n;
  for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i] as number);
  return scalarToLeBytes(x % ORDER);
}

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
  throw new Error("spake2plus/ed25519: failed to sample non-zero scalar");
}

/**
 * Derive (w0, w1) from a memory-hard function output per RFC 9383 §4.
 * See the p256 variant for rationale. Minimum length is 80 bytes.
 */
export function deriveScalars(mhfOutput: Uint8Array): {
  w0: Uint8Array;
  w1: Uint8Array;
} {
  if (mhfOutput.length < 80 || mhfOutput.length % 2 !== 0) {
    throw new Error(
      "spake2plus/ed25519: MHF output must be an even length >= 80 bytes",
    );
  }
  const half = mhfOutput.length >>> 1;
  return {
    w0: reduceMod(mhfOutput.subarray(0, half)),
    w1: reduceMod(mhfOutput.subarray(half)),
  };
}

export function registerVerifier(w1: Uint8Array): Uint8Array {
  const s = leBytesToScalar(w1);
  if (s === 0n || s >= ORDER) {
    throw new Error("spake2plus/ed25519: invalid w1");
  }
  return encodePoint(Point.BASE.multiply(s));
}

export interface ClientStart {
  x: Uint8Array;
  shareP: Uint8Array;
}

export function clientStart(w0: Uint8Array): ClientStart {
  const w0s = leBytesToScalar(w0);
  if (w0s === 0n || w0s >= ORDER) {
    throw new Error("spake2plus/ed25519: invalid w0");
  }
  const xs = sampleScalar();
  const X = Point.BASE.multiply(xs).add(M.multiply(w0s));
  return { x: scalarToLeBytes(xs), shareP: encodePoint(X) };
}

export interface ServerRespond {
  y: Uint8Array;
  shareV: Uint8Array;
  Z: Uint8Array;
  V: Uint8Array;
}

export function serverRespond(params: {
  w0: Uint8Array;
  L: Uint8Array;
  shareP: Uint8Array;
}): ServerRespond {
  const w0s = leBytesToScalar(params.w0);
  if (w0s === 0n || w0s >= ORDER) {
    throw new Error("spake2plus/ed25519: invalid w0");
  }
  const L = decodePoint(params.L);
  const X = decodePoint(params.shareP);
  const ys = sampleScalar();
  const Y = Point.BASE.multiply(ys).add(N.multiply(w0s));
  // Z = h * y * (X - w0*M);  V = h * y * L  (cofactor h = 8 for edwards25519).
  // Cofactor multiplication clears any torsion component from the subtraction.
  const XminusW0M = X.add(M.multiply(w0s).negate()).multiplyUnsafe(COFACTOR);
  const hL = L.multiplyUnsafe(COFACTOR);
  const Z = XminusW0M.multiply(ys);
  const V = hL.multiply(ys);
  assertNonIdentity(Z);
  assertNonIdentity(V);
  return {
    y: scalarToLeBytes(ys),
    shareV: encodePoint(Y),
    Z: encodePoint(Z),
    V: encodePoint(V),
  };
}

export interface ClientFinish {
  Z: Uint8Array;
  V: Uint8Array;
}

export function clientFinish(params: {
  w0: Uint8Array;
  w1: Uint8Array;
  x: Uint8Array;
  shareV: Uint8Array;
}): ClientFinish {
  const w0s = leBytesToScalar(params.w0);
  const w1s = leBytesToScalar(params.w1);
  const xs = leBytesToScalar(params.x);
  if (w0s === 0n || w1s === 0n || xs === 0n) {
    throw new Error("spake2plus/ed25519: zero scalar");
  }
  const Y = decodePoint(params.shareV);
  const YminusW0N = Y.add(N.multiply(w0s).negate()).multiplyUnsafe(COFACTOR);
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

export function verifyConfirmation(
  expected: Uint8Array,
  received: Uint8Array,
): boolean {
  return ctEqual(expected, received);
}

function assertNonIdentity(p: EdPoint): void {
  if (p.equals(Point.ZERO)) {
    throw new Error("spake2plus/ed25519: degenerate point (identity)");
  }
}

export const SUITE_NAME =
  "SPAKE2PLUS-EDWARDS25519-SHA256-HKDF-SHA256-HMAC-SHA256";
export const M_BYTES = encodePoint(M);
export const N_BYTES = encodePoint(N);
