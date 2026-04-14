export function concat(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function bytesToHex(bytes: Uint8Array): string {
  const hex = new Array<string>(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    hex[i] = (bytes[i] as number).toString(16).padStart(2, "0");
  }
  return hex.join("");
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) {
    throw new Error("hexToBytes: odd-length string");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error("hexToBytes: invalid hex");
    out[i] = byte;
  }
  return out;
}

// Constant-time byte comparison. Returns true iff lengths match and all bytes equal.
// Important: timing depends only on lengths, never on byte contents once lengths match.
export function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] as number) ^ (b[i] as number);
  }
  return diff === 0;
}

// RFC 9383 transcript length prefix: 8-byte little-endian.
export function u64LE(n: number | bigint): Uint8Array {
  const v = typeof n === "bigint" ? n : BigInt(n);
  if (v < 0n || v > 0xffff_ffff_ffff_ffffn) {
    throw new RangeError("u64LE: out of range");
  }
  const out = new Uint8Array(8);
  let x = v;
  for (let i = 0; i < 8; i++) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

// draft-irtf-cfrg-cpace-20 length encoding: unsigned LEB128.
export function leb128(n: number | bigint): Uint8Array {
  let v = typeof n === "bigint" ? n : BigInt(n);
  if (v < 0n) throw new RangeError("leb128: negative");
  const out: number[] = [];
  do {
    let byte = Number(v & 0x7fn);
    v >>= 7n;
    if (v !== 0n) byte |= 0x80;
    out.push(byte);
  } while (v !== 0n);
  return new Uint8Array(out);
}

// RFC 9383 "len(x) || x" with 8-byte LE length prefix.
export function lvU64(x: Uint8Array): Uint8Array {
  return concat(u64LE(x.length), x);
}

// draft-irtf-cfrg-cpace-20 lv_cat: each argument is prefixed with LEB128 length, then concatenated.
export function lvCat(...parts: Uint8Array[]): Uint8Array {
  const pieces: Uint8Array[] = [];
  for (const p of parts) {
    pieces.push(leb128(p.length));
    pieces.push(p);
  }
  return concat(...pieces);
}

// draft-irtf-cfrg-cpace-20 Appendix A.3.3:
//   def o_cat(bytes1, bytes2):
//       if lexicographically_larger(bytes1, bytes2):
//           return b"oc" + bytes1 + bytes2
//       else:
//           return b"oc" + bytes2 + bytes1
//
// The larger octet string goes first; both parties always see the same result
// regardless of argument order. The 2-byte "oc" tag is part of the output.
const OC_TAG = new Uint8Array([0x6f, 0x63]); // b"oc"

export function oCat(a: Uint8Array, b: Uint8Array): Uint8Array {
  return compareBytes(a, b) > 0
    ? concat(OC_TAG, a, b)
    : concat(OC_TAG, b, a);
}

// Lexicographic byte comparison matching draft A.3.3:
//   prefix ties are broken by longer-is-larger (hence `a.length - b.length`
//   at the end).
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const min = Math.min(a.length, b.length);
  for (let i = 0; i < min; i++) {
    const av = a[i] as number;
    const bv = b[i] as number;
    if (av !== bv) return av - bv;
  }
  return a.length - b.length;
}

export function zeroBytes(n: number): Uint8Array {
  return new Uint8Array(n);
}
