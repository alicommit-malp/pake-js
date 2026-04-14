// Cryptographically-secure random bytes.
// Uses the platform Web Crypto API (available in Node >=18, Deno, Bun, and all
// modern browsers). No polyfill, no fallback — if getRandomValues is absent the
// environment is not suitable for cryptographic use and we must fail loudly.

export function randomBytes(length: number): Uint8Array {
  if (!Number.isInteger(length) || length < 0 || length > 65536) {
    throw new RangeError("randomBytes: length must be an integer in [0, 65536]");
  }
  const g: Crypto | undefined = (globalThis as { crypto?: Crypto }).crypto;
  if (!g || typeof g.getRandomValues !== "function") {
    throw new Error(
      "pake-js: no secure RNG available (globalThis.crypto.getRandomValues is missing)",
    );
  }
  const out = new Uint8Array(length);
  g.getRandomValues(out);
  return out;
}
