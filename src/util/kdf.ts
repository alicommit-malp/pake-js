import { sha256 } from "@noble/hashes/sha2";
import { sha512 } from "@noble/hashes/sha2";
import { hmac } from "@noble/hashes/hmac";
import { hkdf } from "@noble/hashes/hkdf";

export type HashName = "sha256" | "sha512";

export function hashOf(name: HashName, data: Uint8Array): Uint8Array {
  return name === "sha256" ? sha256(data) : sha512(data);
}

export function hmacOf(
  name: HashName,
  key: Uint8Array,
  data: Uint8Array,
): Uint8Array {
  return name === "sha256" ? hmac(sha256, key, data) : hmac(sha512, key, data);
}

export function hkdfOf(
  name: HashName,
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  return name === "sha256"
    ? hkdf(sha256, ikm, salt, info, length)
    : hkdf(sha512, ikm, salt, info, length);
}

export function hashOutputLength(name: HashName): number {
  return name === "sha256" ? 32 : 64;
}
