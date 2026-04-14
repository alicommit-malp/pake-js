import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  __clientStartWithScalar,
  __serverRespondWithScalar,
  deriveKeys,
  registerVerifier,
  verifyConfirmation,
} from "../../src/spake2plus/p256.js";
import { bytesToHex, hexToBytes, utf8 } from "../../src/util/bytes.js";

// RFC 9383 Appendix C, first P-256 SHA-256 test vector. The assertions below
// exercise every derived value printed in the RFC. Any mismatch means the
// implementation has drifted from the spec and must not ship.

const here = dirname(fileURLToPath(import.meta.url));
interface P256Vector {
  inputs: {
    Context: string;
    idProver: string;
    idVerifier: string;
    w0: string;
    w1: string;
    x: string;
    y: string;
  };
  expected: {
    L: string;
    shareP: string;
    shareV: string;
    Z: string;
    V: string;
    K_main: string;
    K_confirmP: string;
    K_confirmV: string;
    confirmP_hmacKcP_shareV: string;
    confirmV_hmacKcV_shareP: string;
    K_shared: string;
  };
}

const vector: P256Vector = JSON.parse(
  readFileSync(join(here, "spake2plus-p256-sha256.json"), "utf8"),
);

function scalarFromHex(hex: string): bigint {
  return BigInt("0x" + hex);
}

describe("RFC 9383 Appendix C — SPAKE2+ P-256 SHA-256 vector", () => {
  const w0 = hexToBytes(vector.inputs.w0);
  const w1 = hexToBytes(vector.inputs.w1);
  const context = utf8(vector.inputs.Context);
  const idProver = utf8(vector.inputs.idProver);
  const idVerifier = utf8(vector.inputs.idVerifier);
  const xScalar = scalarFromHex(vector.inputs.x);
  const yScalar = scalarFromHex(vector.inputs.y);

  it("registerVerifier(w1) == L", () => {
    const L = registerVerifier(w1);
    expect(bytesToHex(L)).toBe(vector.expected.L);
  });

  it("clientStart with x == vector.x produces shareP", () => {
    const { shareP } = __clientStartWithScalar(w0, xScalar);
    expect(bytesToHex(shareP)).toBe(vector.expected.shareP);
  });

  it("serverRespond with y == vector.y produces shareV, Z, V", () => {
    const L = hexToBytes(vector.expected.L);
    const shareP = hexToBytes(vector.expected.shareP);
    const s = __serverRespondWithScalar({ w0, L, shareP }, yScalar);
    expect(bytesToHex(s.shareV)).toBe(vector.expected.shareV);
    expect(bytesToHex(s.Z)).toBe(vector.expected.Z);
    expect(bytesToHex(s.V)).toBe(vector.expected.V);
  });

  it("deriveKeys produces K_main, K_confirmP, K_confirmV, K_shared, and confirmations", () => {
    const shareP = hexToBytes(vector.expected.shareP);
    const shareV = hexToBytes(vector.expected.shareV);
    const Z = hexToBytes(vector.expected.Z);
    const V = hexToBytes(vector.expected.V);

    const keys = deriveKeys({
      context,
      idProver,
      idVerifier,
      w0,
      shareP,
      shareV,
      Z,
      V,
    });

    expect(bytesToHex(keys.K_main)).toBe(vector.expected.K_main);
    expect(bytesToHex(keys.K_confirmP)).toBe(vector.expected.K_confirmP);
    expect(bytesToHex(keys.K_confirmV)).toBe(vector.expected.K_confirmV);
    expect(bytesToHex(keys.K_shared)).toBe(vector.expected.K_shared);
    // RFC: confirmP = HMAC(K_confirmP, shareV);  confirmV = HMAC(K_confirmV, shareP)
    expect(bytesToHex(keys.confirmP)).toBe(
      vector.expected.confirmP_hmacKcP_shareV,
    );
    expect(bytesToHex(keys.confirmV)).toBe(
      vector.expected.confirmV_hmacKcV_shareP,
    );
  });

  it("peer confirmation verifies in constant time", () => {
    expect(
      verifyConfirmation(
        hexToBytes(vector.expected.confirmV_hmacKcV_shareP),
        hexToBytes(vector.expected.confirmV_hmacKcV_shareP),
      ),
    ).toBe(true);
  });
});
