import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { sha512 } from "@noble/hashes/sha2";
import {
  __calculateGeneratorEncoded,
  __generatorString,
  __initWithScalar,
  __scalarMultVfy,
  deriveIskInitiatorResponder,
  deriveIskSymmetric,
} from "../../src/cpace/ristretto255.js";
import { bytesToHex, hexToBytes } from "../../src/util/bytes.js";

// draft-irtf-cfrg-cpace-20 Appendix B.3 — CPACE-RISTR255-SHA512 test vectors.
// Each assertion below corresponds to a printed block in the draft.

const here = dirname(fileURLToPath(import.meta.url));
interface CPaceVector {
  inputs: {
    PRS: string;
    CI: string;
    sid: string;
    ADa: string;
    ADb: string;
    ya_le: string;
    yb_le: string;
  };
  expected: {
    generator_string: string;
    generator_hash_sha512: string;
    g: string;
    Ya: string;
    Yb: string;
    K: string;
    ISK_IR: string;
    ISK_SY: string;
  };
  scalar_mult_valid: { s_le: string; X: string; result: string };
  scalar_mult_invalid: {
    s_le: string;
    Y_i1_invalid_encoding: string;
    Y_i2_identity: string;
  };
}

const vector: CPaceVector = JSON.parse(
  readFileSync(join(here, "cpace-ristretto255-sha512.json"), "utf8"),
);

function leScalarFromHex(hex: string): bigint {
  const bytes = hexToBytes(hex);
  let x = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    x = (x << 8n) | BigInt(bytes[i] as number);
  }
  return x;
}

describe("draft-irtf-cfrg-cpace-20 B.3 — CPACE-RISTR255-SHA512 vectors", () => {
  const PRS = hexToBytes(vector.inputs.PRS);
  const CI = hexToBytes(vector.inputs.CI);
  const sid = hexToBytes(vector.inputs.sid);
  const ADa = hexToBytes(vector.inputs.ADa);
  const ADb = hexToBytes(vector.inputs.ADb);
  const yaScalar = leScalarFromHex(vector.inputs.ya_le);
  const ybScalar = leScalarFromHex(vector.inputs.yb_le);

  it("B.3.1 — generator_string matches (170 bytes)", () => {
    const gs = __generatorString(PRS, CI, sid);
    expect(bytesToHex(gs)).toBe(vector.expected.generator_string);
    expect(gs.length).toBe(170);
  });

  it("B.3.1 — SHA-512(generator_string) matches hash result", () => {
    const gs = __generatorString(PRS, CI, sid);
    expect(bytesToHex(sha512(gs))).toBe(vector.expected.generator_hash_sha512);
  });

  it("B.3.1 — calculate_generator produces g = 0x222b...", () => {
    const g = __calculateGeneratorEncoded(PRS, CI, sid);
    expect(bytesToHex(g)).toBe(vector.expected.g);
  });

  it("B.3.2 — init with ya produces Ya", () => {
    const { share } = __initWithScalar({ PRS, sid, CI }, yaScalar);
    expect(bytesToHex(share)).toBe(vector.expected.Ya);
  });

  it("B.3.3 — init with yb produces Yb", () => {
    const { share } = __initWithScalar({ PRS, sid, CI }, ybScalar);
    expect(bytesToHex(share)).toBe(vector.expected.Yb);
  });

  it("B.3.4 — scalar_mult_vfy(ya, Yb) and scalar_mult_vfy(yb, Ya) both yield K", () => {
    const Yb = hexToBytes(vector.expected.Yb);
    const Ya = hexToBytes(vector.expected.Ya);
    const K1 = __scalarMultVfy(hexToBytes(vector.inputs.ya_le), Yb);
    const K2 = __scalarMultVfy(hexToBytes(vector.inputs.yb_le), Ya);
    expect(bytesToHex(K1)).toBe(vector.expected.K);
    expect(bytesToHex(K2)).toBe(vector.expected.K);
  });

  it("B.3.5 — initiator-responder ISK matches from both sides", () => {
    const a = __initWithScalar({ PRS, sid, CI }, yaScalar);
    const b = __initWithScalar({ PRS, sid, CI }, ybScalar);

    const iskA = deriveIskInitiatorResponder({
      ephemeralSecret: a.ephemeralSecret,
      ownShare: a.share,
      peerShare: b.share,
      ownAD: ADa,
      peerAD: ADb,
      sid,
      role: "initiator",
    });
    const iskB = deriveIskInitiatorResponder({
      ephemeralSecret: b.ephemeralSecret,
      ownShare: b.share,
      peerShare: a.share,
      ownAD: ADb,
      peerAD: ADa,
      sid,
      role: "responder",
    });

    expect(bytesToHex(iskA)).toBe(vector.expected.ISK_IR);
    expect(bytesToHex(iskB)).toBe(vector.expected.ISK_IR);
  });

  it("B.3.6 — symmetric ISK matches from both sides", () => {
    const a = __initWithScalar({ PRS, sid, CI }, yaScalar);
    const b = __initWithScalar({ PRS, sid, CI }, ybScalar);

    const iskA = deriveIskSymmetric({
      ephemeralSecret: a.ephemeralSecret,
      ownShare: a.share,
      peerShare: b.share,
      ownAD: ADa,
      peerAD: ADb,
      sid,
    });
    const iskB = deriveIskSymmetric({
      ephemeralSecret: b.ephemeralSecret,
      ownShare: b.share,
      peerShare: a.share,
      ownAD: ADb,
      peerAD: ADa,
      sid,
    });

    expect(bytesToHex(iskA)).toBe(vector.expected.ISK_SY);
    expect(bytesToHex(iskB)).toBe(vector.expected.ISK_SY);
  });

  it("B.3.10 — scalar_mult_vfy with valid inputs", () => {
    const out = __scalarMultVfy(
      hexToBytes(vector.scalar_mult_valid.s_le),
      hexToBytes(vector.scalar_mult_valid.X),
    );
    expect(bytesToHex(out)).toBe(vector.scalar_mult_valid.result);
  });

  it("B.3.11 — scalar_mult_vfy aborts on invalid Ristretto encoding", () => {
    expect(() =>
      __scalarMultVfy(
        hexToBytes(vector.scalar_mult_invalid.s_le),
        hexToBytes(vector.scalar_mult_invalid.Y_i1_invalid_encoding),
      ),
    ).toThrow();
  });

  it("B.3.11 — scalar_mult_vfy aborts on identity encoding", () => {
    expect(() =>
      __scalarMultVfy(
        hexToBytes(vector.scalar_mult_invalid.s_le),
        hexToBytes(vector.scalar_mult_invalid.Y_i2_identity),
      ),
    ).toThrow();
  });
});
