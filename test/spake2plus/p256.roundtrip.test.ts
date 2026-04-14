import { describe, expect, it } from "vitest";
import { p256 } from "../../src/spake2plus/index.js";
import { ctEqual, utf8 } from "../../src/util/bytes.js";
import { randomBytes } from "../../src/util/random.js";

// These are roundtrip tests: they prove the implementation is self-consistent
// (client and server derive the same keys). They do NOT prove compliance with
// RFC 9383 bytes-on-the-wire — that requires the official appendix test
// vectors to be added to test/vectors/ and run through a dedicated harness.

function runExchange(params: {
  context: Uint8Array;
  idProver: Uint8Array;
  idVerifier: Uint8Array;
  mhfOutput: Uint8Array;
}) {
  const { context, idProver, idVerifier, mhfOutput } = params;

  // Registration
  const { w0, w1 } = p256.deriveScalars(mhfOutput);
  const L = p256.registerVerifier(w1);

  // Protocol
  const c = p256.clientStart(w0);
  const s = p256.serverRespond({ w0, L, shareP: c.shareP });
  const cFinish = p256.clientFinish({
    w0,
    w1,
    x: c.x,
    shareV: s.shareV,
  });

  // Both sides derive keys
  const clientKeys = p256.deriveKeys({
    context,
    idProver,
    idVerifier,
    w0,
    shareP: c.shareP,
    shareV: s.shareV,
    Z: cFinish.Z,
    V: cFinish.V,
  });
  const serverKeys = p256.deriveKeys({
    context,
    idProver,
    idVerifier,
    w0,
    shareP: c.shareP,
    shareV: s.shareV,
    Z: s.Z,
    V: s.V,
  });

  return { clientKeys, serverKeys, client: c, server: s, cFinish };
}

describe("SPAKE2+ P-256 roundtrip", () => {
  const mhf = randomBytes(80);
  const context = utf8("pake-js test");
  const idProver = utf8("client@example.test");
  const idVerifier = utf8("server@example.test");

  it("both sides agree on Z and V", () => {
    const r = runExchange({ context, idProver, idVerifier, mhfOutput: mhf });
    expect(ctEqual(r.cFinish.Z, r.server.Z)).toBe(true);
    expect(ctEqual(r.cFinish.V, r.server.V)).toBe(true);
  });

  it("both sides derive identical K_main, K_shared, K_confirmP, K_confirmV", () => {
    const r = runExchange({ context, idProver, idVerifier, mhfOutput: mhf });
    expect(ctEqual(r.clientKeys.K_main, r.serverKeys.K_main)).toBe(true);
    expect(ctEqual(r.clientKeys.K_shared, r.serverKeys.K_shared)).toBe(true);
    expect(ctEqual(r.clientKeys.K_confirmP, r.serverKeys.K_confirmP)).toBe(
      true,
    );
    expect(ctEqual(r.clientKeys.K_confirmV, r.serverKeys.K_confirmV)).toBe(
      true,
    );
  });

  it("key confirmation MACs verify on both sides", () => {
    const r = runExchange({ context, idProver, idVerifier, mhfOutput: mhf });
    expect(
      p256.verifyConfirmation(r.clientKeys.confirmV, r.serverKeys.confirmV),
    ).toBe(true);
    expect(
      p256.verifyConfirmation(r.clientKeys.confirmP, r.serverKeys.confirmP),
    ).toBe(true);
  });

  it("K_shared has the expected length (32 bytes for SHA-256)", () => {
    const r = runExchange({ context, idProver, idVerifier, mhfOutput: mhf });
    expect(r.clientKeys.K_shared.length).toBe(32);
  });

  it("different passwords produce different shared keys", () => {
    const a = runExchange({
      context,
      idProver,
      idVerifier,
      mhfOutput: randomBytes(80),
    });
    const b = runExchange({
      context,
      idProver,
      idVerifier,
      mhfOutput: randomBytes(80),
    });
    expect(ctEqual(a.clientKeys.K_shared, b.clientKeys.K_shared)).toBe(false);
  });

  it("different contexts produce different shared keys", () => {
    const a = runExchange({
      context: utf8("context-A"),
      idProver,
      idVerifier,
      mhfOutput: mhf,
    });
    const b = runExchange({
      context: utf8("context-B"),
      idProver,
      idVerifier,
      mhfOutput: mhf,
    });
    expect(ctEqual(a.clientKeys.K_shared, b.clientKeys.K_shared)).toBe(false);
  });

  it("rejects MHF output below 80 bytes", () => {
    expect(() => p256.deriveScalars(new Uint8Array(78))).toThrow();
  });
});
