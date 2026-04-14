import { describe, expect, it } from "vitest";
import { ed25519 } from "../../src/spake2plus/index.js";
import { ctEqual, utf8 } from "../../src/util/bytes.js";
import { randomBytes } from "../../src/util/random.js";

// Roundtrip tests for the edwards25519 SPAKE2+ suite. As with the P-256 tests,
// these prove self-consistency only. The M and N constants are currently
// marked SPEC-VERIFY in src/spake2plus/ed25519.ts — these roundtrip tests will
// pass with any fixed M, N pair even if the bytes disagree with RFC 9383.
// True compliance requires the RFC appendix vectors.

function runExchange() {
  const context = utf8("pake-js ed25519 test");
  const idProver = utf8("alice");
  const idVerifier = utf8("bob");
  const mhf = randomBytes(80);

  const { w0, w1 } = ed25519.deriveScalars(mhf);
  const L = ed25519.registerVerifier(w1);

  const c = ed25519.clientStart(w0);
  const s = ed25519.serverRespond({ w0, L, shareP: c.shareP });
  const cFinish = ed25519.clientFinish({
    w0,
    w1,
    x: c.x,
    shareV: s.shareV,
  });

  const clientKeys = ed25519.deriveKeys({
    context,
    idProver,
    idVerifier,
    w0,
    shareP: c.shareP,
    shareV: s.shareV,
    Z: cFinish.Z,
    V: cFinish.V,
  });
  const serverKeys = ed25519.deriveKeys({
    context,
    idProver,
    idVerifier,
    w0,
    shareP: c.shareP,
    shareV: s.shareV,
    Z: s.Z,
    V: s.V,
  });

  return { clientKeys, serverKeys, cFinish, server: s };
}

describe("SPAKE2+ edwards25519 roundtrip", () => {
  it("client and server agree on Z, V, and all derived keys", () => {
    const r = runExchange();
    expect(ctEqual(r.cFinish.Z, r.server.Z)).toBe(true);
    expect(ctEqual(r.cFinish.V, r.server.V)).toBe(true);
    expect(ctEqual(r.clientKeys.K_main, r.serverKeys.K_main)).toBe(true);
    expect(ctEqual(r.clientKeys.K_shared, r.serverKeys.K_shared)).toBe(true);
    expect(ctEqual(r.clientKeys.confirmP, r.serverKeys.confirmP)).toBe(true);
    expect(ctEqual(r.clientKeys.confirmV, r.serverKeys.confirmV)).toBe(true);
  });
});
