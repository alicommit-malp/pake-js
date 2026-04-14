import { describe, expect, it } from "vitest";
import { ristretto255 } from "../../src/cpace/index.js";
import { ctEqual, utf8 } from "../../src/util/bytes.js";

describe("CPace Ristretto255/SHA-512 roundtrip (initiator-responder)", () => {
  const PRS = utf8("correct horse battery staple");
  const sid = utf8("session-0001");
  const CI = utf8("TLS-binding-token");

  it("initiator and responder derive identical ISK", () => {
    const a = ristretto255.init({ PRS, sid, CI });
    const b = ristretto255.init({ PRS, sid, CI });

    const adA = utf8("initiator-AD");
    const adB = utf8("responder-AD");

    const iskA = ristretto255.deriveIskInitiatorResponder({
      ephemeralSecret: a.ephemeralSecret,
      ownShare: a.share,
      peerShare: b.share,
      ownAD: adA,
      peerAD: adB,
      sid,
      role: "initiator",
    });
    const iskB = ristretto255.deriveIskInitiatorResponder({
      ephemeralSecret: b.ephemeralSecret,
      ownShare: b.share,
      peerShare: a.share,
      ownAD: adB,
      peerAD: adA,
      sid,
      role: "responder",
    });

    expect(ctEqual(iskA, iskB)).toBe(true);
    expect(iskA.length).toBe(64); // SHA-512 output
  });

  it("different PRS produces different ISK", () => {
    const a1 = ristretto255.init({ PRS, sid });
    const b1 = ristretto255.init({ PRS, sid });
    const isk1 = ristretto255.deriveIskInitiatorResponder({
      ephemeralSecret: a1.ephemeralSecret,
      ownShare: a1.share,
      peerShare: b1.share,
      sid,
      role: "initiator",
    });

    const PRS2 = utf8("a different password");
    const a2 = ristretto255.init({ PRS: PRS2, sid });
    const b2 = ristretto255.init({ PRS: PRS2, sid });
    const isk2 = ristretto255.deriveIskInitiatorResponder({
      ephemeralSecret: a2.ephemeralSecret,
      ownShare: a2.share,
      peerShare: b2.share,
      sid,
      role: "initiator",
    });

    expect(ctEqual(isk1, isk2)).toBe(false);
  });

  it("mismatched sid between init and derive would break agreement", () => {
    const a = ristretto255.init({ PRS, sid });
    const b = ristretto255.init({ PRS, sid });
    const iskA = ristretto255.deriveIskInitiatorResponder({
      ephemeralSecret: a.ephemeralSecret,
      ownShare: a.share,
      peerShare: b.share,
      sid,
      role: "initiator",
    });
    const iskB = ristretto255.deriveIskInitiatorResponder({
      ephemeralSecret: b.ephemeralSecret,
      ownShare: b.share,
      peerShare: a.share,
      sid: utf8("a-different-sid"),
      role: "responder",
    });
    expect(ctEqual(iskA, iskB)).toBe(false);
  });
});

describe("CPace Ristretto255/SHA-512 roundtrip (symmetric)", () => {
  const PRS = utf8("shared secret");
  const sid = utf8("symmetric-session");

  it("both parties derive identical ISK regardless of argument order", () => {
    const a = ristretto255.init({ PRS, sid });
    const b = ristretto255.init({ PRS, sid });

    const iskA = ristretto255.deriveIskSymmetric({
      ephemeralSecret: a.ephemeralSecret,
      ownShare: a.share,
      peerShare: b.share,
      sid,
    });
    const iskB = ristretto255.deriveIskSymmetric({
      ephemeralSecret: b.ephemeralSecret,
      ownShare: b.share,
      peerShare: a.share,
      sid,
    });

    expect(ctEqual(iskA, iskB)).toBe(true);
  });
});

describe("CPace Ristretto255/SHA-512 validation", () => {
  it("rejects an all-zero peer share (invalid Ristretto encoding / identity)", () => {
    const a = ristretto255.init({ PRS: utf8("pw"), sid: utf8("s") });
    expect(() =>
      ristretto255.deriveIskInitiatorResponder({
        ephemeralSecret: a.ephemeralSecret,
        ownShare: a.share,
        peerShare: new Uint8Array(32), // all zeros = identity encoding
        sid: utf8("s"),
        role: "initiator",
      }),
    ).toThrow();
  });

  it("rejects a malformed peer share", () => {
    const a = ristretto255.init({ PRS: utf8("pw"), sid: utf8("s") });
    const junk = new Uint8Array(32);
    junk.fill(0xff);
    expect(() =>
      ristretto255.deriveIskInitiatorResponder({
        ephemeralSecret: a.ephemeralSecret,
        ownShare: a.share,
        peerShare: junk,
        sid: utf8("s"),
        role: "initiator",
      }),
    ).toThrow();
  });
});
