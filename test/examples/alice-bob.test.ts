import { describe, expect, it } from "vitest";
import { spake2plus, cpace } from "../../src/index.js";
import { ctEqual, utf8 } from "../../src/util/bytes.js";
import { randomBytes } from "../../src/util/random.js";

// Runnable Alice & Bob scenarios. These back the "Quick start" section of
// README.md — if the README drifts from reality, this file fails and CI
// catches it. Keep the code here in sync with the README snippets.

describe("Example: Alice logs in to Bob's server with SPAKE2+ P-256", () => {
  it("end-to-end walkthrough", () => {
    // ─── Setup: pretend there's a network between Alice and Bob ──────────
    //
    // In a real app these would be HTTP / WebSocket / BLE / whatever. Here
    // they are just variables we pass from one side to the other.
    let aliceToBob: Uint8Array | null = null;
    let bobToAlice: Uint8Array | null = null;

    const appContext = utf8("cipherman-demo v1"); // app-level label both sides agree on
    const aliceId = utf8("alice@example.test");
    const bobId = utf8("bob.example.test");

    // ─── Registration (Alice signs up once) ──────────────────────────────
    //
    // Alice runs a memory-hard KDF over her password + identity info. The
    // result (80+ bytes) is turned into the SPAKE2+ scalars w0, w1. Bob
    // stores (w0, L) as the verifier — he never learns the password or w1.
    //
    // In production `runMhf` should be Argon2id or scrypt with per-user salt.
    const runMhf = (_password: string): Uint8Array => randomBytes(80);
    const registrationMhfOutput = runMhf("correct horse battery staple");
    const registration = spake2plus.p256.deriveScalars(registrationMhfOutput);
    const L = spake2plus.p256.registerVerifier(registration.w1);

    // Alice hands (w0, L) to Bob over an authenticated channel ONCE.
    // Bob writes (w0, L) into his user database for this account.
    const bobDatabaseW0 = registration.w0;
    const bobDatabaseL = L;

    // Alice also needs w0 and w1 on every login. In practice she'd re-run
    // the MHF from the password + stored salt; we just keep them here.
    const aliceW0 = registration.w0;
    const aliceW1 = registration.w1;

    // ─── Login round (happens every session) ─────────────────────────────

    // Alice: start the exchange and send shareP to Bob.
    const alice = spake2plus.p256.clientStart(aliceW0);
    aliceToBob = alice.shareP;

    // Bob: respond with shareV (and privately remember Z, V for key derivation).
    const bob = spake2plus.p256.serverRespond({
      w0: bobDatabaseW0,
      L: bobDatabaseL,
      shareP: aliceToBob,
    });
    bobToAlice = bob.shareV;

    // Alice: finish by computing her own Z, V from Bob's shareV.
    const aliceZV = spake2plus.p256.clientFinish({
      w0: aliceW0,
      w1: aliceW1,
      x: alice.x,
      shareV: bobToAlice,
    });

    // ─── Both sides derive the same keys independently ───────────────────
    const transcript = {
      context: appContext,
      idProver: aliceId,
      idVerifier: bobId,
      w0: aliceW0, // identical on both sides
      shareP: alice.shareP,
      shareV: bob.shareV,
    };
    const aliceKeys = spake2plus.p256.deriveKeys({
      ...transcript,
      Z: aliceZV.Z,
      V: aliceZV.V,
    });
    const bobKeys = spake2plus.p256.deriveKeys({
      ...transcript,
      Z: bob.Z,
      V: bob.V,
    });

    // ─── Key confirmation ────────────────────────────────────────────────
    //
    // Each side sends the MAC the OTHER side should have computed. Alice
    // sends `confirmP` (she MAC'd with K_confirmP over Bob's share) and Bob
    // sends `confirmV`. Each side verifies in constant time.
    const aliceSendsConfirmP = aliceKeys.confirmP;
    const bobSendsConfirmV = bobKeys.confirmV;

    const bobAcceptsAlice = spake2plus.p256.verifyConfirmation(
      bobKeys.confirmP, // what Bob thinks Alice should have sent
      aliceSendsConfirmP, // what Alice actually sent
    );
    const aliceAcceptsBob = spake2plus.p256.verifyConfirmation(
      aliceKeys.confirmV, // what Alice thinks Bob should have sent
      bobSendsConfirmV, // what Bob actually sent
    );

    expect(bobAcceptsAlice).toBe(true);
    expect(aliceAcceptsBob).toBe(true);

    // ─── Both sides now hold the same 32-byte shared secret ──────────────
    //
    // DO NOT use K_shared directly as a session key. Feed it into an
    // application-level KDF (e.g. HKDF with an application label) and
    // derive fresh encryption/MAC keys from there.
    expect(aliceKeys.K_shared.length).toBe(32);
    expect(ctEqual(aliceKeys.K_shared, bobKeys.K_shared)).toBe(true);
  });
});

describe("Example: Alice and Bob agree on a key with CPace Ristretto255", () => {
  it("end-to-end walkthrough (initiator / responder)", () => {
    // CPace is balanced — neither side is the "server". Both parties derive
    // the key from a shared low-entropy secret (PRS), a session id, and
    // optional channel-binding info.

    const PRS = utf8("shared pairing code: 482913");
    const sid = randomBytes(16); // 16+ bytes of agreed freshness per session
    const CI = utf8("ble-pairing:alice<->bob"); // optional channel binding

    // Each party starts independently, producing a public share + private ephemeral.
    const alice = cpace.ristretto255.init({ PRS, sid, CI });
    const bob = cpace.ristretto255.init({ PRS, sid, CI });

    // Exchange shares over the wire.
    const aliceToBob = alice.share;
    const bobToAlice = bob.share;

    // Each side computes ISK from its own secret + the peer's share + AD.
    // The initiator puts its own (share, AD) first in the transcript; the
    // responder puts its peer's (share, AD) first. Same 64-byte result.
    const aliceAD = utf8("alice");
    const bobAD = utf8("bob");

    const aliceIsk = cpace.ristretto255.deriveIskInitiatorResponder({
      ephemeralSecret: alice.ephemeralSecret,
      ownShare: alice.share,
      peerShare: bobToAlice,
      ownAD: aliceAD,
      peerAD: bobAD,
      sid,
      role: "initiator",
    });
    const bobIsk = cpace.ristretto255.deriveIskInitiatorResponder({
      ephemeralSecret: bob.ephemeralSecret,
      ownShare: bob.share,
      peerShare: aliceToBob,
      ownAD: bobAD,
      peerAD: aliceAD,
      sid,
      role: "responder",
    });

    expect(aliceIsk.length).toBe(64);
    expect(ctEqual(aliceIsk, bobIsk)).toBe(true);
  });
});
