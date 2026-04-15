# pake-js

Auditable, standards-based **Password-Authenticated Key Exchange** for JavaScript, built for regulated environments (medical devices, healthcare backends, compliance-bound services).

- **Protocols**: SPAKE2+ (RFC 9383) and CPace (draft-irtf-cfrg-cpace-20)
- **Runtime dependency**: exactly one — [`@noble/curves`](https://github.com/paulmillr/noble-curves)
- **Platforms**: Node ≥18, Deno, Bun, and every modern browser (any framework)
- **API**: fully stateless — plain functions in, plain objects out
- **License**: MIT

> **Status: pre-1.0.** The P-256 SPAKE2+ suite and the Ristretto255/SHA-512 CPace suite are verified byte-for-byte against the official RFC 9383 Appendix C and draft-irtf-cfrg-cpace-20 Appendix B.3 test vectors. The edwards25519 SPAKE2+ suite is still marked SPEC-VERIFY (its RFC vector is not yet wired up). Regardless, do not deploy to production until your own independent audit is complete — see [`THREAT_MODEL.md`](./THREAT_MODEL.md).

## Why another PAKE library?

Most JS PAKE implementations are tied to a framework, pull in opinionated transports, or hand-roll elliptic curve arithmetic. `pake-js` does none of that:

- **One crypto dependency**: `@noble/curves`. Audited, minimal, constant-time. No polyfills, no transports, no storage layer.
- **Standards-first**: every constant and transcript layout is copied from the RFC / draft with a citation. If the spec says 8-byte little-endian length prefix, that's what you get.
- **Stateless**: no classes, no sessions to leak. The caller owns every scalar and every message buffer.
- **Auditable**: ~500 lines of TypeScript per protocol, strict mode, no `any`, no side effects at import time.

## Install

```bash
npm install @cipherman/pake-js
# or: pnpm add @cipherman/pake-js / yarn add @cipherman/pake-js / bun add @cipherman/pake-js
```

## Ciphersuites

| Protocol | Suite | Import path |
| --- | --- | --- |
| SPAKE2+ (RFC 9383) | `SPAKE2PLUS-P256-SHA256-HKDF-SHA256-HMAC-SHA256` | `@cipherman/pake-js/spake2plus` → `p256` |
| SPAKE2+ (RFC 9383) | `SPAKE2PLUS-EDWARDS25519-SHA256-HKDF-SHA256-HMAC-SHA256` | `@cipherman/pake-js/spake2plus` → `ed25519` |
| CPace (draft-20) | `CPACE-RISTR255-SHA512` | `@cipherman/pake-js/cpace` → `ristretto255` |

> The edwards25519 SPAKE2+ suite is marked SPEC-VERIFY: the M, N constants must be cross-checked against RFC 9383 and the appendix test vectors must pass before production use. See [`THREAT_MODEL.md`](./THREAT_MODEL.md) §R2.

## Alice logs in to Bob's server (SPAKE2+ / P-256 / SHA-256)

A complete SPAKE2+ walkthrough, narrated step by step. The full runnable version is in [test/examples/alice-bob.test.ts](./test/examples/alice-bob.test.ts) and runs as part of `npm test` — if this README drifts from the code, CI fails on the next push.

### The scenario

Alice has a password. She wants to log in to Bob's server using that password, with these requirements:

- **Bob never sees the password, not even once.** Not at registration, not at login.
- **A network eavesdropper learns nothing.** Recording the session does not let an attacker try password guesses offline.
- **An active attacker pretending to be one side** gets at most **one** password guess per session attempt. Any wrong guess is detectable and can be rate-limited at the application level.
- **If Bob's database is stolen later**, the attacker still can't recover the password without running a memory-hard function over *every* candidate — the verifier stored on the server is a "hardened" form of the password, not a replayable secret.
- **At the end**, Alice and Bob both hold the *same* 32-byte session key that nobody else could have computed, and each side has cryptographic proof that the other actually derived it correctly.

SPAKE2+ gives all of these. The entire protocol is one round trip (shareP → shareV) plus one round of key confirmation (confirmP → confirmV).

### What each side holds

| Value | Who holds it | What it is |
| --- | --- | --- |
| `password` | Alice only | The low-entropy secret she types. **Never given to pake-js.** |
| `mhfOutput` | Alice only | 80+ bytes from running scrypt/Argon2id over `(password, salt, idProver, idVerifier)`. |
| `w0`, `w1` | Alice (both), Bob (`w0` only) | Two scalars derived from `mhfOutput`. `w1` is Alice's private key; `w0` is shared. |
| `L` | Bob only | `w1 · G` — a public point that proves Bob knows `w1` was once committed to, without revealing `w1`. |
| `x`, `y` | Alice / Bob (ephemeral) | Fresh random scalars sampled once per session. Discarded after the exchange. |
| `shareP`, `shareV` | Sent over the wire | Elliptic-curve points: `x·G + w0·M` and `y·G + w0·N`. Look uniformly random to an observer. |
| `Z`, `V` | Each side derives independently | Two more points that only agree if both sides started from the same password. The whole protocol's security hinges on these. |
| `K_main`, `K_confirmP`, `K_confirmV`, `K_shared` | Each side derives independently | Keys produced by hashing the full transcript. Identical on both sides iff the password was right. |
| `confirmP`, `confirmV` | Sent over the wire | HMACs that let each side prove to the other "I derived the same keys you did." |

`M` and `N` in the formulas above are two fixed group generators defined in RFC 9383 Appendix A for the P-256 suite. pake-js hard-codes them in [src/spake2plus/p256.ts](./src/spake2plus/p256.ts) and gates them with the RFC test vectors.

### Stage 1: Registration — runs exactly once, when Alice creates her account

Alice's client never ships the password to Bob. Instead it runs a **memory-hard key-derivation function** (Argon2id or scrypt, with a per-user salt) and feeds the result into `spake2plus.p256.deriveScalars`. This gives her two scalars, `w0` and `w1`.

She keeps both scalars client-side (or re-derives them from the password on every login). She computes `L = w1·G` and sends `(w0, L)` to Bob over an **already-authenticated** channel — registration is not the moment SPAKE2+ protects against MITM; you need TLS (or an out-of-band confirmation code) to get the verifier into Bob's database safely.

Bob stores `(w0, L)` against Alice's account. Importantly: Bob never stores `w1` and never sees the password. If his database is stolen tomorrow, the attacker gets `w0` and `L` — but recovering the password from those still requires running the memory-hard function over every guess, which is exactly the work factor Alice's MHF choice bought her.

```ts
import { spake2plus } from "@cipherman/pake-js";

// pake-js does NOT bundle an MHF on purpose — pick scrypt, Argon2id, or PBKDF2
// with a strong iteration count. Output must be >= 80 bytes (2 * (32 + 8),
// per the k=64-bit safety margin in RFC 9383 §4).
const mhfOutput = await runYourMhf(
  "correct horse battery staple",   // the password
  perUserSalt,                      // 16+ bytes, stored server-side per account
  80,                               // output length
);

const { w0, w1 } = spake2plus.p256.deriveScalars(mhfOutput);
const L = spake2plus.p256.registerVerifier(w1);

// Ship (w0, L) to Bob over a channel that is already authenticated (TLS is fine).
// Bob's database:
//   users[alice].w0 = w0;
//   users[alice].L  = L;
// Alice keeps w0 and w1 — or re-derives them from the password on every login.
```

### Stage 2: Login round — Alice starts the exchange

On every login attempt, Alice samples a fresh random scalar `x` and computes `shareP = x·G + w0·M`. That point is what she sends to Bob. The `w0·M` term is what makes SPAKE2+ a PAKE instead of plain Diffie-Hellman: it binds the handshake to the password, but in a way that doesn't let anyone recover `w0` from observing `shareP`.

```ts
const alice = spake2plus.p256.clientStart(w0);
// alice.x       — Alice's private ephemeral scalar (keep this local, discard after use)
// alice.shareP  — the 65-byte uncompressed point to send on the wire

sendToBob(alice.shareP);
```

### Stage 3: Bob responds

When Bob receives `shareP`, he looks up Alice's `(w0, L)` in his database, samples his own fresh random scalar `y`, and computes three things:

- `shareV = y·G + w0·N` — his public half of the exchange, which he sends back to Alice.
- `Z = y·(shareP − w0·M)` — a shared point that only equals Alice's version if she started from the same `w0`.
- `V = y·L` — a second shared point that only equals Alice's version if she started from the same `w1`. This is the "+" in SPAKE2**+**: it binds the final key to a proof that Alice knows `w1`, not just `w0`, which is what prevents a server-database compromise from letting the attacker impersonate Alice.

Bob returns `shareV` over the wire but keeps `Z` and `V` local.

```ts
const bob = spake2plus.p256.serverRespond({
  w0,                  // users[alice].w0 from Bob's DB
  L,                   // users[alice].L  from Bob's DB
  shareP: alice.shareP,
});
// bob.y, bob.shareV, bob.Z, bob.V

sendToAlice(bob.shareV);
```

### Stage 4: Alice finishes the handshake

Alice takes Bob's `shareV` and computes her own `Z` and `V` using her private `x` and `w1`. If the password was right, her `(Z, V)` exactly matches Bob's `(Z, V)` — bit for bit. If the password was wrong, they diverge, and every key derived from them will diverge in the next step.

Alice never sends `Z` or `V` on the wire. They stay local.

```ts
const aliceZV = spake2plus.p256.clientFinish({
  w0,
  w1,
  x: alice.x,
  shareV: bob.shareV,
});
// aliceZV.Z, aliceZV.V
```

### Stage 5: Key derivation — the full transcript

Now both sides build a **transcript** — an unambiguous concatenation of everything the protocol touched: the app context, the two identities, the fixed M and N, both public shares, both derived points, and `w0`. RFC 9383 §4 specifies the layout down to the byte; pake-js does it for you in `deriveKeys`.

The transcript gets hashed to `K_main`, then `K_main` feeds HKDF twice: once with the label `"ConfirmationKeys"` to produce the pair `(K_confirmP, K_confirmV)` used for mutual authentication, and once with the label `"SharedKey"` to produce `K_shared`, the session key.

`K_shared` is 32 bytes (SHA-256 output length for this suite). **Do not use it as an AEAD key directly.** Feed it through one more HKDF with an application-specific label so that rotating the application label rotates the session keys without re-running the whole PAKE.

```ts
const transcriptFields = {
  context: new TextEncoder().encode("cipherman-demo v1"),
  idProver: new TextEncoder().encode("alice@example.test"),
  idVerifier: new TextEncoder().encode("bob.example.test"),
  w0,
  shareP: alice.shareP,
  shareV: bob.shareV,
};

const aliceKeys = spake2plus.p256.deriveKeys({
  ...transcriptFields,
  Z: aliceZV.Z,
  V: aliceZV.V,
});

const bobKeys = spake2plus.p256.deriveKeys({
  ...transcriptFields,
  Z: bob.Z,
  V: bob.V,
});

// If Alice typed the password correctly, these are now equal:
//   aliceKeys.K_main     == bobKeys.K_main
//   aliceKeys.K_confirmP == bobKeys.K_confirmP
//   aliceKeys.K_confirmV == bobKeys.K_confirmV
//   aliceKeys.K_shared   == bobKeys.K_shared
// If she didn't, all four pairs diverge. Neither side yet knows which case they're in.
```

### Stage 6: Key confirmation

Neither party has any cryptographic evidence that the *other* party got to the same `K_shared`. That evidence comes from the last exchange: each side sends a short MAC proving "I derived the same confirmation keys you did."

Specifically, per RFC 9383 §4:

- `confirmP = HMAC(K_confirmP, shareV)` — Alice MACs Bob's share with the first confirmation key.
- `confirmV = HMAC(K_confirmV, shareP)` — Bob MACs Alice's share with the second.

Each side sends its MAC; each side verifies the incoming MAC in constant time. A mismatch on either side means one of three things: wrong password, a bug, or an active MITM. In all three cases the session must be aborted — and because the attacker learned nothing, all they accomplished was one failed online guess.

```ts
// Alice -> Bob:  aliceKeys.confirmP
// Bob   -> Alice: bobKeys.confirmV

const bobAcceptsAlice = spake2plus.p256.verifyConfirmation(
  bobKeys.confirmP,            // what Bob expects Alice to have computed
  receivedFromAlice,           // what actually arrived on the wire
);
const aliceAcceptsBob = spake2plus.p256.verifyConfirmation(
  aliceKeys.confirmV,          // what Alice expects Bob to have computed
  receivedFromBob,
);

if (!bobAcceptsAlice) {
  throw new Error("Bob: Alice's key confirmation failed — wrong password or MITM");
}
if (!aliceAcceptsBob) {
  throw new Error("Alice: Bob's key confirmation failed — wrong password or MITM");
}

// Past this line, Alice and Bob are mutually authenticated AND share a 32-byte key.
// aliceKeys.K_shared and bobKeys.K_shared are identical. Use them via an
// application-level HKDF to derive the actual transport keys:
//
//   const transportKey = hkdf(sha256, aliceKeys.K_shared, /* salt */ sid, /* info */ utf8("transport/v1"), 32);
```

### What goes over the wire, and what doesn't

Exactly four values cross the network in a full SPAKE2+ exchange:

1. `shareP` — Alice → Bob (65 bytes uncompressed P-256)
2. `shareV` — Bob → Alice (65 bytes uncompressed P-256)
3. `confirmP` — Alice → Bob (32 bytes HMAC-SHA-256)
4. `confirmV` — Bob → Alice (32 bytes HMAC-SHA-256)

Everything else — the password, `mhfOutput`, `w0`, `w1`, `x`, `y`, `Z`, `V`, `K_main`, `K_confirmP`, `K_confirmV`, `K_shared` — stays on the machine that computed it. A passive attacker capturing the full exchange sees four byte strings that look uniformly random. An active attacker who injects, replays, or reorders messages causes the confirmation step to fail; they gain nothing beyond the knowledge that *this attempt* failed, which is why rate-limiting at the application layer is what turns "at most one guess per session" into a meaningful security property.

## Alice and Bob pair a Bluetooth device (CPace / Ristretto255 / SHA-512)

CPace is the **balanced** PAKE in pake-js. Unlike SPAKE2+, there is no client and no server — there are just two peers who happen to share a low-entropy secret (a 6-digit pairing code, a PIN, a pre-shared phrase) and want to turn that secret into a strong 64-byte key. The full runnable version lives alongside the SPAKE2+ one in [test/examples/alice-bob.test.ts](./test/examples/alice-bob.test.ts).

### When to reach for CPace instead of SPAKE2+

- You're pairing two physical devices that briefly display or exchange a code (BLE pairing, QR-code enrollment, NFC tap-to-pair).
- There's no notion of a "database of verifiers" — the shared secret is generated on the fly and used once.
- Both sides are equally trusted. Neither is enrolling the other; they're meeting as equals.
- The session ID (`sid`) can be agreed out of band — typically both sides already have it from the discovery phase.

CPace in pake-js uses **Ristretto255** as the group and **SHA-512** as the hash. The ciphersuite name is `CPACE-RISTR255-SHA512` and the whole implementation is gated by the draft-20 Appendix B.3 test vectors.

### The inputs both sides need to already have

| Value | How it's obtained | Required |
| --- | --- | --- |
| `PRS` | "Password-Related String" — the shared low-entropy secret. Ideally the output of a memory-hard KDF over the password, but a PIN-encoded-as-bytes also works for short-lived pairing flows. | yes |
| `sid` | Session identifier. 16+ bytes of fresh randomness both sides agree on (exchanged during discovery, or constructed from `random_a ∥ random_b`). Ensures every session derives a unique key. | yes |
| `CI` | Channel identifier. Optional binding to the underlying transport (e.g. the BLE link layer keys, a TLS exporter). Empty if you don't need it. | no |
| `ADa`, `ADb` | Associated data each side wants baked into the transcript (e.g. device serial numbers, roles). Empty by default. | no |

### Stage 1: Each party independently computes its public share

Both sides hash `(PRS, sid, CI)` into a common point `g` on the Ristretto255 group — this is CPace's "calculate_generator" step, and it's the piece that binds the handshake to the shared secret without letting an observer recover it.

Each party then samples a fresh random scalar (the `ephemeralSecret`) and publishes `share = ephemeralSecret · g`. Because `g` depends on `PRS`, only parties who know the same `PRS` will land on the same curve, and only they can complete the handshake.

```ts
import { cpace } from "@cipherman/pake-js";

const PRS = new TextEncoder().encode("pairing code: 482913"); // or MHF output
const sid = await agreedSessionId(); // 16+ bytes of freshness, exchanged during discovery
const CI  = new TextEncoder().encode("ble-pairing:alice<->bob"); // optional channel binding

// Each party runs init independently. Both use the same (PRS, sid, CI).
const alice = cpace.ristretto255.init({ PRS, sid, CI });
const bob   = cpace.ristretto255.init({ PRS, sid, CI });

// alice.ephemeralSecret — 32 bytes, keep local, discard after the handshake
// alice.share           — 32 bytes Ristretto255 point, send to Bob

sendToBob(alice.share);
sendToAlice(bob.share);
```

### Stage 2: Each side derives the ISK

Once both shares are exchanged, each party computes the shared secret `K = ephemeralSecret · peerShare`, then hashes a transcript containing the domain-separation tag `"CPaceRistretto255_ISK"`, `sid`, `K`, and both `(share, AD)` pairs. The result — the **Intermediate Session Key**, or ISK — is 64 bytes of SHA-512 output.

CPace defines two ordering rules for the transcript, and pake-js exposes both:

- **Initiator / responder** (`deriveIskInitiatorResponder`): one party declared itself the initiator when they started the exchange (maybe because they sent the first packet). The initiator's `(share, AD)` goes first in the transcript; the responder's goes second. Both sides must agree on who was which.
- **Symmetric** (`deriveIskSymmetric`): neither side has a role. This happens when, say, two BLE devices simultaneously broadcast discovery packets and there's no natural "first mover". Each side concatenates its own `(share, AD)` and the peer's in a lexicographic (order-independent) way, so both parties land on the same ISK without any coordination about who was first.

The example below uses the initiator/responder form, which is what most pairing flows actually look like (one device scans, the other is discovered).

```ts
const aliceIsk = cpace.ristretto255.deriveIskInitiatorResponder({
  ephemeralSecret: alice.ephemeralSecret,
  ownShare: alice.share,
  peerShare: receivedFromBob,
  ownAD: new TextEncoder().encode("alice-phone"),
  peerAD: new TextEncoder().encode("bob-earbuds"),
  sid,
  role: "initiator",
});

const bobIsk = cpace.ristretto255.deriveIskInitiatorResponder({
  ephemeralSecret: bob.ephemeralSecret,
  ownShare: bob.share,
  peerShare: receivedFromAlice,
  ownAD: new TextEncoder().encode("bob-earbuds"),
  peerAD: new TextEncoder().encode("alice-phone"),
  sid,
  role: "responder",
});

// aliceIsk.length === bobIsk.length === 64
// If both sides used the same PRS, sid, and CI:  aliceIsk === bobIsk
// If anything differed by a single byte:          they diverge completely
```

### CPace worked example: every byte, step by step

This section walks through a *complete* CPace Ristretto255 exchange using the official test vector from [draft-irtf-cfrg-cpace-20 §B.3](https://www.ietf.org/archive/id/draft-irtf-cfrg-cpace-20.txt). Every hex value below is from the draft text and is asserted byte-for-byte by [test/vectors/cpace-ristretto255-sha512.test.ts](./test/vectors/cpace-ristretto255-sha512.test.ts) against pake-js. You can run `npm run test:vectors` and watch it pass.

Normally you would **never** know the ephemeral scalars `ya` and `yb` ahead of time — they are freshly sampled randomness that gets wiped at the end of the session. The only reason we know them here is that the spec needs fixed inputs to produce a reproducible vector. Treat this walkthrough as "what is happening inside the black box," not as how you would call the public API.

#### Inputs — what Alice and Bob both know going in

```text
PRS  (8 bytes)   = 50 61 73 73 77 6f 72 64                               # ASCII: "Password"
CI   (24 bytes)  = 0b 41 5f 69 6e 69 74 69 61 74 6f 72
                    0b 42 5f 72 65 73 70 6f 6e 64 65 72                  # channel identifier
sid  (16 bytes)  = 7e 4b 47 91 d6 a8 ef 01 9b 93 6c 79 fb 7f 2c 57       # session id
ADa  (3 bytes)   = 41 44 61                                              # ASCII: "ADa"
ADb  (3 bytes)   = 41 44 62                                              # ASCII: "ADb"
```

Both parties feed the same `PRS`, `CI`, `sid` into the protocol. The `ADa` / `ADb` values are small pieces of "who I am" that each party binds into its side of the transcript.

#### Step 1 — Build the `generator_string` (170 bytes)

CPace concatenates the domain-separation tag `"CPaceRistretto255"`, the `PRS`, a carefully-sized zero-pad block, the `CI`, and the `sid`, each prefixed with its LEB128 length. The zero-pad is sized so that the first hash block (128 bytes for SHA-512) is filled exactly by the domain tag, the `PRS`, and the padding — this prevents length-extension-style confusion between the secret `PRS` and the public fields.

```text
generator_string (170 bytes) =
  11                                                       # leb128(17)
  43 50 61 63 65 52 69 73 74 72 65 74 74 6f 32 35 35       # "CPaceRistretto255"
  08                                                       # leb128(8)
  50 61 73 73 77 6f 72 64                                  # "Password"
  64                                                       # leb128(100): zero-pad length
  00 × 100                                                 # 100 bytes of zero-padding
  18                                                       # leb128(24)
  0b 41 5f 69 6e 69 74 69 61 74 6f 72
  0b 42 5f 72 65 73 70 6f 6e 64 65 72                      # CI
  10                                                       # leb128(16)
  7e 4b 47 91 d6 a8 ef 01 9b 93 6c 79 fb 7f 2c 57          # sid
```

Hashed through SHA-512, this produces 64 bytes of uniformly-random-looking output:

```text
SHA-512(generator_string) =
  da 6d 3d dc 88 02 fc a9 05 87 55 ff d3 eb de 08
  a9 c2 c7 49 45 90 1a 25 84 82 a2 88 b6 66 3a f0
  6b f6 45 c9 3c d1 c5 15 12 30 71 99 c8 0e 84 90
  89 16 d9 83 b3 4a f7 72 05 f9 08 51 a6 57 ee 27
```

#### Step 2 — Map those 64 bytes onto the Ristretto255 curve → `g`

The 64-byte hash is fed into the Ristretto255 **one-way map** (RFC 9496 §4). It deterministically produces a point on the curve, encoded as 32 bytes:

```text
g (32 bytes) = 22 2b 6b 19 5f e8 4b 16 52 ba db 6f 6a 3a e3 d2
               43 41 e7 30 69 67 f0 b8 11 5b 40 d5 69 8c 7e 56
```

**This is the "tinted starting point" from the plain-English explanation.** Both Alice and Bob compute exactly this `g` from the same inputs. Anybody else — anyone who does not know `PRS` — would derive a *different* `g` and from then on would be doing arithmetic on the wrong curve element.

#### Step 3 — Alice rolls a random scalar `ya`, sends `Ya = ya · g`

Alice's ephemeral secret (little-endian, 32 bytes):

```text
ya = da 3d 23 70 0a 9e 56 99 25 8a ef 94 dc 06 0d fd
     a5 eb b6 1f 02 a5 ea 77 fa d5 3f 4f f0 97 6d 08
```

She keeps `ya` private forever. She computes `Ya = ya · g` and sends only `Ya`:

```text
Ya (32 bytes) = d6 ba c4 80 f2 c3 86 c3 94 ef c7 c4 7a db 99 25
                dc d2 63 0b 64 f2 40 c5 0f 8d 0e ec 48 2b 91 57
```

#### Step 4 — Bob rolls a random scalar `yb`, sends `Yb = yb · g`

Bob's ephemeral secret (also little-endian, 32 bytes):

```text
yb = d2 31 6b 45 47 18 c3 53 62 d8 3d 69 df 63 20 f3
     85 78 ed 59 84 65 14 35 e2 94 97 62 d9 00 b8 0d
```

Bob keeps `yb` private forever. He sends `Yb`:

```text
Yb (32 bytes) = 3e a7 e0 b1 95 60 d7 c0 b0 f5 73 4f 63 b9 55 28
                6d fa 82 32 b5 eb e6 33 24 e2 d9 e7 43 3f 72 58
```

#### Step 5 — Both sides compute the same shared point `K`

Alice computes `K = ya · Yb` (her own secret times Bob's public share). Bob computes `K = yb · Ya` (his own secret times Alice's public share). Because scalar multiplication on an abelian group commutes, both sides arrive at the **same** 32-byte point:

```text
K (32 bytes) = 80 b6 9a 8a 76 45 7a b6 a4 d7 f8 87 a4 bf 6b 55
               a2 f8 0a c1 9c 33 3f 91 7a 05 fc 98 87 c8 b4 0f
```

Spec abort condition: if `K` is the identity element, either the peer's share was invalid or someone is trying to break the protocol. pake-js throws in that case. Here `K` is clearly non-identity, so both sides continue.

#### Step 6 — Build the transcript and hash it to get the 64-byte `ISK`

In the initiator/responder setting, both sides compute:

```text
transcript = lv_cat( "CPaceRistretto255_ISK" , sid , K )
           || lv_cat( Ya , ADa )
           || lv_cat( Yb , ADb )
```

Plugging in the real bytes, the full pre-hash input is 146 bytes:

```text
prefix (43 bytes):
  15                                                         # leb128(21)
  43 50 61 63 65 52 69 73 74 72 65 74 74 6f 32 35 35
  5f 49 53 4b                                                # "CPaceRistretto255_ISK"
  10                                                         # leb128(16)
  7e 4b 47 91 d6 a8 ef 01 9b 93 6c 79 fb 7f 2c 57            # sid
  20                                                         # leb128(32)
  80 b6 9a 8a 76 45 7a b6 a4 d7 f8 87 a4 bf 6b 55
  a2 f8 0a c1 9c 33 3f 91 7a 05 fc 98 87 c8 b4 0f            # K

initiator half (37 bytes):
  20                                                         # leb128(32)
  d6 ba c4 80 f2 c3 86 c3 94 ef c7 c4 7a db 99 25
  dc d2 63 0b 64 f2 40 c5 0f 8d 0e ec 48 2b 91 57            # Ya
  03                                                         # leb128(3)
  41 44 61                                                   # ADa

responder half (37 bytes):
  20                                                         # leb128(32)
  3e a7 e0 b1 95 60 d7 c0 b0 f5 73 4f 63 b9 55 28
  6d fa 82 32 b5 eb e6 33 24 e2 d9 e7 43 3f 72 58            # Yb
  03                                                         # leb128(3)
  41 44 62                                                   # ADb
```

Feed all 146 bytes through SHA-512 and you get the 64-byte **ISK** — the Intermediate Session Key that both Alice and Bob land on:

```text
ISK_IR (64 bytes) =
  b6 9e ff bf 61 b5 1d 56 40 1c 0f 65 60 1a be 42
  8d e8 20 6f ea af 0e 32 19 88 96 dc ae 7b 35 cd
  2b 38 95 0a 39 df d5 d4 a7 91 64 61 4c 29 84 f7
  da a4 60 b5 88 c1 e8 0c 3f a2 06 8a f7 90 04 47
```

That's the handshake done. Alice used `ya` and Bob's `Yb`; Bob used `yb` and Alice's `Ya`; they both hashed the same transcript bytes and got the same 64 bytes of session key.

#### Quick sanity comparison

Here's what an observer on the wire saw for the entire session:

| Direction | Bytes | What it looks like |
| --- | --- | --- |
| Alice → Bob | `Ya` (32 B) | `d6bac480…482b9157` |
| Bob → Alice | `Yb` (32 B) | `3ea7e0b1…433f7258` |

That's it. **64 bytes total, both statistically indistinguishable from random.** No `PRS`, no `ya`, no `yb`, no `g`, no `K`, no `ISK`. An attacker capturing this stream learns nothing they can run through a password cracker later; the only thing they can do is actively play man-in-the-middle and try to complete the handshake with a *guessed* `PRS`, which fails unless they guess right on the first try.

#### Reproduce it yourself

```bash
# Run just the CPace vector test — every assertion below is checked byte-for-byte.
npx vitest run test/vectors/cpace-ristretto255-sha512.test.ts
```

Or in plain code (using the internal deterministic helpers that the vector test uses):

```ts
import {
  __calculateGeneratorEncoded,
  __initWithScalar,
  deriveIskInitiatorResponder,
} from "@cipherman/pake-js/cpace";

const hex = (s: string) => new Uint8Array(s.match(/../g)!.map((b) => parseInt(b, 16)));
const leScalar = (h: string) => {
  const b = hex(h);
  let x = 0n;
  for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]!);
  return x;
};

const PRS = hex("50617373776f7264");
const CI  = hex("0b415f696e69746961746f720b425f726573706f6e646572");
const sid = hex("7e4b4791d6a8ef019b936c79fb7f2c57");
const ADa = hex("414461");
const ADb = hex("414462");
const ya  = leScalar("da3d23700a9e5699258aef94dc060dfda5ebb61f02a5ea77fad53f4ff0976d08");
const yb  = leScalar("d2316b454718c35362d83d69df6320f38578ed5984651435e2949762d900b80d");

console.log("g =", toHex(__calculateGeneratorEncoded(PRS, CI, sid)));
// -> 222b6b195fe84b1652badb6f6a3ae3d24341e7306967f0b8115b40d5698c7e56

const alice = __initWithScalar({ PRS, sid, CI }, ya);
const bob   = __initWithScalar({ PRS, sid, CI }, yb);

console.log("Ya =", toHex(alice.share));
// -> d6bac480f2c386c394efc7c47adb9925dcd2630b64f240c50f8d0eec482b9157
console.log("Yb =", toHex(bob.share));
// -> 3ea7e0b19560d7c0b0f5734f63b955286dfa8232b5ebe63324e2d9e7433f7258

const iskAlice = deriveIskInitiatorResponder({
  ephemeralSecret: alice.ephemeralSecret,
  ownShare: alice.share,
  peerShare: bob.share,
  ownAD: ADa,
  peerAD: ADb,
  sid,
  role: "initiator",
});
console.log("ISK =", toHex(iskAlice));
// -> b69effbf61b51d56401c0f65601abe428de8206feaaf0e32198896dcae7b35cd
//    2b38950a39dfd5d4a79164614c2984f7daa460b588c1e80c3fa2068af7900447
```

The `__initWithScalar` / `__calculateGeneratorEncoded` helpers are prefixed with `__` because they are **internal, for deterministic tests only** — production code must use `cpace.ristretto255.init()` which samples its scalars from the platform CSPRNG. They are documented here purely so you can verify the spec vector against the library on your own machine.

### CPace-specific notes

- **There is no explicit key confirmation step in vanilla CPace.** Confirmation is implicit: if both sides compute the same ISK, the first application-level message encrypted under the ISK will either decrypt correctly (success) or fail the AEAD tag check (abort). You can build an explicit challenge/response on top if your application needs a dedicated round before sending payload.
- **`scalar_mult_vfy` aborts on two specific inputs**: an undecodable Ristretto255 encoding and the identity element. pake-js throws in both cases; handle the throw as "peer is malicious or broken, drop the session."
- **The shared secret stays in the Ristretto255 group.** CPace never exposes it to code that might compare bytes non-constant-time; the only way out is the ISK.
- **Reusing `sid` across sessions breaks the protocol's freshness guarantee.** If both sides re-derive the same `(PRS, sid)` they'll compute the same ISK, which is what you'd want for protocol-level testing but NOT in production. In production, `sid` must change on every session.

## Design rules

1. **One runtime dependency.** The only direct runtime dependency is `@noble/curves`, which transitively pulls in `@noble/hashes` (same author, same audit posture). PRs adding another runtime dependency will not be accepted without a security justification in `THREAT_MODEL.md`.
2. **Stateless only.** Functions take inputs, return plain data. No classes hold protocol state.
3. **No hand-rolled crypto.** All field arithmetic, point decoding, and constant-time primitives are delegated to `@noble/curves` / `@noble/hashes`.
4. **No fallbacks.** If `globalThis.crypto.getRandomValues` is missing, `randomBytes` throws. There is no polyfill and no `Math.random` fallback.
5. **No telemetry, no network, no dynamic imports** in shipped code.

## Development

```bash
npm ci
npm run typecheck
npm run lint
npm run test
npm run test:vectors   # RFC/draft test vectors only (once loaded)
npm run build
npm run size
```

Run a single test file:

```bash
npx vitest run test/spake2plus/p256.roundtrip.test.ts
```

## Compliance posture

- TypeScript `strict` mode, `exactOptionalPropertyTypes`, `noUncheckedIndexedAccess`.
- Releases are published with [npm provenance](https://docs.npmjs.com/generating-provenance-statements) (SLSA) via GitHub Actions OIDC.
- CycloneDX SBOM attached to every GitHub release.
- CodeQL `security-extended` queries run on every PR.
- `SECURITY.md` describes private vulnerability reporting; response SLA is 72 hours.
- `THREAT_MODEL.md` is the gating document for production use — read it.

## Contributing

1. Read `THREAT_MODEL.md` and `SECURITY.md` before touching anything in `src/spake2plus/` or `src/cpace/`.
2. Any change to protocol constants, transcript layout, or KDF info strings needs a spec citation in the commit message.
3. Any change that could affect on-wire bytes needs an RFC / draft test vector that covers it.
4. Never adjust a test vector to make a failing test pass.

## License

MIT — see [`LICENSE`](./LICENSE).

## References

- RFC 9383 — SPAKE2+, an Augmented PAKE: <https://www.rfc-editor.org/rfc/rfc9383>
- draft-irtf-cfrg-cpace-20 — CPace, a Balanced Composable PAKE: <https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/>
- `@noble/curves`: <https://github.com/paulmillr/noble-curves>
