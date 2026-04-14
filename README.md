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
npm install pake-js
# or: pnpm add pake-js / yarn add pake-js / bun add pake-js
```

## Ciphersuites

| Protocol | Suite | Import path |
| --- | --- | --- |
| SPAKE2+ (RFC 9383) | `SPAKE2PLUS-P256-SHA256-HKDF-SHA256-HMAC-SHA256` | `pake-js/spake2plus` → `p256` |
| SPAKE2+ (RFC 9383) | `SPAKE2PLUS-EDWARDS25519-SHA256-HKDF-SHA256-HMAC-SHA256` | `pake-js/spake2plus` → `ed25519` |
| CPace (draft-20) | `CPACE-RISTR255-SHA512` | `pake-js/cpace` → `ristretto255` |

> The edwards25519 SPAKE2+ suite is marked SPEC-VERIFY: the M, N constants must be cross-checked against RFC 9383 and the appendix test vectors must pass before production use. See [`THREAT_MODEL.md`](./THREAT_MODEL.md) §R2.

## SPAKE2+ example (P-256 / SHA-256)

```ts
import { spake2plus } from "pake-js";

// ---- 1. Registration (server-side, one-time) ---------------------------
// You run your memory-hard function first. pake-js does NOT bundle an MHF —
// use scrypt, Argon2id, or PBKDF2 with a strong iteration count. Output must
// be >= 80 bytes.
const mhfOutput = await yourMhf(password, { salt: perUserSalt, dkLen: 80 });

const { w0, w1 } = spake2plus.p256.deriveScalars(mhfOutput);
const L = spake2plus.p256.registerVerifier(w1);
// Server stores (w0, L). Client keeps (w0, w1) — or re-derives per session.

// ---- 2. Protocol exchange ----------------------------------------------
const client = spake2plus.p256.clientStart(w0);
send(client.shareP); // -> server

const server = spake2plus.p256.serverRespond({ w0, L, shareP: client.shareP });
send(server.shareV); // -> client

const cf = spake2plus.p256.clientFinish({
  w0,
  w1,
  x: client.x,
  shareV: server.shareV,
});

// ---- 3. Key derivation (both sides) ------------------------------------
const base = {
  context: new TextEncoder().encode("my-app v1"),
  idProver: new TextEncoder().encode("alice@example.test"),
  idVerifier: new TextEncoder().encode("server.example.test"),
  w0,
  shareP: client.shareP,
  shareV: server.shareV,
};

const clientKeys = spake2plus.p256.deriveKeys({ ...base, Z: cf.Z, V: cf.V });
const serverKeys = spake2plus.p256.deriveKeys({ ...base, Z: server.Z, V: server.V });

// ---- 4. Key confirmation ------------------------------------------------
if (
  !spake2plus.p256.verifyConfirmation(clientKeys.confirmV, serverKeys.confirmV)
) {
  throw new Error("server confirmation failed");
}
// clientKeys.K_shared === serverKeys.K_shared (32 bytes for SHA-256).
// Feed K_shared into an application-level KDF; do not use as a session key directly.
```

## CPace example (Ristretto255 / SHA-512)

```ts
import { cpace } from "pake-js";

const PRS = await yourMhf(password, { salt });
const sid = await agreedSessionId(); // 16+ bytes of agreed randomness
const CI = new TextEncoder().encode("tls-exporter:abc123"); // optional channel binding

// Each party independently:
const me = cpace.ristretto255.init({ PRS, sid, CI });
send(me.share);

// After receiving the peer's share:
const isk = cpace.ristretto255.deriveIskInitiatorResponder({
  ephemeralSecret: me.ephemeralSecret,
  ownShare: me.share,
  peerShare: receivedFromPeer,
  sid,
  role: "initiator",
});
// isk is 64 bytes of SHA-512 output.
```

A symmetric (order-independent) variant is available via `deriveIskSymmetric`.

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
