# Threat Model

This document records the assumptions, goals, non-goals, and adversary model that `pake-js` is designed against. It is a living document — any change that affects the protocol surface, the dependency set, or the validation logic must be reflected here in the same PR.

## Goals

- **Mutual authentication** of two parties who share a low-entropy secret (password, PIN, device-bonding code) without disclosing the secret to a passive eavesdropper or an active attacker.
- **Forward secrecy**: compromise of the long-term password-derived verifier does not compromise past session keys.
- **Online-guessing resistance**: an attacker observing or interacting with a single session learns at most one password guess.
- **Standards compliance**: byte-for-byte conformance with RFC 9383 (SPAKE2+) and `draft-irtf-cfrg-cpace-20` (CPace). Incompatibility with a conformant peer is treated as a bug.
- **Auditability**: stateless API, small surface area, a single runtime dependency, and no hand-rolled field/group arithmetic.

## Non-goals

- **Password storage**: pake-js does not include an MHF (scrypt, Argon2id, PBKDF2). Applications supply MHF output as input to `deriveScalars` / `init`.
- **Transport security**: pake-js produces a shared key; using it to protect an actual channel (AEAD framing, replay protection, channel binding) is the application's responsibility.
- **Identity management**: usernames, enrollment, password reset flows, rate-limiting of online guesses. pake-js authenticates the possession of a password, not the policies around it.
- **Post-quantum resistance**: SPAKE2+ and CPace are classical protocols. A quantum adversary capable of solving the discrete log problem breaks both.
- **Side-channel protection at the hardware level**: we rely on the constant-time guarantees of `@noble/curves`. Hardware-level leakage (EM, power, cache) is out of scope.

## Adversary model

We consider a Dolev-Yao network attacker who:

- Sees every byte on the wire in both directions.
- Can inject, reorder, drop, and replay messages.
- Can run arbitrary parallel sessions with either party.
- Can obtain the server's verifier (`w0`, `L` for SPAKE2+) through a server compromise after the fact — past session keys must remain secure.
- **Cannot** observe local RNG output or memory of either party during a session.
- **Cannot** violate the discrete-log hardness of P-256, edwards25519, or Ristretto255.

Online guessing is mitigated at the *rate* layer (application-enforced), not the *feasibility* layer (protocol-enforced): the protocol guarantees at most one guess per active session.

## Trust boundaries

| Boundary | Trusted | Not trusted |
| --- | --- | --- |
| Random number generator | `globalThis.crypto.getRandomValues` | Any polyfill; `Math.random` |
| Curve / hash primitives | `@noble/curves`, `@noble/hashes` (same author, audited) | Hand-rolled field arithmetic, WebCrypto point ops |
| Transport | The application's TLS / DTLS / secure channel | The raw network |
| Time source | Not used (protocol is time-independent) | — |

## Known risks and mitigations

### R1 — Wrong protocol constants

A single wrong byte in M, N, DSI, or HKDF info strings silently breaks interoperability and may weaken the protocol.

**Mitigation**: constants live in named hex strings at the top of each suite file with a spec citation. They must match the RFC appendix test vectors. Any change requires a spec reference in the commit message.

### R2 — Unverified test vectors

Roundtrip tests prove self-consistency but not interoperability. A conformant peer may still reject our output if an undetected off-by-one exists.

**Mitigation**: `test/vectors/` is the authoritative correctness gate. Currently wired up:

- `spake2plus-p256-sha256.json` — RFC 9383 Appendix C, first P-256/SHA-256 vector, verified byte-for-byte across `L`, `shareP`, `shareV`, `Z`, `V`, `K_main`, `K_confirmP`, `K_confirmV`, `K_shared`, and both confirmation MACs.
- `cpace-ristretto255-sha512.json` — draft-20 Appendix B.3, verified byte-for-byte across `generator_string`, SHA-512 hash output, encoded `g`, `Ya`, `Yb`, `K`, `ISK_IR`, `ISK_SY`, and both `scalar_mult_vfy` valid/invalid test cases.

Still outstanding: the **edwards25519 SPAKE2+** suite has no appendix vector wired up and is therefore still marked SPEC-VERIFY. The M, N constants in `src/spake2plus/ed25519.ts` came from a secondary source and MUST be cross-checked against RFC 9383 Appendix before the suite is used in production.

Vectors must be copied verbatim — never "adjusted" to match code. If a vector fails, the code is wrong.

### R3 — Non-constant-time comparison

Comparing confirmation MACs with `===` or `Buffer.equals` leaks byte-by-byte timing and enables online guessing acceleration.

**Mitigation**: `ctEqual` in `src/util/bytes.ts` is the only comparison used for secret material. ESLint could add a custom rule forbidding `===` on `Uint8Array` in future.

### R4 — Identity / low-order points

Accepting the identity element as a peer share degrades SPAKE2+ to zero-entropy and CPace to trivial. RFC 9383 §4 and CPace §4.4 both require abort.

**Mitigation**: `serverRespond` and `clientFinish` assert `Z` and `V` are non-identity. `cpace.scalarMultVfy` aborts on identity result and on Ristretto255 decode failure.

### R5 — RNG failure

A silent fallback to `Math.random` on a constrained runtime would be catastrophic.

**Mitigation**: `randomBytes` throws loudly if `globalThis.crypto.getRandomValues` is missing. No fallback. CI runs on Node 18, 20, 22 where WebCrypto is built-in.

### R6 — Supply chain

A compromised dependency can exfiltrate passwords.

**Mitigation**: exactly one direct runtime dependency (`@noble/curves`). Releases use npm provenance via GitHub Actions OIDC. A CycloneDX SBOM is attached to every release. `npm audit` runs in CI. Any PR adding a runtime dependency requires maintainer review and a note in this file.

### R7 — Misuse of the stateless API

Callers could reuse ephemeral scalars across sessions, mix `w0`/`w1` between parties, or forget to validate the peer's confirmation MAC.

**Mitigation**: documentation and examples emphasise one-shot use. The API does not expose scalars as long-lived objects — every call returns fresh bytes the caller must keep for exactly one session.

## Audit checklist (gates production use)

Before deploying `pake-js` in a regulated setting, an independent reviewer should confirm:

- [ ] Every constant in `src/spake2plus/*.ts` and `src/cpace/*.ts` matches the RFC / draft byte-for-byte. (P-256 M,N and CPace DSI are gated by vectors; ed25519 M,N are NOT yet gated.)
- [ ] The `test/vectors/` directory contains the full appendix vectors for every suite actually used, and they pass. (Currently: P-256 ✓, CPace Ristretto255 ✓, edwards25519 ✗.)
- [ ] No `===` / `Buffer.equals` appears in any comparison of secret material.
- [ ] `npm ls` shows exactly `@noble/curves` (plus its transitives — currently `@noble/hashes`) and nothing else.
- [ ] The published tarball (`npm pack`) contains only the files listed in `package.json#files`.
- [ ] The `dist/` build was produced by the release workflow, not locally, and carries a provenance attestation.
- [ ] The calling application passes a proper MHF output (scrypt/Argon2id) to `deriveScalars` / `init`, not a raw password.
- [ ] The calling application verifies the peer's key-confirmation MAC before using `K_shared` for anything.
- [ ] A threat model for the *calling application* (rate limiting, account lockout, channel binding) has been reviewed and accepted.
