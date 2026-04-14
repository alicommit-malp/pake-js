# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Status

The repository is a fresh scaffold. Only `LICENSE` (MIT) and a stub `README.md` exist. There is no source code, build system, or tests yet. Any instance picking this up is expected to establish the initial structure in line with the constraints below — do not infer conventions from files that don't exist.

## What this package is

`pake-js` is an npm package implementing Password-Authenticated Key Exchange protocols for use in **regulated medical environments**. It must be auditable and suitable for compliance review. Intended consumers are Node.js servers, browsers, and every JS framework (the package stays framework-agnostic — pure ESM/CJS, no framework adapters).

Repository: https://github.com/alicommit-malp/pake-js

### Protocols in scope

- **SPAKE2+** per RFC 9383, two suites:
  - `SPAKE2PLUS-P256-SHA256-HKDF-SHA256-HMAC-SHA256` (RFC 9383 mandatory)
  - `SPAKE2PLUS-ED25519-SHA256-HKDF-SHA256-HMAC-SHA256` and/or a Ristretto255/SHA-512 variant (the user asked for "both"; confirm the exact second suite against the IANA registry before implementing — do not invent a ciphersuite).
- **CPace** per `draft-irtf-cfrg-cpace-20`, single suite:
  - `CPACE-RISTR255-SHA512` (Ristretto255 group, SHA-512 hash, HKDF-SHA-512 where the draft calls for HKDF).

### Hard constraints (agreed with the user)

1. **Only runtime dependency**: `@noble/curves`. No other crypto libs, no polyfills, no framework shims. `@noble/hashes` is acceptable if required transitively by `@noble/curves`.
2. **Stateless API only.** Functions like `spake2plus.clientStart(...)`, `spake2plus.serverRespond(...)`, `cpace.init(...)` — no classes holding protocol state. The caller owns all state. This is a deliberate auditability choice: easier to reason about, easier to test, easier to review.
3. **License**: MIT (already in place — do not change).
4. **Universal build**: dual ESM/CJS, TypeScript strict mode, targets Node ≥18, Deno, Bun, and modern browsers. No Node-only APIs in the core (`crypto.webcrypto` / `globalThis.crypto` only, or delegate to `@noble/curves`' RNG).

## Non-negotiable rule for cryptographic code

**Never write protocol constants, DSI labels, transcript layouts, HKDF info strings, point generators, or test vectors from memory or from summarized spec output.** For a regulated medical library, a single wrong byte is a security incident.

Before implementing any crypto body:

1. Fetch the literal spec text (RFC 9383, draft-irtf-cfrg-cpace-20) and copy constants byte-for-byte.
2. Include the official appendix test vectors as fixtures and make them the primary correctness gate. If a test vector fails, the implementation is wrong — do not "adjust" the vector.
3. If a detail cannot be verified against the spec (e.g., a summarizer paraphrased it), stop and fetch again or mark the code with a `TODO(spec-verify)` comment and a failing test rather than guessing.
4. Rely on `@noble/curves` for all field/group operations and scalar sampling. Do not hand-roll constant-time code, modular reductions, or point decoding.

## Compliance posture to maintain

When establishing the build/CI, these are the posture items the user expects:

- TypeScript strict, no `any`, no `// @ts-ignore` without justification.
- No telemetry, no network calls, no dynamic `require`/`import()` in runtime code.
- CI must run: typecheck, lint, unit tests, RFC test vectors, `npm audit`, bundle-size budget, and a browser smoke test.
- Release pipeline should publish via GitHub Actions OIDC with npm provenance and attach an SBOM (CycloneDX) + SLSA provenance to the GitHub release.
- `SECURITY.md` and a threat model document live at the repo root and are updated alongside code changes that touch the protocol surface.
- Semver is strict; any change to protocol output bytes or public API is a major bump even if "nobody uses it yet."

## Commands

No build system is configured yet. Once `package.json` exists, document the real commands here (install, build, test, test a single file, lint, typecheck, vector-only run). Do not list commands that don't work.

## When the user says "both SPAKE2+ suites"

Earlier in the seed conversation the user confirmed they want both SPAKE2+ suites implemented. The two suites were proposed as "P-256/SHA-256 and Ristretto255/SHA-512." RFC 9383 does not register a Ristretto255 suite — it registers edwards25519 and edwards448 variants. Before writing code for the second suite, re-confirm with the user whether they want:

- (a) the standardized `SPAKE2PLUS-ED25519-...` suite, or
- (b) a non-standard Ristretto255 suite (which would need a documented DSI and generator derivation, and cannot claim RFC 9383 compliance).

Do not silently pick one. This is the kind of decision that has to be written down, not inferred.
