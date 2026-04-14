# Changelog

All notable changes to this project will be documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial scaffold.
- SPAKE2+ per RFC 9383:
  - `SPAKE2PLUS-P256-SHA256-HKDF-SHA256-HMAC-SHA256` — **verified byte-for-byte against RFC 9383 Appendix C** (registerVerifier, clientStart, serverRespond, deriveKeys all match `L`, `shareP`, `shareV`, `Z`, `V`, `K_main`, `K_confirmP`, `K_confirmV`, `K_shared`, `confirmP`, `confirmV`).
  - `SPAKE2PLUS-EDWARDS25519-SHA256-HKDF-SHA256-HMAC-SHA256` (structural implementation; constants still marked SPEC-VERIFY — no ed25519 appendix vector has been wired up yet).
- CPace per `draft-irtf-cfrg-cpace-20`:
  - `CPACE-RISTR255-SHA512` — **verified byte-for-byte against draft-20 Appendix B.3** (generator_string, SHA-512 hash, calculate_generator, Ya/Yb public shares, shared secret K, ISK_IR, ISK_SY, scalar_mult_vfy valid/invalid cases).
- Stateless function-only public API.
- Universal build (ESM + CJS, Node ≥18, Deno, Bun, browsers) via tsup.
- CI on Node 18/20/22 with typecheck, lint, tests, bundle size, `npm audit`, CodeQL.
- Release workflow with npm provenance (SLSA) via GitHub Actions OIDC and CycloneDX SBOM attached to every GitHub release.
- `SECURITY.md`, `THREAT_MODEL.md`, `CLAUDE.md`.

### Fixed during vector wiring

- `oCat` now implements draft-20 Appendix A.3.3 exactly: prepends the 2-byte `b"oc"` tag and places the lexicographically **larger** argument first. The previous implementation omitted the tag and used the opposite ordering; this would have broken interoperability for the symmetric ISK path. Regression-tested against the A.3.3 test vectors.

### Known limitations

- No ed25519 SPAKE2+ appendix vector wired up yet. The edwards25519 suite passes roundtrip tests but is still marked SPEC-VERIFY until RFC 9383's ed25519 appendix vector is added to `test/vectors/`.
- No MHF (scrypt / Argon2id) is bundled; applications must provide MHF output as input to `deriveScalars` / `init`. This is deliberate — see THREAT_MODEL.md "Non-goals".
