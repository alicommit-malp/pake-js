# Test vectors

This directory is the home for **official test vectors** copied verbatim from the relevant RFC / draft appendices. Roundtrip tests elsewhere in `test/` only prove self-consistency; they cannot catch a subtle bug that makes `pake-js` incompatible with other implementations. Vector tests are the authoritative correctness gate.

## Required vectors before a 1.0 release

- `spake2plus-p256-sha256.json` — RFC 9383 Appendix C test vectors for `SPAKE2PLUS-P256-SHA256-HKDF-SHA256-HMAC-SHA256`.
- `spake2plus-ed25519-sha256.json` — RFC 9383 Appendix C test vectors for `SPAKE2PLUS-EDWARDS25519-SHA256-HKDF-SHA256-HMAC-SHA256`. **This is the blocking item for the ed25519 suite.** Until these vectors pass, the constants in [src/spake2plus/ed25519.ts](../../src/spake2plus/ed25519.ts) are considered unverified.
- `cpace-ristretto255-sha512.json` — Appendix B.3 test vectors from `draft-irtf-cfrg-cpace-20` for `CPACE-RISTR255-SHA512`.

## JSON schema

Each file is an array of objects:

```json
[
  {
    "name": "human-readable label",
    "inputs": { "...hex fields..." },
    "expected": { "...hex fields..." }
  }
]
```

Fields must be hex-encoded with no `0x` prefix. The exact field set depends on the protocol and is fixed by the corresponding test file in `test/vectors/*.test.ts` (to be added alongside the JSON).

## How vectors are added

1. Copy hex values **verbatim** from the canonical spec. Do not reformat, trim, or "clean up" bytes.
2. Include the spec citation in the JSON file's first entry (e.g. `"source": "RFC 9383 Appendix C.1"`).
3. Write a matching `*.test.ts` that loads the JSON and asserts every intermediate value (not just the final key). Every intermediate must be checked so that a failure points at the exact step that diverged.
4. Never adjust a test vector to make a failing test pass. If a vector fails, the implementation is wrong.
