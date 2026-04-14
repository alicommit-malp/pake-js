// Public API for SPAKE2+ (RFC 9383).
//
// Stateless: every function takes its inputs explicitly and returns outputs.
// The caller owns all protocol state (no classes, no hidden storage).
//
// Two ciphersuites are exposed:
//   - p256:    SPAKE2PLUS-P256-SHA256-HKDF-SHA256-HMAC-SHA256  (RFC 9383, verified primary)
//   - ed25519: SPAKE2PLUS-EDWARDS25519-SHA256-HKDF-SHA256-HMAC-SHA256
//              (see THREAT_MODEL.md §"Constants verification" before production use)

export * as p256 from "./p256.js";
export * as ed25519 from "./ed25519.js";
