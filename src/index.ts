// pake-js — Password-Authenticated Key Exchange for Node, Deno, Bun, browsers.
//
// Protocols:
//   - SPAKE2+    (RFC 9383)            via `pake.spake2plus.*`
//   - CPace      (draft-irtf-cfrg-cpace-20) via `pake.cpace.*`
//
// Only runtime dependency: @noble/curves (and its transitive @noble/hashes).
//
// All functions are stateless: callers pass inputs explicitly and receive
// outputs as plain objects. No classes hold protocol state.
//
// See SECURITY.md and THREAT_MODEL.md before using in a regulated environment.

export * as spake2plus from "./spake2plus/index.js";
export * as cpace from "./cpace/index.js";
