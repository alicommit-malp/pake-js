# Security Policy

## Scope

`pake-js` is a cryptographic library intended for use in regulated environments (medical devices, healthcare backends, compliance-bound services). Every report is triaged accordingly.

## Reporting a vulnerability

**Do not open a public GitHub issue for security problems.** Instead:

1. Use GitHub's [private vulnerability reporting](https://github.com/alicommit-malp/pake-js/security/advisories/new) on this repository, or
2. Email the maintainer listed in `package.json` with subject line `pake-js security`.

Please include: affected version, a minimal reproduction (preferably failing test case), your assessment of impact, and any relevant spec citations. Encrypted reports (PGP) are welcome — request the public key out-of-band if needed.

### Response SLA

| Phase | Target |
| --- | --- |
| Acknowledgement of report | 72 hours |
| Initial impact assessment | 7 days |
| Fix + coordinated disclosure | 90 days (earlier for actively-exploited issues) |

## Supported versions

Until the first 1.0 release, only the most recent minor version is supported. After 1.0, the latest two minor versions receive security fixes.

## What counts as a vulnerability

- Any deviation from RFC 9383 or draft-irtf-cfrg-cpace-20 that changes on-wire bytes or derived keys.
- Missing validation (e.g. accepting an off-curve point, accepting the identity element where the spec says to abort).
- Non-constant-time comparison of secret material.
- RNG bypasses, seed leakage, or fallback to `Math.random`.
- Accidental `console.log` / error messages exposing secret bytes.
- Any new runtime dependency sneaking in beyond `@noble/curves` (see THREAT_MODEL.md).

## What does not count

- TypeScript definition bugs that do not affect runtime behaviour.
- Build tooling issues that do not alter the published `dist/`.
- Performance concerns in the absence of a side-channel argument.

## Compliance posture summary

- Release artifacts are published with [npm provenance](https://docs.npmjs.com/generating-provenance-statements) (SLSA) via GitHub Actions OIDC.
- A CycloneDX SBOM is attached to every GitHub release.
- CodeQL security-extended queries run on every PR and weekly on `main`.
- No telemetry, no network calls, no dynamic `require`/`import()` in shipped code.
- Constant-time primitives are delegated to `@noble/curves` / `@noble/hashes`; no hand-rolled crypto.

See `THREAT_MODEL.md` for the full threat model and the audit checklist that gates production use.
