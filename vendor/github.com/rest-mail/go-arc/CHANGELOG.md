# Changelog

All notable changes to go-arc are documented here. This project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.2.3

A single RFC 8617 §5.1.1 hardening fix on the verify path: the
ARC-Message-Signature must sign the From header. The public API (`Seal`,
`Verify`, `SealOptions`, `SealResult`) is unchanged.

### Fixed

- Verify now requires the ARC-Message-Signature to sign the From header
  (RFC 8617 §5.1.1); a chain whose AMS `h=` omits From is treated as cv=fail
  (#31).

## v0.2.2

Restores ARC-Message-Signature verification — which regressed once go-dkim began
enforcing the RFC 6376 `v=` version rule, since a versionless ARC-Message-Signature
(RFC 8617 §4.1.2) carries no `v=` — together with a set of RFC 8617 verify/seal
correctness fixes. The public API (`Seal`, `Verify`, `SealOptions`, `SealResult`)
is unchanged.

### Changed

- Bumped go-dkim to v0.2.1 and switched ARC-Message-Signature verification onto
  its new policy-free primitive (`dkim.VerifySignatureBare`): ARC now verifies the
  DKIM crypto mechanism and applies RFC 8617 policy itself, rather than inheriting
  RFC 6376 DKIM policy. This fixes ARC verification, which DKIM's `v=` requirement
  had broken for the versionless ARC-Message-Signature (RFC 8617 §4.1.2).

### Fixed

- Verify now enforces the RFC 8617 §5.1.1 maximum of 50 ARC sets before any
  structural or cryptographic check (#9, #24).
- Seal now scopes a `cv=fail` ARC-Seal to the current set only, never signing the
  prior (failed) chain, per RFC 8617 §5.1.2 (#25).
- Verify and Seal now reject an ARC-Seal that carries a forbidden `h=` tag, per
  RFC 8617 §4.1.3 (#26).
- The ARC-Seal now requires its `s=` (selector) and `d=` (domain) tags, with no
  fallback to a substituted default selector (#27).
- Seal now derives the new set's instance number from the highest instance
  present rather than the count of prior sets, so a gapped chain no longer
  collides at an existing instance (#28).
- Verify and Seal now validate ARC instance numbers strictly, reject a repeated
  DKIM tag in an ARC-Message-Signature or ARC-Seal, and sanitize Seal output
  against header injection (#29).
- Seal now rejects an incomplete prior ARC set instead of panicking (#23).

## v0.2.1

Verify-path correctness fixes bringing ARC chain validation into line with
RFC 8617. The public API (`Seal`, `Verify`, `SealOptions`, `SealResult`) is
unchanged.

### Fixed

- Verify now validates the ARC-Seal `cv=` chain-validation tag and enforces a
  consistent chain state across the instances, per RFC 8617 §5.2 (#19).
- Verify now rejects a chain that repeats an ARC header field (ARC-Seal,
  ARC-Message-Signature, or ARC-Authentication-Results) at the same instance
  number, closing a header-injection gap (#20).
- Verify now ignores an unexpected `v=` tag on the ARC-Message-Signature
  instead of failing verification, per RFC 8617 §4.1.2 (#21).

### Changed

- Bumped go-dkim to v0.1.2, which fixes a panic on malformed remote key records
  (#18).

## v0.2.0

See the [GitHub release](https://github.com/rest-mail/go-arc/releases/tag/v0.2.0)
for details.

## v0.1.1

See the [GitHub release](https://github.com/rest-mail/go-arc/releases/tag/v0.1.1)
for details.

## v0.1.0

Initial release: ARC sealing and verification (RFC 8617) built on go-dkim.
