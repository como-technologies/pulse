# ADR-0012: Accept the rsa Marvin timing side-channel advisory

> State: Proposed

## Status

Proposed

## Stakeholders

Pulse maintainers (carry the accepted risk and its removal trigger), suite
maintainer (audit gate uniformity across the portfolio), security reviewer
of any future un-park ADR (must revisit this acceptance before deployment).

## Context and Problem Statement

Adding a dependency-audit gate to pulse (cargo-audit in `just ci` and a
weekly CI sweep) surfaced RUSTSEC-2023-0071 — the Marvin Attack, a
potential RSA private-key recovery through timing side-channels in the
RustCrypto `rsa` crate. It hits pulse twice in one lockfile: pulse-crypto's
direct `rsa` 0.9 dependency, and the `rsa` 0.10 release-candidate line
pulled in by `blind-rsa-signatures`, the RFC 9474 blind-signature
implementation at the heart of the protocol (the Token Issuer signs blinded
tokens it cannot link to responses). The advisory has no fixed upstream
release — upgrading cannot clear it — so an audit gate that treats it as a
failure is permanently red, and a permanently red gate trains everyone to
ignore the gate. The lockfile refresh that accompanied the gate already
cleared every fixable advisory (three rustls-webpki certificate-validation
bypasses), leaving RUSTSEC-2023-0071 as the only remaining finding. What is
missing is a recorded decision: on what grounds pulse accepts this
advisory, and what event removes the acceptance.

## Decision Drivers

- The advisory is structural: `rsa` is the substrate of the RFC 9474
  blind-signature core, not an incidental utility — there is no drop-in
  replacement that preserves the blind-signature protocol.
- No fixed upgrade exists; the RustCrypto tracking issue remains open, so
  "wait and bump" is not an available resolution.
- Exploiting Marvin requires a timing oracle against the signer: an
  attacker must drive private-key operations with chosen inputs and measure
  per-operation timing precisely. Pulse is parked at M0 (ADR-0007,
  ADR-0010) — no deployed signer exists, so no such oracle is exposed today.
- The audit gate must be green-by-default to be trusted; a known,
  reasoned-about advisory must not force every CI run red.
- An acceptance without a removal trigger rots into a permanent blind spot;
  the ignore must name the event that deletes it.
- Ignore entries must live in reviewed, versioned configuration
  (`.cargo/audit.toml`), never in ad-hoc command-line flags that differ
  between local runs and CI.

## Considered Options

1. **Accept by dated, documented ignore** — ignore RUSTSEC-2023-0071 in
   `.cargo/audit.toml` with the rationale and removal trigger recorded
   there and in this ADR; the gate stays green and every other advisory
   still fails it.
2. **Replace the RSA substrate** — move the blind-signature core off the
   RustCrypto `rsa` crate (vendor a constant-time RSA, or rebuild blind
   signatures on another library). Clears the advisory at the cost of
   rewriting or forking the protocol's cryptographic core, against
   ADR-0007's park on product work.
3. **Run the audit red or not at all** — either let CI fail on the known
   advisory (normalizing a red gate) or skip the audit leg entirely
   (losing detection of every future advisory).

## Decision Outcome

Chosen: **option 1, accept by dated, documented ignore**, because the
advisory is unfixable by upgrade, structural to the protocol's
blind-signature core, and outside pulse's current threat surface, while
options 2 and 3 either spend cryptographic-rewrite effort against the
accepted park or destroy the value of the gate itself.

RUSTSEC-2023-0071 is ignored in `.cargo/audit.toml` with a dated comment
carrying the same rationale as this ADR. The single ignore entry covers
both affected lockfile lines (`rsa` 0.9 direct, `rsa` 0.10-rc via
`blind-rsa-signatures`), since cargo-audit matches the advisory ID.

**Threat-model note.** Marvin is a remote timing side-channel on RSA
private-key operations: the attacker needs to submit chosen ciphertexts or
signature requests to the key holder and measure a stable per-operation
timing oracle. In pulse the only private-key holder is the Token Issuer in
the Identity zone. Parked at M0, the signer runs only in local development
and deterministic simulation — there is no deployed endpoint an attacker
can measure. Any un-park ADR (per ADR-0010's criteria) must revisit this
acceptance as part of its security review, because deployment is exactly
the event that creates the oracle surface.

**Removal trigger.** The day an `rsa` release fixing RUSTSEC-2023-0071
ships: delete the ignore entry, `cargo update` (and bump
`blind-rsa-signatures` if the fix arrives through it), and confirm
`cargo audit` is clean with an empty ignore list. The weekly scheduled
audit run exists precisely to notice that day without waiting for a code
change.

### Positive Consequences

- The audit gate lands green and stays meaningful: every advisory except
  the one reasoned about here fails CI immediately.
- The acceptance is versioned, dated, and reviewable — in
  `.cargo/audit.toml` and this corpus — instead of living in a maintainer's
  head or a shell flag.
- The removal trigger plus the weekly sweep make the acceptance
  self-expiring in practice: a fix upstream surfaces as an actionable
  diff, not a silent non-event.

### Negative Consequences

- A real, published advisory against the protocol's core crypto crate is
  deliberately silenced; if pulse's deployment posture changes without the
  un-park review this ADR demands, the acceptance could outlive its
  threat-model justification.
- The ignore is advisory-ID-scoped, not version-scoped: a future lockfile
  could add a third vulnerable `rsa` line and be silently covered by the
  same entry.
- RustCrypto may fix the 0.10 line long before 0.9; the trigger then
  requires migrating pulse-crypto's direct dependency rather than a pure
  lockfile bump, which is real (if small) code work.

## Implementation

Carried in the same change series as this ADR: `.cargo/audit.toml` adds the
dated ignore; `just crate-audit` (wired into `just ci`) runs cargo-audit
honoring it; the CI workflow gains an audit job and a weekly schedule so
new advisories — and the removal trigger — surface without a push. On
acceptance, no further action; on the removal trigger, delete the ignore
entry per the Decision Outcome and record nothing new unless the migration
is itself decision-worthy.
