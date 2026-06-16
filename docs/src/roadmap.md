# Roadmap

_Product milestones and phasing. Updated as decisions are made and work completes._

Each milestone represents a capability threshold — what a stakeholder can _do_
with Pulse that they couldn't do before.

**Status: parked at M0 — accepted as the suite-done state.** Product
development beyond M0 is frozen for the duration of the portfolio dogfood
(ADR-0007,
`adr/accepted/0007-park-product-development-at-m0-for-the-portfolio-dogfood.md`):
there is no customer and no survey population, so M1+ feature work has zero
validation signal. ADR-0010
(`adr/accepted/0010-accept-dogfooding-parked-at-m0-as-the-suite-done-state.md`)
extends the park and formalizes dogfooding (parked at M0) as pulse's
suite-done state: the bar is the recurring park-mode duty below (green gate
plus the deterministic Measure artifact each iteration), and M1–M3 are
retired by name. Un-parking requires a superseding ADR naming a real
deployment driver — a committed pilot or design-partner customer with a real
respondent population, or an owner-recorded funded SME-pilot decision.

Milestone tracking is **local**: this page plus the `adr/` corpus are the
source of truth. Historical GitHub Milestones on the `como-technologies`
remote are no longer maintained as a tracking source (nothing is pushed in
park mode; `just ci` is the only trusted check).

---

## M0: Protocol Proof — DONE

End-to-end demonstration over real HTTP. The protocol client library, test
harness with multi-tenant simulation, and integration tests turn working
server code into a working _system_: 8-crate workspace, real RFC 9474 blind
RSA, compile-enforced trust-zone isolation, envelope encryption with
crypto-shredding, k-anonymity-suppressed analytics.

### M0 park-mode duties (recurring)

While parked, each portfolio iteration runs:

- `just ci` — the full local gate (fmt, clippy, tests, book, ADR validation)
- `just dogfood` — the deterministic [Measure report](development/dogfood.md)
  consumed by the portfolio's Assess pass

Allowed work: loop plumbing, doc honesty, breakage fixes (toolchain and
dependency drift), new ADRs, and folding one retro question per iteration
into `dogfood/iteration-retro.toml`. No feature work.

This recurring duty **is the suite-done bar**: ADR-0010 accepts dogfooding
(parked at M0) as pulse's suite-done state, so done means kept green and
re-proven each iteration — not climbed.

## M1: First Pilot — RETIRED (ADR-0010)

One real customer, production-grade. KMS-backed key management, SSO
authentication, control plane architecture, and the first production client
shell. _Retired by ADR-0010; re-openable only via a superseding un-park ADR
naming a real deployment driver._

## M2: General Availability — RETIRED (ADR-0010)

Multi-platform, multi-tenant, commercial launch. A second client platform,
automated update mechanisms, campaign management, and self-service tenant
onboarding. _Depends on M1; retired by ADR-0010 for the same reason._

## M3: Full Suite — RETIRED (ADR-0010)

Every employee, every device. Device attestation, embedded/IoT, shared device
provisioning, and confidence-weighted analytics. _Retired by ADR-0010;
furthest from any deployment driver._
