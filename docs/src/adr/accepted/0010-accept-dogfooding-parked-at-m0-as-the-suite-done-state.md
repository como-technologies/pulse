# ADR-0010: Accept dogfooding parked at M0 as the suite-done state

> State: Accepted

## Status

Accepted

## Stakeholders

Portfolio owner (decision), suite referee (ratified the rung exception for
pulse in iteration 2), pulse maintainers (bound by the bar this sets).

## Context and Problem Statement

The suite mandate asks every portfolio app to reach SME-usable at minimum,
with one escape hatch: all deferred lists must be built or retired by ADR.
Pulse is parked at M0 by ADR-0007 — there is no customer and no respondent
population, so the M1+ product work that SME-usable would require (KMS, SSO,
control plane, production clients) has zero validation signal. Iteration 1
proved the parked configuration works: `just gate` is green, `just dogfood`
emits the deterministic `pulse.measure-report/v1` artifact, and the
portfolio's Assess pass demonstrably consumed it in run-1. What is not yet
recorded is what "done" means for a deliberately parked app. Without a
recorded suite-done bar, every iteration re-litigates whether pulse should
climb, and the retired milestones survive only as prose in the roadmap. This
ADR settles it: it extends — does not supersede — ADR-0007, so the park
stays in force.

## Decision Drivers

- Climbing to SME-usable means un-parking M1+ without a deployment driver,
  which violates accepted ADR-0007 and fabricates Measure signal.
- The suite mandate's escape hatch — all deferred lists built or retired by
  ADR — is the governing clause (iteration-2 referee ruling, ratified for
  pulse only).
- The kept-green proof must be checkable each iteration, not asserted: gate
  exit codes and a byte-identical seeded artifact, enforced in tests.
- Deferred work must not live only in prose; the roadmap's parked milestones
  need a retire-by-ADR record.
- The portfolio book must stay truthful under its verify-claims gate, so the
  suite-done state needs an ADR it can pin.

## Considered Options

- Formalize dogfooding (parked at M0) as pulse's suite-done state by ADR,
  with explicit un-park criteria and the deferred list retired by name.
- Climb the rung to SME-usable: un-park and build M1 (KMS, SSO, control
  plane, production client shell) so pulse matches the mandate's default
  minimum.
- Productize the simulation as an SME-usable demo product (packaging, binary
  distribution, demo UI) so the rung is met without un-parking the product.

## Decision Outcome

Chosen: **formalize dogfooding (parked at M0) as pulse's suite-done state**,
because it is the only target that keeps the book truthful: the rung's other
two routes both spend effort where there is no signal. Climbing to
SME-usable requires real respondents — exactly the M1+ work ADR-0007 froze —
so it would un-park without a deployment driver, against pulse's own
accepted corpus. The simulation-as-demo-product route fails the same
effort/signal test: the simulation's only real consumer is the dogfood loop
(proven in run-1, where the Assess pass consumed `out/pulse-report.json`),
and `just demo` / `just walkthrough` already serve Como-driven demos. The
mandate's escape hatch is satisfied instead by retiring the deferred list by
ADR while the dogfood proof stays green and is re-proven each iteration.

**The suite-done bar.** Pulse is suite-done while, each portfolio iteration:

- `just gate` exits 0 (fmt, clippy `-D warnings`, full workspace tests
  including the reqwest-transport suite, book build, `adroit check` on
  `adr/`), and
- `just dogfood` exits 0 and writes the deterministic
  `pulse.measure-report/v1` artifact — `failed == 0`, at least one
  non-suppressed segment with a numeric `average_score`, two consecutive
  runs byte-identical — handed to the iteration's Assess pass, with one new
  retro question folded into `dogfood/iteration-retro.toml` per iteration.

**Un-park criteria.** Un-parking requires a superseding ADR naming a real
deployment driver, which means one of:

- a committed pilot or design-partner customer with a real respondent
  population, or
- an owner-recorded, funded SME-pilot decision.

Maintenance never requires un-parking: toolchain and dependency drift,
security fixes, and keeping the gate green are always in scope under
ADR-0007's allowed-work list.

**Retired by this ADR** (re-openable only via that superseding un-park ADR):

- M1 First Pilot — KMS-backed key management, SSO authentication, control
  plane, first production client shell.
- M2 General Availability — second client platform, automated updates,
  campaign management, self-service tenant onboarding.
- M3 Full Suite — device attestation, embedded/IoT provisioning,
  confidence-weighted analytics.
- Simulation-as-SME-usable-demo-product — packaging, binary distribution,
  demo UI.
- Wiring the dogfood demo through pulse-relay / the async client transport —
  the direct reqwest transport already proves the flow; routing the demo
  through the least-exercised crates grows the failure surface for zero demo
  value.
- Any AI/ollama lane in pulse — determinism is the feature (the demo doubles
  as a regression test); generated sentiment would be fake Measure signal.

### Positive Consequences

- "Done" for pulse is now a recorded, checkable bar instead of a
  per-iteration argument; the suite can close without pulse climbing.
- The portfolio book's badge — dogfooding (parked) — is pinned to an
  accepted ADR, so the verify-claims gate checks a fact, not a vibe.
- The deferred list is retired by ADR, satisfying the mandate's escape hatch
  without prose-only debt.
- Un-parking has a concrete trigger, so a future customer conversation has a
  ready re-entry path instead of an ambiguous freeze.

### Negative Consequences

- Suite-done for pulse still costs a recurring per-iteration duty (gate +
  dogfood + one retro question); neglect shows up as silent rot.
- The retired milestones make the no-product posture harder to reverse
  casually — re-opening any of them requires authoring a superseding ADR.
- The rung exception is precedent-shaped: it is ratified for pulse only, and
  other apps may be tempted to cite it without an equivalent accepted park
  ADR.

## Implementation

Effective on acceptance. Sync `docs/src/roadmap.md` (M1–M3 lines and the
park banner) and `docs/src/development/dogfood.md` to cite this ADR so the
suite-done claim is book-checkable. Hand the portfolio lane its
verify-claims assertion (an accepted `0010-*.md` records this acceptance)
and the one book sentence stating pulse's suite-done state; the badge line
stays `dogfooding (parked)`. Each iteration, run the suite-done bar above
and record any new decision in this corpus.
