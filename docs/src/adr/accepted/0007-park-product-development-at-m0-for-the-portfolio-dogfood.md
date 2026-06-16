# ADR-0007: Park product development at M0 for the portfolio dogfood

> State: Accepted

## Status

Accepted

## Stakeholders

Portfolio owner (decision), pulse maintainers (bound by the freeze).

## Context and Problem Statement

Pulse has reached M0: the blind-signature protocol is proven end to end — the
full workspace test suite passes and the multi-tenant simulation completes
every flow over real HTTP with k-anonymity-suppressed analytics. The product
roadmap beyond M0 (pilot deployment, KMS integration, SSO, control plane,
production clients) assumes a real customer with real employees. The portfolio
dogfood loop has neither: there is no real survey population, so M1+ feature
work would produce zero signal while consuming the portfolio's most
intellectually attractive codebase budget. A deliberate scope decision is
needed before gravity makes it by default.

## Decision Drivers

- No customer and no employees means M1+ feature work has zero validation
  signal.
- The dogfood loop needs a Measure-stage demo, which the existing simulation
  already nearly provides.
- Scope gravity is a named portfolio risk: pulse is the most tempting codebase
  to keep building.
- A parked repo must still stay healthy across toolchain and dependency drift.

## Considered Options

- Park at M0: freeze the product roadmap, limit work to loop integration and
  maintenance, and repurpose the simulation as the deterministic Measure-stage
  demo.
- Continue product build-out toward M1 (KMS, SSO, control plane, production
  clients) without a deployment driver.
- Archive the repo entirely until a customer appears.

## Decision Outcome

Chosen: **park at M0**, because it is the only honest match between effort and
signal. The product roadmap from M1 onward is frozen for the duration of the
portfolio dogfood — no new protocol or product features. Pulse's near-term
role is the deterministic, seeded iteration-retro demo: the existing simulation
repurposed as the Measure-stage artifact of the dogfood loop, surveying
simulated respondents about the dogfood iteration itself and emitting a
machine-readable k-anonymous aggregate. Allowed work is loop plumbing
(justfile, machine-readable report, survey-as-data, this ADR corpus), doc
honesty, and maintenance (toolchain/dependency drift, keeping the gate green).
Pulse also remains the portfolio's reference for engineering conventions
(newtypes, Sensitive redaction, trust-zone seams). Product build-out resumes
only when a real deployment driver exists, and un-parking requires a
superseding ADR.

### Positive Consequences

- Portfolio time goes where there is signal; pulse stops being a scope-gravity
  risk.
- The simulation gains a second job as a deterministic regression test and
  Measure-stage demo.
- The freeze is recorded and lintable instead of living in someone's head:
  feature work without a superseding ADR is out of process.

### Negative Consequences

- Product momentum is deliberately lost; restarting M1 later will cost ramp-up
  time.
- The roadmap and book must be kept honest about the freeze, which is ongoing
  doc work.
- A parked repo only stays green if the recurring gate run actually happens
  each iteration — neglect shows up as silent rot.

## Implementation

Effective immediately on acceptance: M1+ milestones are treated as frozen;
each portfolio iteration runs the full local gate and the simulation demo,
fixes only breakage, and records any new decision here. Un-parking requires a
superseding ADR naming the deployment driver.
