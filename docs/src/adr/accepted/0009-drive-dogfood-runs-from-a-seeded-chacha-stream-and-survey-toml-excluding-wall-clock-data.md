# ADR-0009: Drive dogfood runs from a seeded ChaCha stream and survey TOML, excluding wall-clock data

> State: Accepted

## Status

Accepted

## Stakeholders

Portfolio owner (loop operator), pulse maintainers.

## Context and Problem Statement

The dogfood demo's whole value is that it doubles as a regression test: `just
dogfood` with the same seed must write a byte-identical
`out/pulse-report.json`, or drift in the protocol stack goes unnoticed in a
parked repo. But the simulation is concurrent over real HTTP (task completion
order varies), provisioning generates random UUIDs that appear in the
artifact, respondent answers were hardcoded in `simulate.rs`, and wall-clock
timings can never repeat. Determinism has to be designed, not assumed, and
respondent behavior has to move out of code so each iteration can retro
itself without recompiling.

## Decision Drivers

- Same seed → byte-identical artifact, provable with `diff` across two runs.
- Concurrency must stay (it is part of what the simulation proves), so
  nondeterministic completion order must not be able to reach the artifact.
- Survey content must be data (`dogfood/iteration-retro.toml`), editable per
  iteration without recompiling (survey-as-data direction).
- No AI: respondent answers come from a seeded distribution defined in data —
  deterministic output is the point, generated sentiment would be fake signal.
- A `rand` upgrade should not silently re-roll the artifact stream.
- With N=10 respondents, a misconfigured k either suppresses everything or
  (k=1) disables anonymity in the reference demo — both sides need tests.

## Considered Options

- Seed a pinned ChaCha12 stream for IDs and answer sampling, sample answers
  before tasks spawn, define distributions in TOML, and strip wall-clock
  fields from seeded artifacts.
- Run flows sequentially when seeded (kills the concurrency claim).
- Post-process the JSON to normalize volatile fields (hides drift instead of
  preventing it; the diff stops meaning anything).
- `StdRng` instead of pinned ChaCha (its algorithm is explicitly not stable
  across `rand` versions).

## Decision Outcome

Chosen: **seeded ChaCha12 + pre-spawn sampling + survey TOML + no wall-clock
in seeded artifacts**, because it makes every byte of the artifact a function
of (seed, survey file, code) while leaving the concurrent protocol exercise
untouched.

Mechanics:

- `--seed <u64>` seeds `ChaCha12Rng` explicitly (pinned; survives `rand`
  algorithm changes). The cluster derives tenant and batch UUIDs from one
  stream; the runner samples respondent answers from a second stream salted
  with a fixed constant, so the two uses cannot interleave.
- Answers are sampled in deterministic loop order (tenant × employee × batch)
  **before** any task spawns, into a per-employee `ResponsePlan`. Completion
  order over HTTP cannot reorder them, and Scale5 scores are small integers,
  so the f64 average is exact and order-independent.
- Question text, segment labels, and per-question score weights live in
  `dogfood/iteration-retro.toml`, loaded via `--batch-file`; the harness's
  multi-batch `SimSamplingEngine` serves one batch per retro question.
- Seeded runs strip `timing`/`duration` from the artifact (ADR-0008's
  optional fields); employee secrets stay random because only pseudonym
  *counts* reach the artifact.
- `--k-threshold` configures suppression; the dogfood recipe uses k=5 with 10
  respondents, and integration tests pin both sides (3 < k=5 suppresses,
  10 ≥ k=5 publishes).

### Positive Consequences

- `diff` between two seeded runs is a real regression check on the whole
  protocol stack — the demo is the test.
- Each iteration's retro is a TOML edit, not a code change (park-mode M-p6
  maintenance stays trivial).
- Concurrency, real HTTP, and full blind-signature flows remain exercised.
- The seeded distribution is honest about being synthetic (no AI theater).

### Negative Consequences

- Changing the survey file, seed, or RNG consumption order intentionally
  changes the artifact — consumers must treat (seed, survey) as part of the
  contract.
- Two salted streams from one user-facing seed is a convention that must be
  preserved when adding RNG draws (new draws change downstream values).
- Deterministic artifacts carry no performance data; timing inspection
  requires an unseeded run.

## Implementation

Done in milestone M-p4: `survey.rs` (TOML schema + weighted sampling),
`sampling.rs` (`SimSamplingEngine`), seeded UUIDs in the cluster, pre-spawn
`ResponsePlan` sampling in the runner, `--batch-file`/`--seed`/`--k-threshold`
flags, the checked-in `dogfood/iteration-retro.toml`, and the
`dogfood_determinism` integration suite (byte-identity, seed divergence, and
both k-threshold sides). M-p5 wires `just dogfood`.
