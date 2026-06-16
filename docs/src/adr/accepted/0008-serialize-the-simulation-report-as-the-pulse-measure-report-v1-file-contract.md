# ADR-0008: Serialize the simulation report as the pulse.measure-report/v1 file contract

> State: Accepted

## Status

Accepted

## Stakeholders

Portfolio owner (Measure-contract consumer), pulse maintainers (producer).

## Context and Problem Statement

In the portfolio dogfood loop pulse's interface is a Measure artifact the next
Assess pass consumes. The existing `SimulationReport` prints text only — it is
not `Serialize`, carries no analytics, and identifies nothing about its own
provenance. The Signal zone already computes the right payload
(`BatchAggregation`: total responses, per-segment average score, unique
pseudonyms, k-suppression flag) and serves it at `GET /analytics/batch/{id}`,
but the simulation throws that away. The loop needs a machine-readable shape,
and the shape is a contract: once iteration-2's Assess pass reads it, changing
it casually breaks the loop.

## Decision Drivers

- The Measure artifact is a file contract, not a live service (per the parked
  M0 direction): one JSON document, written by `pulse-simulate`, read later.
- The k-anonymity semantics proven in the Signal zone must survive into the
  artifact unaltered — re-deriving aggregates client-side would fork the truth.
- The artifact doubles as a regression fixture, so a seeded run must serialize
  byte-identically (see ADR-0009); wall-clock data cannot be mandatory.
- Demo honesty: seeded simulated respondents must not be mistakable for real
  survey data.
- Consumers need to detect shape drift without guessing.

## Considered Options

- Derive `Serialize` on the existing report types, embed the server's
  `BatchAggregation` verbatim per batch, and add a self-identifying envelope
  (`schema`, `data_source`, optional `seed`) with wall-clock fields optional.
- Define a separate hand-rolled artifact struct distinct from the in-memory
  report (two shapes to keep in sync).
- Have the loop call the analytics endpoint itself (requires keeping servers
  alive past the run; the artifact stops being a file contract).

## Decision Outcome

Chosen: **serialize `SimulationReport` itself as `pulse.measure-report/v1`,
embedding `BatchAggregation` verbatim**, because one shape that the simulation
already maintains cannot drift from a second copy, and reusing the Signal
zone's aggregation type carries the k-anonymity contract into the file without
reinterpretation.

The shape: a top-level `schema: "pulse.measure-report/v1"` discriminator; a
constant `data_source` honesty label ("simulated respondents — synthetic demo
data, not a real survey"); an optional `seed` echoing deterministic runs; flow
counts (`total_flows`/`successful`/`failed`) plus per-flow `errors`;
`per_tenant` counts; and `batches` — one entry per question batch pairing
`tenant_name` and `question_text` with the `aggregation` fetched over real
HTTP from `/analytics/batch/{id}`. Wall-clock `timing` and `duration` are
`Option`s skipped when absent: present for humans on ad-hoc runs, stripped
from deterministic artifacts where they would break byte-identity. The schema
is documented in the book (`development/dogfood.md`).

### Positive Consequences

- The Assess stage gets a stable, self-describing JSON contract with an
  explicit version to detect drift.
- k-suppression (`suppressed`, `average_score: null`) is preserved end-to-end
  from the Signal zone into the artifact.
- The artifact advertises its own synthetic provenance, blocking
  demo-dishonesty creep.
- The same document serves humans (`--json`, with timings) and the loop
  (`--out`, deterministic).

### Negative Consequences

- `pulse.measure-report/v1` is now a frozen surface; shape changes require a
  version bump and a superseding ADR.
- The harness depends on `pulse-server`'s `BatchAggregation` (now also
  `Deserialize`), coupling the artifact to a server-internal type — accepted
  because the harness already composes the server.
- Conditional fields (`seed`, `timing`, `duration`) mean consumers must treat
  them as optional.

## Implementation

Done in milestone M-p3: `Serialize` derives on the report and flow types,
`Deserialize` on `BatchAggregation`/`SegmentAggregation`, the runner fetches
every provisioned batch's aggregation after the run, and `pulse-simulate`
gains `--json` (pure JSON on stdout, logs on stderr) and `--out <path>`.
Covered by unit tests on the serialized shape and an HTTP integration test
(`measure_report`).
