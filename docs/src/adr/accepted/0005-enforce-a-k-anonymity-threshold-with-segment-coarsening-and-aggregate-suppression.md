# ADR-0005: Enforce a k-anonymity threshold with segment coarsening and aggregate suppression

> State: Accepted

## Status

Accepted

## Stakeholders

Pulse maintainers, tenant administrators configuring `PULSE_K_THRESHOLD`,
anyone consuming analytics aggregates.

## Context and Problem Statement

Blind signatures stop the system linking a response to a person, but small
segments re-identify people statistically: a result sliced to a three-person
team is barely anonymous even when the cryptography is perfect. Segment labels
travel inside the token's segment vector and reappear in analytics aggregates,
so de-anonymization by narrow slicing has to be prevented at both ends of the
pipeline, not just one.

## Decision Drivers

- No segment slice should ever describe fewer than k people, at issuance or in
  results.
- Protection must not silently discard responses — small-segment respondents
  still count, just at a coarser granularity.
- The threshold must be tenant-configurable (`PULSE_K_THRESHOLD`, dev default
  5) rather than hard-coded.
- Both enforcement points must be independently testable.

## Considered Options

- Enforce k at both ends: coarsen sub-k segments up the org hierarchy at token
  issuance (Identity zone), and suppress sub-k aggregates at analytics time
  (Signal-side engine).
- Suppress only at read time, leaving fine-grained labels in stored tokens.
- Coarsen only at issuance and trust that aggregates can never go sub-k.

## Decision Outcome

Chosen: **enforce at both ends**, because each end fails differently. The
sampling engine in `pulse-identity` walks a small segment up the org hierarchy
to the nearest ancestor with at least k members before the label ever enters a
token, so fine-grained labels for small populations never exist on the wire.
Independently, the analytics engine marks any segment aggregate with fewer
than k unique pseudonyms as `suppressed` and withholds its average score, so
even drift, churn, or partial response never exposes a sub-k slice in results.

### Positive Consequences

- Defense in depth: a bug or population drift at one layer is caught by the
  other.
- Small-segment respondents stay in the data at coarser granularity instead of
  being dropped.
- The `suppressed` flag makes the protection visible and machine-checkable in
  every aggregate — consumers can distinguish "no data" from "withheld".

### Negative Consequences

- Coarsening loses granularity: small teams are only visible at parent-level
  labels.
- A misconfigured k cuts both ways — too high silently suppresses most
  segments in small populations; k=1 disables the protection entirely. Demo
  and test configurations must exercise both sides of the threshold.
- Two enforcement points mean the invariant lives in two crates and must be
  kept consistent.

## Implementation

In force: hierarchy coarsening lives in the `pulse-identity` sampling engine
(`coarsen_segments`, threshold on the engine); aggregate suppression lives in
the analytics engine (`SegmentAggregation.suppressed`, score withheld when
unique pseudonyms < k). Both are covered by unit and integration tests; the
threshold is configured per deployment via `PULSE_K_THRESHOLD`.
