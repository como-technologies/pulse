# Dogfood: The Measure Report

Pulse's role in the portfolio dogfood loop is the **Measure stage**: it emits a
machine-readable, k-anonymous report that the next Assess pass consumes. The
report is a **file contract, not a live service** — `pulse-simulate` writes a
JSON document and exits.

This page describes pulse's **suite-done bar**. ADR-0010
(`adr/accepted/0010-accept-dogfooding-parked-at-m0-as-the-suite-done-state.md`)
accepts dogfooding (parked at M0) as pulse's suite-done state: each portfolio
iteration, `just gate` exits 0 and `just dogfood` re-proves the deterministic
artifact below — that, not a rung climb, is what done means for pulse.

The respondents are **simulated**. There are no employees in the dogfood loop,
so respondent answers come from a deterministic, seeded distribution defined in
data — never from an AI model. The report labels itself accordingly in its
`data_source` field; do not present it as real survey data.

## The contract: `just dogfood`

```sh
just dogfood
```

runs the iteration-retro pulse — the full blind-signature protocol over real
HTTP against an in-process multi-zone cluster — and writes
`out/pulse-report.json`. It is exactly:

```sh
cargo run -p pulse-test-harness --features reqwest-transport --bin pulse-simulate -- \
    --batch-file dogfood/iteration-retro.toml --seed 42 --employees 10 --k-threshold 5 \
    --out out/pulse-report.json
```

Proof of a working run: exit code `0`, the report shows `"failed": 0`, and at
least one segment is unsuppressed with a numeric `average_score`. That JSON
file is the Measure artifact the next Assess iteration reads.

### Determinism

The run is seeded, so **the same seed produces a byte-identical report**:
tenant and batch IDs come from a pinned ChaCha12 stream, respondent answers
are sampled in deterministic order before any concurrent task spawns, and
wall-clock fields are stripped from seeded artifacts (see ADR-0009). Verify:

```sh
just dogfood && cp out/pulse-report.json /tmp/first.json
just dogfood && diff /tmp/first.json out/pulse-report.json && echo identical
```

This turns the demo into a regression test: any unexplained diff means the
protocol stack or the survey definition drifted.

### The survey is data

Questions, segment labels, and per-question Scale5 weight distributions live
in `dogfood/iteration-retro.toml`, checked in at the repo root. Each
portfolio iteration edits that file — for
steady-state park mode, fold in one retro question about the current
iteration — without recompiling anything. Editing the survey (or the seed)
intentionally changes the artifact; the (seed, survey) pair is part of the
contract.

## Emitting reports ad hoc

```sh
# Print the report as JSON to stdout (logs and progress go to stderr)
cargo run -p pulse-test-harness --features reqwest-transport --bin pulse-simulate -- --json

# Write the report to a file (parent directories are created)
cargo run -p pulse-test-harness --features reqwest-transport --bin pulse-simulate -- \
    --out out/pulse-report.json
```

Exit code is `0` when every protocol flow succeeded, `1` otherwise. Unseeded
runs include wall-clock timing and are not expected to be reproducible.

## Report schema: `pulse.measure-report/v1`

The report is a single JSON object:

| Field | Type | Notes |
|---|---|---|
| `schema` | string | Always `"pulse.measure-report/v1"`. |
| `data_source` | string | Honesty label: simulated respondents, synthetic demo data. |
| `seed` | u64 | Present only on seeded (deterministic) runs. |
| `total_flows` | number | Protocol flows attempted. |
| `successful` | number | Flows that completed every step. |
| `failed` | number | Flows that failed at any step. |
| `errors` | array | One entry per failed flow (employee id, tenant, failing step, error). |
| `timing` | object? | Wall-clock percentiles per protocol step. **Omitted in deterministic artifacts.** |
| `per_tenant` | array | Per-tenant flow counts (plus `timing` unless deterministic). |
| `batches` | array | One entry per question batch — the Measure payload. |
| `duration` | object? | Wall-clock run duration. **Omitted in deterministic artifacts.** |

Each entry in `batches` pairs the question with the k-anonymous aggregate the
Signal zone returned from `GET /analytics/batch/{id}`:

```json
{
  "tenant_name": "dogfood",
  "question_text": "How are you feeling about work today?",
  "aggregation": {
    "question_batch_id": "5d3f…",
    "tenant_id": "9a41…",
    "total_responses": 10,
    "total_decrypted": 10,
    "total_failed": 0,
    "segments": [
      {
        "segment_label": "company",
        "response_count": 10,
        "unique_pseudonyms": 10,
        "average_score": 3.8,
        "suppressed": false
      }
    ]
  }
}
```

`aggregation` is the server's `BatchAggregation` type embedded verbatim — the
same shape the analytics endpoint serves. The k-anonymity contract carries
through to the artifact: a segment with fewer than `k` unique pseudonyms has
`suppressed: true` and `average_score: null`.

Timing percentiles (`timing.authenticate`, `timing.fetch_questions`,
`timing.blind_and_sign`, `timing.encrypt_and_submit`, `timing.total_flow`) each
carry `p50`/`p90`/`p99`/`max` as `{ "secs": n, "nanos": n }` pairs. They exist
for humans inspecting performance, not for the Measure contract, which is why
deterministic artifacts omit them: the same seed must produce a byte-identical
report, and wall-clock time is the one thing a seed cannot pin down.
