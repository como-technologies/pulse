# Sampling and Statistics

*How Pulse manages statistical sampling to produce rigorous, representative results without over-polling.*

---

## Philosophy

Pulse favors **statistical rigor over volume**. A smaller, well-sampled dataset with known confidence is better than a flood of opt-in responses with unknown bias. The system manages the full sampling strategy -- administrators set policy; the system executes.

---

## Capabilities

The Sampling Engine handles:

- **Workforce rotation** -- rotate through employees so no individual is over-polled
- **Frequency caps** -- enforce per-employee limits (e.g., max N questions per week)
- **Segment balancing** -- balance samples across organizational segments (teams, locations, roles) for representativeness
- **Significance tracking** -- dynamically calculate and maintain statistical significance thresholds
- **Adaptive sizing** -- adjust sample sizes based on workforce size and desired confidence levels
- **Confidence reporting** -- report confidence intervals and margin of error alongside all results

---

## The Anonymity Constraint

The Sampling Engine (Identity zone) knows **who** is assigned to each question. The Response Collector (Signal zone) knows **what** was answered. Neither knows both.

This means the system **cannot track per-individual response status.** It cannot send "you haven't answered yet" reminders -- only broadcast reminders to all assigned employees. This is an intentional privacy trade-off.

### Compensating Strategies

- **Over-sampling** -- issue more tokens than needed, anticipating non-response
- **Adaptive top-up** -- if aggregate response rates are low, issue additional tokens to new employees in subsequent waves
- **Confidence reporting** -- analytics prominently display confidence intervals and margins of error so stakeholders understand the data quality

---

## Sampling Engine Inputs

| Input | Source |
|-------|--------|
| Workforce roster | Identity Gateway |
| Org structure and metadata tags | Org Structure Service |
| Active questions and campaigns | Question Registry / Campaign Manager |
| Historical issuance records | Token Issuer logs ("Employee X was last issued a token on date D") |
| Aggregate response counts per batch | Analytics Engine (counts only, no identity linkage) |
