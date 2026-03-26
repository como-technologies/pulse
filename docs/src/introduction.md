# Pulse

Pulse gives organizations a continuous read on how their workforce actually feels -- through brief, infrequent interactions that employees trust enough to answer honestly.

---

## The Problem

Traditional employee surveys don't work. Once a year, a lengthy questionnaire lands and employees rush through it just to get it done -- clicking through answers rather than giving thoughtful responses. Participation dips with every cycle, and by the time results are analyzed the moment has passed. Organizations get stale snapshots filled with checkbox fatigue -- not actionable insight.

And even when employees do respond, they self-censor. "Your responses are anonymous" is a promise, not a proof. Most platforms can't actually guarantee it -- an admin query, a database join, a small-team filter could unmask anyone. Employees know this, so they say what feels safe, not what's true. The result: data that is both late and dishonest.

---

## What Pulse Does

Pulse replaces heavyweight surveys with brief, single-gesture interactions delivered continuously across the workforce. A managed sampling engine handles who gets asked, when, and what -- ensuring statistical significance without over-polling anyone.

Responses are verified-anonymous: cryptographically proven untraceable, not just promised. Employees trust the system, so they tell the truth.

---

## Why Pulse Is Different

### Effortless for Everyone

Employees see a brief interaction, not a questionnaire. One gesture, done. The system manages all the complexity -- sampling, rotation, frequency caps -- so no individual is over-polled. Desktop, mobile, wearables, even a physical button in a breakroom. Every employee can participate regardless of their role or work environment.

### Continuous, Not Periodic

Annual surveys give you a snapshot. Pulse gives you a trend line. Continuous baseline monitoring detects shifts in sentiment as they happen, not months after the fact. Time-bound campaigns can run alongside the baseline for specific events or initiatives.

### Anonymity You Can Prove, Not Just Promise

Pulse uses [blind signature cryptography](design/anonymity-protocol.md) to decouple *who responded* from *what they said*. There is no admin backdoor, no database join, no scenario where a response can be unmasked. This isn't a policy -- it's a guarantee enforced by math.

### Honest Data, Not Noisy Data

Because anonymity is provable, employees trust it. Trust drives candor. Candor drives signal quality. Organizations get responses that reflect what people actually feel -- not what feels safe to say.

### Enterprise-Grade Isolation

Each customer's data is cryptographically isolated with customer-managed encryption keys. The platform operator has zero access to tenant data -- by design, not by policy. Offboarding is instant and irreversible via crypto-shredding.

---

Better data. Better decisions. Because people told you the truth.

---

## Learn More

- **[Vision & Capabilities](concepts/README.md)** -- what Pulse does in detail, design principles, and open design areas
- **[System Architecture](design/README.md)** -- how the system is built
- **[Roadmap](roadmap.md)** -- where Pulse is headed
