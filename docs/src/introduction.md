# Pulse

Pulse is a verified-anonymous employee sentiment platform built by Como Technologies. It lets organizations continuously measure workforce sentiment with cryptographic privacy guarantees — responses are provably anonymous, yet provably from authorized employees.

---

## The Problem

Organizations need honest employee feedback to make good decisions — but employees don't trust traditional surveys. They worry responses can be traced back to them, so they self-censor, disengage, or don't respond at all. The result: unreliable data, low participation, and blind spots where leadership needs clarity most.

---

## What Pulse Does

Pulse collects **verified-anonymous** feedback — continuously, automatically, and with cryptographic proof that responses cannot be traced back to individuals.

---

## Why Pulse Is Different

### Anonymity You Can Prove, Not Just Promise

Most platforms say "responses are anonymous." Pulse proves it mathematically. The system uses blind signature cryptography — the same class of technology behind private digital currencies — to decouple *who responded* from *what they said*. There is no admin backdoor, no database join, no scenario where a response can be unmasked. This isn't a policy — it's a guarantee enforced by math.

### Honest Data, Not Noisy Data

Because anonymity is provable, employees trust it. Trust drives candor. Candor drives signal quality. Organizations get responses that reflect what people actually feel — not what feels safe to say.

### Statistical Rigor Without Survey Fatigue

Pulse doesn't blast every employee with a survey every quarter. It uses a managed sampling engine that rotates through the workforce intelligently — ensuring statistically significant results while minimizing the burden on any individual. Employees get polled infrequently, with brief single-gesture interactions.

### Continuous, Not Periodic

Quarterly surveys give you a snapshot. Pulse gives you a trend line. Continuous baseline monitoring detects shifts in sentiment as they happen, not months after the fact. Time-bound campaigns can run alongside the baseline for specific events or initiatives.

### Meets Employees Where They Are

Desktop, mobile, wearables, even a physical button in a breakroom — Pulse supports diverse device classes. The protocol is lightweight enough for low-power and intermittently-connected devices. Every employee can participate, regardless of their role or work environment.

### Enterprise-Grade Isolation

Each customer's data is cryptographically isolated with customer-managed encryption keys. The platform operator has zero access to tenant data — by design, not by policy. Offboarding is instant and irreversible via crypto-shredding.

---

## Key Capabilities

| Capability | What It Means |
|---|---|
| **Verified-anonymous responses** | Cryptographic proof that responses can't be traced — no admin backdoor |
| **Continuous monitoring** | Always-on sentiment baseline with automatic workforce rotation |
| **Targeted campaigns** | Time-bound deep dives on specific topics, compared against the baseline |
| **Statistical sampling engine** | System-managed polling — significance without over-polling |
| **Segmented analytics** | Slice by org level, location, tenure, role — with k-anonymity protection |
| **Trend and anomaly detection** | Surface what matters automatically, not just dashboards |
| **Research-informed question bank** | Validated questions across themes: leadership, culture, workload, belonging |
| **Custom questions** | Add your own, tied to campaigns or the continuous rotation |
| **Multi-platform support** | Desktop, mobile, wearables, IoT — online or offline |
| **SSO integration** | Plugs into existing identity providers |
| **Customer-managed keys** | You control encryption; we can't see your data even if we wanted to |

---

Better data. Better decisions. Because people told you the truth.

---

## Learn More

- **[Vision & Principles](vision.md)** — design philosophy, core capabilities in detail, and open design areas
- **[System Architecture](architecture.md)** — how the system is built
- **[Anonymity Protocol](anonymity-protocol.md)** — the cryptographic protocol that makes it work
