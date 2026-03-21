# Verified Anonymity

*How Pulse guarantees that responses are both verified (from a real employee) and anonymous (unlinkable to that employee).*

---

## The Problem

Employee sentiment platforms face a fundamental tension: you need to **verify** that each response comes from a legitimate employee, but you also need to guarantee that **no one** -- not even the platform operator -- can link a response back to the person who submitted it.

Most platforms resolve this with policy ("we promise not to look"). Pulse resolves it with cryptography.

---

## How It Works

Pulse uses **blind signatures** -- a cryptographic technique where a signer can produce a valid signature on a message without ever seeing the message content.

The system is split into two trust zones that never communicate directly:

- **Identity zone** -- knows WHO people are. Handles authentication, sampling, and token issuance. Never sees responses.
- **Signal zone** -- knows WHAT was answered. Collects and stores responses. Never knows who answered.

### The Flow

1. An employee authenticates normally (SSO) with the Identity zone
2. The client generates a random token and **blinds** it (a cryptographic operation that hides the token's value)
3. The Identity zone signs the blinded token -- proving "a valid employee is authorized to answer" -- without seeing the actual token value
4. The client **unblinds** the signed token locally
5. After a random delay, the client submits the response with the unblinded token through an **anonymizing relay** to the Signal zone -- with no authentication, no cookies, no identity
6. The Signal zone verifies the signature (valid employee) and checks for duplicates, then stores the response

**The key property:** Even if both zones are compromised and collude, they cannot correlate tokens to identities. This is a mathematical guarantee, not a policy promise.

---

## Key Constraints

| Constraint | How It's Enforced |
|-----------|-------------------|
| No link between response and individual | Blind signature scheme (information-theoretic security) |
| No PII in stored responses | Protocol design -- responses contain only opaque data + verified token |
| No replay or duplication | Spent-token ledger -- each token can only be used once |
| No forgery | Tokens require a valid signature from the Token Issuer's private key |
| Audit trail without identity | Aggregate reconciliation: tokens issued vs. responses received |

---

## Architectural Enforcement

Anonymity in Pulse is not a feature layered on top -- it is an architectural invariant:

- The Identity zone and Signal zone are **separate services with no shared state** except the Token Issuer's public verification key
- All anonymous submissions pass through a **mandatory anonymizing relay** that strips IP addresses, timing metadata, and client fingerprints
- K-anonymity thresholds are enforced **at the data level** (issuance-time segment coarsening), not at the UI level
- Pseudonyms for longitudinal tracking are derived **client-side** and included inside encrypted response blobs -- invisible to both zones

For the full cryptographic protocol specification, see [Anonymity Protocol](anonymity-protocol.md).
For the threat analysis, see [Threat Model](threat-model.md).
