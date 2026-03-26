# Vision and Principles

*What Pulse does, why it exists, and the principles that guide its design.*

---

## Vision

Pulse helps organizations continuously take the pulse of their workforce through lightweight, infrequent polling. It is designed to be:

- **Low-touch** -- minimal effort for employees and administrators
- **Unobtrusive** -- brief, single-gesture interactions; employees are polled infrequently
- **Simple to deploy** -- runs anywhere, supports diverse client devices
- **Statistically rigorous** -- system-managed sampling ensures significance without over-polling
- **Privacy-first** -- verified-anonymous responses with cryptographic guarantees

---

## Core Capabilities

### Verified-Anonymous Response Collection

Responses are fully anonymous in storage -- no link between a response and the individual who submitted it. The system verifies that each response originates from a valid, authorized employee before accepting it. Authentication and response submission are cryptographically decoupled.

See [Verified Anonymity](verified-anonymity.md) for details.

### Statistical Sampling Engine

The system manages the full sampling strategy. Administrators set policy; the system executes -- rotating through the workforce, enforcing frequency caps, balancing across segments, and maintaining statistical significance thresholds.

See [Sampling & Statistics](sampling.md) for details.

### Question Management

Pulse provides a validated, research-informed question bank categorized by theme (leadership, culture, workload, belonging, etc.). Organizations can also create custom questions tied to campaigns or added to the continuous rotation.

### Response Types

At the protocol level, responses are opaque byte streams -- the protocol is response-type-agnostic. The client knows how to capture input, the backend knows how to interpret it, and the protocol just transports bytes.

### Organizational Structure and K-Anonymity

Organizations can optionally model their structure (company > division > department > team) and tag employees with arbitrary metadata (location, role level, tenure band). The system enforces minimum group size thresholds ([k-anonymity](../design/README.md#10-k-anonymity)) when displaying segmented results to prevent responses from small groups from being reverse-engineered to identify individuals.

### Campaigns and Continuous Monitoring

Always-on baseline sentiment tracking rotates through the question library and workforce automatically. Time-bound campaigns can be created for specific events or initiatives, with results reported separately and compared against the continuous baseline.

### Insights and Analytics

The system actively surfaces what matters -- aggregate dashboards, trend detection, anomaly detection, and recommendations. Results are viewable at any level of the org hierarchy where [k-anonymity](../design/README.md#10-k-anonymity) thresholds are met.

### Multi-Tenancy with Cryptographic Isolation

A single deployment serves multiple organizations with cryptographic data isolation and customer-managed keys. The platform operator has zero access to tenant data under any circumstance.

See [Multi-Tenancy](multi-tenancy.md) for details.

### Multi-Platform Client Support

Clients span desktop, mobile, wearables, and embedded/IoT devices (e.g., a breakroom sentiment button). Both always-connected and store-and-forward modes are supported using the same protocol. See [Device Attestation](../design/device-attestation.md) for how different device classes participate.

### Access Control

Flexible, policy-based role and permission system with sensible defaults. Ships with roles like platform admin, org admin, campaign manager, and viewer -- defined as policy, not hard-coded.

### Identity Integration

Integrates with external identity providers (SSO/federation) for authentication. User directory and org structure are managed internally.

---

## Design Principles

1. **Privacy is non-negotiable** -- Anonymity guarantees are [cryptographic](../design/anonymity-protocol.md), not procedural. There is no admin backdoor to unmask respondents.
2. **Statistical rigor over volume** -- A smaller, well-sampled dataset with known confidence is better than a flood of opt-in responses with unknown bias.
3. **Protocol simplicity** -- Lightweight, efficient messaging. The protocol transports opaque payloads; interpretation lives at the edges.
4. **Device diversity** -- The architecture must not assume always-connected, high-powered clients. A [button on a wall](../design/device-attestation.md) is a first-class citizen.
5. **Tenant isolation is absolute** -- [Customer-managed keys](../design/key-management.md), zero-knowledge for the operator. Crypto-shredding on offboarding. Key loss = data loss, by design.
6. **Minimize burden** -- On employees (single-gesture responses, infrequent polls), on admins (system-managed sampling, smart defaults), on operators (single deployment, multi-tenant).

---

## Open Design Areas

| Area | Status | Notes |
|------|--------|-------|
| Response type catalog | Partially resolved | Protocol transports opaque bytes via postcard. `ResponseType` enum exists (`Scale5`, `Binary`, `Emoji`, `FreeText`). Full catalog of validated, research-informed types TBD. |
| Push vs. pull strategy per device class | Open | Leaning toward both; will be informed by client SDK development. |
| Offline sync conflict resolution | Open | How to handle edge cases in store-and-forward. |
| Question scheduling algorithm | Open | How the sampling engine selects questions and recipients. |
| Recommendation engine scope | Open | How sophisticated should automated recommendations be. |
| Notification/nudge strategy | Open | How/whether to remind employees to respond (system cannot track individual response status — only broadcast reminders). |
