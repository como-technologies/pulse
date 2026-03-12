# Pulse — Capabilities and Goals

*Living document. Technology-agnostic. Captures what the system does and why.*

## 1. Vision

Pulse helps organizations continuously take the pulse of their workforce through lightweight, infrequent polling. It is designed to be:

- **Low-touch** — minimal effort for employees and administrators
- **Unobtrusive** — brief, single-gesture interactions; employees are polled infrequently
- **Simple to deploy** — runs anywhere, supports diverse client devices
- **Statistically rigorous** — system-managed sampling ensures significance without over-polling
- **Privacy-first** — verified-anonymous responses with cryptographic guarantees

## 2. Core Capabilities

### 2.1 Verified-Anonymous Response Collection

Responses are fully anonymous in storage — no link between a response and the individual who submitted it. However, the system must verify that each response originates from a valid, authorized employee before accepting it.

**Key constraints:**
- Authentication and response submission are cryptographically decoupled — the system can verify "this came from a valid employee" without recording *which* employee
- Stored responses contain zero personally-identifiable information
- The verification mechanism must prevent replay, forgery, and duplicate submission
- Audit trail proves response legitimacy without revealing identity

### 2.2 Statistical Sampling Engine

The system manages the full sampling strategy. Administrators set policy; the system executes.

**Capabilities:**
- Rotate through the workforce so no individual is over-polled
- Enforce per-employee frequency caps (e.g., max N questions per week)
- Balance samples across organizational segments (teams, locations, roles) for representativeness
- Dynamically calculate and maintain statistical significance thresholds
- Adapt sample sizes based on workforce size and desired confidence levels
- Report confidence intervals and margin of error alongside all results

### 2.3 Question Management

**Curated library:**
- Pulse provides a validated, research-informed question bank
- Questions are categorized by theme (leadership, culture, workload, belonging, etc.)
- Library is versioned and updated over time

**Org-authored questions:**
- Organizations can create custom questions
- Custom questions specify a response type (see 2.4) and optional metadata
- Questions can be tied to campaigns (see 2.6) or added to the continuous rotation

### 2.4 Response Types

At the protocol level, responses are opaque byte streams — the protocol is response-type-agnostic.

**Responsibilities are split:**
- **Client** — knows how to prompt the user and capture input for a given response type
- **Backend/Analyzer** — knows how to interpret the byte stream based on the question's declared response type
- **Protocol** — transports bytes; does not interpret them

The set of supported response types (binary, scale, emoji, free-text, etc.) is an open design area to be refined as client UX and analysis needs become clearer.

### 2.5 Organizational Structure and K-Anonymity

**Flexible hierarchy:**
- Organizations can optionally model their structure (company > division > department > team)
- Neither hierarchy nor tagging is required — the system works with a flat pool if that's all that's provided

**Ad-hoc metadata tagging:**
- Employees can be tagged with arbitrary metadata (location, role level, tenure band, etc.)
- Tags enable slicing and filtering of aggregate results

**K-anonymity protection:**
- The system enforces minimum group size thresholds when displaying segmented results
- If a segment (team, tag combination, etc.) has too few respondents, results are suppressed or rolled up into a larger group
- This prevents responses from small/narrow groups from being reverse-engineered to identify individuals

### 2.6 Campaigns and Continuous Monitoring

**Continuous monitoring:**
- Always-on baseline sentiment tracking
- System rotates through the question library and workforce automatically
- Provides a longitudinal view of organizational health

**Campaigns:**
- Time-bound polling tied to specific events or initiatives (e.g., "post all-hands feedback this week")
- Campaigns have a defined audience, question set, start/end dates
- Campaign results are reported separately and can be compared against the continuous baseline

### 2.7 Insights and Analytics

The system actively surfaces what matters — not just raw data.

**Aggregate dashboards:**
- Response distributions, averages, participation rates
- Viewable at any level of the org hierarchy (where k-anonymity thresholds are met)

**Trend detection:**
- Track sentiment over time across any dimension
- Compare across teams, locations, time periods

**Anomaly detection:**
- Flag statistically significant shifts (positive or negative)
- Alert administrators to emerging issues before they escalate

**Recommendations:**
- System suggests actions or areas of focus based on detected patterns
- Contextualizes shifts against campaigns, org changes, or external events when data is available

### 2.8 Multi-Tenancy with Cryptographic Isolation and Customer-Managed Keys

- Single deployment serves multiple organizations
- Tenant data is cryptographically isolated — not just logically separated
- **Customer-Managed Keys (CMK)** — each tenant holds their own encryption keys
- The platform operator/vendor has **zero access** to tenant data under any circumstance — this is a true zero-knowledge architecture from the operator's perspective
- **Explicit trade-off:** if a tenant loses their keys, their data is irrecoverable. The vendor cannot help. This is by design, not a limitation.
- Compromise of one tenant's data does not expose another tenant's data
- Key management supports tenant offboarding (crypto-shredding — delete the key, the data becomes meaningless)

### 2.9 Multi-Platform Client Support

Clients must be buildable for diverse architectures and form factors:

- **Desktop/laptop** — native or browser-based
- **Mobile** — phones and tablets
- **Wearables** — smartwatches, fitness bands
- **Embedded/IoT** — dedicated physical devices (e.g., a breakroom sentiment button)

**Offline and real-time modes:**
- Always-connected clients submit responses in real-time
- Constrained or intermittently-connected devices store responses locally and sync when connectivity is available (store-and-forward)
- Both modes use the same protocol; delivery adapts to the device's capabilities

### 2.10 Question Delivery

The system must support two delivery models:

- **Server push** — for always-connected clients; server decides when to present a question
- **Client pull** — for constrained or firewalled environments; client checks in periodically for pending questions

*Note: Many corporate network policies make push delivery difficult or impossible. The pull model ensures Pulse works in restrictive environments. Specific delivery strategy per use case is an open design area.*

### 2.11 Access Control (Policy-Based)

- Flexible, policy-based role and permission system
- Ships with sensible defaults but allows organizations to customize
- **Default roles (indicative, not final):**
  - Platform admin — manages tenants, platform-wide configuration
  - Org admin — manages their organization's configuration, campaigns, question library
  - Campaign manager — creates and manages campaigns within policy
  - Viewer — sees insights and dashboards, cannot configure
- Roles and permissions are defined as policy, not hard-coded

### 2.12 Identity Integration

- Integrates with external identity providers (SSO/federation) for authentication
- User directory and org structure are managed internally
- *Note: Broader integrations (HR sync, messaging channels) are out of scope initially but the system should not preclude them*

## 3. Design Principles

1. **Privacy is non-negotiable** — Anonymity guarantees are cryptographic, not procedural. There is no admin backdoor to unmask respondents.
2. **Statistical rigor over volume** — A smaller, well-sampled dataset with known confidence is better than a flood of opt-in responses with unknown bias.
3. **Protocol simplicity** — Lightweight, efficient messaging. The protocol transports opaque payloads; interpretation lives at the edges (client and analyzer).
4. **Device diversity** — The architecture must not assume always-connected, high-powered clients. A button on a wall is a first-class citizen.
5. **Tenant isolation is absolute** — Customer-managed keys, zero-knowledge for the operator. Crypto-shredding on offboarding. Key loss = data loss, by design.
6. **Minimize burden** — On employees (single-gesture responses, infrequent polls), on admins (system-managed sampling, smart defaults), on operators (single deployment, multi-tenant).

## 4. Open Design Areas

These topics need further discussion before the design is complete:

| Area | Status | Notes |
|------|--------|-------|
| Response type catalog | Open | What types to support, encoding format, extensibility model |
| Push vs. pull strategy per device class | Open | Leaning toward both; needs use-case analysis |
| Anonymous credential scheme | Open | Specific cryptographic mechanism for verified-anonymous submission |
| Offline sync conflict resolution | Open | How to handle edge cases in store-and-forward |
| Question scheduling algorithm | Open | How the sampling engine selects questions and recipients |
| Recommendation engine scope | Open | How sophisticated should automated recommendations be |
| Notification/nudge strategy | Open | How/whether to remind employees to respond |

## 5. Out of Scope (For Now)

- Specific technology or language choices
- UI/UX design and wireframes
- Data schema design
- Deployment architecture
- HR platform or messaging app integrations (beyond SSO)
- Pricing or licensing model
