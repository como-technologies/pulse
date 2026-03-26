# Pulse — Device Attestation Model

*Describes how devices of varying capability and identity confidence participate in the Pulse system.*

*Parent document: [Architecture](architecture.md)*

---

## 1. Overview

Pulse supports clients ranging from full-featured phones/laptops to single-button IoT devices. These devices differ not just in capability, but in what their signals **mean** — a response from a personal phone tied to an authenticated employee carries different weight than a button press in a cafeteria.

The device attestation model captures this nuance, ensuring the system interprets every signal honestly.

---

## 2. Device Classes

### 2.1 Personal, Authenticated (High Confidence)

**Examples:** Employee's phone, laptop, desktop browser.

| Property | Value |
|----------|-------|
| Identity confidence | High — tied to a specific, authenticated employee |
| Attestation model | Full blind signature flow: SSO authentication → token request → blind signing → anonymous submission |
| Pseudonym support | Yes — client derives stable pseudonym for longitudinal tracking |
| Statistical weight | Full — counts as a verified individual response for significance calculations |

The standard flow described in the [Anonymity Protocol](anonymity-protocol.md). This is the baseline and highest-fidelity signal.

### 2.2 Shared, Group-Scoped (Medium Confidence)

**Examples:** Tablet mounted in a team project room. Shared terminal at a department station.

| Property | Value |
|----------|-------|
| Identity confidence | Medium — tied to a known organizational group, not an individual |
| Attestation model | Device registered to a group (team, project, department). Token issued to the group identity. No individual SSO. |
| Pseudonym support | No — responses are attributed to the group, not a pseudonymous individual |
| Statistical weight | Partial — contributes to group-level sentiment but not counted as individual responses for significance |

**How it works:**
- During device provisioning, the device is associated with an org group (e.g., "Backend Team", "Project X").
- The device authenticates using a device credential (not employee SSO).
- Tokens are issued scoped to the group's segment.
- Responses represent "someone in this group felt X" — the system doesn't know who, and doesn't try to.

**Practical scenario:** A tablet in Team Alpha's project room displays the current question. Any team member can tap a response. The signal means "someone on Team Alpha responded" — valuable for team-level pulse, but not individually tracked.

### 2.3 Shared, Location-Scoped (Low Confidence)

**Examples:** Breakroom sentiment button. Cafeteria kiosk. Lobby feedback terminal.

| Property | Value |
|----------|-------|
| Identity confidence | Low — tied to a physical location, not a group or individual |
| Attestation model | Device registered to a location node in the org hierarchy. Token issued to the location identity. |
| Pseudonym support | No |
| Statistical weight | Contextual — provides location-level sentiment signal. Not counted in individual or group significance calculations. |

**How it works:**
- During provisioning, the device is mapped to a location in the org hierarchy (Campus > Building > Floor > Area).
- The device authenticates using a device credential.
- Tokens are scoped to the location segment.
- Responses represent "someone at this location felt X."

**Location hierarchy example for a large organization:**

```
Acme Corp
  |-- San Francisco Campus
  |     |-- Building A
  |     |     |-- Floor 3 Cafeteria
  |     |     |-- Floor 5 Breakroom
  |     |-- Building B
  |           |-- Lobby
  |-- London Campus
  |     |-- Main Office
  |           |-- Canteen
  |           |-- Reception
  |-- Singapore Campus
        |-- Cafeteria
```

Each location node can have devices. The Analytics Engine aggregates location signals up the hierarchy: Building → Campus → Company.

**Important limitations:**
- No frequency cap per individual (the device doesn't know who pressed the button)
- Potential for one person to submit multiple responses on the same device for the same question batch
- Mitigated by: device-level rate limiting (e.g., one response per button per 30 seconds), and by treating location signals as low-confidence context rather than statistically rigorous data

### 2.4 Hybrid — Device + Phone Handoff (High Confidence)

**Examples:** Wall-mounted question display with a QR code. Digital signage with NFC tap.

| Property | Value |
|----------|-------|
| Identity confidence | High — employee authenticates via their personal device |
| Attestation model | Shared device presents a pairing mechanism (QR code, NFC, short code). Employee's phone handles SSO auth + full blind signature token flow. |
| Pseudonym support | Yes — the phone is the client, so pseudonym derivation works normally |
| Statistical weight | Full — equivalent to a personal device response |

**How it works:**
1. The shared device displays a question and a pairing mechanism (e.g., QR code containing a session-specific question reference).
2. The employee scans the QR code with their phone.
3. The phone handles the full protocol: SSO auth → token request → blind signing → anonymous submission via relay.
4. The shared device is just a trigger/display — it never handles tokens or responses.

**Advantage:** Brings high-confidence individual responses to physical locations where carrying a laptop would be impractical.

---

## 3. Attestation Profile

Every device in the system has an attestation profile, established during provisioning. The `AttestationClass` enum is the only part of the profile currently implemented — it is embedded in `TokenPayload` at issuance time. The full profile struct (device registration, capabilities, credential types, confidence-weighted analytics) is tracked in [#16](https://github.com/como-technologies/pulse/issues/16), which depends on the control plane architecture ([#11](https://github.com/como-technologies/pulse/issues/11)).

```rust
{{#include ../../crates/pulse-protocol/src/token.rs:attestation_class}}
```

The remaining fields below are the intended shape of the full attestation profile:

| Field | Description |
|-------|-------------|
| `device_id` | Unique identifier for the device |
| `device_class` | `personal` \| `group` \| `location` \| `hybrid` |
| `confidence_level` | `high` \| `medium` \| `low` |
| `segment_binding` | What org segment this device is bound to (employee ID, group ID, or location node ID) |
| `capabilities` | Supported response types, push/pull, max payload size, store-and-forward, etc. |
| `credential_type` | How the device authenticates (`employee_sso`, `device_certificate`, `pre_shared_key`) |
| `rate_limit_policy` | Per-device submission rate limits (especially for group/location devices) |

### 3.1 Provisioning

- **Personal devices:** Self-provisioned by the employee during onboarding. The attestation profile is generated automatically from the SSO authentication context.
- **Group devices:** Provisioned by a team lead or org admin. Bound to a specific group in the Org Structure Service.
- **Location devices:** Provisioned by an org admin or facilities team. Bound to a specific location node.
- **Hybrid displays:** Provisioned by an admin. The display itself gets a device profile (`hybrid_display` class), but responses flow through the employee's personal device.

---

## 4. Signal Confidence and Analytics

### 4.1 Confidence-Aware Aggregation

The Analytics Engine tags every response with its attestation confidence level and treats them accordingly:

| Confidence | Treatment in Analytics |
|------------|----------------------|
| High | Full statistical weight. Included in significance calculations, trend analysis, anomaly detection. Pseudonym enables longitudinal tracking. |
| Medium | Group-level weight. Contributes to group sentiment metrics. Excluded from individual-level analysis. Cannot produce longitudinal individual trajectories. |
| Low | Contextual signal. Displayed as location-level sentiment ("mood at this location"). Excluded from significance calculations. Clearly labeled as low-confidence. |

### 4.2 Dashboard Presentation

Dashboards should clearly communicate signal confidence:

- High-confidence data: presented with confidence intervals and statistical rigor
- Medium-confidence data: labeled as "group-level signal" with appropriate caveats
- Low-confidence data: labeled as "location sentiment indicator" — directional, not statistically rigorous
- Users can filter by confidence level: "show me only high-confidence data" or "include all signals"

### 4.3 The Non-Inflation Principle

The system **never inflates** confidence:

- A location signal is never promoted to group-level or individual-level confidence, regardless of how many responses are collected
- Aggregate counts from low-confidence devices do not contribute to statistical significance thresholds
- This is enforced in the Analytics Engine, not just in the UI

---

## 5. Token Issuance by Device Class

| Device Class | Who Requests Token? | Token Scoped To | Frequency Cap Basis |
|---|---|---|---|
| Personal | Employee (via SSO) | Employee's assignment (question_batch_id + employee-specific nonce) | Per employee |
| Group | Device (via device credential) | Group's segment + question_batch_id | Per device (configurable rate limit) |
| Location | Device (via device credential) | Location's segment + question_batch_id | Per device (configurable rate limit) |
| Hybrid display | Employee's phone (via SSO, triggered by display) | Employee's assignment (same as personal) | Per employee |

### 5.1 Token Pre-Issuance for Constrained Devices

Group and location devices that are intermittently connected can pre-fetch token batches:

- During a sync window, the device requests tokens for upcoming question batches
- Tokens are stored locally in the device's secure storage
- Each token is scoped and has an expiry — unused tokens expire naturally
- Batch size is configurable per device (balance between availability and stale-token risk)

**Revocation concern:** If an employee leaves the org, pre-issued tokens to personal devices should ideally be invalidated. Options:
1. Keep token expiry windows short (hours/days, not weeks) to minimize the window
2. Accept the risk — a departed employee with unexpired tokens could submit a small number of responses. The impact is bounded by the token batch size and expiry.
3. Maintain a revocation list in the Response Collector (adds complexity, creates a potential correlation vector if not carefully designed)

For group/location devices, employee departure is not a concern — the device token is not tied to an individual.

---

## 6. Capability Negotiation

When a device connects, it declares its capabilities:

```
CLIENT_HELLO:
    protocol_version: 1
    device_class: location
    confidence_level: low
    capabilities:
        delivery_mode: pull_only
        supported_response_types: [scale_5]
        max_payload_size: 256 bytes
        store_and_forward: true
        batch_token_request: true
    rate_limit: 1 response per 30 seconds
```

The server uses this to:
- Deliver only questions compatible with the device's supported response types
- Respect the device's payload size constraints
- Choose push or pull delivery
- Pre-issue token batches if requested
- Apply the declared rate limit as a server-side enforcement (the device declares it, the server enforces it)

---

## 7. Physical Security Considerations

For shared physical devices (group, location):

| Concern | Mitigation |
|---------|-----------|
| Device theft | Device credentials can be revoked. Pre-issued tokens have expiry windows. Stolen device produces at most a bounded number of low-confidence signals. |
| Tampering | Device should use secure boot / attestation where possible. For simple IoT (buttons), accept that physical access = device compromise and bound the damage via rate limits and low confidence weighting. |
| Vandalism (button-mashing) | Device-level rate limiting. Server-side rate limiting per device. Low-confidence classification means the damage to data quality is bounded. |
| Eavesdropping on responses | Responses are encrypted in transit and at rest. Even intercepting the wireless/wired traffic yields only encrypted blobs. |
