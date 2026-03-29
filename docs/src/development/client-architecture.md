# Client Architecture

_How client applications are structured across deployment targets._

---

## Core + Shells

All clients share a single Rust core library (`pulse-client`) that implements the complete client-side protocol. Platform-specific applications are thin shells that provide UI and platform integration on top of this core.

| Shell          | Wrapper               | Distribution                                       | Status      |
| -------------- | --------------------- | -------------------------------------------------- | ----------- |
| Desktop        | Slint (native Rust)   | Enterprise UEM (Intune, SCCM, Jamf) or self-update | Planned     |
| Mobile         | Slint (native Rust)   | App stores                                         | Planned     |
| Embedded / IoT | Slint MCU / `no_std`  | OTA firmware (embassy-boot)                        | Planned     |

All shells use [Slint](https://slint.dev/) — a pure Rust, declarative UI toolkit that targets desktop, mobile, and embedded from a single codebase. The core library is the bulk of the client investment. Shell priority can shift based on market signals without rearchitecting.

---

## pulse-client Crate

The `pulse-client` crate owns the client-side protocol state machine. It is platform-agnostic — no I/O, no UI, no platform-specific code.

**Responsibilities:**

- Authenticate with the Identity Gateway (Phase 1)
- Fetch assigned questions
- Blind a token nonce, request signing, unblind the signature
- Derive the epoch pseudonym (HMAC-SHA256)
- Encrypt the response payload (AES-256-GCM)
- Submit the response via the anonymizing relay (Phase 2)
- Token persistence between blinding and submission
- Random timing delay before submission

**Dependencies:**

```
pulse-client
  -> pulse-protocol   (wire types, message definitions)
  -> pulse-crypto     (blind signatures, AEAD, pseudonym derivation)
```

`pulse-client` must **never** depend on `pulse-identity` or `pulse-signal`. Those are server-side zone implementations. The client bridges both zones through the protocol, not through code sharing.

**Transport abstraction:** The crate defines an `HttpTransport` trait for HTTP operations so that shells can provide platform-appropriate implementations — `reqwest` on desktop/mobile (shipped as `ReqwestTransport`, feature-gated behind `reqwest-transport`), and custom transports on embedded.

**Sync core:** The `ProtocolEngine` handles all message construction, response parsing, and cryptographic operations synchronously — no async runtime required. This makes the core testable without tokio and portable to `no_std` environments.

**Typestate flow:** Protocol progression is enforced at compile time at three levels:

1. **Connection state:** `PulseClient<T>` (disconnected) transitions to `ConnectedClient<T>` via `connect()`. Crypto operations like `blind_token()` only exist on `ConnectedClient` — calling them before connecting is a compile error.
2. **Data-flow ordering:** Each method returns the type required by the next step. `authenticate()` → `SessionContext`, `blind_token()` → `BlindedTokenState`, etc. You cannot skip steps.
3. **Token lifecycle:** `BlindedTokenState` → `SignedTokenState` → `ReadyToken`. Each transition consumes the previous state.

**Orchestrator:** `ConnectedClient<T: HttpTransport>` is the high-level entry point. Each async method delegates to `ProtocolEngine` for sync work and uses the transport only for I/O: `authenticate` → `fetch_questions` → `blind_token` → `request_signature` → `finalize_token` → `submit_response`.

---

## Trust Zone Bridging

The client is the only component that interacts with both trust zones:

```
Phase 1 (Identity zone)        Phase 2 (Signal zone)
  Authenticated                   Anonymous
  ┌──────────────┐               ┌──────────────┐
  │ SSO login    │               │ Submit via   │
  │ Fetch Qs     │               │ relay        │
  │ Get token    │               │ No auth      │
  │ signed       │               │ No cookies   │
  └──────┬───────┘               └──────▲───────┘
         │                              │
         │      ┌──────────────┐        │
         └─────>│ pulse-client │────────┘
                │ (unblinds,   │
                │  encrypts,   │
                │  delays)     │
                └──────────────┘
```

The two phases use separate connections, separate network paths, and carry no shared session state. The client deliberately does not persist the correlation between identity and response.

---

## Shell Responsibilities

Shells are intentionally thin. A shell provides:

1. **Platform UI** — system tray icon, mobile app chrome, browser page, or physical button handler
2. **HTTP transport** — platform-appropriate implementation of the client transport trait
3. **Secure storage** — keychain/keystore for token material and client secrets
4. **Lifecycle integration** — app launch, background scheduling, push notifications, update mechanisms

All protocol logic, cryptographic operations, and wire format handling stay in the core.

---

## Why This Architecture

The core + shells architecture lets the team build the protocol client once and target any platform Slint supports. Slint's pure-Rust rendering pipeline keeps the dependency tree minimal and the attack surface small — no web engine, no JavaScript runtime, no platform-specific UI frameworks. The postcard wire format is `no_std`-compatible, so even the embedded path shares serialization code with the server and desktop clients.
