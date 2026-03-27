# pulse-tui

Interactive terminal client for Pulse anonymous polling.

A fully interactive TUI built with [ratatui](https://ratatui.rs/) that exercises the complete Pulse protocol flow end-to-end. Useful for development, demos, and protocol verification.

## Quick Start

Start the dev server in one terminal, then the TUI in another:

```sh
# Terminal 1 — start the server
cargo run -p pulse-server

# Terminal 2 — start the TUI
cargo run -p pulse-tui
```

## Walkthrough

### 1. Connect

The first screen shows the server URLs pre-filled with dev defaults (`127.0.0.1:8001` / `8002`). Press **Enter** to continue.

### 2. Login

Type any non-empty string as the API key — the dev server accepts anything. This string becomes your employee ID (e.g. `alice`, `bob`, `Mike`). Press **Enter**.

The client will automatically:
- Fetch server config (public key, tenant ID) via `GET /config`
- Authenticate via `POST /auth`
- Fetch assigned questions via `GET /question`

Watch the log panel at the bottom — it shows each step as it happens.

### 3. Questions

You'll see the dev question: _"How are you feeling about work today?"_ (Scale 1-5). Press **Enter** to select it.

### 4. Token Acquisition

The client performs the blind signature flow automatically:
1. Constructs a `TokenPayload` with a random nonce
2. Blinds it (hiding contents from the server)
3. Sends the blinded token to the Identity Zone for signing
4. Unblinds the signature locally

This happens in under a second. You'll advance to the response screen automatically.

### 5. Respond

Use **Up/Down** or **Left/Right** to pick a value (1-5). Press **Enter** to submit.

### 6. Submit

The client:
1. Derives an anonymous pseudonym (HMAC-SHA256)
2. Encrypts the response payload (AES-256-GCM)
3. Submits to the Signal Zone with **no authentication** — the server cannot tell who you are

If you see _"Response submitted successfully!"_ the full protocol flow is complete.

### Going Again

Press **Esc** to return to the Questions screen. You'll see an error if you try to submit again with the same identity — the frequency cap is 1 token per employee per batch. Use a different name on the Login screen to go through the flow again.

## Navigation

| Key        | Action                                   |
| ---------- | ---------------------------------------- |
| Enter      | Advance / submit                         |
| Esc        | Go back                                  |
| Tab        | Switch fields (Connect screen)           |
| Up/Down    | Select question or adjust scale value    |
| Left/Right | Adjust scale value                       |
| Ctrl+C     | Quit                                     |

## Screens

| Screen      | Purpose                                                         |
| ----------- | --------------------------------------------------------------- |
| Connect     | Configure identity and signal zone URLs                         |
| Login       | Authenticate with API key / employee ID                         |
| Questions   | Browse assigned questions, select one                           |
| Token       | Watch blind signature acquisition (blind, sign, unblind)        |
| Respond     | Enter response (scale selector, text input)                     |
| Submit      | Encrypt and submit anonymously, see result                      |
| Log (panel) | Color-coded protocol events showing what each trust zone sees   |

## Configuration

Override default URLs via environment variables:

```sh
PULSE_IDENTITY_URL=http://localhost:8001 \
PULSE_SIGNAL_URL=http://localhost:8002 \
cargo run -p pulse-tui
```

## Architecture

Elm architecture (TEA) with async protocol operations:

- **Model** (`App`) — all application state
- **Action** enum — user events + async protocol results
- **Update** (`App::update`) — pure state transitions
- **View** (`ui::render`) — renders from state

HTTP calls run in tokio tasks and send results back through an `mpsc` channel to the main event loop.

## Dependencies

Uses `pulse-client` for all protocol operations. No server-side crate dependencies.

```
pulse-tui -> pulse-client -> pulse-protocol + pulse-crypto
```
