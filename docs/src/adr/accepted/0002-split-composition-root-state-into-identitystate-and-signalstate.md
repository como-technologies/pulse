# ADR-0002: Split composition-root state into IdentityState and SignalState

> State: Accepted

## Status

Accepted

## Stakeholders

Pulse maintainers, anyone adding route handlers or state to `pulse-server`.

## Context and Problem Statement

`pulse-server` is the composition root: the one crate that intentionally sees
both trust zones (ADR-0001). Inside it, a single shared application state would
quietly re-merge what the Cargo graph keeps apart — an auth component reachable
from a signal-zone handler is exactly the leak the architecture exists to
prevent. The crate boundary cannot help here, so the composition root needs its
own enforcement layer.

## Decision Drivers

- Zone isolation must hold even inside the one crate that composes both zones.
- Misuse should be a compile error, not a code-review catch.
- Axum's extractor model should keep working idiomatically per zone.

## Considered Options

- Two separate state types: `IdentityState` (TokenIssuer, Authenticator,
  SessionStore) and `SignalState` (ResponseCollector, ResponseStore), each used
  only by its zone's routers.
- One shared `AppState` holding everything, relying on handler discipline.
- Runtime guards (e.g. panics or middleware checks) on cross-zone access.

## Decision Outcome

Chosen: **two separate state types**, because it extends compile-time
enforcement into the composition root. Identity-zone route handlers extract
from `IdentityState`; signal-zone handlers from `SignalState`. The
`AuthenticatedEmployee` extractor compiles only against `IdentityState`, so
using it in a signal-zone handler is a compile error. The two types must never
be merged back into a single shared state.

### Positive Consequences

- Auth components cannot leak into signal-zone handlers, even by accident.
- The second enforcement layer (after the Cargo graph) covers the one place the
  first layer cannot.
- Each zone's router declares exactly the capabilities it needs, which keeps
  the composition root readable.

### Negative Consequences

- Some duplication in server wiring: two state constructors, two router trees.
- Cross-cutting concerns (tracing, config) have to be threaded into both states
  separately.
- Contributors must learn which state belongs to which zone before extending
  the server.

## Implementation

In force in `pulse-server`: `IdentityState` and `SignalState` are separate
types, the Identity and Signal zones listen on separate ports, and the rule is
documented in CLAUDE.md as a hard constraint.
