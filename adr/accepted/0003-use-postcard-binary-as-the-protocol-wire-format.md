# ADR-0003: Use postcard binary as the protocol wire format

> State: Accepted

## Status

Accepted

## Stakeholders

Pulse maintainers, client implementers (desktop, mobile, embedded targets).

## Context and Problem Statement

Protocol messages (`TokenRequest`, `TokenResponse`, `QuestionDelivery`,
`ResponseSubmit`, `ResponseAck`) cross the wire between clients and both zone
servers, and the client roadmap includes constrained and embedded targets. The
wire format determines payload size, serialization cost, how much code clients
can share with the server, and how the protocol can evolve. A format had to be
fixed before the client protocol library and test harness could be built.

## Decision Drivers

- Compactness — blind-signature payloads are already large; framing overhead
  should be minimal.
- `no_std` compatibility, so embedded clients share serialization code with the
  server instead of reimplementing it.
- serde-native, to reuse the existing type definitions in `pulse-protocol`.
- Room for protocol evolution without out-of-band negotiation.
- Debuggability of the non-protocol surface (auth, errors, analytics).

## Considered Options

- postcard binary for protocol messages, JSON retained for auth, debug,
  analytics, and error responses.
- JSON everywhere.
- Other binary formats (CBOR, MessagePack, protobuf).

## Decision Outcome

Chosen: **postcard with a version byte prefix, JSON retained at the edges**,
because postcard is compact, `no_std`-compatible, and serde-native — the same
`pulse-protocol` types serialize on every target. Every postcard message
carries a version byte prefix (`[major | minor | payload]`) so receivers can
dispatch to the correct deserializer without out-of-band context. JSON stays
where humans and generic tooling need it: `POST /auth`, error responses
(`{ "code": "...", "message": "..." }`), debug, and analytics.

### Positive Consequences

- Compact payloads and cheap serialization on every target, including embedded.
- One set of wire types in `pulse-protocol` shared by client and server —
  serialization drift between sides is impossible.
- The version prefix gives a forward path for protocol evolution.

### Negative Consequences

- Protocol endpoints are not curl-able; inspecting traffic needs the
  walkthrough example or integration tests rather than a JSON pretty-printer.
- postcard is not self-describing, so schema evolution discipline rests on the
  version prefix being respected.
- Two formats coexist in the server (postcard protocol + JSON edges), which
  contributors must keep straight.

## Implementation

In force: `pulse-protocol` serializes all protocol messages with postcard via
serde; success responses are postcard, denials and rejections are JSON error
responses. Documented in the design book (protocol and architecture pages).
