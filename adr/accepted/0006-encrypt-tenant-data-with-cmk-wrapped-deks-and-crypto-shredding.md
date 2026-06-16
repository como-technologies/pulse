# ADR-0006: Encrypt tenant data with CMK-wrapped DEKs and crypto-shredding

> State: Accepted

## Status

Accepted

## Stakeholders

Pulse maintainers, tenant security owners (the CMK is customer-managed),
operators running multi-tenant deployments.

## Context and Problem Statement

Pulse stores anonymous response blobs and per-tenant signing keys at rest in a
multi-tenant deployment. Tenants need a credible answer to "what happens to our
data when we leave?" and to "what does a database breach expose?". Plain
at-rest encryption with an operator-held key answers neither: the operator can
always decrypt, and offboarding depends on provably deleting rows. The key
architecture had to be decided before the storage layer hardened around a
weaker model.

## Decision Drivers

- Tenant data sovereignty: the tenant, not the operator, should hold the root
  of trust.
- Offboarding must be cryptographically verifiable, not best-effort row
  deletion.
- A compromise of one data domain should not expose the others.
- Key rotation must not require re-encrypting all stored data.

## Considered Options

- Two-tier envelope encryption: a tenant-held Customer-Managed Key (CMK) wraps
  per-domain Data Encryption Keys (DEKs); deleting the wrapped DEKs
  crypto-shreds the tenant's data.
- One symmetric key per tenant, held by Pulse.
- Database-level encryption (TDE / encrypted volume) with a single operator
  key.

## Decision Outcome

Chosen: **CMK-wrapped per-domain DEKs with crypto-shredding**, because the
envelope gives sovereignty, isolation, and shreddability in one structure. The
tenant's CMK (tier 1) wraps tier-2 DEKs that Pulse stores only in wrapped form
— one DEK per data domain per tenant (`DEK-responses` for stored response
blobs, `DEK-blindsig` for the tenant's blind-signature private key,
`DEK-analytics` for client-side analytics payloads). Deleting a tenant's
wrapped DEKs renders every blob encrypted under them permanently unreadable;
stores return remaining ciphertext as-is rather than crashing. CMK rotation
re-wraps DEKs without touching bulk data.

### Positive Consequences

- Offboarding is a small, verifiable operation: destroy the wrapped DEKs and
  the data is gone cryptographically.
- Compromising one domain's unwrapped DEK does not expose other domains.
- The tenant holds the root of trust; the operator cannot unilaterally decrypt.
- Tested end to end: provisioning, envelope round-trips, and shredding are
  covered by multi-tenancy tests.

### Negative Consequences

- Key management complexity: provisioning, wrapping, rotation, and CMK
  availability become operational concerns (a production KMS integration is
  parked with the M1+ roadmap — see ADR-0007).
- Crypto-shredding is irreversible by design; an accidental DEK deletion is
  unrecoverable data loss.
- Every storage read/write pays an unwrap/encrypt cost relative to plaintext
  storage.

## Implementation

In force at M0 with dev providers: `TenantProvisioner` generates DEKs, wraps
them under the CMK, generates blind-signature keypairs, and registers
everything atomically; `EncryptingResponseStore` envelopes blobs under
`DEK-responses`. The full tier design is documented in the book's
key-management page. Production KMS-backed CMKs are deliberately out of scope
while the product is parked at M0.
