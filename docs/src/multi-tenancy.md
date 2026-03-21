# Multi-Tenancy

*How Pulse serves multiple organizations from a single deployment with cryptographic data isolation.*

---

## Model

A single Pulse deployment serves multiple organizations (tenants). Tenant isolation is **cryptographic**, not just logical -- compromise of one tenant's data does not expose another's.

### Customer-Managed Keys

Each tenant holds their own encryption keys. The platform operator has **zero access** to tenant data under any circumstance. This is a true zero-knowledge architecture from the operator's perspective.

**Explicit trade-off:** if a tenant loses their keys, their data is irrecoverable. The operator cannot help. This is by design, not a limitation.

### Crypto-Shredding

Key management supports clean tenant offboarding: delete the key and all tenant data becomes meaningless ciphertext. No need to locate and securely wipe every data record.

---

## What the Operator Can See

| Visible | Not Visible |
|---------|-------------|
| Tenant IDs | Response content |
| Data volume per tenant | Question content |
| Request rates and patterns | Employee identity data |
| Encrypted ciphertext blobs | Analytics results |
| System health metrics | Anything requiring a DEK to decrypt |

The operator can run the system, monitor its health, and bill tenants -- but cannot access any tenant data content.

---

## Per-Tenant Isolation

Each tenant has:
- **Separate data encryption keys** (DEKs) for each data domain (responses, questions, org data, analytics, blind signature keys)
- **Separate blind signature key pairs** -- tokens from Tenant A are invalid for Tenant B
- **Separate k-anonymity thresholds** -- configurable per tenant based on their privacy posture

For the full key hierarchy, envelope encryption architecture, and key lifecycle details, see [Key Management](key-management.md).
