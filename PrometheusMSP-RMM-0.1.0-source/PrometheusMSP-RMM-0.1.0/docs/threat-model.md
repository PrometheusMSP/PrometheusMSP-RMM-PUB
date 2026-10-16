# Threat Model

## Protected assets

Device identity keys, CA and job-signing keys, enrollment tokens, operator credentials, endpoint command authority, tenant data, telemetry integrity, and the audit trail are the highest-value assets.

## Principal threats and controls

| Threat | MVP control | Remaining risk |
|---|---|---|
| Stolen enrollment token | Short expiry, server-side consumption, rate limit, public-key binding | Deployment must provision tokens through a separate trusted path |
| Impersonated endpoint | Per-device certificate, mTLS identity/body match, revocation state | Automated rotation and OCSP/CRL distribution are future work |
| Malicious/replayed job | Canonical Ed25519 signature, expiry, random nonce, device/tenant scope, persistent replay cache | Clock integrity and signing-key custody remain operational dependencies |
| Privilege abuse | Typed allowlisted actions, RBAC, separate approval, maintenance policy, immutable audit | MVP roles need external identity-provider integration |
| Tenant data leak | Tenant ID on all records and repository queries; auth-derived scope | Add PostgreSQL row-level security as defense in depth before production |
| Command injection | Typed parameters and direct process argument arrays; no raw commands by default | Each new action requires security review and adversarial tests |
| Event/telemetry flood | Body limits, batch caps, bounded endpoint queue | Rate limiting is not implemented in the MVP and must be applied at the trusted edge |
| Webhook spoof/replay | HMAC-SHA256 over timestamp and raw body, delivery ID, five-minute tolerance, idempotency | Consumers must persist delivery IDs atomically |
| Database compromise | Network isolation, least privilege, encrypted backup guidance | Field-level encryption and managed KMS integration are future work |
| Agent binary replacement | OS service ACLs and documented checksums | Signed installer/update chain is not yet implemented |

## Explicit non-goals

The software must not hide from endpoint users or security tools, scrape credentials, log keystrokes, bypass consent, disable endpoint protection, weaken repository signing, or accept unsigned arbitrary commands. Emergency override does not bypass cryptographic validation; it adds a privileged role, justification, short expiry, and enhanced auditing.

## Security validation before production

Perform independent penetration testing, dependency and container scanning, CA/HSM design review, RBAC and tenant-isolation tests, restore drills, load tests, log-redaction review, certificate rotation exercises, and platform-specific privileged action testing.
