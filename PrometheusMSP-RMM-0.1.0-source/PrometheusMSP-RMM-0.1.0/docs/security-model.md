# Security Model

## Authentication and authorization

Agent enrollment uses a one-time or short-lived tenant-scoped token. All later agent routes require a valid per-device client certificate. Operator/Base44 routes use scoped bearer credentials in the MVP; production should use OIDC with short-lived access tokens and roles such as viewer, technician, approver, tenant administrator, and emergency operator.

Read-only inventory and telemetry can run automatically under local policy. Maintenance actions may run only when action, parameters, and maintenance window match policy. Installs, removals, arbitrary scripts, reboots, and security-sensitive changes require recorded technician approval. Approval should be by a different principal where policy requires separation of duties.

The MVP action catalog includes service restart, temporary-file cleanup, reboot, and Linux-only package install/removal and patch installation. Package names are validated and native package-manager argument arrays are used. Windows package and patch actions are explicitly unsupported in this milestone. Arbitrary scripts and raw command strings are not accepted.

## Signed envelopes

The signature covers a deterministic representation of job ID, tenant ID, device ID, issue and expiry timestamps, nonce, action, parameters, risk, and approver. Agents reject unknown fields/actions, invalid schemas, expired/future jobs, prior nonces, mismatched identities, and signatures from unknown keys. Private signing keys belong in a KMS/HSM in production. Public verification keys may be pinned and rotated with overlapping validity.

## Secrets and data

Never commit `.env`, private keys, tokens, client certificates, or endpoint telemetry. Restrict configuration/state directories to SYSTEM or root. Redact authorization headers, tokens, secrets, and sensitive command output from logs. Apply retention limits to raw events and job output. Backups must be encrypted, access logged, and regularly restored in tests.

The development PKI script is intentionally unsuitable for production: it stores an exportable CA key on disk and issues 30-day certificates. Compose mounts that key so the MVP can issue enrollment certificates. Use a narrowly scoped online intermediate backed by a managed PKI, or a dedicated certificate-issuing service, for real deployments; never mount a production root CA key into the control plane.
