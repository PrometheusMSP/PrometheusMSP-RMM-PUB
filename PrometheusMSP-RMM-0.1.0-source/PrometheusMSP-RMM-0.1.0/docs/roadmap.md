# Roadmap

## MVP

- Device enrollment and certificate identity
- Heartbeat, inventory, and bounded event ingestion
- Signed typed jobs, approval state, polling, results, and audit records
- PostgreSQL persistence, Docker Compose, API schemas, and Windows/Linux service packaging

## Hardening

- OIDC/MFA, richer RBAC, PostgreSQL row-level security, managed CA/KMS, certificate rotation/revocation
- Durable webhook outbox, delivery history, dead-letter replay, Redis only if queue scale warrants it
- Metrics, dashboards, alerting, backup/restore automation, load testing, SBOM and signed releases
- Expanded Windows Event Log/journald checkpointing and collector coverage
- Complete Windows uptime and disk inventory; Windows event checkpointing is limited in the MVP

## Management coverage

- Native Windows Update and distro-aware Linux patch workflows with preflight/postflight checks
- Expanded Windows installer support; the MVP package and patch actions are Linux-only
- Signed agent updates with canary rollout and rollback
- Optional Splash Time remote-support adapter after an official specification is supplied

Remote desktop, PSA integration, and full ticketing remain later phases.
