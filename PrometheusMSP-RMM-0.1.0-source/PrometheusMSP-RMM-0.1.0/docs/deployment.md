# Deployment Guide

## Local evaluation

Requirements: Go 1.23, Docker with Compose v2, OpenSSL, and `sha256sum`.

1. Copy `.env.example` to `.env` and replace every `CHANGE_ME` value. Do not reuse these values outside local evaluation.
2. Run `make pki`. This produces development-only secrets under `deploy/pki/`.
3. Run `make test`, `make compose-up`, and then `make seed-dev`. The seeded tenant ID matches `.env.example`; this command is strictly for local evaluation.
4. Check `curl --cacert deploy/pki/ca.crt https://localhost:8443/healthz`. The separate cleartext health listener is bound only inside the control-plane container.
5. Create short-lived enrollment material through `POST /api/v1/enrollment-tokens`, then run the platform installer. Remove the enrollment token from shell history and configuration after successful enrollment.

Compose publishes the control plane only on loopback. PostgreSQL has no host port. Do not expose port 8080 directly to the internet.

The Compose backend network permits outbound connectivity. PostgreSQL remains unpublished, but Compose networking is not a substitute for host/cloud firewall policy. Restrict database ingress to the control-plane workload. When the planned webhook worker is implemented, restrict control-plane egress to approved destinations.

The SQL file under `control-plane/migrations/` is mounted into PostgreSQL's initialization directory and therefore runs only when the data volume is first created. Real upgrades require a reviewed, versioned migration runner and backups; restarting Compose does not apply later migrations.

## Production minimums

- Put the application behind an L4/TCP load balancer using TLS passthrough, with firewall policy restricting backend access. The application must terminate TLS 1.3 and receive the client certificate directly because it derives device identity from `r.TLS.VerifiedChains`. Ordinary HTTP reverse-proxy TLS termination and forwarded certificate headers are unsupported in this MVP.
- Replace development PKI with a managed/offline root plus a narrowly scoped issuing workflow; never give the control plane a production root key. Replace signing files with a KMS/HSM-backed workflow.
- Use a dedicated PostgreSQL role, mandatory TLS, encrypted storage/backups, tested point-in-time recovery, and network policy.
- Integrate OIDC, central secret management, rate limiting, alerting, metrics, log aggregation, time synchronization, and certificate revocation/rotation.
- Pin image digests, generate an SBOM, scan artifacts, sign releases, and stage agent rollouts with rollback.
- Configure webhook destinations from an allowlist to prevent SSRF. Require HTTPS and resolve/validate destinations at delivery time.

## Building endpoint artifacts

`make build` cross-compiles Linux amd64/arm64 agents, a Windows amd64 agent, and the Linux control plane into `dist/`, then generates SHA-256 checksums. Linux installation uses `scripts/install-agent-linux.sh`; Windows installation uses `scripts/install-agent-windows.ps1` from an elevated PowerShell session. Both install with `PROMETHEUS_DRY_RUN=true`. Review service privileges and action requirements before deployment: the MVP service runs privileged because maintenance and native package actions require broad host access. A split unprivileged collector/privileged helper is future hardening work.

After enrollment succeeds and the identity exists in the protected state directory, remove `PROMETHEUS_ENROLLMENT_TOKEN` from `/etc/prometheus-rmm/agent.env` (Linux) or the service's `Environment` registry value (Windows), then restart the service. The agent no longer needs that bootstrap token. Configure explicit service and action allowlists before disabling dry-run mode.

## Operations

Monitor `/healthz`, request latency/error rate, enrollment failures, device heartbeat age, queue depth, rejected signatures/nonces, and database saturation. The future webhook worker will also need backlog/dead-letter monitoring. Alert on emergency role use and repeated authorization failure. Before upgrades, back up PostgreSQL, verify restore, deploy control-plane changes before dependent agent behavior, and use a small canary device group.
