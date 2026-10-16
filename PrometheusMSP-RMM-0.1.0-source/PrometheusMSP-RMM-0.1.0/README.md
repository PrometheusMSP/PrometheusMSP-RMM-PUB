# Prometheus MSP RMM

Prometheus MSP RMM is an early, self-hostable remote monitoring and management MVP for Windows and Linux endpoints that you are authorized to administer. A Go agent makes outbound TLS connections to a Go control plane backed by PostgreSQL. The vertical slice covers enrollment, heartbeat, inventory/events, policy-controlled signed jobs, results, and audit records.

> **MVP warning:** this is development software, not production-ready RMM. It lacks the full hardening, high availability, managed-key integration, certificate lifecycle automation, scale validation, and platform coverage expected of a commercial service. It does not provide remote desktop or covert monitoring.

## Security properties

- Per-device identity and mTLS after enrollment; no inbound endpoint port
- Tenant scope enforced from authenticated identity
- Typed, expiring Ed25519-signed jobs with nonce replay protection
- Approval required for high-impact actions; privileged activity is audited
- Bounded payloads/output and no raw server-provided commands by default
- Base44 can use the implemented scoped API and is not an endpoint execution authority; the signed webhook contract is specified, but its delivery worker remains roadmap work

## Repository

```text
agent/          endpoint service, collectors, local policy, job execution
control-plane/  API, policy, persistence, migrations, audit and dispatch
internal/       shared protocol and security packages
schemas/        versioned JSON schemas and examples
deploy/         Dockerfiles, Compose and service definitions
scripts/        builds, development PKI, packaging and service installation
docs/           architecture, threat model, OpenAPI and operations guidance
```

## Quick start

Requirements are Go 1.23, Docker with Compose v2, and OpenSSL.

```sh
cp .env.example .env
# Replace every CHANGE_ME value in .env.
make pki
make test
make compose-up
make seed-dev
```

`make seed-dev` creates the local tenant referenced by `.env.example`; it does not create or handle credentials. Compose binds the TLS control-plane port to `127.0.0.1:8443`. For network exposure, use L4/TCP TLS passthrough so the application verifies device certificates end to end; ordinary TLS termination breaks agent identity in this MVP. The development CA stores an exportable key locally and must never be used for production.

Build native artifacts with `make build`. Install a Linux agent with `PROMETHEUS_SERVER_URL` and a short-lived `PROMETHEUS_ENROLLMENT_TOKEN` set in the environment, then run `sudo -E scripts/install-agent-linux.sh <binary>`. For the development CA, also set `PROMETHEUS_BOOTSTRAP_CA_FILE`; production should use normal OS trust. On Windows, invoke `scripts/install-agent-windows.ps1` from an elevated PowerShell session and provide its required parameters. Remove enrollment material after successful enrollment.

## API and integration

The contract is in [docs/openapi.yaml](docs/openapi.yaml), with complete schemas/examples under `schemas/v1/`. Agent calls after enrollment use mTLS and should include `X-Correlation-ID`. Base44 API usage and the planned timestamped-HMAC webhook contract, including replay protection and retry/dead-letter behavior, are described in [docs/base44-integration.md](docs/base44-integration.md).

## Documentation

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Security model](docs/security-model.md)
- [Deployment guide](docs/deployment.md)
- [Roadmap](docs/roadmap.md)
- [Security reporting](SECURITY.md)

The license is currently a placeholder and must be selected before distribution.
