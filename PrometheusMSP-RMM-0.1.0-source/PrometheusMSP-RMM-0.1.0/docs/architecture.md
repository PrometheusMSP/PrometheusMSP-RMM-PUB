# Architecture

## MVP boundary

Prometheus MSP RMM is a self-hosted control plane and outbound-only Go endpoint agent. This repository is an MVP for authorized Windows and Linux administration; it is not production-ready and does not include remote desktop, covert monitoring, credential collection, PSA/ticketing, or a hardened agent updater.

```text
Windows/Linux agent -- TLS 1.3 + device mTLS --> Control plane --> PostgreSQL
                                                      |
Base44 dashboard -- scoped bearer API ----------------+
Base44 webhook <-- planned timestamped HMAC worker -----+
```

The endpoint enrolls once with a short-lived token and a locally generated public key. The response binds a tenant/device identity to a client certificate and provides the independent Ed25519 job-verification key. Subsequent agent calls require mTLS. Endpoints never listen for inbound management traffic.

## Trust boundaries

- The control plane itself terminates TLS 1.3 and derives device identity from the verified client-certificate chain. Any public load balancer must use L4/TCP passthrough so mTLS remains end to end. This MVP does not trust forwarded certificate headers, and ordinary TLS termination will break agent authentication.
- The control plane authorizes every database operation within the authenticated tenant. Device IDs in bodies are matched to the mTLS identity.
- Base44 is a presentation/integration client, not endpoint execution authority. Read scopes and job approval scopes use distinct tokens/roles. Webhook delivery is a specified future worker, not implemented in this MVP.
- Agents treat the control plane as potentially fallible: every job is independently checked for Ed25519 signature, tenant/device scope, expiry, nonce replay, typed action, parameter schema, local policy, and approval.
- PostgreSQL is durable state. Secrets and private keys are file-mounted, never stored in images or source.

## Job lifecycle

An authorized actor creates a typed job. High-impact jobs remain pending until a separate authorized approval is recorded. The control plane signs a canonical envelope only after policy passes. The target polls, validates, records the nonce, executes with a deadline and output bound, then uploads a structured result. Creation, approval, dispatch, validation failure, and result are immutable audit events.

## Reliability and limits

Agents use bounded queues and exponential backoff with jitter. API payload and batch limits prevent event storms. Correlation IDs cross the implemented API, logs, and audits; the planned webhook worker will propagate them too. The current MVP is single-region, polling based, and has no HA migration orchestration, production CA/HSM integration, automated certificate rotation, signed updater, or disaster-recovery automation.
