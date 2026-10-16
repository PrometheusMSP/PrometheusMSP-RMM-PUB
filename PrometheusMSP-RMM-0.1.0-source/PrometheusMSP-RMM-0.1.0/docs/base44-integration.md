# Base44 Integration

The scoped REST API described here is implemented. Webhook delivery is a contract and roadmap design only in this MVP; there is no delivery worker yet.

Base44 consumes the implemented operator REST API; it can consume webhooks after the planned delivery worker is built. It must never generate, sign, or send raw endpoint commands. Use separate credentials for dashboard reads, job requests, and approvals. The control plane derives tenant scope from the authenticated credential.

## API behavior

Use `/api/v1` endpoints documented in `openapi.yaml`. Send `Authorization: Bearer <scoped-token>`, `Accept: application/json`, and a unique `X-Correlation-ID`. List responses use opaque cursor pagination. The MVP does not implement request idempotency keys: after an ambiguous timeout, retrieve current state before retrying a job mutation.

Do not expose a job as dispatchable until policy and approval are satisfied. The dashboard should render server-returned state rather than infer approval from its own UI state.

## Planned webhook verification

Deliveries include `Webhook-Id`, `Webhook-Timestamp` (Unix seconds), and `Webhook-Signature: v1=<hex>`. Compute `HMAC-SHA256(secret, timestamp + "." + raw_request_body)` and compare in constant time. Reject timestamps more than five minutes from local time and atomically store `Webhook-Id`; duplicate IDs return 2xx without repeating side effects.

Events include `device.enrolled`, `device.state_changed`, `alert.created`, `job.completed`, and `patch.completed`. Each envelope contains `id`, `type`, `occurred_at`, `tenant_id`, and `data`. See `schemas/v1/examples.json`.

The delivery worker should retry timeouts, connection failures, HTTP 408, 429, and 5xx with exponential backoff and jitter. Honor a bounded `Retry-After`. Do not retry other 4xx responses. After the configured maximum attempts, move the immutable delivery to a dead-letter queue with response metadata and permit an authorized replay that retains the event ID but creates a new delivery ID. Never log the signing secret or authorization headers.

## Current limitation

The MVP documents the webhook contract, but does not implement a delivery worker, administrative replay UI, or production secret rotation. Base44 webhook integration must be exercised against a staging receiver after that worker exists and before relying on it operationally.
