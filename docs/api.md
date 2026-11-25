# HTTP API

The framework-light Node API and CLI invoke the same `ScanApplicationService`. The API is a local
integration surface with application-level controls; it is not by itself a production-ready service.
It has no user system, database, distributed quota, external monitoring, or deployment automation.

## Start locally

Configure at least one API credential through a protected secret source as described in
[configuration](configuration.md), then run:

```sh
pnpm start:api
```

The default listener is `127.0.0.1:8787`. Scan requests and health/readiness require a bearer key by
default. Health/readiness can be made public with `BLUELEAF_API_PUBLIC_HEALTH=true`; public health
responses reveal only `ok` or `ready` and do not authorize scanning.

## Authentication

Provide `Authorization: Bearer <token>` to `POST /v1/scans` and, unless health is public, to
`GET /health` and `GET /ready`. Keys are configured as an environment JSON array, not in source or
command-line arguments. Each configured credential has a bounded identity label, a secret token,
and optional `expiresAt` ISO timestamp or `disabled: true` field. Disabled, expired, malformed, and
unknown credentials return the same 401 response. Rotate keys by adding a new identity/key, updating
the secret source, then disabling/removing the old entry.

```http
Authorization: Bearer <secret supplied by your secret manager>
```

The server hashes candidate and configured values to fixed-size digests and compares them with
Node's timing-safe comparison. Keys are never included in responses or audit events.

## Endpoints

### `GET /health`

Liveness only. Returns `{"schemaVersion":"1.0","status":"ok"}` and never scans.

### `GET /ready`

Readiness only. Returns `{"schemaVersion":"1.0","status":"ready"}` and does not probe targets
or query intelligence providers.

### `POST /v1/scans`

Requires bearer authentication and `Content-Type: application/json`. The request is bounded by
`BLUELEAF_API_MAX_REQUEST_BYTES` (8 KiB by default) and must match
[`schemas/scan-request.schema.json`](../schemas/scan-request.schema.json):

```json
{
  "schemaVersion": "1.0",
  "target": { "url": "https://your-authorized-host.example/" }
}
```

Success returns HTTP 200 with the shared versioned `ScanResult` described by
[`schemas/scan-result.schema.json`](../schemas/scan-result.schema.json). The CLI serializes this
same service result. The API omits raw request/response headers, cookies, and body bytes; target and
redirect URLs omit credentials, query, and fragment values. Responses are bounded by
`BLUELEAF_API_MAX_RESPONSE_BYTES` (12 MiB default) and use `Cache-Control: no-store`.

The response carries `X-Request-ID`; a caller-supplied ID is echoed only if it matches the restricted
ASCII identifier format, otherwise a random UUID is generated. Errors use the versioned
[`schemas/api-error.schema.json`](../schemas/api-error.schema.json) envelope and the same request ID
header.

Error statuses include 400 invalid request, 401 missing/invalid credential, 403 target/origin/proxy
policy rejection, 404 unknown route, 405 method not allowed, 413 request too large, 415 unsupported content type, 429
identity rate/concurrency limit, 499 client cancellation, 502 provider failure, 503 global capacity
or shutdown, and 504 scan deadline. Rate-limited responses include `Retry-After`. Internal errors
use generic messages and do not expose stack traces, filesystem paths, provider payloads, headers,
environment values, or credentials.

## Limits and CORS

Defaults are 60 scan requests per identity per 60-second fixed window, two scans per identity and
two scans globally at a time. Windows, request bytes, request receive duration, scan duration,
response bytes, concurrent scans, and rate buckets have configured hard bounds. Authentication
failures use an additional process-local client-address limiter. If the bounded bucket table fills,
new identities/addresses are rejected until expired buckets are reclaimed.

Rate and concurrency state is in memory, local to one process, and resets on restart. It is not a
distributed quota and does not replace an ingress gateway/WAF limit. No wildcard CORS is supported.
Configure exact `BLUELEAF_API_ALLOWED_ORIGINS`; without an allowlisted `Origin`, browser requests are
rejected. Preflight permits only the implemented methods and headers. Credentials are not enabled
through CORS.

## Cancellation and SSRF

Client disconnects and scan deadlines abort the shared scan signal. Cancellation reaches the secure
Phase 2 target probe and registered advisory fetch providers; provider calls also have their own
timeouts. OS-level DNS resolution itself may finish after cancellation, but no connection is opened
from a cancelled resolution. Active work remains counted until it settles. Shutdown stops accepting
new scans, aborts active scan signals, waits for the configured grace period, then closes remaining
connections.

The API has no alternate target HTTP client. Every probe applies DNS A/AAAA validation, default
private/reserved address blocking, checked-IP pinning, redirect revalidation, HTTPS downgrade
rejection, TLS certificate checks, response-byte limits, and timeout limits. Scanning is passive and
bounded. Use only against systems you own or are authorized to assess.

## Deployment

External binding is rejected unless all of these are configured: explicit external bind opt-in,
TLS termination at a trusted ingress, at least one active API key, and exact trusted proxy IPs. The
server also rejects external requests that do not arrive from an allowlisted proxy. The ingress must
restrict direct access, terminate TLS, and overwrite or append `X-Forwarded-For` correctly. Forwarded
addresses from untrusted peers are ignored. See [deployment guidance](deployment.md).

Security headers include `nosniff`, frame denial, a restrictive content security policy, referrer
and permissions policies, and HSTS only when external TLS termination is explicitly configured.
These application controls do not replace TLS, firewalling, gateway quotas, log retention policy,
secret rotation, or operational monitoring.
