# Deployment guidance

Phase 12 adds authentication, bounded process-local limits, request cancellation, security headers,
and audit events. These controls do not make an instance production-ready by themselves. The project
does not include deployment manifests, a distributed quota store, a WAF, an external log service,
or abuse analytics.

## Local operation

Keep the API on `127.0.0.1:8787` unless a trusted ingress is configured. API startup requires at
least one active key. Health/readiness require a key unless `BLUELEAF_API_PUBLIC_HEALTH=true` is
set; exposing those two endpoints reveals only process liveness/readiness.

## Reverse proxy requirements

To bind beyond loopback, configure all of:

- `BLUELEAF_API_ALLOW_EXTERNAL=true`
- `BLUELEAF_API_TLS_TERMINATED=true`
- `BLUELEAF_API_KEYS_JSON` with an active credential
- `BLUELEAF_API_TRUSTED_PROXY_ADDRESSES` with exact ingress source IP addresses

The API rejects external connections whose direct peer is not allowlisted. Put the application on a
private network reachable only by the ingress. The ingress must terminate HTTPS, enforce its own
request/rate limits, and sanitize or append `X-Forwarded-For` consistently. The application uses
forwarded client addresses only when the direct connection is from an allowlisted proxy. It ignores
`Forwarded`, `X-Real-IP`, and Cloud-provider-specific headers. Do not use broad or stale proxy IP
lists.

Configure `BLUELEAF_API_ALLOWED_ORIGINS` only for exact browser origins that need access. CORS is
disabled by default; wildcard origins and credentialed CORS are unsupported. Non-browser bearer
clients need no CORS configuration.

## TLS, secrets, and operations

Use HTTPS at the trusted ingress for all external traffic. HSTS is emitted only when external TLS
termination is explicitly configured. Keep API and NVD keys in the platform secret manager or
protected service environment; avoid command-line arguments, tracked files, shell history, and
diagnostic dumps. Rotate keys by adding a new identity before disabling the old one.

The process emits one-line structured security events to stderr. Route stderr through an operator
controlled log collector with access controls, retention limits, and alerting. Events intentionally
omit target URLs, client IPs, request headers/cookies, response bodies, API keys, and provider error
payloads. No external monitoring service is called by this application.

Rate limits are fixed-window and in-memory per process. The advisory cache is also process-local,
with entry and serialized-byte caps, TTL, and LRU eviction. Both reset on restart and do not
coordinate across replicas. Place a gateway/WAF in front of multi-replica or internet-facing deployments for
distributed quotas, connection limits, abuse detection, and network ACLs. Configure platform CPU,
memory, file-descriptor, and egress limits. Review supported Node.js updates and rotate credentials.

## Remaining limitations

There is no user management, persistent scan history, distributed limiter/quota, database, queue,
external audit sink, alerting, production deployment recipe, automatic certificate management, or
infrastructure firewall policy. Public internet exposure requires a separately reviewed ingress and
operational security design. Unknown or incomplete scan results never mean a target is safe.
