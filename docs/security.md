# Security implementation status

This page distinguishes controls implemented in the application from controls that must be
provided by a deployment. The checks below were reconciled against the current Phase 2, Phase 3,
Phase 6–7, and Phase 11–13 implementation. They describe code behavior, not an independent
penetration test or infrastructure certification.

## Implemented application controls

### Target requests and SSRF boundaries

- [x] Accept only absolute HTTP or HTTPS URLs and reject embedded URL credentials.
- [x] Resolve all DNS A/AAAA answers and, by default, reject targets if any answer is not globally
      routable. Blocked classes include loopback, private, link-local, shared, documentation,
      benchmark, multicast, reserved, and relevant IPv6 transition ranges.
- [x] Pin target connections to a checked resolved IP address to prevent a DNS answer change from
      selecting a different address for the connection.
- [x] Re-resolve and revalidate redirect targets, apply host allowlists at every hop, enforce the
      redirect limit, and reject HTTPS-to-HTTP downgrade.
- [x] Keep normal TLS certificate verification enabled. A caller may explicitly inject a custom CA
      trust set; certificate verification is not disabled.
- [x] Bound probe timeout and response bytes. Private-network access is disabled by default;
      enabling it is an explicit trusted-deployment override and requires an allowlist in production
      configuration.
- [x] Strip Authorization, Cookie, and Proxy-Authorization on cross-origin redirects. Response
      cookies are recorded separately and are never replayed.

### Passive evidence and result handling

- [x] Limit evidence body inspection and evidence count independently, and report truncation.
- [x] Extract only passive response evidence. The engine does not execute scripts, submit forms,
      follow discovered links, crawl, probe paths, or exploit targets.
- [x] Redact cookie values and attributes, sensitive headers, URL credentials/query/fragment, and
      token-bearing metadata. Bound retained snippets and normalized values.
- [x] Keep raw response headers, cookies, and body bytes out of CLI/API scan results. Sanitize
      target and redirect URLs before serialization.
- [x] Keep fingerprint definitions local, versioned, validated literal data; no regex or downloaded
      executable rules are accepted. Fingerprint and version confidence are heuristics, not
      calibrated probabilities or proof of origin software.
- [x] Preserve unknown, contradictory, stale, unsupported, and unavailable data. An empty or
      incomplete result is not evidence that a target is safe.

### Intelligence, cache, and provenance

- [x] Validate OSV, NVD, Canonical Ubuntu, and Red Hat responses in provider adapters and normalize
      them into provider-independent records. Provider wire formats stay in infrastructure code.
- [x] Bound external provider requests with timeouts, limits, retries, pagination/date windows, and
      rate-limit handling. NVD credentials are injected through configuration, transmitted only in
      the provider request header, and excluded from diagnostics.
- [x] Preserve source identity, original advisory identifiers, retrieval and source modification
      times, references, and source-specific provenance. Keep conflicting provider records
      separate.
- [x] Cache only successful normalized results. The default in-memory cache has TTL, a 2,000-entry
      limit, a 32 MiB serialized key/value limit, and least-recently-used eviction. Oversized
      entries are not retained. Cache and rate-limit state are process-local and reset on restart.
- [x] Require explicit technology-to-package/ecosystem mappings. Unsupported mappings, unknown
      versions, and unavailable sources remain explicit; missing records never imply safety.
- [x] Keep PHP security bulletins without a stable documented machine-readable interface
      unsupported/manual; the application does not scrape arbitrary bulletin HTML.

### API authentication, limits, cancellation, and logging

- [x] Require configured bearer credentials for scans and, by default, health/readiness routes.
      Compare hashed fixed-size digests with a timing-safe comparison; reject missing, disabled,
      and expired credentials without revealing which check failed.
- [x] Bind the API to `127.0.0.1` by default. External binding requires explicit opt-in, a
      configured TLS-terminating ingress, active credentials, and exact trusted proxy addresses;
      external peers not in the proxy allowlist are rejected.
- [x] Use `X-Forwarded-For` only for a direct peer in the trusted proxy allowlist. Ignore forwarded
      client identity from untrusted peers. CORS is disabled unless exact HTTP(S) origins are
      configured; wildcard origins are rejected.
- [x] Bound request body and receive time, serialized response size, scan duration, rate-limit
      buckets, global and per-identity concurrency, and shutdown grace period. Rate and concurrency
      limits are in-memory controls, not distributed quotas.
- [x] Apply bounded fixed-window scan and authentication-failure rate limits. Reject requests when
      the bucket table is full; return `Retry-After` where applicable.
- [x] Propagate client-disconnect and scan-deadline cancellation to the scan workflow, secure
      target provider, and provider calls that support cancellation. DNS system resolution itself
      may finish after cancellation; the canceled pipeline does not open a target connection after
      the resolution boundary.
- [x] Emit one-line structured security events to stderr with bounded event codes, timestamps,
      request IDs, and configured identity labels. Events omit target URLs, client IP addresses,
      request/response headers, cookies, payloads, provider error bodies, and credentials.
- [x] Return generic API errors without stack traces, filesystem paths, provider payloads, or
      secret configuration. Include restrictive response headers and request IDs.
- [x] Stop new work on shutdown, abort active scans, wait for a bounded grace period, then close
      remaining connections.

## Remaining application limitations

- Fingerprint confidence has not been calibrated against a curated labeled corpus. It is an
  explainable heuristic and must not be treated as a probability or policy-grade proof.
- Package mappings, installed-package inventory, source-lineage declarations, and lifecycle facts
  are caller-supplied. The application cannot authenticate their truth or authority.
- Intelligence coverage is limited to configured providers and mappings. No provider's missing
  record proves absence of vulnerabilities; PHP security bulletin scraping, GitHub Advisory, and
  other unsupported sources are not implemented.
- Cache, rate-limit, and concurrency state is local to one process. There is no database,
  distributed quota store, shared cache, user system, persistent history, external audit sink, or
  abuse analytics service.
- The API's bearer authentication and resource limits do not make direct internet exposure safe.
  No production deployment, penetration test, infrastructure firewall, WAF, or deployment
  automation is included.
- Scanning is limited to one bounded passive HTTP/HTTPS probe. No crawling, active exploitation,
  fuzzing, brute forcing, port scanning, remediation execution, or secure/insecure binary verdict
  is provided.

## Infrastructure responsibilities

Before exposing an instance beyond a trusted local environment, operators must separately review
and provide:

- HTTPS termination and certificate lifecycle at a trusted ingress;
- firewall/network ACLs that prevent bypassing the ingress and restrict outbound access as needed;
- gateway/WAF rate limits, distributed quotas, connection limits, and abuse monitoring for
  multi-process or public deployments;
- protected secret injection, access control, rotation, and incident response for API/NVD keys;
- access-controlled log collection, retention, alerting, and operational ownership for stderr
  security events; and
- platform CPU, memory, process, file-descriptor, DNS, and egress limits.

Configure the ingress to overwrite or append `X-Forwarded-For` according to the documented trust
model. Do not trust arbitrary forwarding headers or enable private target networking for an
untrusted scanner. Application controls are defense in depth and do not replace an infrastructure
security review. See [deployment guidance](deployment.md) and [SECURITY.md](../SECURITY.md).
