# Project Context — Blueleaf Identify Techstack CVE

## Purpose

This file is authoritative repository context. The long-term purpose is to identify a target's
technology stack and associate vulnerability intelligence. The current milestone includes the
Phase 1 foundation, Phase 2 bounded probing, Phase 3 passive evidence collection, Phase 4
technology fingerprinting, Phase 5 version intelligence, Phase 6 live OSV advisory retrieval,
Phase 7 multi-source NVD and official vendor intelligence retrieval, Phase 8 advisory correlation,
Phase 9 confidence and security assessment, Phase 10 deterministic remediation planning, Phase 11
shared CLI and HTTP API integration, and **Phase 12 runtime security hardening**.
Phase 13 establishes end-to-end and v0.1.0 package release-readiness verification.

## Frozen architecture

- Runtime: Node.js 22+, strict TypeScript, native ESM (`NodeNext`), pnpm; runtime dependencies
  remain absent.
- Dependency direction: presentation/infrastructure → application → domain. Domain has no
  dependencies on adapters, configuration sources, networks, or third-party providers.
- Application owns use-case contracts and provider ports. Phase 2's resolver/probe live under
  `src/infrastructure/http`; Phase 3's deterministic `EvidenceEngine` lives under
  `src/application/evidence` and consumes the existing `HttpResponse` contract.
- `IdentificationService` remains unchanged for Phase 1 compatibility. Phase 11 adds the
  versioned `ScanApplicationService` as the shared end-to-end application boundary for CLI and
  HTTP API adapters. Transports must not implement pipeline logic.
- Configuration is immutable and passed explicitly. `loadRuntimeSettings` is the explicit
  environment boundary used by executable composition; domain and application services do not
  read process environment or secret stores.
- Runtime dependencies remain absent. Phase 2 and Phase 3 use Node built-ins.
- Phase 4's `FingerprintEngine` is a pure application service. Versioned, data-only knowledge is
  stored separately in `src/fingerprinting/definitions.ts`; the engine contains no product rules.
- Phase 5's `VersionIntelligenceEngine` is pure application logic. Ecosystem parsing/comparison
  rules are supplied by `VersionStrategyRegistry` and kept separate from assessment/reconciliation.
- Phase 6/7 provider-independent advisory and result contracts live in the domain.
  `IntelligenceResolverService` selects registered provider ports and explicit package mappings;
  OSV, NVD, Ubuntu, and Red Hat wire formats remain in infrastructure adapters.
- Phase 8 `VulnerabilityCorrelationEngine` preserves source-separated package applicability.
  Phase 9 `SecurityAssessmentEngine` separately assesses confidence and state; it cannot rewrite
  Phase 8 correlation results.
- Phase 10 `RemediationEngine` derives recommendations from supplied Phase 5–9 contracts and
  explicit package/lifecycle inputs; it cannot alter Phase 9 states or fetch external data.
- CLI commands are `--help`, `--version`, and `scan <url> [--json]`. The API exposes health,
  readiness, and `POST /v1/scans`. Both call the same `ScanApplicationService`.

## Stable domain and serialization contracts

- `IdentificationResult` remains schema version `1.0` with its existing required fields.
  `schemas/identification-result.schema.json` remains its Draft 2020-12 schema.
- `HttpRequest` and required `HttpResponse` fields (`status`, `headers`, `body`, `finalUrl`) remain
  unchanged. Phase 2 metadata and Phase 3 evidence contracts are additive.
- `Evidence` has stable `type`, `source`, `normalizedValue`, `strength`, and human-readable
  `reason` fields. Bounded `rawValue`, `key`, and generic `versionHint` are optional.
- `EvidenceCollection` has its own `schemaVersion: "1.0"`, ordered `evidence` array, and
  processing byte/truncation metadata. Its Draft 2020-12 schema is
  `schemas/evidence-collection.schema.json`.
- `technologyHint` is reserved for a later classifier and is never populated in Phase 3.
  `versionHint` is a generic version-like candidate, never an authoritative software version.
  `strength` describes source fidelity (`direct` or `derived`), not confidence in attribution.
- Existing result and provider contracts must not be removed or reinterpreted. Breaking shape or
  meaning changes require a new schema version and release notes.
- `FingerprintResult` has its own `schemaVersion: "1.0"` and declares the consumed evidence schema
  version. `TechnologyDetection` and evidence provenance references are defined in
  `src/domain/fingerprints.ts` and `schemas/fingerprint-result.schema.json`.
- Fingerprint knowledge uses `FingerprintDefinitionSet` schema version `1.0`, validated literal
  match operators, and `schemas/fingerprint-definitions.schema.json`. Update rules without changing
  engine logic when possible; incompatible definition changes require a new schema version.
- `VersionAssessmentCollection` uses schema version `1.0`, records consumed fingerprint schema
  version, and keeps raw observations, parsed upstream versions, vendor/package versions, parsing
  status, reconciliation status, confidence, and evidence provenance in separate fields.
- `VersionRange` and vendor advisory range contracts are mechanical comparison inputs only. No
  OSV/NVD data is fetched, and no vulnerability or vendor backport verdict is made.

## Phase 2 probe invariants

- Targets must be absolute HTTP(S) URLs. They are canonicalized, fragments removed, and URL
  username/password credentials rejected.
- Resolve all DNS A/AAAA answers. With private access disabled, every answer must be globally
  routable; mixed public/private answers are rejected. Pin each connection to a checked address.
- Normalize and recheck every redirect against scheme, host allowlist, DNS, and IP policy before
  requesting it. Reject HTTPS-to-HTTP redirects.
- Bound total elapsed time, response bytes, and redirect count. Defaults are 10 seconds, 2 MiB,
  and 5 redirects. Private/reserved ranges are blocked by default; explicit private access is a
  trusted-deployment override.
- Cross-origin redirects remove Authorization, Cookie, and Proxy-Authorization. Response
  cookies are collected and never replayed automatically. HTTPS verification is never disabled.

## Phase 3 Evidence Engine invariants

- Collection is deterministic, synchronous, network-free, and consumes one normalized Phase 2
  `HttpResponse`. It does not modify the probe result or invoke other providers.
- Supported observations include response status/final URL/content metadata/headers/cookies,
  HTML metadata/generator/title, script/stylesheet/asset URLs, generic body structure markers,
  redirect chain, TLS metadata, connected/resolved addresses, and timing.
- Header names, cookie names, URLs, HTML attributes/entities, whitespace, and generic
  version-like strings are normalized deterministically. Headers are ordered lexically; HTML
  evidence follows document order; redirect and cookie arrays retain probe order.
- Evidence is never merged into a technology verdict. Conflicting observations remain separate.
  No fingerprint-specific patterns or technology hints are implemented.
- Cookie values/attributes, sensitive header and token-bearing meta values, and URL
  query/fragment/userinfo data are redacted or removed. Raw values are optional, sanitized, and
  capped at 512 characters. Each normalized value is bounded to 512 characters, or 2,048 for URL
  evidence.
- Default body inspection is capped at 512 KiB and cannot be configured above the Phase 2 2 MiB
  response limit. Output is capped at 512 evidence items (configurable up to 4,096). The report
  declares received/examined body bytes and both truncation flags.
- HTML parsing is a bounded passive tokenizer. It does not execute JavaScript, submit forms,
  follow links, crawl, brute-force paths, or parse technology-specific fingerprints.

## Phase 4 Fingerprint Engine invariants

- The engine consumes only an `EvidenceCollection` with schema version `1.0`. It has no transport,
  network, CLI, API-controller, cache, intelligence, or remediation dependencies.
- Fingerprint definitions are versioned data. They use validated literal `equals`, `contains`, and
  `prefix` match operators; no regular expressions or executable remote rules are accepted.
- Built-in definitions cover PHP, nginx, and Apache. Unknown evidence produces no detection.
  Conflicting or overlapping evidence remains visible in `contradictoryEvidence` and matched
  references; contradictory server signals reduce detection confidence.
- Detection confidence and version confidence are separate values. Independent signal weights use
  noisy-OR aggregation, duplicate hits for one signal do not raise confidence, and a lone signal is
  capped. Conflicting evidence is penalized. Confidence is a heuristic, not a probability.
- A version candidate can only come from a Phase 3 generic `versionHint` adjacent to the matching
  technology token in the same evidence value. No exact version is inferred from hidden, missing,
  conflicting, or unrelated version hints. All candidates retain evidence references.
- Header and generator signals account for spoofing, reverse proxies, CDNs, and stale self-reported
  values. A single header is not treated as unquestionable truth.
- Results are deterministically ordered and suitable for JSON, future CLI output, and Blueleaf API
  use. No vulnerability or remediation conclusions are made.

## Phase 5 Version Intelligence invariants

- The engine consumes `FingerprintResult` schema `1.0` only. It does not call probe, fingerprint,
  intelligence, cache, transport, CLI, or API-controller providers.
- `VersionStrategyRegistry` selects a technology-specific strategy or strict SemVer fallback.
  Strategies parse and compare within their own declared schemes; unknown technology IDs use only
  the generic SemVer strategy.
- Raw observed versions and evidence references are retained separately from normalized parsed
  upstream versions and vendor/distribution package revisions. Original token casing is recovered
  from Phase 4 evidence references where possible.
- Prereleases follow SemVer ordering for strategies that declare SemVer compatibility. Build
  metadata is preserved in normalized output and ignored for SemVer precedence. Missing components
  are `incomplete`; malformed, ambiguous, unsupported, and absent values remain explicit states.
- No vendor suffix or package revision is silently removed. Recognized package revisions retain
  their full raw string and parsed upstream portion separately. Unknown vendor formats remain
  `unsupported` or `ambiguous` and are not compared as upstream versions.
- Candidate reconciliation preserves every candidate and provenance. A selected upstream version is
  present only when all candidates parse and reconcile to the same normalized version.
- Range evaluation uses the selected strategy, treats `introduced` as inclusive, `fixed` as
  exclusive, and `lastAffected` as inclusive. It reports mechanical membership only. Distro package
  values yield `unknown` for upstream ranges because vendor backports are not evaluated.
- Contracts support future OSV/NVD range correlation and vendor/package backport inputs, but no
  advisory correlation, affected/fixed security verdict, or remediation is implemented.

## Phase 6 Live Intelligence invariants

- `NormalizedAdvisory` and `IntelligenceResult` use schema version `1.0`. The domain/application
  never consume OSV wire records; only the OSV infrastructure adapter validates and normalizes them.
- `OsvIntelligenceProvider` calls the official public OSV `query`, `querybatch`, and `vulns/{id}`
  endpoints. Batch IDs are hydrated to full advisory records. Pagination, retries, timeout, request,
  batch and result-size limits are bounded. No API key is accepted or logged.
- The resolver only uses package/ecosystem mappings explicitly registered by the composition root.
  No default mapping guesses package identity for PHP, nginx, or Apache. A mapping still requires a
  reconciled upstream version; vendor/distribution package values and unknown/conflicting versions
  return an explicit insufficient-data result.
- Unsupported mappings return `unsupported`; absent usable versions return `insufficient-data`.
  Partial provider retrieval is marked `partial`; malformed/provider failures throw typed errors and
  are never cached as successful empty responses.
- Advisory provenance records provider identity, retrieval timestamp, source modification timestamp,
  and record URL when available. Cache keys include schema version, source, ecosystem, package and
  version. Cache TTL is configurable and defaults to 300 seconds; malformed entries are deleted.
- OSV aliases are retained and used for deterministic duplicate merging. OSV ranges, explicit
  affected versions, fixed boundaries, severity, references, published/modified/withdrawn times are
  normalized as source data only. No range comparison, CVE correlation, confidence, security
  verdict, vendor backport evaluation, or remediation is performed.

## Scope

Phase 1 established the strict ESM project, shared service boundary, provider ports, config,
typed errors, result schema, tests, and documentation. Phase 2 added secure target resolution and
bounded HTTP/HTTPS probing. Phase 3 adds normalized, structured, passive evidence. Phase 4 maps
that evidence to confidence-scored PHP, nginx, and Apache detections. Phase 5 parses and reconciles
their version candidates. Phase 6 retrieves normalized OSV advisory data. Phase 7 adds bounded NVD
and official Ubuntu/Red Hat data with source-separated multi-source results. Phase 8 correlates
advisory applicability only under explicit package and version semantics. Phase 9 assesses confidence,
coverage, and per-target/per-technology/per-advisory states without declaring a target secure.

Explicitly excluded: automatic remote rule downloading, AI-generated rules, authoritative upstream
verification, GitHub Advisory integration, binary secure/insecure verdicts, automatic remediation
execution, crawling, port scanning, fuzzing, exploitation, persistence, user management, a database,
distributed quotas, and external monitoring. Phase 12 establishes application security controls but
does not claim infrastructure deployment is production ready. Do not add fake verdicts or scan data.

## Definition of done

- Strict typecheck, lint, tests, format check, and build pass.
- Phase 2 SSRF, TLS, redirect, timeout, and response-byte invariants remain enforced.
- Evidence output is deterministic, normalized, schema-versioned, and bounded.
- Sensitive cookie/header/URL data is redacted; raw snippets are bounded.
- Conflicting observations remain separate, and Phase 3 makes no technology or vulnerability
  verdicts.
- Fingerprint definitions validate against schema 1.0; engine output is deterministic and retains
  evidence provenance, separate detection/version confidence, contradictions, and version candidates.
- Version assessments and ranges validate against their schemas; comparisons are strategy-specific,
  deterministic, and preserve unsupported or conflicting states without guessing.
- OSV responses validate into normalized advisory/result contracts with provenance and bounded
  freshness; mappings are explicit, cache failures do not become successful empty results, and no
  vulnerability verdict or correlation is made.
- NVD CVE ID lookup and explicitly bounded modified-date synchronization normalize CVSS, CWE, CPE,
  status, references, and timestamps. No unbounded NVD dataset download or inferred package/CPE
  mapping is allowed; credentials remain injected secrets.
- Canonical Ubuntu OSV notice JSON and Red Hat Security Data CVE JSON remain source-specific
  normalized records. Unsupported sources (including PHP HTML bulletins without a stable documented
  machine interface) are documented without scraping.
- Multi-source results preserve each provider record independently, isolate provider failures, and
  distinguish empty, unavailable, partial, and unsupported information. Missing records never mean
  safe; Phase 7 itself makes no correlation or overall vulnerability verdict.
- Phase 9 confidence dimensions, freshness, and state transitions are deterministic from the
  supplied timestamp and inputs. `NO_KNOWN_VULNERABILITY` is scoped to requested providers and never
  means safe; unknown, partial, stale, and unavailable coverage remain explicit. Phase 9 does not
  provide remediation, exploitability, or a binary secure/insecure verdict.

## Phase 8 Correlation invariants

- `VulnerabilityCorrelationEngine` consumes Phase 4 detections, Phase 5 version assessments, and
  Phase 6/7 multi-source intelligence. It is a pure application service with stable schema `1.0`;
  input, package mapping, and output schemas live under `schemas/correlation-*.schema.json` and
  `schemas/technology-package-mapping.schema.json`.
- Package/ecosystem identity must come from an explicit `TechnologyPackageIdentityMapping` with
  authority, package identity, a registered Phase 5 strategy, and explicitly supported range types.
  No remote technology name implies package identity. Missing or ambiguous mappings produce
  `INSUFFICIENT_EVIDENCE`; unresolved versions produce `UNKNOWN`.
- OSV event boundaries are evaluated through the existing Phase 5 version engine. Introduced and
  last-affected bounds are inclusive; fixed and limit bounds are exclusive. Unsupported range types
  and malformed event streams remain explicit unknown/invalid evaluations.
- NVD CPE identity is used only with an exact configured vendor/product mapping; NVD CPE matches
  remain potential when environmental configuration conditions are unresolved.
- Vendor backport conclusions require an authoritative installed package identity with exact vendor,
  distribution, package, and revision, plus matching official vendor patch evidence. Upstream version
  comparisons never imply a vendor patch.
- Aliases group per-advisory results while every provider record, source ID, range, fixed version,
  severity, CPE, patch fact, and provenance remains traceable. Source conflicts are explicit;
  `PATCHED_BY_VENDOR` applies only to an exact installed vendor revision and preserves upstream
  evidence. Rejected/withdrawn records do not yield active range conclusions.
- Results express advisory applicability only. There is no overall security status, confidence
  aggregation, remediation, or inference of safety from missing/failed source data.

## Phase 9 Assessment invariants

- `SecurityAssessmentEngine` consumes Phase 4 detections, Phase 5 version assessments, Phase 6/7
  multi-source intelligence and Phase 8 correlations. It never changes correlation semantics or
  external provider behavior. Inputs include the exact explicit package mappings and caller-supplied
  `assessedAt`; no hidden clock or network dependency is used.
- Target, technology, and advisory states remain independently visible. Original Phase 8 results
  and source records remain embedded in per-advisory results. Detection confidence, version
  confidence, package identity, vulnerability applicability, advisory evidence quality, intelligence
  completeness, corroboration and contradiction penalty are separate dimensions. Corroboration
  requires caller-verified distinct source lineage groups; duplicate payloads remain one origin.
- Scores use the documented deterministic heuristic formula; duplicate evidence references,
  records, and aliases do not inflate scores. Corroboration counts only distinct recognized
  provenance authority classes; aggregator/unknown provenance is not independent support.
- `CONFIRMED_VULNERABLE` requires reliable detection and version, exact package mapping, active
  authoritative in-range evidence from Phase 8, complete fresh requested-source coverage, and the
  confidence threshold. `LIKELY_VULNERABLE` remains distinct. `PATCHED` requires a failed fixed
  boundary; `PATCHED_BY_VENDOR` requires Phase 8 exact vendor revision evidence.
- `NO_KNOWN_VULNERABILITY` is scoped to the supplied package/version and requested providers and
  never means secure. Missing, stale, partial, unsupported, or unavailable intelligence cannot
  support that state. Coverage, freshness, unsupported mappings and limitations are always exposed.
- An empty detection set is `TECHNOLOGY_UNKNOWN`. Target aggregation preserves the highest
  supported finding, while per-technology entries and conservative confidence retain other unknown
  or incomplete technologies. Phase 9 does not provide remediation, exploitability, or a binary
  secure/insecure verdict.
- Stable schema `1.0` contracts are in `src/domain/assessment.ts` and
  `schemas/security-assessment-input.schema.json` / `schemas/security-assessment-result.schema.json`.
  Formula, freshness limits, precedence and limitations are documented under `docs/`.

## Phase 10 Remediation invariants

- `RemediationEngine` consumes only supplied Phase 5 versions, Phase 8 correlations, Phase 9
  assessments, normalized advisory records, explicit package mappings, and optional caller-verified
  lifecycle facts. It is deterministic, performs no network work, and never changes security states.
- Advisory-level and technology-level plans preserve source records, fix statements, references,
  severity, confidence, and applicability separately. Severity is not exploitability; exploitability
  is serialized as `NOT_ASSESSED`.
- An upstream target requires a unique mapping, fresh complete coverage, reconciled upstream version,
  active authoritative source record, matching Phase 8 in-range evidence, and Phase 5 comparison
  using the mapping's exact strategy. Combined requirements are selected only if one candidate is
  proven to satisfy every included boundary using the same package mapping, strategy, and scheme.
- Vendor package updates and upstream fixes remain distinct. Vendor guidance requires an explicit
  vendor/distribution/package mapping and official vendor release evidence; it includes no fabricated
  command. Backport conclusions remain Phase 8 results and do not change Phase 9.
- Unknown versions or status, ambiguous identity, stale/partial intelligence, conflicts, missing
  fixed-version evidence, and unsupported semantics cannot produce a guessed upgrade. EOL and a
  migration path are reported only from fresh caller-verified lifecycle facts with HTTPS references.
- Contracts are in `src/domain/remediation.ts`, the engine is in
  `src/application/remediation/remediation-engine.ts`, and the stable Draft 2020-12 schema is
  `schemas/remediation-plan.schema.json`. See `docs/remediation.md` for precedence, priority,
  limitations, and administrator verification requirements.

## Phase 11 CLI and API invariants

- `ScanApplicationService` is the single orchestration boundary for probe, evidence, fingerprint,
  version, intelligence, correlation, assessment, and remediation stages. The CLI and HTTP API only
  adapt inputs/outputs and never duplicate stage logic. Dependencies are injected through the
  composition root; tests may substitute providers and clocks.
- New `ScanRequest` and `ScanResult` use schema version `1.0` without changing `IdentificationResult`
  or any Phase 1–10 schema. The public probe summary deliberately excludes raw headers, cookies,
  and response body. Target and redirect URLs omit credentials, query, and fragment values.
- CLI syntax is `scan <http(s)-url> [--json]`, plus `--help` and `--version`. Exit codes distinguish
  complete (0), partial/uncertain (1), invalid/policy rejected (2), and operational failure (3).
  No other scan options are supported.
- `POST /v1/scans` validates `ScanRequest` 1.0 and returns the same `ScanResult` as the CLI service.
  `GET /health` and `GET /ready` do not scan or call intelligence providers. API errors use the
  versioned `ApiErrorEnvelope` and never disclose stack traces, paths, secrets, or raw headers.
- API defaults to `127.0.0.1:8787`; external binding requires explicit Phase 12 ingress settings.
  Request size, deadline, and concurrent scans are bounded.
- Both interfaces invoke only the injected Phase 2 `HttpProvider`. No alternative HTTP request path
  exists for target probing. DNS checks, address policy, IP pinning, redirect revalidation, TLS
  verification, and Phase 2 bounds remain mandatory.
- Environment variables are read only by the explicit runtime configuration boundary. NVD keys are
  passed to the existing provider through configuration and are excluded from results and errors.
- Scans are passive and bounded. Use only against systems you own or are authorized to assess.
  Unknown, partial, stale, conflicting, or unavailable results never imply target safety.
- Schemas are `schemas/scan-request.schema.json`, `schemas/scan-result.schema.json`, and
  `schemas/api-error.schema.json`. CLI and endpoint usage is documented in `docs/cli.md` and
  `docs/api.md`; environment settings are documented in `docs/configuration.md`.

## Phase 12 runtime security invariants

- Scan and protected health/readiness routes require `Authorization: Bearer` credentials from the
  explicit `BLUELEAF_API_KEYS_JSON` secret boundary. Tokens are hashed to fixed-size digests and
  compared with `timingSafeEqual`; disabled and expired credentials are rejected identically.
- Health/readiness are protected by default. `BLUELEAF_API_PUBLIC_HEALTH=true` exposes only
  liveness/readiness, and does not authorize scans. Credentials are never logged or returned.
- Authenticated scans use a bounded fixed-window per-identity rate limiter, per-identity concurrency
  caps, and a global concurrency cap. Authentication failures use a bounded client-address fallback
  limiter. Buckets are capped and fail closed when full. All limits are process-local and reset on
  restart; they are not distributed quotas.
- Request bytes, request receive time, scan deadline, response bytes, concurrent work, credentials,
  CORS origins, trusted proxies, and rate buckets are bounded. Client disconnect and deadline
  cancellation reach the secure Phase 2 probe and supported advisory fetch providers. OS-level DNS
  resolution may finish after cancellation, but the cancelled pipeline will not open a target
  connection after the resolution boundary.
- External binding requires explicit opt-in, TLS termination, active API credentials, and exact
  trusted proxy IPs. Requests must arrive from an allowlisted proxy. `X-Forwarded-For` is ignored
  from untrusted peers; the ingress must overwrite or append the client chain correctly. CORS uses
  exact allowlisted HTTP(S) origins only and is disabled by default.
- Responses include request IDs and restrictive JSON security headers. Structured events cover
  authentication/origin/proxy/rate rejection, invalid requests, target rejection, scan failure or
  cancellation, and shutdown. Logs contain bounded event codes, request IDs, and configured identity
  labels only; they omit URLs, client addresses, headers, cookies, payloads, and credentials.
- Graceful shutdown stops new scans, aborts active scan signals, waits for the configured grace
  period, then closes remaining connections. No user database, distributed limiter, external
  monitoring service, or abuse analytics backend is included. See `docs/deployment.md` for ingress
  and operational limits.

## Phase 13 release-readiness invariants

- Release validation inspects the package manifest, compiled ESM output, public exports, CLI
  executable, schemas, files allowlist, and package contents. The package is publishable in
  principle, but no registry publication or GitHub release is performed by this phase.
- All published JSON Schemas compile and their references resolve. CLI and HTTP scan responses are
  checked against `ScanResult` schema 1.0; structured API errors are checked against
  `ApiErrorEnvelope` schema 1.0.
- The compiled `blueleaf` wrapper invokes the same `runCli` and shared scan service. Human/JSON
  behavior remains bounded and does not reveal sensitive probe material.
- The default in-memory intelligence cache is bounded to 2,000 entries and 32 MiB of serialized
  keys/values. `BLUELEAF_CACHE_MAX_ENTRIES` and `BLUELEAF_CACHE_MAX_BYTES` remain within hard
  configuration bounds. Oversized values are not cached; LRU eviction maintains the cap.
- End-to-end and security tests use fixtures and local listeners. Real targets are scanned only
  after the owner supplies and confirms authorization. Fixture success does not remove known
  coverage and infrastructure limitations.
