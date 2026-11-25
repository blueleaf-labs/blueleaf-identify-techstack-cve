# Live advisory intelligence

Phase 6 adds a normalized advisory provider boundary and an official OSV API adapter. The
`IntelligenceResolverService` is transport independent and invoked by the shared scan application
service. The CLI and Blueleaf API do not implement their own provider or cache behavior.
`NormalizedAdvisory` and
`IntelligenceResult` are stable schema `1.0` contracts in `src/domain/intelligence.ts`, with the
result shape described by `schemas/intelligence-result.schema.json`.

## Queries and mappings

Call `resolveQueries` with an explicit ecosystem, package name, and upstream version, or call
`resolveAssessments` with Phase 5 output and register exact `TechnologyPackageMapping` values at the
composition boundary. There are intentionally no default mappings for PHP, nginx, or Apache:
technology identity alone does not determine whether the installed package came from upstream,
Composer, Debian, Ubuntu, Fedora, RHEL, a container, or another package source. Do not map a distro
package revision to an upstream OSV version. Unknown, conflicting, absent, and vendor/package-only
versions produce `insufficient-data`; unmapped technologies produce `unsupported`.

The resolver supports registered `AdvisoryIntelligenceProvider` implementations. OSV supports package/version queries (`/v1/query`), batch package/version queries
(`/v1/querybatch`), and advisory ID lookups (`/v1/vulns/{id}`). Batch results contain IDs, so the
provider fetches full records before returning normalized advisories. Paginated results are bounded
by configured page limits. Partial hydration/page-limit failures are returned with `partial` status
and diagnostics.

## Phase 7 sources and multi-source retrieval

Phase 7 adds `NvdIntelligenceProvider`, `UbuntuSecurityAdvisoryProvider`, and
`RedHatSecurityAdvisoryProvider`. They return the same `NormalizedAdvisory` contract. The
multi-source resolver methods `lookupMultiSourceAdvisory` and `resolveMultiSourceQueries` return a
source-separated `MultiSourceIntelligenceResult` (`schemas/multi-source-intelligence-result.schema.json`).
Records from different providers are never merged, even when their CVE IDs or aliases overlap.
This preserves disagreements in ranges, severity, CPEs, and vendor patch information for later
review. Duplicate IDs and aliases are coalesced only within one provider.

NVD uses the [official CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) for CVE ID lookups and explicit modified-date windows. Date
synchronization requires timezone-qualified endpoints, caps windows at 120 days, and bounds page
size and page count. It does not perform a full-dataset download. NVD package queries are marked
unsupported because technology names do not provide authoritative CPE identities. An optional
NVD API key is injected through configuration and sent only in the `apiKey` request header.

Canonical Ubuntu security notices are fetched as OSV JSON records using the documented
[Ubuntu OSV guidance](https://documentation.ubuntu.com/security/security-updates/osv/) and the
official [`canonical/ubuntu-security-notices` repository](https://github.com/canonical/ubuntu-security-notices).
CVE aliases are converted to Canonical's documented `UBUNTU-CVE` record identity; USN and LSN
identifiers are also accepted. Red Hat records use the documented [Security Data API](https://docs.redhat.com/en/documentation/red_hat_security_data_api/1.0/security_data_api-security_data_api_overview)
[CVE endpoint](https://docs.redhat.com/en/documentation/red_hat_security_data_api/1.0/security_data_api-cve)
and retain vendor package state, affected release, CPE, errata, and upstream fix fields. Both
providers support ID lookup only; neither invents a package query mapping. The official [PHP security
bulletins](https://www.php.net/security/) do not provide a stable documented machine-readable
advisory API, so PHP vendor advisories remain unsupported/manual; no HTML scraping is used. GitHub
Advisory and other vendor providers are not yet implemented.

The source outcome values distinguish `NO_RESULTS`, `PROVIDER_UNAVAILABLE`, `PARTIAL_RESULTS`, and
`INTELLIGENCE_UNAVAILABLE`. Empty data never means that a version is safe. Failure diagnostics are
sanitized and do not contain request headers, API keys, or raw provider records. The multi-source
cache is partitioned by schema version, provider ID, and exact request; only complete successful
responses are cached. The source record retains `retrievedAt`, `sourceModifiedAt`, authority,
original identifier, and record URL separately.

Source authority is descriptive metadata: NVD records are primary CVE data, while Ubuntu and Red Hat
records are vendor-maintained advisories. The resolver does not rank or reconcile them. NVD may
have CPE configurations that differ from vendor package states, and vendor advisories may describe
backports not expressible as upstream semantic versions. Those differences remain visible.

## Normalized data and limitations

The adapter preserves advisory IDs and aliases, summaries/details, affected ecosystem/package
names, explicit affected versions, version range event boundaries, fixed-event versions, severity
strings, references, published/modified/withdrawn timestamps, and OSV provenance. `retrievedAt`
states when this provider fetched the record; `sourceModifiedAt` comes from the source record.
Withdrawn records are retained and marked, not silently omitted. Duplicate IDs and aliases are
merged deterministically.

Advisory ranges are source data only. Phase 6 does not correlate an assessed version with ranges,
decide whether a product is vulnerable, normalize severity into a risk score, check vendor
backports, recommend fixes, or claim that an empty query proves safety. OSV coverage and package
ecosystem semantics vary by upstream source; users must provide a verified package mapping.

## Cache and provider bounds

The existing cache abstraction stores only successful normalized results. Keys include schema
version, source ID, ecosystem, package name, and exact version. TTL defaults to 300 seconds and is
configurable in `IntelligenceResolverService`; cache records retain provider retrieval and source
modification timestamps. The default process-local memory cache is capped at 2,000 entries and
32 MiB of serialized key/value bytes. `BLUELEAF_CACHE_MAX_ENTRIES` and
`BLUELEAF_CACHE_MAX_BYTES` adjust these bounded limits. Oversized individual values are returned
to the current request but not retained; least-recently-used entries are evicted to admit new
values. Malformed cache records are deleted. Cache read/write failures are best-effort and do not
convert failed provider calls into empty successes.

The OSV provider uses HTTPS to `api.osv.dev`, has no API key, and accepts no credentials. Defaults
are a 5-second timeout, two retries, 100 queries per batch, five pages, and at most 500 hydrated
advisories per batch; response bodies are capped at 8 MiB. Retries are bounded and honor a capped
`Retry-After` for 429/503. Provider failures return typed, sanitized errors; callers must avoid
logging request payloads or raw external records. The adapter has no live internet dependency in
automated tests.

## Extending providers

Implement `AdvisoryIntelligenceProvider` and return `NormalizedAdvisory` records with source
identity, retrieval time, optional source modification time, and provenance. Keep provider wire
models inside the adapter. Register providers and explicit package mappings through composition;
do not add guessed mappings or adjudication logic to the resolver. Add mock-only tests for response
validation, error modes, partial retrieval, cache behavior, and deterministic normalization.

Phase 8 correlation consumes source-separated results and preserves each record, severity, range,
fixed boundary, CPE, and vendor package record. It applies only explicit package mappings and
registered Phase 5 version strategies. See [`docs/correlation.md`](correlation.md) for applicability
and source reconciliation rules.
