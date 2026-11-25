# Vulnerability correlation (Phase 8)

`VulnerabilityCorrelationEngine` consumes Phase 4 `TechnologyDetection` values, Phase 5
`VersionAssessmentCollection`, and Phase 6/7 `MultiSourceIntelligenceResult` values. It is a pure
application service. It does not fetch advisories or produce an overall target security status.
The stable result is schema `1.0` in `schemas/correlation-result.schema.json`; callers can validate
the full input against `schemas/correlation-input.schema.json` and individual mappings against
`schemas/technology-package-mapping.schema.json`.

## Explicit identity is required

The caller must provide `TechnologyPackageIdentityMapping` records that name the exact technology
ID, package ecosystem and package name, mapping authority, Phase 5 strategy ID, and the source range
types verified for that strategy. Package names are exact-match identities; ecosystem names are
case-insensitive. There are no inferred mappings for PHP, nginx, Apache, or other detections. More
than one mapping for one technology is ambiguous and returns `INSUFFICIENT_EVIDENCE`. Unknown or
ambiguous Phase 5 versions return `UNKNOWN`; a strategy mismatch or missing package mapping is
insufficient evidence.

For vendor-specific mappings, `vendor` names the advisory source identity (for example `redhat`),
while `distribution` names the installed distribution. The separate `cpe.vendor` field names the
software vendor component in the CPE identity.

An optional `InstalledPackageIdentity` is separate from the observed upstream version. Vendor patch
conclusions require an exact package revision from an `authoritative-inventory`, exact mapping ID,
ecosystem/package, vendor, distribution, and source record identifiers. A version-like HTTP header
or upstream version alone cannot establish installed distribution package identity.

## Range rules

OSV `SEMVER` and `ECOSYSTEM` ranges are evaluated only when the mapping explicitly registers that
range type for its Phase 5 strategy. No generic SemVer fallback is selected by the correlation
engine. Unsupported range types, malformed event streams, unknown versions, package revisions
without vendor semantics, and missing range data remain unknown. `introduced` is inclusive, `fixed`
exclusive, `last_affected` inclusive, and `limit` exclusive. A stream may contain multiple
introduced/closing event pairs. Exact OSV affected-version entries use the same mapped strategy.
NVD CPE ranges require an exact mapped CPE vendor/product and use the mapped strategy. A matching
NVD CPE result is `POTENTIALLY_AFFECTED` because environmental configuration logic is preserved but
not fully evaluated.

## Source reconciliation

Records are grouped for display by CVE ID and aliases, but original records are retained verbatim in
`sourceRecords`, with source IDs, severity values, fixed versions, range data, CPEs, vendor package
records, and provenance intact. Source duplicates are removed only when both provider and complete
record payload are identical. Range evaluations retain provider/advisory IDs and Phase 5 evidence
references.

Active source records that produce both positive and negative applicability evidence yield
`CONFLICTING_EVIDENCE`. When an authoritative vendor record for the exact installed vendor package
and distribution revision identifies that exact revision in an `affected-release` entry, that
explicit vendor fix evidence yields `PATCHED_BY_VENDOR`; upstream affected ranges remain in the
result and are described as upstream/vendor evidence. Red Hat `Not affected` or `Affected` package
state is used only when the package name and mapped CPE match, the vendor source is the mapped vendor,
and an exact authoritative installed package identity was supplied. A generic fixed version or
advisory lookup alone never proves a package is patched.

Rejected and withdrawn records are retained and produce no active range conclusion. `NOT_AFFECTED`
means only that evaluated source ranges or explicit package state did not apply to the mapped
package/version. `NO_RESULTS`, unavailable providers, partial retrieval, and absent source records
never mean safe. Results describe each advisory's applicability only; the engine has no aggregate
security status, confidence score, correlation verdict, or remediation advice.
