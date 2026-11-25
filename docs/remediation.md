# Remediation Engine (Phase 10)

`RemediationEngine.plan` is a deterministic application service over supplied Phase 5 version
assessments, Phase 8 correlations, Phase 9 security assessments, normalized Phase 6/7 advisory
records, explicit package mappings, and optional caller-verified lifecycle facts. It performs no
network requests, package-manager operations, or changes to the earlier assessment results.

The versioned JSON result is `schemas/remediation-plan.schema.json`; TypeScript contracts live in
`src/domain/remediation.ts`. The public package exports `RemediationEngine`, its options, and all
stable remediation contracts.

## States and precedence

Each technology and advisory remains visible. `PATCH_ALREADY_APPLIED` copies Phase 9's advisory
`PATCHED` or `PATCHED_BY_VENDOR` conclusion. `NO_ACTION_IDENTIFIED` means only that Phase 9 found no
applicable finding in the supplied coverage or all matched records are explicitly rejected or
withdrawn; it is not a safety claim. `REMEDIATION_UNAVAILABLE` preserves unavailable intelligence.
Unknown identity/version, incomplete or stale coverage, unknown advisory status, conflicting source
evidence, potential applicability, or unsupported semantics lead to `MANUAL_REVIEW_REQUIRED`.

For an active affected record, `UPGRADE_RECOMMENDED` requires a unique exact mapping, complete fresh
Phase 9 coverage, a reconciled upstream version, an authoritative active source, a matching Phase 8
in-range record/package/range assessment, and a fixed boundary accepted by that mapping's registered
Phase 5 version strategy. If the finding is established but the source provides no usable fix,
`ACTION_REQUIRED` requests administrator review without inventing a release. Distribution-specific
packages require matching official vendor update evidence; the engine never substitutes an upstream
version for a vendor package revision.

## Fixed version selection

Per-advisory fixed values, source IDs, references, authority, and eligibility reasons are retained.
Candidates are parsed only through the explicit mapping's Phase 5 strategy. Incomplete, vendor or
distribution suffixed, malformed, ambiguous, or strategy-unsupported versions are not used as
upstream targets. When several advisory requirements affect the same exact component, the engine
selects the least supplied candidate that Phase 5 proves satisfies every requirement under the same
strategy and scheme. If no candidate proves all boundaries, the combined target is omitted and
manual review is required. It never sorts arbitrary version strings or compares package revisions
as upstream versions.

Official vendor package release values are kept separate from upstream fixes. A vendor update plan
requires explicit mapping vendor and distribution, exact package name, matching provider authority,
and an official vendor `affected-release` record. It contains general update guidance only and
requires administrator verification. No shell or package-manager command is generated. Vendor
backport conclusions remain Phase 8 results; a release record here does not rewrite Phase 9 state.

NVD CPE upper bounds are preserved as evidence but cannot independently create an upgrade target
because Phase 8 does not establish all environmental configuration conditions from a CPE record.

## Priority, lifecycle, and limitations

Priority is separate from severity, exploitability, confidence, and remediation state. Critical
confirmed findings map to P0; high confirmed findings to P1; medium and low confirmed findings to P2
and P3. Likely findings are capped at P1. Uncertain findings use `REVIEW`; patched/no-action plans
use `NONE`. Severity is never described as exploitability; exploitability is explicitly
`NOT_ASSESSED`.

Lifecycle is not inferred from product age or version. An optional lifecycle record must be marked
verified by its caller, match the exact technology and package mapping, have an HTTPS reference, and
be within the configured freshness window (365 days by default). EOL is reported separately from
advisory fixes. A migration path is included only when that exact authoritative record supplies a
referenced path. The engine does not invent supported versions or migration destinations.

All source provenance, conflicting values, stale/partial coverage, unknown states, and explanation
strings remain available to clients. Recommendations are guidance from caller-supplied records;
operators must validate installed package identity, repositories, compatibility, backups, and
deployment procedures before changes. A missing plan or advisory is not evidence of safety.
