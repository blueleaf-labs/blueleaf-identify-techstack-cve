# Version intelligence

`VersionIntelligenceEngine.assess(FingerprintResult)` consumes only the versioned Phase 4 result and
returns a `VersionAssessmentCollection` consumed by the shared scan workflow and serialized by the
CLI and Blueleaf API.
The engine has no network, HTTP, CLI, API-controller, cache, or intelligence dependencies. Stable
contracts are defined in `src/domain/versions.ts` and documented by
`schemas/version-assessment.schema.json` and `schemas/version-range.schema.json`.
The mechanical range evaluator response schema is
`schemas/version-range-evaluation.schema.json`.

## Assessment fields

Each technology assessment keeps these data separate:

- `rawObservedVersions`: source candidate strings recovered from Phase 4 evidence, their original
  evidence references, and Phase 4 candidate confidence.
- `parsedUpstreamVersions`: normalized versions parsed by a named strategy. A selected upstream
  value appears only if every observed candidate parses and all parsed values reconcile exactly.
- `vendorPackageVersions`: full package strings plus any safely recognized upstream component,
  distribution, epoch, and package revision. The suffix remains available and is never silently
  discarded.
- `versionConfidence`: Phase 4's confidence in the presence of version evidence. It does not change
  because a string parsed successfully.
- `parsingStatus`: `parsed`, `incomplete`, `ambiguous`, `malformed`, `unsupported`, or `unknown`.
  `reconciliationStatus` separately reports a single value, corroboration, conflict, ambiguity, or
  absence.
- `candidateAssessments`: one explanation and provenance record per recovered raw candidate.

## Strategies and supported formats

`VersionStrategyRegistry` selects one technology-specific parser/comparator or its strict generic
SemVer fallback. The default strategies cover PHP, nginx, and Apache. New ecosystem behavior belongs
in a separately registered `VersionStrategy`; the generic assessment engine does not contain
technology-specific parsing branches.

The built-in parser accepts complete semantic versions with prerelease/build identifiers. PHP also
accepts compact `RC`, `alpha`, and `beta` release forms such as `8.3.0RC1`. Incomplete forms such as
`8.2` retain their available components and are not comparable. Leading-zero components and invalid
SemVer identifiers are malformed. Unknown strings and vendor suffixes that the strategy cannot
recognize are unsupported. Numeric revision endings that could mean either a prerelease or a package
revision are ambiguous.

Known Debian/Ubuntu/Fedora/RHEL-family revision forms retain the complete package value and parsed
upstream part independently. For example, `1.22.1-9+deb12u3` records upstream `1.22.1` and a Debian
revision `9+deb12u3`. This is parsing only; it does not establish whether a distribution backported a
fix. Other suffixes are not stripped or guessed.

## Comparison and ranges

`VersionIntelligenceEngine.compare(technologyId, left, operator, right)` supports `<`, `<=`, `=`,
`==`, `!=`, `>=`, and `>`. Parsing failures and unhandled vendor/package ordering return `unknown`.
For SemVer, numeric components compare numerically; prereleases sort before the corresponding stable
release; numeric prerelease identifiers sort numerically and before non-numeric identifiers. Build
metadata is retained in output and ignored for precedence.

`evaluateRange` supports OSV-like event bounds with inclusive `introduced`, exclusive `fixed`, and
inclusive `lastAffected`, plus conjunctive NVD-style comparison constraints. `introduced: "0"` is
the open lower-bound sentinel. The return value says only whether a parseable upstream value is
within/outside the supplied range. It is not an affected/fixed security verdict. Vendor package
versions return `unknown` against upstream-only ranges. The `VendorAdvisoryRange` and
`VendorBackportAssessment` contracts reserve package/vendor identity for future vendor-specific
correlation; no backport evaluation or OSV/NVD query is implemented.

## Candidate reconciliation

Every Phase 4 version candidate and evidence reference is retained. Original casing is recovered by
matching the candidate against the source evidence value where possible. Equivalent normalized
upstream versions can be corroborated; different parsed versions are conflicting; any mixture of
parsed and unparsed values is ambiguous. Conflicting, ambiguous, incomplete, malformed, unsupported,
or missing candidates do not produce a selected upstream version. Output ordering is lexical and
stable for identical versioned input.

## Adding a strategy

Implement the exported `VersionStrategy` contract with a stable strategy ID, technology IDs, parser,
and comparator. Register it alongside the required generic `semver` fallback in
`VersionStrategyRegistry`. Keep the parser conservative: preserve the source spelling and vendor
metadata, and return an explicit non-parsed status whenever a format cannot be interpreted safely.
Add parsing, comparison, range-boundary, provenance, and deterministic-output tests. Do not add
network fetching, advisory logic, AI-generated parsers, CVE verdicts, or remediation behavior.

Phase 8 correlation calls `VersionIntelligenceEngine` using the explicit strategy ID in a
technology-to-package mapping. A range is evaluated only if that mapping declares the source range
encoding supported for the strategy. Vendor/distribution package revisions remain separate and
prevent upstream-only comparisons from implying a vendor patch or safe status. See
[`docs/correlation.md`](correlation.md) for event boundaries and source reconciliation.
