import type { EvidenceReference } from "./fingerprints.js";

export type VersionParsingStatus =
  "parsed" | "incomplete" | "ambiguous" | "malformed" | "unsupported" | "unknown";

export type VersionComparisonOperator = "<" | "<=" | "=" | "==" | "!=" | ">=" | ">";

export interface VersionComponents {
  readonly major: number;
  readonly minor?: number;
  readonly patch?: number;
}

/** A successfully parsed upstream version; build metadata is retained but ignored for ordering. */
export interface ParsedUpstreamVersion {
  readonly scheme: string;
  readonly normalized: string;
  readonly components: VersionComponents;
  readonly prerelease?: readonly (string | number)[];
  readonly build?: readonly string[];
}

/** Vendor or distribution package data is retained separately from upstream version semantics. */
export interface VendorPackageVersion {
  readonly rawValue: string;
  readonly upstreamValue: string;
  readonly vendor?: string;
  readonly distribution?: string;
  readonly epoch?: number;
  readonly revision: string;
}

export interface ObservedVersion {
  /** Exact candidate text recovered from evidence provenance where possible. */
  readonly rawValue: string;
  /** Phase 4's normalized version candidate. */
  readonly candidateValue: string;
  readonly confidence: number;
  readonly evidenceReferences: readonly EvidenceReference[];
}

export interface VersionCandidateAssessment {
  readonly rawObservedVersion: string;
  readonly strategyId?: string;
  readonly parsingStatus: VersionParsingStatus;
  readonly parsedUpstreamVersion?: ParsedUpstreamVersion;
  readonly partialUpstreamComponents?: VersionComponents;
  readonly vendorPackageVersion?: VendorPackageVersion;
  readonly reason: string;
  readonly evidenceReferences: readonly EvidenceReference[];
}

export type VersionReconciliationStatus =
  "single" | "corroborated" | "conflicting" | "ambiguous" | "unavailable";

export interface VersionAssessment {
  readonly technologyId: string;
  readonly displayName: string;
  readonly category: string;
  /** Confidence reported by Phase 4 for version evidence, kept separate from parsing status. */
  readonly versionConfidence: number;
  readonly parsingStatus: VersionParsingStatus;
  readonly reconciliationStatus: VersionReconciliationStatus;
  readonly rawObservedVersions: readonly ObservedVersion[];
  readonly parsedUpstreamVersions: readonly ParsedUpstreamVersion[];
  readonly vendorPackageVersions: readonly VendorPackageVersion[];
  readonly candidateAssessments: readonly VersionCandidateAssessment[];
  /** Present only when all observed candidates reconcile to one parsed upstream version. */
  readonly selectedUpstreamVersion?: ParsedUpstreamVersion;
}

/** Stable, versioned JSON payload for future CLI and Blueleaf API consumers. */
export interface VersionAssessmentCollection {
  readonly schemaVersion: "1.0";
  readonly fingerprintSchemaVersion: "1.0";
  readonly assessments: readonly VersionAssessment[];
}

export interface VersionParseResult {
  readonly status: VersionParsingStatus;
  readonly parsedUpstreamVersion?: ParsedUpstreamVersion;
  readonly partialUpstreamComponents?: VersionComponents;
  readonly vendorPackageVersion?: VendorPackageVersion;
  readonly reason: string;
}

export interface VersionComparisonConstraint {
  readonly operator: VersionComparisonOperator;
  readonly version: string;
}

/** Advisory-shaped range contract: fixed is exclusive; lastAffected is inclusive. */
export interface VersionRange {
  readonly introduced?: string;
  readonly fixed?: string;
  readonly lastAffected?: string;
  /** Optional NVD-style constraints; every constraint must hold. */
  readonly constraints?: readonly VersionComparisonConstraint[];
}

export type VersionRangeStatus = "within" | "outside" | "unknown" | "invalid-range";

export interface VersionRangeEvaluation {
  readonly status: VersionRangeStatus;
  readonly strategyId: string;
  readonly rawVersion: string;
  readonly reason: string;
  readonly comparisons: readonly {
    readonly operator: VersionComparisonOperator;
    readonly boundary: string;
    readonly matched?: boolean;
  }[];
}

/** Future advisory adapters can preserve package-specific ranges without applying upstream SemVer. */
export interface VendorAdvisoryRange extends VersionRange {
  readonly ecosystem: string;
  readonly packageName: string;
  readonly vendor?: string;
  readonly distribution?: string;
}

export type VendorBackportStatus =
  "not-evaluated" | "fixed-by-vendor" | "affected-by-vendor" | "unknown";

/** Contract only in Phase 5; no advisory or vendor backport data is queried. */
export interface VendorBackportAssessment {
  readonly status: VendorBackportStatus;
  readonly packageVersion: VendorPackageVersion;
  readonly advisoryRange: VendorAdvisoryRange;
  readonly reason: string;
}
