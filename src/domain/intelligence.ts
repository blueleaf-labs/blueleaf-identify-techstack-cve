import type { VersionComparisonOperator } from "./versions.js";

export interface AdvisoryPackage {
  readonly ecosystem: string;
  readonly name: string;
}

export interface AdvisoryRangeEvent {
  readonly introduced?: string;
  readonly fixed?: string;
  readonly lastAffected?: string;
  readonly limit?: string;
}

export interface AdvisoryVersionRange {
  readonly type: string;
  readonly events: readonly AdvisoryRangeEvent[];
  readonly repository?: string;
}

export interface AdvisoryAffectedPackage {
  readonly package: AdvisoryPackage;
  readonly ranges: readonly AdvisoryVersionRange[];
  readonly explicitVersions: readonly string[];
  readonly fixedVersions: readonly string[];
}

export interface AdvisorySeverity {
  readonly type: string;
  readonly score: string;
  readonly severity?: string;
  readonly vector?: string;
}

export interface AdvisoryReference {
  readonly type?: string;
  readonly url: string;
  readonly tags?: readonly string[];
}

export interface AdvisoryCpeMatch {
  readonly criteria: string;
  readonly vulnerable?: boolean;
  readonly matchCriteriaId?: string;
  readonly versionStartIncluding?: string;
  readonly versionStartExcluding?: string;
  readonly versionEndIncluding?: string;
  readonly versionEndExcluding?: string;
}

export interface AdvisoryCpeNode {
  readonly operator?: string;
  readonly negate?: boolean;
  readonly matches: readonly AdvisoryCpeMatch[];
  readonly nodes: readonly AdvisoryCpeNode[];
}

export interface AdvisoryCpeConfiguration {
  readonly operator?: string;
  readonly negate?: boolean;
  readonly nodes: readonly AdvisoryCpeNode[];
}

export interface VendorPackageInformation {
  readonly providerId: string;
  readonly recordType?: "affected-release" | "package-state";
  readonly productName?: string;
  readonly packageName?: string;
  readonly packageVersion?: string;
  readonly cpe?: string;
  readonly advisoryId?: string;
  readonly releaseDate?: string;
  readonly fixState?: string;
  readonly upstreamFix?: string;
}

export type AdvisoryRecordStatus = "active" | "rejected" | "withdrawn" | "unknown";

export interface AdvisoryProvenance {
  readonly providerId: string;
  readonly authority?: "primary" | "vendor" | "aggregator" | "unknown";
  readonly originalIdentifier?: string;
  readonly recordUrl?: string;
  readonly retrievedAt: string;
  readonly sourceModifiedAt?: string;
}

/** Provider-independent advisory data. Range data is descriptive; no version correlation is implied. */
export interface NormalizedAdvisory {
  readonly id: string;
  readonly aliases: readonly string[];
  readonly summary?: string;
  readonly details?: string;
  readonly affectedPackages: readonly AdvisoryAffectedPackage[];
  readonly severity: readonly AdvisorySeverity[];
  readonly references: readonly AdvisoryReference[];
  readonly publishedAt?: string;
  readonly modifiedAt?: string;
  readonly withdrawnAt?: string;
  readonly recordStatus?: AdvisoryRecordStatus;
  readonly relatedIdentifiers?: readonly string[];
  readonly cweIds?: readonly string[];
  readonly cpeConfigurations?: readonly AdvisoryCpeConfiguration[];
  readonly vendorPackageInformation?: readonly VendorPackageInformation[];
  readonly provenance: AdvisoryProvenance;
}

export interface AdvisoryPackageQuery extends AdvisoryPackage {
  readonly version: string;
}

export type IntelligenceResultStatus =
  "resolved" | "no-advisories" | "partial" | "unsupported" | "insufficient-data";

export interface IntelligenceResult {
  readonly schemaVersion: "1.0";
  readonly status: IntelligenceResultStatus;
  readonly providerIds: readonly string[];
  readonly queries: readonly AdvisoryPackageQuery[];
  readonly advisories: readonly NormalizedAdvisory[];
  readonly retrievedAt: string;
  readonly sourceModifiedAt?: string;
  readonly diagnostics: readonly string[];
}

export type MultiSourceIntelligenceStatus =
  | "RESULTS"
  | "NO_RESULTS"
  | "PROVIDER_UNAVAILABLE"
  | "PARTIAL_RESULTS"
  | "INTELLIGENCE_UNAVAILABLE";

export type IntelligenceSourceStatus =
  "RESULTS" | "NO_RESULTS" | "PARTIAL_RESULTS" | "PROVIDER_UNAVAILABLE" | "UNSUPPORTED";

export type MultiSourceIntelligenceRequest =
  | {
      readonly kind: "package-version-batch";
      readonly queries: readonly AdvisoryPackageQuery[];
    }
  | { readonly kind: "advisory-id"; readonly id: string };

export interface IntelligenceSourceResult {
  readonly providerId: string;
  readonly status: IntelligenceSourceStatus;
  readonly advisories: readonly NormalizedAdvisory[];
  readonly retrievedAt?: string;
  readonly sourceModifiedAt?: string;
  readonly diagnostics: readonly string[];
}

/** Source-separated result; records from disagreeing providers are never merged together. */
export interface MultiSourceIntelligenceResult {
  readonly schemaVersion: "1.0";
  readonly request: MultiSourceIntelligenceRequest;
  readonly status: MultiSourceIntelligenceStatus;
  readonly sourceResults: readonly IntelligenceSourceResult[];
  readonly advisories: readonly NormalizedAdvisory[];
  readonly retrievedAt: string;
  readonly diagnostics: readonly string[];
}

/** Standalone comparison input retained for API compatibility; Phase 8 uses versioned correlation contracts. */
export interface AdvisoryRangeComparisonInput {
  readonly package: AdvisoryPackage;
  readonly version: string;
  readonly operator: VersionComparisonOperator;
  readonly boundary: string;
}
