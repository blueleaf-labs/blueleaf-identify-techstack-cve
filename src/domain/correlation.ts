import type { EvidenceReference, TechnologyDetection } from "./fingerprints.js";
import type {
  AdvisoryPackage,
  AdvisorySeverity,
  MultiSourceIntelligenceResult,
  NormalizedAdvisory,
} from "./intelligence.js";
import type { VersionAssessmentCollection, VersionRangeEvaluation } from "./versions.js";

export type PackageMappingAuthority =
  "operator-verified" | "upstream-documentation" | "vendor-documentation";
export type CorrelatableRangeType = "SEMVER" | "ECOSYSTEM";

/** Explicit identity mapping; technology names never imply package names or ecosystems. */
export interface TechnologyPackageIdentityMapping {
  readonly mappingId: string;
  readonly technologyId: string;
  readonly package: AdvisoryPackage;
  readonly authority: PackageMappingAuthority;
  /** Phase 5 strategy ID appropriate for this package ecosystem. */
  readonly versionStrategyId: string;
  /** Range encodings this mapping has explicitly verified against that strategy. */
  readonly supportedRangeTypes: readonly CorrelatableRangeType[];
  readonly vendor?: string;
  readonly distribution?: string;
  /** Optional exact NVD CPE identity. Both components must match. */
  readonly cpe?: {
    readonly vendor: string;
    readonly product: string;
    readonly rangeType: CorrelatableRangeType;
  };
}

/** Exact installed package identity from an authoritative inventory or operator record. */
export interface InstalledPackageIdentity {
  readonly mappingId: string;
  readonly ecosystem: string;
  readonly packageName: string;
  readonly vendor: string;
  readonly distribution: string;
  readonly exactPackageRevision: string;
  readonly verification: "authoritative-inventory";
  readonly sourceId: string;
  readonly recordId: string;
}

export type CorrelationApplicability =
  | "AFFECTED"
  | "NOT_AFFECTED"
  | "PATCHED_BY_VENDOR"
  | "POTENTIALLY_AFFECTED"
  | "UNKNOWN"
  | "CONFLICTING_EVIDENCE"
  | "INSUFFICIENT_EVIDENCE";

export interface CorrelationRangeAssessment {
  readonly providerId: string;
  readonly advisoryId: string;
  readonly package: AdvisoryPackage;
  readonly rangeType: string;
  readonly strategyId?: string;
  readonly status: VersionRangeEvaluation["status"];
  readonly rawVersion: string;
  readonly comparisons: VersionRangeEvaluation["comparisons"];
  readonly reason: string;
  readonly evidenceReferences: readonly EvidenceReference[];
}

export interface CorrelationExplanation {
  readonly code: string;
  readonly message: string;
  readonly providerId?: string;
  readonly mappingId?: string;
  readonly sourceRecordId?: string;
  readonly installedPackageSourceId?: string;
  readonly installedPackageRecordId?: string;
  readonly evidenceReferences?: readonly EvidenceReference[];
}

/** Advisory applicability only; this is not an overall target security status. */
export interface CorrelationResult {
  readonly technologyId: string;
  readonly applicability: CorrelationApplicability;
  readonly packageMappingId?: string;
  readonly package?: AdvisoryPackage;
  /** Canonical display key; every original per-source record remains in sourceRecords. */
  readonly advisoryId?: string;
  readonly aliases: readonly string[];
  readonly sourceRecords: readonly NormalizedAdvisory[];
  readonly sourceSeverities: readonly {
    readonly providerId: string;
    readonly advisoryId: string;
    readonly values: readonly AdvisorySeverity[];
  }[];
  readonly rangeAssessments: readonly CorrelationRangeAssessment[];
  readonly explanations: readonly CorrelationExplanation[];
}

export interface CorrelationInput {
  readonly schemaVersion: "1.0";
  readonly detections: readonly TechnologyDetection[];
  readonly versionAssessments: VersionAssessmentCollection;
  readonly intelligenceResults: readonly MultiSourceIntelligenceResult[];
  readonly packageMappings: readonly TechnologyPackageIdentityMapping[];
  readonly installedPackages?: readonly InstalledPackageIdentity[];
}

export interface CorrelationCollection {
  readonly schemaVersion: "1.0";
  readonly fingerprintSchemaVersion: "1.0";
  readonly versionAssessmentSchemaVersion: "1.0";
  readonly intelligenceSchemaVersion: "1.0";
  /** Source retrieval completeness is informational and never substitutes for a finding. */
  readonly intelligenceStatuses: readonly {
    readonly status: MultiSourceIntelligenceResult["status"];
    readonly providers: readonly {
      readonly providerId: string;
      readonly status: MultiSourceIntelligenceResult["sourceResults"][number]["status"];
      readonly diagnostics: readonly string[];
    }[];
    readonly diagnostics: readonly string[];
  }[];
  readonly results: readonly CorrelationResult[];
  readonly diagnostics: readonly string[];
}
