import type { TechnologyDetection } from "./fingerprints.js";
import type {
  IntelligenceSourceStatus,
  MultiSourceIntelligenceResult,
  NormalizedAdvisory,
} from "./intelligence.js";
import type {
  CorrelationCollection,
  CorrelationResult,
  TechnologyPackageIdentityMapping,
} from "./correlation.js";
import type { VersionAssessment, VersionAssessmentCollection } from "./versions.js";

export type AssessmentState =
  | "CONFIRMED_VULNERABLE"
  | "LIKELY_VULNERABLE"
  | "PATCHED"
  | "PATCHED_BY_VENDOR"
  | "NO_KNOWN_VULNERABILITY"
  | "VERSION_UNKNOWN"
  | "TECHNOLOGY_UNKNOWN"
  | "INSUFFICIENT_EVIDENCE"
  | "INTELLIGENCE_UNAVAILABLE"
  | "CONFLICTING_EVIDENCE";

export type IntelligenceCompleteness =
  "complete" | "partial" | "unavailable" | "stale" | "unsupported" | "unknown";

export interface ConfidenceDimension {
  readonly score: number;
  readonly rationale: string;
}

/** Heuristic component scores; they are not probabilities. */
export interface AssessmentConfidence {
  readonly technologyIdentification: ConfidenceDimension;
  readonly versionIdentification: ConfidenceDimension;
  readonly packageIdentity: ConfidenceDimension;
  readonly vulnerabilityApplicability: ConfidenceDimension;
  readonly advisoryEvidence: ConfidenceDimension;
  readonly intelligenceCompleteness: ConfidenceDimension;
  readonly independentCorroboration: ConfidenceDimension;
  readonly contradictionPenalty: ConfidenceDimension;
  readonly overall: number;
  readonly formula: string;
}

export interface AssessmentSourceCoverage {
  readonly providerId: string;
  readonly status: IntelligenceSourceStatus;
  readonly retrievedAt?: string;
  readonly sourceModifiedAt?: string;
  readonly ageMs?: number;
  readonly stale: boolean;
  readonly diagnostics: readonly string[];
}

export interface IntelligenceCoverage {
  readonly status: IntelligenceCompleteness;
  /** Provider results actually supplied by the caller; this is not global source coverage. */
  readonly sources: readonly AssessmentSourceCoverage[];
  readonly unsupportedMappings: readonly string[];
  readonly limitations: readonly string[];
}

export interface AdvisoryAssessment {
  readonly advisoryId?: string;
  readonly aliases: readonly string[];
  readonly state: AssessmentState;
  readonly confidence: AssessmentConfidence;
  /** Phase 8 result and all per-source advisory records remain attached and traceable. */
  readonly correlation: CorrelationResult;
  readonly sourceRecords: readonly NormalizedAdvisory[];
  readonly explanations: readonly string[];
}

export interface TechnologySecurityAssessment {
  readonly technologyId: string;
  readonly displayName: string;
  readonly state: AssessmentState;
  readonly confidence: AssessmentConfidence;
  readonly explanations: readonly string[];
  readonly detection: TechnologyDetection;
  readonly versionAssessment?: VersionAssessment;
  readonly packageMapping?: TechnologyPackageIdentityMapping;
  readonly advisoryAssessments: readonly AdvisoryAssessment[];
  readonly intelligenceCoverage: IntelligenceCoverage;
  readonly limitations: readonly string[];
}

export interface TargetSecurityAssessment {
  readonly schemaVersion: "1.0";
  readonly assessedAt: string;
  readonly state: AssessmentState;
  readonly confidence: AssessmentConfidence;
  readonly explanations: readonly string[];
  readonly technologyAssessments: readonly TechnologySecurityAssessment[];
  readonly intelligenceCoverage: IntelligenceCoverage;
  readonly limitations: readonly string[];
}

/** Stable named alias for the serialized Phase 9 target output. */
export type SecurityAssessmentResult = TargetSecurityAssessment;

/** Caller-verified source lineage; providers in one group are not independent corroborators. */
export interface SourceIndependenceDeclaration {
  readonly providerId: string;
  readonly sourceGroupId: string;
  readonly verified: true;
}

/** Stable Phase 9 input. `assessedAt` makes freshness evaluation reproducible. */
export interface SecurityAssessmentInput {
  readonly schemaVersion: "1.0";
  readonly assessedAt: string;
  readonly detections: readonly TechnologyDetection[];
  readonly versionAssessments: VersionAssessmentCollection;
  readonly intelligenceResults: readonly MultiSourceIntelligenceResult[];
  readonly correlation: CorrelationCollection;
  readonly packageMappings: readonly TechnologyPackageIdentityMapping[];
  /** Without declarations, provider records do not count as independent corroboration. */
  readonly sourceIndependenceGroups?: readonly SourceIndependenceDeclaration[];
}
