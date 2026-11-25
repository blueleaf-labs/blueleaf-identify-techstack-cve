import type { AssessmentState, TargetSecurityAssessment } from "./assessment.js";
import type {
  CorrelationCollection,
  CorrelationApplicability,
  CorrelationResult,
  TechnologyPackageIdentityMapping,
} from "./correlation.js";
import type {
  AdvisoryPackage,
  AdvisorySeverity,
  NormalizedAdvisory,
} from "./intelligence.js";
import type { VersionAssessmentCollection } from "./versions.js";

export type RemediationState =
  | "ACTION_REQUIRED"
  | "UPGRADE_RECOMMENDED"
  | "VENDOR_UPDATE_REQUIRED"
  | "PATCH_ALREADY_APPLIED"
  | "NO_ACTION_IDENTIFIED"
  | "MANUAL_REVIEW_REQUIRED"
  | "REMEDIATION_UNAVAILABLE";

export type RemediationPriorityLevel = "P0" | "P1" | "P2" | "P3" | "REVIEW" | "NONE";
export type AdvisorySeverityBand = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";

export interface RemediationPriority {
  readonly level: RemediationPriorityLevel;
  readonly severityBand: AdvisorySeverityBand;
  readonly applicabilityState: AssessmentState;
  readonly rationale: string;
}

export interface RemediationReference {
  readonly providerId: string;
  readonly advisoryId: string;
  readonly url: string;
  readonly authority: string;
  readonly authoritative: boolean;
}

export type FixedVersionKind =
  | "upstream-fixed-version"
  | "vendor-package-fixed-version"
  | "vendor-upstream-fix"
  | "cpe-fixed-boundary";

/** Preserves a source's fix statement, including values that are not safe to recommend. */
export interface RemediationFixEvidence {
  readonly kind: FixedVersionKind;
  readonly providerId: string;
  readonly advisoryId: string;
  readonly value: string;
  readonly package?: AdvisoryPackage;
  readonly versionStrategyId?: string;
  readonly authority: string;
  readonly authoritative: boolean;
  readonly recommendationEligible: boolean;
  readonly reason: string;
  readonly references: readonly RemediationReference[];
}

export interface MinimumSafeUpgrade {
  readonly version: string;
  readonly scheme: string;
  readonly strategyId: string;
  readonly sourceRequirements: readonly string[];
  readonly reason: string;
}

export interface VendorUpdateRequirement {
  readonly providerId: string;
  readonly packageName: string;
  readonly ecosystem: string;
  readonly vendor: string;
  readonly distribution: string;
  readonly fixedPackageRevisions: readonly string[];
  readonly upstreamFixes: readonly string[];
  readonly references: readonly RemediationReference[];
  readonly administratorVerificationRequired: true;
  readonly instructions: string;
}

export interface RemediationAdvisoryPlan {
  readonly advisoryId?: string;
  readonly aliases: readonly string[];
  readonly state: RemediationState;
  /** Phase 9 state is copied; remediation never rewrites it. */
  readonly securityAssessmentState: AssessmentState;
  readonly correlationApplicability: CorrelationApplicability;
  readonly confidence: number;
  readonly severity: readonly {
    readonly providerId: string;
    readonly advisoryId: string;
    readonly values: readonly AdvisorySeverity[];
    readonly bands: readonly AdvisorySeverityBand[];
  }[];
  readonly highestSeverityBand: AdvisorySeverityBand;
  readonly exploitability: "NOT_ASSESSED";
  readonly priority: RemediationPriority;
  readonly fixedVersionEvidence: readonly RemediationFixEvidence[];
  readonly minimumSafeUpgrade?: MinimumSafeUpgrade;
  readonly vendorUpdates: readonly VendorUpdateRequirement[];
  readonly references: readonly RemediationReference[];
  readonly followUpVerification: readonly string[];
  readonly explanations: readonly string[];
  readonly limitations: readonly string[];
  readonly correlation: CorrelationResult;
  readonly sourceRecords: readonly NormalizedAdvisory[];
}

export type LifecycleStatus = "supported" | "end-of-life" | "unknown";

/** Optional lifecycle source data; the engine does not infer EOL from age or version. */
export interface ComponentLifecycleInformation {
  readonly technologyId: string;
  readonly mappingId: string;
  readonly status: LifecycleStatus;
  readonly endOfLifeAt?: string;
  readonly providerId: string;
  readonly authority: "primary" | "vendor";
  readonly verified: true;
  readonly reference: string;
  readonly retrievedAt: string;
  readonly migrationPath?: {
    readonly technologyId: string;
    readonly displayName: string;
    readonly package?: AdvisoryPackage;
    readonly recommendation: string;
    readonly reference: string;
  };
}

export interface ComponentLifecycleAssessment {
  readonly status: LifecycleStatus | "not-assessed";
  readonly endOfLifeAt?: string;
  readonly providerId?: string;
  readonly reference?: string;
  readonly concern?: string;
  readonly migrationPath?: ComponentLifecycleInformation["migrationPath"];
}

export interface ComponentRemediationPlan {
  readonly technologyId: string;
  readonly displayName: string;
  readonly state: RemediationState;
  readonly securityAssessmentState: AssessmentState;
  readonly packageMappingId?: string;
  readonly package?: AdvisoryPackage;
  readonly versionStrategyId?: string;
  readonly currentUpstreamVersion?: string;
  readonly vendorPackageRevisions: readonly string[];
  readonly advisoryPlans: readonly RemediationAdvisoryPlan[];
  readonly recommendedTargetVersion?: MinimumSafeUpgrade;
  readonly lifecycle: ComponentLifecycleAssessment;
  readonly references: readonly RemediationReference[];
  readonly followUpVerification: readonly string[];
  readonly explanations: readonly string[];
  readonly limitations: readonly string[];
}

export interface RemediationPlanCollection {
  readonly schemaVersion: "1.0";
  readonly assessedAt: string;
  /** Copy of the Phase 9 target state, never a remediation-derived security verdict. */
  readonly securityAssessmentState: AssessmentState;
  readonly plans: readonly ComponentRemediationPlan[];
  readonly limitations: readonly string[];
}

export interface RemediationInput {
  readonly schemaVersion: "1.0";
  readonly securityAssessment: TargetSecurityAssessment;
  readonly correlation: CorrelationCollection;
  readonly advisories: readonly NormalizedAdvisory[];
  readonly versionAssessments: VersionAssessmentCollection;
  readonly packageMappings: readonly TechnologyPackageIdentityMapping[];
  readonly lifecycleInformation?: readonly ComponentLifecycleInformation[];
}
