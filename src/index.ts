export type {
  ApplicationDependencies,
  IdentificationService,
  IdentifyRequest,
} from "./application/contracts.js";
export type {
  CacheProvider,
  FingerprintingProvider,
  HttpProvider,
  HttpRequest,
  HttpResponse,
  IntelligenceProvider,
  ProbeTiming,
  ProviderRegistry,
  RedirectHop,
  TlsMetadata,
} from "./application/ports.js";
export type {
  AdvisoryIntelligenceProvider,
  AdvisoryProviderResult,
  IntelligenceResolver as IntelligenceResolverContract,
  IntelligenceResolverOptions,
  MultiSourceIntelligenceResolver,
  TechnologyPackageMapping,
} from "./application/intelligence/contracts.js";
export { IntelligenceResolverService } from "./application/intelligence/intelligence-resolver.js";
export { VulnerabilityCorrelationEngine } from "./application/correlation/correlation-engine.js";
export { SecurityAssessmentEngine } from "./application/assessment/security-assessment-engine.js";
export type { SecurityAssessmentEngineOptions } from "./application/assessment/security-assessment-engine.js";
export { RemediationEngine } from "./application/remediation/remediation-engine.js";
export type { RemediationEngineOptions } from "./application/remediation/remediation-engine.js";
export type {
  AdvisorySeverityBand,
  ComponentLifecycleAssessment,
  ComponentLifecycleInformation,
  ComponentRemediationPlan,
  FixedVersionKind,
  MinimumSafeUpgrade,
  RemediationAdvisoryPlan,
  RemediationFixEvidence,
  RemediationInput,
  RemediationPlanCollection,
  RemediationPriority,
  RemediationPriorityLevel,
  RemediationReference,
  RemediationState,
  VendorUpdateRequirement,
} from "./domain/remediation.js";
export type {
  AdvisoryAssessment,
  AssessmentConfidence,
  AssessmentSourceCoverage,
  AssessmentState,
  ConfidenceDimension,
  IntelligenceCompleteness,
  IntelligenceCoverage,
  SecurityAssessmentInput,
  SecurityAssessmentResult,
  SourceIndependenceDeclaration,
  TargetSecurityAssessment,
  TechnologySecurityAssessment,
} from "./domain/assessment.js";
export type {
  CorrelationApplicability,
  CorrelationCollection,
  CorrelationExplanation,
  CorrelationInput,
  CorrelationRangeAssessment,
  CorrelationResult,
  CorrelatableRangeType,
  InstalledPackageIdentity,
  PackageMappingAuthority,
  TechnologyPackageIdentityMapping,
} from "./domain/correlation.js";
export { OsvIntelligenceProvider } from "./infrastructure/intelligence/osv-provider.js";
export type { OsvProviderOptions } from "./infrastructure/intelligence/osv-provider.js";
export { NvdIntelligenceProvider } from "./infrastructure/intelligence/nvd-provider.js";
export type {
  NvdProviderOptions,
  NvdSyncResult,
} from "./infrastructure/intelligence/nvd-provider.js";
export {
  RedHatSecurityAdvisoryProvider,
  UbuntuSecurityAdvisoryProvider,
} from "./infrastructure/intelligence/vendor-providers.js";
export type { OfficialVendorProviderOptions } from "./infrastructure/intelligence/vendor-providers.js";
export {
  adaptOsvAdvisory,
  adaptOsvBatchPage,
  adaptOsvQueryPage,
} from "./infrastructure/intelligence/osv-adapter.js";
export type {
  OsvBatchPage,
  OsvBatchPageItem,
  OsvQueryPage,
} from "./infrastructure/intelligence/osv-adapter.js";
export type {
  ApplicationConfiguration,
  ConfigurationLoader,
  ConfigurationSource,
} from "./config/configuration.js";
export { DEFAULT_APPLICATION_CONFIGURATION } from "./config/configuration.js";
export { loadRuntimeSettings, processEnvironmentSource } from "./config/environment.js";
export type { RuntimeSettings } from "./config/environment.js";
export { ScanApplicationService } from "./application/scan/scan-service.js";
export type {
  ScanApplicationDependencies,
  ScanService,
} from "./application/scan/contracts.js";
export type {
  ApiErrorEnvelope,
  ProbeSummary,
  ScanRequest,
  ScanResult,
} from "./domain/scan.js";
export { createScanApplicationService } from "./infrastructure/composition-root.js";
export type { ScanCompositionOverrides } from "./infrastructure/composition-root.js";
export { createApiServer, listenApiServer, shutdownApiServer } from "./api/server.js";
export type { ApiServerOptions } from "./api/server.js";
export type {
  ApiCredential,
  SecurityEvent,
  SecurityEventLogger,
} from "./config/api-security.js";
export { MemoryCacheProvider } from "./infrastructure/cache/memory-cache.js";
export type { MemoryCacheOptions } from "./infrastructure/cache/memory-cache.js";
export type {
  Evidence,
  EvidenceCollection,
  EvidenceProcessingSummary,
  EvidenceSource,
  EvidenceStrength,
  EvidenceType,
} from "./domain/evidence.js";
export type {
  ContradictoryEvidence,
  EvidenceReference,
  FingerprintDefinition,
  FingerprintDefinitionSet,
  FingerprintMatchOperator,
  FingerprintResult,
  FingerprintSignalDefinition,
  TechnologyDetection,
  VersionCandidate,
} from "./domain/fingerprints.js";
export type {
  ObservedVersion,
  ParsedUpstreamVersion,
  VendorAdvisoryRange,
  VendorBackportAssessment,
  VendorBackportStatus,
  VendorPackageVersion,
  VersionAssessment,
  VersionAssessmentCollection,
  VersionCandidateAssessment,
  VersionComparisonConstraint,
  VersionComparisonOperator,
  VersionComponents,
  VersionParseResult,
  VersionParsingStatus,
  VersionRange,
  VersionRangeEvaluation,
  VersionRangeStatus,
  VersionReconciliationStatus,
} from "./domain/versions.js";
export { ApplicationError, isApplicationError } from "./domain/errors.js";
export type { ErrorCode } from "./domain/errors.js";
export type {
  IdentificationResult,
  IdentificationTarget,
  TechnologyObservation,
  VulnerabilityFinding,
} from "./domain/models.js";
export type {
  AdvisoryCpeConfiguration,
  AdvisoryCpeMatch,
  AdvisoryCpeNode,
  AdvisoryAffectedPackage,
  AdvisoryPackage,
  AdvisoryPackageQuery,
  AdvisoryProvenance,
  AdvisoryRangeComparisonInput,
  AdvisoryRangeEvent,
  AdvisoryReference,
  AdvisoryRecordStatus,
  AdvisorySeverity,
  AdvisoryVersionRange,
  IntelligenceSourceResult,
  IntelligenceSourceStatus,
  IntelligenceResult,
  IntelligenceResultStatus,
  MultiSourceIntelligenceRequest,
  MultiSourceIntelligenceResult,
  MultiSourceIntelligenceStatus,
  NormalizedAdvisory,
  VendorPackageInformation,
} from "./domain/intelligence.js";
export { HttpProbeProvider } from "./infrastructure/http/http-probe-provider.js";
export {
  isGloballyRoutableAddress,
  normalizeTarget,
  SecureTargetResolver,
} from "./infrastructure/http/target-resolver.js";
export {
  DEFAULT_EVIDENCE_BODY_LIMIT,
  DEFAULT_EVIDENCE_ITEM_LIMIT,
  EvidenceEngine,
  extractVersionHint,
  MAX_EVIDENCE_BODY_LIMIT,
  MAX_EVIDENCE_ITEM_LIMIT,
  normalizeEvidenceText,
  normalizeEvidenceUrl,
} from "./application/evidence/evidence-engine.js";
export type {
  EvidenceCollector,
  EvidenceEngineOptions,
} from "./application/evidence/evidence-engine.js";
export type {
  HostResolver,
  ResolvedAddress,
  ResolvedTarget,
} from "./infrastructure/http/target-resolver.js";
export {
  FingerprintEngine,
  validateFingerprintDefinitions,
} from "./application/fingerprinting/fingerprint-engine.js";
export { BUILTIN_FINGERPRINT_DEFINITIONS } from "./fingerprinting/definitions.js";
export {
  DEFAULT_VERSION_STRATEGIES,
  VersionStrategyRegistry,
  compareSemVer,
} from "./application/versioning/strategies.js";
export type { VersionStrategy } from "./application/versioning/strategies.js";
export { VersionIntelligenceEngine } from "./application/versioning/version-engine.js";
export type { VersionComparisonResult } from "./application/versioning/version-engine.js";
