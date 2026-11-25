import type { HttpProvider } from "../ports.js";
import type { EvidenceCollector } from "../evidence/evidence-engine.js";
import type { MultiSourceIntelligenceResolver } from "../intelligence/contracts.js";
import type { FingerprintEngine } from "../fingerprinting/fingerprint-engine.js";
import type { VersionIntelligenceEngine } from "../versioning/version-engine.js";
import type { VulnerabilityCorrelationEngine } from "../correlation/correlation-engine.js";
import type { SecurityAssessmentEngine } from "../assessment/security-assessment-engine.js";
import type { RemediationEngine } from "../remediation/remediation-engine.js";
import type { TechnologyPackageIdentityMapping } from "../../domain/correlation.js";
import type { ScanRequest, ScanResult } from "../../domain/scan.js";

export interface ScanService {
  scan(request: ScanRequest, signal?: AbortSignal): Promise<ScanResult>;
}

/** Fully composed dependencies; presentation and web adapters only call ScanService.scan. */
export interface ScanApplicationDependencies {
  readonly http: HttpProvider;
  readonly evidence: EvidenceCollector;
  readonly fingerprinting: Pick<FingerprintEngine, "fingerprint">;
  readonly versions: Pick<VersionIntelligenceEngine, "assess">;
  readonly intelligence: MultiSourceIntelligenceResolver;
  readonly correlation: Pick<VulnerabilityCorrelationEngine, "correlate">;
  readonly assessment: Pick<SecurityAssessmentEngine, "assess">;
  readonly remediation: Pick<RemediationEngine, "plan">;
  readonly packageMappings: readonly TechnologyPackageIdentityMapping[];
  readonly probeTimeoutMs: number;
  readonly now?: () => Date;
  readonly maxAdvisoryLookups?: number;
}
