import type { TargetSecurityAssessment } from "./assessment.js";
import type { CorrelationCollection } from "./correlation.js";
import type { EvidenceCollection } from "./evidence.js";
import type { FingerprintResult } from "./fingerprints.js";
import type { MultiSourceIntelligenceResult } from "./intelligence.js";
import type { IdentificationTarget } from "./models.js";
import type { RemediationPlanCollection } from "./remediation.js";
import type { VersionAssessmentCollection } from "./versions.js";

/** Shared CLI/API request contract. The target is revalidated by the secure transport. */
export interface ScanRequest {
  readonly schemaVersion: "1.0";
  readonly target: IdentificationTarget;
}

/** Probe metadata safe for serialization; response headers, cookies, and body are excluded. */
export interface ProbeSummary {
  readonly status: number;
  readonly finalUrl: string;
  readonly contentType?: string;
  readonly contentLength?: number;
  readonly receivedBodyBytes: number;
  readonly redirectChain: readonly {
    readonly from: string;
    readonly status: number;
    readonly to: string;
  }[];
  readonly timing?: {
    readonly requestStartedAt: string;
    readonly responseReceivedAt: string;
    readonly completedAt: string;
    readonly durationMs: number;
  };
  readonly tls?: {
    readonly authorized: boolean;
    readonly protocol?: string;
    readonly cipher?: string;
    readonly peerCertificate?: {
      readonly subjectAltName?: string;
      readonly fingerprint256?: string;
      readonly validFrom?: string;
      readonly validTo?: string;
    };
  };
}

/** Versioned end-to-end result built once by the application and shared by CLI and API. */
export interface ScanResult {
  readonly schemaVersion: "1.0";
  readonly target: IdentificationTarget;
  readonly generatedAt: string;
  readonly probe: ProbeSummary;
  readonly evidence: EvidenceCollection;
  readonly fingerprint: FingerprintResult;
  readonly versions: VersionAssessmentCollection;
  readonly intelligence: MultiSourceIntelligenceResult;
  readonly correlation: CorrelationCollection;
  readonly assessment: TargetSecurityAssessment;
  readonly remediation: RemediationPlanCollection;
}

export interface ApiErrorEnvelope {
  readonly schemaVersion: "1.0";
  readonly error: {
    readonly code: string;
    readonly message: string;
  };
}
