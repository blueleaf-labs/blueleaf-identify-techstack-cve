import type { EvidenceSource, EvidenceType } from "./evidence.js";

export type FingerprintMatchOperator = "equals" | "contains" | "prefix";

export interface FingerprintSignalDefinition {
  readonly id: string;
  readonly evidenceTypes: readonly EvidenceType[];
  readonly sources?: readonly EvidenceSource[];
  readonly keys?: readonly string[];
  readonly operator: FingerprintMatchOperator;
  readonly value: string;
  /** Independent support contribution in the [0, 1] range. */
  readonly weight: number;
  readonly reason: string;
}

export interface FingerprintDefinition {
  readonly id: string;
  readonly displayName: string;
  readonly category: string;
  readonly minimumConfidence: number;
  /** Limit confidence when only one rule signal matched. */
  readonly singleSignalConfidenceCap: number;
  /** Technologies whose matched signals are materially inconsistent with this definition. */
  readonly contradicts?: readonly string[];
  readonly signals: readonly FingerprintSignalDefinition[];
}

/** Versioned, data-only knowledge pack. It contains no executable rule code. */
export interface FingerprintDefinitionSet {
  readonly schemaVersion: "1.0";
  readonly definitions: readonly FingerprintDefinition[];
}

export interface EvidenceReference {
  readonly evidenceIndex: number;
  readonly type: EvidenceType;
  readonly source: EvidenceSource;
  readonly normalizedValue: string;
  readonly key?: string;
}

export interface VersionCandidate {
  readonly value: string;
  readonly confidence: number;
  readonly evidenceReferences: readonly EvidenceReference[];
}

export interface ContradictoryEvidence extends EvidenceReference {
  readonly technologyId: string;
  readonly signalId: string;
}

export interface TechnologyDetection {
  readonly technologyId: string;
  readonly displayName: string;
  readonly category: string;
  readonly versionCandidate?: VersionCandidate;
  /** All observed version candidates, including conflicting candidates. */
  readonly versionCandidates: readonly VersionCandidate[];
  readonly detectionConfidence: number;
  readonly versionConfidence: number;
  readonly matchedEvidenceReferences: readonly EvidenceReference[];
  readonly detectionReasons: readonly string[];
  readonly contradictoryEvidence: readonly ContradictoryEvidence[];
}

/** Stable result shape for JSON and future CLI/API consumers. */
export interface FingerprintResult {
  readonly schemaVersion: "1.0";
  readonly evidenceSchemaVersion: "1.0";
  readonly detections: readonly TechnologyDetection[];
}
