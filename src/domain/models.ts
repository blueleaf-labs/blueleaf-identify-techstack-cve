/** Canonical target requested for future identification. */
export interface IdentificationTarget {
  /** Absolute HTTP(S) URL supplied by the caller. Validation belongs to the application boundary. */
  readonly url: string;
}

/** A technology observation returned by a future identification workflow. */
export interface TechnologyObservation {
  readonly name: string;
  readonly version?: string;
  readonly category?: string;
  readonly confidence?: number;
  readonly evidence?: readonly string[];
}

/** An identified vulnerability record. No CVE lookup or correlation is implemented in Phase 1. */
export interface VulnerabilityFinding {
  readonly id: string;
  readonly summary?: string;
  readonly severity?: string;
  readonly references?: readonly string[];
}

/** Serializable result envelope shared by CLI and future HTTP adapters. */
export interface IdentificationResult {
  readonly schemaVersion: "1.0";
  readonly target: IdentificationTarget;
  readonly technologies: readonly TechnologyObservation[];
  readonly vulnerabilities: readonly VulnerabilityFinding[];
  readonly generatedAt: string;
}
