/** Stable evidence categories. These describe observations, not technology verdicts. */
export type EvidenceType =
  | "http-status"
  | "final-url"
  | "content-type"
  | "content-length"
  | "header"
  | "cookie"
  | "redirect"
  | "tls"
  | "network"
  | "timing"
  | "content-marker"
  | "html-meta"
  | "html-generator"
  | "html-title"
  | "script-url"
  | "stylesheet-url"
  | "asset-url";

/** Stable origin identifiers shared by JSON and future API representations. */
export type EvidenceSource =
  | "probe.status"
  | "probe.final-url"
  | "probe.content-type"
  | "probe.content-length"
  | "response.headers"
  | "response.cookies"
  | "probe.redirect-chain"
  | "probe.tls"
  | "probe.network"
  | "probe.timing"
  | "response.body.signature"
  | "html.meta"
  | "html.generator"
  | "html.title"
  | "html.script.src"
  | "html.link.stylesheet"
  | "html.asset.url";

/** Direct describes probe fields; derived describes parsing of response content. */
export type EvidenceStrength = "direct" | "derived";

export interface Evidence {
  readonly type: EvidenceType;
  readonly source: EvidenceSource;
  /** Stable normalized observation value. */
  readonly normalizedValue: string;
  /** Bounded, sanitized raw observation when retaining it is useful and safe. */
  readonly rawValue?: string;
  /** Normalized header/meta key or HTML element context, when applicable. */
  readonly key?: string;
  /** Generic unverified version-like token; never an authoritative technology version. */
  readonly versionHint?: string;
  /** Reserved for later classifiers. Phase 3 does not populate technology hints. */
  readonly technologyHint?: string;
  /** Source fidelity only; this is not confidence in a technology attribution. */
  readonly strength: EvidenceStrength;
  readonly reason: string;
}

export interface EvidenceProcessingSummary {
  readonly bodyBytesReceived: number;
  readonly bodyBytesExamined: number;
  readonly bodyTruncated: boolean;
  readonly evidenceTruncated: boolean;
}

/** Stable, transport-neutral JSON payload for a future CLI and Blueleaf API. */
export interface EvidenceCollection {
  readonly schemaVersion: "1.0";
  readonly evidence: readonly Evidence[];
  readonly processing: EvidenceProcessingSummary;
}
