import { ApplicationError } from "../../domain/errors.js";
import type {
  AssessmentConfidence,
  AssessmentSourceCoverage,
  AssessmentState,
  ConfidenceDimension,
  IntelligenceCompleteness,
  IntelligenceCoverage,
  SecurityAssessmentInput,
  TargetSecurityAssessment,
  TechnologySecurityAssessment,
  AdvisoryAssessment,
} from "../../domain/assessment.js";
import type { TechnologyDetection } from "../../domain/fingerprints.js";
import type {
  CorrelationApplicability,
  CorrelationResult,
  TechnologyPackageIdentityMapping,
} from "../../domain/correlation.js";
import type { NormalizedAdvisory } from "../../domain/intelligence.js";
import type { VersionAssessment } from "../../domain/versions.js";

const MAX_AGE_MS_DEFAULT = 30 * 24 * 60 * 60 * 1000;
const DETECTION_LIKELY_THRESHOLD = 0.5;
const DETECTION_CONFIRMED_THRESHOLD = 0.75;
const VERSION_CONFIRMED_THRESHOLD = 0.75;
const CONFIRMED_CONFIDENCE_THRESHOLD = 0.75;

function textOrder(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
function clamp(value: number): number {
  return Math.max(0, Math.min(1, value));
}
function unique<T>(values: readonly T[]): T[] {
  return [...new Set(values)];
}
function samePackage(
  left: { readonly ecosystem: string; readonly name: string } | undefined,
  right: { readonly ecosystem: string; readonly name: string },
): boolean {
  return (
    left !== undefined &&
    left.ecosystem.trim().toLocaleLowerCase("en-US") ===
      right.ecosystem.trim().toLocaleLowerCase("en-US") &&
    left.name === right.name
  );
}
function dimension(score: number, rationale: string): ConfidenceDimension {
  return { score: Number(clamp(score).toFixed(3)), rationale };
}
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function assertInput(value: unknown): asserts value is SecurityAssessmentInput {
  if (
    !isRecord(value) ||
    value["schemaVersion"] !== "1.0" ||
    typeof value["assessedAt"] !== "string" ||
    Number.isNaN(Date.parse(value["assessedAt"])) ||
    !Array.isArray(value["detections"]) ||
    !isRecord(value["versionAssessments"]) ||
    value["versionAssessments"]["schemaVersion"] !== "1.0" ||
    value["versionAssessments"]["fingerprintSchemaVersion"] !== "1.0" ||
    !Array.isArray(value["versionAssessments"]["assessments"]) ||
    !Array.isArray(value["intelligenceResults"]) ||
    !isRecord(value["correlation"]) ||
    value["correlation"]["schemaVersion"] !== "1.0" ||
    value["correlation"]["fingerprintSchemaVersion"] !== "1.0" ||
    value["correlation"]["versionAssessmentSchemaVersion"] !== "1.0" ||
    value["correlation"]["intelligenceSchemaVersion"] !== "1.0" ||
    !Array.isArray(value["correlation"]["results"]) ||
    !Array.isArray(value["packageMappings"]) ||
    !value["intelligenceResults"].every(
      (item) => isRecord(item) && item["schemaVersion"] === "1.0",
    )
  ) {
    throw new ApplicationError(
      "INVALID_INPUT",
      "Security assessment requires valid Phase 4–8 schema 1.0 inputs and an assessment timestamp.",
    );
  }
  for (const detection of value["detections"]) {
    if (
      !isRecord(detection) ||
      typeof detection["technologyId"] !== "string" ||
      typeof detection["detectionConfidence"] !== "number" ||
      !Number.isFinite(detection["detectionConfidence"]) ||
      detection["detectionConfidence"] < 0 ||
      detection["detectionConfidence"] > 1
    )
      throw new ApplicationError(
        "INVALID_INPUT",
        "Assessment input contains an invalid technology detection.",
      );
  }
  if (value["sourceIndependenceGroups"] !== undefined) {
    const declarations = value["sourceIndependenceGroups"];
    if (
      !Array.isArray(declarations) ||
      !declarations.every(
        (item) =>
          isRecord(item) &&
          typeof item["providerId"] === "string" &&
          item["providerId"].length > 0 &&
          typeof item["sourceGroupId"] === "string" &&
          item["sourceGroupId"].length > 0 &&
          item["verified"] === true,
      ) ||
      new Set(
        declarations.map((item) => (isRecord(item) ? item["providerId"] : undefined)),
      ).size !== declarations.length
    )
      throw new ApplicationError(
        "INVALID_INPUT",
        "Source independence declarations must be verified and unique by provider ID.",
      );
  }
}

function sourceRecords(result: CorrelationResult): readonly NormalizedAdvisory[] {
  return result.sourceRecords;
}
function advisoryActive(record: NormalizedAdvisory): boolean {
  return (record.recordStatus ?? "active") === "active";
}
function advisoryPayloadFingerprint(record: NormalizedAdvisory): string {
  return JSON.stringify({
    id: record.id,
    aliases: record.aliases,
    summary: record.summary,
    details: record.details,
    affectedPackages: record.affectedPackages,
    severity: record.severity,
    references: record.references,
    recordStatus: record.recordStatus,
    cpeConfigurations: record.cpeConfigurations,
    vendorPackageInformation: record.vendorPackageInformation,
  });
}
function independentAuthorityGroups(
  records: readonly NormalizedAdvisory[],
  declarations: SecurityAssessmentInput["sourceIndependenceGroups"] = [],
): string[] {
  // Provider names and authority labels do not prove separate lineage. The caller must verify
  // source groups; identical payloads across providers remain one origin regardless.
  const declaredGroupByProvider = new Map(
    (declarations ?? [])
      .filter((item) => item.verified === true)
      .map((item) => [item.providerId, item.sourceGroupId]),
  );
  const origins = new Map<string, string>();
  const seenPayloads = new Set<string>();
  for (const record of [...records]
    .filter(advisoryActive)
    .sort((a, b) => textOrder(a.provenance.providerId, b.provenance.providerId))) {
    const authority = record.provenance.authority;
    if (authority !== "primary" && authority !== "vendor") continue;
    const declaredGroup = declaredGroupByProvider.get(record.provenance.providerId);
    if (!declaredGroup) continue;
    const identity = advisoryPayloadFingerprint(record);
    if (seenPayloads.has(identity)) continue;
    seenPayloads.add(identity);
    origins.set(identity, declaredGroup);
  }
  return unique([...origins.values()]).sort(textOrder);
}
function advisoryEvidenceScore(
  records: readonly NormalizedAdvisory[],
  hasCompleteNoResult: boolean,
): number {
  const scoresByOrigin = new Map<string, number[]>();
  for (const record of records.filter(advisoryActive)) {
    let score: number;
    switch (record.provenance.authority) {
      case "vendor":
        score = 0.95;
        break;
      case "primary":
        score = 0.9;
        break;
      case "aggregator":
        score = 0.4;
        break;
      default:
        score = 0.5;
    }
    const origin = advisoryPayloadFingerprint(record);
    const group = scoresByOrigin.get(origin) ?? [];
    group.push(score);
    scoresByOrigin.set(origin, group);
  }
  // Identical payloads are one underlying source: use the least-strong label in that group.
  const scores = [...scoresByOrigin.values()].map((group) => Math.min(...group));
  return scores.length ? Math.max(...scores) : hasCompleteNoResult ? 0.8 : 0;
}
function applicabilityEvidenceScore(
  applicability: CorrelationApplicability | undefined,
  completeNoResult: boolean,
): { readonly score: number; readonly rationale: string } {
  switch (applicability) {
    case "AFFECTED":
      return {
        score: 0.95,
        rationale: "Phase 8 produced a direct supported affected-range result.",
      };
    case "NOT_AFFECTED":
      return {
        score: 0.9,
        rationale: "Phase 8 produced a direct supported non-applicability result.",
      };
    case "PATCHED_BY_VENDOR":
      return {
        score: 0.95,
        rationale: "Phase 8 established an exact vendor package patch result.",
      };
    case "POTENTIALLY_AFFECTED":
      return {
        score: 0.65,
        rationale: "Phase 8 reports potential applicability with unresolved conditions.",
      };
    case "CONFLICTING_EVIDENCE":
      return {
        score: 0.35,
        rationale: "Phase 8 retained conflicting source applicability evidence.",
      };
    case "INSUFFICIENT_EVIDENCE":
      return {
        score: 0,
        rationale:
          "Applicability is unknown or insufficient; missing data contributes no positive score.",
      };
    case "UNKNOWN":
      return completeNoResult
        ? {
            score: 0.8,
            rationale:
              "The correlated source set is complete and has no matching advisory; this is scoped coverage evidence only.",
          }
        : {
            score: 0,
            rationale:
              "Applicability is unknown; missing data contributes no positive score.",
          };
    default:
      return completeNoResult
        ? {
            score: 0.8,
            rationale:
              "Requested sources completed without an advisory; this is scoped coverage evidence, not positive vulnerability evidence.",
          }
        : { score: 0, rationale: "No applicability evidence is available." };
  }
}
function confidenceFor(input: {
  readonly detection?: TechnologyDetection;
  readonly version?: VersionAssessment;
  readonly mapping?: TechnologyPackageIdentityMapping;
  readonly records: readonly NormalizedAdvisory[];
  readonly coverage: IntelligenceCoverage;
  readonly completeNoResult?: boolean;
  readonly applicability?: CorrelationApplicability;
  readonly applicabilityScore?: number;
  readonly sourceIndependenceGroups?: SecurityAssessmentInput["sourceIndependenceGroups"];
  readonly conflict?: boolean;
  readonly uniqueEvidenceCount?: number;
}): AssessmentConfidence {
  const detectionScore = input.detection ? clamp(input.detection.detectionConfidence) : 0;
  const detection = dimension(
    detectionScore,
    input.detection
      ? `${input.uniqueEvidenceCount ?? 0} distinct evidence references retained; repeated copies do not add weight.`
      : "No technology detection supports identification.",
  );
  const versionIsExact =
    input.version?.parsingStatus === "parsed" &&
    (input.version.reconciliationStatus === "single" ||
      input.version.reconciliationStatus === "corroborated") &&
    input.version.selectedUpstreamVersion !== undefined;
  const version = dimension(
    versionIsExact ? (input.version?.versionConfidence ?? 0) : 0,
    versionIsExact
      ? "A strategy-parsed upstream version reconciled to one value; the Phase 5 version confidence is retained separately."
      : "No single parsed upstream version is established; missing or ambiguous versions contribute zero.",
  );
  const packageScore = input.mapping
    ? input.mapping.authority === "operator-verified"
      ? 0.95
      : input.mapping.authority === "vendor-documentation"
        ? 0.9
        : 0.85
    : 0;
  const packageIdentity = dimension(
    packageScore,
    input.mapping
      ? `Package identity is explicitly mapped with ${input.mapping.authority} authority.`
      : "No unique explicit package mapping is available.",
  );
  const advisoryScore = advisoryEvidenceScore(
    input.records,
    input.completeNoResult ?? false,
  );
  const advisoryEvidence = dimension(
    advisoryScore,
    input.records.length
      ? "Score uses the strongest active record authority; duplicate records and aliases are not summed."
      : input.completeNoResult
        ? "Requested sources completed without a matching advisory; this describes coverage only, not software safety."
        : "No active advisory evidence is available.",
  );
  const applicabilityInput =
    input.applicabilityScore !== undefined
      ? {
          score: input.applicabilityScore,
          rationale:
            "Technology-level applicability uses the least-supported advisory result; missing/unknown findings are not averaged away.",
        }
      : applicabilityEvidenceScore(input.applicability, input.completeNoResult ?? false);
  const vulnerabilityApplicability = dimension(
    applicabilityInput.score,
    applicabilityInput.rationale,
  );
  const coverageScores: Record<IntelligenceCompleteness, number> = {
    complete: 1,
    partial: 0.5,
    stale: 0.35,
    unavailable: 0,
    unsupported: 0,
    unknown: 0,
  };
  const intelligence = dimension(
    coverageScores[input.coverage.status],
    `Intelligence coverage is ${input.coverage.status} for the providers supplied by the caller.`,
  );
  const groups = independentAuthorityGroups(
    input.records,
    input.sourceIndependenceGroups,
  );
  const corroboration = dimension(
    groups.length < 2 ? 0 : groups.length === 2 ? 0.65 : 0.9,
    groups.length
      ? `${groups.length} caller-verified source lineage group(s) support the result; provider/authority labels or identical records alone do not establish independence.`
      : "Fewer than two caller-verified, distinct primary/vendor source lineage groups are established; corroboration contributes zero.",
  );
  const contradictionCount = unique(
    (input.detection?.contradictoryEvidence ?? []).map(
      (item) =>
        `${item.source}\0${item.type}\0${item.key ?? ""}\0${item.normalizedValue}`,
    ),
  ).length;
  const penalty = input.conflict
    ? Math.max(0.2, 1 - Math.max(0.55, contradictionCount * 0.1))
    : Math.max(0.35, 1 - contradictionCount * 0.1);
  const contradiction = dimension(
    penalty,
    input.conflict || contradictionCount
      ? `Conflicting source/advisory evidence and ${contradictionCount} distinct contradictory technology observation(s) reduce confidence.`
      : "No distinct contradictory evidence is present.",
  );
  const weighted =
    detection.score * 0.2 +
    version.score * 0.2 +
    packageIdentity.score * 0.15 +
    vulnerabilityApplicability.score * 0.15 +
    advisoryEvidence.score * 0.1 +
    intelligence.score * 0.1 +
    corroboration.score * 0.1;
  const overall = Number((weighted * contradiction.score).toFixed(3));
  return {
    technologyIdentification: detection,
    versionIdentification: version,
    packageIdentity,
    vulnerabilityApplicability,
    advisoryEvidence,
    intelligenceCompleteness: intelligence,
    independentCorroboration: corroboration,
    contradictionPenalty: contradiction,
    overall,
    formula:
      "(0.20×technology + 0.20×version + 0.15×package + 0.15×applicability + 0.10×advisory + 0.10×coverage + 0.10×independent corroboration) × contradiction penalty",
  };
}

export interface SecurityAssessmentEngineOptions {
  /** Maximum age for provider retrieval timestamps. Defaults to 30 days. */
  readonly maxIntelligenceAgeMs?: number;
  readonly minimumDetectionConfidence?: number;
  readonly confirmedDetectionConfidence?: number;
  readonly confirmedVersionConfidence?: number;
  readonly confirmedAssessmentConfidence?: number;
}

/** Deterministic Phase 9 state assessment; no network, clock, or Phase 8 mutations. */
export class SecurityAssessmentEngine {
  private readonly maxAge: number;
  private readonly minimumDetection: number;
  private readonly confirmedDetection: number;
  private readonly confirmedVersion: number;
  private readonly confirmedAssessment: number;

  public constructor(options: SecurityAssessmentEngineOptions = {}) {
    this.maxAge = options.maxIntelligenceAgeMs ?? MAX_AGE_MS_DEFAULT;
    this.minimumDetection =
      options.minimumDetectionConfidence ?? DETECTION_LIKELY_THRESHOLD;
    this.confirmedDetection =
      options.confirmedDetectionConfidence ?? DETECTION_CONFIRMED_THRESHOLD;
    this.confirmedVersion =
      options.confirmedVersionConfidence ?? VERSION_CONFIRMED_THRESHOLD;
    this.confirmedAssessment =
      options.confirmedAssessmentConfidence ?? CONFIRMED_CONFIDENCE_THRESHOLD;
    if (
      !Number.isSafeInteger(this.maxAge) ||
      this.maxAge < 0 ||
      [
        this.minimumDetection,
        this.confirmedDetection,
        this.confirmedVersion,
        this.confirmedAssessment,
      ].some((value) => !Number.isFinite(value) || value < 0 || value > 1)
    )
      throw new ApplicationError(
        "INVALID_CONFIGURATION",
        "Security assessment thresholds are invalid.",
      );
  }

  public assess(input: SecurityAssessmentInput): TargetSecurityAssessment {
    assertInput(input);
    const timestamp = Date.parse(input.assessedAt);
    const sourceCoverage = this.collectSourceCoverage(input, timestamp);
    const baseCoverage = this.coverage(sourceCoverage, input.intelligenceResults);
    const versionByTechnology = new Map(
      input.versionAssessments.assessments.map((item) => [item.technologyId, item]),
    );
    const detections = [...input.detections].sort((a, b) =>
      textOrder(a.technologyId, b.technologyId),
    );
    const unresolvedMappings = detections.flatMap((detection) => {
      const count = input.packageMappings.filter(
        (item) => item.technologyId === detection.technologyId,
      ).length;
      return count === 1
        ? []
        : [
            `${detection.technologyId}:${count === 0 ? "missing explicit package mapping" : "ambiguous package mappings"}`,
          ];
    });
    const coverage: IntelligenceCoverage = {
      ...baseCoverage,
      unsupportedMappings: unique([
        ...baseCoverage.unsupportedMappings,
        ...unresolvedMappings,
        ...input.correlation.results.flatMap((result) =>
          result.explanations
            .filter((item) =>
              /UNSUPPORTED_RANGE_TYPE|VERSION_STRATEGY_MISMATCH|PACKAGE_MAPPING_(MISSING|AMBIGUOUS)/.test(
                item.code,
              ),
            )
            .map((item) => `${result.technologyId}:${item.code}`),
        ),
      ]).sort(textOrder),
    };
    const technologyAssessments = detections.map((detection) => {
      const version = versionByTechnology.get(detection.technologyId);
      const mappingCandidates = input.packageMappings.filter(
        (item) => item.technologyId === detection.technologyId,
      );
      const mapping = mappingCandidates.length === 1 ? mappingCandidates[0] : undefined;
      const correlations = input.correlation.results
        .filter((item) => item.technologyId === detection.technologyId)
        .sort(
          (a, b) =>
            textOrder(a.advisoryId ?? "", b.advisoryId ?? "") ||
            textOrder(JSON.stringify(a), JSON.stringify(b)),
        );
      const technologyCoverage = this.coverageForTechnology(coverage, correlations);
      const weakDetection = detection.detectionConfidence < this.minimumDetection;
      const packageMissing =
        mappingCandidates.length !== 1 ||
        correlations.some(
          (item) =>
            item.packageMappingId !== mapping?.mappingId ||
            mapping === undefined ||
            !samePackage(item.package, mapping.package),
        );
      const selectedVersion = Boolean(
        version?.selectedUpstreamVersion &&
        version.parsingStatus === "parsed" &&
        (version.reconciliationStatus === "single" ||
          version.reconciliationStatus === "corroborated"),
      );
      const advisoryAssessments = correlations.map((correlation) =>
        this.assessAdvisory({
          detection,
          version,
          mapping,
          correlation,
          coverage: technologyCoverage,
          ...(input.sourceIndependenceGroups
            ? { sourceIndependenceGroups: input.sourceIndependenceGroups }
            : {}),
        }),
      );
      let state: AssessmentState;
      if (weakDetection) state = "INSUFFICIENT_EVIDENCE";
      else if (packageMissing) state = "INSUFFICIENT_EVIDENCE";
      else if (correlations.some((item) => item.applicability === "CONFLICTING_EVIDENCE"))
        state = "CONFLICTING_EVIDENCE";
      else if (advisoryAssessments.some((item) => item.state === "CONFIRMED_VULNERABLE"))
        state = "CONFIRMED_VULNERABLE";
      else if (advisoryAssessments.some((item) => item.state === "LIKELY_VULNERABLE"))
        state = "LIKELY_VULNERABLE";
      else if (
        advisoryAssessments.length &&
        advisoryAssessments.every((item) => item.state === "PATCHED_BY_VENDOR")
      )
        state = "PATCHED_BY_VENDOR";
      else if (
        advisoryAssessments.length &&
        advisoryAssessments.every((item) => item.state === "PATCHED")
      )
        state = "PATCHED";
      else if (
        technologyCoverage.status === "unavailable" ||
        technologyCoverage.status === "unsupported"
      )
        state = "INTELLIGENCE_UNAVAILABLE";
      else if (!selectedVersion) state = "VERSION_UNKNOWN";
      else if (advisoryAssessments.some((item) => item.state === "INSUFFICIENT_EVIDENCE"))
        state = "INSUFFICIENT_EVIDENCE";
      else if (
        technologyCoverage.status === "partial" ||
        technologyCoverage.status === "stale" ||
        technologyCoverage.status === "unknown"
      )
        state = "INTELLIGENCE_UNAVAILABLE";
      else state = "NO_KNOWN_VULNERABILITY";
      const completeNoResult = state === "NO_KNOWN_VULNERABILITY";
      const advisoryApplicabilityScores = advisoryAssessments.map(
        (item) => item.confidence.vulnerabilityApplicability.score,
      );
      const confidence = confidenceFor({
        detection,
        ...(version ? { version } : {}),
        ...(mapping && !packageMissing ? { mapping } : {}),
        records: correlations.flatMap(sourceRecords),
        coverage: technologyCoverage,
        ...(input.sourceIndependenceGroups
          ? { sourceIndependenceGroups: input.sourceIndependenceGroups }
          : {}),
        completeNoResult,
        ...(advisoryApplicabilityScores.length
          ? { applicabilityScore: Math.min(...advisoryApplicabilityScores) }
          : {}),
        conflict: state === "CONFLICTING_EVIDENCE",
        uniqueEvidenceCount: this.uniqueEvidenceCount(detection),
      });
      if (
        state === "NO_KNOWN_VULNERABILITY" &&
        (coverage.status !== "complete" || !selectedVersion)
      )
        state = "INTELLIGENCE_UNAVAILABLE";
      const limitations = this.limitations(
        state,
        technologyCoverage,
        mappingCandidates.length,
      );
      return {
        technologyId: detection.technologyId,
        displayName: detection.displayName,
        state,
        confidence,
        explanations: [this.explainState(state, detection.technologyId)],
        detection,
        ...(version ? { versionAssessment: version } : {}),
        ...(mapping ? { packageMapping: mapping } : {}),
        advisoryAssessments,
        intelligenceCoverage: technologyCoverage,
        limitations,
      } satisfies TechnologySecurityAssessment;
    });
    const targetState = this.aggregate(technologyAssessments);
    const targetConfidence = this.aggregateConfidence(
      technologyAssessments,
      targetState,
      coverage,
    );
    const limitations = unique([
      ...technologyAssessments.flatMap((item) => item.limitations),
      ...coverage.limitations,
      ...(technologyAssessments.some((item) => item.state === "NO_KNOWN_VULNERABILITY")
        ? [
            "NO_KNOWN_VULNERABILITY is limited to the supplied package/version and requested sources; it does not mean secure or vulnerability-free.",
          ]
        : []),
    ]).sort(textOrder);
    return {
      schemaVersion: "1.0",
      assessedAt: new Date(timestamp).toISOString(),
      state: targetState,
      confidence: targetConfidence,
      explanations: [this.explainTargetState(targetState, technologyAssessments)],
      technologyAssessments,
      intelligenceCoverage: coverage,
      limitations,
    };
  }

  private assessAdvisory(args: {
    readonly detection: TechnologyDetection;
    readonly version: VersionAssessment | undefined;
    readonly mapping: TechnologyPackageIdentityMapping | undefined;
    readonly correlation: CorrelationResult;
    readonly coverage: IntelligenceCoverage;
    readonly sourceIndependenceGroups?: SecurityAssessmentInput["sourceIndependenceGroups"];
  }): AdvisoryAssessment {
    const { detection, version, mapping, correlation, coverage } = args;
    const records = correlation.sourceRecords;
    const active = records.some(advisoryActive);
    const mappingEstablished =
      mapping !== undefined &&
      correlation.packageMappingId === mapping.mappingId &&
      samePackage(correlation.package, mapping.package);
    const exactVersion = Boolean(
      version?.selectedUpstreamVersion &&
      version.parsingStatus === "parsed" &&
      version.versionConfidence >= this.confirmedVersion &&
      (version.reconciliationStatus === "single" ||
        version.reconciliationStatus === "corroborated"),
    );
    const hasCompleteNoResult =
      !records.length &&
      coverage.status === "complete" &&
      exactVersion &&
      mappingEstablished;
    const confidence = confidenceFor({
      detection,
      ...(version ? { version } : {}),
      ...(mappingEstablished && mapping ? { mapping } : {}),
      records,
      coverage,
      ...(args.sourceIndependenceGroups
        ? { sourceIndependenceGroups: args.sourceIndependenceGroups }
        : {}),
      completeNoResult: hasCompleteNoResult,
      ...(mappingEstablished &&
      (exactVersion || correlation.applicability === "PATCHED_BY_VENDOR")
        ? { applicability: correlation.applicability }
        : {}),
      conflict: correlation.applicability === "CONFLICTING_EVIDENCE",
      uniqueEvidenceCount: this.uniqueEvidenceCount(detection),
    });
    const trustedAffected = records.some(
      (record) =>
        advisoryActive(record) &&
        (record.provenance.authority === "primary" ||
          record.provenance.authority === "vendor") &&
        correlation.rangeAssessments.some(
          (range) =>
            range.providerId === record.provenance.providerId &&
            range.advisoryId === record.id &&
            range.status === "within",
        ),
    );
    const evidenceRefs = detection.matchedEvidenceReferences;
    let state: AssessmentState;
    const explanations: string[] = [];
    if (correlation.applicability === "CONFLICTING_EVIDENCE") {
      state = "CONFLICTING_EVIDENCE";
      explanations.push(
        "Phase 8 retained contradictory source applicability; no source conflict is discarded.",
      );
    } else if (correlation.applicability === "PATCHED_BY_VENDOR") {
      state = "PATCHED_BY_VENDOR";
      explanations.push(
        "Phase 8 established an exact installed vendor revision and matching official vendor patch evidence.",
      );
    } else if (correlation.applicability === "AFFECTED") {
      const qualifies =
        detection.detectionConfidence >= this.confirmedDetection &&
        exactVersion &&
        mappingEstablished &&
        trustedAffected &&
        coverage.status === "complete" &&
        !records.some((record) => !advisoryActive(record)) &&
        confidence.overall >= this.confirmedAssessment;
      state = !exactVersion
        ? "VERSION_UNKNOWN"
        : !mappingEstablished
          ? "INSUFFICIENT_EVIDENCE"
          : qualifies
            ? "CONFIRMED_VULNERABLE"
            : "LIKELY_VULNERABLE";
      explanations.push(
        qualifies
          ? "Reliable technology and version identification, explicit package identity, complete fresh intelligence, and authoritative in-range evidence satisfy the confirmed transition rules."
          : !exactVersion
            ? "Phase 8 affected evidence cannot establish applicability without a sufficiently specific parsed version."
            : !mappingEstablished
              ? "Phase 8 affected evidence cannot establish applicability without the matching explicit package mapping."
              : "Phase 8 reports an affected range, but one or more reliability, provenance, coverage, or confidence requirements for confirmation are not met.",
      );
    } else if (correlation.applicability === "POTENTIALLY_AFFECTED") {
      state = exactVersion ? "LIKELY_VULNERABLE" : "VERSION_UNKNOWN";
      explanations.push(
        exactVersion
          ? "Phase 8 potential applicability is preserved as likely, never promoted to confirmed."
          : "Potential advisory evidence cannot establish applicability without a sufficiently specific parsed version.",
      );
    } else if (
      correlation.applicability === "NOT_AFFECTED" &&
      exactVersion &&
      mappingEstablished &&
      this.hasFixedBoundary(correlation)
    ) {
      state = "PATCHED";
      explanations.push(
        "The assessed version is at or beyond an explicit fixed boundary in a retained source range.",
      );
    } else if (
      correlation.applicability === "NOT_AFFECTED" &&
      active &&
      exactVersion &&
      mappingEstablished &&
      coverage.status === "complete"
    ) {
      state = "NO_KNOWN_VULNERABILITY";
      explanations.push(
        "The supplied complete source set explicitly places this package/version outside the affected applicability evidence; no fixed version is asserted.",
      );
    } else if (correlation.applicability === "INSUFFICIENT_EVIDENCE") {
      state = "INSUFFICIENT_EVIDENCE";
      explanations.push(
        "Phase 8 could not establish the required package identity or range semantics.",
      );
    } else if (!active && hasCompleteNoResult) {
      state = "NO_KNOWN_VULNERABILITY";
      explanations.push(
        "No active source record applies in the requested complete source set; this does not indicate that the software is secure.",
      );
    } else if (
      coverage.status === "unavailable" ||
      coverage.status === "unsupported" ||
      coverage.status === "partial" ||
      coverage.status === "stale"
    ) {
      state = "INTELLIGENCE_UNAVAILABLE";
      explanations.push(
        "Available intelligence is unavailable, unsupported, incomplete, or stale; missing data is not treated as a negative finding.",
      );
    } else if (!exactVersion) {
      state = "VERSION_UNKNOWN";
      explanations.push(
        "No single sufficiently confident parsed upstream version is established.",
      );
    } else {
      state = "INSUFFICIENT_EVIDENCE";
      explanations.push(
        "The advisory does not contain enough supported range evidence to determine applicability.",
      );
    }
    explanations.push(...correlation.explanations.map((item) => item.message));
    explanations.push(
      `${evidenceRefs.length} matched technology evidence reference(s) are preserved on the parent technology assessment.`,
    );
    if (!mappingEstablished)
      explanations.push("An explicit matching package mapping is missing or ambiguous.");
    // Correlation is deliberately embedded intact so source records, severities, ranges, and provenance survive.
    return {
      ...(correlation.advisoryId ? { advisoryId: correlation.advisoryId } : {}),
      aliases: correlation.aliases,
      state,
      confidence,
      correlation,
      sourceRecords: records,
      explanations: unique(explanations).sort(textOrder),
    };
  }

  private hasFixedBoundary(correlation: CorrelationResult): boolean {
    return correlation.rangeAssessments.some((range) => {
      if (range.status !== "outside") return false;
      return range.comparisons.some((comparison) => {
        if (comparison.operator !== "<" || comparison.matched !== false) return false;
        return correlation.sourceRecords.some(
          (record) =>
            advisoryActive(record) &&
            record.provenance.providerId === range.providerId &&
            record.id === range.advisoryId &&
            record.affectedPackages.some(
              (affected) =>
                affected.fixedVersions.includes(comparison.boundary) ||
                affected.ranges.some((sourceRange) =>
                  sourceRange.events.some((event) => event.fixed === comparison.boundary),
                ),
            ),
        );
      });
    });
  }

  private collectSourceCoverage(
    input: SecurityAssessmentInput,
    at: number,
  ): AssessmentSourceCoverage[] {
    const sources = input.intelligenceResults.flatMap((result) =>
      result.sourceResults.map((source) => ({
        source,
        fallbackRetrievedAt: result.retrievedAt,
      })),
    );
    const byKey = new Map<string, AssessmentSourceCoverage>();
    for (const { source, fallbackRetrievedAt } of sources) {
      const retrievedAt = source.retrievedAt ?? fallbackRetrievedAt;
      const retrievedMs = retrievedAt === undefined ? undefined : Date.parse(retrievedAt);
      const ageMs =
        retrievedMs !== undefined && Number.isFinite(retrievedMs)
          ? Math.max(0, at - retrievedMs)
          : undefined;
      const hasRetrievableData =
        source.status === "RESULTS" ||
        source.status === "NO_RESULTS" ||
        source.status === "PARTIAL_RESULTS";
      const stale =
        hasRetrievableData &&
        (retrievedMs === undefined ||
          !Number.isFinite(retrievedMs) ||
          at - retrievedMs > this.maxAge ||
          retrievedMs > at);
      const item: AssessmentSourceCoverage = {
        providerId: source.providerId,
        status: source.status,
        ...(retrievedAt ? { retrievedAt } : {}),
        ...(source.sourceModifiedAt ? { sourceModifiedAt: source.sourceModifiedAt } : {}),
        ...(ageMs !== undefined ? { ageMs } : {}),
        stale,
        diagnostics: [...source.diagnostics].sort(textOrder),
      };
      const key = `${source.providerId}\0${source.status}\0${retrievedAt ?? ""}\0${source.sourceModifiedAt ?? ""}\0${JSON.stringify(item.diagnostics)}`;
      byKey.set(key, item);
    }
    return [...byKey.values()].sort(
      (a, b) =>
        textOrder(a.providerId, b.providerId) ||
        textOrder(a.status, b.status) ||
        textOrder(a.retrievedAt ?? "", b.retrievedAt ?? "") ||
        textOrder(JSON.stringify(a), JSON.stringify(b)),
    );
  }

  private coverage(
    sources: readonly AssessmentSourceCoverage[],
    results: SecurityAssessmentInput["intelligenceResults"],
  ): IntelligenceCoverage {
    const statuses = sources.map((source) => source.status);
    const inconsistentProviderData = results.some((result) =>
      result.sourceResults.some(
        (source) =>
          (source.status === "RESULTS" && source.advisories.length === 0) ||
          (source.status === "NO_RESULTS" && source.advisories.length > 0),
      ),
    );
    const unsupportedMappings = unique(
      results.flatMap((result) =>
        result.diagnostics.filter((item) => /unsupported|mapping/i.test(item)),
      ),
    ).sort(textOrder);
    const limitations = [
      "Coverage describes only providers requested and included in these inputs; it is not a claim that all vulnerability sources were queried.",
      "Provider absence, no-results responses, and missing advisories do not establish that software is safe.",
    ];
    let status: IntelligenceCompleteness;
    if (!sources.length || statuses.every((item) => item === "PROVIDER_UNAVAILABLE"))
      status = "unavailable";
    else if (statuses.every((item) => item === "UNSUPPORTED")) status = "unsupported";
    else if (inconsistentProviderData) status = "unknown";
    else if (sources.some((item) => item.stale)) status = "stale";
    else if (
      statuses.some(
        (item) =>
          item === "PARTIAL_RESULTS" ||
          item === "PROVIDER_UNAVAILABLE" ||
          item === "UNSUPPORTED",
      )
    )
      status = "partial";
    else if (statuses.every((item) => item === "RESULTS" || item === "NO_RESULTS"))
      status = "complete";
    else status = "unknown";
    if (status !== "complete")
      limitations.push(
        `Intelligence coverage is ${status}; absence of records cannot be interpreted as a negative result.`,
      );
    if (inconsistentProviderData)
      limitations.push(
        "A provider result status conflicts with its advisory records; no negative assessment is made from that input.",
      );
    return {
      status,
      sources,
      unsupportedMappings,
      limitations: unique(limitations).sort(textOrder),
    };
  }

  private coverageForTechnology(
    coverage: IntelligenceCoverage,
    correlations: readonly CorrelationResult[],
  ): IntelligenceCoverage {
    // Phase 8 collections do not scope source status to each package query. Keep aggregate coverage
    // conservative so a provider with no record cannot disappear from the completeness dimension.
    void correlations;
    return coverage;
  }

  private uniqueEvidenceCount(detection: TechnologyDetection): number {
    return unique(
      detection.matchedEvidenceReferences.map(
        (item) =>
          `${item.source}\0${item.type}\0${item.key ?? ""}\0${item.normalizedValue}`,
      ),
    ).length;
  }

  private aggregate(items: readonly TechnologySecurityAssessment[]): AssessmentState {
    if (!items.length) return "TECHNOLOGY_UNKNOWN";
    const states = items.map((item) => item.state);
    if (states.includes("CONFIRMED_VULNERABLE")) return "CONFIRMED_VULNERABLE";
    if (states.includes("LIKELY_VULNERABLE")) return "LIKELY_VULNERABLE";
    if (states.includes("CONFLICTING_EVIDENCE")) return "CONFLICTING_EVIDENCE";
    if (states.includes("INTELLIGENCE_UNAVAILABLE")) return "INTELLIGENCE_UNAVAILABLE";
    if (states.includes("INSUFFICIENT_EVIDENCE")) return "INSUFFICIENT_EVIDENCE";
    if (states.includes("VERSION_UNKNOWN")) return "VERSION_UNKNOWN";
    if (states.includes("PATCHED_BY_VENDOR"))
      return states.every(
        (item) => item === "PATCHED_BY_VENDOR" || item === "NO_KNOWN_VULNERABILITY",
      )
        ? "PATCHED_BY_VENDOR"
        : "INSUFFICIENT_EVIDENCE";
    if (states.includes("PATCHED"))
      return states.every(
        (item) => item === "PATCHED" || item === "NO_KNOWN_VULNERABILITY",
      )
        ? "PATCHED"
        : "INSUFFICIENT_EVIDENCE";
    if (states.every((item) => item === "NO_KNOWN_VULNERABILITY"))
      return "NO_KNOWN_VULNERABILITY";
    return "TECHNOLOGY_UNKNOWN";
  }

  private aggregateConfidence(
    items: readonly TechnologySecurityAssessment[],
    state: AssessmentState,
    coverage: IntelligenceCoverage,
  ): AssessmentConfidence {
    if (!items.length) return { ...confidenceFor({ records: [], coverage }), overall: 0 };
    // Conservative minimum retains unknown technologies instead of averaging them away.
    const weakest = [...items].sort(
      (a, b) => a.confidence.overall - b.confidence.overall,
    )[0]!.confidence;
    if (state === "CONFIRMED_VULNERABLE" || state === "LIKELY_VULNERABLE") return weakest;
    return weakest;
  }

  private limitations(
    state: AssessmentState,
    coverage: IntelligenceCoverage,
    mappingCount: number,
  ): string[] {
    const values = [...coverage.limitations];
    if (mappingCount !== 1)
      values.push(
        mappingCount
          ? "Package mapping is ambiguous."
          : "No explicit package mapping is available.",
      );
    if (state === "VERSION_UNKNOWN")
      values.push(
        "No sufficiently specific, reconciled upstream version is established for this technology.",
      );
    if (state === "INSUFFICIENT_EVIDENCE")
      values.push(
        "Available evidence does not satisfy the identity, provenance, or range requirements for a stronger conclusion.",
      );
    if (state === "CONFLICTING_EVIDENCE")
      values.push(
        "Conflicting source records or technology observations are retained and unresolved.",
      );
    if (state === "INTELLIGENCE_UNAVAILABLE")
      values.push(
        "One or more requested intelligence sources are unavailable, unsupported, partial, or stale.",
      );
    if (state === "LIKELY_VULNERABLE")
      values.push(
        "Applicability is potential or misses at least one confirmation requirement; it is not confirmed.",
      );
    if (state === "PATCHED" || state === "PATCHED_BY_VENDOR")
      values.push(
        "Patched applies only to the evaluated advisory and supplied package/version evidence; it is not a target-wide security guarantee.",
      );
    if (state === "NO_KNOWN_VULNERABILITY")
      values.push(
        "No known vulnerability was identified in the supplied sources for this package/version; this does not mean secure or vulnerability-free.",
      );
    return unique(values).sort(textOrder);
  }

  private explainState(state: AssessmentState, technologyId: string): string {
    switch (state) {
      case "CONFIRMED_VULNERABLE":
        return `${technologyId} has at least one advisory satisfying every confirmed applicability gate.`;
      case "LIKELY_VULNERABLE":
        return `${technologyId} has potential or affected advisory evidence that does not satisfy every confirmation gate.`;
      case "PATCHED":
        return `${technologyId} is at or beyond an explicit fixed boundary for the evaluated advisory evidence.`;
      case "PATCHED_BY_VENDOR":
        return `${technologyId} has an exact vendor package revision supported by Phase 8 vendor patch evidence.`;
      case "NO_KNOWN_VULNERABILITY":
        return `${technologyId} has no applicable vulnerability identified in the supplied complete source set for the assessed package/version; this does not mean secure.`;
      case "VERSION_UNKNOWN":
        return `${technologyId} was detected, but a sufficiently specific reconciled version is unavailable.`;
      case "TECHNOLOGY_UNKNOWN":
        return `No technology identity was established for ${technologyId}.`;
      case "INSUFFICIENT_EVIDENCE":
        return `${technologyId} lacks sufficient identity, package, provenance, or range evidence for a stronger assessment.`;
      case "INTELLIGENCE_UNAVAILABLE":
        return `${technologyId} cannot be assessed against a complete fresh set of requested intelligence providers.`;
      case "CONFLICTING_EVIDENCE":
        return `${technologyId} has conflicting source or observation evidence that remains unresolved.`;
    }
  }

  private explainTargetState(
    state: AssessmentState,
    technologies: readonly TechnologySecurityAssessment[],
  ): string {
    if (!technologies.length)
      return "No Phase 4 technology detections were supplied; the target status is TECHNOLOGY_UNKNOWN.";
    const unresolved = technologies
      .filter((item) =>
        ["VERSION_UNKNOWN", "INSUFFICIENT_EVIDENCE", "INTELLIGENCE_UNAVAILABLE"].includes(
          item.state,
        ),
      )
      .map((item) => item.technologyId)
      .sort(textOrder);
    const suffix = unresolved.length
      ? ` Unresolved technology assessments remain visible for: ${unresolved.join(", ")}.`
      : "";
    return `Target state ${state} follows the documented state precedence across ${technologies.length} technology assessment(s); it is not a binary secure/insecure verdict.${suffix}`;
  }
}
