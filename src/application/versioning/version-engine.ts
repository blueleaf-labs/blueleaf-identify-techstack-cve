import { ApplicationError } from "../../domain/errors.js";
import type {
  FingerprintResult,
  TechnologyDetection,
  VersionCandidate,
} from "../../domain/fingerprints.js";
import type {
  ObservedVersion,
  ParsedUpstreamVersion,
  VersionAssessment,
  VersionAssessmentCollection,
  VersionCandidateAssessment,
  VersionComparisonOperator,
  VersionComparisonConstraint,
  VersionParseResult,
  VersionParsingStatus,
  VersionRange,
  VersionRangeEvaluation,
} from "../../domain/versions.js";
import { VersionStrategyRegistry } from "./strategies.js";

export interface VersionComparisonResult {
  readonly status: "compared" | "unknown";
  readonly technologyId: string;
  readonly strategyId: string;
  readonly operator: VersionComparisonOperator;
  readonly left: string;
  readonly right: string;
  readonly ordering?: -1 | 0 | 1;
  readonly matches?: boolean;
  readonly reason: string;
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function recoverRawValue(
  candidate: VersionCandidate,
  referenceValue: string,
): string | undefined {
  const expression = new RegExp(
    `(?<![A-Za-z0-9])((?:v)?${escapeRegExp(candidate.value)}(?:(?:rc|alpha|beta)\\d+)?)(?![A-Za-z0-9.+-])`,
    "i",
  );
  const match = expression.exec(referenceValue);
  return match?.[1];
}

function collectObservedVersions(
  detection: TechnologyDetection,
): readonly ObservedVersion[] {
  const candidates = detection.versionCandidates ?? [];
  const sourceCandidates =
    candidates.length > 0
      ? candidates
      : detection.versionCandidate !== undefined
        ? [detection.versionCandidate]
        : [];
  const byKey = new Map<
    string,
    {
      value: ObservedVersion;
      references: Map<number, ObservedVersion["evidenceReferences"][number]>;
    }
  >();
  for (const candidate of sourceCandidates) {
    const refs = candidate.evidenceReferences ?? [];
    const observations =
      refs.length > 0
        ? refs.map((reference) => ({
            rawValue:
              recoverRawValue(candidate, reference.normalizedValue) ?? candidate.value,
            reference,
          }))
        : [{ rawValue: candidate.value, reference: undefined }];
    for (const observation of observations) {
      const key = `${candidate.value}\u0000${observation.rawValue}`;
      const existing = byKey.get(key);
      const references = existing?.references ?? new Map();
      if (observation.reference !== undefined) {
        references.set(observation.reference.evidenceIndex, observation.reference);
      }
      byKey.set(key, {
        value: {
          rawValue: observation.rawValue,
          candidateValue: candidate.value,
          confidence: Math.max(existing?.value.confidence ?? 0, candidate.confidence),
          evidenceReferences: [...references.values()].sort(
            (left, right) => left.evidenceIndex - right.evidenceIndex,
          ),
        },
        references,
      });
    }
  }
  return [...byKey.values()]
    .map(({ value }) => value)
    .sort(
      (left, right) =>
        compareText(left.candidateValue, right.candidateValue) ||
        compareText(left.rawValue, right.rawValue),
    );
}

function parseAssessment(
  observed: ObservedVersion,
  strategyId: string,
  parsed: VersionParseResult,
): VersionCandidateAssessment {
  return {
    rawObservedVersion: observed.rawValue,
    strategyId,
    parsingStatus: parsed.status,
    ...(parsed.parsedUpstreamVersion !== undefined
      ? { parsedUpstreamVersion: parsed.parsedUpstreamVersion }
      : {}),
    ...(parsed.partialUpstreamComponents !== undefined
      ? { partialUpstreamComponents: parsed.partialUpstreamComponents }
      : {}),
    ...(parsed.vendorPackageVersion !== undefined
      ? { vendorPackageVersion: parsed.vendorPackageVersion }
      : {}),
    reason: parsed.reason,
    evidenceReferences: observed.evidenceReferences,
  };
}

function overallParsingStatus(
  assessments: readonly VersionCandidateAssessment[],
): VersionParsingStatus {
  if (assessments.length === 0) return "unknown";
  const statuses = new Set(assessments.map((assessment) => assessment.parsingStatus));
  if (statuses.size === 1) return assessments[0]?.parsingStatus ?? "unknown";
  return "ambiguous";
}

function reconcile(
  observed: readonly ObservedVersion[],
  assessments: readonly VersionCandidateAssessment[],
): {
  readonly status: VersionAssessment["reconciliationStatus"];
  readonly selected?: ParsedUpstreamVersion;
} {
  if (observed.length === 0) return { status: "unavailable" };
  if (assessments.some((assessment) => assessment.parsingStatus !== "parsed")) {
    return { status: "ambiguous" };
  }
  const unique = new Map<string, ParsedUpstreamVersion>();
  for (const assessment of assessments) {
    const parsed = assessment.parsedUpstreamVersion;
    if (!parsed) return { status: "ambiguous" };
    unique.set(`${parsed.scheme}:${parsed.normalized}`, parsed);
  }
  if (unique.size > 1) return { status: "conflicting" };
  const selected = [...unique.values()][0];
  if (!selected) return { status: "ambiguous" };
  const evidenceCount = observed.reduce(
    (count, item) => count + item.evidenceReferences.length,
    0,
  );
  return {
    status: observed.length === 1 && evidenceCount <= 1 ? "single" : "corroborated",
    selected,
  };
}

function assertFingerprintInput(value: unknown): asserts value is FingerprintResult {
  if (
    !isRecord(value) ||
    value["schemaVersion"] !== "1.0" ||
    value["evidenceSchemaVersion"] !== "1.0" ||
    !Array.isArray(value["detections"])
  ) {
    throw new ApplicationError(
      "INVALID_INPUT",
      "Version engine requires a FingerprintResult schema version 1.0.",
    );
  }
  for (const detection of value["detections"]) {
    if (
      !isRecord(detection) ||
      typeof detection["technologyId"] !== "string" ||
      typeof detection["displayName"] !== "string" ||
      typeof detection["category"] !== "string" ||
      typeof detection["versionConfidence"] !== "number" ||
      !Number.isFinite(detection["versionConfidence"]) ||
      detection["versionConfidence"] < 0 ||
      detection["versionConfidence"] > 1 ||
      !Array.isArray(detection["versionCandidates"])
    ) {
      throw new ApplicationError(
        "INVALID_INPUT",
        "FingerprintResult contains a malformed technology detection.",
      );
    }
    for (const candidate of detection["versionCandidates"]) {
      if (
        !isRecord(candidate) ||
        typeof candidate["value"] !== "string" ||
        candidate["value"].length === 0 ||
        candidate["value"].length > 128 ||
        typeof candidate["confidence"] !== "number" ||
        !Number.isFinite(candidate["confidence"]) ||
        candidate["confidence"] < 0 ||
        candidate["confidence"] > 1 ||
        !Array.isArray(candidate["evidenceReferences"]) ||
        !candidate["evidenceReferences"].every(
          (reference) =>
            isRecord(reference) &&
            Number.isSafeInteger(reference["evidenceIndex"]) &&
            typeof reference["normalizedValue"] === "string" &&
            typeof reference["type"] === "string" &&
            typeof reference["source"] === "string" &&
            (reference["key"] === undefined || typeof reference["key"] === "string"),
        )
      ) {
        throw new ApplicationError(
          "INVALID_INPUT",
          "FingerprintResult contains a malformed version candidate.",
        );
      }
    }
  }
}

function comparisonMatches(
  ordering: -1 | 0 | 1,
  operator: VersionComparisonOperator,
): boolean {
  switch (operator) {
    case "<":
      return ordering < 0;
    case "<=":
      return ordering <= 0;
    case "=":
    case "==":
      return ordering === 0;
    case "!=":
      return ordering !== 0;
    case ">=":
      return ordering >= 0;
    case ">":
      return ordering > 0;
  }
}

function isComparisonOperator(value: unknown): value is VersionComparisonOperator {
  return ["<", "<=", "=", "==", "!=", ">=", ">"].includes(String(value));
}

function compareParsed(
  strategy: ReturnType<VersionStrategyRegistry["forTechnology"]>,
  left: VersionParseResult,
  right: VersionParseResult,
): -1 | 0 | 1 | undefined {
  if (
    left.status !== "parsed" ||
    right.status !== "parsed" ||
    left.vendorPackageVersion !== undefined ||
    right.vendorPackageVersion !== undefined ||
    left.parsedUpstreamVersion === undefined ||
    right.parsedUpstreamVersion === undefined
  ) {
    return undefined;
  }
  return strategy.compare(left.parsedUpstreamVersion, right.parsedUpstreamVersion);
}

/** Technology-independent version parsing, comparison, range evaluation, and reconciliation. */
export class VersionIntelligenceEngine {
  public constructor(
    public readonly strategies: VersionStrategyRegistry = new VersionStrategyRegistry(),
  ) {}

  public assess(input: FingerprintResult): VersionAssessmentCollection {
    assertFingerprintInput(input);
    const assessments = input.detections
      .map((detection) => {
        const strategy = this.strategies.forTechnology(detection.technologyId);
        const rawObservedVersions = collectObservedVersions(detection);
        const candidateAssessments = rawObservedVersions.map((observed) =>
          parseAssessment(observed, strategy.id, strategy.parse(observed.rawValue)),
        );
        const reconciled = reconcile(rawObservedVersions, candidateAssessments);
        const parsedUpstreamVersions = new Map<string, ParsedUpstreamVersion>();
        const vendorPackageVersions = new Map<
          string,
          NonNullable<VersionParseResult["vendorPackageVersion"]>
        >();
        for (const assessment of candidateAssessments) {
          const upstream = assessment.parsedUpstreamVersion;
          if (upstream)
            parsedUpstreamVersions.set(
              `${upstream.scheme}:${upstream.normalized}`,
              upstream,
            );
          const packageVersion = assessment.vendorPackageVersion;
          if (packageVersion)
            vendorPackageVersions.set(packageVersion.rawValue, packageVersion);
        }
        return {
          technologyId: detection.technologyId,
          displayName: detection.displayName,
          category: detection.category,
          versionConfidence: detection.versionConfidence,
          parsingStatus: overallParsingStatus(candidateAssessments),
          reconciliationStatus: reconciled.status,
          rawObservedVersions,
          parsedUpstreamVersions: [...parsedUpstreamVersions.values()].sort((a, b) =>
            compareText(a.normalized, b.normalized),
          ),
          vendorPackageVersions: [...vendorPackageVersions.values()].sort((a, b) =>
            compareText(a.rawValue, b.rawValue),
          ),
          candidateAssessments,
          ...(reconciled.selected !== undefined
            ? { selectedUpstreamVersion: reconciled.selected }
            : {}),
        };
      })
      .sort((left, right) => compareText(left.technologyId, right.technologyId));
    return {
      schemaVersion: "1.0",
      fingerprintSchemaVersion: input.schemaVersion,
      assessments,
    };
  }

  public compare(
    technologyId: string,
    leftValue: string,
    operator: VersionComparisonOperator,
    rightValue: string,
  ): VersionComparisonResult {
    const strategy = this.strategies.forTechnology(technologyId);
    if (!isComparisonOperator(operator)) {
      return {
        status: "unknown",
        technologyId,
        strategyId: strategy.id,
        operator,
        left: leftValue,
        right: rightValue,
        reason: "The requested comparison operator is unsupported.",
      };
    }
    const left = strategy.parse(leftValue);
    const right = strategy.parse(rightValue);
    const ordering = compareParsed(strategy, left, right);
    if (ordering === undefined) {
      return {
        status: "unknown",
        technologyId,
        strategyId: strategy.id,
        operator,
        left: leftValue,
        right: rightValue,
        reason: `Comparison is unsupported because parsing returned ${left.status} and ${right.status}, or package-specific version semantics require a vendor strategy.`,
      };
    }
    return {
      status: "compared",
      technologyId,
      strategyId: strategy.id,
      operator,
      left: leftValue,
      right: rightValue,
      ordering,
      matches: comparisonMatches(ordering, operator),
      reason:
        "Both values were parsed by the selected strategy and compared using its ordering rules.",
    };
  }

  public evaluateRange(
    technologyId: string,
    rawVersion: string,
    range: VersionRange,
  ): VersionRangeEvaluation {
    const strategy = this.strategies.forTechnology(technologyId);
    const invalid = (reason: string): VersionRangeEvaluation => ({
      status: "invalid-range",
      strategyId: strategy.id,
      rawVersion,
      reason,
      comparisons: [],
    });
    const rawRange: unknown = range;
    if (!isRecord(rawRange))
      return invalid("The supplied version range is not an object.");
    if (
      rawRange["ecosystem"] !== undefined ||
      rawRange["packageName"] !== undefined ||
      rawRange["vendor"] !== undefined ||
      rawRange["distribution"] !== undefined
    ) {
      return {
        status: "unknown",
        strategyId: strategy.id,
        rawVersion,
        reason:
          "Vendor advisory ranges require vendor/package backport evaluation, which is not implemented.",
        comparisons: [],
      };
    }
    const introduced = rawRange["introduced"];
    const fixed = rawRange["fixed"];
    const lastAffected = rawRange["lastAffected"];
    const rawConstraints = rawRange["constraints"];
    if (fixed !== undefined && lastAffected !== undefined) {
      return invalid(
        "A range cannot provide both exclusive fixed and inclusive lastAffected upper bounds.",
      );
    }
    if (
      rawConstraints !== undefined &&
      (!Array.isArray(rawConstraints) ||
        !rawConstraints.every(
          (constraint) =>
            isRecord(constraint) &&
            isComparisonOperator(constraint["operator"]) &&
            typeof constraint["version"] === "string" &&
            constraint["version"].length > 0,
        ))
    ) {
      return invalid(
        "Comparison constraints must contain supported operators and non-empty version values.",
      );
    }
    for (const boundary of [introduced, fixed, lastAffected]) {
      if (boundary !== undefined && typeof boundary !== "string") {
        return invalid("Range boundaries must be strings when provided.");
      }
    }
    const constraints = (
      Array.isArray(rawConstraints)
        ? (rawConstraints as VersionComparisonConstraint[])
        : []
    ).sort(
      (left, right) =>
        compareText(left.operator, right.operator) ||
        compareText(left.version, right.version),
    );
    if (
      introduced === undefined &&
      fixed === undefined &&
      lastAffected === undefined &&
      constraints.length === 0
    ) {
      return invalid("At least one range boundary or comparison constraint is required.");
    }
    const parsedValue = strategy.parse(rawVersion);
    if (
      parsedValue.status !== "parsed" ||
      parsedValue.vendorPackageVersion !== undefined ||
      !parsedValue.parsedUpstreamVersion
    ) {
      return {
        status: "unknown",
        strategyId: strategy.id,
        rawVersion,
        reason: `The observed version cannot be evaluated as an upstream range value (${parsedValue.status}); vendor package versions require vendor-specific range handling.`,
        comparisons: [],
      };
    }
    const comparisons: VersionRangeEvaluation["comparisons"][number][] = [];
    const check = (
      boundary: string,
      operator: VersionComparisonOperator,
    ): boolean | undefined => {
      if (operator === ">=" && boundary === "0") {
        comparisons.push({ operator, boundary, matched: true });
        return true;
      }
      const parsedBoundary = strategy.parse(boundary);
      const ordering = compareParsed(strategy, parsedValue, parsedBoundary);
      if (ordering === undefined) {
        comparisons.push({ operator, boundary });
        return undefined;
      }
      const matched = comparisonMatches(ordering, operator);
      comparisons.push({ operator, boundary, matched });
      return matched;
    };
    const checks: (boolean | undefined)[] = [];
    if (typeof introduced === "string") checks.push(check(introduced, ">="));
    if (typeof fixed === "string") checks.push(check(fixed, "<"));
    if (typeof lastAffected === "string") checks.push(check(lastAffected, "<="));
    for (const constraint of constraints) {
      checks.push(check(constraint.version, constraint.operator));
    }
    if (checks.some((result) => result === undefined)) {
      return {
        status: "unknown",
        strategyId: strategy.id,
        rawVersion,
        reason:
          "At least one range boundary or comparison constraint could not be parsed by the selected strategy.",
        comparisons,
      };
    }
    const within = checks.every((result) => result === true);
    return {
      status: within ? "within" : "outside",
      strategyId: strategy.id,
      rawVersion,
      reason: within
        ? "The version satisfies every supplied range boundary; this is mechanical range membership only."
        : "The version falls outside at least one supplied range boundary; this is not a security verdict.",
      comparisons,
    };
  }
}
