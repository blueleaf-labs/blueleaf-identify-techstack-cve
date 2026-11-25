import { ApplicationError } from "../../domain/errors.js";
import type { Evidence, EvidenceCollection } from "../../domain/evidence.js";
import type {
  ContradictoryEvidence,
  EvidenceReference,
  FingerprintDefinition,
  FingerprintDefinitionSet,
  FingerprintMatchOperator,
  FingerprintResult,
  FingerprintSignalDefinition,
  TechnologyDetection,
  VersionCandidate,
} from "../../domain/fingerprints.js";
import { BUILTIN_FINGERPRINT_DEFINITIONS } from "../../fingerprinting/definitions.js";

const CONFIDENCE_DECIMALS = 3;
const CONFLICT_PENALTY = 0.65;
const KNOWN_EVIDENCE_TYPES = new Set([
  "http-status",
  "final-url",
  "content-type",
  "content-length",
  "header",
  "cookie",
  "redirect",
  "tls",
  "network",
  "timing",
  "content-marker",
  "html-meta",
  "html-generator",
  "html-title",
  "script-url",
  "stylesheet-url",
  "asset-url",
]);
const KNOWN_EVIDENCE_SOURCES = new Set([
  "probe.status",
  "probe.final-url",
  "probe.content-type",
  "probe.content-length",
  "response.headers",
  "response.cookies",
  "probe.redirect-chain",
  "probe.tls",
  "probe.network",
  "probe.timing",
  "response.body.signature",
  "html.meta",
  "html.generator",
  "html.title",
  "html.script.src",
  "html.link.stylesheet",
  "html.asset.url",
]);

interface SignalMatch {
  readonly signal: FingerprintSignalDefinition;
  readonly evidenceIndex: number;
  readonly evidence: Evidence;
}

interface DefinitionMatch {
  readonly definition: FingerprintDefinition;
  readonly signalMatches: readonly SignalMatch[];
  readonly confidence: number;
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function roundConfidence(value: number): number {
  return Number(Math.min(1, Math.max(0, value)).toFixed(CONFIDENCE_DECIMALS));
}

function combineContributions(values: readonly number[]): number {
  return 1 - values.reduce((remaining, value) => remaining * (1 - value), 1);
}

function validString(value: unknown, maxLength: number): value is string {
  return (
    typeof value === "string" && value.trim().length > 0 && value.length <= maxLength
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

function isEvidenceCollectionInput(value: unknown): value is EvidenceCollection {
  if (!isRecord(value) || value["schemaVersion"] !== "1.0") return false;
  const evidence = value["evidence"];
  const processing = value["processing"];
  if (!Array.isArray(evidence) || !isRecord(processing)) return false;
  const validEvidence = evidence.every(
    (item) =>
      isRecord(item) &&
      typeof item["type"] === "string" &&
      KNOWN_EVIDENCE_TYPES.has(item["type"]) &&
      typeof item["source"] === "string" &&
      KNOWN_EVIDENCE_SOURCES.has(item["source"]) &&
      typeof item["normalizedValue"] === "string" &&
      (item["strength"] === "direct" || item["strength"] === "derived") &&
      typeof item["reason"] === "string" &&
      (item["rawValue"] === undefined || typeof item["rawValue"] === "string") &&
      (item["key"] === undefined || typeof item["key"] === "string") &&
      (item["versionHint"] === undefined || typeof item["versionHint"] === "string") &&
      (item["technologyHint"] === undefined ||
        typeof item["technologyHint"] === "string"),
  );
  return (
    validEvidence &&
    typeof processing["bodyBytesReceived"] === "number" &&
    Number.isSafeInteger(processing["bodyBytesReceived"]) &&
    processing["bodyBytesReceived"] >= 0 &&
    typeof processing["bodyBytesExamined"] === "number" &&
    Number.isSafeInteger(processing["bodyBytesExamined"]) &&
    processing["bodyBytesExamined"] >= 0 &&
    typeof processing["bodyTruncated"] === "boolean" &&
    typeof processing["evidenceTruncated"] === "boolean"
  );
}

function isConfidence(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1;
}

function isStringArray(value: unknown): value is readonly string[] {
  return (
    Array.isArray(value) &&
    value.every((item) => typeof item === "string" && item.trim().length > 0)
  );
}

function validationErrorsForSignal(signal: unknown, path: string): string[] {
  if (!isRecord(signal)) return [`${path} must be an object.`];
  const errors: string[] = [];
  if (
    !hasOnlyKeys(signal, [
      "id",
      "evidenceTypes",
      "sources",
      "keys",
      "operator",
      "value",
      "weight",
      "reason",
    ])
  ) {
    errors.push(`${path} contains unsupported fields.`);
  }
  if (!validString(signal["id"], 64))
    errors.push(`${path}.id must be a non-empty string up to 64 characters.`);
  else if (!/^[a-z0-9][a-z0-9._-]*$/.test(signal["id"]))
    errors.push(`${path}.id must be a lowercase identifier.`);
  if (
    !Array.isArray(signal["evidenceTypes"]) ||
    signal["evidenceTypes"].length === 0 ||
    new Set(signal["evidenceTypes"]).size !== signal["evidenceTypes"].length ||
    !signal["evidenceTypes"].every(
      (type) => typeof type === "string" && KNOWN_EVIDENCE_TYPES.has(type),
    )
  ) {
    errors.push(`${path}.evidenceTypes must contain known evidence types.`);
  }
  if (
    signal["sources"] !== undefined &&
    (!isStringArray(signal["sources"]) ||
      signal["sources"].length === 0 ||
      new Set(signal["sources"]).size !== signal["sources"].length ||
      !signal["sources"].every((source) => KNOWN_EVIDENCE_SOURCES.has(source)))
  ) {
    errors.push(`${path}.sources must contain known evidence sources.`);
  }
  if (
    signal["keys"] !== undefined &&
    (!isStringArray(signal["keys"]) ||
      signal["keys"].length === 0 ||
      new Set(signal["keys"]).size !== signal["keys"].length)
  ) {
    errors.push(`${path}.keys must be a non-empty list of strings when provided.`);
  }
  if (!(
    signal["operator"] === "equals" ||
    signal["operator"] === "contains" ||
    signal["operator"] === "prefix"
  )) {
    errors.push(`${path}.operator must be equals, contains, or prefix.`);
  }
  if (!validString(signal["value"], 128))
    errors.push(`${path}.value must be a non-empty string up to 128 characters.`);
  if (!isConfidence(signal["weight"]) || signal["weight"] === 0)
    errors.push(`${path}.weight must be greater than 0 and at most 1.`);
  if (!validString(signal["reason"], 256))
    errors.push(`${path}.reason must be a non-empty string up to 256 characters.`);
  return errors;
}

/** Validate an externally supplied data-only fingerprint pack without executing it. */
export function validateFingerprintDefinitions(input: unknown): readonly string[] {
  if (!isRecord(input)) return ["Definition set must be an object."];
  const errors: string[] = [];
  if (!hasOnlyKeys(input, ["schemaVersion", "definitions"])) {
    errors.push("Definition set contains unsupported fields.");
  }
  if (input["schemaVersion"] !== "1.0") errors.push('schemaVersion must be "1.0".');
  if (!Array.isArray(input["definitions"]) || input["definitions"].length === 0) {
    errors.push("definitions must be a non-empty array.");
    return errors;
  }
  const ids = new Set<string>();
  input["definitions"].forEach((definition, definitionIndex) => {
    const path = `definitions[${definitionIndex}]`;
    if (!isRecord(definition)) {
      errors.push(`${path} must be an object.`);
      return;
    }
    if (
      !hasOnlyKeys(definition, [
        "id",
        "displayName",
        "category",
        "minimumConfidence",
        "singleSignalConfidenceCap",
        "contradicts",
        "signals",
      ])
    ) {
      errors.push(`${path} contains unsupported fields.`);
    }
    if (
      !validString(definition["id"], 64) ||
      !/^[a-z0-9][a-z0-9._-]*$/.test(definition["id"])
    ) {
      errors.push(`${path}.id must be a lowercase identifier up to 64 characters.`);
    } else if (ids.has(definition["id"])) errors.push(`${path}.id must be unique.`);
    else ids.add(definition["id"]);
    if (!validString(definition["displayName"], 128))
      errors.push(`${path}.displayName must be a non-empty string up to 128 characters.`);
    if (!validString(definition["category"], 64))
      errors.push(`${path}.category must be a non-empty string up to 64 characters.`);
    if (
      !isConfidence(definition["minimumConfidence"]) ||
      definition["minimumConfidence"] === 0
    )
      errors.push(`${path}.minimumConfidence must be greater than 0 and at most 1.`);
    if (
      !isConfidence(definition["singleSignalConfidenceCap"]) ||
      definition["singleSignalConfidenceCap"] === 0
    )
      errors.push(
        `${path}.singleSignalConfidenceCap must be greater than 0 and at most 1.`,
      );
    if (
      definition["contradicts"] !== undefined &&
      (!isStringArray(definition["contradicts"]) ||
        new Set(definition["contradicts"]).size !== definition["contradicts"].length)
    )
      errors.push(
        `${path}.contradicts must be a list of technology identifiers when provided.`,
      );
    if (!Array.isArray(definition["signals"]) || definition["signals"].length === 0) {
      errors.push(`${path}.signals must be a non-empty array.`);
      return;
    }
    const signalIds = new Set<string>();
    definition["signals"].forEach((signal, signalIndex) => {
      const signalPath = `${path}.signals[${signalIndex}]`;
      errors.push(...validationErrorsForSignal(signal, signalPath));
      if (isRecord(signal) && typeof signal["id"] === "string") {
        if (signalIds.has(signal["id"]))
          errors.push(`${signalPath}.id must be unique within its technology.`);
        signalIds.add(signal["id"]);
      }
    });
  });
  input["definitions"].forEach((definition, definitionIndex) => {
    if (!isRecord(definition) || !Array.isArray(definition["contradicts"])) return;
    for (const technologyId of definition["contradicts"]) {
      if (
        technologyId === definition["id"] ||
        typeof technologyId !== "string" ||
        !ids.has(technologyId)
      ) {
        errors.push(
          `definitions[${definitionIndex}].contradicts must reference a different known technology identifier.`,
        );
      }
    }
  });
  return errors;
}

function matchesOperator(
  evidence: Evidence,
  signal: FingerprintSignalDefinition,
  operator: FingerprintMatchOperator,
): boolean {
  if (!signal.evidenceTypes.includes(evidence.type)) return false;
  if (signal.sources !== undefined && !signal.sources.includes(evidence.source))
    return false;
  if (
    signal.keys !== undefined &&
    (evidence.key === undefined ||
      !signal.keys.some((key) => key.toLowerCase() === evidence.key?.toLowerCase()))
  ) {
    return false;
  }
  const actual = evidence.normalizedValue.normalize("NFKC").toLowerCase();
  const expected = signal.value.normalize("NFKC").toLowerCase();
  if (operator === "equals") return actual === expected;
  if (operator === "prefix") return actual.startsWith(expected);
  return actual.includes(expected);
}

function evidenceReference(evidence: Evidence, evidenceIndex: number): EvidenceReference {
  return {
    evidenceIndex,
    type: evidence.type,
    source: evidence.source,
    normalizedValue: evidence.normalizedValue,
    ...(evidence.key !== undefined ? { key: evidence.key } : {}),
  };
}

function uniqueReferences(matches: readonly SignalMatch[]): readonly EvidenceReference[] {
  const byIndex = new Map<number, EvidenceReference>();
  for (const match of matches) {
    byIndex.set(
      match.evidenceIndex,
      evidenceReference(match.evidence, match.evidenceIndex),
    );
  }
  return [...byIndex.values()].sort(
    (left, right) => left.evidenceIndex - right.evidenceIndex,
  );
}

function isVersionAssociatedWithSignal(match: SignalMatch): boolean {
  const version = match.evidence.versionHint;
  if (!version) return false;
  const escapedSignal = match.signal.value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const escapedVersion = version.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pattern = new RegExp(
    `(?:^|[^a-z0-9])${escapedSignal}(?:\\s*[/ :]\\s*|\\s+v\\s*)${escapedVersion}(?![a-z0-9.])`,
    "i",
  );
  return pattern.test(match.evidence.normalizedValue);
}

function buildVersionCandidates(
  matches: readonly SignalMatch[],
): readonly VersionCandidate[] {
  const byValue = new Map<string, { matches: SignalMatch[] }>();
  for (const match of matches) {
    if (!isVersionAssociatedWithSignal(match)) continue;
    const value = match.evidence.versionHint?.trim().toLowerCase();
    if (!value) continue;
    const existing = byValue.get(value) ?? { matches: [] };
    existing.matches.push(match);
    byValue.set(value, existing);
  }
  return [...byValue.entries()]
    .map(([value, group]) => {
      const signalWeights = new Map<string, number>();
      for (const match of group.matches) {
        signalWeights.set(
          match.signal.id,
          Math.max(signalWeights.get(match.signal.id) ?? 0, match.signal.weight),
        );
      }
      const rawConfidence = combineContributions([...signalWeights.values()]);
      const references = uniqueReferences(group.matches);
      return {
        value,
        confidence: roundConfidence(Math.min(rawConfidence, 0.65)),
        evidenceReferences: references,
      };
    })
    .sort(
      (left, right) =>
        right.confidence - left.confidence || compareText(left.value, right.value),
    );
}

function scoreDefinition(
  definition: FingerprintDefinition,
  evidence: readonly Evidence[],
): DefinitionMatch {
  const signalMatches: SignalMatch[] = [];
  const contributions = new Map<string, number>();
  for (const signal of [...definition.signals].sort((left, right) =>
    compareText(left.id, right.id),
  )) {
    const matches = evidence.flatMap((item, evidenceIndex) =>
      matchesOperator(item, signal, signal.operator)
        ? [{ signal, evidenceIndex, evidence: item }]
        : [],
    );
    if (matches.length === 0) continue;
    signalMatches.push(...matches);
    contributions.set(signal.id, signal.weight);
  }
  let confidence = combineContributions([...contributions.values()]);
  if (contributions.size === 1)
    confidence = Math.min(confidence, definition.singleSignalConfidenceCap);
  return { definition, signalMatches, confidence: roundConfidence(confidence) };
}

function snapshotDefinitions(input: FingerprintDefinitionSet): FingerprintDefinitionSet {
  const definitions = input.definitions.map((definition) =>
    Object.freeze({
      ...definition,
      ...(definition.contradicts !== undefined
        ? { contradicts: Object.freeze([...definition.contradicts]) }
        : {}),
      signals: Object.freeze(
        definition.signals.map((signal) =>
          Object.freeze({
            ...signal,
            evidenceTypes: Object.freeze([...signal.evidenceTypes]),
            ...(signal.sources !== undefined
              ? { sources: Object.freeze([...signal.sources]) }
              : {}),
            ...(signal.keys !== undefined
              ? { keys: Object.freeze([...signal.keys]) }
              : {}),
          }),
        ),
      ),
    }),
  );
  return Object.freeze({
    schemaVersion: input.schemaVersion,
    definitions: Object.freeze(definitions),
  });
}

/** Pure evidence-to-fingerprint application service. It never probes or consults external sources. */
export class FingerprintEngine {
  private readonly definitions: FingerprintDefinitionSet;

  public constructor(
    definitions: FingerprintDefinitionSet = BUILTIN_FINGERPRINT_DEFINITIONS,
  ) {
    const errors = validateFingerprintDefinitions(definitions);
    if (errors.length > 0) {
      throw new ApplicationError(
        "INVALID_CONFIGURATION",
        `Invalid fingerprint definitions: ${errors.join(" ")}`,
      );
    }
    this.definitions = snapshotDefinitions(definitions);
  }

  public fingerprint(input: EvidenceCollection): FingerprintResult {
    if (!isEvidenceCollectionInput(input)) {
      throw new ApplicationError(
        "INVALID_INPUT",
        "Fingerprint engine requires an EvidenceCollection schema version 1.0.",
      );
    }
    const matches = this.definitions.definitions
      .map((definition) => scoreDefinition(definition, input.evidence))
      .sort((left, right) => compareText(left.definition.id, right.definition.id));
    const detectionById = new Map<string, DefinitionMatch>(
      matches.map((match) => [match.definition.id, match]),
    );
    const detections: TechnologyDetection[] = [];
    for (const match of matches) {
      if (match.signalMatches.length === 0) continue;
      const contradictionMatches = (match.definition.contradicts ?? [])
        .flatMap((technologyId) => detectionById.get(technologyId)?.signalMatches ?? [])
        .sort(
          (left, right) =>
            compareText(left.signal.id, right.signal.id) ||
            left.evidenceIndex - right.evidenceIndex,
        );
      const contradictionWeights = new Map<string, number>();
      for (const technologyId of match.definition.contradicts ?? []) {
        for (const item of detectionById.get(technologyId)?.signalMatches ?? []) {
          contradictionWeights.set(
            `${technologyId}:${item.signal.id}`,
            item.signal.weight,
          );
        }
      }
      const contradictionConfidence = combineContributions([
        ...contradictionWeights.values(),
      ]);
      const detectionConfidence = roundConfidence(
        match.confidence * (1 - contradictionConfidence * CONFLICT_PENALTY),
      );
      if (detectionConfidence < match.definition.minimumConfidence) continue;

      const contradictoryIndexes = new Set(
        contradictionMatches.map((item) => item.evidenceIndex),
      );
      const versionCandidates = buildVersionCandidates(
        match.signalMatches.filter(
          (item) => !contradictoryIndexes.has(item.evidenceIndex),
        ),
      );
      const versionCandidate = versionCandidates[0];
      const contradictoryEvidence: ContradictoryEvidence[] = contradictionMatches.map(
        (item) => ({
          ...evidenceReference(item.evidence, item.evidenceIndex),
          technologyId:
            (match.definition.contradicts ?? []).find((id) =>
              detectionById.get(id)?.signalMatches.includes(item),
            ) ?? "unknown",
          signalId: item.signal.id,
        }),
      );
      const detectionReasons = [
        ...new Set(match.signalMatches.map((item) => item.signal.reason)),
        ...(contradictoryEvidence.length > 0
          ? [
              "Conflicting server evidence was observed; proxy, CDN, spoofing, or mixed infrastructure may explain it.",
            ]
          : []),
      ].sort(compareText);
      detections.push({
        technologyId: match.definition.id,
        displayName: match.definition.displayName,
        category: match.definition.category,
        ...(versionCandidate !== undefined ? { versionCandidate } : {}),
        versionCandidates,
        detectionConfidence,
        versionConfidence: versionCandidate?.confidence ?? 0,
        matchedEvidenceReferences: uniqueReferences(match.signalMatches),
        detectionReasons,
        contradictoryEvidence: contradictoryEvidence.sort(
          (left, right) =>
            compareText(left.technologyId, right.technologyId) ||
            left.evidenceIndex - right.evidenceIndex ||
            compareText(left.signalId, right.signalId),
        ),
      });
    }
    return {
      schemaVersion: "1.0",
      evidenceSchemaVersion: input.schemaVersion,
      detections: detections.sort((left, right) =>
        compareText(left.technologyId, right.technologyId),
      ),
    };
  }
}
