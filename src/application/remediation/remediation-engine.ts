import { ApplicationError } from "../../domain/errors.js";
import type {
  AssessmentState,
  TargetSecurityAssessment,
} from "../../domain/assessment.js";
import type {
  CorrelationResult,
  TechnologyPackageIdentityMapping,
} from "../../domain/correlation.js";
import type { AdvisoryReference, NormalizedAdvisory } from "../../domain/intelligence.js";
import type {
  AdvisorySeverityBand,
  ComponentLifecycleAssessment,
  ComponentLifecycleInformation,
  ComponentRemediationPlan,
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
} from "../../domain/remediation.js";
import type { VersionAssessment } from "../../domain/versions.js";
import type { VersionRange } from "../../domain/versions.js";
import type { VersionIntelligenceEngine } from "../versioning/version-engine.js";

function textOrder(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
function same(a: string, b: string): boolean {
  return a.trim().toLocaleLowerCase("en-US") === b.trim().toLocaleLowerCase("en-US");
}
function unique(values: readonly string[]): string[] {
  return [...new Set(values)].sort(textOrder);
}
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function httpsUrl(value: string | undefined): value is string {
  if (!value) return false;
  try {
    return new URL(value).protocol === "https:";
  } catch {
    return false;
  }
}
function assertInput(value: unknown): asserts value is RemediationInput {
  if (
    !isRecord(value) ||
    value["schemaVersion"] !== "1.0" ||
    !isRecord(value["securityAssessment"]) ||
    value["securityAssessment"]["schemaVersion"] !== "1.0" ||
    !isRecord(value["correlation"]) ||
    value["correlation"]["schemaVersion"] !== "1.0" ||
    value["correlation"]["fingerprintSchemaVersion"] !== "1.0" ||
    value["correlation"]["versionAssessmentSchemaVersion"] !== "1.0" ||
    value["correlation"]["intelligenceSchemaVersion"] !== "1.0" ||
    !Array.isArray(value["correlation"]["results"]) ||
    !Array.isArray(value["advisories"]) ||
    !isRecord(value["versionAssessments"]) ||
    value["versionAssessments"]["schemaVersion"] !== "1.0" ||
    value["versionAssessments"]["fingerprintSchemaVersion"] !== "1.0" ||
    !Array.isArray(value["versionAssessments"]["assessments"]) ||
    !Array.isArray(value["packageMappings"])
  ) {
    throw new ApplicationError(
      "INVALID_INPUT",
      "Remediation requires Phase 5, Phase 8, and Phase 9 schema version 1.0 inputs.",
    );
  }
  const lifecycle = value["lifecycleInformation"];
  const validLifecycle =
    lifecycle === undefined ||
    (Array.isArray(lifecycle) &&
      lifecycle.every(
        (item) =>
          isRecord(item) &&
          item["verified"] === true &&
          ["primary", "vendor"].includes(String(item["authority"])) &&
          typeof item["technologyId"] === "string" &&
          typeof item["mappingId"] === "string" &&
          typeof item["providerId"] === "string" &&
          typeof item["reference"] === "string" &&
          httpsUrl(item["reference"]) &&
          typeof item["retrievedAt"] === "string" &&
          !Number.isNaN(Date.parse(item["retrievedAt"])) &&
          ["supported", "end-of-life", "unknown"].includes(String(item["status"])),
      ));
  if (!validLifecycle)
    throw new ApplicationError(
      "INVALID_INPUT",
      "Lifecycle information must be verified, timestamped, and use HTTPS references.",
    );
}
function active(record: NormalizedAdvisory): boolean {
  return (
    (record.recordStatus === undefined || record.recordStatus === "active") &&
    record.withdrawnAt === undefined
  );
}
function terminalRecord(record: NormalizedAdvisory): boolean {
  return (
    record.recordStatus === "rejected" ||
    record.recordStatus === "withdrawn" ||
    record.withdrawnAt !== undefined
  );
}
function cpeMatches(
  mapping: TechnologyPackageIdentityMapping,
  cpe: string | undefined,
): boolean {
  if (!mapping.cpe || !cpe) return false;
  const parts = cpe.split(":");
  if (parts[0] !== "cpe") return false;
  return parts[1] === "2.3"
    ? parts.length >= 6 &&
        same(parts[3] ?? "", mapping.cpe.vendor) &&
        same(parts[4] ?? "", mapping.cpe.product)
    : parts[1]?.startsWith("/") === true &&
        parts.length >= 4 &&
        same(parts[2] ?? "", mapping.cpe.vendor) &&
        same(parts[3] ?? "", mapping.cpe.product);
}
function packageMatches(
  pkg: { ecosystem: string; name: string },
  mapping: TechnologyPackageIdentityMapping,
): boolean {
  return (
    same(pkg.ecosystem, mapping.package.ecosystem) && pkg.name === mapping.package.name
  );
}
function refsFor(record: NormalizedAdvisory): RemediationReference[] {
  const references = record.references.map((reference: AdvisoryReference) => ({
    providerId: record.provenance.providerId,
    advisoryId: record.id,
    url: reference.url,
    authority: record.provenance.authority ?? "unknown",
    authoritative:
      record.provenance.authority === "primary" ||
      record.provenance.authority === "vendor",
  }));
  if (record.provenance.recordUrl)
    references.push({
      providerId: record.provenance.providerId,
      advisoryId: record.id,
      url: record.provenance.recordUrl,
      authority: record.provenance.authority ?? "unknown",
      authoritative:
        record.provenance.authority === "primary" ||
        record.provenance.authority === "vendor",
    });
  return references.sort(
    (a, b) => textOrder(a.providerId, b.providerId) || textOrder(a.url, b.url),
  );
}
function parseSeverityBand(value: string): AdvisorySeverityBand {
  const normalized = value.trim().toUpperCase();
  if (
    normalized === "CRITICAL" ||
    normalized === "HIGH" ||
    normalized === "MEDIUM" ||
    normalized === "MODERATE" ||
    normalized === "LOW"
  )
    return normalized === "MODERATE" ? "MEDIUM" : normalized;
  const score = Number.parseFloat(value);
  if (!Number.isFinite(score) || score < 0 || score > 10) return "UNKNOWN";
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  if (score > 0) return "LOW";
  return "UNKNOWN";
}
function highestSeverity(records: readonly NormalizedAdvisory[]): AdvisorySeverityBand {
  const rank: Record<AdvisorySeverityBand, number> = {
    UNKNOWN: -1,
    LOW: 1,
    MEDIUM: 2,
    HIGH: 3,
    CRITICAL: 4,
  };
  const values = records.flatMap((record) =>
    record.severity.flatMap((item) =>
      [item.severity, item.score]
        .filter((value): value is string => value !== undefined)
        .map(parseSeverityBand),
    ),
  );
  return values.sort((a, b) => rank[b] - rank[a] || textOrder(a, b))[0] ?? "UNKNOWN";
}
function priorityFor(
  state: AssessmentState,
  severityBand: AdvisorySeverityBand,
  applicability: CorrelationResult["applicability"],
): RemediationPriority {
  let level: RemediationPriorityLevel;
  let rationale: string;
  if (
    ["AFFECTED", "CONFLICTING_EVIDENCE"].includes(applicability) &&
    ["PATCHED", "PATCHED_BY_VENDOR", "NO_KNOWN_VULNERABILITY"].includes(state)
  ) {
    level = "REVIEW";
    rationale =
      "Phase 8 applicability conflicts with the Phase 9 state; resolve the contradiction before prioritizing action.";
  } else if (["PATCHED", "PATCHED_BY_VENDOR", "NO_KNOWN_VULNERABILITY"].includes(state)) {
    level = "NONE";
    rationale =
      "The Phase 9 advisory state does not identify an outstanding applicable vulnerability.";
  } else if (state === "CONFIRMED_VULNERABLE") {
    level =
      severityBand === "CRITICAL"
        ? "P0"
        : severityBand === "HIGH"
          ? "P1"
          : severityBand === "MEDIUM"
            ? "P2"
            : severityBand === "LOW"
              ? "P3"
              : "REVIEW";
    rationale = `Priority combines confirmed applicability with ${severityBand.toLowerCase()} source severity; severity is not exploitability.`;
  } else if (state === "LIKELY_VULNERABLE") {
    level =
      severityBand === "CRITICAL" || severityBand === "HIGH"
        ? "P1"
        : severityBand === "MEDIUM"
          ? "P2"
          : severityBand === "LOW"
            ? "P3"
            : "REVIEW";
    rationale = `Priority combines likely applicability with ${severityBand.toLowerCase()} source severity; confirmation is still absent and exploitability is not assessed.`;
  } else {
    level = "REVIEW";
    rationale =
      "Uncertain, conflicting, or unavailable applicability requires review; severity alone does not establish exploitability or actionability.";
  }
  return { level, severityBand, applicabilityState: state, rationale };
}
function flattenCpe(
  record: NormalizedAdvisory,
): NonNullable<
  NormalizedAdvisory["cpeConfigurations"]
>[number]["nodes"][number]["matches"] {
  const output: NonNullable<
    NormalizedAdvisory["cpeConfigurations"]
  >[number]["nodes"][number]["matches"][number][] = [];
  const visit = (
    node: NonNullable<NormalizedAdvisory["cpeConfigurations"]>[number]["nodes"][number],
  ): void => {
    output.push(...node.matches);
    node.nodes.forEach(visit);
  };
  record.cpeConfigurations?.forEach((item) => item.nodes.forEach(visit));
  return output;
}
function rangesFromEvents(
  events: NormalizedAdvisory["affectedPackages"][number]["ranges"][number]["events"],
): VersionRange[] | undefined {
  const ranges: VersionRange[] = [];
  let introduced: string | undefined;
  if (events.length === 0) return undefined;
  for (const event of events) {
    const values = [
      event.introduced,
      event.fixed,
      event.lastAffected,
      event.limit,
    ].filter((value) => value !== undefined);
    if (values.length !== 1 || values[0] === "") return undefined;
    if (event.introduced !== undefined) {
      if (introduced !== undefined) return undefined;
      introduced = event.introduced;
      continue;
    }
    if (introduced === undefined) return undefined;
    ranges.push({
      introduced,
      ...(event.fixed !== undefined ? { fixed: event.fixed } : {}),
      ...(event.lastAffected !== undefined ? { lastAffected: event.lastAffected } : {}),
      ...(event.limit !== undefined
        ? { constraints: [{ operator: "<", version: event.limit }] }
        : {}),
    });
    introduced = undefined;
  }
  if (introduced !== undefined) ranges.push({ introduced });
  return ranges;
}

export interface RemediationEngineOptions {
  readonly maxLifecycleAgeMs?: number;
}

/** Deterministic, evidence-backed remediation planning over supplied Phase 5–9 results. */
export class RemediationEngine {
  private readonly maxLifecycleAgeMs: number;

  public constructor(
    private readonly versions: VersionIntelligenceEngine,
    options: RemediationEngineOptions = {},
  ) {
    this.maxLifecycleAgeMs = options.maxLifecycleAgeMs ?? 365 * 24 * 60 * 60 * 1000;
    if (!Number.isSafeInteger(this.maxLifecycleAgeMs) || this.maxLifecycleAgeMs < 0)
      throw new ApplicationError(
        "INVALID_CONFIGURATION",
        "Lifecycle freshness limit is invalid.",
      );
  }

  public plan(input: RemediationInput): RemediationPlanCollection {
    assertInput(input);
    const assessment = input.securityAssessment;
    const assessedAt = assessment.assessedAt;
    const versionByTechnology = new Map(
      input.versionAssessments.assessments.map((item) => [item.technologyId, item]),
    );
    const plans = assessment.technologyAssessments
      .map((technology) => {
        const mappings = input.packageMappings.filter(
          (item) => item.technologyId === technology.technologyId,
        );
        const mapping =
          mappings.length === 1 &&
          technology.packageMapping?.mappingId === mappings[0]?.mappingId
            ? mappings[0]
            : undefined;
        const version = versionByTechnology.get(technology.technologyId);
        const correlations = input.correlation.results
          .filter((item) => item.technologyId === technology.technologyId)
          .sort(
            (a, b) =>
              textOrder(a.advisoryId ?? "", b.advisoryId ?? "") ||
              textOrder(JSON.stringify(a), JSON.stringify(b)),
          );
        const lifecycle = this.lifecycleFor(
          input.lifecycleInformation ?? [],
          technology.technologyId,
          mapping?.mappingId,
          assessedAt,
        );
        const advisoryPlans = correlations
          .filter((item) => item.advisoryId !== undefined)
          .map((correlation) =>
            this.planAdvisory(input, technology, correlation, mapping, version),
          );
        const actionPlans = advisoryPlans.filter(
          (item) =>
            !["PATCH_ALREADY_APPLIED", "NO_ACTION_IDENTIFIED"].includes(item.state),
        );
        const actionable = actionPlans.filter((item) =>
          ["UPGRADE_RECOMMENDED", "VENDOR_UPDATE_REQUIRED", "ACTION_REQUIRED"].includes(
            item.state,
          ),
        );
        let state = this.componentState(
          technology.state,
          advisoryPlans,
          actionPlans,
          mapping,
          version,
        );
        let recommendedTargetVersion: MinimumSafeUpgrade | undefined;
        const target = this.aggregateUpgrade(actionable, mapping, version);
        if (target.status === "selected") {
          recommendedTargetVersion = target.value;
          state = "UPGRADE_RECOMMENDED";
        } else if (target.status === "conflict") {
          state = "MANUAL_REVIEW_REQUIRED";
        }
        if (lifecycle.status === "end-of-life") state = "MANUAL_REVIEW_REQUIRED";
        const references = this.references(advisoryPlans);
        const explanations = [
          `Remediation was derived for Phase 9 state ${technology.state}; this plan does not change that assessment.`,
          ...actionable.flatMap((item) => item.explanations),
          ...(target.status === "selected" ? [target.reason] : []),
          ...(target.status === "conflict" ? [target.reason] : []),
          ...(lifecycle.status === "end-of-life"
            ? [
                lifecycle.concern ??
                  "An authoritative lifecycle record reports end of life.",
              ]
            : []),
        ];
        const limitations = unique([
          ...technology.limitations,
          ...actionable.flatMap((item) => item.limitations),
          ...(lifecycle.status === "end-of-life" && !lifecycle.migrationPath
            ? [
                "No authoritative supported migration path was supplied; do not infer one.",
              ]
            : []),
        ]);
        return {
          technologyId: technology.technologyId,
          displayName: technology.displayName,
          state,
          securityAssessmentState: technology.state,
          ...(mapping
            ? {
                packageMappingId: mapping.mappingId,
                package: mapping.package,
                versionStrategyId: mapping.versionStrategyId,
              }
            : {}),
          ...(version?.selectedUpstreamVersion
            ? { currentUpstreamVersion: version.selectedUpstreamVersion.normalized }
            : {}),
          vendorPackageRevisions:
            version?.vendorPackageVersions.map((item) => item.rawValue).sort(textOrder) ??
            [],
          advisoryPlans,
          ...(recommendedTargetVersion ? { recommendedTargetVersion } : {}),
          lifecycle,
          references,
          followUpVerification: this.componentVerification(state, lifecycle.status),
          explanations: unique(explanations),
          limitations,
        } satisfies ComponentRemediationPlan;
      })
      .sort(
        (a, b) =>
          textOrder(a.technologyId, b.technologyId) ||
          textOrder(a.packageMappingId ?? "", b.packageMappingId ?? ""),
      );
    return {
      schemaVersion: "1.0",
      assessedAt,
      securityAssessmentState: assessment.state,
      plans,
      limitations: unique([
        "Remediation is guidance derived only from supplied Phase 5–9 data; it does not establish exploitability or alter security assessment states.",
        "No shell commands or package-manager instructions are generated. Administrators must verify distribution, package identity, repository, and installed revision.",
        ...plans.flatMap((item) => item.limitations),
      ]),
    };
  }

  private planAdvisory(
    input: RemediationInput,
    technology: TargetSecurityAssessment["technologyAssessments"][number],
    correlation: CorrelationResult,
    mapping: TechnologyPackageIdentityMapping | undefined,
    version: VersionAssessment | undefined,
  ): RemediationAdvisoryPlan {
    const advisoryAssessment = technology.advisoryAssessments.find(
      (item) =>
        item.advisoryId === correlation.advisoryId ||
        item.aliases.some((alias) => correlation.aliases.includes(alias)),
    );
    const sourceRecords = input.advisories
      .filter((record) =>
        correlation.sourceRecords.some(
          (correlated) =>
            record.provenance.providerId === correlated.provenance.providerId &&
            record.id === correlated.id,
        ),
      )
      .sort(
        (a, b) =>
          textOrder(a.provenance.providerId, b.provenance.providerId) ||
          textOrder(a.id, b.id),
      );
    const completeRecords = correlation.sourceRecords.every((record) =>
      sourceRecords.some(
        (item) =>
          item.provenance.providerId === record.provenance.providerId &&
          item.id === record.id,
      ),
    );
    const phase9State = advisoryAssessment?.state ?? technology.state;
    const confidence =
      advisoryAssessment?.confidence.overall ?? technology.confidence.overall;
    const severity = sourceRecords.map((record) => ({
      providerId: record.provenance.providerId,
      advisoryId: record.id,
      values: record.severity,
      bands: unique(
        record.severity.flatMap((item) =>
          [item.severity, item.score]
            .filter((value): value is string => value !== undefined)
            .map(parseSeverityBand),
        ),
      ) as AdvisorySeverityBand[],
    }));
    const severityBand = highestSeverity(sourceRecords);
    const priority = priorityFor(phase9State, severityBand, correlation.applicability);
    const references = sourceRecords
      .flatMap(refsFor)
      .sort((a, b) => textOrder(a.providerId, b.providerId) || textOrder(a.url, b.url));
    const explanations: string[] = [];
    const limitations: string[] = [];
    const fixedVersionEvidence = sourceRecords.flatMap((record) =>
      this.fixedEvidence(record, correlation, mapping, version),
    );
    const vendorUpdates = sourceRecords.flatMap((record) =>
      this.vendorUpdate(record, mapping),
    );
    const coverageComplete = technology.intelligenceCoverage.status === "complete";
    let minimumSafeUpgrade: MinimumSafeUpgrade | undefined;
    let state: RemediationState;
    if (["PATCHED", "PATCHED_BY_VENDOR"].includes(phase9State)) {
      const correlationContradictsPatch = ["AFFECTED", "CONFLICTING_EVIDENCE"].includes(
        correlation.applicability,
      );
      state =
        correlationContradictsPatch || !coverageComplete
          ? "MANUAL_REVIEW_REQUIRED"
          : "PATCH_ALREADY_APPLIED";
      explanations.push(
        correlationContradictsPatch
          ? `Phase 9 reports ${phase9State}, while Phase 8 reports ${correlation.applicability}; resolve the contradiction before closing the plan.`
          : !coverageComplete
            ? `Phase 9 reports ${phase9State}, but current intelligence coverage is ${technology.intelligenceCoverage.status}; revalidate before closing the plan.`
            : `Phase 9 already reports ${phase9State}; remediation preserves that state and issues no duplicate patch claim.`,
      );
    } else if (
      phase9State === "INTELLIGENCE_UNAVAILABLE" ||
      phase9State === "TECHNOLOGY_UNKNOWN"
    ) {
      state = "REMEDIATION_UNAVAILABLE";
      explanations.push(
        "Assessment or provider availability does not support evidence-backed remediation.",
      );
      limitations.push(
        "Refresh supported intelligence and establish the technology/package identity before planning changes.",
      );
    } else if (phase9State === "NO_KNOWN_VULNERABILITY") {
      state =
        coverageComplete &&
        !["AFFECTED", "CONFLICTING_EVIDENCE"].includes(correlation.applicability)
          ? "NO_ACTION_IDENTIFIED"
          : "MANUAL_REVIEW_REQUIRED";
      explanations.push(
        state === "NO_ACTION_IDENTIFIED"
          ? "Phase 9 found no applicable vulnerability in the supplied complete source set; this is not a security guarantee."
          : "Phase 9 reports no known vulnerability without complete consistent coverage; resolve the input conflict or refresh intelligence.",
      );
    } else if (sourceRecords.length > 0 && sourceRecords.every(terminalRecord)) {
      const assessmentAlreadyReportsExposure =
        ["CONFIRMED_VULNERABLE", "LIKELY_VULNERABLE"].includes(phase9State) ||
        ["AFFECTED", "CONFLICTING_EVIDENCE"].includes(correlation.applicability) ||
        !coverageComplete;
      state = assessmentAlreadyReportsExposure
        ? "MANUAL_REVIEW_REQUIRED"
        : "NO_ACTION_IDENTIFIED";
      explanations.push(
        assessmentAlreadyReportsExposure
          ? "Phase 9 reports vulnerability applicability while all supplied source records are withdrawn or rejected; resolve the source conflict before taking action."
          : "All matched advisory records are explicitly withdrawn or rejected; no active update is recommended.",
      );
    } else if (
      ["CONFLICTING_EVIDENCE", "VERSION_UNKNOWN", "INSUFFICIENT_EVIDENCE"].includes(
        phase9State,
      ) ||
      sourceRecords.some((record) => record.recordStatus === "unknown") ||
      !coverageComplete ||
      !completeRecords ||
      !mapping ||
      !version ||
      !this.hasComparableCurrentVersion(version, mapping, technology.technologyId)
    ) {
      state = "MANUAL_REVIEW_REQUIRED";
      explanations.push(
        "Conflicting, incomplete, stale, unmapped, or unparsed evidence prevents an automatic remediation recommendation.",
      );
      if (!completeRecords)
        limitations.push(
          "One or more Phase 8 source records were not supplied in the normalized advisory input.",
        );
      if (technology.intelligenceCoverage.status !== "complete")
        limitations.push(
          `Intelligence coverage is ${technology.intelligenceCoverage.status}; stale or partial data cannot support an upgrade target.`,
        );
    } else if (
      correlation.applicability === "POTENTIALLY_AFFECTED" ||
      correlation.applicability === "CONFLICTING_EVIDENCE"
    ) {
      state = "MANUAL_REVIEW_REQUIRED";
      explanations.push(
        "Phase 8 applicability is potential or conflicting; confirm package applicability before choosing an update.",
      );
    } else if (
      !["CONFIRMED_VULNERABLE", "LIKELY_VULNERABLE"].includes(phase9State) ||
      correlation.applicability !== "AFFECTED"
    ) {
      state = "NO_ACTION_IDENTIFIED";
      explanations.push(
        "No active applicable Phase 8 finding supports a remediation action for this advisory.",
      );
    } else if (
      mapping &&
      (mapping.vendor !== undefined ||
        mapping.distribution !== undefined ||
        (version?.vendorPackageVersions.length ?? 0) > 0)
    ) {
      if (vendorUpdates.length > 0) {
        state = "VENDOR_UPDATE_REQUIRED";
        explanations.push(
          "An official matching vendor package release is available; upstream version fixes are not substituted for vendor package updates.",
        );
      } else {
        state = "MANUAL_REVIEW_REQUIRED";
        explanations.push(
          "The installed package is vendor/distribution-specific, but no matching authoritative vendor fixed package revision was supplied.",
        );
        limitations.push(
          "Do not infer vendor backport status or convert an upstream fixed version into a distribution package revision.",
        );
      }
    } else {
      const selected = this.minimumSafeUpgrade(
        fixedVersionEvidence,
        sourceRecords,
        mapping,
        version,
        technology.technologyId,
      );
      if (selected.status === "selected") {
        state = "UPGRADE_RECOMMENDED";
        minimumSafeUpgrade = selected.value;
        explanations.push(selected.reason);
      } else if (selected.status === "conflict") {
        state = "MANUAL_REVIEW_REQUIRED";
        explanations.push(selected.reason);
      } else {
        state = sourceRecords.some(
          (record) =>
            active(record) &&
            (record.provenance.authority === "primary" ||
              record.provenance.authority === "vendor"),
        )
          ? "ACTION_REQUIRED"
          : "MANUAL_REVIEW_REQUIRED";
        explanations.push(
          "An active affected advisory is present, but a supported authoritative fixed version was not established.",
        );
        limitations.push(
          "Consult the source advisory and verify the publisher's supported fix; no release version is inferred.",
        );
      }
    }
    if (!sourceRecords.length && phase9State !== "NO_KNOWN_VULNERABILITY") {
      state =
        phase9State === "INTELLIGENCE_UNAVAILABLE"
          ? "REMEDIATION_UNAVAILABLE"
          : "MANUAL_REVIEW_REQUIRED";
      explanations.push(
        "No normalized advisory record matched this correlation result; no update target can be substantiated.",
      );
    }
    if (vendorUpdates.length && state === "VENDOR_UPDATE_REQUIRED")
      explanations.push(
        "Vendor package revisions are preserved as source values and require administrator verification; no package-manager command is generated.",
      );
    if (state === "UPGRADE_RECOMMENDED" && minimumSafeUpgrade)
      explanations.push(
        `The recommended upstream target ${minimumSafeUpgrade.version} was compared using Phase 5 strategy ${minimumSafeUpgrade.strategyId}.`,
      );
    return {
      ...(correlation.advisoryId ? { advisoryId: correlation.advisoryId } : {}),
      aliases: correlation.aliases,
      state,
      securityAssessmentState: phase9State,
      correlationApplicability: correlation.applicability,
      confidence,
      severity,
      highestSeverityBand: severityBand,
      exploitability: "NOT_ASSESSED",
      priority,
      fixedVersionEvidence,
      ...(minimumSafeUpgrade ? { minimumSafeUpgrade } : {}),
      vendorUpdates,
      references,
      followUpVerification: this.advisoryVerification(state, mapping, vendorUpdates),
      explanations: unique(explanations),
      limitations: unique(limitations),
      correlation,
      sourceRecords,
    };
  }

  private hasComparableCurrentVersion(
    version: VersionAssessment,
    mapping: TechnologyPackageIdentityMapping,
    technologyId: string,
  ): boolean {
    if (
      !version.selectedUpstreamVersion ||
      version.parsingStatus !== "parsed" ||
      !["single", "corroborated"].includes(version.reconciliationStatus) ||
      this.versions.strategies.forTechnology(technologyId).id !==
        mapping.versionStrategyId
    )
      return false;
    return version.candidateAssessments.some(
      (item) =>
        item.strategyId === mapping.versionStrategyId &&
        item.parsingStatus === "parsed" &&
        item.parsedUpstreamVersion?.normalized ===
          version.selectedUpstreamVersion?.normalized &&
        item.vendorPackageVersion === undefined,
    );
  }

  private fixedEvidence(
    record: NormalizedAdvisory,
    correlation: CorrelationResult,
    mapping: TechnologyPackageIdentityMapping | undefined,
    version: VersionAssessment | undefined,
  ): RemediationFixEvidence[] {
    const refs = refsFor(record);
    const authoritative =
      record.provenance.authority === "primary" ||
      record.provenance.authority === "vendor";
    const currentVersion = version?.selectedUpstreamVersion?.normalized;
    const strategyMatches =
      mapping !== undefined &&
      this.versions.strategies.forTechnology(mapping.technologyId).id ===
        mapping.versionStrategyId;
    const values: RemediationFixEvidence[] = [];
    if (mapping) {
      for (const affected of record.affectedPackages.filter((item) =>
        packageMatches(item.package, mapping),
      )) {
        const candidates = unique([
          ...affected.fixedVersions,
          ...affected.ranges.flatMap((range) =>
            range.events.flatMap((event) => (event.fixed ? [event.fixed] : [])),
          ),
        ]);
        for (const candidate of candidates) {
          const sourceRanges = affected.ranges.filter((range) =>
            range.events.some((event) => event.fixed === candidate),
          );
          const matchingEvaluation = correlation.rangeAssessments.some(
            (item) =>
              item.providerId === record.provenance.providerId &&
              item.advisoryId === record.id &&
              packageMatches(item.package, mapping) &&
              item.status === "within" &&
              (item.rangeType === "EXPLICIT_VERSION" ||
                sourceRanges.some((range) => range.type === item.rangeType)),
          );
          const supportedType = sourceRanges.some((range) =>
            mapping.supportedRangeTypes.includes(range.type as "SEMVER" | "ECOSYSTEM"),
          );
          const parsed = this.versions.strategies
            .forTechnology(mapping.technologyId)
            .parse(candidate);
          const order = currentVersion
            ? this.versions.compare(mapping.technologyId, currentVersion, "<", candidate)
            : undefined;
          const candidateValid =
            parsed.status === "parsed" &&
            parsed.vendorPackageVersion === undefined &&
            parsed.parsedUpstreamVersion?.scheme ===
              version?.selectedUpstreamVersion?.scheme;
          const eligible =
            active(record) &&
            authoritative &&
            strategyMatches &&
            supportedType &&
            matchingEvaluation &&
            candidateValid &&
            order?.status === "compared" &&
            order.matches === true;
          values.push({
            kind: "upstream-fixed-version",
            providerId: record.provenance.providerId,
            advisoryId: record.id,
            value: candidate,
            package: affected.package,
            ...(mapping.versionStrategyId
              ? { versionStrategyId: mapping.versionStrategyId }
              : {}),
            authority: record.provenance.authority ?? "unknown",
            authoritative,
            recommendationEligible: eligible,
            reason: !active(record)
              ? "Inactive source record retained without an update recommendation."
              : !authoritative
                ? "Source authority is unverified; the fixed value is preserved but not used for a recommendation."
                : !supportedType || !strategyMatches
                  ? "The package mapping has no matching Phase 5 range semantics for this fixed value."
                  : !matchingEvaluation
                    ? "Phase 8 has no matching in-range evaluation for this record, package, and fixed boundary."
                    : !candidateValid || order?.status !== "compared"
                      ? `The fixed version is unsupported by the mapped Phase 5 version strategy (parse=${parsed.status}, scheme=${parsed.parsedUpstreamVersion?.scheme ?? "unknown"}, selectedScheme=${version?.selectedUpstreamVersion?.scheme ?? "unknown"}, comparison=${order?.status ?? "unknown"}).`
                      : !order.matches
                        ? "The observed version is not below this fixed boundary; an upgrade is not recommended from this candidate."
                        : "Authoritative fixed boundary matches the mapped package and Phase 8 in-range evidence.",
            references: refs,
          });
        }
      }
    }
    for (const item of record.vendorPackageInformation ?? []) {
      if (item.recordType === "affected-release" && item.packageVersion) {
        const vendorMatch =
          mapping !== undefined &&
          mapping.vendor !== undefined &&
          mapping.distribution !== undefined &&
          same(mapping.vendor, record.provenance.providerId) &&
          record.provenance.authority === "vendor" &&
          item.providerId === record.provenance.providerId &&
          item.packageName === mapping.package.name &&
          (!item.cpe || cpeMatches(mapping, item.cpe));
        values.push({
          kind: "vendor-package-fixed-version",
          providerId: record.provenance.providerId,
          advisoryId: record.id,
          value: item.packageVersion,
          ...(mapping ? { package: mapping.package } : {}),
          authority: record.provenance.authority ?? "unknown",
          authoritative: vendorMatch,
          recommendationEligible: vendorMatch && active(record),
          reason: vendorMatch
            ? "Official vendor affected-release package revision matches the explicit vendor/distribution/package mapping."
            : "Vendor package revision is preserved but does not match a verified vendor/distribution/package identity.",
          references: refs,
        });
      }
      if (item.upstreamFix) {
        values.push({
          kind: "vendor-upstream-fix",
          providerId: record.provenance.providerId,
          advisoryId: record.id,
          value: item.upstreamFix,
          ...(mapping ? { package: mapping.package } : {}),
          ...(mapping ? { versionStrategyId: mapping.versionStrategyId } : {}),
          authority: record.provenance.authority ?? "unknown",
          authoritative: record.provenance.authority === "vendor",
          recommendationEligible: false,
          reason:
            "The vendor record's upstreamFix value is retained separately; it is not a vendor package revision or an automatic distribution update target.",
          references: refs,
        });
      }
    }
    for (const match of flattenCpe(record)) {
      if (
        match.vulnerable === false ||
        !match.versionEndExcluding ||
        !mapping ||
        !cpeMatches(mapping, match.criteria)
      )
        continue;
      values.push({
        kind: "cpe-fixed-boundary",
        providerId: record.provenance.providerId,
        advisoryId: record.id,
        value: match.versionEndExcluding,
        package: mapping.package,
        versionStrategyId: mapping.versionStrategyId,
        authority: record.provenance.authority ?? "unknown",
        authoritative,
        recommendationEligible: false,
        reason:
          "NVD CPE upper boundary is retained, but Phase 8 CPE environmental configuration remains unresolved; it cannot alone establish an upgrade target.",
        references: refs,
      });
    }
    return values.sort(
      (a, b) =>
        textOrder(a.kind, b.kind) ||
        textOrder(a.providerId, b.providerId) ||
        textOrder(a.value, b.value),
    );
  }

  private vendorUpdate(
    record: NormalizedAdvisory,
    mapping: TechnologyPackageIdentityMapping | undefined,
  ): VendorUpdateRequirement[] {
    if (
      !mapping?.vendor ||
      !mapping.distribution ||
      record.provenance.authority !== "vendor" ||
      !same(record.provenance.providerId, mapping.vendor)
    )
      return [];
    const packageRecords = (record.vendorPackageInformation ?? []).filter(
      (item) =>
        item.recordType === "affected-release" &&
        item.packageVersion !== undefined &&
        item.packageName === mapping.package.name &&
        item.providerId === record.provenance.providerId &&
        (!item.cpe || cpeMatches(mapping, item.cpe)),
    );
    if (!packageRecords.length) return [];
    return [
      {
        providerId: record.provenance.providerId,
        packageName: mapping.package.name,
        ecosystem: mapping.package.ecosystem,
        vendor: mapping.vendor,
        distribution: mapping.distribution,
        fixedPackageRevisions: unique(packageRecords.map((item) => item.packageVersion!)),
        upstreamFixes: unique(
          packageRecords
            .map((item) => item.upstreamFix)
            .filter((item): item is string => Boolean(item)),
        ),
        references: refsFor(record),
        administratorVerificationRequired: true,
        instructions: `Review the official ${mapping.vendor} advisory and apply the vendor's update for ${mapping.distribution} package ${mapping.package.name}. Verify the installed package revision against the advisory before closing the finding; no package-manager command is inferred.`,
      },
    ];
  }

  private minimumSafeUpgrade(
    evidence: readonly RemediationFixEvidence[],
    sourceRecords: readonly NormalizedAdvisory[],
    mapping: TechnologyPackageIdentityMapping,
    version: VersionAssessment,
    technologyId: string,
  ):
    | {
        readonly status: "selected";
        readonly value: MinimumSafeUpgrade;
        readonly reason: string;
      }
    | { readonly status: "conflict"; readonly reason: string }
    | { readonly status: "unavailable" } {
    const upstreamCandidates = evidence.filter(
      (item) => item.kind === "upstream-fixed-version",
    );
    if (!upstreamCandidates.length) return { status: "unavailable" };
    if (upstreamCandidates.some((item) => !item.recommendationEligible))
      return {
        status: "conflict",
        reason:
          "One or more upstream fixed-version statements lack matching authoritative Phase 8 range evidence or supported version semantics.",
      };
    const strategy = this.versions.strategies.forTechnology(technologyId);
    if (strategy.id !== mapping.versionStrategyId || !version.selectedUpstreamVersion)
      return {
        status: "conflict",
        reason:
          "Mapping and Phase 5 version strategies do not establish a common upstream version order.",
      };
    const parsed = upstreamCandidates.map((item) => ({
      item,
      result: strategy.parse(item.value),
    }));
    if (
      parsed.some(
        (item) =>
          item.result.status !== "parsed" ||
          item.result.vendorPackageVersion ||
          item.result.parsedUpstreamVersion?.scheme !==
            version.selectedUpstreamVersion?.scheme,
      )
    )
      return {
        status: "conflict",
        reason:
          "Fixed-version requirements use incomplete, vendor-specific, or incompatible version semantics; no highest version is guessed.",
      };
    let minimum = parsed[0]!;
    for (const candidate of parsed.slice(1)) {
      const order = strategy.compare(
        candidate.result.parsedUpstreamVersion!,
        minimum.result.parsedUpstreamVersion!,
      );
      if (order !== undefined && order > 0) minimum = candidate;
    }
    const normalized = minimum.result.parsedUpstreamVersion!.normalized;
    const resolution = this.candidateResolves(
      sourceRecords,
      mapping,
      normalized,
      technologyId,
    );
    if (!resolution.safe) return { status: "conflict", reason: resolution.reason };
    const sourceRequirements = unique(
      upstreamCandidates.map(
        (item) => `${item.providerId}:${item.advisoryId}=${item.value}`,
      ),
    );
    return {
      status: "selected",
      value: {
        version: normalized,
        scheme: minimum.result.parsedUpstreamVersion!.scheme,
        strategyId: strategy.id,
        sourceRequirements,
        reason: `Selected ${normalized} as the least candidate under Phase 5 strategy ${strategy.id} that meets every authoritative fixed boundary for this advisory.`,
      },
      reason: `The source fixed requirements were comparable under Phase 5 strategy ${strategy.id}; the selected boundary satisfies all of them.`,
    };
  }

  private candidateResolves(
    records: readonly NormalizedAdvisory[],
    mapping: TechnologyPackageIdentityMapping,
    candidate: string,
    technologyId: string,
  ): { readonly safe: true } | { readonly safe: false; readonly reason: string } {
    for (const record of records) {
      if (!active(record)) continue;
      for (const affected of record.affectedPackages.filter((item) =>
        packageMatches(item.package, mapping),
      )) {
        for (const range of affected.ranges) {
          if (!mapping.supportedRangeTypes.includes(range.type as "SEMVER" | "ECOSYSTEM"))
            return {
              safe: false,
              reason: `The target cannot be proven safe because ${record.provenance.providerId} uses unsupported range type ${range.type}.`,
            };
          const parsedRanges = rangesFromEvents(range.events);
          if (!parsedRanges)
            return {
              safe: false,
              reason: `The target cannot be proven safe because ${record.provenance.providerId} supplied a malformed or incomplete affected range.`,
            };
          for (const parsedRange of parsedRanges) {
            const result = this.versions.evaluateRange(
              technologyId,
              candidate,
              parsedRange,
            );
            if (result.status !== "outside")
              return {
                safe: false,
                reason: `Phase 5 could not prove that ${candidate} resolves ${record.id}; the affected range evaluated as ${result.status}.`,
              };
          }
        }
      }
    }
    return { safe: true };
  }

  private aggregateUpgrade(
    actionable: readonly RemediationAdvisoryPlan[],
    mapping: TechnologyPackageIdentityMapping | undefined,
    version: VersionAssessment | undefined,
  ):
    | {
        readonly status: "selected";
        readonly value: MinimumSafeUpgrade;
        readonly reason: string;
      }
    | { readonly status: "conflict"; readonly reason: string }
    | { readonly status: "none" } {
    if (
      !actionable.length ||
      actionable.some(
        (item) => item.state !== "UPGRADE_RECOMMENDED" || !item.minimumSafeUpgrade,
      )
    )
      return { status: "none" };
    if (!mapping || !version?.selectedUpstreamVersion)
      return {
        status: "conflict",
        reason:
          "The component has no single explicit package mapping and selected upstream version for compatible aggregation.",
      };
    const requirements = actionable.map((item) => item.minimumSafeUpgrade!);
    if (
      requirements.some(
        (item) =>
          item.strategyId !== mapping.versionStrategyId ||
          item.scheme !== version.selectedUpstreamVersion?.scheme,
      )
    )
      return {
        status: "conflict",
        reason:
          "The findings use different ecosystems, package mappings, or version strategies; they cannot share one target version.",
      };
    const parsedRequirements = requirements.map((item) =>
      this.versions.strategies.forTechnology(mapping.technologyId).parse(item.version),
    );
    if (
      parsedRequirements.some(
        (item) =>
          item.status !== "parsed" ||
          item.vendorPackageVersion ||
          item.parsedUpstreamVersion?.scheme !== version.selectedUpstreamVersion?.scheme,
      )
    )
      return {
        status: "conflict",
        reason:
          "One or more compatible-target requirements cannot be compared using the registered Phase 5 strategy.",
      };
    let candidate = parsedRequirements[0]!.parsedUpstreamVersion!;
    for (const item of parsedRequirements.slice(1)) {
      const parsed = item.parsedUpstreamVersion!;
      const order = this.versions.strategies
        .forTechnology(mapping.technologyId)
        .compare(parsed, candidate);
      if (order !== undefined && order > 0) candidate = parsed;
    }
    for (const requirement of requirements) {
      const comparison = this.versions.compare(
        mapping.technologyId,
        candidate.normalized,
        ">=",
        requirement.version,
      );
      if (comparison.status !== "compared" || comparison.matches !== true)
        return {
          status: "conflict",
          reason:
            "Phase 5 could not prove that one candidate satisfies every affected advisory's fixed-version requirement.",
        };
    }
    const sourceRequirements = unique(
      requirements.flatMap((item) => item.sourceRequirements),
    );
    const value: MinimumSafeUpgrade = {
      version: candidate.normalized,
      scheme: candidate.scheme,
      strategyId: mapping.versionStrategyId,
      sourceRequirements,
      reason: `Phase 5 strategy ${mapping.versionStrategyId} proved that ${candidate.normalized} meets every included advisory-specific fixed requirement for this exact package mapping.`,
    };
    return { status: "selected", value, reason: value.reason };
  }

  private componentState(
    assessmentState: AssessmentState,
    advisories: readonly RemediationAdvisoryPlan[],
    actionable: readonly RemediationAdvisoryPlan[],
    mapping: TechnologyPackageIdentityMapping | undefined,
    version: VersionAssessment | undefined,
  ): RemediationState {
    if (assessmentState === "INTELLIGENCE_UNAVAILABLE") return "REMEDIATION_UNAVAILABLE";
    if (!mapping) return "MANUAL_REVIEW_REQUIRED";
    if (
      [
        "CONFLICTING_EVIDENCE",
        "VERSION_UNKNOWN",
        "TECHNOLOGY_UNKNOWN",
        "INSUFFICIENT_EVIDENCE",
      ].includes(assessmentState)
    )
      return "MANUAL_REVIEW_REQUIRED";
    if (!advisories.length)
      return assessmentState === "NO_KNOWN_VULNERABILITY"
        ? "NO_ACTION_IDENTIFIED"
        : "REMEDIATION_UNAVAILABLE";
    if (advisories.every((item) => item.state === "PATCH_ALREADY_APPLIED"))
      return "PATCH_ALREADY_APPLIED";
    if (
      actionable.some(
        (item) =>
          item.state === "MANUAL_REVIEW_REQUIRED" ||
          item.state === "REMEDIATION_UNAVAILABLE",
      )
    )
      return "MANUAL_REVIEW_REQUIRED";
    if (actionable.some((item) => item.state === "VENDOR_UPDATE_REQUIRED"))
      return actionable.every((item) => item.state === "VENDOR_UPDATE_REQUIRED")
        ? "VENDOR_UPDATE_REQUIRED"
        : "MANUAL_REVIEW_REQUIRED";
    if (actionable.some((item) => item.state === "UPGRADE_RECOMMENDED"))
      return "UPGRADE_RECOMMENDED";
    if (actionable.some((item) => item.state === "ACTION_REQUIRED"))
      return "ACTION_REQUIRED";
    if (
      version &&
      advisories.every(
        (item) =>
          item.state === "NO_ACTION_IDENTIFIED" || item.state === "PATCH_ALREADY_APPLIED",
      )
    )
      return "NO_ACTION_IDENTIFIED";
    return "MANUAL_REVIEW_REQUIRED";
  }

  private lifecycleFor(
    infos: readonly ComponentLifecycleInformation[],
    technologyId: string,
    mappingId: string | undefined,
    assessedAt: string,
  ): ComponentLifecycleAssessment {
    const matches = infos.filter(
      (item) => item.technologyId === technologyId && item.mappingId === mappingId,
    );
    if (matches.length !== 1)
      return {
        status: matches.length ? "unknown" : "not-assessed",
        ...(matches.length
          ? {
              concern:
                "Lifecycle information is ambiguous; no EOL or migration recommendation is inferred.",
            }
          : {}),
      };
    const item = matches[0]!;
    const age = Date.parse(assessedAt) - Date.parse(item.retrievedAt);
    if (age < 0 || age > this.maxLifecycleAgeMs || !httpsUrl(item.reference))
      return {
        status: "unknown",
        providerId: item.providerId,
        reference: item.reference,
        concern:
          "Lifecycle evidence is stale, future-dated, or lacks a secure official reference.",
      };
    const migrationPath =
      item.status === "end-of-life" &&
      item.migrationPath &&
      httpsUrl(item.migrationPath.reference)
        ? item.migrationPath
        : undefined;
    return {
      status: item.status,
      ...(item.endOfLifeAt ? { endOfLifeAt: item.endOfLifeAt } : {}),
      providerId: item.providerId,
      reference: item.reference,
      ...(item.status === "end-of-life"
        ? {
            concern:
              "An authoritative lifecycle record identifies this component/package line as end of life.",
          }
        : {}),
      ...(migrationPath ? { migrationPath } : {}),
    };
  }

  private references(plans: readonly RemediationAdvisoryPlan[]): RemediationReference[] {
    const byKey = new Map<string, RemediationReference>();
    for (const reference of plans.flatMap((item) => item.references))
      byKey.set(
        `${reference.providerId}\0${reference.advisoryId}\0${reference.url}`,
        reference,
      );
    return [...byKey.values()].sort(
      (a, b) =>
        textOrder(a.providerId, b.providerId) ||
        textOrder(a.advisoryId, b.advisoryId) ||
        textOrder(a.url, b.url),
    );
  }

  private advisoryVerification(
    state: RemediationState,
    mapping: TechnologyPackageIdentityMapping | undefined,
    vendorUpdates: readonly VendorUpdateRequirement[],
  ): string[] {
    if (state === "UPGRADE_RECOMMENDED")
      return [
        "After the administrator-approved upgrade, verify the installed and running version against the selected fixed boundary.",
        "Refresh intelligence and rerun identification, version assessment, and vulnerability correlation to confirm the advisory no longer applies.",
      ];
    if (state === "VENDOR_UPDATE_REQUIRED")
      return [
        ...(mapping
          ? [
              `Verify distribution ${mapping.distribution ?? "(unverified)"}, package ${mapping.package.name}, and installed package revision against the official vendor advisory.`,
            ]
          : []),
        ...(vendorUpdates.length
          ? [
              "After applying the vendor update, refresh the installed package inventory and rerun correlation to verify the vendor advisory state.",
            ]
          : []),
      ];
    if (state === "ACTION_REQUIRED")
      return [
        "Review the official advisory for a supported fix and ask the system administrator to verify release availability; no version or command is inferred.",
      ];
    if (state === "MANUAL_REVIEW_REQUIRED")
      return [
        "Resolve the listed identity, version, source, lifecycle, or applicability uncertainty before making a change.",
      ];
    return [];
  }

  private componentVerification(
    state: RemediationState,
    lifecycle: ComponentLifecycleAssessment["status"],
  ): string[] {
    const output = new Set<string>();
    if (
      ["UPGRADE_RECOMMENDED", "VENDOR_UPDATE_REQUIRED", "ACTION_REQUIRED"].includes(state)
    )
      output.add(
        "After an administrator-approved change, verify the installed/running component and refresh intelligence before reevaluating the finding.",
      );
    if (lifecycle === "end-of-life")
      output.add(
        "Verify the migration destination is supported by its official lifecycle source and reassess all affected advisories after migration.",
      );
    return [...output].sort(textOrder);
  }
}
