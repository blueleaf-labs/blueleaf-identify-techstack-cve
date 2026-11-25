import { ApplicationError } from "../../domain/errors.js";
import type { TechnologyDetection } from "../../domain/fingerprints.js";
import type {
  AdvisoryAffectedPackage,
  AdvisoryPackage,
  NormalizedAdvisory,
  VendorPackageInformation,
} from "../../domain/intelligence.js";
import type {
  CorrelationApplicability,
  CorrelationCollection,
  CorrelatableRangeType,
  CorrelationExplanation,
  CorrelationInput,
  CorrelationRangeAssessment,
  CorrelationResult,
  InstalledPackageIdentity,
  TechnologyPackageIdentityMapping,
} from "../../domain/correlation.js";
import type { VersionAssessment, VersionRange } from "../../domain/versions.js";
import type { VersionIntelligenceEngine } from "../versioning/version-engine.js";

function textOrder(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
function same(a: string, b: string): boolean {
  return a.trim().toLocaleLowerCase("en-US") === b.trim().toLocaleLowerCase("en-US");
}
function identifiers(record: NormalizedAdvisory): readonly string[] {
  return [record.id, ...record.aliases].map((item) => item.toUpperCase());
}
function stableUnique(records: readonly NormalizedAdvisory[]): NormalizedAdvisory[] {
  const bySourceAndContent = new Map<string, NormalizedAdvisory>();
  for (const item of records) {
    const key = `${item.provenance.providerId}\0${item.id}\0${JSON.stringify(item)}`;
    bySourceAndContent.set(key, item);
  }
  return [...bySourceAndContent.values()].sort(
    (a, b) =>
      textOrder(a.provenance.providerId, b.provenance.providerId) ||
      textOrder(a.id, b.id) ||
      textOrder(JSON.stringify(a), JSON.stringify(b)),
  );
}
function groupAliases(records: readonly NormalizedAdvisory[]): NormalizedAdvisory[][] {
  const parent = records.map((_, index) => index);
  const root = (index: number): number => {
    let current = index;
    while (parent[current] !== current) current = parent[current]!;
    while (parent[index] !== index) {
      const next = parent[index]!;
      parent[index] = current;
      index = next;
    }
    return current;
  };
  const byIdentifier = new Map<string, number>();
  records.forEach((record, index) => {
    for (const id of identifiers(record)) {
      const previous = byIdentifier.get(id);
      if (previous === undefined) byIdentifier.set(id, index);
      else {
        const a = root(index);
        const b = root(previous);
        if (a !== b) parent[Math.max(a, b)] = Math.min(a, b);
      }
    }
  });
  const groups = new Map<number, NormalizedAdvisory[]>();
  records.forEach((record, index) => {
    const key = root(index);
    const group = groups.get(key) ?? [];
    group.push(record);
    groups.set(key, group);
  });
  return [...groups.values()]
    .map((group) =>
      group.sort(
        (a, b) =>
          textOrder(a.provenance.providerId, b.provenance.providerId) ||
          textOrder(a.id, b.id),
      ),
    )
    .sort((a, b) => textOrder(canonicalId(a), canonicalId(b)));
}
function canonicalId(records: readonly NormalizedAdvisory[]): string {
  const ids = [...new Set(records.flatMap(identifiers))];
  return (ids.find((id) => /^CVE-\d{4}-\d{4,}$/.test(id)) ?? ids[0] ?? "").toUpperCase();
}
function mappingCpeMatches(
  mapping: TechnologyPackageIdentityMapping,
  cpe: string | undefined,
): boolean {
  if (!mapping.cpe || !cpe) return false;
  const parts = cpe.split(":");
  if (parts[0] !== "cpe") return false;
  if (parts[1] === "2.3")
    return (
      parts.length >= 6 &&
      same(parts[3] ?? "", mapping.cpe.vendor) &&
      same(parts[4] ?? "", mapping.cpe.product)
    );
  if (parts[1]?.startsWith("/"))
    return (
      parts.length >= 4 &&
      same(parts[2] ?? "", mapping.cpe.vendor) &&
      same(parts[3] ?? "", mapping.cpe.product)
    );
  return false;
}
type CpeMatch = NonNullable<
  NormalizedAdvisory["cpeConfigurations"]
>[number]["nodes"][number]["matches"][number];
function flattenCpeMatches(advisory: NormalizedAdvisory): CpeMatch[] {
  const matches: NonNullable<
    NormalizedAdvisory["cpeConfigurations"]
  >[number]["nodes"][number]["matches"][number][] = [];
  const visit = (
    node: NonNullable<NormalizedAdvisory["cpeConfigurations"]>[number]["nodes"][number],
  ): void => {
    matches.push(...node.matches);
    node.nodes.forEach(visit);
  };
  advisory.cpeConfigurations?.forEach((configuration) =>
    configuration.nodes.forEach(visit),
  );
  return matches;
}
function packageMatches(
  pkg: AdvisoryPackage,
  mapping: TechnologyPackageIdentityMapping,
): boolean {
  return (
    same(pkg.ecosystem, mapping.package.ecosystem) && pkg.name === mapping.package.name
  );
}
function vendorRecordMatches(
  value: VendorPackageInformation,
  mapping: TechnologyPackageIdentityMapping,
): boolean {
  return (
    (value.packageName !== undefined && value.packageName === mapping.package.name) ||
    mappingCpeMatches(mapping, value.cpe) ||
    (value.productName !== undefined &&
      mapping.vendor !== undefined &&
      same(value.productName, mapping.vendor))
  );
}
function eventRanges(
  events: readonly {
    readonly introduced?: string;
    readonly fixed?: string;
    readonly lastAffected?: string;
    readonly limit?: string;
  }[],
): { ranges: VersionRange[]; malformed: boolean } {
  const ranges: VersionRange[] = [];
  let introduced: string | undefined;
  let malformed = events.length === 0;
  for (const event of events) {
    const keys = [event.introduced, event.fixed, event.lastAffected, event.limit].filter(
      (item) => item !== undefined,
    );
    if (keys.length !== 1 || keys[0] === "") {
      malformed = true;
      continue;
    }
    if (event.introduced !== undefined) {
      if (introduced !== undefined) malformed = true;
      else introduced = event.introduced;
      continue;
    }
    if (introduced === undefined) {
      malformed = true;
      continue;
    }
    if (event.fixed !== undefined) ranges.push({ introduced, fixed: event.fixed });
    else if (event.lastAffected !== undefined)
      ranges.push({ introduced, lastAffected: event.lastAffected });
    else if (event.limit !== undefined)
      ranges.push({ introduced, constraints: [{ operator: "<", version: event.limit }] });
    introduced = undefined;
  }
  if (introduced !== undefined) ranges.push({ introduced });
  return { ranges, malformed };
}
function exactPackage(
  installed: readonly InstalledPackageIdentity[],
  mapping: TechnologyPackageIdentityMapping,
): InstalledPackageIdentity | undefined {
  return installed.find(
    (item) =>
      item.mappingId === mapping.mappingId &&
      item.verification === "authoritative-inventory" &&
      same(item.ecosystem, mapping.package.ecosystem) &&
      item.packageName === mapping.package.name &&
      mapping.vendor !== undefined &&
      mapping.distribution !== undefined &&
      same(item.vendor, mapping.vendor) &&
      same(item.distribution, mapping.distribution) &&
      item.exactPackageRevision.trim().length > 0 &&
      item.sourceId.trim().length > 0 &&
      item.recordId.trim().length > 0,
  );
}
function vendorState(
  advisory: NormalizedAdvisory,
  mapping: TechnologyPackageIdentityMapping,
  installed: InstalledPackageIdentity | undefined,
): "PATCHED_BY_VENDOR" | "NOT_AFFECTED" | "POTENTIALLY_AFFECTED" | undefined {
  if (
    !installed ||
    advisory.provenance.authority !== "vendor" ||
    mapping.vendor === undefined ||
    !same(advisory.provenance.providerId, mapping.vendor)
  )
    return undefined;
  const info = advisory.vendorPackageInformation ?? [];
  const applicable = info.filter(
    (item) =>
      vendorRecordMatches(item, mapping) &&
      mappingCpeMatches(mapping, item.cpe) &&
      (item.recordType === "affected-release" ||
        item.packageName === mapping.package.name),
  );
  if (
    applicable.some(
      (item) =>
        item.recordType === "affected-release" &&
        mappingCpeMatches(mapping, item.cpe) &&
        item.packageVersion === installed.exactPackageRevision,
    )
  )
    return "PATCHED_BY_VENDOR";
  if (
    applicable.some(
      (item) =>
        item.recordType === "package-state" &&
        item.fixState?.trim().toLowerCase() === "not affected",
    )
  )
    return "NOT_AFFECTED";
  if (
    applicable.some(
      (item) =>
        item.recordType === "package-state" &&
        item.fixState?.trim().toLowerCase() === "affected",
    )
  )
    return "POTENTIALLY_AFFECTED";
  return undefined;
}
function exactVendorPatchRecord(
  records: readonly NormalizedAdvisory[],
  mapping: TechnologyPackageIdentityMapping,
  installed: InstalledPackageIdentity | undefined,
): NormalizedAdvisory | undefined {
  return records.find(
    (record) =>
      isActive(record) && vendorState(record, mapping, installed) === "PATCHED_BY_VENDOR",
  );
}
function isActive(advisory: NormalizedAdvisory): boolean {
  return (
    advisory.recordStatus !== "rejected" &&
    advisory.recordStatus !== "withdrawn" &&
    advisory.recordStatus !== "unknown" &&
    advisory.withdrawnAt === undefined
  );
}

/** Deterministic evidence correlation; never computes an overall target security verdict. */
export class VulnerabilityCorrelationEngine {
  public constructor(private readonly versions: VersionIntelligenceEngine) {}

  public correlate(input: CorrelationInput): CorrelationCollection {
    this.validate(input);
    const assessments = new Map(
      input.versionAssessments.assessments.map((item) => [item.technologyId, item]),
    );
    const mappings = new Map<string, TechnologyPackageIdentityMapping[]>();
    for (const item of input.packageMappings) {
      const byTechnology = mappings.get(item.technologyId) ?? [];
      byTechnology.push(item);
      mappings.set(item.technologyId, byTechnology);
    }
    const installed = input.installedPackages ?? [];
    const allRecords = stableUnique(
      input.intelligenceResults.flatMap((item) => item.advisories),
    );
    const groups = groupAliases(allRecords);
    const results: CorrelationResult[] = [];
    const diagnostics: string[] = [];

    for (const detection of [...input.detections].sort((a, b) =>
      textOrder(a.technologyId, b.technologyId),
    )) {
      const technologyMappings = mappings.get(detection.technologyId) ?? [];
      const mapping = technologyMappings.length === 1 ? technologyMappings[0] : undefined;
      const assessment = assessments.get(detection.technologyId);
      if (technologyMappings.length !== 1)
        diagnostics.push(
          technologyMappings.length === 0
            ? `No explicit package identity mapping is available for ${detection.technologyId}.`
            : `Multiple package identity mappings are available for ${detection.technologyId}; correlation is ambiguous.`,
        );
      const applicableGroups = mapping
        ? groups.filter((records) =>
            records.some((record) => this.recordCanDescribePackage(record, mapping)),
          )
        : groups;
      if (applicableGroups.length === 0) {
        const explanations: CorrelationExplanation[] =
          technologyMappings.length !== 1
            ? [
                {
                  code:
                    technologyMappings.length === 0
                      ? "PACKAGE_MAPPING_MISSING"
                      : "PACKAGE_MAPPING_AMBIGUOUS",
                  message:
                    "An explicit, unique package identity mapping is required before advisory applicability can be evaluated.",
                },
              ]
            : [
                {
                  code: "NO_SOURCE_ADVISORY",
                  message:
                    "No matching source advisory record was available. This is not evidence that the package is safe.",
                  ...(mapping ? { mappingId: mapping.mappingId } : {}),
                  evidenceReferences: detection.matchedEvidenceReferences,
                },
              ];
        results.push(
          this.result(
            detection.technologyId,
            technologyMappings.length === 1 ? "UNKNOWN" : "INSUFFICIENT_EVIDENCE",
            mapping,
            undefined,
            [],
            [],
            [],
            [],
            explanations,
          ),
        );
      }
      for (const records of applicableGroups) {
        results.push(
          this.correlateAdvisory(
            detection.technologyId,
            records,
            mapping,
            technologyMappings.length > 1,
            assessment,
            installed,
            detection.matchedEvidenceReferences,
          ),
        );
      }
    }

    const finalResults = results.sort(
      (a, b) =>
        textOrder(a.technologyId, b.technologyId) ||
        textOrder(a.advisoryId ?? "", b.advisoryId ?? ""),
    );
    return {
      schemaVersion: "1.0",
      fingerprintSchemaVersion: "1.0",
      versionAssessmentSchemaVersion: input.versionAssessments.schemaVersion,
      intelligenceSchemaVersion: "1.0",
      intelligenceStatuses: input.intelligenceResults
        .map((item) => ({
          status: item.status,
          providers: item.sourceResults
            .map((source) => ({
              providerId: source.providerId,
              status: source.status,
              diagnostics: [...source.diagnostics].sort(textOrder),
            }))
            .sort((a, b) => textOrder(a.providerId, b.providerId)),
          diagnostics: [...item.diagnostics].sort(textOrder),
        }))
        .sort(
          (a, b) =>
            textOrder(a.status, b.status) ||
            textOrder(a.diagnostics.join("\0"), b.diagnostics.join("\0")) ||
            textOrder(JSON.stringify(a), JSON.stringify(b)),
        ),
      results: finalResults,
      diagnostics: [
        ...new Set([
          ...diagnostics,
          ...input.intelligenceResults.flatMap((item) => item.diagnostics),
        ]),
      ].sort(textOrder),
    };
  }

  private recordCanDescribePackage(
    advisory: NormalizedAdvisory,
    mapping: TechnologyPackageIdentityMapping,
  ): boolean {
    return (
      advisory.affectedPackages.some((item) => packageMatches(item.package, mapping)) ||
      (mapping.cpe !== undefined &&
        flattenCpeMatches(advisory).some(
          (item) =>
            item.vulnerable !== false && mappingCpeMatches(mapping, item.criteria),
        )) ||
      (advisory.vendorPackageInformation ?? []).some((item) =>
        vendorRecordMatches(item, mapping),
      )
    );
  }

  private correlateAdvisory(
    technologyId: string,
    records: readonly NormalizedAdvisory[],
    mapping: TechnologyPackageIdentityMapping | undefined,
    ambiguousMapping: boolean,
    assessment: VersionAssessment | undefined,
    installedRecords: readonly InstalledPackageIdentity[],
    detectionReferences: TechnologyDetection["matchedEvidenceReferences"],
  ): CorrelationResult {
    const id = canonicalId(records);
    const aliases = [...new Set(records.flatMap(identifiers))]
      .filter((item) => item !== id)
      .sort(textOrder);
    const explanations: CorrelationExplanation[] = [];
    const rangeAssessments: CorrelationRangeAssessment[] = [];
    const sourceSeverities = records.map((record) => ({
      providerId: record.provenance.providerId,
      advisoryId: record.id,
      values: record.severity,
    }));
    if (!mapping) {
      explanations.push({
        code: ambiguousMapping ? "PACKAGE_MAPPING_AMBIGUOUS" : "PACKAGE_MAPPING_MISSING",
        message: ambiguousMapping
          ? "Multiple explicit package mappings exist for this technology, so package identity is ambiguous."
          : "Remote technology detection does not establish canonical package identity or ecosystem.",
        evidenceReferences: detectionReferences,
      });
      return this.result(
        technologyId,
        "INSUFFICIENT_EVIDENCE",
        undefined,
        id,
        aliases,
        records,
        sourceSeverities,
        rangeAssessments,
        explanations,
      );
    }
    explanations.push({
      code: "PACKAGE_MAPPING_APPLIED",
      message: `Used explicit ${mapping.authority} mapping ${mapping.mappingId} for ${mapping.package.ecosystem}:${mapping.package.name}.`,
      mappingId: mapping.mappingId,
      evidenceReferences: detectionReferences,
    });
    const installed = exactPackage(installedRecords, mapping);
    if (
      !assessment ||
      !assessment.selectedUpstreamVersion ||
      !["single", "corroborated"].includes(assessment.reconciliationStatus) ||
      assessment.parsingStatus !== "parsed"
    ) {
      const vendorPatch = exactVendorPatchRecord(records, mapping, installed);
      if (vendorPatch) {
        explanations.push({
          code: "VENDOR_PATCH_EXACT_REVISION",
          message: `Exact authoritative package revision ${installed?.exactPackageRevision} matches the official vendor release record; this conclusion does not depend on an upstream version comparison.`,
          providerId: vendorPatch.provenance.providerId,
          sourceRecordId: vendorPatch.id,
          mappingId: mapping.mappingId,
          ...(installed
            ? {
                installedPackageSourceId: installed.sourceId,
                installedPackageRecordId: installed.recordId,
              }
            : {}),
        });
        return this.result(
          technologyId,
          "PATCHED_BY_VENDOR",
          mapping,
          id,
          aliases,
          records,
          sourceSeverities,
          rangeAssessments,
          explanations,
        );
      }
      explanations.push({
        code: "UPSTREAM_VERSION_UNAVAILABLE",
        message:
          "A single parsed Phase 5 upstream version is unavailable for comparison.",
        mappingId: mapping.mappingId,
      });
      return this.result(
        technologyId,
        "UNKNOWN",
        mapping,
        id,
        aliases,
        records,
        sourceSeverities,
        rangeAssessments,
        explanations,
      );
    }
    const strategy = this.versions.strategies.forTechnology(technologyId);
    if (strategy.id !== mapping.versionStrategyId) {
      const vendorPatch = exactVendorPatchRecord(records, mapping, installed);
      if (vendorPatch) {
        explanations.push({
          code: "VENDOR_PATCH_EXACT_REVISION",
          message: `Exact authoritative package revision ${installed?.exactPackageRevision} matches the official vendor release record; this conclusion does not depend on the mismatched upstream strategy.`,
          providerId: vendorPatch.provenance.providerId,
          sourceRecordId: vendorPatch.id,
          mappingId: mapping.mappingId,
          ...(installed
            ? {
                installedPackageSourceId: installed.sourceId,
                installedPackageRecordId: installed.recordId,
              }
            : {}),
        });
        return this.result(
          technologyId,
          "PATCHED_BY_VENDOR",
          mapping,
          id,
          aliases,
          records,
          sourceSeverities,
          rangeAssessments,
          explanations,
        );
      }
      explanations.push({
        code: "VERSION_STRATEGY_MISMATCH",
        message: `The mapping requires ${mapping.versionStrategyId}, while Phase 5 selected ${strategy.id}.`,
        mappingId: mapping.mappingId,
      });
      return this.result(
        technologyId,
        "INSUFFICIENT_EVIDENCE",
        mapping,
        id,
        aliases,
        records,
        sourceSeverities,
        rangeAssessments,
        explanations,
      );
    }
    const candidate = assessment.candidateAssessments.find(
      (item) =>
        item.strategyId === mapping.versionStrategyId &&
        item.parsingStatus === "parsed" &&
        item.parsedUpstreamVersion?.normalized ===
          assessment.selectedUpstreamVersion?.normalized,
    );
    if (!candidate) {
      explanations.push({
        code: "VERSION_PROVENANCE_MISSING",
        message:
          "The selected upstream version has no matching parsed candidate and evidence provenance under the mapped Phase 5 strategy.",
        mappingId: mapping.mappingId,
      });
      return this.result(
        technologyId,
        "UNKNOWN",
        mapping,
        id,
        aliases,
        records,
        sourceSeverities,
        rangeAssessments,
        explanations,
      );
    }
    const refs = candidate?.evidenceReferences ?? [];
    explanations.push({
      code: "VERSION_SELECTED",
      message: `Compared selected upstream version ${assessment.selectedUpstreamVersion.normalized} using Phase 5 strategy ${strategy.id}.`,
      mappingId: mapping.mappingId,
      evidenceReferences: refs,
    });
    const sourceStates: {
      providerId: string;
      advisoryId: string;
      state: CorrelationApplicability;
    }[] = [];
    const hasVendorRevision =
      assessment.vendorPackageVersions.length > 0 || mapping.distribution !== undefined;

    for (const record of records) {
      if (!isActive(record)) {
        const inactiveCode =
          record.recordStatus === "rejected"
            ? "ADVISORY_REJECTED"
            : record.recordStatus === "withdrawn" || record.withdrawnAt !== undefined
              ? "ADVISORY_WITHDRAWN"
              : "ADVISORY_STATUS_UNKNOWN";
        explanations.push({
          code: inactiveCode,
          message: `Source record ${record.id} is retained without active range conclusions because its status is rejected, withdrawn, or explicitly unknown.`,
          providerId: record.provenance.providerId,
          sourceRecordId: record.id,
        });
        sourceStates.push({
          providerId: record.provenance.providerId,
          advisoryId: record.id,
          state: "UNKNOWN",
        });
        continue;
      }
      const vendorResult = vendorState(record, mapping, installed);
      if (vendorResult) {
        sourceStates.push({
          providerId: record.provenance.providerId,
          advisoryId: record.id,
          state: vendorResult,
        });
        explanations.push({
          code: `VENDOR_${vendorResult}`,
          message:
            vendorResult === "PATCHED_BY_VENDOR"
              ? `Exact installed package revision ${installed?.exactPackageRevision} matches an official vendor affected-release record for this mapped package.`
              : `Official vendor package-state record explicitly reports ${vendorResult === "NOT_AFFECTED" ? "Not affected" : "Affected"} for the mapped package; exact installed identity is required and present.`,
          providerId: record.provenance.providerId,
          sourceRecordId: record.id,
          mappingId: mapping.mappingId,
          ...(installed
            ? {
                installedPackageSourceId: installed.sourceId,
                installedPackageRecordId: installed.recordId,
              }
            : {}),
        });
      }

      for (const affected of record.affectedPackages.filter((item) =>
        packageMatches(item.package, mapping),
      )) {
        const affectedState = this.evaluateAffectedPackage(
          record,
          affected,
          mapping,
          assessment,
          hasVendorRevision,
          refs,
          rangeAssessments,
          explanations,
        );
        if (affectedState)
          sourceStates.push({
            providerId: record.provenance.providerId,
            advisoryId: record.id,
            state: affectedState,
          });
      }
      if (mapping.cpe) {
        for (const item of flattenCpeMatches(record).filter(
          (match) =>
            match.vulnerable !== false && mappingCpeMatches(mapping, match.criteria),
        )) {
          const state = this.evaluateCpeMatch(
            record,
            item,
            mapping,
            assessment,
            hasVendorRevision,
            refs,
            rangeAssessments,
            explanations,
          );
          if (state)
            sourceStates.push({
              providerId: record.provenance.providerId,
              advisoryId: record.id,
              state,
            });
        }
      }
    }

    const perRecord = new Map<string, CorrelationApplicability[]>();
    for (const item of sourceStates) {
      const key = `${item.providerId}\0${item.advisoryId}`;
      const list = perRecord.get(key) ?? [];
      list.push(item.state);
      perRecord.set(key, list);
    }
    const states = [...perRecord.values()]
      .map((values): CorrelationApplicability =>
        values.includes("PATCHED_BY_VENDOR")
          ? "PATCHED_BY_VENDOR"
          : values.includes("AFFECTED")
            ? "AFFECTED"
            : values.includes("POTENTIALLY_AFFECTED")
              ? "POTENTIALLY_AFFECTED"
              : values.includes("NOT_AFFECTED")
                ? "NOT_AFFECTED"
                : "UNKNOWN",
      )
      .filter((item) => item !== "UNKNOWN" && item !== "INSUFFICIENT_EVIDENCE");
    let applicability: CorrelationApplicability;
    if (states.includes("PATCHED_BY_VENDOR")) {
      applicability = "PATCHED_BY_VENDOR";
      if (states.includes("AFFECTED") || states.includes("POTENTIALLY_AFFECTED"))
        explanations.push({
          code: "UPSTREAM_VENDOR_RECONCILIATION",
          message:
            "The upstream source range remains preserved as affected/potential; the exact vendor package revision matches an official vendor fixed release, so vendor patch evidence governs this package-specific applicability result.",
          providerId: "vendor",
          mappingId: mapping.mappingId,
        });
    } else if (
      (states.includes("AFFECTED") && states.includes("NOT_AFFECTED")) ||
      (states.includes("POTENTIALLY_AFFECTED") && states.includes("NOT_AFFECTED"))
    ) {
      applicability = "CONFLICTING_EVIDENCE";
      explanations.push({
        code: "SOURCE_CONFLICT",
        message:
          "Active source records disagree about this mapped package/version; all source records and range evaluations are retained.",
      });
    } else if (states.includes("AFFECTED"))
      applicability = hasVendorRevision ? "POTENTIALLY_AFFECTED" : "AFFECTED";
    else if (states.includes("POTENTIALLY_AFFECTED"))
      applicability = "POTENTIALLY_AFFECTED";
    else if (states.length > 0 && states.every((item) => item === "NOT_AFFECTED"))
      applicability = "NOT_AFFECTED";
    else applicability = "UNKNOWN";

    if (hasVendorRevision && !installed) {
      applicability =
        applicability === "AFFECTED" || applicability === "NOT_AFFECTED"
          ? "POTENTIALLY_AFFECTED"
          : applicability;
      explanations.push({
        code: "VENDOR_IDENTITY_UNVERIFIED",
        message:
          "Vendor/distribution package context is present, but no matching authoritative installed package identity/revision record permits a vendor backport conclusion.",
        mappingId: mapping.mappingId,
      });
    }
    if (states.length === 0)
      explanations.push({
        code: "NO_COMPARABLE_RANGE",
        message:
          "No active matching source record supplied a comparable affected range or explicit vendor patch state; absence is not evidence of safety.",
        mappingId: mapping.mappingId,
      });
    return this.result(
      technologyId,
      applicability,
      mapping,
      id,
      aliases,
      records,
      sourceSeverities,
      rangeAssessments,
      explanations,
    );
  }

  private evaluateAffectedPackage(
    record: NormalizedAdvisory,
    affected: AdvisoryAffectedPackage,
    mapping: TechnologyPackageIdentityMapping,
    assessment: VersionAssessment,
    hasVendorRevision: boolean,
    refs: VersionAssessment["rawObservedVersions"][number]["evidenceReferences"],
    out: CorrelationRangeAssessment[],
    explanations: CorrelationExplanation[],
  ): CorrelationApplicability | undefined {
    const version = assessment.selectedUpstreamVersion!.normalized;
    let evaluated = false;
    let anyWithin = false;
    let anyUnknown = false;
    for (const range of affected.ranges) {
      if (!mapping.supportedRangeTypes.includes(range.type as "SEMVER" | "ECOSYSTEM")) {
        anyUnknown = true;
        out.push({
          providerId: record.provenance.providerId,
          advisoryId: record.id,
          package: affected.package,
          rangeType: range.type,
          strategyId: mapping.versionStrategyId,
          status: "unknown",
          rawVersion: version,
          comparisons: [],
          reason: `Range type ${range.type} has no explicitly registered ${mapping.versionStrategyId} semantics.`,
          evidenceReferences: refs,
        });
        explanations.push({
          code: "UNSUPPORTED_RANGE_TYPE",
          message: `Source range type ${range.type} was preserved but not evaluated.`,
          providerId: record.provenance.providerId,
          sourceRecordId: record.id,
          mappingId: mapping.mappingId,
          evidenceReferences: refs,
        });
        continue;
      }
      const converted = eventRanges(range.events);
      if (converted.malformed) anyUnknown = true;
      if (converted.ranges.length === 0) {
        out.push({
          providerId: record.provenance.providerId,
          advisoryId: record.id,
          package: affected.package,
          rangeType: range.type,
          strategyId: mapping.versionStrategyId,
          status: "invalid-range",
          rawVersion: version,
          comparisons: [],
          reason: "The source range events are malformed or incomplete.",
          evidenceReferences: refs,
        });
        continue;
      }
      for (const segment of converted.ranges) {
        const evaluation = this.versions.evaluateRange(
          mapping.technologyId,
          version,
          segment,
        );
        evaluated = true;
        if (evaluation.status === "within") anyWithin = true;
        else if (evaluation.status !== "outside") anyUnknown = true;
        out.push({
          providerId: record.provenance.providerId,
          advisoryId: record.id,
          package: affected.package,
          rangeType: range.type,
          strategyId: evaluation.strategyId,
          status: evaluation.status,
          rawVersion: version,
          comparisons: evaluation.comparisons,
          reason: evaluation.reason,
          evidenceReferences: refs,
        });
        explanations.push({
          code: "OSV_RANGE_EVALUATED",
          message: `Evaluated ${range.type} event segment with Phase 5 strategy ${evaluation.strategyId}: ${evaluation.reason}`,
          providerId: record.provenance.providerId,
          sourceRecordId: record.id,
          mappingId: mapping.mappingId,
          evidenceReferences: refs,
        });
      }
    }
    if (affected.explicitVersions.length) {
      const comparisons = affected.explicitVersions.map((value) => ({
        value,
        result: this.versions.compare(mapping.technologyId, version, "=", value),
      }));
      const matches = comparisons.some((item) => item.result.matches === true);
      const comparisonsSupported = comparisons.every(
        (item) => item.result.status === "compared",
      );
      for (const item of comparisons) {
        const status =
          item.result.status !== "compared"
            ? "unknown"
            : item.result.matches
              ? "within"
              : "outside";
        const comparison = {
          operator: "=" as const,
          boundary: item.value,
          ...(item.result.matches !== undefined ? { matched: item.result.matches } : {}),
        };
        out.push({
          providerId: record.provenance.providerId,
          advisoryId: record.id,
          package: affected.package,
          rangeType: "EXPLICIT_VERSION",
          strategyId: item.result.strategyId,
          status,
          rawVersion: version,
          comparisons: [comparison],
          reason: item.result.reason,
          evidenceReferences: refs,
        });
        explanations.push({
          code: "OSV_EXPLICIT_VERSION_EVALUATED",
          message: `Compared exact source version ${item.value} with strategy ${item.result.strategyId}: ${item.result.reason}`,
          providerId: record.provenance.providerId,
          sourceRecordId: record.id,
          mappingId: mapping.mappingId,
          evidenceReferences: refs,
        });
      }
      if (matches) return hasVendorRevision ? "POTENTIALLY_AFFECTED" : "AFFECTED";
      if (!comparisonsSupported) anyUnknown = true;
      else if (affected.ranges.length === 0) evaluated = true;
    }
    if (anyWithin) return hasVendorRevision ? "POTENTIALLY_AFFECTED" : "AFFECTED";
    if (evaluated && !anyUnknown) return hasVendorRevision ? undefined : "NOT_AFFECTED";
    return undefined;
  }

  private evaluateCpeMatch(
    record: NormalizedAdvisory,
    match: NonNullable<
      NormalizedAdvisory["cpeConfigurations"]
    >[number]["nodes"][number]["matches"][number],
    mapping: TechnologyPackageIdentityMapping,
    assessment: VersionAssessment,
    hasVendorRevision: boolean,
    refs: VersionAssessment["rawObservedVersions"][number]["evidenceReferences"],
    out: CorrelationRangeAssessment[],
    explanations: CorrelationExplanation[],
  ): CorrelationApplicability | undefined {
    if (match.vulnerable === false) return undefined;
    const version = assessment.selectedUpstreamVersion!.normalized;
    const parts = match.criteria.split(":");
    const cpeVersion = parts[1] === "2.3" ? parts[5] : parts[4];
    let range: VersionRange | undefined;
    if (match.versionStartIncluding || match.versionEndExcluding)
      range = {
        ...(match.versionStartIncluding
          ? { introduced: match.versionStartIncluding }
          : {}),
        ...(match.versionEndExcluding ? { fixed: match.versionEndExcluding } : {}),
      };
    const constraints: { operator: ">" | "<="; version: string }[] = [];
    if (match.versionStartExcluding)
      constraints.push({ operator: ">", version: match.versionStartExcluding });
    if (match.versionEndIncluding)
      constraints.push({ operator: "<=", version: match.versionEndIncluding });
    if (constraints.length)
      range = {
        ...(range ?? {}),
        constraints: [...(range?.constraints ?? []), ...constraints],
      };
    if (!range && cpeVersion && cpeVersion !== "*" && cpeVersion !== "-")
      range = { constraints: [{ operator: "=", version: cpeVersion }] };
    if (!range) {
      explanations.push({
        code: "CPE_VERSION_UNBOUNDED",
        message:
          "NVD CPE product identity matched, but its version is wildcarded without comparable bounds.",
        providerId: record.provenance.providerId,
        sourceRecordId: record.id,
        mappingId: mapping.mappingId,
        evidenceReferences: refs,
      });
      return undefined;
    }
    const rangeType = mapping.cpe?.rangeType;
    if (!rangeType) return undefined;
    if (!mapping.supportedRangeTypes.includes(rangeType)) return undefined;
    const evaluation = this.versions.evaluateRange(mapping.technologyId, version, range);
    out.push({
      providerId: record.provenance.providerId,
      advisoryId: record.id,
      package: mapping.package,
      rangeType: `CPE:${rangeType}`,
      strategyId: evaluation.strategyId,
      status: evaluation.status,
      rawVersion: version,
      comparisons: evaluation.comparisons,
      reason: evaluation.reason,
      evidenceReferences: refs,
    });
    explanations.push({
      code: "NVD_CPE_EVALUATED",
      message: `NVD CPE version criteria were evaluated; environmental configuration logic remains source evidence and is not fully resolved: ${evaluation.reason}`,
      providerId: record.provenance.providerId,
      sourceRecordId: record.id,
      mappingId: mapping.mappingId,
      evidenceReferences: refs,
    });
    if (evaluation.status === "within")
      return hasVendorRevision ? "POTENTIALLY_AFFECTED" : "POTENTIALLY_AFFECTED";
    if (evaluation.status === "outside")
      return hasVendorRevision ? undefined : "NOT_AFFECTED";
    return undefined;
  }

  private result(
    technologyId: string,
    applicability: CorrelationApplicability,
    mapping: TechnologyPackageIdentityMapping | undefined,
    advisoryId: string | undefined,
    aliases: readonly string[],
    sourceRecords: readonly NormalizedAdvisory[],
    sourceSeverities: CorrelationResult["sourceSeverities"],
    rangeAssessments: readonly CorrelationRangeAssessment[],
    explanations: readonly CorrelationExplanation[],
  ): CorrelationResult {
    return {
      technologyId,
      applicability,
      ...(mapping
        ? { packageMappingId: mapping.mappingId, package: mapping.package }
        : {}),
      ...(advisoryId ? { advisoryId } : {}),
      aliases,
      sourceRecords,
      sourceSeverities,
      rangeAssessments: [...rangeAssessments].sort(
        (a, b) =>
          textOrder(a.providerId, b.providerId) ||
          textOrder(a.advisoryId, b.advisoryId) ||
          textOrder(a.rangeType, b.rangeType),
      ),
      explanations: [...explanations],
    };
  }

  private validate(input: CorrelationInput): void {
    if (
      !input ||
      input.schemaVersion !== "1.0" ||
      input.versionAssessments?.schemaVersion !== "1.0" ||
      input.versionAssessments?.fingerprintSchemaVersion !== "1.0" ||
      !Array.isArray(input.detections) ||
      !Array.isArray(input.intelligenceResults) ||
      !Array.isArray(input.packageMappings)
    )
      throw new ApplicationError(
        "INVALID_INPUT",
        "Correlation input requires Phase 4, Phase 5, and Phase 6/7 schema version 1.0 contracts.",
      );
    const mappingIds = new Set<string>();
    for (const mapping of input.packageMappings) {
      if (
        !mapping.mappingId.trim() ||
        !mapping.technologyId.trim() ||
        !mapping.package.ecosystem.trim() ||
        !mapping.package.name.trim() ||
        !["operator-verified", "upstream-documentation", "vendor-documentation"].includes(
          mapping.authority,
        ) ||
        !mapping.versionStrategyId.trim() ||
        !this.versions.strategies.byStrategyId(mapping.versionStrategyId) ||
        !Array.isArray(mapping.supportedRangeTypes) ||
        mapping.supportedRangeTypes.some(
          (type: CorrelatableRangeType) => type !== "SEMVER" && type !== "ECOSYSTEM",
        ) ||
        (mapping.cpe !== undefined &&
          (!mapping.cpe.vendor.trim() ||
            !mapping.cpe.product.trim() ||
            !mapping.cpe.rangeType ||
            !mapping.supportedRangeTypes.includes(mapping.cpe.rangeType))) ||
        mappingIds.has(mapping.mappingId)
      )
        throw new ApplicationError(
          "INVALID_INPUT",
          "Package mappings must be explicit, unique, and include a registered version strategy and range semantics.",
        );
      mappingIds.add(mapping.mappingId);
    }
    for (const result of input.intelligenceResults) {
      if (
        !result ||
        result.schemaVersion !== "1.0" ||
        !Array.isArray(result.advisories) ||
        !Array.isArray(result.sourceResults)
      )
        throw new ApplicationError(
          "INVALID_INPUT",
          "Intelligence input contains an invalid multi-source result.",
        );
      for (const advisory of result.advisories) {
        if (
          !advisory?.id ||
          !advisory.provenance?.providerId ||
          !advisory.provenance?.retrievedAt
        )
          throw new ApplicationError(
            "INVALID_INPUT",
            "Intelligence input contains a malformed source record.",
          );
      }
    }
  }
}
