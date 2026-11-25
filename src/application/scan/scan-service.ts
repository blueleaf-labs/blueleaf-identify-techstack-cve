import { ApplicationError } from "../../domain/errors.js";
import type {
  IntelligenceSourceResult,
  MultiSourceIntelligenceResult,
  NormalizedAdvisory,
} from "../../domain/intelligence.js";
import type { ScanRequest, ScanResult } from "../../domain/scan.js";
import type { AdvisoryPackageQuery } from "../../domain/intelligence.js";
import type { ScanApplicationDependencies, ScanService } from "./contracts.js";

function textOrder(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function validateRequest(value: unknown): asserts value is ScanRequest {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new ApplicationError("INVALID_INPUT", "Scan request must be a JSON object.");
  const request = value as Record<string, unknown>;
  const target = request["target"];
  if (
    request["schemaVersion"] !== "1.0" ||
    typeof target !== "object" ||
    target === null ||
    Array.isArray(target) ||
    typeof (target as Record<string, unknown>)["url"] !== "string"
  )
    throw new ApplicationError(
      "INVALID_INPUT",
      "Scan request requires schemaVersion 1.0 and target.url.",
    );
  const valueUrl = (target as Record<string, unknown>)["url"] as string;
  if (valueUrl.length > 4096)
    throw new ApplicationError(
      "INVALID_INPUT",
      "Target URL exceeds the supported length.",
    );
  let parsed: URL;
  try {
    parsed = new URL(valueUrl);
  } catch (cause) {
    throw new ApplicationError(
      "INVALID_INPUT",
      "Target must be an absolute HTTP or HTTPS URL.",
      { cause },
    );
  }
  if (
    !["http:", "https:"].includes(parsed.protocol) ||
    !parsed.hostname ||
    parsed.username.length > 0 ||
    parsed.password.length > 0
  )
    throw new ApplicationError(
      "INVALID_INPUT",
      "Target must be an absolute HTTP or HTTPS URL without credentials.",
    );
}

function publicUrl(value: string): string {
  try {
    const url = new URL(value);
    url.username = "";
    url.password = "";
    url.search = "";
    url.hash = "";
    return url.href;
  } catch {
    return "[unavailable]";
  }
}

function uniqueRecords(records: readonly NormalizedAdvisory[]): NormalizedAdvisory[] {
  const values = new Map<string, NormalizedAdvisory>();
  for (const record of records) {
    const key = `${record.provenance.providerId}\0${record.id}\0${JSON.stringify(record)}`;
    values.set(key, record);
  }
  return [...values.values()].sort(
    (left, right) =>
      textOrder(left.provenance.providerId, right.provenance.providerId) ||
      textOrder(left.id, right.id) ||
      textOrder(JSON.stringify(left), JSON.stringify(right)),
  );
}

function sourceStatus(
  rows: readonly IntelligenceSourceResult[],
  records: readonly NormalizedAdvisory[],
): IntelligenceSourceResult["status"] {
  if (rows.some((item) => item.status === "PROVIDER_UNAVAILABLE"))
    return records.length > 0 ? "PARTIAL_RESULTS" : "PROVIDER_UNAVAILABLE";
  if (rows.some((item) => item.status === "PARTIAL_RESULTS")) return "PARTIAL_RESULTS";
  if (rows.some((item) => item.status === "UNSUPPORTED"))
    return records.length > 0 ? "PARTIAL_RESULTS" : "UNSUPPORTED";
  return records.length > 0 ? "RESULTS" : "NO_RESULTS";
}

function mergedIntelligence(
  packageResult: MultiSourceIntelligenceResult,
  idResults: readonly MultiSourceIntelligenceResult[],
  retrievedAt: string,
): MultiSourceIntelligenceResult {
  const byProvider = new Map<string, IntelligenceSourceResult[]>();
  for (const source of [
    ...packageResult.sourceResults,
    ...idResults.flatMap((result) => result.sourceResults),
  ]) {
    const entries = byProvider.get(source.providerId) ?? [];
    entries.push(source);
    byProvider.set(source.providerId, entries);
  }
  const idSources = idResults.flatMap((result) => result.sourceResults);
  const sourceResults = [...byProvider.entries()]
    .sort(([left], [right]) => textOrder(left, right))
    .map(([providerId, rows]) => {
      const records = uniqueRecords(rows.flatMap((item) => item.advisories));
      const providerIdRows = idSources.filter((item) => item.providerId === providerId);
      const effectiveRows =
        providerIdRows.length === 0
          ? rows
          : providerIdRows.some((item) => item.status !== "UNSUPPORTED")
            ? providerIdRows.filter((item) => item.status !== "UNSUPPORTED")
            : providerIdRows;
      const status = sourceStatus(effectiveRows, records);
      return {
        providerId,
        status,
        advisories: records,
        ...(rows
          .map((item) => item.retrievedAt)
          .filter((item): item is string => item !== undefined)
          .sort(textOrder)
          .at(-1)
          ? {
              retrievedAt: rows
                .map((item) => item.retrievedAt)
                .filter((item): item is string => item !== undefined)
                .sort(textOrder)
                .at(-1)!,
            }
          : {}),
        diagnostics: [...new Set(effectiveRows.flatMap((item) => item.diagnostics))].sort(
          textOrder,
        ),
      } satisfies IntelligenceSourceResult;
    });
  const hasRecords = sourceResults.some((item) => item.advisories.length > 0);
  const failures = sourceResults.some((item) =>
    ["PROVIDER_UNAVAILABLE", "PARTIAL_RESULTS", "UNSUPPORTED"].includes(item.status),
  );
  const successful = sourceResults.some((item) =>
    ["RESULTS", "NO_RESULTS"].includes(item.status),
  );
  const status: MultiSourceIntelligenceResult["status"] =
    sourceResults.length === 0
      ? "INTELLIGENCE_UNAVAILABLE"
      : idResults.length === 0 && packageResult.status === "PARTIAL_RESULTS"
        ? "PARTIAL_RESULTS"
        : failures && successful
          ? "PARTIAL_RESULTS"
          : failures && !successful
            ? "PROVIDER_UNAVAILABLE"
            : hasRecords
              ? "RESULTS"
              : "NO_RESULTS";
  return {
    schemaVersion: "1.0",
    request: packageResult.request,
    status,
    sourceResults,
    advisories: uniqueRecords(sourceResults.flatMap((item) => item.advisories)),
    retrievedAt,
    diagnostics: [
      ...new Set([
        ...packageResult.diagnostics,
        ...idResults.flatMap((item) => item.diagnostics),
      ]),
    ].sort(textOrder),
  };
}

function lookupIdentifiers(
  records: readonly NormalizedAdvisory[],
  maximum: number,
): string[] {
  return [...new Set(records.flatMap((item) => [item.id, ...item.aliases]))]
    .filter((item) => /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(item))
    .sort(textOrder)
    .slice(0, maximum);
}

function packageQueries(
  versions: ScanResult["versions"],
  mappings: ScanApplicationDependencies["packageMappings"],
): AdvisoryPackageQuery[] {
  const assessmentsByTechnology = new Map(
    versions.assessments.map((item) => [item.technologyId, item]),
  );
  const mappingCounts = new Map<string, number>();
  for (const mapping of mappings)
    mappingCounts.set(
      mapping.technologyId,
      (mappingCounts.get(mapping.technologyId) ?? 0) + 1,
    );
  return mappings
    .filter((mapping) => mappingCounts.get(mapping.technologyId) === 1)
    .flatMap((mapping) => {
      const assessment = assessmentsByTechnology.get(mapping.technologyId);
      if (
        !assessment?.selectedUpstreamVersion ||
        !["single", "corroborated"].includes(assessment.reconciliationStatus) ||
        assessment.vendorPackageVersions.length > 0
      )
        return [];
      return [
        {
          ecosystem: mapping.package.ecosystem,
          name: mapping.package.name,
          version: assessment.selectedUpstreamVersion.normalized,
        },
      ];
    })
    .sort(
      (left, right) =>
        textOrder(left.ecosystem, right.ecosystem) ||
        textOrder(left.name, right.name) ||
        textOrder(left.version, right.version),
    );
}

/** Shared Phase 2–10 orchestration. It contains no CLI/API or provider-specific logic. */
export class ScanApplicationService implements ScanService {
  private readonly now: () => Date;
  private readonly maxAdvisoryLookups: number;

  public constructor(private readonly dependencies: ScanApplicationDependencies) {
    this.now = dependencies.now ?? ((): Date => new Date());
    this.maxAdvisoryLookups = dependencies.maxAdvisoryLookups ?? 20;
    if (
      !Number.isSafeInteger(this.maxAdvisoryLookups) ||
      this.maxAdvisoryLookups < 0 ||
      this.maxAdvisoryLookups > 100
    )
      throw new ApplicationError(
        "INVALID_CONFIGURATION",
        "Advisory lookup limit must be between 0 and 100.",
      );
  }

  public async scan(request: ScanRequest, signal?: AbortSignal): Promise<ScanResult> {
    validateRequest(request);
    const ensureActive = (): void => {
      if (signal?.aborted) throw new ApplicationError("CANCELLED", "Scan was cancelled.");
    };
    ensureActive();
    const response = await this.dependencies.http.request({
      url: request.target.url,
      method: "GET",
      timeoutMs: this.dependencies.probeTimeoutMs,
      ...(signal ? { signal } : {}),
    });
    ensureActive();
    const evidence = this.dependencies.evidence.collect(response);
    const fingerprint = this.dependencies.fingerprinting.fingerprint(evidence);
    const versions = this.dependencies.versions.assess(fingerprint);
    ensureActive();
    const queries = packageQueries(versions, this.dependencies.packageMappings);
    const packageResult =
      queries.length > 0
        ? await this.dependencies.intelligence.resolveMultiSourceQueries(
            queries,
            undefined,
            signal,
          )
        : {
            schemaVersion: "1.0" as const,
            request: { kind: "package-version-batch" as const, queries: [] },
            status: "INTELLIGENCE_UNAVAILABLE" as const,
            sourceResults: [],
            advisories: [],
            retrievedAt: this.now().toISOString(),
            diagnostics: [
              "No unique explicit package mapping with a reconciled upstream version was available; advisory lookup was not guessed.",
            ],
          };
    ensureActive();
    const allIds = lookupIdentifiers(packageResult.advisories, Number.MAX_SAFE_INTEGER);
    const ids = allIds.slice(0, this.maxAdvisoryLookups);
    const lookupProviderIds = packageResult.sourceResults
      .filter((item) => item.status === "UNSUPPORTED")
      .map((item) => item.providerId)
      .sort(textOrder);
    const idResults: MultiSourceIntelligenceResult[] = [];
    for (
      let offset = 0;
      offset < ids.length && lookupProviderIds.length > 0;
      offset += 4
    ) {
      const chunk = ids.slice(offset, offset + 4);
      ensureActive();
      idResults.push(
        ...(await Promise.all(
          chunk.map((id) =>
            this.dependencies.intelligence.lookupMultiSourceAdvisory(
              id,
              lookupProviderIds,
              signal,
            ),
          ),
        )),
      );
      ensureActive();
    }
    const generatedAt = this.now().toISOString();
    const merged = mergedIntelligence(packageResult, idResults, generatedAt);
    const lookupsTruncated = ids.length < allIds.length;
    const intelligence = lookupsTruncated
      ? {
          ...merged,
          status: "PARTIAL_RESULTS" as const,
          diagnostics: [
            ...new Set([
              ...merged.diagnostics,
              `Advisory ID enrichment was capped at ${this.maxAdvisoryLookups} identifiers.`,
            ]),
          ].sort(textOrder),
        }
      : merged;
    const correlation = this.dependencies.correlation.correlate({
      schemaVersion: "1.0",
      detections: fingerprint.detections,
      versionAssessments: versions,
      intelligenceResults: [intelligence],
      packageMappings: this.dependencies.packageMappings,
    });
    const assessment = this.dependencies.assessment.assess({
      schemaVersion: "1.0",
      assessedAt: generatedAt,
      detections: fingerprint.detections,
      versionAssessments: versions,
      intelligenceResults: [intelligence],
      correlation,
      packageMappings: this.dependencies.packageMappings,
    });
    const remediation = this.dependencies.remediation.plan({
      schemaVersion: "1.0",
      securityAssessment: assessment,
      correlation,
      advisories: intelligence.advisories,
      versionAssessments: versions,
      packageMappings: this.dependencies.packageMappings,
    });
    return {
      schemaVersion: "1.0",
      target: { url: publicUrl(request.target.url) },
      generatedAt,
      probe: {
        status: response.status,
        finalUrl: publicUrl(response.finalUrl),
        ...(response.contentType ? { contentType: response.contentType } : {}),
        ...(response.contentLength !== undefined
          ? { contentLength: response.contentLength }
          : {}),
        receivedBodyBytes: response.body.byteLength,
        redirectChain: (response.redirectChain ?? []).map((item) => ({
          ...item,
          from: publicUrl(item.from),
          to: publicUrl(item.to),
        })),
        ...(response.timing ? { timing: response.timing } : {}),
        ...(response.tls ? { tls: response.tls } : {}),
      },
      evidence,
      fingerprint,
      versions,
      intelligence,
      correlation,
      assessment,
      remediation,
    };
  }
}
