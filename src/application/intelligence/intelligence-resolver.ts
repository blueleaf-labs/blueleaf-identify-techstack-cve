import { ApplicationError } from "../../domain/errors.js";
import type {
  IntelligenceResult,
  IntelligenceSourceResult,
  MultiSourceIntelligenceRequest,
  MultiSourceIntelligenceResult,
  NormalizedAdvisory,
  AdvisoryPackageQuery,
} from "../../domain/intelligence.js";
import type { VersionAssessmentCollection } from "../../domain/versions.js";
import type {
  AdvisoryIntelligenceProvider,
  AdvisoryProviderResult,
  IntelligenceResolver as ResolverContract,
  MultiSourceIntelligenceResolver,
  IntelligenceResolverOptions,
  TechnologyPackageMapping,
} from "./contracts.js";

function textOrder(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function validResult(value: unknown): value is IntelligenceResult {
  return (
    isRecord(value) &&
    value["schemaVersion"] === "1.0" &&
    ["resolved", "no-advisories", "partial", "unsupported", "insufficient-data"].includes(
      String(value["status"]),
    ) &&
    Array.isArray(value["providerIds"]) &&
    value["providerIds"].every((id: unknown) => typeof id === "string") &&
    Array.isArray(value["queries"]) &&
    value["queries"].every(
      (query: unknown) =>
        isRecord(query) &&
        typeof query["ecosystem"] === "string" &&
        typeof query["name"] === "string" &&
        typeof query["version"] === "string",
    ) &&
    Array.isArray(value["advisories"]) &&
    value["advisories"].every(
      (advisory: unknown) =>
        isRecord(advisory) &&
        typeof advisory["id"] === "string" &&
        Array.isArray(advisory["aliases"]) &&
        Array.isArray(advisory["affectedPackages"]) &&
        Array.isArray(advisory["severity"]) &&
        Array.isArray(advisory["references"]) &&
        isRecord(advisory["provenance"]) &&
        typeof advisory["provenance"]["providerId"] === "string" &&
        typeof advisory["provenance"]["retrievedAt"] === "string",
    ) &&
    typeof value["retrievedAt"] === "string" &&
    !Number.isNaN(Date.parse(value["retrievedAt"])) &&
    Array.isArray(value["diagnostics"]) &&
    value["diagnostics"].every((item: unknown) => typeof item === "string")
  );
}
function uniqueAdvisories(
  records: readonly NormalizedAdvisory[],
): readonly NormalizedAdvisory[] {
  const byId = new Map<string, NormalizedAdvisory>();
  for (const record of [...records].sort(
    (a, b) => textOrder(a.id, b.id) || textOrder(JSON.stringify(a), JSON.stringify(b)),
  )) {
    const keys = [record.id, ...record.aliases].map(
      (item) => `${record.provenance.providerId}\0${item.toUpperCase()}`,
    );
    const prior = keys.map((key) => byId.get(key)).find((item) => item !== undefined);
    const merged =
      prior === undefined
        ? record
        : {
            ...prior,
            aliases: [
              ...new Set(
                [...prior.aliases, ...record.aliases, record.id].filter(
                  (id) => id !== prior.id,
                ),
              ),
            ].sort(textOrder),
            affectedPackages: [
              ...new Map(
                [...prior.affectedPackages, ...record.affectedPackages].map((item) => [
                  JSON.stringify(item),
                  item,
                ]),
              ).values(),
            ].sort((a, b) => textOrder(JSON.stringify(a), JSON.stringify(b))),
            severity: [
              ...new Map(
                [...prior.severity, ...record.severity].map((item) => [
                  `${item.type}\0${item.score}`,
                  item,
                ]),
              ).values(),
            ].sort((a, b) => textOrder(a.type, b.type) || textOrder(a.score, b.score)),
            references: [
              ...new Map(
                [...prior.references, ...record.references].map((ref) => [ref.url, ref]),
              ).values(),
            ].sort((a, b) => textOrder(a.url, b.url)),
            cpeConfigurations: [
              ...new Map(
                [
                  ...(prior.cpeConfigurations ?? []),
                  ...(record.cpeConfigurations ?? []),
                ].map((item) => [JSON.stringify(item), item]),
              ).values(),
            ].sort((a, b) => textOrder(JSON.stringify(a), JSON.stringify(b))),
            vendorPackageInformation: [
              ...new Map(
                [
                  ...(prior.vendorPackageInformation ?? []),
                  ...(record.vendorPackageInformation ?? []),
                ].map((item) => [JSON.stringify(item), item]),
              ).values(),
            ].sort((a, b) => textOrder(JSON.stringify(a), JSON.stringify(b))),
            relatedIdentifiers: [
              ...new Set([
                ...(prior.relatedIdentifiers ?? []),
                ...(record.relatedIdentifiers ?? []),
              ]),
            ].sort(textOrder),
            cweIds: [
              ...new Set([...(prior.cweIds ?? []), ...(record.cweIds ?? [])]),
            ].sort(textOrder),
          };
    for (const key of [
      ...keys,
      `${merged.provenance.providerId}\0${merged.id.toUpperCase()}`,
      ...merged.aliases.map(
        (item) => `${merged.provenance.providerId}\0${item.toUpperCase()}`,
      ),
    ])
      byId.set(key, merged);
  }
  return [...new Set(byId.values())].sort((a, b) => textOrder(a.id, b.id));
}
function validateProviderRecords(
  advisories: readonly NormalizedAdvisory[],
  providerId: string,
): readonly NormalizedAdvisory[] {
  if (
    !Array.isArray(advisories) ||
    advisories.some(
      (item) =>
        !item ||
        typeof item.id !== "string" ||
        !Array.isArray(item.aliases) ||
        item.provenance?.providerId !== providerId ||
        typeof item.provenance?.retrievedAt !== "string" ||
        Number.isNaN(Date.parse(item.provenance?.retrievedAt ?? "")),
    )
  )
    throw new ApplicationError(
      "PROVIDER_FAILURE",
      "Intelligence provider returned invalid source records.",
    );
  return advisories;
}
function validateQueries(input: readonly AdvisoryPackageQuery[]): void {
  if (!Array.isArray(input) || input.length > 100)
    throw new ApplicationError(
      "INVALID_INPUT",
      "Intelligence query batch must contain at most 100 queries.",
    );
  for (const query of input) {
    if (
      !query ||
      typeof query.ecosystem !== "string" ||
      !query.ecosystem.trim() ||
      typeof query.name !== "string" ||
      !query.name.trim() ||
      typeof query.version !== "string" ||
      !query.version.trim() ||
      query.version.length > 128
    ) {
      throw new ApplicationError(
        "INVALID_INPUT",
        "Intelligence query requires a bounded package, ecosystem, and version.",
      );
    }
  }
}
function mappingQueries(
  input: VersionAssessmentCollection,
  mappings: readonly TechnologyPackageMapping[],
): { queries: AdvisoryPackageQuery[]; unsupported: string[]; insufficient: string[] } {
  if (input.schemaVersion !== "1.0")
    throw new ApplicationError(
      "INVALID_INPUT",
      "Resolver requires VersionAssessmentCollection schema version 1.0.",
    );
  const queries: AdvisoryPackageQuery[] = [];
  const unsupported: string[] = [];
  const insufficient: string[] = [];
  for (const assessment of input.assessments) {
    const mapping = mappings.find(
      (item) => item.technologyId === assessment.technologyId,
    );
    if (!mapping) {
      unsupported.push(assessment.technologyId);
      continue;
    }
    if (
      !assessment.selectedUpstreamVersion ||
      !["single", "corroborated"].includes(assessment.reconciliationStatus) ||
      assessment.vendorPackageVersions.length > 0
    ) {
      insufficient.push(assessment.technologyId);
      continue;
    }
    queries.push({
      ecosystem: mapping.ecosystem,
      name: mapping.packageName,
      version: assessment.selectedUpstreamVersion.normalized,
    });
  }
  return { queries, unsupported, insufficient };
}

/** Application service that selects providers, maps explicit package identities, and caches normalized results. */
export class IntelligenceResolverService
  implements ResolverContract, MultiSourceIntelligenceResolver
{
  private readonly now: () => Date;
  private readonly ttl: number;
  private readonly selectedProvider: string | undefined;

  public constructor(private readonly options: IntelligenceResolverOptions) {
    this.now = options.now ?? ((): Date => new Date());
    this.ttl = options.cacheTtlSeconds ?? 300;
    this.selectedProvider = options.providerId;
    if (!Number.isSafeInteger(this.ttl) || this.ttl < 0)
      throw new ApplicationError(
        "INVALID_CONFIGURATION",
        "Intelligence cache TTL must be a non-negative integer.",
      );
    const ids = options.providers.map((provider) => provider.providerId);
    if (new Set(ids).size !== ids.length)
      throw new ApplicationError(
        "INVALID_CONFIGURATION",
        "Intelligence provider IDs must be unique.",
      );
    const mappings = options.mappings ?? [];
    const mappingIds = mappings.map((mapping) => mapping.technologyId);
    if (
      mappings.some(
        (mapping) =>
          !mapping.technologyId.trim() ||
          !mapping.ecosystem.trim() ||
          !mapping.packageName.trim(),
      ) ||
      new Set(mappingIds).size !== mappingIds.length
    )
      throw new ApplicationError(
        "INVALID_CONFIGURATION",
        "Technology package mappings must be non-empty and unique by technology ID.",
      );
    if (
      this.selectedProvider &&
      !options.providers.some((provider) => provider.providerId === this.selectedProvider)
    )
      throw new ApplicationError(
        "INVALID_CONFIGURATION",
        "Selected intelligence provider is not registered.",
      );
  }

  public async resolveAssessments(
    input: VersionAssessmentCollection,
  ): Promise<IntelligenceResult> {
    const mapped = mappingQueries(input, this.options.mappings ?? []);
    if (mapped.queries.length === 0)
      return this.emptyResult(
        mapped.unsupported.length ? "unsupported" : "insufficient-data",
        mapped.unsupported,
        mapped.insufficient,
      );
    const result = await this.resolveQueries(mapped.queries);
    const diagnostics = [
      ...result.diagnostics,
      ...mapped.unsupported.map(
        (id) => `No authoritative package mapping is registered for ${id}.`,
      ),
      ...mapped.insufficient.map(
        (id) => `A usable upstream version is unavailable for ${id}.`,
      ),
    ];
    return {
      ...result,
      status:
        mapped.unsupported.length || mapped.insufficient.length
          ? "partial"
          : result.status,
      diagnostics,
    };
  }

  public async resolveQueries(
    queries: readonly AdvisoryPackageQuery[],
  ): Promise<IntelligenceResult> {
    validateQueries(queries);
    const sorted = [
      ...new Map(
        queries.map((q) => [`${q.ecosystem}\0${q.name}\0${q.version}`, q]),
      ).values(),
    ].sort((a, b) =>
      textOrder(
        `${a.ecosystem}\0${a.name}\0${a.version}`,
        `${b.ecosystem}\0${b.name}\0${b.version}`,
      ),
    );
    const providers = this.providers();
    if (providers.length === 0) return this.emptyResult("unsupported", [], [], sorted);
    const cached: IntelligenceResult[] = [];
    const missing: AdvisoryPackageQuery[] = [];
    for (const query of sorted) {
      const key = this.cacheKey(providers[0]!.providerId, query);
      let raw: string | undefined;
      try {
        raw = await this.options.cache.get(key);
      } catch {
        missing.push(query);
        continue;
      }
      if (raw === undefined) {
        missing.push(query);
        continue;
      }
      try {
        const value: unknown = JSON.parse(raw);
        if (!validResult(value) || value.queries.length !== 1)
          throw new Error("invalid cache record");
        cached.push(value);
      } catch {
        try {
          await this.options.cache.delete(key);
        } catch {
          /* cache is best-effort */
        }
        missing.push(query);
      }
    }
    let fresh: IntelligenceResult | undefined;
    if (missing.length) {
      const provider = providers[0]!;
      let providerResult;
      try {
        if (missing.length === 1) {
          providerResult = await provider.queryPackage(missing[0]!);
        } else {
          const chunkSize = provider.maxBatchSize ?? 100;
          if (!Number.isSafeInteger(chunkSize) || chunkSize < 1 || chunkSize > 100)
            throw new ApplicationError(
              "INVALID_CONFIGURATION",
              "Intelligence provider batch bound is invalid.",
            );
          const chunks = [];
          for (let offset = 0; offset < missing.length; offset += chunkSize)
            chunks.push(
              await provider.queryBatch(missing.slice(offset, offset + chunkSize)),
            );
          providerResult = {
            advisories: chunks.flatMap((chunk) => chunk.advisories),
            complete: chunks.every((chunk) => chunk.complete),
            diagnostics: [...new Set(chunks.flatMap((chunk) => chunk.diagnostics))],
          };
        }
      } catch (error) {
        if (error instanceof ApplicationError) throw error;
        throw new ApplicationError(
          "PROVIDER_FAILURE",
          "Intelligence provider request failed.",
          { cause: error },
        );
      }
      const retrievedAt = this.now().toISOString();
      const advisories = uniqueAdvisories(providerResult.advisories);
      const sourceModifiedAt = advisories
        .map((a) => a.provenance.sourceModifiedAt)
        .filter((v): v is string => v !== undefined)
        .sort(textOrder)
        .at(-1);
      fresh = {
        schemaVersion: "1.0",
        status: providerResult.complete
          ? advisories.length
            ? "resolved"
            : "no-advisories"
          : "partial",
        providerIds: [provider.providerId],
        queries: missing,
        advisories,
        retrievedAt,
        ...(sourceModifiedAt ? { sourceModifiedAt } : {}),
        diagnostics: providerResult.diagnostics,
      };
      for (const query of providerResult.complete ? missing : []) {
        const scoped = advisories.filter((advisory) =>
          advisory.affectedPackages.some(
            (item) =>
              item.package.ecosystem === query.ecosystem &&
              item.package.name === query.name,
          ),
        );
        const queryResult: IntelligenceResult = {
          ...fresh,
          status: providerResult.complete
            ? scoped.length
              ? "resolved"
              : "no-advisories"
            : "partial",
          queries: [query],
          advisories: scoped,
        };
        try {
          await this.options.cache.set(
            this.cacheKey(provider.providerId, query),
            JSON.stringify(queryResult),
            this.ttl,
          );
        } catch {
          /* provider success must not be lost because cache is unavailable */
        }
      }
    }
    const combined = [...cached, ...(fresh ? [fresh] : [])];
    const advisories = uniqueAdvisories(combined.flatMap((item) => item.advisories));
    const queriesOut = sorted;
    const statuses = new Set(combined.map((item) => item.status));
    const status = statuses.has("partial")
      ? "partial"
      : advisories.length
        ? "resolved"
        : "no-advisories";
    const retrievedAt =
      combined
        .map((item) => item.retrievedAt)
        .sort(textOrder)
        .at(-1) ?? this.now().toISOString();
    const modified = advisories
      .map((a) => a.provenance.sourceModifiedAt)
      .filter((v): v is string => !!v)
      .sort(textOrder)
      .at(-1);
    return {
      schemaVersion: "1.0",
      status,
      providerIds: [providers[0]!.providerId],
      queries: queriesOut,
      advisories,
      retrievedAt,
      ...(modified ? { sourceModifiedAt: modified } : {}),
      diagnostics: [...new Set(combined.flatMap((item) => item.diagnostics))],
    };
  }

  public async lookupAdvisory(
    id: string,
    providerId?: string,
  ): Promise<NormalizedAdvisory> {
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(id))
      throw new ApplicationError("INVALID_INPUT", "Advisory ID is malformed.");
    const provider = this.providers(providerId)[0];
    if (!provider)
      throw new ApplicationError(
        "UNSUPPORTED_OPERATION",
        "Requested intelligence provider is not registered.",
      );
    const key = `blueleaf:intelligence:1.0:${provider.providerId}:id:${encodeURIComponent(id)}`;
    let cached: string | undefined;
    try {
      cached = await this.options.cache.get(key);
    } catch {
      /* cache errors do not prevent live lookup */
    }
    if (cached !== undefined) {
      try {
        const value: unknown = JSON.parse(cached);
        if (
          isRecord(value) &&
          typeof value["id"] === "string" &&
          (value["id"] === id ||
            (Array.isArray(value["aliases"]) && value["aliases"].includes(id))) &&
          Array.isArray(value["aliases"]) &&
          Array.isArray(value["affectedPackages"]) &&
          isRecord(value["provenance"]) &&
          value["provenance"]["providerId"] === provider.providerId &&
          typeof value["provenance"]["retrievedAt"] === "string"
        )
          return value as unknown as NormalizedAdvisory;
      } catch {
        /* malformed cache values are discarded below */
      }
      try {
        await this.options.cache.delete(key);
      } catch {
        /* cache is best-effort */
      }
    }
    const advisory = await provider.getAdvisory(id);
    try {
      await this.options.cache.set(key, JSON.stringify(advisory), this.ttl);
    } catch {
      /* cache is best-effort */
    }
    return advisory;
  }

  public async resolveMultiSourceQueries(
    queries: readonly AdvisoryPackageQuery[],
    providerIds?: readonly string[],
    signal?: AbortSignal,
  ): Promise<MultiSourceIntelligenceResult> {
    validateQueries(queries);
    const request = { kind: "package-version-batch" as const, queries: [...queries] };
    const providers = this.providers().filter(
      (provider) => !providerIds || providerIds.includes(provider.providerId),
    );
    const sources = await Promise.all(
      providers.map(async (provider) => {
        if (provider.supportsPackageQueries === false)
          return {
            providerId: provider.providerId,
            status: "UNSUPPORTED" as const,
            advisories: [],
            diagnostics: [
              "Provider does not support generic package and version queries.",
            ],
          };
        const key = `blueleaf:intelligence:multi:1.0:${provider.providerId}:query:${encodeURIComponent(JSON.stringify(queries))}`;
        const cached = await this.readSourceCache(key, provider.providerId);
        if (cached) return cached;
        try {
          const unique = [
            ...new Map(
              queries.map((q) => [`${q.ecosystem}\0${q.name}\0${q.version}`, q]),
            ).values(),
          ];
          const chunks: AdvisoryProviderResult[] = [];
          const batchSize = provider.maxBatchSize ?? 1;
          for (let i = 0; i < unique.length; i += batchSize) {
            const batch = unique.slice(i, i + batchSize);
            chunks.push(
              batch.length === 1
                ? await provider.queryPackage(batch[0]!, signal)
                : await provider.queryBatch(batch, signal),
            );
          }
          const advisories = uniqueAdvisories(
            validateProviderRecords(
              chunks.flatMap((chunk) => chunk.advisories),
              provider.providerId,
            ),
          );
          const complete = chunks.every((chunk) => chunk.complete);
          const result = {
            providerId: provider.providerId,
            status: complete
              ? advisories.length
                ? ("RESULTS" as const)
                : ("NO_RESULTS" as const)
              : ("PARTIAL_RESULTS" as const),
            advisories,
            retrievedAt: this.now().toISOString(),
            ...(advisories
              .map((item) => item.provenance.sourceModifiedAt)
              .filter((item): item is string => !!item)
              .sort(textOrder)
              .at(-1)
              ? {
                  sourceModifiedAt: advisories
                    .map((item) => item.provenance.sourceModifiedAt)
                    .filter((item): item is string => !!item)
                    .sort(textOrder)
                    .at(-1)!,
                }
              : {}),
            diagnostics: [...new Set(chunks.flatMap((chunk) => chunk.diagnostics))],
          };
          if (complete) await this.writeSourceCache(key, result);
          return result;
        } catch {
          if (signal?.aborted)
            throw new ApplicationError("CANCELLED", "Intelligence lookup was cancelled.");
          return {
            providerId: provider.providerId,
            status: "PROVIDER_UNAVAILABLE" as const,
            advisories: [],
            diagnostics: ["Provider request failed; source data is unavailable."],
          };
        }
      }),
    );
    return this.multiResult(request, sources);
  }

  public async lookupMultiSourceAdvisory(
    id: string,
    providerIds?: readonly string[],
    signal?: AbortSignal,
  ): Promise<MultiSourceIntelligenceResult> {
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(id))
      throw new ApplicationError("INVALID_INPUT", "Advisory ID is malformed.");
    const request = { kind: "advisory-id" as const, id };
    const providers = this.providers().filter(
      (provider) => !providerIds || providerIds.includes(provider.providerId),
    );
    const sources = await Promise.all(
      providers.map(async (provider) => {
        if (provider.supportsAdvisoryId && !provider.supportsAdvisoryId(id))
          return {
            providerId: provider.providerId,
            status: "UNSUPPORTED" as const,
            advisories: [],
            diagnostics: ["Provider does not support this advisory identifier format."],
          };
        if (provider.supportsIdLookups === false)
          return {
            providerId: provider.providerId,
            status: "UNSUPPORTED" as const,
            advisories: [],
            diagnostics: ["Provider does not support advisory ID lookups."],
          };
        const key = `blueleaf:intelligence:multi:1.0:${provider.providerId}:id:${encodeURIComponent(id)}`;
        const cached = await this.readSourceCache(key, provider.providerId);
        if (cached) return cached;
        try {
          const advisory = await provider.getAdvisory(id, signal);
          validateProviderRecords([advisory], provider.providerId);
          const result = {
            providerId: provider.providerId,
            status: "RESULTS" as const,
            advisories: [advisory],
            retrievedAt: this.now().toISOString(),
            ...(advisory.provenance.sourceModifiedAt
              ? { sourceModifiedAt: advisory.provenance.sourceModifiedAt }
              : {}),
            diagnostics: [],
          };
          await this.writeSourceCache(key, result);
          return result;
        } catch (error) {
          if (signal?.aborted)
            throw new ApplicationError("CANCELLED", "Intelligence lookup was cancelled.");
          if (error instanceof ApplicationError && error.code === "NOT_FOUND")
            return {
              providerId: provider.providerId,
              status: "NO_RESULTS" as const,
              advisories: [],
              retrievedAt: this.now().toISOString(),
              diagnostics: [],
            };
          return {
            providerId: provider.providerId,
            status: "PROVIDER_UNAVAILABLE" as const,
            advisories: [],
            diagnostics: ["Provider request failed; source data is unavailable."],
          };
        }
      }),
    );
    return this.multiResult(request, sources);
  }

  private async readSourceCache(
    key: string,
    providerId: string,
  ): Promise<IntelligenceSourceResult | undefined> {
    try {
      const raw = await this.options.cache.get(key);
      if (raw === undefined) return undefined;
      const value: unknown = JSON.parse(raw);
      if (
        isRecord(value) &&
        value["providerId"] === providerId &&
        ["RESULTS", "NO_RESULTS", "PARTIAL_RESULTS"].includes(String(value["status"])) &&
        Array.isArray(value["advisories"]) &&
        value["advisories"].every(
          (item) =>
            isRecord(item) &&
            isRecord(item["provenance"]) &&
            item["provenance"]["providerId"] === providerId,
        ) &&
        typeof value["retrievedAt"] === "string" &&
        Array.isArray(value["diagnostics"])
      )
        return value as unknown as IntelligenceSourceResult;
      await this.options.cache.delete(key);
    } catch {
      /* cache is best-effort */
    }
    return undefined;
  }
  private async writeSourceCache(
    key: string,
    value: IntelligenceSourceResult,
  ): Promise<void> {
    try {
      await this.options.cache.set(key, JSON.stringify(value), this.ttl);
    } catch {
      /* cache is best-effort */
    }
  }
  private multiResult(
    request: MultiSourceIntelligenceRequest,
    sourceResults: readonly IntelligenceSourceResult[],
  ): MultiSourceIntelligenceResult {
    const unavailable = sourceResults.filter(
      (item) => item.status === "PROVIDER_UNAVAILABLE",
    ).length;
    const unsupported = sourceResults.filter(
      (item) => item.status === "UNSUPPORTED",
    ).length;
    const successful = sourceResults.filter(
      (item) => item.status === "RESULTS" || item.status === "NO_RESULTS",
    ).length;
    const failed = unavailable + unsupported;
    const hasAdvisories = sourceResults.some((item) => item.advisories.length > 0);
    const status =
      sourceResults.length === 0 || (successful === 0 && unavailable === 0)
        ? ("INTELLIGENCE_UNAVAILABLE" as const)
        : unavailable > 0 && successful === 0
          ? ("PROVIDER_UNAVAILABLE" as const)
          : failed > 0 || sourceResults.some((item) => item.status === "PARTIAL_RESULTS")
            ? ("PARTIAL_RESULTS" as const)
            : hasAdvisories
              ? ("RESULTS" as const)
              : ("NO_RESULTS" as const);
    const sorted = [...sourceResults].sort((a, b) =>
      textOrder(a.providerId, b.providerId),
    );
    const advisories = sorted
      .flatMap((item) => item.advisories)
      .sort(
        (a, b) =>
          textOrder(a.provenance.providerId, b.provenance.providerId) ||
          textOrder(a.id, b.id),
      );
    return {
      schemaVersion: "1.0",
      request,
      status,
      sourceResults: sorted,
      advisories,
      retrievedAt: this.now().toISOString(),
      diagnostics: [...new Set(sorted.flatMap((item) => item.diagnostics))],
    };
  }

  private providers(providerId?: string): readonly AdvisoryIntelligenceProvider[] {
    const selected = providerId ?? this.selectedProvider;
    return selected
      ? this.options.providers.filter((item) => item.providerId === selected)
      : this.options.providers;
  }
  private cacheKey(provider: string, query: AdvisoryPackageQuery): string {
    return `blueleaf:intelligence:1.0:${provider}:${encodeURIComponent(query.ecosystem)}:${encodeURIComponent(query.name)}:${encodeURIComponent(query.version)}`;
  }
  private emptyResult(
    status: IntelligenceResult["status"],
    unsupported: readonly string[],
    insufficient: readonly string[],
    queries: readonly AdvisoryPackageQuery[] = [],
  ): IntelligenceResult {
    return {
      schemaVersion: "1.0",
      status,
      providerIds: [],
      queries,
      advisories: [],
      retrievedAt: this.now().toISOString(),
      diagnostics: [
        ...unsupported.map(
          (id) => `No authoritative package mapping is registered for ${id}.`,
        ),
        ...insufficient.map(
          (id) => `A usable upstream version is unavailable for ${id}.`,
        ),
      ],
    };
  }
}
