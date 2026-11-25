import type {
  AdvisoryPackageQuery,
  IntelligenceResult,
  MultiSourceIntelligenceResult,
  NormalizedAdvisory,
} from "../../domain/intelligence.js";
import type { VersionAssessmentCollection } from "../../domain/versions.js";

export interface AdvisoryProviderResult {
  readonly advisories: readonly NormalizedAdvisory[];
  readonly complete: boolean;
  readonly diagnostics: readonly string[];
}

/** Provider port shared by OSV and future advisory sources. */
export interface AdvisoryIntelligenceProvider {
  readonly providerId: string;
  readonly maxBatchSize?: number;
  readonly supportsPackageQueries?: boolean;
  readonly supportsIdLookups?: boolean;
  /** Optional generic capability hint for identifiers rejected by a provider's public interface. */
  supportsAdvisoryId?(id: string): boolean;
  queryPackage(
    query: AdvisoryPackageQuery,
    signal?: AbortSignal,
  ): Promise<AdvisoryProviderResult>;
  queryBatch(
    queries: readonly AdvisoryPackageQuery[],
    signal?: AbortSignal,
  ): Promise<AdvisoryProviderResult>;
  getAdvisory(id: string, signal?: AbortSignal): Promise<NormalizedAdvisory>;
}

export interface TechnologyPackageMapping {
  readonly technologyId: string;
  readonly ecosystem: string;
  readonly packageName: string;
}

export interface IntelligenceResolverOptions {
  readonly providers: readonly AdvisoryIntelligenceProvider[];
  readonly cache: {
    get(key: string): Promise<string | undefined>;
    set(key: string, value: string, ttlSeconds: number): Promise<void>;
    delete(key: string): Promise<void>;
  };
  readonly mappings?: readonly TechnologyPackageMapping[];
  readonly cacheTtlSeconds?: number;
  readonly providerId?: string;
  readonly now?: () => Date;
}

export interface IntelligenceResolver {
  resolveAssessments(input: VersionAssessmentCollection): Promise<IntelligenceResult>;
  resolveQueries(queries: readonly AdvisoryPackageQuery[]): Promise<IntelligenceResult>;
  lookupAdvisory(id: string, providerId?: string): Promise<NormalizedAdvisory>;
}

/** Additive Phase 7 port; keeps the Phase 6 resolver contract source-compatible. */
export interface MultiSourceIntelligenceResolver {
  resolveMultiSourceQueries(
    queries: readonly AdvisoryPackageQuery[],
    providerIds?: readonly string[],
    signal?: AbortSignal,
  ): Promise<MultiSourceIntelligenceResult>;
  lookupMultiSourceAdvisory(
    id: string,
    providerIds?: readonly string[],
    signal?: AbortSignal,
  ): Promise<MultiSourceIntelligenceResult>;
}
