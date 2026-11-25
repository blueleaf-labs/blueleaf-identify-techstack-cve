/** Validated, immutable configuration passed across the composition boundary. */
export interface ApplicationConfiguration {
  readonly http: {
    readonly timeoutMs: number;
    readonly maxResponseBytes: number;
    readonly redirectLimit?: number;
  };
  readonly network: {
    readonly allowedHosts: readonly string[];
    readonly allowPrivateNetworks: boolean;
  };
  readonly cache: {
    readonly defaultTtlSeconds: number;
    readonly maxEntries: number;
    readonly maxBytes: number;
  };
  /** Optional Phase 6 remote intelligence bounds; omitted by older configuration sources. */
  readonly intelligence?: {
    readonly timeoutMs: number;
    readonly maxRetries: number;
    readonly maxBatchSize: number;
    readonly maxPages: number;
    readonly maxAdvisoriesPerBatch: number;
    readonly maxResponseBytes: number;
    readonly cacheTtlSeconds: number;
    /** Optional NVD developer key; injected by the host secret/configuration source. */
    readonly nvdApiKey?: string;
  };
}

/** Safe defaults: public destinations only, bounded requests, and no implicit allowlist. */
export const DEFAULT_APPLICATION_CONFIGURATION: ApplicationConfiguration = Object.freeze({
  http: Object.freeze({
    timeoutMs: 10_000,
    maxResponseBytes: 2 * 1024 * 1024,
    redirectLimit: 5,
  }),
  network: Object.freeze({
    allowedHosts: Object.freeze([]),
    allowPrivateNetworks: false,
  }),
  cache: Object.freeze({
    defaultTtlSeconds: 300,
    maxEntries: 2_000,
    maxBytes: 32 * 1024 * 1024,
  }),
  intelligence: Object.freeze({
    timeoutMs: 5_000,
    maxRetries: 2,
    maxBatchSize: 100,
    maxPages: 5,
    maxAdvisoriesPerBatch: 500,
    maxResponseBytes: 8 * 1024 * 1024,
    cacheTtlSeconds: 300,
  }),
});

/** Source abstraction keeps process environment access outside the domain. */
export interface ConfigurationSource {
  get(name: string): string | undefined;
}

/** Configuration loader boundary; concrete parsing and secret sources are infrastructure concerns. */
export interface ConfigurationLoader {
  load(source: ConfigurationSource): ApplicationConfiguration;
}
