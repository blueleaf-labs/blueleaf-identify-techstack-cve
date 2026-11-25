import type {
  IdentificationTarget,
  TechnologyObservation,
  VulnerabilityFinding,
} from "../domain/models.js";
import type { AdvisoryIntelligenceProvider } from "./intelligence/contracts.js";

/** Transport-neutral HTTP capability. Implementations must enforce configured network policy. */
export interface HttpProvider {
  request(input: HttpRequest): Promise<HttpResponse>;
}

export interface HttpRequest {
  readonly url: string;
  readonly method?: "GET" | "HEAD";
  readonly headers?: Readonly<Record<string, string>>;
  readonly timeoutMs: number;
  readonly signal?: AbortSignal;
}

export interface HttpResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Uint8Array;
  readonly finalUrl: string;
  readonly cookies?: readonly string[];
  readonly contentType?: string;
  readonly contentLength?: number;
  readonly redirectChain?: readonly RedirectHop[];
  readonly timing?: ProbeTiming;
  readonly tls?: TlsMetadata;
  readonly remoteAddress?: string;
  readonly resolvedAddresses?: readonly string[];
}

/** Structured probe metadata for a future Evidence Engine. */
export interface RedirectHop {
  readonly from: string;
  readonly status: number;
  readonly to: string;
}

export interface ProbeTiming {
  readonly requestStartedAt: string;
  readonly responseReceivedAt: string;
  readonly completedAt: string;
  readonly durationMs: number;
}

export interface TlsMetadata {
  readonly authorized: boolean;
  readonly protocol?: string;
  readonly cipher?: string;
  readonly peerCertificate?: {
    readonly subjectAltName?: string;
    readonly fingerprint256?: string;
    readonly validFrom?: string;
    readonly validTo?: string;
  };
}

/** Pure analysis boundary; implementation is outside Phase 2. */
export interface FingerprintingProvider {
  fingerprint(input: FingerprintInput): Promise<readonly TechnologyObservation[]>;
}

export interface FingerprintInput {
  readonly target: IdentificationTarget;
  readonly response: HttpResponse;
}

/** External intelligence source boundary; implementation is outside Phase 2. */
export interface IntelligenceProvider {
  lookup(input: IntelligenceLookup): Promise<readonly VulnerabilityFinding[]>;
}

export interface IntelligenceLookup {
  readonly technologies: readonly TechnologyObservation[];
}

/** Generic cache boundary for future provider and workflow results. */
export interface CacheProvider {
  get(key: string): Promise<string | undefined>;
  set(key: string, value: string, ttlSeconds: number): Promise<void>;
  delete(key: string): Promise<void>;
}

export interface ProviderRegistry {
  readonly http: HttpProvider;
  readonly fingerprinting: FingerprintingProvider;
  readonly intelligence: IntelligenceProvider;
  /** Additive normalized advisory-provider boundary; legacy lookup remains unchanged. */
  readonly advisoryIntelligence?: readonly AdvisoryIntelligenceProvider[];
  readonly cache: CacheProvider;
}
