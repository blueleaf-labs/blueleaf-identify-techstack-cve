import type { RuntimeSettings } from "../config/environment.js";
import { EvidenceEngine } from "../application/evidence/evidence-engine.js";
import { FingerprintEngine } from "../application/fingerprinting/fingerprint-engine.js";
import { VersionIntelligenceEngine } from "../application/versioning/version-engine.js";
import { IntelligenceResolverService } from "../application/intelligence/intelligence-resolver.js";
import { VulnerabilityCorrelationEngine } from "../application/correlation/correlation-engine.js";
import { SecurityAssessmentEngine } from "../application/assessment/security-assessment-engine.js";
import { RemediationEngine } from "../application/remediation/remediation-engine.js";
import { ScanApplicationService } from "../application/scan/scan-service.js";
import type { ScanApplicationDependencies } from "../application/scan/contracts.js";
import type { HttpProvider, CacheProvider } from "../application/ports.js";
import type { AdvisoryIntelligenceProvider } from "../application/intelligence/contracts.js";
import type { TechnologyPackageIdentityMapping } from "../domain/correlation.js";
import { HttpProbeProvider } from "./http/http-probe-provider.js";
import { OsvIntelligenceProvider } from "./intelligence/osv-provider.js";
import { NvdIntelligenceProvider } from "./intelligence/nvd-provider.js";
import {
  RedHatSecurityAdvisoryProvider,
  UbuntuSecurityAdvisoryProvider,
} from "./intelligence/vendor-providers.js";
import { MemoryCacheProvider } from "./cache/memory-cache.js";
import { DEFAULT_APPLICATION_CONFIGURATION } from "../config/configuration.js";

export interface ScanCompositionOverrides {
  readonly http?: HttpProvider;
  readonly cache?: CacheProvider;
  readonly intelligenceProviders?: readonly AdvisoryIntelligenceProvider[];
  readonly now?: () => Date;
}

/** Infrastructure-only object graph construction. Shared application service is returned to both adapters. */
export function createScanApplicationService(
  settings: RuntimeSettings,
  overrides: ScanCompositionOverrides = {},
): ScanApplicationService {
  const configuration = settings.configuration;
  const intelligenceConfig =
    configuration.intelligence ?? DEFAULT_APPLICATION_CONFIGURATION.intelligence!;
  const versionEngine = new VersionIntelligenceEngine();
  const now = overrides.now ?? ((): Date => new Date());
  const providers = overrides.intelligenceProviders ?? [
    new OsvIntelligenceProvider({
      timeoutMs: intelligenceConfig?.timeoutMs,
      maxRetries: intelligenceConfig?.maxRetries,
      maxBatchSize: intelligenceConfig?.maxBatchSize,
      maxPages: intelligenceConfig?.maxPages,
      maxAdvisoriesPerBatch: intelligenceConfig?.maxAdvisoriesPerBatch,
      maxResponseBytes: intelligenceConfig?.maxResponseBytes,
      now,
    }),
    new NvdIntelligenceProvider({
      ...(intelligenceConfig.nvdApiKey ? { apiKey: intelligenceConfig.nvdApiKey } : {}),
      timeoutMs: intelligenceConfig.timeoutMs,
      maxRetries: intelligenceConfig.maxRetries,
      maxPages: intelligenceConfig.maxPages,
      maxResponseBytes: intelligenceConfig.maxResponseBytes,
      now,
    }),
    new UbuntuSecurityAdvisoryProvider({
      timeoutMs: intelligenceConfig.timeoutMs,
      maxRetries: intelligenceConfig.maxRetries,
      maxResponseBytes: intelligenceConfig.maxResponseBytes,
      now,
    }),
    new RedHatSecurityAdvisoryProvider({
      timeoutMs: intelligenceConfig.timeoutMs,
      maxRetries: intelligenceConfig.maxRetries,
      maxResponseBytes: intelligenceConfig.maxResponseBytes,
      now,
    }),
  ];
  const counts = new Map<string, number>();
  settings.packageMappings.forEach((item) =>
    counts.set(item.technologyId, (counts.get(item.technologyId) ?? 0) + 1),
  );
  const resolverMappings = settings.packageMappings
    .filter((item) => counts.get(item.technologyId) === 1)
    .map((item) => ({
      technologyId: item.technologyId,
      ecosystem: item.package.ecosystem,
      packageName: item.package.name,
    }));
  const cache =
    overrides.cache ??
    new MemoryCacheProvider(() => now().getTime(), {
      maxEntries: configuration.cache.maxEntries,
      maxBytes: configuration.cache.maxBytes,
    });
  const resolver = new IntelligenceResolverService({
    providers,
    cache,
    mappings: resolverMappings,
    cacheTtlSeconds:
      intelligenceConfig.cacheTtlSeconds ?? configuration.cache.defaultTtlSeconds,
    now,
  });
  const dependencies: ScanApplicationDependencies = {
    http: overrides.http ?? new HttpProbeProvider(configuration),
    evidence: new EvidenceEngine(),
    fingerprinting: new FingerprintEngine(),
    versions: versionEngine,
    intelligence: resolver,
    correlation: new VulnerabilityCorrelationEngine(versionEngine),
    assessment: new SecurityAssessmentEngine(),
    remediation: new RemediationEngine(versionEngine),
    packageMappings:
      settings.packageMappings as readonly TechnologyPackageIdentityMapping[],
    probeTimeoutMs: configuration.http.timeoutMs,
    now,
    maxAdvisoryLookups: settings.maxAdvisoryLookups,
  };
  return new ScanApplicationService(dependencies);
}
