import { vi } from "vitest";
import type { HttpProvider, HttpResponse } from "../../src/application/ports.js";
import type { ScanApplicationDependencies } from "../../src/application/scan/contracts.js";
import { ScanApplicationService } from "../../src/application/scan/scan-service.js";
import { EvidenceEngine } from "../../src/application/evidence/evidence-engine.js";
import { FingerprintEngine } from "../../src/application/fingerprinting/fingerprint-engine.js";
import { VersionIntelligenceEngine } from "../../src/application/versioning/version-engine.js";
import { VulnerabilityCorrelationEngine } from "../../src/application/correlation/correlation-engine.js";
import { SecurityAssessmentEngine } from "../../src/application/assessment/security-assessment-engine.js";
import { RemediationEngine } from "../../src/application/remediation/remediation-engine.js";
import type { TechnologyPackageIdentityMapping } from "../../src/domain/correlation.js";
import type {
  MultiSourceIntelligenceRequest,
  MultiSourceIntelligenceResult,
  NormalizedAdvisory,
} from "../../src/domain/intelligence.js";
import type { MultiSourceIntelligenceResolver } from "../../src/application/intelligence/contracts.js";

export const now = (): Date => new Date("2026-11-11T00:00:00.000Z");
export const mapping: TechnologyPackageIdentityMapping = {
  mappingId: "php-packagist",
  technologyId: "php",
  package: { ecosystem: "Packagist", name: "php" },
  authority: "operator-verified",
  versionStrategyId: "php",
  supportedRangeTypes: ["SEMVER"],
};

export function advisory(
  overrides: Partial<NormalizedAdvisory> = {},
): NormalizedAdvisory {
  return {
    id: "CVE-2026-12345",
    aliases: ["GHSA-blueleaf-test"],
    summary: "Fixture advisory",
    affectedPackages: [
      {
        package: mapping.package,
        ranges: [
          { type: "SEMVER", events: [{ introduced: "8.0.0" }, { fixed: "8.2.2" }] },
        ],
        explicitVersions: [],
        fixedVersions: ["8.2.2"],
      },
    ],
    severity: [{ type: "CVSS_V3", score: "8.8" }],
    references: [{ url: "https://example.invalid/CVE-2026-12345" }],
    provenance: {
      providerId: "osv",
      authority: "primary",
      originalIdentifier: "CVE-2026-12345",
      retrievedAt: now().toISOString(),
    },
    ...overrides,
  };
}

export function httpResponse(overrides: Partial<HttpResponse> = {}): HttpResponse {
  return {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "x-powered-by": "PHP/8.2.1",
      authorization: "Bearer response-secret-never-serialize",
    },
    body: Buffer.from(
      '<html><head><title>Fixture</title><meta name="generator" content="Fixture CMS"></head><body>hello</body></html>',
    ),
    finalUrl: "https://example.test/app?access_token=private",
    cookies: ["session_token=raw-cookie-secret; HttpOnly; Secure"],
    contentType: "text/html; charset=utf-8",
    contentLength: 109,
    redirectChain: [],
    ...overrides,
  };
}

function result(
  request: MultiSourceIntelligenceRequest,
  record: NormalizedAdvisory,
  status: "RESULTS" | "NO_RESULTS" = "RESULTS",
): MultiSourceIntelligenceResult {
  const advisories = status === "RESULTS" ? [record] : [];
  return {
    schemaVersion: "1.0",
    request,
    status,
    sourceResults: [
      {
        providerId: "osv",
        status,
        advisories,
        retrievedAt: now().toISOString(),
        diagnostics: [],
      },
    ],
    advisories,
    retrievedAt: now().toISOString(),
    diagnostics: [],
  };
}

export function fakeResolver(record = advisory()): MultiSourceIntelligenceResolver {
  return {
    resolveMultiSourceQueries: vi.fn(async (queries) =>
      result({ kind: "package-version-batch", queries }, record),
    ),
    lookupMultiSourceAdvisory: vi.fn(async (id) =>
      result({ kind: "advisory-id", id }, record),
    ),
  };
}

export function createTestScanService(
  options: {
    readonly response?: HttpResponse;
    readonly http?: HttpProvider;
    readonly intelligence?: MultiSourceIntelligenceResolver;
    readonly packageMappings?: readonly TechnologyPackageIdentityMapping[];
    readonly overrides?: Partial<ScanApplicationDependencies>;
  } = {},
): ScanApplicationService {
  const http: HttpProvider = options.http ?? {
    request: vi.fn(async () => options.response ?? httpResponse()),
  };
  const versionEngine = new VersionIntelligenceEngine();
  const dependencies: ScanApplicationDependencies = {
    http,
    evidence: new EvidenceEngine(),
    fingerprinting: new FingerprintEngine(),
    versions: versionEngine,
    intelligence: options.intelligence ?? fakeResolver(),
    correlation: new VulnerabilityCorrelationEngine(versionEngine),
    assessment: new SecurityAssessmentEngine(),
    remediation: new RemediationEngine(versionEngine),
    packageMappings: options.packageMappings ?? [mapping],
    probeTimeoutMs: 10_000,
    now,
    maxAdvisoryLookups: 20,
    ...options.overrides,
  };
  return new ScanApplicationService(dependencies);
}
