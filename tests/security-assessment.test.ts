import { describe, expect, it } from "vitest";
import type { TechnologyDetection } from "../src/domain/fingerprints.js";
import type { EvidenceReference } from "../src/domain/fingerprints.js";
import type { VersionAssessment } from "../src/domain/versions.js";
import type {
  CorrelationCollection,
  CorrelationResult,
  TechnologyPackageIdentityMapping,
} from "../src/domain/correlation.js";
import type {
  IntelligenceSourceResult,
  MultiSourceIntelligenceResult,
  NormalizedAdvisory,
} from "../src/domain/intelligence.js";
import type { SecurityAssessmentInput } from "../src/domain/assessment.js";
import { SecurityAssessmentEngine } from "../src/application/assessment/security-assessment-engine.js";

const engine = new SecurityAssessmentEngine({
  maxIntelligenceAgeMs: 30 * 24 * 60 * 60 * 1000,
});
const assessedAt = "2026-11-10T00:00:00.000Z";
const mapping: TechnologyPackageIdentityMapping = {
  mappingId: "php-packagist",
  technologyId: "php",
  package: { ecosystem: "Packagist", name: "php" },
  authority: "operator-verified",
  versionStrategyId: "php",
  supportedRangeTypes: ["SEMVER"],
};
const reference: EvidenceReference = {
  evidenceIndex: 0,
  type: "header",
  source: "response.headers",
  normalizedValue: "x-powered-by: PHP/8.2.1",
  key: "x-powered-by",
};

function detection(overrides: Partial<TechnologyDetection> = {}): TechnologyDetection {
  return {
    technologyId: "php",
    displayName: "PHP",
    category: "runtime",
    versionCandidate: {
      value: "8.2.1",
      confidence: 0.95,
      evidenceReferences: [reference],
    },
    versionCandidates: [
      { value: "8.2.1", confidence: 0.95, evidenceReferences: [reference] },
    ],
    detectionConfidence: 0.95,
    versionConfidence: 0.95,
    matchedEvidenceReferences: [reference],
    detectionReasons: ["Direct version header"],
    contradictoryEvidence: [],
    ...overrides,
  };
}
function versionAssessment(
  overrides: Partial<VersionAssessment> = {},
): VersionAssessment {
  return {
    technologyId: "php",
    displayName: "PHP",
    category: "runtime",
    versionConfidence: 0.95,
    parsingStatus: "parsed" as const,
    reconciliationStatus: "single" as const,
    rawObservedVersions: [
      {
        rawValue: "8.2.1",
        candidateValue: "8.2.1",
        confidence: 0.95,
        evidenceReferences: [reference],
      },
    ],
    parsedUpstreamVersions: [
      {
        scheme: "php",
        normalized: "8.2.1",
        components: { major: 8, minor: 2, patch: 1 },
      },
    ],
    vendorPackageVersions: [],
    candidateAssessments: [
      {
        rawObservedVersion: "8.2.1",
        strategyId: "php",
        parsingStatus: "parsed",
        parsedUpstreamVersion: {
          scheme: "php",
          normalized: "8.2.1",
          components: { major: 8, minor: 2, patch: 1 },
        },
        reason: "parsed",
        evidenceReferences: [reference],
      },
    ],
    selectedUpstreamVersion: {
      scheme: "php",
      normalized: "8.2.1",
      components: { major: 8, minor: 2, patch: 1 },
    },
    ...overrides,
  };
}
function unknownVersionAssessment(
  technologyId = "php",
  displayName = "PHP",
): VersionAssessment {
  return {
    technologyId,
    displayName,
    category: "runtime",
    versionConfidence: 0,
    parsingStatus: "unknown",
    reconciliationStatus: "unavailable",
    rawObservedVersions: [],
    parsedUpstreamVersions: [],
    vendorPackageVersions: [],
    candidateAssessments: [],
  };
}
function advisory(overrides: Partial<NormalizedAdvisory> = {}): NormalizedAdvisory {
  return {
    id: "CVE-2026-12345",
    aliases: ["GHSA-test"],
    affectedPackages: [
      {
        package: mapping.package,
        ranges: [],
        explicitVersions: [],
        fixedVersions: ["8.2.2"],
      },
    ],
    severity: [{ type: "CVSS_V3", score: "8.8" }],
    references: [{ url: "https://example.invalid/advisory" }],
    provenance: {
      providerId: "nvd",
      authority: "primary",
      originalIdentifier: "CVE-2026-12345",
      retrievedAt: assessedAt,
    },
    ...overrides,
  };
}
function corr(overrides: Partial<CorrelationResult> = {}): CorrelationResult {
  return {
    technologyId: "php",
    applicability: "AFFECTED",
    packageMappingId: mapping.mappingId,
    package: mapping.package,
    advisoryId: "CVE-2026-12345",
    aliases: ["GHSA-test"],
    sourceRecords: [advisory()],
    sourceSeverities: [
      {
        providerId: "nvd",
        advisoryId: "CVE-2026-12345",
        values: [{ type: "CVSS_V3", score: "8.8" }],
      },
    ],
    rangeAssessments: [
      {
        providerId: "nvd",
        advisoryId: "CVE-2026-12345",
        package: mapping.package,
        rangeType: "SEMVER",
        strategyId: "php",
        status: "within",
        rawVersion: "8.2.1",
        comparisons: [{ operator: ">=", boundary: "8.0.0", matched: true }],
        reason: "within",
        evidenceReferences: [reference],
      },
    ],
    explanations: [
      {
        code: "MATCHED_RANGE",
        message: "Version matches affected range.",
        providerId: "nvd",
        mappingId: mapping.mappingId,
        sourceRecordId: "CVE-2026-12345",
        evidenceReferences: [reference],
      },
    ],
    ...overrides,
  };
}
function source(
  status: IntelligenceSourceResult["status"] = "RESULTS",
  providerId = "nvd",
  retrievedAt = assessedAt,
): IntelligenceSourceResult {
  return {
    providerId,
    status,
    advisories:
      status === "RESULTS"
        ? [
            advisory({
              provenance: {
                providerId,
                authority: providerId === "redhat" ? "vendor" : "primary",
                retrievedAt,
              },
            }),
          ]
        : [],
    retrievedAt,
    diagnostics: [],
  };
}
function intelligence(
  sources: readonly IntelligenceSourceResult[] = [source()],
): MultiSourceIntelligenceResult {
  const hasRecord = sources.some((item) => item.advisories.length > 0);
  const failed = sources.some(
    (item) => item.status === "PROVIDER_UNAVAILABLE" || item.status === "PARTIAL_RESULTS",
  );
  return {
    schemaVersion: "1.0",
    request: { kind: "advisory-id", id: "CVE-2026-12345" },
    status: failed ? "PARTIAL_RESULTS" : hasRecord ? "RESULTS" : "NO_RESULTS",
    sourceResults: sources,
    advisories: sources.flatMap((item) => item.advisories),
    retrievedAt: assessedAt,
    diagnostics: [],
  };
}
function input(
  overrides: Partial<SecurityAssessmentInput> = {},
): SecurityAssessmentInput {
  const correlationResults = [corr()];
  const intel = [intelligence()];
  const correlations: CorrelationCollection = {
    schemaVersion: "1.0",
    fingerprintSchemaVersion: "1.0",
    versionAssessmentSchemaVersion: "1.0",
    intelligenceSchemaVersion: "1.0",
    intelligenceStatuses: [],
    results: correlationResults,
    diagnostics: [],
  };
  return {
    schemaVersion: "1.0",
    assessedAt,
    detections: [detection()],
    versionAssessments: {
      schemaVersion: "1.0",
      fingerprintSchemaVersion: "1.0",
      assessments: [versionAssessment()],
    },
    intelligenceResults: intel,
    correlation: correlations,
    packageMappings: [mapping],
    ...overrides,
  };
}

describe("SecurityAssessmentEngine", () => {
  it("confirms only authoritative affected evidence with reliable detection, exact package, version, and fresh coverage", () => {
    const result = engine.assess(input());
    expect(result.state).toBe("CONFIRMED_VULNERABLE");
    expect(result.technologyAssessments[0]?.advisoryAssessments[0]?.state).toBe(
      "CONFIRMED_VULNERABLE",
    );
    expect(
      result.technologyAssessments[0]?.advisoryAssessments[0]?.sourceRecords,
    ).toHaveLength(1);
    expect(result.confidence.versionIdentification.score).toBe(0.95);
    expect(result.confidence.vulnerabilityApplicability.score).toBe(0.95);
  });

  it("keeps potential applicability distinct as likely vulnerable", () => {
    const result = engine.assess(
      input({
        correlation: {
          ...input().correlation,
          results: [corr({ applicability: "POTENTIALLY_AFFECTED" })],
        },
      }),
    );
    expect(result.state).toBe("LIKELY_VULNERABLE");
  });

  it("reports patched only when Phase 8 demonstrates a fixed boundary", () => {
    const fixedRecord = advisory({
      affectedPackages: [
        {
          package: mapping.package,
          ranges: [
            { type: "SEMVER", events: [{ introduced: "8.0.0" }, { fixed: "8.2.0" }] },
          ],
          explicitVersions: [],
          fixedVersions: ["8.2.0"],
        },
      ],
    });
    const fixed = corr({
      applicability: "NOT_AFFECTED",
      sourceRecords: [fixedRecord],
      rangeAssessments: [
        {
          providerId: "nvd",
          advisoryId: fixedRecord.id,
          package: mapping.package,
          rangeType: "SEMVER",
          strategyId: "php",
          status: "outside",
          rawVersion: "8.2.1",
          comparisons: [{ operator: "<", boundary: "8.2.0", matched: false }],
          reason: "at or above fix",
          evidenceReferences: [reference],
        },
      ],
    });
    const result = engine.assess(
      input({ correlation: { ...input().correlation, results: [fixed] } }),
    );
    expect(result.technologyAssessments[0]?.advisoryAssessments[0]?.state).toBe(
      "PATCHED",
    );
  });

  it("retains vendor patched only from the exact Phase 8 vendor conclusion", () => {
    const result = engine.assess(
      input({
        correlation: {
          ...input().correlation,
          results: [corr({ applicability: "PATCHED_BY_VENDOR" })],
        },
      }),
    );
    expect(result.state).toBe("PATCHED_BY_VENDOR");
  });

  it("distinguishes unknown version, unknown technology, and insufficient evidence", () => {
    const unknownVersion = engine.assess(
      input({
        versionAssessments: {
          schemaVersion: "1.0",
          fingerprintSchemaVersion: "1.0",
          assessments: [unknownVersionAssessment()],
        },
      }),
    );
    expect(unknownVersion.technologyAssessments[0]?.state).toBe("VERSION_UNKNOWN");
    const technologyUnknown = engine.assess(
      input({
        detections: [],
        versionAssessments: {
          schemaVersion: "1.0",
          fingerprintSchemaVersion: "1.0",
          assessments: [],
        },
        correlation: { ...input().correlation, results: [] },
      }),
    );
    expect(technologyUnknown.state).toBe("TECHNOLOGY_UNKNOWN");
    expect(technologyUnknown.confidence.overall).toBe(0);
    expect(
      engine.assess(input({ detections: [detection({ detectionConfidence: 0.3 })] }))
        .state,
    ).toBe("INSUFFICIENT_EVIDENCE");
    expect(
      engine.assess(input({ packageMappings: [] })).technologyAssessments[0]?.state,
    ).toBe("INSUFFICIENT_EVIDENCE");
    expect(
      engine.assess(
        input({
          packageMappings: [mapping, { ...mapping, mappingId: "php-second-mapping" }],
        }),
      ).technologyAssessments[0]?.state,
    ).toBe("INSUFFICIENT_EVIDENCE");
    expect(
      engine.assess(
        input({
          correlation: {
            ...input().correlation,
            results: [
              corr({ package: { ecosystem: "Packagist", name: "other-package" } }),
            ],
          },
        }),
      ).technologyAssessments[0]?.state,
    ).toBe("INSUFFICIENT_EVIDENCE");
  });

  it("uses NO_KNOWN_VULNERABILITY only for a complete fresh no-record source set", () => {
    const noRecord = corr({
      applicability: "UNKNOWN",
      sourceRecords: [],
      rangeAssessments: [],
      explanations: [{ code: "NO_SOURCE_ADVISORY", message: "No record." }],
    });
    const result = engine.assess(
      input({
        intelligenceResults: [intelligence([source("NO_RESULTS")])],
        correlation: { ...input().correlation, results: [noRecord] },
      }),
    );
    expect(result.state).toBe("NO_KNOWN_VULNERABILITY");
    expect(result.limitations.join(" ")).toContain("does not mean secure");
    const unknownVersion = engine.assess(
      input({
        intelligenceResults: [intelligence([source("NO_RESULTS")])],
        versionAssessments: {
          schemaVersion: "1.0",
          fingerprintSchemaVersion: "1.0",
          assessments: [unknownVersionAssessment()],
        },
        correlation: { ...input().correlation, results: [noRecord] },
      }),
    );
    expect(unknownVersion.technologyAssessments[0]?.state).toBe("VERSION_UNKNOWN");
    expect(unknownVersion.technologyAssessments[0]?.advisoryAssessments[0]?.state).toBe(
      "VERSION_UNKNOWN",
    );
  });

  it("reports unavailable intelligence instead of treating provider failures as no vulnerabilities", () => {
    const result = engine.assess(
      input({
        intelligenceResults: [intelligence([source("PROVIDER_UNAVAILABLE")])],
        correlation: {
          ...input().correlation,
          results: [
            corr({ applicability: "UNKNOWN", sourceRecords: [], rangeAssessments: [] }),
          ],
        },
      }),
    );
    expect(result.state).toBe("INTELLIGENCE_UNAVAILABLE");
  });

  it("does not treat a contradictory provider status and record list as a complete no-result", () => {
    const inconsistentSource = { ...source("RESULTS"), advisories: [] };
    const noRecord = corr({
      applicability: "UNKNOWN",
      sourceRecords: [],
      rangeAssessments: [],
    });
    const result = engine.assess(
      input({
        intelligenceResults: [intelligence([inconsistentSource])],
        correlation: { ...input().correlation, results: [noRecord] },
      }),
    );
    expect(result.intelligenceCoverage.status).toBe("unknown");
    expect(result.state).not.toBe("NO_KNOWN_VULNERABILITY");
  });

  it("exposes unsupported provider and package/range mappings", () => {
    const unsupportedProvider: IntelligenceSourceResult = {
      providerId: "manual",
      status: "UNSUPPORTED",
      advisories: [],
      diagnostics: ["Provider unsupported"],
    };
    const unsupportedRange = corr({
      applicability: "INSUFFICIENT_EVIDENCE",
      explanations: [
        { code: "UNSUPPORTED_RANGE_TYPE", message: "No matching evaluator" },
      ],
    });
    const result = engine.assess(
      input({
        intelligenceResults: [intelligence([unsupportedProvider])],
        correlation: { ...input().correlation, results: [unsupportedRange] },
      }),
    );
    expect(result.intelligenceCoverage.status).toBe("unsupported");
    expect(result.intelligenceCoverage.unsupportedMappings).toContain(
      "php:UNSUPPORTED_RANGE_TYPE",
    );
    expect(result.state).toBe("INTELLIGENCE_UNAVAILABLE");
  });

  it("preserves Phase 8 conflicts and source records", () => {
    const conflict = corr({
      applicability: "CONFLICTING_EVIDENCE",
      sourceRecords: [
        advisory(),
        advisory({
          id: "CVE-2026-12345",
          aliases: [],
          provenance: {
            providerId: "redhat",
            authority: "vendor",
            retrievedAt: assessedAt,
          },
        }),
      ],
    });
    const result = engine.assess(
      input({ correlation: { ...input().correlation, results: [conflict] } }),
    );
    expect(result.state).toBe("CONFLICTING_EVIDENCE");
    expect(
      result.technologyAssessments[0]?.advisoryAssessments[0]?.sourceRecords,
    ).toHaveLength(2);
    expect(result.confidence.contradictionPenalty.score).toBeLessThan(1);
  });

  it("does not inflate scores for duplicate evidence or identical advisory copies across providers", () => {
    const repeated = detection({
      matchedEvidenceReferences: [reference, reference, reference],
    });
    const repeatedInput = input({
      detections: [repeated],
      correlation: {
        ...input().correlation,
        results: [
          corr({
            sourceRecords: [
              advisory(),
              advisory({
                provenance: {
                  providerId: "redhat",
                  authority: "vendor",
                  retrievedAt: assessedAt,
                },
              }),
            ],
          }),
        ],
      },
      sourceIndependenceGroups: [
        { providerId: "nvd", sourceGroupId: "origin-a", verified: true },
        { providerId: "redhat", sourceGroupId: "origin-b", verified: true },
      ],
    });
    const singleInput = input({
      correlation: {
        ...input().correlation,
        results: [corr({ sourceRecords: [advisory()] })],
      },
    });
    const one = engine.assess(singleInput).confidence;
    const two = engine.assess(repeatedInput).confidence;
    expect(two.independentCorroboration.score).toBe(one.independentCorroboration.score);
    expect(two.overall).toBe(one.overall);
  });

  it("counts corroboration only for distinct caller-verified source groups with distinct advisory payloads", () => {
    const vendorRecord = advisory({
      details: "Independently published vendor affected-version statement.",
      provenance: { providerId: "redhat", authority: "vendor", retrievedAt: assessedAt },
    });
    const result = engine.assess(
      input({
        intelligenceResults: [intelligence([source(), source("RESULTS", "redhat")])],
        correlation: {
          ...input().correlation,
          results: [corr({ sourceRecords: [advisory(), vendorRecord] })],
        },
        sourceIndependenceGroups: [
          { providerId: "nvd", sourceGroupId: "primary-nvd", verified: true },
          { providerId: "redhat", sourceGroupId: "vendor-redhat", verified: true },
        ],
      }),
    );
    expect(
      result.technologyAssessments[0]?.advisoryAssessments[0]?.confidence
        .independentCorroboration.score,
    ).toBe(0.65);
  });

  it("marks stale intelligence explicitly and does not claim no known vulnerability", () => {
    const old = "2026-08-01T00:00:00.000Z";
    const result = engine.assess(
      input({
        intelligenceResults: [intelligence([source("NO_RESULTS", "nvd", old)])],
        correlation: {
          ...input().correlation,
          results: [
            corr({ applicability: "UNKNOWN", sourceRecords: [], rangeAssessments: [] }),
          ],
        },
      }),
    );
    expect(result.intelligenceCoverage.status).toBe("stale");
    expect(result.state).toBe("INTELLIGENCE_UNAVAILABLE");
  });

  it("retains partial provider failure when another provider returned data", () => {
    const result = engine.assess(
      input({
        intelligenceResults: [
          intelligence([source("RESULTS"), source("PROVIDER_UNAVAILABLE", "redhat")]),
        ],
      }),
    );
    expect(result.intelligenceCoverage.status).toBe("partial");
    expect(result.technologyAssessments[0]?.intelligenceCoverage.sources).toHaveLength(2);
  });

  it("keeps a vulnerable technology visible when another detected technology has unknown version", () => {
    const otherDetection = detection({
      technologyId: "nginx",
      displayName: "nginx",
      detectionConfidence: 0.9,
      versionConfidence: 0,
      versionCandidates: [],
    });
    const otherVersion = unknownVersionAssessment("nginx", "nginx");
    const otherMapping = {
      ...mapping,
      mappingId: "nginx-generic",
      technologyId: "nginx",
      package: { ecosystem: "Generic", name: "nginx" },
      versionStrategyId: "nginx",
    };
    const otherCorrelation = corr({
      technologyId: "nginx",
      applicability: "UNKNOWN",
      packageMappingId: otherMapping.mappingId,
      package: otherMapping.package,
      aliases: [],
      sourceRecords: [],
      rangeAssessments: [],
      explanations: [{ code: "NO_SOURCE_ADVISORY", message: "No record." }],
    });
    const base = input();
    const result = engine.assess({
      ...base,
      detections: [detection(), otherDetection],
      versionAssessments: {
        ...base.versionAssessments,
        assessments: [versionAssessment(), otherVersion],
      },
      packageMappings: [mapping, otherMapping],
      correlation: { ...base.correlation, results: [corr(), otherCorrelation] },
    });
    expect(result.state).toBe("CONFIRMED_VULNERABLE");
    expect(result.technologyAssessments.map((item) => item.state)).toEqual([
      "VERSION_UNKNOWN",
      "CONFIRMED_VULNERABLE",
    ]);
    expect(result.confidence.overall).toBeLessThan(
      result.technologyAssessments[1]!.confidence.overall,
    );
  });

  it("returns deterministic assessments for identical timestamped inputs", () => {
    const same = input();
    expect(JSON.stringify(engine.assess(same))).toBe(JSON.stringify(engine.assess(same)));
  });
});
