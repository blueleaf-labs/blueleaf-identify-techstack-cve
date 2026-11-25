import { describe, expect, it } from "vitest";
import type { TechnologyDetection } from "../src/domain/fingerprints.js";
import type { EvidenceReference } from "../src/domain/fingerprints.js";
import type { VersionAssessment } from "../src/domain/versions.js";
import type {
  CorrelationCollection,
  CorrelationResult,
  TechnologyPackageIdentityMapping,
} from "../src/domain/correlation.js";
import type { NormalizedAdvisory } from "../src/domain/intelligence.js";
import type { SecurityAssessmentInput } from "../src/domain/assessment.js";
import { SecurityAssessmentEngine } from "../src/application/assessment/security-assessment-engine.js";
import { RemediationEngine } from "../src/application/remediation/remediation-engine.js";
import { VersionIntelligenceEngine } from "../src/application/versioning/version-engine.js";
import type { RemediationInput } from "../src/domain/remediation.js";

const assessedAt = "2026-11-10T00:00:00.000Z";
const versionEngine = new VersionIntelligenceEngine();
const packageIdentity = { ecosystem: "Packagist", name: "php" };
const mapping: TechnologyPackageIdentityMapping = {
  mappingId: "php-packagist",
  technologyId: "php",
  package: packageIdentity,
  authority: "operator-verified",
  versionStrategyId: "php",
  supportedRangeTypes: ["SEMVER"],
};
const evidence: EvidenceReference = {
  evidenceIndex: 0,
  type: "header",
  source: "response.headers",
  normalizedValue: "x-powered-by: PHP/8.2.1",
  key: "x-powered-by",
};
function advisory(
  id = "CVE-2026-12345",
  providerId = "nvd",
  fixed = "8.2.2",
  overrides: Partial<NormalizedAdvisory> = {},
): NormalizedAdvisory {
  return {
    id,
    aliases: [],
    affectedPackages: [
      {
        package: packageIdentity,
        ranges: [{ type: "SEMVER", events: [{ introduced: "8.0.0" }, { fixed }] }],
        explicitVersions: [],
        fixedVersions: [fixed],
      },
    ],
    severity: [{ type: "CVSS_V3", score: "8.8" }],
    references: [{ url: "https://example.invalid/advisory" }],
    provenance: {
      providerId,
      authority: "primary",
      originalIdentifier: id,
      retrievedAt: assessedAt,
    },
    ...overrides,
  };
}
function correlation(
  record: NormalizedAdvisory,
  overrides: Partial<CorrelationResult> = {},
): CorrelationResult {
  return {
    technologyId: "php",
    applicability: "AFFECTED",
    packageMappingId: mapping.mappingId,
    package: packageIdentity,
    advisoryId: record.id,
    aliases: record.aliases,
    sourceRecords: [record],
    sourceSeverities: [
      {
        providerId: record.provenance.providerId,
        advisoryId: record.id,
        values: record.severity,
      },
    ],
    rangeAssessments: [
      {
        providerId: record.provenance.providerId,
        advisoryId: record.id,
        package: packageIdentity,
        rangeType: "SEMVER",
        strategyId: "php",
        status: "within",
        rawVersion: "8.2.1",
        comparisons: [{ operator: ">=", boundary: "8.0.0", matched: true }],
        reason: "within affected range",
        evidenceReferences: [evidence],
      },
    ],
    explanations: [
      {
        code: "MATCHED_RANGE",
        message: "Version is in affected range",
        providerId: record.provenance.providerId,
        mappingId: mapping.mappingId,
        sourceRecordId: record.id,
        evidenceReferences: [evidence],
      },
    ],
    ...overrides,
  };
}
function detection(technologyId = "php"): TechnologyDetection {
  return {
    technologyId,
    displayName: technologyId === "php" ? "PHP" : technologyId,
    category: "runtime",
    versionCandidate: {
      value: "8.2.1",
      confidence: 0.95,
      evidenceReferences: [evidence],
    },
    versionCandidates: [
      { value: "8.2.1", confidence: 0.95, evidenceReferences: [evidence] },
    ],
    detectionConfidence: 0.95,
    versionConfidence: 0.95,
    matchedEvidenceReferences: [evidence],
    detectionReasons: ["Explicit version header"],
    contradictoryEvidence: [],
  };
}
function versionAssessment(technologyId = "php", current = "8.2.1"): VersionAssessment {
  const parse = versionEngine.strategies.forTechnology(technologyId).parse(current);
  const parsed = parse.parsedUpstreamVersion!;
  return {
    technologyId,
    displayName: technologyId.toUpperCase(),
    category: "runtime",
    versionConfidence: 0.95,
    parsingStatus: "parsed",
    reconciliationStatus: "single",
    rawObservedVersions: [
      {
        rawValue: current,
        candidateValue: current,
        confidence: 0.95,
        evidenceReferences: [evidence],
      },
    ],
    parsedUpstreamVersions: [parsed],
    vendorPackageVersions: [],
    candidateAssessments: [
      {
        rawObservedVersion: current,
        strategyId: versionEngine.strategies.forTechnology(technologyId).id,
        parsingStatus: "parsed",
        parsedUpstreamVersion: parsed,
        reason: "parsed",
        evidenceReferences: [evidence],
      },
    ],
    selectedUpstreamVersion: parsed,
  };
}
function assessmentInput(
  records: readonly NormalizedAdvisory[],
  correlations: readonly CorrelationResult[],
  versions = [versionAssessment()],
): SecurityAssessmentInput {
  const intelligence = {
    schemaVersion: "1.0" as const,
    request: { kind: "advisory-id" as const, id: records[0]?.id ?? "CVE-2026-12345" },
    status: "RESULTS" as const,
    sourceResults: records.map((item) => ({
      providerId: item.provenance.providerId,
      status: "RESULTS" as const,
      advisories: [item],
      retrievedAt: assessedAt,
      diagnostics: [],
    })),
    advisories: records,
    retrievedAt: assessedAt,
    diagnostics: [],
  };
  const correlationCollection: CorrelationCollection = {
    schemaVersion: "1.0",
    fingerprintSchemaVersion: "1.0",
    versionAssessmentSchemaVersion: "1.0",
    intelligenceSchemaVersion: "1.0",
    intelligenceStatuses: [],
    results: correlations,
    diagnostics: [],
  };
  return {
    schemaVersion: "1.0",
    assessedAt,
    detections: [detection()],
    versionAssessments: {
      schemaVersion: "1.0",
      fingerprintSchemaVersion: "1.0",
      assessments: versions,
    },
    intelligenceResults: [intelligence],
    correlation: correlationCollection,
    packageMappings: [mapping],
  };
}
function remediationInput(
  records: readonly NormalizedAdvisory[],
  correlations: readonly CorrelationResult[],
  versions = [versionAssessment()],
): RemediationInput {
  const assessment = new SecurityAssessmentEngine().assess(
    assessmentInput(records, correlations, versions),
  );
  return {
    schemaVersion: "1.0",
    securityAssessment: assessment,
    correlation: {
      schemaVersion: "1.0",
      fingerprintSchemaVersion: "1.0",
      versionAssessmentSchemaVersion: "1.0",
      intelligenceSchemaVersion: "1.0",
      intelligenceStatuses: [],
      results: correlations,
      diagnostics: [],
    },
    advisories: records,
    versionAssessments: {
      schemaVersion: "1.0",
      fingerprintSchemaVersion: "1.0",
      assessments: versions,
    },
    packageMappings: [mapping],
  };
}
const engine = new RemediationEngine(new VersionIntelligenceEngine());

describe("RemediationEngine", () => {
  it("recommends a source-backed single advisory fix and follow-up verification", () => {
    const record = advisory();
    const plan = engine.plan(remediationInput([record], [correlation(record)])).plans[0]!;
    expect(plan.state, JSON.stringify(plan, null, 2)).toBe("UPGRADE_RECOMMENDED");
    expect(plan.recommendedTargetVersion?.version).toBe("8.2.2");
    expect(plan.advisoryPlans[0]?.fixedVersionEvidence[0]?.recommendationEligible).toBe(
      true,
    );
    expect(plan.followUpVerification.length).toBeGreaterThan(0);
  });

  it("selects a target satisfying multiple compatible CVE boundaries", () => {
    const first = advisory("CVE-2026-10001", "nvd", "8.2.2");
    const second = advisory("CVE-2026-10002", "osv", "8.2.4", {
      provenance: { providerId: "osv", authority: "primary", retrievedAt: assessedAt },
    });
    const result = engine.plan(
      remediationInput([first, second], [correlation(first), correlation(second)]),
    );
    expect(result.plans[0]?.recommendedTargetVersion?.version).toBe("8.2.4");
    expect(result.plans[0]?.advisoryPlans).toHaveLength(2);
  });

  it("keeps source conflicts and uncertain applicability at manual review", () => {
    const a = advisory("CVE-2026-10001");
    const b = advisory("CVE-2026-10001", "osv", "8.2.4", {
      provenance: { providerId: "osv", authority: "primary", retrievedAt: assessedAt },
    });
    const conflicting = correlation(a, {
      applicability: "CONFLICTING_EVIDENCE",
      sourceRecords: [a, b],
    });
    const plan = engine.plan(remediationInput([a, b], [conflicting])).plans[0]!;
    expect(plan.advisoryPlans[0]?.state).toBe("MANUAL_REVIEW_REQUIRED");
    expect(plan.recommendedTargetVersion).toBeUndefined();
    expect(plan.advisoryPlans[0]?.fixedVersionEvidence).toHaveLength(2);
  });

  it("does not select a target for unknown versions or unsupported range semantics", () => {
    const record = advisory();
    const unknown: VersionAssessment = {
      ...versionAssessment("php"),
      parsingStatus: "unknown",
      reconciliationStatus: "unavailable",
      candidateAssessments: [],
    };
    const plan = engine.plan(remediationInput([record], [correlation(record)], [unknown]))
      .plans[0]!;
    expect(plan.state).toBe("MANUAL_REVIEW_REQUIRED");
    expect(plan.recommendedTargetVersion).toBeUndefined();
  });

  it("refuses unsupported package version semantics and partial intelligence coverage", () => {
    const record = advisory();
    const unsupportedMapping: TechnologyPackageIdentityMapping = {
      ...mapping,
      versionStrategyId: "distribution-package",
      supportedRangeTypes: ["ECOSYSTEM"],
    };
    const base = assessmentInput([record], [correlation(record)]);
    const unsupportedAssessment = new SecurityAssessmentEngine().assess({
      ...base,
      packageMappings: [unsupportedMapping],
    });
    const unsupportedPlan = engine.plan({
      schemaVersion: "1.0",
      securityAssessment: unsupportedAssessment,
      correlation: base.correlation,
      advisories: [record],
      versionAssessments: base.versionAssessments,
      packageMappings: [unsupportedMapping],
    }).plans[0]!;
    expect(unsupportedPlan.state).toBe("MANUAL_REVIEW_REQUIRED");
    expect(unsupportedPlan.recommendedTargetVersion).toBeUndefined();

    const partialInput = remediationInput([record], [correlation(record)]);
    const partialAssessment = {
      ...partialInput.securityAssessment,
      technologyAssessments: partialInput.securityAssessment.technologyAssessments.map(
        (item) => ({
          ...item,
          intelligenceCoverage: {
            ...item.intelligenceCoverage,
            status: "partial" as const,
          },
        }),
      ),
    };
    const partialPlan = engine.plan({
      ...partialInput,
      securityAssessment: partialAssessment,
    }).plans[0]!;
    expect(partialPlan.state).toBe("MANUAL_REVIEW_REQUIRED");
    expect(partialPlan.recommendedTargetVersion).toBeUndefined();

    const staleAssessment = {
      ...partialInput.securityAssessment,
      technologyAssessments: partialInput.securityAssessment.technologyAssessments.map(
        (item) => ({
          ...item,
          state: "PATCHED" as const,
          intelligenceCoverage: {
            ...item.intelligenceCoverage,
            status: "stale" as const,
          },
        }),
      ),
    };
    const stalePlan = engine.plan({
      ...partialInput,
      securityAssessment: staleAssessment,
    }).plans[0]!;
    expect(stalePlan.state).toBe("MANUAL_REVIEW_REQUIRED");
  });

  it("preserves already patched, withdrawn, and incomplete-intelligence states", () => {
    const record = advisory();
    const patched = engine.plan(
      remediationInput(
        [record],
        [correlation(record, { applicability: "NOT_AFFECTED" })],
      ),
    );
    expect(patched.plans[0]?.advisoryPlans[0]?.state).toBe("NO_ACTION_IDENTIFIED");
    const withdrawn = advisory("CVE-2026-12345", "nvd", "8.2.2", {
      recordStatus: "withdrawn",
      withdrawnAt: assessedAt,
    });
    const withdrawnCorrelation = correlation(withdrawn, { applicability: "UNKNOWN" });
    const withdrawnPlan = engine.plan(
      remediationInput([withdrawn], [withdrawnCorrelation]),
    ).plans[0]!;
    expect(withdrawnPlan.advisoryPlans[0]?.state).toBe("NO_ACTION_IDENTIFIED");
    expect(withdrawnPlan.recommendedTargetVersion).toBeUndefined();
    const contradictoryWithdrawn = engine.plan(
      remediationInput([withdrawn], [correlation(withdrawn)]),
    ).plans[0]!;
    expect(contradictoryWithdrawn.advisoryPlans[0]?.state).toBe("MANUAL_REVIEW_REQUIRED");
  });

  it("preserves Phase 9 patch conclusions without reclassifying the security assessment", () => {
    const record = advisory("CVE-2026-12345", "nvd", "8.2.0");
    const fixed = correlation(record, {
      applicability: "NOT_AFFECTED",
      rangeAssessments: [
        {
          providerId: "nvd",
          advisoryId: record.id,
          package: packageIdentity,
          rangeType: "SEMVER",
          strategyId: "php",
          status: "outside",
          rawVersion: "8.2.1",
          comparisons: [{ operator: "<", boundary: "8.2.0", matched: false }],
          reason: "at or above fixed version",
          evidenceReferences: [evidence],
        },
      ],
    });
    const plan = engine.plan(remediationInput([record], [fixed])).plans[0]!;
    expect(plan.securityAssessmentState).toBe("PATCHED");
    expect(plan.state).toBe("PATCH_ALREADY_APPLIED");
    expect(plan.recommendedTargetVersion).toBeUndefined();
  });

  it("requests administrator review when an applicable authoritative advisory gives no fixed version", () => {
    const record = advisory("CVE-2026-12345", "nvd", "8.2.2", {
      affectedPackages: [
        {
          package: packageIdentity,
          ranges: [{ type: "SEMVER", events: [{ introduced: "8.0.0" }] }],
          explicitVersions: [],
          fixedVersions: [],
        },
      ],
    });
    const plan = engine.plan(remediationInput([record], [correlation(record)])).plans[0]!;
    expect(plan.advisoryPlans[0]?.state).toBe("ACTION_REQUIRED");
    expect(plan.advisoryPlans[0]?.minimumSafeUpgrade).toBeUndefined();
    expect(plan.recommendedTargetVersion).toBeUndefined();
  });

  it("does not select a fixed boundary that remains inside another affected range", () => {
    const record = advisory("CVE-2026-12345", "nvd", "8.2.2", {
      affectedPackages: [
        {
          package: packageIdentity,
          ranges: [
            { type: "SEMVER", events: [{ introduced: "8.0.0" }, { fixed: "8.2.2" }] },
            { type: "SEMVER", events: [{ introduced: "8.2.0" }] },
          ],
          explicitVersions: [],
          fixedVersions: ["8.2.2"],
        },
      ],
    });
    const plan = engine.plan(remediationInput([record], [correlation(record)])).plans[0]!;
    expect(plan.advisoryPlans[0]?.state).toBe("MANUAL_REVIEW_REQUIRED");
    expect(plan.recommendedTargetVersion).toBeUndefined();
    expect(plan.advisoryPlans[0]?.explanations.join(" ")).toContain("could not prove");
  });

  it("requires exact official vendor package evidence for vendor-specific updates", () => {
    const vendorMapping = {
      ...mapping,
      mappingId: "php-ubuntu",
      vendor: "ubuntu",
      distribution: "ubuntu-24.04",
    };
    const record = advisory("CVE-2026-12345", "ubuntu", "8.2.2", {
      provenance: { providerId: "ubuntu", authority: "vendor", retrievedAt: assessedAt },
      vendorPackageInformation: [
        {
          providerId: "ubuntu",
          recordType: "affected-release",
          packageName: "php",
          packageVersion: "8.2.1-1ubuntu1.2",
          upstreamFix: "8.2.2",
        },
      ],
    });
    const vendorCorrelation = correlation(record, {
      packageMappingId: vendorMapping.mappingId,
    });
    const vendorAssessmentInput = assessmentInput([record], [vendorCorrelation]);
    const assessment = new SecurityAssessmentEngine().assess({
      ...vendorAssessmentInput,
      packageMappings: [vendorMapping],
    });
    const input: RemediationInput = {
      schemaVersion: "1.0",
      securityAssessment: assessment,
      correlation: { ...vendorAssessmentInput.correlation, results: [vendorCorrelation] },
      advisories: [record],
      versionAssessments: {
        schemaVersion: "1.0",
        fingerprintSchemaVersion: "1.0",
        assessments: [versionAssessment()],
      },
      packageMappings: [vendorMapping],
    };
    const plan = engine.plan(input).plans[0]!;
    expect(plan.advisoryPlans[0]?.state).toBe("VENDOR_UPDATE_REQUIRED");
    expect(plan.advisoryPlans[0]?.vendorUpdates[0]?.fixedPackageRevisions).toEqual([
      "8.2.1-1ubuntu1.2",
    ]);
    expect(
      plan.advisoryPlans[0]?.vendorUpdates[0]?.administratorVerificationRequired,
    ).toBe(true);
    expect(plan.recommendedTargetVersion).toBeUndefined();

    const patchedVendorCorrelation = correlation(record, {
      packageMappingId: vendorMapping.mappingId,
      applicability: "PATCHED_BY_VENDOR",
    });
    const patchedVendorBase = assessmentInput([record], [patchedVendorCorrelation]);
    const patchedVendorAssessment = new SecurityAssessmentEngine().assess({
      ...patchedVendorBase,
      packageMappings: [vendorMapping],
    });
    const patchedVendorPlan = engine.plan({
      schemaVersion: "1.0",
      securityAssessment: patchedVendorAssessment,
      correlation: {
        ...patchedVendorBase.correlation,
        results: [patchedVendorCorrelation],
      },
      advisories: [record],
      versionAssessments: patchedVendorBase.versionAssessments,
      packageMappings: [vendorMapping],
    });
    expect(patchedVendorPlan.plans[0]?.advisoryPlans[0]?.state).toBe(
      "PATCH_ALREADY_APPLIED",
    );
    expect(patchedVendorPlan.plans[0]?.recommendedTargetVersion).toBeUndefined();
  });

  it("uses only fresh verified lifecycle sources for EOL concerns and migration paths", () => {
    const record = advisory();
    const input = remediationInput([record], [correlation(record)]);
    const lifecycle: RemediationInput["lifecycleInformation"] = [
      {
        technologyId: "php",
        mappingId: mapping.mappingId,
        status: "end-of-life",
        endOfLifeAt: "2025-12-31",
        providerId: "php.net",
        authority: "primary",
        verified: true,
        reference: "https://www.php.net/supported-versions.php",
        retrievedAt: assessedAt,
        migrationPath: {
          technologyId: "php",
          displayName: "PHP",
          recommendation: "Select a currently supported PHP branch",
          reference: "https://www.php.net/supported-versions.php",
        },
      },
    ];
    const plan = engine.plan({ ...input, lifecycleInformation: lifecycle }).plans[0]!;
    expect(plan.lifecycle.status).toBe("end-of-life");
    expect(plan.lifecycle.migrationPath?.reference).toContain("php.net");
    expect(plan.state).toBe("MANUAL_REVIEW_REQUIRED");
  });

  it("keeps severity, priority and exploitability distinct and serializes deterministically", () => {
    const record = advisory();
    const input = remediationInput([record], [correlation(record)]);
    const first = engine.plan(input);
    expect(first.plans[0]?.advisoryPlans[0]?.highestSeverityBand).toBe("HIGH");
    expect(first.plans[0]?.advisoryPlans[0]?.priority.level).toBe("P1");
    expect(first.plans[0]?.advisoryPlans[0]?.exploitability).toBe("NOT_ASSESSED");
    expect(JSON.stringify(first)).toBe(JSON.stringify(engine.plan(input)));
  });

  it("keeps multiple technologies visible when one has no package mapping", () => {
    const record = advisory();
    const base = assessmentInput([record], [correlation(record)]);
    const securityAssessment = new SecurityAssessmentEngine().assess({
      ...base,
      detections: [detection(), detection("nginx")],
    });
    const input: RemediationInput = {
      schemaVersion: "1.0",
      securityAssessment,
      correlation: base.correlation,
      advisories: [record],
      versionAssessments: base.versionAssessments,
      packageMappings: [mapping],
    };
    const plans = engine.plan(input).plans;
    expect(plans).toHaveLength(2);
    expect(plans.find((item) => item.technologyId === "nginx")?.state).toBe(
      "MANUAL_REVIEW_REQUIRED",
    );
  });
});
