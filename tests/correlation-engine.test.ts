import { describe, expect, it } from "vitest";
import { VulnerabilityCorrelationEngine } from "../src/application/correlation/correlation-engine.js";
import { VersionIntelligenceEngine } from "../src/application/versioning/version-engine.js";
import type {
  CorrelationInput,
  TechnologyPackageIdentityMapping,
} from "../src/domain/correlation.js";
import type {
  MultiSourceIntelligenceResult,
  NormalizedAdvisory,
} from "../src/domain/intelligence.js";
import type { TechnologyDetection } from "../src/domain/fingerprints.js";
import type { VersionAssessment } from "../src/domain/versions.js";

const detection: TechnologyDetection = {
  technologyId: "nginx",
  displayName: "nginx",
  category: "web-server",
  versionCandidates: [],
  detectionConfidence: 0.9,
  versionConfidence: 0.8,
  matchedEvidenceReferences: [],
  detectionReasons: [],
  contradictoryEvidence: [],
};
function assessment(
  version = "1.5.0",
  options: {
    vendor?: boolean;
    status?: VersionAssessment["parsingStatus"];
    selected?: boolean;
  } = {},
): VersionAssessment {
  const parsed =
    options.status === "unknown" || options.selected === false
      ? undefined
      : {
          scheme: "semver",
          normalized: version,
          components: { major: 1, minor: 5, patch: 0 },
        };
  return {
    technologyId: "nginx",
    displayName: "nginx",
    category: "web-server",
    versionConfidence: 0.8,
    parsingStatus: options.status ?? "parsed",
    reconciliationStatus: parsed ? "single" : "unavailable",
    rawObservedVersions: [
      {
        rawValue: version,
        candidateValue: version,
        confidence: 0.8,
        evidenceReferences: [
          {
            evidenceIndex: 1,
            type: "header",
            source: "response.headers",
            key: "server",
            normalizedValue: `nginx/${version}`,
          },
        ],
      },
    ],
    parsedUpstreamVersions: parsed ? [parsed] : [],
    vendorPackageVersions: options.vendor
      ? [
          {
            rawValue: "1:1.5.0-2ubuntu1",
            upstreamValue: version,
            vendor: "ubuntu",
            distribution: "ubuntu",
            epoch: 1,
            revision: "2ubuntu1",
          },
        ]
      : [],
    candidateAssessments: parsed
      ? [
          {
            rawObservedVersion: version,
            strategyId: "nginx",
            parsingStatus: "parsed",
            parsedUpstreamVersion: parsed,
            reason: "test version",
            evidenceReferences: [
              {
                evidenceIndex: 1,
                type: "header",
                source: "response.headers",
                key: "server",
                normalizedValue: `nginx/${version}`,
              },
            ],
          },
        ]
      : [],
    ...(parsed ? { selectedUpstreamVersion: parsed } : {}),
  };
}
const mapping: TechnologyPackageIdentityMapping = {
  mappingId: "nginx-upstream",
  technologyId: "nginx",
  package: { ecosystem: "Generic", name: "nginx" },
  authority: "upstream-documentation",
  versionStrategyId: "nginx",
  supportedRangeTypes: ["SEMVER"],
};
function advisory(
  options: {
    provider?: string;
    id?: string;
    aliases?: string[];
    status?: NormalizedAdvisory["recordStatus"];
    ranges?: NormalizedAdvisory["affectedPackages"][number]["ranges"];
    versions?: string[];
    vendorInfo?: NormalizedAdvisory["vendorPackageInformation"];
    cpe?: NormalizedAdvisory["cpeConfigurations"];
  } = {},
): NormalizedAdvisory {
  return {
    id: options.id ?? "CVE-2025-12345",
    aliases: options.aliases ?? [],
    affectedPackages: [
      {
        package: mapping.package,
        ranges: options.ranges ?? [],
        explicitVersions: options.versions ?? [],
        fixedVersions: [],
      },
    ],
    severity: [{ type: "CVSS_V3", score: "7.5" }],
    references: [],
    ...(options.status ? { recordStatus: options.status } : {}),
    ...(options.vendorInfo ? { vendorPackageInformation: options.vendorInfo } : {}),
    ...(options.cpe ? { cpeConfigurations: options.cpe } : {}),
    provenance: {
      providerId: options.provider ?? "osv",
      authority:
        options.provider === "redhat" || options.provider === "ubuntu"
          ? "vendor"
          : options.provider === "nvd"
            ? "primary"
            : "aggregator",
      originalIdentifier: options.id ?? "CVE-2025-12345",
      retrievedAt: "2026-01-02T00:00:00.000Z",
    },
  };
}
function intelligence(
  records: readonly NormalizedAdvisory[],
  status: MultiSourceIntelligenceResult["status"] = "RESULTS",
): MultiSourceIntelligenceResult {
  return {
    schemaVersion: "1.0",
    request: { kind: "advisory-id", id: "CVE-2025-12345" },
    status,
    sourceResults:
      status === "PARTIAL_RESULTS"
        ? [
            {
              providerId: "nvd",
              status: "PROVIDER_UNAVAILABLE",
              advisories: [],
              diagnostics: ["NVD unavailable"],
            },
          ]
        : [],
    advisories: records,
    retrievedAt: "2026-01-02T00:00:00.000Z",
    diagnostics: [],
  };
}
function input(
  options: {
    version?: string;
    versionOptions?: Parameters<typeof assessment>[1];
    advisories?: NormalizedAdvisory[];
    mappings?: TechnologyPackageIdentityMapping[];
    installed?: CorrelationInput["installedPackages"];
    sourceStatus?: MultiSourceIntelligenceResult["status"];
  } = {},
): CorrelationInput {
  return {
    schemaVersion: "1.0",
    detections: [detection],
    versionAssessments: {
      schemaVersion: "1.0",
      fingerprintSchemaVersion: "1.0",
      assessments: [assessment(options.version, options.versionOptions)],
    },
    intelligenceResults: [
      intelligence(
        options.advisories ?? [
          advisory({
            ranges: [
              { type: "SEMVER", events: [{ introduced: "1.0.0" }, { fixed: "2.0.0" }] },
            ],
          }),
        ],
        options.sourceStatus,
      ),
    ],
    packageMappings: options.mappings ?? [mapping],
    ...(options.installed ? { installedPackages: options.installed } : {}),
  };
}
const engine = new VulnerabilityCorrelationEngine(new VersionIntelligenceEngine());

describe("VulnerabilityCorrelationEngine", () => {
  it("correlates an established version inside an inclusive introduced/exclusive fixed range", () => {
    const result = engine.correlate(input()).results[0]!;
    expect(result.applicability).toBe("AFFECTED");
    expect(result.rangeAssessments[0]?.comparisons.map((item) => item.matched)).toEqual([
      true,
      true,
    ]);
    expect(
      result.explanations.some(
        (item) =>
          item.code === "OSV_RANGE_EVALUATED" &&
          item.evidenceReferences?.[0]?.evidenceIndex === 1,
      ),
    ).toBe(true);
  });

  it("honors fixed, last-affected, introduced, and limit boundaries", () => {
    const range = (
      events: NonNullable<
        NormalizedAdvisory["affectedPackages"][number]["ranges"]
      >[number]["events"],
    ): NormalizedAdvisory => advisory({ ranges: [{ type: "SEMVER", events }] });
    expect(
      engine.correlate(
        input({
          version: "2.0.0",
          advisories: [range([{ introduced: "1.0.0" }, { fixed: "2.0.0" }])],
        }),
      ).results[0]?.applicability,
    ).toBe("NOT_AFFECTED");
    expect(
      engine.correlate(
        input({
          version: "2.0.0",
          advisories: [range([{ introduced: "1.0.0" }, { lastAffected: "2.0.0" }])],
        }),
      ).results[0]?.applicability,
    ).toBe("AFFECTED");
    expect(
      engine.correlate(
        input({
          version: "1.0.0",
          advisories: [range([{ introduced: "1.0.0" }, { limit: "2.0.0" }])],
        }),
      ).results[0]?.applicability,
    ).toBe("AFFECTED");
    expect(
      engine.correlate(
        input({
          version: "2.0.0",
          advisories: [range([{ introduced: "1.0.0" }, { limit: "2.0.0" }])],
        }),
      ).results[0]?.applicability,
    ).toBe("NOT_AFFECTED");
  });

  it("evaluates multiple ranges and explicit affected versions", () => {
    const ranges = [
      { type: "SEMVER", events: [{ introduced: "1.0.0" }, { fixed: "1.2.0" }] },
      { type: "SEMVER", events: [{ introduced: "1.4.0" }, { fixed: "1.8.0" }] },
    ];
    expect(
      engine.correlate(input({ version: "1.5.0", advisories: [advisory({ ranges })] }))
        .results[0]?.applicability,
    ).toBe("AFFECTED");
    expect(
      engine.correlate(input({ advisories: [advisory({ versions: ["1.5.0"] })] }))
        .results[0]?.applicability,
    ).toBe("AFFECTED");
  });

  it("keeps unknown versions and unsupported ecosystems explicit", () => {
    expect(
      engine.correlate(input({ versionOptions: { status: "unknown" } })).results[0]
        ?.applicability,
    ).toBe("UNKNOWN");
    const unsupported = advisory({
      ranges: [{ type: "GIT", events: [{ introduced: "abc" }, { fixed: "def" }] }],
    });
    const result = engine.correlate(input({ advisories: [unsupported] })).results[0]!;
    expect(result.applicability).toBe("UNKNOWN");
    expect(result.rangeAssessments[0]?.status).toBe("unknown");
  });

  it("correlates a matching NVD CPE conservatively and preserves partial provider status", () => {
    const nvd = advisory({
      provider: "nvd",
      cpe: [
        {
          nodes: [
            {
              matches: [
                {
                  criteria: "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                  vulnerable: true,
                  versionStartIncluding: "1.0.0",
                  versionEndExcluding: "2.0.0",
                },
              ],
              nodes: [],
            },
          ],
        },
      ],
    });
    const cpeMapping: TechnologyPackageIdentityMapping = {
      ...mapping,
      cpe: { vendor: "nginx", product: "nginx", rangeType: "SEMVER" },
    };
    const result = engine.correlate(
      input({
        advisories: [nvd],
        mappings: [cpeMapping],
        sourceStatus: "PARTIAL_RESULTS",
      }),
    );
    expect(result.results[0]?.applicability).toBe("POTENTIALLY_AFFECTED");
    expect(result.intelligenceStatuses[0]?.status).toBe("PARTIAL_RESULTS");
    expect(result.intelligenceStatuses[0]?.providers[0]?.status).toBe(
      "PROVIDER_UNAVAILABLE",
    );
  });

  it("returns insufficient evidence for missing or ambiguous package mappings", () => {
    expect(engine.correlate(input({ mappings: [] })).results[0]?.applicability).toBe(
      "INSUFFICIENT_EVIDENCE",
    );
    expect(
      engine.correlate(input({ mappings: [], advisories: [] })).results[0]?.applicability,
    ).toBe("INSUFFICIENT_EVIDENCE");
    expect(
      engine.correlate(
        input({ mappings: [mapping, { ...mapping, mappingId: "ambiguous" }] }),
      ).results[0]?.applicability,
    ).toBe("INSUFFICIENT_EVIDENCE");
  });

  it("requires an exact authoritative installed revision before a vendor patch conclusion", () => {
    const vendorMapping: TechnologyPackageIdentityMapping = {
      ...mapping,
      mappingId: "nginx-rhel",
      authority: "vendor-documentation",
      vendor: "redhat",
      distribution: "rhel",
      cpe: { vendor: "nginx", product: "nginx", rangeType: "SEMVER" },
    };
    const redhat = advisory({
      provider: "redhat",
      vendorInfo: [
        {
          providerId: "redhat",
          recordType: "affected-release",
          packageVersion: "nginx-1.5.0-2.el9",
          cpe: "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
        },
      ],
    });
    const installed = [
      {
        mappingId: "nginx-rhel",
        ecosystem: "Generic",
        packageName: "nginx",
        vendor: "redhat",
        distribution: "rhel",
        exactPackageRevision: "nginx-1.5.0-2.el9",
        verification: "authoritative-inventory" as const,
        sourceId: "rpm-inventory",
        recordId: "pkg-1",
      },
    ];
    const upstream = advisory({
      ranges: [{ type: "SEMVER", events: [{ introduced: "1.0.0" }, { fixed: "2.0.0" }] }],
    });
    const result = engine.correlate(
      input({ advisories: [upstream, redhat], mappings: [vendorMapping], installed }),
    ).results[0]!;
    expect(result.applicability).toBe("PATCHED_BY_VENDOR");
    expect(result.sourceRecords).toHaveLength(2);
    expect(
      engine.correlate(
        input({
          versionOptions: { status: "unknown", vendor: true, selected: false },
          advisories: [redhat],
          mappings: [vendorMapping],
          installed,
        }),
      ).results[0]?.applicability,
    ).toBe("PATCHED_BY_VENDOR");
    expect(
      engine.correlate(input({ advisories: [redhat], mappings: [vendorMapping] }))
        .results[0]?.applicability,
    ).toBe("UNKNOWN");
  });

  it("reports conflicting vendor and upstream statements instead of discarding either", () => {
    const vendorMapping: TechnologyPackageIdentityMapping = {
      ...mapping,
      mappingId: "nginx-rhel",
      authority: "vendor-documentation",
      vendor: "redhat",
      distribution: "rhel",
      cpe: { vendor: "nginx", product: "nginx", rangeType: "SEMVER" },
    };
    const redhat = advisory({
      provider: "redhat",
      vendorInfo: [
        {
          providerId: "redhat",
          recordType: "package-state",
          packageName: "nginx",
          cpe: "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
          fixState: "Not affected",
        },
      ],
    });
    const installed = [
      {
        mappingId: "nginx-rhel",
        ecosystem: "Generic",
        packageName: "nginx",
        vendor: "redhat",
        distribution: "rhel",
        exactPackageRevision: "1.5.0-2.el9",
        verification: "authoritative-inventory" as const,
        sourceId: "rpm-inventory",
        recordId: "pkg-1",
      },
    ];
    const upstream = advisory({
      ranges: [{ type: "SEMVER", events: [{ introduced: "1.0.0" }, { fixed: "2.0.0" }] }],
    });
    const result = engine.correlate(
      input({ advisories: [upstream, redhat], mappings: [vendorMapping], installed }),
    ).results[0]!;
    expect(result.applicability).toBe("CONFLICTING_EVIDENCE");
    expect(result.sourceRecords.map((item) => item.provenance.providerId)).toEqual([
      "osv",
      "redhat",
    ]);
  });

  it("groups duplicate CVE aliases while retaining source records and source severities", () => {
    const result = engine.correlate(
      input({
        advisories: [
          advisory({ provider: "osv", id: "OSV-2025-1", aliases: ["CVE-2025-12345"] }),
          advisory({ provider: "nvd" }),
        ],
      }),
    ).results[0]!;
    expect(result.advisoryId).toBe("CVE-2025-12345");
    expect(result.sourceRecords).toHaveLength(2);
    expect(result.sourceSeverities.map((item) => item.providerId)).toEqual([
      "nvd",
      "osv",
    ]);
  });

  it("retains rejected and withdrawn advisories without active affected conclusions", () => {
    for (const status of ["rejected", "withdrawn"] as const) {
      const result = engine.correlate(
        input({
          advisories: [
            advisory({
              status,
              ranges: [{ type: "SEMVER", events: [{ introduced: "1.0.0" }] }],
            }),
          ],
        }),
      ).results[0]!;
      expect(result.applicability).toBe("UNKNOWN");
      expect(result.sourceRecords).toHaveLength(1);
    }
  });

  it("does not turn missing or malformed ranges into safety claims and retains partial-source status", () => {
    const empty = advisory();
    expect(
      engine.correlate(input({ advisories: [empty], sourceStatus: "PARTIAL_RESULTS" }))
        .results[0]?.applicability,
    ).toBe("UNKNOWN");
    const malformed = advisory({
      ranges: [{ type: "SEMVER", events: [{ fixed: "2.0.0" }] }],
    });
    const result = engine.correlate(input({ advisories: [malformed] })).results[0]!;
    expect(result.applicability).toBe("UNKNOWN");
    expect(result.rangeAssessments[0]?.status).toBe("invalid-range");
  });

  it("produces stable source ordering and explanations across reordered inputs", () => {
    const records = [
      advisory({ provider: "osv" }),
      advisory({ provider: "nvd", aliases: ["OSV-2025-1"] }),
    ];
    const forward = engine.correlate(input({ advisories: records }));
    const reversed = engine.correlate(input({ advisories: [...records].reverse() }));
    expect(JSON.stringify(forward)).toBe(JSON.stringify(reversed));
  });
});
