import { describe, expect, it } from "vitest";
import {
  compareSemVer,
  DEFAULT_VERSION_STRATEGIES,
  VersionIntelligenceEngine,
  VersionStrategyRegistry,
} from "../src/index.js";
import type {
  EvidenceReference,
  FingerprintResult,
  ParsedUpstreamVersion,
  TechnologyDetection,
  VersionCandidate,
  VendorAdvisoryRange,
  VersionStrategy,
} from "../src/index.js";

function ref(value: string, evidenceIndex = 0): EvidenceReference {
  return {
    evidenceIndex,
    type: "header",
    source: "response.headers",
    normalizedValue: value,
    key: "server",
  };
}

function candidate(
  value: string,
  observation?: string,
  evidenceIndex = 0,
): VersionCandidate {
  return {
    value,
    confidence: 0.65,
    evidenceReferences:
      observation === undefined ? [] : [ref(observation, evidenceIndex)],
  };
}

function detection(
  technologyId: string,
  values: readonly VersionCandidate[],
  displayName = technologyId,
): TechnologyDetection {
  const primary = [...values].sort((left, right) =>
    left.value.localeCompare(right.value),
  )[0];
  return {
    technologyId,
    displayName,
    category: technologyId === "php" ? "programming-language" : "web-server",
    ...(primary !== undefined ? { versionCandidate: primary } : {}),
    versionCandidates: values,
    detectionConfidence: values.length > 0 ? 0.8 : 0,
    versionConfidence: primary?.confidence ?? 0,
    matchedEvidenceReferences: values.flatMap((item) => item.evidenceReferences),
    detectionReasons: [],
    contradictoryEvidence: [],
  };
}

function fingerprintResult(
  ...detections: readonly TechnologyDetection[]
): FingerprintResult {
  return {
    schemaVersion: "1.0",
    evidenceSchemaVersion: "1.0",
    detections,
  };
}

describe("VersionIntelligenceEngine", () => {
  const engine = new VersionIntelligenceEngine();

  it.each([
    ["php", "8.2.3", "8.2.3"],
    ["nginx", "1.26.1", "1.26.1"],
    ["apache", "2.4.62", "2.4.62"],
  ])(
    "parses upstream %s versions without conflating version confidence",
    (technologyId, raw, normalized) => {
      const result = engine.assess(
        fingerprintResult(
          detection(technologyId, [candidate(raw, `${technologyId}/${raw}`)]),
        ),
      );
      const assessment = result.assessments[0];

      expect(assessment?.rawObservedVersions[0]?.rawValue).toBe(raw);
      expect(assessment?.parsedUpstreamVersions[0]?.normalized).toBe(normalized);
      expect(assessment?.versionConfidence).toBe(0.65);
      expect(assessment?.parsingStatus).toBe("parsed");
      expect(assessment?.selectedUpstreamVersion).toBeDefined();
    },
  );

  it("recovers original prerelease casing and normalizes PHP RC formats", () => {
    const assessment = engine.assess(
      fingerprintResult(detection("php", [candidate("8.3.0", "PHP/8.3.0RC1")])),
    ).assessments[0];

    expect(assessment?.rawObservedVersions[0]?.rawValue).toBe("8.3.0RC1");
    expect(assessment?.parsedUpstreamVersions[0]?.normalized).toBe("8.3.0-rc1");
  });

  it("separates recognized Debian and Ubuntu package revisions from upstream versions", () => {
    const assessment = engine.assess(
      fingerprintResult(
        detection("nginx", [
          candidate("1.22.1-9+deb12u3", "nginx/1.22.1-9+deb12u3"),
          candidate("1:1.24.0-1ubuntu2.1", "nginx/1:1.24.0-1ubuntu2.1", 1),
          candidate("1.26.1-2.el9", "nginx/1.26.1-2.el9", 2),
        ]),
      ),
    ).assessments[0];

    expect(assessment?.vendorPackageVersions).toHaveLength(3);
    expect(assessment?.vendorPackageVersions[0]).toMatchObject({
      distribution: "debian",
      revision: "9+deb12u3",
      upstreamValue: "1.22.1",
    });
    expect(
      assessment?.vendorPackageVersions.find((item) => item.distribution === "ubuntu"),
    ).toMatchObject({
      distribution: "ubuntu",
      epoch: 1,
      revision: "1ubuntu2.1",
      upstreamValue: "1.24.0",
    });
    expect(
      assessment?.vendorPackageVersions.find(
        (item) => item.distribution === "rhel-family",
      ),
    ).toMatchObject({
      distribution: "rhel-family",
      revision: "2.el9",
      upstreamValue: "1.26.1",
    });
    expect(
      assessment?.parsedUpstreamVersions.map((version) => version.normalized),
    ).toEqual(["1.22.1", "1.24.0", "1.26.1"]);
    expect(assessment?.reconciliationStatus).toBe("conflicting");
  });

  it("retains a recognized package suffix even when its upstream portion is malformed", () => {
    const assessment = engine.assess(
      fingerprintResult(
        detection("nginx", [candidate("1.02.3-1ubuntu1", "nginx/1.02.3-1ubuntu1")]),
      ),
    ).assessments[0];

    expect(assessment?.parsingStatus).toBe("ambiguous");
    expect(assessment?.vendorPackageVersions[0]).toMatchObject({
      rawValue: "1.02.3-1ubuntu1",
      upstreamValue: "1.02.3",
      distribution: "ubuntu",
      revision: "1ubuntu1",
    });
    expect(assessment?.parsedUpstreamVersions).toEqual([]);
  });

  it("reports missing components as incomplete without inventing a patch level", () => {
    const assessment = engine.assess(
      fingerprintResult(detection("php", [candidate("8.2", "PHP/8.2")])),
    ).assessments[0];

    expect(assessment?.parsingStatus).toBe("incomplete");
    expect(assessment?.parsedUpstreamVersions).toEqual([]);
    expect(assessment?.candidateAssessments[0]?.partialUpstreamComponents).toEqual({
      major: 8,
      minor: 2,
    });
    expect(assessment?.selectedUpstreamVersion).toBeUndefined();
  });

  it("compares SemVer prereleases and build metadata according to SemVer ordering", () => {
    const alpha = engine.compare("nginx", "1.2.3-alpha.2", "<", "1.2.3-alpha.10");
    const prereleaseToRelease = engine.compare("nginx", "1.2.3-rc.1", "<", "1.2.3");
    const builds = engine.compare("nginx", "1.2.3+build.1", "=", "1.2.3+build.2");

    expect(alpha).toMatchObject({ status: "compared", ordering: -1, matches: true });
    expect(prereleaseToRelease.matches).toBe(true);
    expect(builds).toMatchObject({ status: "compared", ordering: 0, matches: true });
  });

  it.each([
    ["<", "1.0.0", "2.0.0", true],
    ["<=", "2.0.0", "2.0.0", true],
    ["=", "2.0.0", "2.0.0", true],
    ["==", "2.0.0", "2.0.0", true],
    ["!=", "2.0.0", "2.0.1", true],
    [">=", "2.0.0", "2.0.0", true],
    [">", "2.0.1", "2.0.0", true],
  ] as const)("supports comparison operator %s", (operator, left, right, matches) => {
    expect(engine.compare("php", left, operator, right)).toMatchObject({
      status: "compared",
      matches,
    });
  });

  it("evaluates introduced-inclusive and fixed-exclusive range boundaries", () => {
    const beforeFixed = engine.evaluateRange("nginx", "1.2.3", {
      introduced: "1.2.0",
      fixed: "1.2.4",
    });
    const atFixed = engine.evaluateRange("nginx", "1.2.4", {
      introduced: "1.2.0",
      fixed: "1.2.4",
    });
    const lastAffected = engine.evaluateRange("php", "8.2.9", {
      introduced: "8.2.0",
      lastAffected: "8.2.9",
    });

    expect(beforeFixed.status).toBe("within");
    expect(atFixed.status).toBe("outside");
    expect(lastAffected.status).toBe("within");
    expect(
      engine.evaluateRange("php", "8.2.10", {
        introduced: "8.2.0",
        lastAffected: "8.2.9",
      }).status,
    ).toBe("outside");
  });

  it("evaluates NVD-style comparison constraints and handles OSV introduced zero", () => {
    expect(
      engine.evaluateRange("apache", "2.4.60", {
        introduced: "0",
        constraints: [
          { operator: ">=", version: "2.4.50" },
          { operator: "<", version: "2.4.62" },
        ],
      }).status,
    ).toBe("within");
    expect(
      engine.evaluateRange("apache", "2.4.62", {
        constraints: [{ operator: "<", version: "2.4.62" }],
      }).status,
    ).toBe("outside");
  });

  it("does not evaluate an upstream range as a vendor backport verdict", () => {
    const result = engine.evaluateRange("nginx", "1.22.1-9+deb12u3", {
      introduced: "1.22.0",
      fixed: "1.22.2",
    });

    expect(result.status).toBe("unknown");
    expect(result.reason).toMatch(/vendor-specific/i);
    expect(engine.compare("nginx", "1.22.1-9+deb12u3", "<", "1.22.2").status).toBe(
      "unknown",
    );
  });

  it("rejects structurally conflicting or empty ranges", () => {
    expect(
      engine.evaluateRange("php", "8.2.3", { fixed: "8.2.4", lastAffected: "8.2.3" })
        .status,
    ).toBe("invalid-range");
    expect(engine.evaluateRange("php", "8.2.3", {}).status).toBe("invalid-range");
  });

  it("reserves vendor advisory ranges for future package-specific evaluation", () => {
    const vendorRange: VendorAdvisoryRange = {
      ecosystem: "Debian:12",
      packageName: "nginx",
      distribution: "debian",
      introduced: "1.22.1-1",
      fixed: "1.22.1-9+deb12u3",
    };

    expect(engine.evaluateRange("nginx", "1.22.1", vendorRange).status).toBe("unknown");
  });

  it.each([
    ["8.2.0-1", "ambiguous"],
    ["8.2.0-alpine3.18", "unsupported"],
    ["8.02.0", "malformed"],
    ["1.2.x", "unsupported"],
  ] as const)(
    "keeps ambiguous, vendor-suffixed, and malformed value %s explicit",
    (raw, status) => {
      const assessment = engine.assess(
        fingerprintResult(detection("php", [candidate(raw, `PHP/${raw}`)])),
      ).assessments[0];

      expect(assessment?.candidateAssessments[0]?.parsingStatus).toBe(status);
      expect(assessment?.selectedUpstreamVersion).toBeUndefined();
      expect(assessment?.rawObservedVersions[0]?.rawValue).toBe(raw);
    },
  );

  it("keeps malformed comparisons and unsupported formats unknown", () => {
    expect(engine.compare("php", "8.02.0", "<", "8.3.0").status).toBe("unknown");
    expect(engine.compare("nginx", "1.2.x", "=", "1.2.0").status).toBe("unknown");
    expect(engine.compare("custom-stack", "1.2.3", "=", "1.2.3").status).toBe("compared");
    expect(engine.compare("nginx", "1.2.3+deb12u1", "=", "1.2.3").status).toBe("unknown");
  });

  it("returns explicit unknown assessments for missing and unknown versions", () => {
    const result = engine.assess(
      fingerprintResult(
        detection("unknown-tech", []),
        detection("php", [candidate("latest")]),
      ),
    );

    expect(result.assessments[0]).toMatchObject({
      technologyId: "php",
      parsingStatus: "unsupported",
      reconciliationStatus: "ambiguous",
    });
    expect(result.assessments[1]).toMatchObject({
      technologyId: "unknown-tech",
      parsingStatus: "unknown",
      reconciliationStatus: "unavailable",
    });
    const unknownEcosystemSuffix = engine.assess(
      fingerprintResult(
        detection("unknown-tech", [
          candidate("1.2.3-alpine3.18", "Thing/1.2.3-alpine3.18"),
        ]),
      ),
    ).assessments[0];
    expect(unknownEcosystemSuffix?.parsingStatus).toBe("unsupported");
  });

  it("reconciles repeated candidates but preserves conflicting versions", () => {
    const corroborated = engine.assess(
      fingerprintResult(
        detection("apache", [
          candidate("2.4.62", "Apache/2.4.62", 0),
          candidate("2.4.62", "Apache Server/2.4.62", 1),
        ]),
      ),
    ).assessments[0];
    const conflict = engine.assess(
      fingerprintResult(
        detection("apache", [
          candidate("2.4.61", "Apache/2.4.61", 0),
          candidate("2.4.62", "Apache/2.4.62", 1),
        ]),
      ),
    ).assessments[0];

    expect(corroborated?.reconciliationStatus).toBe("corroborated");
    expect(corroborated?.selectedUpstreamVersion?.normalized).toBe("2.4.62");
    expect(conflict?.reconciliationStatus).toBe("conflicting");
    expect(conflict?.selectedUpstreamVersion).toBeUndefined();
    expect(conflict?.parsedUpstreamVersions.map((item) => item.normalized)).toEqual([
      "2.4.61",
      "2.4.62",
    ]);
  });

  it("marks mixed parsed and unknown candidates ambiguous", () => {
    const assessment = engine.assess(
      fingerprintResult(
        detection("nginx", [candidate("1.26.1", "nginx/1.26.1"), candidate("latest")]),
      ),
    ).assessments[0];

    expect(assessment?.parsingStatus).toBe("ambiguous");
    expect(assessment?.reconciliationStatus).toBe("ambiguous");
    expect(assessment?.selectedUpstreamVersion).toBeUndefined();
  });

  it("supports custom ecosystem strategies through the registry", () => {
    const fallback = new VersionStrategyRegistry().forTechnology("unknown");
    const customStrategy: VersionStrategy = {
      id: "custom-semver",
      technologyIds: ["custom"],
      parse: (rawValue) => fallback.parse(rawValue),
      compare: (left: ParsedUpstreamVersion, right: ParsedUpstreamVersion) =>
        compareSemVer(left, right),
    };
    const registry = new VersionStrategyRegistry([
      ...DEFAULT_VERSION_STRATEGIES,
      customStrategy,
    ]);

    expect(registry.forTechnology("custom").id).toBe("custom-semver");
    expect(
      new VersionIntelligenceEngine(registry).compare("custom", "1.0.0", "=", "1.0.0")
        .matches,
    ).toBe(true);
    expect(() => new VersionStrategyRegistry([customStrategy])).toThrow(/fallback/);
    expect(
      () =>
        new VersionStrategyRegistry([
          ...DEFAULT_VERSION_STRATEGIES,
          { ...customStrategy, id: "custom-other", technologyIds: ["php"] },
        ]),
    ).toThrow(/already registered/);
  });

  it("rejects malformed Phase 4 result contracts", () => {
    expect(() =>
      engine.assess({ schemaVersion: "2.0" } as unknown as FingerprintResult),
    ).toThrow(/FingerprintResult schema version 1.0/);
  });

  it("serializes assessments deterministically across detection and candidate order", () => {
    const php = detection("php", [candidate("8.2.3", "PHP/8.2.3")]);
    const nginx = detection("nginx", [candidate("1.26.1", "nginx/1.26.1")]);
    const first = engine.assess(fingerprintResult(php, nginx));
    const second = engine.assess(fingerprintResult(nginx, php));

    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });
});
