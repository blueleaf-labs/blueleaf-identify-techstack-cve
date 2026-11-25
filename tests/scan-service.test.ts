import { describe, expect, it, vi } from "vitest";
import type { ApplicationError } from "../src/domain/errors.js";
import { DEFAULT_APPLICATION_CONFIGURATION } from "../src/config/configuration.js";
import { HttpProbeProvider } from "../src/infrastructure/http/http-probe-provider.js";
import {
  createTestScanService,
  httpResponse,
  mapping,
  fakeResolver,
} from "./helpers/scan-fixture.js";

describe("ScanApplicationService", () => {
  it("composes the existing probe, evidence, fingerprint, version, intelligence, correlation, assessment, and remediation services", async () => {
    const service = createTestScanService();
    const result = await service.scan({
      schemaVersion: "1.0",
      target: { url: "https://example.test/path?auth=secret#fragment" },
    });
    expect(result.schemaVersion).toBe("1.0");
    expect(result.target.url).toBe("https://example.test/path");
    expect(result.probe.finalUrl).toBe("https://example.test/app");
    expect(
      result.fingerprint.detections.some((item) => item.technologyId === "php"),
    ).toBe(true);
    expect(result.versions.assessments[0]?.selectedUpstreamVersion?.normalized).toBe(
      "8.2.1",
    );
    expect(result.correlation.results).toHaveLength(1);
    expect(result.assessment.technologyAssessments).toHaveLength(1);
    expect(result.remediation.plans[0]?.state).toBe("MANUAL_REVIEW_REQUIRED");
    expect(result.remediation.plans[0]?.recommendedTargetVersion).toBeUndefined();
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain("response-secret-never-serialize");
    expect(serialized).not.toContain("raw-cookie-secret");
    expect(serialized).not.toContain("auth=secret");
  });

  it("does not query intelligence when there is no explicit package mapping", async () => {
    const intelligence = fakeResolver();
    const result = await createTestScanService({
      packageMappings: [],
      intelligence,
    }).scan({ schemaVersion: "1.0", target: { url: "https://example.test" } });
    expect(intelligence.resolveMultiSourceQueries).not.toHaveBeenCalled();
    expect(result.intelligence.status).toBe("INTELLIGENCE_UNAVAILABLE");
    expect(result.assessment.technologyAssessments[0]?.state).toBe(
      "INSUFFICIENT_EVIDENCE",
    );
  });

  it("preserves provider failure and partial intelligence states", async () => {
    const partialResolver = {
      resolveMultiSourceQueries: vi.fn(
        async (
          queries: readonly { ecosystem: string; name: string; version: string }[],
        ) => ({
          schemaVersion: "1.0" as const,
          request: { kind: "package-version-batch" as const, queries },
          status: "PARTIAL_RESULTS" as const,
          sourceResults: [
            {
              providerId: "osv",
              status: "PROVIDER_UNAVAILABLE" as const,
              advisories: [],
              diagnostics: ["provider unavailable"],
            },
          ],
          advisories: [],
          retrievedAt: "2026-11-11T00:00:00.000Z",
          diagnostics: ["partial provider failure"],
        }),
      ),
      lookupMultiSourceAdvisory: vi.fn(),
    };
    const result = await createTestScanService({ intelligence: partialResolver }).scan({
      schemaVersion: "1.0",
      target: { url: "https://example.test" },
    });
    expect(result.intelligence.status).toBe("PARTIAL_RESULTS");
    expect(result.intelligence.sourceResults[0]?.status).toBe("PROVIDER_UNAVAILABLE");
    expect(result.assessment.state).toBe("INTELLIGENCE_UNAVAILABLE");
    expect(result.remediation.plans[0]?.state).toBe("REMEDIATION_UNAVAILABLE");
  });

  it("keeps unknown versions and conflicting evidence explicit", async () => {
    const unknown = await createTestScanService({
      response: httpResponse({
        headers: { "content-type": "text/html", "x-powered-by": "PHP" },
      }),
      packageMappings: [],
    }).scan({ schemaVersion: "1.0", target: { url: "https://example.test" } });
    expect(unknown.versions.assessments[0]?.parsingStatus).toBe("unknown");
    expect(unknown.assessment.state).toBe("INSUFFICIENT_EVIDENCE");
    expect(unknown.remediation.plans[0]?.recommendedTargetVersion).toBeUndefined();

    const conflictResponse = httpResponse({
      headers: {
        "x-powered-by": "PHP/8.2.1",
        server: "Apache nginx/1.25.0",
        "content-type": "text/html",
      },
    });
    const conflict = await createTestScanService({
      response: conflictResponse,
      packageMappings: [mapping],
    }).scan({ schemaVersion: "1.0", target: { url: "https://example.test" } });
    expect(conflict.fingerprint.detections.length).toBeGreaterThan(0);
    expect(
      conflict.assessment.technologyAssessments.some(
        (item) => item.detection.contradictoryEvidence.length > 0,
      ),
    ).toBe(true);
  });

  it("preserves target resolver SSRF protections through the shared service", async () => {
    const secure = new HttpProbeProvider(DEFAULT_APPLICATION_CONFIGURATION);
    const service = createTestScanService({ http: secure });
    await expect(
      service.scan({ schemaVersion: "1.0", target: { url: "http://127.0.0.1:9/" } }),
    ).rejects.toMatchObject({
      code: "TARGET_REJECTED",
    } satisfies Partial<ApplicationError>);
  });

  it("validates scan request and target shape before probing", async () => {
    const http = { request: vi.fn(async () => httpResponse()) };
    const service = createTestScanService({ http });
    await expect(
      service.scan({ schemaVersion: "1.0", target: { url: "file:///etc/passwd" } }),
    ).rejects.toMatchObject({ code: "INVALID_INPUT" });
    await expect(
      service.scan({
        schemaVersion: "9.0",
        target: { url: "https://example.test" },
      } as never),
    ).rejects.toMatchObject({ code: "INVALID_INPUT" });
    expect(http.request).not.toHaveBeenCalled();
  });
});
