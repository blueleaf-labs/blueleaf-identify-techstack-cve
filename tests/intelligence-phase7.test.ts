/* Test doubles use contextually typed async callbacks. */
/* eslint-disable @typescript-eslint/explicit-function-return-type */
import { describe, expect, it } from "vitest";
import { IntelligenceResolverService } from "../src/application/intelligence/intelligence-resolver.js";
import type { AdvisoryIntelligenceProvider } from "../src/application/intelligence/contracts.js";
import { ApplicationError } from "../src/domain/errors.js";
import type { NormalizedAdvisory } from "../src/domain/intelligence.js";
import { NvdIntelligenceProvider } from "../src/infrastructure/intelligence/nvd-provider.js";
import {
  RedHatSecurityAdvisoryProvider,
  UbuntuSecurityAdvisoryProvider,
} from "../src/infrastructure/intelligence/vendor-providers.js";

const now = () => new Date("2026-01-02T00:00:00.000Z");
function nvdPayload(id = "CVE-2025-12345") {
  return {
    startIndex: 0,
    resultsPerPage: 2,
    totalResults: 1,
    vulnerabilities: [
      {
        cve: {
          id,
          vulnStatus: "Analyzed",
          published: "2025-01-01T00:00:00.000Z",
          lastModified: "2025-01-02T00:00:00.000Z",
          descriptions: [{ lang: "en", value: "sample" }],
          metrics: {
            cvssMetricV31: [
              {
                cvssData: {
                  version: "3.1",
                  baseScore: 7.5,
                  baseSeverity: "HIGH",
                  vectorString: "CVSS:3.1/AV:N",
                },
              },
            ],
          },
          weaknesses: [{ description: [{ value: "CWE-79" }] }],
          references: [{ url: "https://example.test/ref", tags: ["Vendor Advisory"] }],
          configurations: [
            {
              operator: "OR",
              nodes: [
                {
                  operator: "AND",
                  cpeMatch: [
                    {
                      criteria: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                      vulnerable: true,
                      versionStartIncluding: "1.0",
                    },
                  ],
                },
              ],
            },
          ],
        },
      },
    ],
  };
}
const response = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

describe("Phase 7 authoritative intelligence providers", () => {
  it("normalizes NVD ID records including CVSS, CWE, CPE, dates and credential header", async () => {
    let requestUrl = "";
    let requestKey: string | null = null;
    const provider = new NvdIntelligenceProvider({
      apiKey: "test-key",
      throttleIntervalMs: 0,
      now,
      fetch: async (input, init) => {
        requestUrl = String(input);
        requestKey = new Headers(init?.headers).get("apiKey");
        return response(nvdPayload());
      },
    });
    const item = await provider.getAdvisory("cve-2025-12345");
    expect(new URL(requestUrl).searchParams.get("cveId")).toBe("CVE-2025-12345");
    expect(requestKey).toBe("test-key");
    expect(item.severity[0]).toMatchObject({
      type: "3.1",
      score: "7.5",
      severity: "HIGH",
    });
    expect(item.cweIds).toEqual(["CWE-79"]);
    expect(item.cpeConfigurations?.[0]?.nodes[0]?.matches[0]?.versionStartIncluding).toBe(
      "1.0",
    );
    expect(item.provenance.providerId).toBe("nvd");
  });

  it("bounds modified-date pagination and rejects overlong windows", async () => {
    const urls: URL[] = [];
    const provider = new NvdIntelligenceProvider({
      pageSize: 1,
      maxPages: 2,
      throttleIntervalMs: 0,
      now,
      fetch: async (input) => {
        urls.push(new URL(String(input)));
        return response({ ...nvdPayload(), totalResults: 3, resultsPerPage: 1 });
      },
    });
    const result = await provider.queryModifiedDateRange(
      "2026-01-01T00:00:00Z",
      "2026-01-02T00:00:00Z",
    );
    expect(urls).toHaveLength(2);
    expect(urls[1]?.searchParams.get("startIndex")).toBe("1");
    expect(urls[0]?.searchParams.get("lastModStartDate")).toBe(
      "2026-01-01T00:00:00.000Z",
    );
    expect(result.complete).toBe(false);
    await expect(
      provider.queryModifiedDateRange("2025-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
    ).rejects.toMatchObject({ code: "INVALID_INPUT" });
  });

  it("rejects malformed NVD payloads and handles a retry-after response", async () => {
    let count = 0;
    const delays: number[] = [];
    const provider = new NvdIntelligenceProvider({
      throttleIntervalMs: 0,
      maxRetries: 1,
      sleep: async (ms) => {
        delays.push(ms);
      },
      fetch: async () => {
        count++;
        return count === 1
          ? new Response("", { status: 429, headers: { "retry-after": "1" } })
          : response(nvdPayload());
      },
    });
    await expect(provider.getAdvisory("CVE-2025-12345")).resolves.toMatchObject({
      id: "CVE-2025-12345",
    });
    expect(delays).toContain(1000);
    const malformed = new NvdIntelligenceProvider({
      throttleIntervalMs: 0,
      fetch: async () => response({ vulnerabilities: [] }),
    });
    await expect(malformed.getAdvisory("CVE-2025-12345")).rejects.toMatchObject({
      code: "PROVIDER_FAILURE",
    });
  });

  it("normalizes Red Hat vendor patch records and keeps package state provenance", async () => {
    const provider = new RedHatSecurityAdvisoryProvider({
      now,
      fetch: async () =>
        response({
          name: "CVE-2025-12345",
          threat_severity: "Important",
          public_date: "2025-01-01T00:00:00Z",
          modified_date: "2025-01-02T00:00:00Z",
          details: ["issue"],
          cvss3: { cvss3_base_score: 7.5, cvss3_scoring_vector: "CVSS:3.1/AV:N" },
          affected_release: [
            {
              product_name: "RHEL 9",
              package: "pkg-1.2-3.el9",
              cpe: "cpe:/o:redhat:enterprise_linux:9",
              advisory: "RHSA-2025:0001",
            },
          ],
          package_state: [{ package_name: "pkg", fix_state: "Not affected" }],
          references: "https://access.redhat.com/errata/RHSA-2025:0001",
        }),
    });
    const item = await provider.getAdvisory("CVE-2025-12345");
    expect(item.severity.map((value) => value.score)).toEqual(["Important", "7.5"]);
    expect(item.vendorPackageInformation).toHaveLength(2);
    expect(item.cpeConfigurations).toHaveLength(1);
    expect(item.references[0]?.url).toContain("redhat.com");
    expect(item.provenance.sourceModifiedAt).toBe("2025-01-02T00:00:00Z");
    await expect(provider.queryPackage()).rejects.toMatchObject({
      code: "UNSUPPORTED_OPERATION",
    });
  });

  it("normalizes Canonical Ubuntu OSV JSON with vendor provenance and aliases", async () => {
    const provider = new UbuntuSecurityAdvisoryProvider({
      now,
      fetch: async (input) => {
        expect(String(input)).toContain("/osv/cve/2025/UBUNTU-CVE-2025-12345.json");
        return response({
          id: "UBUNTU-CVE-2025-12345",
          aliases: ["CVE-2025-12345"],
          summary: "Ubuntu issue",
          modified: "2025-01-02T00:00:00Z",
          affected: [],
        });
      },
    });
    const item = await provider.getAdvisory("CVE-2025-12345");
    expect(item.aliases).toEqual(["CVE-2025-12345"]);
    expect(item.provenance).toMatchObject({
      providerId: "ubuntu",
      authority: "vendor",
      originalIdentifier: "UBUNTU-CVE-2025-12345",
    });
    expect(item.provenance.recordUrl).toContain("canonical/ubuntu-security-notices");
  });

  it("preserves source conflicts and isolates unavailable providers", async () => {
    const advisory = (providerId: string, score: string): NormalizedAdvisory => ({
      id: "CVE-2025-12345",
      aliases: [],
      affectedPackages: [],
      severity: [{ type: "CVSS", score }],
      references: [],
      provenance: { providerId, retrievedAt: now().toISOString() },
    });
    const provider = (
      providerId: string,
      result: NormalizedAdvisory | Error,
    ): AdvisoryIntelligenceProvider => ({
      providerId,
      supportsIdLookups: true,
      async queryPackage() {
        return { advisories: [], complete: true, diagnostics: [] };
      },
      async queryBatch() {
        return { advisories: [], complete: true, diagnostics: [] };
      },
      async getAdvisory() {
        if (result instanceof Error) throw result;
        return result;
      },
    });
    const memory = new Map<string, string>();
    const resolver = new IntelligenceResolverService({
      providers: [
        provider("nvd", advisory("nvd", "7.5")),
        provider("redhat", advisory("redhat", "Important")),
        provider("ubuntu", new ApplicationError("PROVIDER_FAILURE", "offline")),
      ],
      cache: {
        async get(key) {
          return memory.get(key);
        },
        async set(key, value) {
          memory.set(key, value);
        },
        async delete(key) {
          memory.delete(key);
        },
      },
      now,
    });
    const result = await resolver.lookupMultiSourceAdvisory("CVE-2025-12345");
    expect(result.status).toBe("PARTIAL_RESULTS");
    expect(result.advisories.map((item) => item.provenance.providerId)).toEqual([
      "nvd",
      "redhat",
    ]);
    expect(
      result.sourceResults.find((item) => item.providerId === "ubuntu")?.status,
    ).toBe("PROVIDER_UNAVAILABLE");
    expect(
      (await resolver.lookupMultiSourceAdvisory("CVE-2025-12345")).advisories,
    ).toHaveLength(2);
  });

  it("distinguishes provider outage from unsupported intelligence", async () => {
    const memory = new Map<string, string>();
    const cache = {
      async get(key: string): Promise<string | undefined> {
        return memory.get(key);
      },
      async set(key: string, value: string): Promise<void> {
        memory.set(key, value);
      },
      async delete(key: string): Promise<void> {
        memory.delete(key);
      },
    };
    const unavailable: AdvisoryIntelligenceProvider = {
      providerId: "offline",
      supportsIdLookups: true,
      async queryPackage() {
        return { advisories: [], complete: true, diagnostics: [] };
      },
      async queryBatch() {
        return { advisories: [], complete: true, diagnostics: [] };
      },
      async getAdvisory() {
        throw new ApplicationError("PROVIDER_FAILURE", "offline");
      },
    };
    const unsupported: AdvisoryIntelligenceProvider = {
      ...unavailable,
      providerId: "unsupported",
      supportsIdLookups: false,
    };
    const outage = new IntelligenceResolverService({
      providers: [unavailable],
      cache,
      now,
    });
    const noMapping = new IntelligenceResolverService({
      providers: [unsupported],
      cache,
      now,
    });
    expect((await outage.lookupMultiSourceAdvisory("CVE-2025-12345")).status).toBe(
      "PROVIDER_UNAVAILABLE",
    );
    expect((await noMapping.lookupMultiSourceAdvisory("CVE-2025-12345")).status).toBe(
      "INTELLIGENCE_UNAVAILABLE",
    );
  });
});
