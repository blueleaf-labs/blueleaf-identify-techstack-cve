import { describe, expect, it, vi } from "vitest";
import {
  ApplicationError,
  IntelligenceResolverService,
  OsvIntelligenceProvider,
  adaptOsvAdvisory,
} from "../src/index.js";
import type {
  AdvisoryIntelligenceProvider,
  AdvisoryPackageQuery,
  AdvisoryProviderResult,
  CacheProvider,
  NormalizedAdvisory,
} from "../src/index.js";

const retrievedAt = "2026-11-10T00:00:00.000Z";
const advisoryRecord = {
  id: "GHSA-aaaa-bbbb-cccc",
  aliases: ["CVE-2026-1234"],
  summary: "Issue",
  details: "Details",
  published: "2026-01-01T00:00:00Z",
  modified: "2026-02-01T00:00:00Z",
  withdrawn: "2026-03-01T00:00:00Z",
  affected: [
    {
      package: { ecosystem: "npm", name: "sample" },
      versions: ["1.0.0"],
      ranges: [{ type: "SEMVER", events: [{ introduced: "1.0.0" }, { fixed: "1.2.0" }] }],
    },
  ],
  severity: [{ type: "CVSS_V3", score: "7.5" }],
  references: [{ type: "WEB", url: "https://example.test/advisory" }],
};
function response(
  value: unknown,
  status = 200,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}
function query(version = "1.1.0"): AdvisoryPackageQuery {
  return { ecosystem: "npm", name: "sample", version };
}
function memoryCache(
  now: () => number = (): number => 0,
): CacheProvider & { entries: Map<string, string> } {
  const entries = new Map<string, string>();
  const expirations = new Map<string, number>();
  return {
    entries,
    async get(key: string): Promise<string | undefined> {
      const expiresAt = expirations.get(key);
      if (expiresAt !== undefined && expiresAt <= now()) {
        entries.delete(key);
        expirations.delete(key);
      }
      return entries.get(key);
    },
    async set(key: string, value: string, ttlSeconds: number): Promise<void> {
      entries.set(key, value);
      expirations.set(key, now() + ttlSeconds * 1_000);
    },
    async delete(key: string): Promise<void> {
      entries.delete(key);
      expirations.delete(key);
    },
  };
}
function mockAdvisory(): NormalizedAdvisory {
  return adaptOsvAdvisory(advisoryRecord, retrievedAt);
}

describe("OSV adapter", () => {
  it("normalizes aliases, affected ranges, fixed versions, severity, timestamps and withdrawal", () => {
    const advisory = mockAdvisory();
    expect(advisory.id).toBe("GHSA-aaaa-bbbb-cccc");
    expect(advisory.aliases).toEqual(["CVE-2026-1234"]);
    expect(advisory.affectedPackages[0]?.fixedVersions).toEqual(["1.2.0"]);
    expect(advisory.affectedPackages[0]?.explicitVersions).toEqual(["1.0.0"]);
    expect(advisory.severity[0]?.score).toBe("7.5");
    expect(advisory.withdrawnAt).toBe("2026-03-01T00:00:00Z");
    expect(advisory.provenance.sourceModifiedAt).toBe("2026-02-01T00:00:00Z");
  });
  it("rejects malformed records and invalid schemas instead of returning empty data", () => {
    expect(() =>
      adaptOsvAdvisory({ id: "X", affected: [{ package: { name: "x" } }] }, retrievedAt),
    ).toThrow(ApplicationError);
    expect(() =>
      adaptOsvAdvisory({ id: "X", severity: [{ type: "CVSS", score: 1 }] }, retrievedAt),
    ).toThrow(ApplicationError);
  });
});

describe("OSV provider", () => {
  it("aborts an in-flight advisory request when the scan signal is cancelled", async () => {
    const fetcher = vi.fn<typeof fetch>(
      (_input, init) =>
        new Promise<Response>((_resolve, reject) => {
          const signal = init?.signal as AbortSignal;
          signal.addEventListener(
            "abort",
            () => reject(new DOMException("aborted", "AbortError")),
            { once: true },
          );
        }),
    );
    const provider = new OsvIntelligenceProvider({ fetch: fetcher, maxRetries: 0 });
    const controller = new AbortController();
    const pending = provider.queryPackage(query(), controller.signal);
    await vi.waitFor(() => expect(fetcher).toHaveBeenCalledTimes(1));
    controller.abort();
    await expect(pending).rejects.toMatchObject({ code: "CANCELLED" });
  });

  it("supports a package/version query and returns normalized advisories", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValue(response({ vulns: [advisoryRecord] }));
    const provider = new OsvIntelligenceProvider({
      fetch: fetcher,
      now: (): Date => new Date(retrievedAt),
    });
    const result = await provider.queryPackage(query());
    expect(fetcher).toHaveBeenCalledWith(
      "https://api.osv.dev/v1/query",
      expect.objectContaining({ method: "POST" }),
    );
    expect(String(fetcher.mock.calls[0]?.[1]?.body)).toContain('"version":"1.1.0"');
    expect(result.advisories[0]?.id).toBe("GHSA-aaaa-bbbb-cccc");
  });
  it("uses batch queries then hydrates advisory IDs and keeps partial failures explicit", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        response({
          results: [
            { vulns: [{ id: "CVE-2026-1234", modified: "2026-02-01T00:00:00Z" }] },
            { vulns: [] },
          ],
        }),
      )
      .mockResolvedValueOnce(response(advisoryRecord));
    const provider = new OsvIntelligenceProvider({ fetch: fetcher });
    const result = await provider.queryBatch([
      query(),
      { ecosystem: "npm", name: "other", version: "1.0.0" },
    ]);
    expect(result.advisories).toHaveLength(1);
    expect(result.advisories[0]?.id).toBe("GHSA-aaaa-bbbb-cccc");
    const partialFetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        response({ results: [{ vulns: [{ id: "CVE-2026-1234" }] }] }),
      )
      .mockRejectedValueOnce(new Error("offline"));
    const partial = await new OsvIntelligenceProvider({
      fetch: partialFetcher,
      maxRetries: 0,
    }).queryBatch([query()]);
    expect(partial.complete).toBe(false);
    expect(partial.advisories).toEqual([]);
  });
  it("deduplicates IDs that resolve to the same canonical record", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        response({
          results: [{ vulns: [{ id: "CVE-2026-1234" }, { id: "GHSA-aaaa-bbbb-cccc" }] }],
        }),
      )
      .mockResolvedValueOnce(response(advisoryRecord))
      .mockResolvedValueOnce(response(advisoryRecord));
    const result = await new OsvIntelligenceProvider({ fetch: fetcher }).queryBatch([
      query(),
    ]);
    expect(result.advisories).toHaveLength(1);
    expect(result.advisories[0]?.aliases).toContain("CVE-2026-1234");
  });
  it("looks up an advisory ID and handles empty results, malformed JSON, rate limits, timeout and retries", async () => {
    const provider = new OsvIntelligenceProvider({
      fetch: vi.fn<typeof fetch>().mockResolvedValue(response(advisoryRecord)),
    });
    expect((await provider.getAdvisory("CVE-2026-1234")).id).toBe("GHSA-aaaa-bbbb-cccc");
    const empty = await new OsvIntelligenceProvider({
      fetch: vi.fn<typeof fetch>().mockResolvedValue(response({})),
    }).queryPackage(query());
    expect(empty.advisories).toEqual([]);
    const malformed = new OsvIntelligenceProvider({
      fetch: vi.fn<typeof fetch>().mockResolvedValue(new Response("not-json")),
    });
    await expect(malformed.queryPackage(query())).rejects.toMatchObject({
      code: "PROVIDER_FAILURE",
    });
    const serverError = new OsvIntelligenceProvider({
      fetch: vi.fn<typeof fetch>().mockResolvedValue(response({}, 500)),
      maxRetries: 0,
    });
    await expect(serverError.queryPackage(query())).rejects.toMatchObject({
      code: "PROVIDER_FAILURE",
    });
    const oversized = new OsvIntelligenceProvider({
      fetch: vi
        .fn<typeof fetch>()
        .mockResolvedValue(response({ value: "this response is too large" })),
      maxResponseBytes: 8,
    });
    await expect(oversized.queryPackage(query())).rejects.toMatchObject({
      code: "PROVIDER_FAILURE",
    });
    const retry = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(response({}, 429, { "retry-after": "0" }))
      .mockResolvedValueOnce(response({ vulns: [] }));
    const retried = await new OsvIntelligenceProvider({
      fetch: retry,
      sleep: async (): Promise<void> => undefined,
    }).queryPackage(query());
    expect(retried.complete).toBe(true);
    const limited = new OsvIntelligenceProvider({
      fetch: vi.fn<typeof fetch>().mockResolvedValue(response({}, 429)),
      maxRetries: 0,
    });
    await expect(limited.queryPackage(query())).rejects.toMatchObject({
      code: "RATE_LIMITED",
    });
    const timeout = new OsvIntelligenceProvider({
      fetch: vi
        .fn<typeof fetch>()
        .mockRejectedValue(Object.assign(new Error("timeout"), { name: "AbortError" })),
      maxRetries: 0,
    });
    await expect(timeout.queryPackage(query())).rejects.toMatchObject({
      code: "TIMEOUT",
    });
    const hangingBody = new OsvIntelligenceProvider({
      fetch: vi
        .fn<typeof fetch>()
        .mockResolvedValue(
          new Response(new ReadableStream<Uint8Array>({ start(): void {} })),
        ),
      timeoutMs: 5,
      maxRetries: 0,
    });
    await expect(hangingBody.queryPackage(query())).rejects.toMatchObject({
      code: "TIMEOUT",
    });
    const unsupportedEcosystem = new OsvIntelligenceProvider({
      fetch: vi
        .fn<typeof fetch>()
        .mockResolvedValue(response({ error: "unsupported ecosystem" }, 400)),
      maxRetries: 0,
    });
    await expect(
      unsupportedEcosystem.queryPackage({
        ecosystem: "Unknown",
        name: "pkg",
        version: "1.0.0",
      }),
    ).rejects.toMatchObject({ code: "PROVIDER_FAILURE" });
  });
});

describe("IntelligenceResolverService", () => {
  it("uses the cache on subsequent queries and stores normalized source and freshness metadata", async () => {
    const cache = memoryCache();
    const provider = {
      providerId: "osv",
      queryPackage: vi.fn(async (): Promise<AdvisoryProviderResult> => ({
        advisories: [mockAdvisory()],
        complete: true,
        diagnostics: [],
      })),
      queryBatch: vi.fn(),
      getAdvisory: vi.fn(),
    } as unknown as AdvisoryIntelligenceProvider;
    const resolver = new IntelligenceResolverService({
      providers: [provider],
      cache,
      now: (): Date => new Date(retrievedAt),
    });
    const first = await resolver.resolveQueries([query()]);
    const second = await resolver.resolveQueries([query()]);
    expect(first.status).toBe("resolved");
    expect(second.advisories[0]?.provenance.providerId).toBe("osv");
    expect(provider.queryPackage).toHaveBeenCalledTimes(1);
    expect(cache.entries.size).toBe(1);
  });
  it("deletes malformed cache records and does not cache failed provider calls", async () => {
    const cache = memoryCache();
    cache.entries.set("blueleaf:intelligence:1.0:osv:npm:sample:1.1.0", "{}");
    const provider = {
      providerId: "osv",
      queryPackage: vi
        .fn()
        .mockRejectedValue(new ApplicationError("PROVIDER_FAILURE", "offline")),
      queryBatch: vi.fn(),
      getAdvisory: vi.fn(),
    } as unknown as AdvisoryIntelligenceProvider;
    const resolver = new IntelligenceResolverService({ providers: [provider], cache });
    await expect(resolver.resolveQueries([query()])).rejects.toMatchObject({
      code: "PROVIDER_FAILURE",
    });
    expect(cache.entries.size).toBe(0);
  });
  it("does not cache incomplete provider results as empty success", async () => {
    const cache = memoryCache();
    const provider = {
      providerId: "osv",
      queryPackage: vi.fn(async (): Promise<AdvisoryProviderResult> => ({
        advisories: [],
        complete: false,
        diagnostics: ["partial"],
      })),
      queryBatch: vi.fn(),
      getAdvisory: vi.fn(),
    } as unknown as AdvisoryIntelligenceProvider;
    const resolver = new IntelligenceResolverService({ providers: [provider], cache });
    const result = await resolver.resolveQueries([query()]);
    expect(result.status).toBe("partial");
    expect(cache.entries.size).toBe(0);
  });
  it("refreshes query results after cache TTL expiry", async () => {
    let clock = 0;
    const cache = memoryCache((): number => clock);
    const provider = {
      providerId: "osv",
      queryPackage: vi.fn(async (): Promise<AdvisoryProviderResult> => ({
        advisories: [],
        complete: true,
        diagnostics: [],
      })),
      queryBatch: vi.fn(),
      getAdvisory: vi.fn(),
    } as unknown as AdvisoryIntelligenceProvider;
    const resolver = new IntelligenceResolverService({
      providers: [provider],
      cache,
      cacheTtlSeconds: 1,
    });
    await resolver.resolveQueries([query()]);
    clock = 1_001;
    await resolver.resolveQueries([query()]);
    expect(provider.queryPackage).toHaveBeenCalledTimes(2);
  });
  it("caches direct advisory ID lookups by source and ID", async () => {
    const cache = memoryCache();
    const provider = {
      providerId: "osv",
      queryPackage: vi.fn(),
      queryBatch: vi.fn(),
      getAdvisory: vi.fn(async (): Promise<NormalizedAdvisory> => mockAdvisory()),
    } as unknown as AdvisoryIntelligenceProvider;
    const resolver = new IntelligenceResolverService({ providers: [provider], cache });
    await resolver.lookupAdvisory("GHSA-aaaa-bbbb-cccc");
    await resolver.lookupAdvisory("GHSA-aaaa-bbbb-cccc");
    expect(provider.getAdvisory).toHaveBeenCalledTimes(1);
  });
  it("returns explicit unsupported and insufficient results without guessing package identities", async () => {
    const resolver = new IntelligenceResolverService({
      providers: [],
      cache: memoryCache(),
    });
    const unsupported = await resolver.resolveAssessments({
      schemaVersion: "1.0",
      fingerprintSchemaVersion: "1.0",
      assessments: [
        {
          technologyId: "nginx",
          displayName: "nginx",
          category: "server",
          versionConfidence: 0,
          parsingStatus: "unknown",
          reconciliationStatus: "unavailable",
          rawObservedVersions: [],
          parsedUpstreamVersions: [],
          vendorPackageVersions: [],
          candidateAssessments: [],
        },
      ],
    });
    expect(unsupported.status).toBe("unsupported");
    expect(unsupported.diagnostics[0]).toContain("No authoritative package mapping");
    await expect(
      resolver.resolveQueries([{ ecosystem: "", name: "pkg", version: "1.0" }]),
    ).rejects.toMatchObject({ code: "INVALID_INPUT" });
  });
  it("supports explicitly registered mappings and reports unknown versions as insufficient", async () => {
    const provider = {
      providerId: "osv",
      queryPackage: vi.fn(async (): Promise<AdvisoryProviderResult> => ({
        advisories: [],
        complete: true,
        diagnostics: [],
      })),
      queryBatch: vi.fn(),
      getAdvisory: vi.fn(),
    } as unknown as AdvisoryIntelligenceProvider;
    const resolver = new IntelligenceResolverService({
      providers: [provider],
      cache: memoryCache(),
      mappings: [{ technologyId: "php", ecosystem: "Packagist", packageName: "php" }],
    });
    const result = await resolver.resolveAssessments({
      schemaVersion: "1.0",
      fingerprintSchemaVersion: "1.0",
      assessments: [
        {
          technologyId: "php",
          displayName: "PHP",
          category: "language",
          versionConfidence: 0.8,
          parsingStatus: "unknown",
          reconciliationStatus: "unavailable",
          rawObservedVersions: [],
          parsedUpstreamVersions: [],
          vendorPackageVersions: [],
          candidateAssessments: [],
        },
      ],
    });
    expect(result.status).toBe("insufficient-data");
    expect(provider.queryPackage).not.toHaveBeenCalled();
  });
});
